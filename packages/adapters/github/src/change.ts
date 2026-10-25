import { createHash } from "node:crypto";
import { OpsError } from "@ops/contracts";
import type { ActionPreview, RawToolOutput } from "@ops/contracts";
import { diffFile } from "@ops/diff";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { writeCheck } from "@ops/workspace";
import { ghError } from "./client.ts";
import type { GithubClient, GhResponse } from "./client.ts";
import { GIT_REF_MESSAGE, int, isGitRef, isoOrUndefined, safeName, sha40 } from "./safe.ts";

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const enc = (full: string): string => full.split("/").map(encodeURIComponent).join("/");
const encPath = (p: string): string => p.split("/").map(encodeURIComponent).join("/");
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

function json(resp: GhResponse, what: string): Obj {
  if (resp.status < 200 || resp.status >= 300) throw ghError(resp, what);
  try {
    return obj(JSON.parse(resp.body));
  } catch {
    throw new OpsError("github_error", `${what}: yanıt JSON değil`);
  }
}

const MAX_TOTAL_CHARS = 200_000;
const NO_PATH_POLICY = { writePaths: ["**"] as string[], denyPaths: [] as string[] };

export interface PrFile {
  readonly path: string;
  readonly content: string;
}
export interface PrArgs {
  readonly repo: string;
  readonly base: string;
  readonly branch: string;
  readonly title: string;
  readonly body?: string;
  readonly files: readonly PrFile[];
  readonly draft?: boolean;
}

/**
 * PR içeriği doğrulaması (çağrı çözümlemesinde ve araçta TEKRAR): dosya yolları çalışma alanıyla AYNI
 * yazma politikasından geçer (CI/pipeline tanımları, gizli/state/anahtar/tfvars dosyaları, eklenti
 * dizinleri YASAK — T21), içerik/başlık/gövde secret benzeri değer taşıyamaz, toplam boyut sınırlı.
 */
export function validatePr(a: PrArgs): void {
  // dal adları API yollarına girer (`.../git/ref/heads/<dal>`): şemanın yanı sıra burada da
  if (!isGitRef(a.base) || !isGitRef(a.branch)) throw new OpsError("pr_invalid", `dal adı reddedildi: ${GIT_REF_MESSAGE}`);
  if (a.branch === a.base) throw new OpsError("pr_invalid", "baş dal ile hedef dal aynı olamaz");
  const seen = new Set<string>();
  let total = 0;
  for (const f of a.files) {
    const c = writeCheck(f.path, NO_PATH_POLICY);
    if (!c.ok) throw new OpsError("path_denied", `dosya yolu reddedildi (${f.path.slice(0, 80)}): ${c.reason}`);
    if (seen.has(f.path)) throw new OpsError("pr_invalid", `yinelenen dosya yolu: ${f.path.slice(0, 80)}`);
    seen.add(f.path);
    total += f.content.length;
  }
  if (total > MAX_TOTAL_CHARS) throw new OpsError("pr_too_large", `toplam içerik ${MAX_TOTAL_CHARS} karakteri aşıyor`);
  const known = new KnownSecrets();
  const texts: [string, string][] = [["başlık", a.title], ["gövde", a.body ?? ""], ...a.files.map((f): [string, string] => [`dosya ${f.path}`, f.content])];
  for (const [label, t] of texts) {
    if (scrubText(t, known) !== t) throw new OpsError("secret_in_content", `${label} secret benzeri bir değer içeriyor: PR oluşturulmaz`);
  }
}

async function baseSha(c: GithubClient, repo: string, branch: string): Promise<string> {
  const r = json(await c.get(`/repos/${enc(repo)}/git/ref/heads/${encPath(branch)}`), `hedef dal '${branch}'`);
  const sha = sha40(obj(r["object"])["sha"]);
  if (!sha) throw new OpsError("github_error", "hedef dalın commit SHA'sı okunamadı");
  return sha;
}

interface Existing {
  readonly sha: string | null;
  readonly text: string | null;
}

async function existing(c: GithubClient, repo: string, path: string, ref: string): Promise<Existing> {
  const resp = await c.get(`/repos/${enc(repo)}/contents/${encPath(path)}`, { ref });
  if (resp.status === 404) return { sha: null, text: null };
  const j = json(resp, `dosya ${path}`);
  if (j["type"] !== "file") throw new OpsError("pr_invalid", `${path} bir dizin/bağ: yalnız dosyalar güncellenir`);
  if (j["encoding"] !== "base64" || typeof j["content"] !== "string" || typeof j["sha"] !== "string") throw new OpsError("file_too_large", `${path} içeriği API'den dönmedi (çok büyük olabilir)`);
  const buf = Buffer.from(j["content"], "base64");
  if (buf.includes(0)) throw new OpsError("file_binary", `${path} ikili dosya: güncellenmez`);
  return { sha: j["sha"], text: buf.toString("utf8") };
}

export async function previewPr(c: GithubClient, a: PrArgs): Promise<ActionPreview> {
  validatePr(a);
  const head = await c.get(`/repos/${enc(a.repo)}/git/ref/heads/${encPath(a.branch)}`);
  if (head.status !== 404) {
    if (head.status >= 200 && head.status < 300) throw new OpsError("pr_invalid", `baş dal '${a.branch}' zaten var: farklı bir ops/... adı seçin`);
    throw ghError(head, `baş dal '${a.branch}'`);
  }
  const sha = await baseSha(c, a.repo, a.base);
  const lines: string[] = [];
  const parts: [string, string | null][] = [];
  let created = 0;
  let changed = 0;
  for (const f of a.files) {
    const ex = await existing(c, a.repo, f.path, sha);
    parts.push([f.path, ex.sha]);
    const d = diffFile(f.path, ex.text, f.content);
    if (ex.text === null) created++;
    else if (d.patch !== "") changed++;
    if (d.patch !== "") lines.push(d.patch);
  }
  const digest = sha256(JSON.stringify(parts)).slice(0, 16);
  return {
    targetVersion: `${sha}:${digest}`,
    diff: lines.join(""),
    impact: [
      `${a.files.length} dosya (${created} yeni, ${changed} değişen) → yeni dal '${a.branch}' → ${a.draft === false ? "" : "TASLAK "}PR hedef '${a.base}'`,
      "dal ve commit'ler belirteç sahibi hesap adına oluşturulur; hedef dala DOĞRUDAN yazılmaz",
    ],
    rollback: `PR'ı kapatın ve '${a.branch}' dalını silin`,
  };
}

export async function doPr(c: GithubClient, a: PrArgs, approvedVersion: string | undefined): Promise<RawToolOutput> {
  validatePr(a);
  if (approvedVersion === undefined) throw new OpsError("approval_version_missing", "onaylanan hedef sürümü yok; uygulama reddedildi");
  const sha = approvedVersion.split(":")[0] as string;
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new OpsError("approval_version_missing", "onaylanan sürüm biçimi geçersiz");
  const ref = await c.post(`/repos/${enc(a.repo)}/git/refs`, { ref: `refs/heads/${a.branch}`, sha });
  if (ref.status === 422) throw new OpsError("target_changed", `dal '${a.branch}' zaten var (onaydan sonra oluşturulmuş olabilir)`);
  json(ref, "dal oluşturma");
  let step = "dosyalar";
  try {
    for (const f of a.files) {
      const ex = await existing(c, a.repo, f.path, sha); // onaylanan commit'e sabitlenmiş okuma
      const put = await c.put(`/repos/${enc(a.repo)}/contents/${encPath(f.path)}`, {
        message: `${a.title.split("\n")[0]?.slice(0, 100) ?? "değişiklik"}\n\nops-assistant ile hazırlandı (taslak).`,
        content: Buffer.from(f.content, "utf8").toString("base64"),
        branch: a.branch,
        ...(ex.sha ? { sha: ex.sha } : {}),
      });
      json(put, `dosya ${f.path}`);
    }
    step = "pull request";
    const pr = json(await c.post(`/repos/${enc(a.repo)}/pulls`, { title: a.title, body: a.body ?? "", head: a.branch, base: a.base, draft: a.draft !== false }), "pull request");
    const number = int(pr["number"]);
    return {
      data: { created: true, repo: a.repo, pr: number, head: a.branch, base: a.base, draft: a.draft !== false, files: a.files.length },
      summary: `PR #${String(number)} oluşturuldu (${a.draft === false ? "" : "taslak, "}${a.branch} → ${a.base})`,
      subjects: [`Repo/${a.repo}`, ...(number !== undefined ? [`PR/${a.repo}#${number}`] : [])],
    };
  } catch (e) {
    // yarım kalan dalı (YALNIZ bu çağrıda oluşturduğumuz) geri al; başarısız olursa kullanıcıya söyle
    const cleaned = await c.del(`/repos/${enc(a.repo)}/git/refs/heads/${encPath(a.branch)}`).then((r) => r.status === 204 || r.status === 200, () => false);
    const msg = e instanceof Error ? e.message : String(e);
    throw new OpsError("pr_failed", `${step} adımında hata: ${msg.slice(0, 160)} — ${cleaned ? `oluşturulan '${a.branch}' dalı geri alındı` : `'${a.branch}' dalı elle silinmeli`}`);
  }
}

// ---- workflow koşusu rerun / cancel -----------------------------------------------------------------

interface RunArgs {
  readonly repo: string;
  readonly runId: number;
  readonly failedOnly?: boolean;
}

async function getRun(c: GithubClient, a: RunArgs): Promise<Obj> {
  return json(await c.get(`/repos/${enc(a.repo)}/actions/runs/${a.runId}`), `koşu ${a.runId}`);
}

const runVersion = (r: Obj): string => `${safeName(r["status"], 20) ?? "?"}/${safeName(r["conclusion"], 20) ?? "-"}/${int(r["run_attempt"]) ?? 0}`;

export async function previewRerun(c: GithubClient, a: RunArgs): Promise<ActionPreview> {
  const r = await getRun(c, a);
  if (r["status"] !== "completed") throw new OpsError("run_state", `koşu '${safeName(r["status"], 20)}' durumunda: yalnız tamamlanmış koşular yeniden çalıştırılır`);
  const event = safeName(r["event"], 40);
  return {
    targetVersion: runVersion(r),
    impact: [
      `${safeName(r["name"])} (deneme ${int(r["run_attempt"])} → ${(int(r["run_attempt"]) ?? 0) + 1}) dal ${safeName(r["head_branch"])}, commit ${(sha40(r["head_sha"]) ?? "?").slice(0, 12)}, tetikleyici ${event}`,
      a.failedOnly ? "yalnız başarısız işler yeniden çalışır" : "TÜM işler yeniden çalışır",
      "⚠ workflow dağıtım/yayın adımları içeriyorsa ETKİLİ bir deploy tetiklenebilir (tanıma bakın)",
    ],
    rollback: "çalışan koşu pipeline.run.cancel ile iptal edilebilir; tamamlanmış bir dağıtım geri alınmaz",
  };
}

export async function doRerun(c: GithubClient, a: RunArgs, approvedVersion: string | undefined): Promise<RawToolOutput> {
  if (approvedVersion === undefined) throw new OpsError("approval_version_missing", "onaylanan hedef sürümü yok; uygulama reddedildi");
  const resp = await c.post(`/repos/${enc(a.repo)}/actions/runs/${a.runId}/${a.failedOnly ? "rerun-failed-jobs" : "rerun"}`, {});
  if (resp.status === 403 && /already running|cannot be rerun/i.test(resp.body)) throw new OpsError("target_changed", "koşu artık yeniden çalıştırılamaz (durumu değişti)");
  if (resp.status !== 201 && resp.status !== 200 && resp.status !== 204) throw ghError(resp, "yeniden çalıştırma");
  return { data: { rerun: true, repo: a.repo, runId: a.runId, failedOnly: a.failedOnly === true }, summary: `koşu ${a.runId} yeniden çalıştırılıyor`, subjects: [`Repo/${a.repo}`, `Run/${a.runId}`] };
}

export async function previewCancel(c: GithubClient, a: RunArgs): Promise<ActionPreview> {
  const r = await getRun(c, a);
  const st = r["status"];
  if (st !== "in_progress" && st !== "queued" && st !== "waiting" && st !== "pending") throw new OpsError("run_state", `koşu '${safeName(st, 20)}' durumunda: yalnız süren/kuyruktaki koşular iptal edilir`);
  return {
    targetVersion: runVersion(r),
    impact: [`${safeName(r["name"])} (deneme ${int(r["run_attempt"])}) dal ${safeName(r["head_branch"])}, commit ${(sha40(r["head_sha"]) ?? "?").slice(0, 12)}, başlangıç ${isoOrUndefined(r["created_at"]) ?? "?"} iptal edilecek`, "⚠ yarım kalan dağıtım adımları tutarsız durum bırakabilir"],
    rollback: "iptal geri alınmaz; gerekirse pipeline.run.rerun ile yeniden başlatılır",
  };
}

export async function doCancel(c: GithubClient, a: RunArgs, approvedVersion: string | undefined): Promise<RawToolOutput> {
  if (approvedVersion === undefined) throw new OpsError("approval_version_missing", "onaylanan hedef sürümü yok; uygulama reddedildi");
  const resp = await c.post(`/repos/${enc(a.repo)}/actions/runs/${a.runId}/cancel`, {});
  if (resp.status === 409) throw new OpsError("target_changed", "koşu artık iptal edilemez (durumu değişti)");
  if (resp.status !== 202 && resp.status !== 200 && resp.status !== 204) throw ghError(resp, "iptal");
  return { data: { cancelled: true, repo: a.repo, runId: a.runId }, summary: `koşu ${a.runId} iptal isteği gönderildi`, subjects: [`Repo/${a.repo}`, `Run/${a.runId}`] };
}
