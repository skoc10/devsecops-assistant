import { ADAPTER_CONTRACT, AdapterManifestSchema, OpsError, parseSince, riskRank } from "@ops/contracts";
import type {
  ActionPreview,
  Adapter,
  AdapterCall,
  AdapterManifest,
  CredentialHandle,
  DoctorFinding,
  DoctorReport,
  Profile,
  RawToolOutput,
  RiskClass,
  Target,
  ToolDefinition,
} from "@ops/contracts";
import type { CredentialResolver } from "@ops/broker";
import { GithubClient, ghError, isAllowedLogHost } from "./client.ts";
import type { GhResponse } from "./client.ts";
import { assertRepo, int, isoOrUndefined, pathProblem, safeName, sha40 } from "./safe.ts";
import { PIPELINE_TOOLS, PIPELINE_WRITE_TOOLS, SCM_TOOLS, SCM_WRITE_TOOLS } from "./tools.ts";
import { doCancel, doPr, doRerun, previewCancel, previewPr, previewRerun, validatePr } from "./change.ts";
import type { PrArgs } from "./change.ts";

const PIPELINE_ALL = [...PIPELINE_TOOLS, ...PIPELINE_WRITE_TOOLS] as const;
const SCM_ALL = [...SCM_TOOLS, ...SCM_WRITE_TOOLS] as const;
const WRITE_NAMES: ReadonlySet<string> = new Set([...PIPELINE_WRITE_TOOLS, ...SCM_WRITE_TOOLS].map((t) => t.descriptor.name));
import { workflowFacts } from "./workflow.ts";

type Args = Record<string, unknown>;
type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (a: Args, k: string): string | undefined => (typeof a[k] === "string" ? (a[k] as string) : undefined);

function json(resp: GhResponse, what: string): unknown {
  if (resp.status < 200 || resp.status >= 300) throw ghError(resp, what);
  try {
    return JSON.parse(resp.body);
  } catch {
    throw new OpsError("github_error", `${what}: yanıt JSON değil`);
  }
}

const enc = (full: string): string => full.split("/").map(encodeURIComponent).join("/");

export interface GithubAdapterOptions {
  readonly now?: () => Date;
}

/** GitHub REST ortak mantığı: pin → istemci, kapsam çözümü, doktor. */
abstract class GithubBase implements Adapter {
  abstract readonly manifest: AdapterManifest;
  abstract readonly profileKind: "pipeline" | "scm";
  protected readonly resolver: CredentialResolver;
  protected readonly now: () => Date;

  constructor(resolver: CredentialResolver, opts: GithubAdapterOptions) {
    this.resolver = resolver;
    this.now = opts.now ?? (() => new Date());
  }

  abstract invoke(call: AdapterCall): Promise<RawToolOutput>;
  protected abstract refsFor(tool: string, a: Args, repo: string): string[];

  validateProfile(profile: Profile): string[] {
    const p: string[] = [];
    if (profile.kind !== this.profileKind) p.push(`profil türü '${this.profileKind}' olmalı: ${profile.kind}`);
    if (!profile.targetPin.endpoint.startsWith("https://")) p.push("pin uç noktası https olmalı");
    if (profile.credentialSource.kind !== "static") p.push(`kimlik kaynağı henüz desteklenmiyor: ${profile.credentialSource.kind}`);
    if (riskRank(profile.classCeiling) > riskRank("deploy")) p.push(`${this.profileKind} profilleri en çok 'deploy' tavanlı olabilir (destroy aracı yok)`);
    return p;
  }

  resolveTarget(tool: string, args: unknown, profile: Profile): Target {
    const a = (args ?? {}) as Args;
    const repo = assertRepo(str(a, "repo") ?? "");
    if (tool === "pipeline.runs.list" || tool === "scm.commit.list") parseSince(str(a, "since") ?? "");
    if (tool === "scm.file.read") {
      const why = pathProblem(str(a, "path") ?? "");
      if (why) throw new OpsError("path_denied", `yol reddedildi: ${why}`);
    }
    if (tool === "scm.pr.create") validatePr({ ...(a as unknown as PrArgs), repo });
    return { profileId: profile.id, kind: profile.kind, endpoint: profile.targetPin.endpoint, scopes: [repo], refs: this.refsFor(tool, a, repo) };
  }

  protected client(handle: CredentialHandle | null, profile: Profile, call: { maxBytes: number; timeoutMs: number; signal?: AbortSignal; allowWrite?: boolean }): GithubClient {
    if (!handle) throw new OpsError("lease_inactive", "kimlik tutamacı yok");
    return new GithubClient(this.resolver.token(handle), profile.targetPin, {
      maxBytes: call.maxBytes,
      timeoutMs: call.timeoutMs,
      ...(call.signal ? { signal: call.signal } : {}),
      ...(call.allowWrite ? { allowWrite: true } : {}),
    });
  }

  protected callClient(call: AdapterCall): GithubClient {
    return this.client(call.handle, call.profile, { maxBytes: Math.min(call.limits.maxBytes * 2, 2_000_000), timeoutMs: call.limits.timeoutMs, signal: call.signal, allowWrite: WRITE_NAMES.has(call.tool) });
  }

  /** Mutasyon önizlemesi: salt OKUMA istemcisiyle (yazma yetkisiz). */
  async preview(call: AdapterCall): Promise<ActionPreview> {
    const a = (call.args ?? {}) as Args;
    const repo = assertRepo(str(a, "repo") ?? "");
    const c = this.client(call.handle, call.profile, { maxBytes: 2_000_000, timeoutMs: Math.min(call.limits.timeoutMs, 30_000), signal: call.signal });
    switch (call.tool) {
      case "scm.pr.create":
        return previewPr(c, { ...(a as unknown as PrArgs), repo });
      case "pipeline.run.rerun":
        return previewRerun(c, { repo, runId: a["runId"] as number, ...(a["failedOnly"] === true ? { failedOnly: true } : {}) });
      case "pipeline.run.cancel":
        return previewCancel(c, { repo, runId: a["runId"] as number });
      default:
        throw new OpsError("no_preview", `araç önizleme desteklemiyor: ${call.tool}`);
    }
  }

  async connectCheck(handle: CredentialHandle, profile: Profile): Promise<{ identity: string; targetFingerprint: string }> {
    const c = this.client(handle, profile, { maxBytes: 64_000, timeoutMs: 10_000 });
    const r = await c.get("/user");
    let identity = "bilinmiyor";
    if (r.status === 200) {
      const login = obj(JSON.parse(r.body))["login"];
      if (typeof login === "string") identity = safeName(login, 60) ?? identity;
    } else if (r.status === 401) {
      throw ghError(r, "kimlik doğrulama");
    }
    return { identity, targetFingerprint: profile.targetPin.caFingerprint ?? "system-roots" };
  }

  /**
   * Doktor: belirteç gerçekten çalışıyor mu, yazma yetkisi var mı? Klasik belirteçlerde `x-oauth-scopes`
   * yazma kapsamlarını AÇIKÇA gösterir (hata). Fine-grained/App belirteçlerinin izinleri API'den
   * ENUMERE EDİLEMEZ: bu durumda uyarı verilir (Best-effort); güvenceyi asıl olarak araç yüzünde
   * yazma aracının olmaması (yalnız GET) sağlar.
   */
  async doctor(handle: CredentialHandle, profile: Profile): Promise<DoctorReport> {
    const findings: DoctorFinding[] = [];
    const add = (severity: DoctorFinding["severity"], code: string, message: string): void => void findings.push({ severity, code, message });
    const report = (over: Partial<DoctorReport>): DoctorReport => ({
      profileId: profile.id,
      checkedAt: this.now().toISOString(),
      connected: false,
      pinOk: true,
      declaredCeiling: profile.classCeiling,
      scopesChecked: [],
      findings,
      bindable: false,
      ...over,
    });
    let client: GithubClient;
    try {
      client = this.client(handle, profile, { maxBytes: 200_000, timeoutMs: 15_000 });
    } catch (e) {
      if (e instanceof OpsError && e.code === "target_pin_mismatch") {
        add("error", "pin_mismatch", e.message);
        return report({ pinOk: false });
      }
      add("error", "connect_failed", e instanceof Error ? e.message.slice(0, 200) : "istemci kurulamadı");
      return report({});
    }
    let identity = "bilinmiyor";
    let scopesHeader: string | undefined;
    try {
      const u = await client.get("/user");
      scopesHeader = u.headers["x-oauth-scopes"];
      if (u.status === 200) identity = safeName(obj(JSON.parse(u.body))["login"], 60) ?? identity;
      else if (u.status === 401) {
        add("error", "unauthorized", "belirteç geçersiz veya süresi dolmuş");
        return report({ connected: true });
      } else add("info", "identity_unknown", "belirteç kimliği /user ile okunamadı (App/fine-grained belirteç olabilir)");
    } catch (e) {
      add("error", "connect_failed", e instanceof Error ? e.message.slice(0, 200) : "bağlantı kurulamadı");
      return report({});
    }

    let effective: RiskClass = "read";
    const raise = (c: RiskClass): void => {
      if (riskRank(c) > riskRank(effective)) effective = c;
    };
    if (scopesHeader !== undefined) {
      const scopes = scopesHeader.split(",").map((s) => s.trim()).filter(Boolean);
      const writeLike = scopes.filter((s) => s === "repo" || s === "workflow" || s === "delete_repo" || s.startsWith("write:") || s.startsWith("admin:") || s === "gist" || s === "user");
      if (writeLike.length > 0) {
        const allowsWrite = riskRank(profile.classCeiling) >= riskRank("mutate");
        add(allowsWrite ? "warn" : "error", "classic_write_scope", `klasik belirteç yazma yetkili kapsamlar içeriyor: ${writeLike.slice(0, 6).join(", ")} — ${allowsWrite ? "tavan yazmaya izin veriyor ama klasik kapsamlar geniştir (workflow/delete_repo dahil olabilir); dar fine-grained belirteç tercih edin" : "salt okunur fine-grained belirteç kullanın"}`);
        raise(writeLike.includes("delete_repo") || writeLike.includes("workflow") ? "deploy" : "mutate");
      }
    } else {
      add("warn", "permissions_unverified", "belirteç izinleri API'den doğrulanamıyor (fine-grained/App): yalnız 'Contents/Actions/Pull requests: Read-only' izinli belirteç kullanın");
    }

    const exact = profile.allowedScopes.filter((s) => !s.includes("*")).slice(0, 5);
    const checked: string[] = [];
    if (exact.length === 0) add("info", "scope_sampled", "izinli kapsam joker içeriyor: depo erişimi örneklenmedi");
    for (const repo of exact) {
      try {
        const r = await client.get(`/repos/${enc(repo)}`);
        if (r.status === 200) {
          checked.push(repo);
          const perms = obj(obj(JSON.parse(r.body))["permissions"]);
          if (perms["push"] === true || perms["admin"] === true || perms["maintain"] === true) {
            // klasik belirteçte rol = belirteç yetkisi; fine-grained'de kullanıcı rolünü yansıtabilir
            const allowsWrite = riskRank(profile.classCeiling) >= riskRank("mutate");
            add(allowsWrite ? "info" : scopesHeader !== undefined ? "error" : "warn", "repo_write_role", `${repo}: hesap bu depoya yazabiliyor (push/admin/maintain)${allowsWrite ? " — tavan yazmaya izin veriyor" : scopesHeader === undefined ? "; belirtecin salt okunur olduğunu GitHub ayarlarında doğrulayın" : ""}`);
            if (scopesHeader !== undefined) raise("mutate");
          }
        } else {
          add("warn", "repo_unreachable", `${repo}: erişilemedi (HTTP ${r.status})`);
        }
      } catch (e) {
        add("warn", "repo_unreachable", `${repo}: ${e instanceof Error ? e.message.slice(0, 120) : "hata"}`);
      }
    }
    if (exact.length > 0 && checked.length === 0) add("error", "no_repo_access", "izinli depoların hiçbirine erişilemedi");
    if (riskRank(effective) > riskRank(profile.classCeiling)) add("error", "ceiling_exceeded_by_token", `beyan edilen tavan '${profile.classCeiling}', belirtecin fiili yetkisi '${effective}'; profil oturuma bağlanmaz`);
    const bindable = !findings.some((f) => f.severity === "error");
    return report({ connected: true, identity, effectiveClass: effective, scopesChecked: checked, bindable });
  }
}


// ============================================================================================
// pipeline (GitHub Actions)
// ============================================================================================

function runItem(r: Obj): Obj {
  const created = isoOrUndefined(r["created_at"]);
  const updated = isoOrUndefined(r["updated_at"]);
  return {
    id: int(r["id"]),
    workflow: safeName(r["name"]),
    path: typeof r["path"] === "string" ? safeName(r["path"], 120) : undefined,
    sha: sha40(r["head_sha"]),
    branch: safeName(r["head_branch"]),
    event: safeName(r["event"], 40),
    status: safeName(r["status"], 40),
    conclusion: safeName(r["conclusion"], 40),
    createdAt: created,
    updatedAt: updated,
    attempt: int(r["run_attempt"]),
    actor: safeName(obj(r["actor"])["login"], 60),
    durationSec: created && updated ? Math.max(0, Math.round((Date.parse(updated) - Date.parse(created)) / 1000)) : undefined,
  };
}

export class GithubActionsAdapter extends GithubBase {
  readonly manifest: AdapterManifest;
  readonly profileKind = "pipeline" as const;

  constructor(resolver: CredentialResolver, opts: GithubAdapterOptions = {}) {
    super(resolver, opts);
    this.manifest = AdapterManifestSchema.parse({
      id: "github-actions",
      version: "0.1.0",
      contract: ADAPTER_CONTRACT,
      kind: "pipeline",
      profileKinds: ["pipeline"],
      credentialKinds: ["static"],
      capabilities: ["pagination", "log-redirect-guard", "preview", "toctou"],
      tools: PIPELINE_ALL.map((t) => t.descriptor),
    });
  }

  get definitions(): readonly ToolDefinition[] {
    return PIPELINE_ALL;
  }

  protected refsFor(tool: string, a: Args, repo: string): string[] {
    const refs = [`Repo/${repo}`];
    if (typeof a["runId"] === "number") refs.push(`Run/${a["runId"]}`);
    if (typeof a["jobId"] === "number") refs.push(`Job/${a["jobId"]}`);
    if (tool === "pipeline.workflow.definition" && typeof a["path"] === "string") refs.push(`File/${repo}/${a["path"]}`);
    return refs;
  }

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    const a = (call.args ?? {}) as Args;
    const repo = assertRepo(str(a, "repo") ?? "");
    const c = this.callClient(call);
    switch (call.tool) {
      case "pipeline.runs.list":
        return this.runsList(c, repo, a, call);
      case "pipeline.run.get": {
        const r = obj(json(await c.get(`/repos/${enc(repo)}/actions/runs/${a["runId"]}`), "koşu"));
        const item = runItem(r);
        return { data: { repo, ...item }, summary: `koşu ${String(item["id"])} ${String(item["conclusion"] ?? item["status"])}`, subjects: [`Repo/${repo}`, `Run/${String(item["id"])}`] };
      }
      case "pipeline.jobs.list":
        return this.jobsList(c, repo, a, call);
      case "pipeline.job.logs":
        return this.jobLogs(c, repo, a, call);
      case "pipeline.workflow.definition":
        return this.workflowDefinition(c, repo, a);
      case "pipeline.artifacts.list":
        return this.artifacts(c, repo, a, call);
      case "pipeline.run.rerun":
        return doRerun(c, { repo, runId: a["runId"] as number, ...(a["failedOnly"] === true ? { failedOnly: true } : {}) }, call.approvedVersion);
      case "pipeline.run.cancel":
        return doCancel(c, { repo, runId: a["runId"] as number }, call.approvedVersion);
      default:
        throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
    }
  }

  private async runsList(c: GithubClient, repo: string, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const sinceSec = parseSince(str(a, "since") ?? "");
    const limit = Math.min(typeof a["limit"] === "number" ? (a["limit"] as number) : 20, call.limits.maxItems);
    const from = new Date(this.now().getTime() - sinceSec * 1000).toISOString();
    const j = obj(
      json(
        await c.get(`/repos/${enc(repo)}/actions/runs`, { per_page: limit, created: `>=${from}`, branch: str(a, "branch"), event: str(a, "event"), status: str(a, "status") }),
        "koşu listesi",
      ),
    );
    const runs = arr(j["workflow_runs"]).map(obj);
    const items = runs.slice(0, limit).map(runItem);
    const total = int(j["total_count"]) ?? items.length;
    return {
      data: { repo, since: str(a, "since"), total, truncated: total > items.length || undefined, items },
      summary: `${items.length}/${total} koşu (${repo})`,
      truncated: total > items.length,
      subjects: [`Repo/${repo}`, ...items.flatMap((i) => (i["id"] !== undefined ? [`Run/${String(i["id"])}`] : []))].slice(0, 60),
    };
  }

  private async jobsList(c: GithubClient, repo: string, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const runId = a["runId"] as number;
    const j = obj(json(await c.get(`/repos/${enc(repo)}/actions/runs/${runId}/jobs`, { per_page: Math.min(100, call.limits.maxItems) }), "iş listesi"));
    const jobs = arr(j["jobs"]).map(obj);
    const items = jobs.map((job) => {
      const steps = arr(job["steps"]).map(obj);
      const started = isoOrUndefined(job["started_at"]);
      const done = isoOrUndefined(job["completed_at"]);
      return {
        id: int(job["id"]),
        name: safeName(job["name"]),
        status: safeName(job["status"], 40),
        conclusion: safeName(job["conclusion"], 40),
        startedAt: started,
        completedAt: done,
        durationSec: started && done ? Math.max(0, Math.round((Date.parse(done) - Date.parse(started)) / 1000)) : undefined,
        runner: safeName(job["runner_name"], 60),
        failedSteps: steps.filter((s) => s["conclusion"] === "failure").map((s) => safeName(s["name"], 80)).filter((x): x is string => x !== undefined).slice(0, 5),
        steps: steps.length,
      };
    });
    const total = int(j["total_count"]) ?? items.length;
    return {
      data: { repo, runId, total, truncated: total > items.length || undefined, items },
      summary: `${items.length} iş (koşu ${runId})`,
      truncated: total > items.length,
      subjects: [`Repo/${repo}`, `Run/${runId}`, ...items.flatMap((i) => (i.id !== undefined ? [`Job/${i.id}`] : []))],
    };
  }

  /** Günlükler GitHub'da bir blob adresine 302 ile yönlendirilir: belirteç o adrese GİTMEZ, host izinli listede olmalı. */
  private async jobLogs(c: GithubClient, repo: string, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const jobId = a["jobId"] as number;
    const tail = Math.min(typeof a["tailLines"] === "number" ? (a["tailLines"] as number) : 200, call.limits.maxItems);
    let resp = await c.get(`/repos/${enc(repo)}/actions/jobs/${jobId}/logs`);
    if (resp.status === 301 || resp.status === 302 || resp.status === 303 || resp.status === 307 || resp.status === 308) {
      const loc = resp.headers["location"];
      let u: URL;
      try {
        u = new URL(loc ?? "");
      } catch {
        throw new OpsError("log_redirect_invalid", "günlük yönlendirme adresi geçersiz");
      }
      const extra = (call.profile.attributes["logHosts"] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
      if (!isAllowedLogHost(c.host, u, extra)) {
        throw new OpsError("log_redirect_denied", `günlük yönlendirmesi izinli olmayan host'a: ${u.hostname.slice(0, 60)} (profilde logHosts ile izin verilebilir)`);
      }
      resp = await c.fetchSigned(u);
    }
    if (resp.status < 200 || resp.status >= 300) throw ghError(resp, "iş günlüğü");
    const lines = resp.body.split("\n");
    const shown = lines.length > tail ? lines.slice(-tail) : lines;
    return {
      data: shown.join("\n"),
      summary: `iş ${jobId} günlüğü: son ${shown.length}/${lines.length} satır`,
      truncated: lines.length > tail || resp.truncated,
      subjects: [`Repo/${repo}`, `Job/${jobId}`, ...(typeof a["runId"] === "number" ? [`Run/${a["runId"]}`] : [])],
    };
  }

  private async workflowDefinition(c: GithubClient, repo: string, a: Args): Promise<RawToolOutput> {
    const path = str(a, "path") as string;
    const r = obj(json(await c.get(`/repos/${enc(repo)}/contents/${path.split("/").map(encodeURIComponent).join("/")}`, { ref: str(a, "ref") }), "workflow dosyası"));
    if (r["type"] !== "file" || r["encoding"] !== "base64" || typeof r["content"] !== "string") throw new OpsError("github_error", "workflow dosyası okunamadı");
    const text = Buffer.from(r["content"], "base64").toString("utf8");
    const facts = workflowFacts(path, text);
    return { data: { repo, ref: str(a, "ref"), ...facts }, summary: `${path}: ${facts.jobs.length} iş, ${facts.riskyTriggers.length} riskli tetikleyici`, subjects: [`Repo/${repo}`, `File/${repo}/${path}`] };
  }

  private async artifacts(c: GithubClient, repo: string, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const runId = a["runId"] as number;
    const j = obj(json(await c.get(`/repos/${enc(repo)}/actions/runs/${runId}/artifacts`, { per_page: Math.min(50, call.limits.maxItems) }), "artefakt listesi"));
    const items = arr(j["artifacts"]).map(obj).map((x) => ({
      id: int(x["id"]),
      name: safeName(x["name"]),
      sizeBytes: int(x["size_in_bytes"]),
      expired: x["expired"] === true,
      createdAt: isoOrUndefined(x["created_at"]),
      digest: typeof x["digest"] === "string" && /^sha256:[0-9a-f]{64}$/.test(x["digest"]) ? x["digest"] : undefined,
    }));
    const total = int(j["total_count"]) ?? items.length;
    return { data: { repo, runId, total, truncated: total > items.length || undefined, items }, summary: `${items.length} artefakt (koşu ${runId})`, truncated: total > items.length, subjects: [`Repo/${repo}`, `Run/${runId}`] };
  }
}

// ============================================================================================
// scm
// ============================================================================================

const commitItem = (c: Obj): Obj => {
  const commit = obj(c["commit"]);
  const author = obj(commit["author"]);
  return {
    sha: sha40(c["sha"]),
    author: safeName(obj(c["author"])["login"] ?? author["name"], 60),
    date: isoOrUndefined(author["date"] ?? obj(commit["committer"])["date"]),
    message: typeof commit["message"] === "string" ? commit["message"].split("\n")[0]?.slice(0, 120) : undefined,
  };
};

export class GithubScmAdapter extends GithubBase {
  readonly manifest: AdapterManifest;
  readonly profileKind = "scm" as const;

  constructor(resolver: CredentialResolver, opts: GithubAdapterOptions = {}) {
    super(resolver, opts);
    this.manifest = AdapterManifestSchema.parse({
      id: "github-scm",
      version: "0.1.0",
      contract: ADAPTER_CONTRACT,
      kind: "scm",
      profileKinds: ["scm"],
      credentialKinds: ["static"],
      capabilities: ["pagination", "secret-path-denylist", "preview", "toctou"],
      tools: SCM_ALL.map((t) => t.descriptor),
    });
  }

  get definitions(): readonly ToolDefinition[] {
    return SCM_ALL;
  }

  protected refsFor(tool: string, a: Args, repo: string): string[] {
    const refs = [`Repo/${repo}`];
    if (tool === "scm.file.read" && typeof a["path"] === "string") refs.push(`File/${repo}/${a["path"]}`);
    if (tool === "scm.pr.create" && Array.isArray(a["files"])) {
      for (const f of a["files"]) if (f !== null && typeof f === "object" && typeof (f as Obj)["path"] === "string") refs.push(`File/${repo}/${String((f as Obj)["path"])}`);
    }
    return refs;
  }

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    const a = (call.args ?? {}) as Args;
    const repo = assertRepo(str(a, "repo") ?? "");
    // araç girişinde TEKRAR: PEP'e güvenmeden
    if (call.tool === "scm.file.read") {
      const why = pathProblem(str(a, "path") ?? "");
      if (why) throw new OpsError("path_denied", `yol reddedildi: ${why}`);
    }
    const c = this.callClient(call);
    switch (call.tool) {
      case "scm.file.read":
        return this.fileRead(c, repo, a, call);
      case "scm.diff.get":
        return this.diff(c, repo, a, call);
      case "scm.pr.list":
        return this.prList(c, repo, a, call);
      case "scm.commit.list":
        return this.commitList(c, repo, a, call);
      case "scm.pr.create":
        return doPr(c, { ...(a as unknown as PrArgs), repo }, call.approvedVersion);
      default:
        throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
    }
  }

  private async fileRead(c: GithubClient, repo: string, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const path = str(a, "path") as string;
    const r = obj(json(await c.get(`/repos/${enc(repo)}/contents/${path.split("/").map(encodeURIComponent).join("/")}`, { ref: str(a, "ref") }), "dosya"));
    if (r["type"] !== "file") throw new OpsError("github_error", "yol bir dosya değil");
    if (r["encoding"] !== "base64" || typeof r["content"] !== "string") throw new OpsError("file_too_large", "dosya içeriği API'den dönmedi (çok büyük olabilir)");
    const buf = Buffer.from(r["content"], "base64");
    if (buf.includes(0)) throw new OpsError("file_binary", "ikili dosya okunmaz");
    const lines = buf.toString("utf8").split("\n");
    const start = Math.max(1, typeof a["startLine"] === "number" ? (a["startLine"] as number) : 1);
    const max = Math.min(typeof a["maxLines"] === "number" ? (a["maxLines"] as number) : 200, call.limits.maxItems);
    const slice = lines.slice(start - 1, start - 1 + max);
    return {
      data: { repo, path, ref: str(a, "ref"), totalLines: lines.length, startLine: start, shownLines: slice.length, content: slice.join("\n") },
      summary: `${path} satır ${start}-${start + slice.length - 1}/${lines.length}`,
      truncated: start - 1 + max < lines.length,
      subjects: [`Repo/${repo}`, `File/${repo}/${path}`],
    };
  }

  private async diff(c: GithubClient, repo: string, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const base = str(a, "base") as string;
    const head = str(a, "head") as string;
    const maxFiles = Math.min(typeof a["maxFiles"] === "number" ? (a["maxFiles"] as number) : 20, call.limits.maxItems);
    const j = obj(json(await c.get(`/repos/${enc(repo)}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`), "karşılaştırma"));
    const files = arr(j["files"]).map(obj);
    const items = files.slice(0, maxFiles).map((f) => {
      const filename = typeof f["filename"] === "string" ? f["filename"].slice(0, 200) : "?";
      const denied = pathProblem(filename);
      return {
        file: filename,
        status: safeName(f["status"], 20),
        additions: int(f["additions"]),
        deletions: int(f["deletions"]),
        patch: denied ? `‹yama verilmedi: ${denied}›` : typeof f["patch"] === "string" ? f["patch"].slice(0, 1_500) : undefined,
      };
    });
    const commits = arr(j["commits"]).map(obj).slice(0, 30).map(commitItem);
    return {
      data: { repo, base, head, status: safeName(j["status"], 20), aheadBy: int(j["ahead_by"]), behindBy: int(j["behind_by"]), commits, files: items, truncated: files.length > items.length || undefined, totalFiles: files.length },
      summary: `${items.length}/${files.length} dosya, ${commits.length} commit`,
      truncated: files.length > items.length,
      subjects: [`Repo/${repo}`, ...items.slice(0, 20).map((i) => `File/${repo}/${i.file}`)],
    };
  }

  private async prList(c: GithubClient, repo: string, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const limit = Math.min(typeof a["limit"] === "number" ? (a["limit"] as number) : 20, call.limits.maxItems);
    const j = arr(json(await c.get(`/repos/${enc(repo)}/pulls`, { state: str(a, "state") ?? "open", per_page: limit, sort: "updated", direction: "desc" }), "pull request listesi")).map(obj);
    const items = j.slice(0, limit).map((p) => ({
      number: int(p["number"]),
      state: safeName(p["state"], 20),
      draft: p["draft"] === true || undefined,
      author: safeName(obj(p["user"])["login"], 60),
      head: safeName(obj(p["head"])["ref"], 80),
      headSha: sha40(obj(p["head"])["sha"]),
      base: safeName(obj(p["base"])["ref"], 80),
      createdAt: isoOrUndefined(p["created_at"]),
      updatedAt: isoOrUndefined(p["updated_at"]),
      mergedAt: isoOrUndefined(p["merged_at"]),
      title: typeof p["title"] === "string" ? p["title"].slice(0, 120) : undefined,
    }));
    return { data: { repo, total: items.length, truncated: j.length > items.length || undefined, items }, summary: `${items.length} PR (${repo})`, truncated: j.length > items.length, subjects: [`Repo/${repo}`, ...items.flatMap((i) => (i.number !== undefined ? [`PR/${repo}#${i.number}`] : []))] };
  }

  private async commitList(c: GithubClient, repo: string, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const sinceSec = parseSince(str(a, "since") ?? "");
    const limit = Math.min(typeof a["limit"] === "number" ? (a["limit"] as number) : 20, call.limits.maxItems);
    const from = new Date(this.now().getTime() - sinceSec * 1000).toISOString();
    const j = arr(json(await c.get(`/repos/${enc(repo)}/commits`, { per_page: limit, since: from, sha: str(a, "branch") }), "commit listesi")).map(obj);
    const items = j.slice(0, limit).map(commitItem);
    return { data: { repo, since: str(a, "since"), total: items.length, truncated: j.length > items.length || undefined, items }, summary: `${items.length} commit (${repo})`, truncated: j.length > limit, subjects: [`Repo/${repo}`, ...items.flatMap((i) => (i["sha"] ? [`Commit/${repo}@${String(i["sha"]).slice(0, 12)}`] : []))] };
  }
}

