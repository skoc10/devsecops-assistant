import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { BUILD_REPO, FakeApprovalGate, gitBlobSha } from "@ops/testkit";
import { GithubClient, validatePr } from "../src/index.ts";
import { makeGhHarness } from "./harness.ts";
import type { GhHarness } from "./harness.ts";

let h: GhHarness | undefined;
afterEach(async () => {
  await h?.stop();
  h = undefined;
});

const writes = (x: GhHarness) => x.api.requests.filter((r) => r.method !== "GET");
const prArgs = (over: Record<string, unknown> = {}) => ({
  repo: BUILD_REPO,
  base: "main",
  branch: "ops/raise-replicas",
  title: "api: replika sayısını artır",
  body: "payments/api için replika 2 → 3",
  files: [
    { path: "src/app.ts", content: "export const x = 2;\n" },
    { path: "k8s/api.yaml", content: "spec:\n  replicas: 3\n" },
  ],
  ...over,
});

async function scm(ceiling: "read" | "mutate" | "deploy" = "mutate", gate = new FakeApprovalGate(), extra: Parameters<typeof makeGhHarness>[0] = {}) {
  h = await makeGhHarness({ kind: "scm", profile: { classCeiling: ceiling }, approval: gate, ...extra });
  h.api.repo(BUILD_REPO).permissions.push = true;
  const ev = await h.call("scm.pr.list", { repo: BUILD_REPO });
  expect(ev.status, JSON.stringify(ev)).toBe("ok");
  return { h, gate, ev: ev.evidenceId as string };
}
async function pipe(ceiling: "read" | "mutate" | "deploy" = "deploy", gate = new FakeApprovalGate(), extra: Parameters<typeof makeGhHarness>[0] = {}) {
  h = await makeGhHarness({ kind: "pipeline", profile: { classCeiling: ceiling }, approval: gate, ...extra });
  const ev = await h.call("pipeline.run.get", { repo: BUILD_REPO, runId: 9002 });
  expect(ev.status, JSON.stringify(ev)).toBe("ok");
  return { h, gate, ev: ev.evidenceId as string };
}

describe("scm.pr.create", () => {
  it("önizleme (diff, etki) + onay → yeni dal, dosya commit'leri (güncelleme sha ön koşuluyla), TASLAK PR; hedef dala doğrudan yazı YOK", async () => {
    const { h, gate, ev } = await scm();
    const r = await h.call("scm.pr.create", prArgs(), { cited: [ev] });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(h.evidenceJson(r)).toMatchObject({ created: true, pr: 100, head: "ops/raise-replicas", base: "main", draft: true, files: 2 });
    // onay özeti
    const sum = gate.requests[0]!.summary;
    expect(sum).toMatchObject({ tool: "scm.pr.create", class: "mutate" });
    expect(sum.preview?.diff).toContain("+export const x = 2;");
    expect(sum.preview?.diff).toContain("-export const x = 1;");
    expect(sum.preview?.impact?.[0]).toMatch(/2 dosya \(1 yeni, 1 değişen\).*TASLAK PR hedef 'main'/);
    expect(sum.preview?.targetVersion).toMatch(/^b{40}:[0-9a-f]{16}$/);
    // sunucudaki durum
    const repo = h.api.repo(BUILD_REPO);
    expect(repo.branchFiles["ops/raise-replicas"]).toMatchObject({ "src/app.ts": "export const x = 2;\n", "k8s/api.yaml": "spec:\n  replicas: 3\n" });
    expect(repo.files["src/app.ts"]).toBe("export const x = 1;\n"); // hedef dal DEĞİŞMEDİ
    expect(repo.pulls.at(-1)).toMatchObject({ number: 100, draft: true, head_ref: "ops/raise-replicas", base_ref: "main" });
    // yazma istekleri: yalnız yeni dal + o dala PUT + PR
    const w = writes(h).map((q) => `${q.method} ${q.path.replace(`/repos/${BUILD_REPO}`, "")}`);
    expect(w).toEqual(["POST /git/refs", "PUT /contents/src/app.ts", "PUT /contents/k8s/api.yaml", "POST /pulls"]);
    for (const q of writes(h).filter((x) => x.method === "PUT")) expect(JSON.parse(q.body).branch).toBe("ops/raise-replicas");
    // güncelleme PUT'u gerçek blob sha'sını taşıdı
    const put = writes(h).find((q) => q.path.endsWith("/src/app.ts"));
    expect(JSON.parse(put!.body).sha).toBe(gitBlobSha("export const x = 1;\n"));
    // belirteç yalnız pinli hosta (hepsi aynı sunucu) ve Bearer olarak gitti
    expect(writes(h).every((q) => q.authorization === `Bearer ${h.canaries.token.value}`)).toBe(true);
  });

  it("read tavanlı profilde reddedilir; sunucuya yazma isteği gitmez", async () => {
    const { h, ev } = await scm("read");
    expect(await h.call("scm.pr.create", prArgs(), { cited: [ev] })).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    expect(writes(h)).toEqual([]);
  });

  const bad: [string, Record<string, unknown>, RegExp][] = [
    ["CI tanımı yolu", { files: [{ path: ".github/workflows/deploy.yml", content: "name: x\n" }] }, /yazma yasak.*CI/],
    ["gizli dosya yolu", { files: [{ path: "prod.tfvars", content: "a = 1\n" }] }, /gizli dosya deseni/],
    ["state dosyası", { files: [{ path: "terraform.tfstate", content: "{}" }] }, /gizli dosya deseni/],
    ["yol kaçışı", { files: [{ path: "../etc/passwd", content: "x" }] }, /yol/],
    ["yinelenen yol", { files: [{ path: "a.txt", content: "1" }, { path: "a.txt", content: "2" }] }, /yinelenen/],
    ["secret içerik", { files: [{ path: "a.txt", content: "key: AKIAABCDEFGHIJKLMNOP" }] }, /secret benzeri/],
    ["secret başlık", { title: "anahtar AKIAABCDEFGHIJKLMNOP" }, /secret benzeri/],
    ["baş dal = hedef dal", { branch: "ops/x", base: "ops/x" }, /aynı olamaz/],
  ];
  for (const [label, over, re] of bad) {
    it(`reddeder: ${label}`, async () => {
      const { h, ev } = await scm();
      const before = h.api.requests.length;
      const r = await h.call("scm.pr.create", prArgs(over), { cited: [ev] });
      expect(r.status, label).toBe("denied");
      expect(r.summary, label).toMatch(re);
      expect(h.api.requests.length).toBe(before); // API'ye hiç gidilmedi
    });
  }

  it("şema: 'ops/' önekli olmayan baş dal ve 20'den çok dosya reddedilir", async () => {
    const { h, ev } = await scm();
    expect(await h.call("scm.pr.create", prArgs({ branch: "main" }), { cited: [ev] })).toMatchObject({ reasonCode: "schema_invalid" });
    expect(await h.call("scm.pr.create", prArgs({ branch: "feature/x" }), { cited: [ev] })).toMatchObject({ reasonCode: "schema_invalid" });
    const many = Array.from({ length: 21 }, (_, i) => ({ path: `f${i}.txt`, content: "x" }));
    expect(await h.call("scm.pr.create", prArgs({ files: many }), { cited: [ev] })).toMatchObject({ reasonCode: "schema_invalid" });
  });

  it("baş dal zaten varsa önizleme reddeder (onay İSTENMEZ)", async () => {
    const { h, gate, ev } = await scm();
    h.api.repo(BUILD_REPO).branches["ops/raise-replicas"] = "c".repeat(40);
    const r = await h.call("scm.pr.create", prArgs(), { cited: [ev] });
    expect(r).toMatchObject({ status: "denied", reasonCode: "preview_failed" });
    expect(r.summary).toMatch(/zaten var/);
    expect(gate.requests).toHaveLength(0);
  });

  it("S-09: onay sırasında hedef dal ilerlerse (yeni commit) PR AÇILMAZ (target_changed); dal oluşmaz", async () => {
    let hh!: GhHarness;
    const s = await scm("mutate", new FakeApprovalGate(() => {
      hh.api.repo(BUILD_REPO).branches["main"] = "d".repeat(40);
      return true;
    }));
    hh = s.h;
    const r = await hh.call("scm.pr.create", prArgs(), { cited: [s.ev] });
    expect(r).toMatchObject({ status: "denied", reasonCode: "target_changed" });
    expect(writes(hh)).toEqual([]);
    expect(hh.api.repo(BUILD_REPO).branches["ops/raise-replicas"]).toBeUndefined();
  });

  it("S-09: onay sırasında DOSYA değişirse de açılmaz (blob sha özeti sürüme dahil)", async () => {
    let hh!: GhHarness;
    const s = await scm("mutate", new FakeApprovalGate(() => {
      hh.api.repo(BUILD_REPO).files["src/app.ts"] = "export const x = 99;\n";
      return true;
    }));
    hh = s.h;
    expect(await hh.call("scm.pr.create", prArgs(), { cited: [s.ev] })).toMatchObject({ reasonCode: "target_changed" });
    expect(writes(hh)).toEqual([]);
  });

  it("yarım kalan işlem: ikinci dosya yazımı başarısız → oluşturulan dal geri alınır, PR açılmaz, kullanıcıya bildirilir", async () => {
    const { h, ev } = await scm();
    const repo = h.api.repo(BUILD_REPO);
    repo.failPut.push("k8s/api.yaml");
    const r = await h.call("scm.pr.create", prArgs(), { cited: [ev] });
    expect(r.status).toBe("error");
    expect(r.summary).toMatch(/dosyalar adımında hata.*geri alındı/);
    expect(repo.pulls.some((p) => p.head_ref === "ops/raise-replicas")).toBe(false);
    expect(repo.branches["ops/raise-replicas"]).toBeUndefined();
    expect(writes(h).map((q) => q.method)).toEqual(["POST", "PUT", "PUT", "DELETE"]);
  });

  it("belirteç izni yok (403): anlamlı hata, hiçbir dal/PR kalmaz", async () => {
    const { h, ev } = await scm("mutate", new FakeApprovalGate(), { forbidWrites: true });
    const r = await h.call("scm.pr.create", prArgs(), { cited: [ev] });
    expect(r.status).toBe("error");
    expect(r.summary).toMatch(/erişim yok|belirtecin izni/);
    expect(h.api.repo(BUILD_REPO).pulls.some((p) => p.head_ref === "ops/raise-replicas")).toBe(false);
  });

  it("onay reddedilirse yazma yok; canary denetim/kanıt/onay özetinde yok", async () => {
    const { h, gate, ev } = await scm("mutate", new FakeApprovalGate(() => false));
    const r = await h.call("scm.pr.create", prArgs(), { cited: [ev] });
    expect(r).toMatchObject({ reasonCode: "approval_denied" });
    expect(writes(h)).toEqual([]);
    const sink = await h.sinkFor([r]);
    sink.push("onay", JSON.stringify(gate.requests));
    expect(sink.leaks(h.all)).toEqual([]);
  });

  it("GithubClient: yazma izni olmayan istemci POST/PUT/DELETE yapamaz", async () => {
    const { h } = await scm();
    const lease = await h.broker.acquire({ profile: h.profile, purpose: "t", callId: "c", ttlSec: 60 }, h.known);
    try {
      const c = new GithubClient(h.broker.resolver.token(lease.handle), h.profile.targetPin, { maxBytes: 10_000, timeoutMs: 5_000 });
      expect(() => c.post("/repos/a/b/git/refs", {})).toThrow(/salt okunur/);
      expect(() => c.put("/repos/a/b/contents/x", {})).toThrow(/salt okunur/);
      expect(() => c.del("/repos/a/b/git/refs/heads/x")).toThrow(/salt okunur/);
    } finally {
      await lease.release();
    }
  });

  it("validatePr birimi: geçerli içerik geçer", () => {
    expect(() => validatePr({ repo: BUILD_REPO, base: "main", branch: "ops/x", title: "t t", files: [{ path: "a/b.txt", content: "x" }] })).not.toThrow();
    expect(randomBytes(1).length).toBe(1);
  });
});

describe("pipeline.run.rerun / cancel", () => {
  it("rerun (deploy): tamamlanmış koşu; önizleme koşuyu ve dağıtım uyarısını gösterir; deneme sayısı artar", async () => {
    const { h, gate, ev } = await pipe("deploy");
    const r = await h.call("pipeline.run.rerun", { repo: BUILD_REPO, runId: 9002 }, { cited: [ev] });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    const sum = gate.requests[0]!.summary;
    expect(sum).toMatchObject({ tool: "pipeline.run.rerun", class: "deploy" });
    expect(sum.preview?.targetVersion).toBe("completed/failure/2");
    expect(sum.preview?.impact?.join("\n")).toMatch(/deneme 2 → 3.*feature\/x/);
    expect(sum.preview?.impact?.join("\n")).toMatch(/deploy tetiklenebilir/);
    const run = h.api.repo(BUILD_REPO).runs.find((x) => x.id === 9002)!;
    expect(run).toMatchObject({ status: "queued", run_attempt: 3 });
    expect(writes(h).map((q) => `${q.method} ${q.path.replace(`/repos/${BUILD_REPO}`, "")}`)).toEqual(["POST /actions/runs/9002/rerun"]);
  });

  it("failedOnly: rerun-failed-jobs uç noktası", async () => {
    const { h, ev } = await pipe("deploy");
    const r = await h.call("pipeline.run.rerun", { repo: BUILD_REPO, runId: 9002, failedOnly: true }, { cited: [ev] });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(writes(h)[0]!.path).toMatch(/rerun-failed-jobs$/);
  });

  it("mutate tavan: rerun (deploy) reddedilir, cancel (mutate) çalışır; read tavan: ikisi de reddedilir", async () => {
    const { h, ev } = await pipe("mutate");
    h.api.repo(BUILD_REPO).runs.push({ id: 9100, name: "ci", path: ".github/workflows/ci.yml", head_sha: "5".repeat(40), head_branch: "feature/y", event: "push", status: "in_progress", conclusion: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), run_attempt: 1, actor: "dev", display_title: "x" });
    expect(await h.call("pipeline.run.rerun", { repo: BUILD_REPO, runId: 9002 }, { cited: [ev] })).toMatchObject({ reasonCode: "ceiling_exceeded" });
    const get = await h.call("pipeline.run.get", { repo: BUILD_REPO, runId: 9100 });
    const r = await h.call("pipeline.run.cancel", { repo: BUILD_REPO, runId: 9100 }, { cited: [get.evidenceId as string] });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(h.api.repo(BUILD_REPO).runs.find((x) => x.id === 9100)).toMatchObject({ status: "completed", conclusion: "cancelled" });
    const ro = await pipe("read");
    expect(await ro.h.call("pipeline.run.cancel", { repo: BUILD_REPO, runId: 9100 }, { cited: [ro.ev] })).toMatchObject({ reasonCode: "ceiling_exceeded" });
  });

  it("durum uyuşmazlığı: süren koşu rerun edilemez, tamamlanmış koşu iptal edilemez (önizleme ret; onay istenmez)", async () => {
    const { h, gate, ev } = await pipe("deploy");
    expect(await h.call("pipeline.run.cancel", { repo: BUILD_REPO, runId: 9002 }, { cited: [ev] })).toMatchObject({ reasonCode: "preview_failed" });
    h.api.repo(BUILD_REPO).runs.find((x) => x.id === 9002)!.status = "in_progress";
    expect(await h.call("pipeline.run.rerun", { repo: BUILD_REPO, runId: 9002 }, { cited: [ev] })).toMatchObject({ reasonCode: "preview_failed" });
    expect(gate.requests).toHaveLength(0);
    expect(writes(h)).toEqual([]);
  });

  it("S-09: onay sırasında koşu yeniden çalıştırılırsa (deneme sayısı değişti) uygulanmaz", async () => {
    let hh!: GhHarness;
    const s = await pipe("deploy", new FakeApprovalGate(() => {
      hh.api.repo(BUILD_REPO).runs.find((x) => x.id === 9002)!.run_attempt = 3;
      return true;
    }));
    hh = s.h;
    expect(await hh.call("pipeline.run.rerun", { repo: BUILD_REPO, runId: 9002 }, { cited: [s.ev] })).toMatchObject({ reasonCode: "target_changed" });
    expect(writes(hh)).toEqual([]);
  });
});

describe("doktor: tavan farkındalığı", () => {
  it("mutate tavanlı profilde klasik 'repo' kapsamı uyarıdır (bağlanır); read tavanlıda hata (bağlanmaz)", async () => {
    const mutate = await makeGhHarness({ kind: "scm", oauthScopes: "repo", profile: { classCeiling: "mutate" } });
    try {
      const r = await mutate.doctor();
      expect(r).toMatchObject({ bindable: true, effectiveClass: "mutate", declaredCeiling: "mutate" });
      expect(r.findings.find((f) => f.code === "classic_write_scope")?.severity).toBe("warn");
    } finally {
      await mutate.stop();
    }
    const read = await makeGhHarness({ kind: "scm", oauthScopes: "repo" });
    try {
      const r = await read.doctor();
      expect(r.bindable).toBe(false);
      expect(r.findings.find((f) => f.code === "classic_write_scope")?.severity).toBe("error");
    } finally {
      await read.stop();
    }
  });

  it("belirteç tavanı aşıyorsa bağlanmaz: mutate tavan + 'workflow'/'delete_repo' kapsamı (deploy düzeyi) → ceiling_exceeded_by_token", async () => {
    const x = await makeGhHarness({ kind: "scm", oauthScopes: "repo, workflow", profile: { classCeiling: "mutate" } });
    try {
      const r = await x.doctor();
      expect(r.bindable).toBe(false);
      expect(r.findings.map((f) => f.code)).toContain("ceiling_exceeded_by_token");
    } finally {
      await x.stop();
    }
  });
});
