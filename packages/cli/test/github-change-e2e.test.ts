import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { OrchestratorEvent } from "@ops/core";
import { BUILD_REPO, CaptureSink, FakeGithubApi, ScriptedProvider, makeCanary, say, seedBuildDeploy, toolUse } from "@ops/testkit";
import { TtyApprovalGate, createRuntime, renderEvent, runCli } from "../src/index.ts";
import type { TtyIo } from "../src/index.ts";
import { idsIn, makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

function fakeTty(answers: string[]): { open: () => Promise<TtyIo>; shown: () => string } {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  let i = 0;
  output.on("data", (b: Buffer) => {
    chunks.push(b.toString());
    if (/: $|> $/.test(chunks.join("").slice(-12))) {
      const a = answers[i++];
      if (a !== undefined) setTimeout(() => input.write(`${a}\n`), 0);
    }
  });
  return { open: async () => ({ input, output }), shown: () => chunks.join("") };
}

describe("Faz 2c: GitHub değişikliği uçtan uca (CLI profil + scripted model + TTY onayı + sahte GitHub)", () => {
  let fx: Fixture;
  let gh: FakeGithubApi;
  const c = { token: makeCanary("gh-token"), logSecret: makeCanary("gh-log"), workflowSecret: makeCanary("gh-wf"), envFileSecret: makeCanary("gh-env") };
  beforeEach(async () => {
    fx = await makeFixture({ addProfile: false });
    gh = await FakeGithubApi.start({ pki: fx.pki, token: c.token.value });
    seedBuildDeploy(gh, c);
    gh.repo(BUILD_REPO).permissions.push = true;
    await fx.rt.close();
  });
  afterEach(async () => {
    await gh.stop();
    await fx.cleanup();
  });

  const cli = async (argv: string[], env: Record<string, string> = {}) => {
    const io = { input: new PassThrough(), output: new PassThrough(), error: new PassThrough() };
    const code = await runCli({ argv, env, io, paths: fx.rt.paths, store: fx.store, sandbox: null });
    return { code, out: (io.output.read() as Buffer | null)?.toString() ?? "", err: (io.error.read() as Buffer | null)?.toString() ?? "" };
  };

  it("`ops profile add scm --ceiling mutate` → doktor bağlanır → model PR önerir → TTY'de 'evet' → taslak PR; reddedilen ikinci PR hiçbir şey yazmaz; canary yok", async () => {
    const tokFile = join(fx.home, "gh-token");
    await writeFile(tokFile, `${c.token.value}\n`, { mode: 0o600 });
    const caFile = join(fx.home, "ca.pem");
    await writeFile(caFile, fx.pki.caPem);
    const add = await cli(["profile", "add", "scm", "--id", "git", "--env", "sandbox", "--scope", BUILD_REPO, "--api-url", gh.url, "--ca-file", caFile, "--ceiling", "mutate"], { OPS_GITHUB_TOKEN_FILE: tokFile });
    expect(add.code, add.err).toBe(0);
    const doc = await cli(["profile", "doctor", "git"]);
    expect(doc.code, doc.out).toBe(0);
    expect(doc.out).toMatch(/BAĞLANABİLİR/);

    const tty = fakeTty(["evet", ""]); // 1. PR onay, 2. PR ret
    const gate = new TtyApprovalGate({ openTty: tty.open, sleep: async () => undefined });
    const rt = await createRuntime({ paths: fx.rt.paths, store: fx.store, sandbox: null, approval: gate });
    const ev: OrchestratorEvent[] = [];
    let provider!: ScriptedProvider;
    try {
      expect((await rt.bindProfile("git")).bindable).toBe(true);
      expect(rt.skills.all().map((s) => s.name)).toEqual(expect.arrayContaining(["github-change", "pipelines"]));
      expect(rt.skills.all().map((s) => s.name)).not.toContain("kubernetes"); // k8s profili yok → skill ilan edilmez
      const pr = (branch: string, ids: string[]) => ({
        repo: BUILD_REPO, base: "main", branch, title: "batch boyutunu düşür", body: "BATCH 5000 → 500",
        files: [{ path: "src/app.ts", content: "export const x = 2;\nexport const BATCH = 500;\n" }],
        cited: [ids[1]],
      });
      provider = new ScriptedProvider(
        [
          toolUse([{ name: "skill.load", args: { name: "github-change" } }]),
          toolUse([{ name: "scm.file.read", args: { repo: BUILD_REPO, path: "src/app.ts" } }]),
          (req) => toolUse([{ name: "scm.pr.create", args: pr("ops/batch-500", idsIn(req.messages)) }]),
          (req) => toolUse([{ name: "scm.pr.create", args: pr("ops/batch-501", idsIn(req.messages)) }]),
          (req) => toolUse([{ name: "scm.pr.create", args: { ...pr("ops/ci-yaml", idsIn(req.messages)), files: [{ path: ".github/workflows/deploy.yml", content: "name: x\n" }] } }]),
          (req) => say(`Taslak PR açıldı [${idsIn(req.messages)[2]}]; ikincisi reddedildi; CI tanımına yazma engellendi.`),
        ],
        { trustZone: "tenant-cloud" },
      );
      const orch = rt.createOrchestrator(provider, { maxIterations: 20 });
      for await (const e of orch.send("batch boyutunu düşüren bir PR aç")) ev.push(e);
      const results = ev.filter((e): e is Extract<OrchestratorEvent, { type: "tool_result" }> => e.type === "tool_result");
      expect(results.filter((r) => r.name === "scm.pr.create").map((r) => [r.status, r.reasonCode])).toEqual([["ok", undefined], ["denied", "approval_denied"], ["denied", "target_unresolved"]]);
      const repo = gh.repo(BUILD_REPO);
      expect(repo.pulls.filter((p) => p.number >= 100).map((p) => [p.head_ref, p.draft])).toEqual([["ops/batch-500", true]]);
      expect(repo.branches["ops/batch-501"]).toBeUndefined();
      expect(repo.files["src/app.ts"]).toBe("export const x = 1;\n"); // main değişmedi
      const writes = gh.requests.filter((q) => q.method !== "GET").map((q) => `${q.method} ${q.path.replace(`/repos/${BUILD_REPO}`, "")}`);
      expect(writes).toEqual(["POST /git/refs", "PUT /contents/src/app.ts", "POST /pulls"]);
      // onay ekranı
      const shown = tty.shown();
      expect(shown).toContain("scm.pr.create");
      expect(shown).toContain("+export const BATCH = 500;");
      expect(shown).toMatch(/TASLAK PR hedef 'main'/);
      expect(shown).toContain("Geri alma: PR'ı kapatın ve 'ops/batch-500' dalını silin");
      // canary taraması: denetim, kanıt, sağlayıcı, arayüz, onay ekranı
      const sink = new CaptureSink();
      sink.push("audit", await readFile(rt.paths.auditLog, "utf8"));
      for (const e of rt.evidence.all()) sink.push("evidence", e.text);
      sink.push("sağlayıcı", provider.serialized.join("\n"));
      sink.push("ui", ev.map((e) => renderEvent(e) ?? "").join("\n"));
      sink.push("onay", shown);
      expect(sink.leaks(Object.values(c))).toEqual([]);
      expect(gh.blobRequests).toEqual([]);
    } finally {
      await rt.close();
    }
    expect((await cli(["audit", "verify"])).code).toBe(0);
  }, 60_000);

  it("read tavanlı (varsayılan) scm profili: PR aracı PEP'te reddedilir, sunucuya yazma gitmez", async () => {
    const tokFile = join(fx.home, "gh-token2");
    await writeFile(tokFile, `${c.token.value}\n`, { mode: 0o600 });
    const caFile = join(fx.home, "ca2.pem");
    await writeFile(caFile, fx.pki.caPem);
    await cli(["profile", "add", "scm", "--id", "git", "--env", "sandbox", "--scope", BUILD_REPO, "--api-url", gh.url, "--ca-file", caFile], { OPS_GITHUB_TOKEN_FILE: tokFile });
    const rt = await createRuntime({ paths: fx.rt.paths, store: fx.store, sandbox: null });
    try {
      await rt.bindProfile("git");
      const r = await rt.gateway.invoke({ tool: "scm.pr.create", profile: "git", providerZone: "local", args: { repo: BUILD_REPO, base: "main", branch: "ops/x", title: "x y z", files: [{ path: "a.txt", content: "x" }] }, citedEvidence: [] });
      expect(r).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
      expect(gh.requests.filter((q) => q.method !== "GET")).toEqual([]);
    } finally {
      await rt.close();
    }
  });
});
