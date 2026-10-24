import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildTokenCredential } from "@ops/broker";
import type { OrchestratorEvent } from "@ops/core";
import { BUILD_DIGEST, BUILD_REPO, BUILD_SHA, CaptureSink, FakeGithubApi, ScriptedProvider, makeCanary, say, seedBuildDeploy, toolUse } from "@ops/testkit";
import type { ScriptStep } from "@ops/testkit";
import { renderEvent, runCli } from "../src/index.ts";
import { idsIn, makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

describe("Faz 1: küme ↔ pipeline ↔ depo korelasyonu (timeline.build) — scripted model, sahte küme + sahte GitHub", () => {
  let fx: Fixture;
  let gh: FakeGithubApi;
  const ghCanaries = { token: makeCanary("gh-token"), logSecret: makeCanary("gh-log-secret"), workflowSecret: makeCanary("gh-workflow-secret"), envFileSecret: makeCanary("gh-envfile-secret") };

  beforeEach(async () => {
    fx = await makeFixture();
    gh = await FakeGithubApi.start({ pki: fx.pki, token: ghCanaries.token.value });
    seedBuildDeploy(gh, ghCanaries);
    for (const kind of ["pipeline", "scm"] as const) {
      await fx.rt.profiles.addToken({
        id: kind === "pipeline" ? "ci" : "git",
        kind,
        environment: "sandbox",
        apiBase: gh.url,
        token: ghCanaries.token.value,
        caPem: fx.pki.caPem,
        allowedScopes: [BUILD_REPO],
        attributes: { logHosts: gh.blobHost },
      });
    }
  });
  afterEach(async () => {
    await gh.stop();
    await fx.cleanup();
  });

  const script = (): ScriptStep[] => [
    toolUse([{ name: "skill.load", args: { name: "kubernetes" }, id: "a" }, { name: "skill.load", args: { name: "pipelines" }, id: "b" }]),
    toolUse([
      { name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" }, id: "c" },
      { name: "k8s.events.list", args: { namespace: "payments", since: "2h", type: "Warning" }, id: "d" },
      { name: "pipeline.runs.list", args: { repo: BUILD_REPO, since: "3h" }, id: "e" },
      { name: "scm.commit.list", args: { repo: BUILD_REPO, since: "3h" }, id: "f" },
    ]),
    toolUse([
      { name: "pipeline.jobs.list", args: { repo: BUILD_REPO, runId: 9001 }, id: "g" },
      { name: "pipeline.job.logs", args: { repo: BUILD_REPO, jobId: 70001, runId: 9001, tailLines: 50 }, id: "h" },
    ]),
    toolUse([{ name: "timeline.build", args: {}, id: "i" }]),
    (req) => {
      const ids = idsIn(req.messages);
      return say(`Sıra: commit → koşu #9001 → rollout; imaj özeti ve commit SHA ile bağlı [${ids.at(-1)}]. Bellek sınırı kaynaklı OOM [${ids[0]}] .`);
    },
  ];

  it("tek zaman çizelgesi: commit → koşu → rollout; imaj özeti + SHA + koşu kimliği ile hesaplanmış bağ; serbest metin YOK", async () => {
    expect((await fx.rt.bindProfile("payments-sbx")).bindable).toBe(true);
    expect((await fx.rt.bindProfile("ci")).bindable).toBe(true);
    expect((await fx.rt.bindProfile("git")).bindable).toBe(true);

    const provider = new ScriptedProvider(script(), { trustZone: "third-party-cloud" });
    const ev: OrchestratorEvent[] = [];
    for await (const e of fx.rt.createOrchestrator(provider).send("api neden çöktü, son dağıtımla ilgili mi?")) ev.push(e);
    const results = ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[];
    expect(results.map((r) => `${r.name}:${r.status}`)).toEqual([
      "skill.load:ok", "skill.load:ok",
      "k8s.workload.health:ok", "k8s.events.list:ok", "pipeline.runs.list:ok", "scm.commit.list:ok",
      "pipeline.jobs.list:ok", "pipeline.job.logs:ok",
      "timeline.build:ok",
    ]);
    const final = ev.find((e) => e.type === "final") as Extract<OrchestratorEvent, { type: "final" }>;
    expect(final.citations.invalid).toEqual([]);

    const tl = fx.rt.evidence.all().filter((e) => e.tool === "timeline.build").map((e) => JSON.parse(e.text))[0];
    expect(tl).toBeDefined();
    const kinds = tl.events.map((x: { source: string; kind: string }) => `${x.source}:${x.kind}`);
    // zaman sırası: commit (75dk) < koşu bitişi (65dk) < k8s rollout (≈58dk) < k8s olayları (dakikalar önce)
    expect(kinds.indexOf("scm:commit")).toBeLessThan(kinds.indexOf("pipeline:run_success"));
    expect(kinds.indexOf("pipeline:run_success")).toBeLessThan(kinds.indexOf("k8s:rollout"));
    expect(kinds.indexOf("k8s:rollout")).toBeLessThan(kinds.indexOf("k8s:OOMKilling"));
    // hesaplanmış bağ: k8s ↔ pipeline ↔ scm (imaj özeti + commit SHA)
    expect(tl.links.length).toBe(1);
    expect(tl.links[0].sources).toEqual(["k8s", "pipeline", "scm"]);
    expect(tl.links[0].via).toEqual(["commit", "digest"]);
    const linked = tl.links[0].events.map((i: number) => tl.events[i].summary).join(" | ");
    expect(linked).toMatch(/rollout=degraded/);
    expect(linked).toMatch(/koşu #9001 build-and-deploy success/);
    expect(linked).toMatch(/commit 9f2c1ab/);
    // her olay kaynak kanıt kimliğini taşır ve o kanıt gerçekten var
    for (const e of tl.events) expect(fx.rt.evidence.get(e.ev)).toBeDefined();
    // serbest metin çizelgeye girmedi (enjeksiyon denemeleri commit mesajı/başlık/günlük/olay mesajındaydı)
    const tlText = JSON.stringify(tl);
    expect(tlText).not.toMatch(/IGNORE|PREVIOUS INSTRUCTIONS|kubectl delete/i);
    expect(tlText).not.toContain("Raise batch size");
    // sürelerle uyumlu: koşu ≈65 dk, rollout ≈58 dk önce
    const t = (k: string) => Date.parse(tl.events.find((x: { source: string; kind: string }) => `${x.source}:${x.kind}` === k).t);
    expect((t("k8s:rollout") - t("pipeline:run_success")) / 60_000).toBeGreaterThan(5);
    expect((t("k8s:rollout") - t("pipeline:run_success")) / 60_000).toBeLessThan(9);

    // tüm kanallarda canary yok (küme + GitHub)
    const ui = ev.map((e) => renderEvent(e) ?? "").join("\n");
    const sink = new CaptureSink();
    sink.push("audit", await readFile(fx.rt.paths.auditLog, "utf8"));
    for (const e of fx.rt.evidence.all()) sink.push("evidence", e.text);
    sink.push("sağlayıcı-baytları", provider.serialized.join("\n"));
    sink.push("ui", ui);
    expect(sink.leaks([...fx.all, ...Object.values(ghCanaries)])).toEqual([]);
    // belirteç blob host'una gitmedi; API'ye yalnız GET gitti
    expect(gh.blobRequests.every((q) => q.authorization === null)).toBe(true);
    expect(gh.requests.every((q) => q.method === "GET" && q.authorization === `Bearer ${ghCanaries.token.value}`)).toBe(true);
    // imaj özeti çizelgede KISALTILMIŞ yer alır; bağ anahtarı ham özet metni değil
    expect(tl.links[0].keys.some((k: string) => k.startsWith("digest:sha256:"))).toBe(true);
    expect(BUILD_SHA).toHaveLength(40);
    expect(BUILD_DIGEST).toMatch(/^sha256:a{64}$/);
  });

  it("bağ kurulamadığında ilişki İDDİA EDİLMEZ: farklı imaj özeti → link yok", async () => {
    await fx.rt.bindProfile("payments-sbx");
    await fx.rt.bindProfile("ci");
    // iş günlüğündeki digest k8s'tekiyle aynı olmasın
    const repo = gh.repo(BUILD_REPO);
    repo.logs[70001] = (repo.logs[70001] as string).replaceAll(BUILD_DIGEST, "sha256:" + "d".repeat(64));
    const provider = new ScriptedProvider(
      [
        toolUse([{ name: "skill.load", args: { name: "kubernetes" }, id: "a" }]),
        toolUse([{ name: "skill.load", args: { name: "pipelines" }, id: "b" }]),
        toolUse([
          { name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" }, id: "c" },
          { name: "pipeline.runs.list", args: { repo: BUILD_REPO, since: "3h", status: "success" }, id: "e" },
          { name: "pipeline.job.logs", args: { repo: BUILD_REPO, jobId: 70001, runId: 9001, tailLines: 50 }, id: "h" },
        ]),
        toolUse([{ name: "timeline.build", args: {}, id: "i" }]),
        say("ilişki doğrulanamadı"),
      ],
      { trustZone: "third-party-cloud" },
    );
    const ev: OrchestratorEvent[] = [];
    for await (const e of fx.rt.createOrchestrator(provider).send("q")) ev.push(e);
    const tl = fx.rt.evidence.all().filter((e) => e.tool === "timeline.build").map((e) => JSON.parse(e.text))[0];
    expect(tl.links).toEqual([]);
    // yalnız zaman yakınlığı ipucu verilir ve bunun kesin olmadığı belirtilir
    expect(tl.hints.join(" ")).toMatch(/anahtar bağı yok/);
  });

  it("ops profile add pipeline/scm: belirteç 0600 dosyadan; çıktıda belirteç yok; doctor çalışır; geçersiz kapsam reddedilir", async () => {
    const io = () => ({ input: new PassThrough(), output: new PassThrough(), error: new PassThrough() });
    const cli = async (argv: string[], env: Record<string, string> = {}) => {
      const i = io();
      const code = await runCli({ argv, env, io: i, paths: fx.rt.paths, store: fx.store, sandbox: null });
      return { code, out: (i.output.read() as Buffer | null)?.toString() ?? "", err: (i.error.read() as Buffer | null)?.toString() ?? "" };
    };
    const tokFile = join(fx.home, "gh-token");
    await writeFile(tokFile, `${ghCanaries.token.value}\n`, { mode: 0o600 });
    await writeFile(join(fx.home, "gh-ca.pem"), fx.pki.caPem);
    const base = ["--env", "sandbox", "--api-url", gh.url, "--ca-file", join(fx.home, "gh-ca.pem"), "--scope", "acme/payments,Acme/*"];
    const env = { OPS_GITHUB_TOKEN_FILE: tokFile };
    const add = await cli(["profile", "add", "pipeline", "--id", "ci2", ...base, "--log-hosts", gh.blobHost], env);
    expect(add.code, add.err).toBe(0);
    expect(add.out).toContain("Profil eklendi: ci2");
    expect(add.out + add.err).not.toContain(ghCanaries.token.value);
    expect((await cli(["profile", "list"])).out).toContain("kapsam acme/payments|acme/*"); // küçük harfe indi
    const doc = await cli(["profile", "doctor", "ci2"]);
    expect(doc.code, doc.out).toBe(0);
    expect(doc.out).toMatch(/BAĞLANABİLİR/);
    expect(doc.out).toMatch(/permissions_unverified/);
    expect(doc.out + doc.err).not.toContain(ghCanaries.token.value);
    const scm = await cli(["profile", "add", "scm", "--id", "git2", ...base], env);
    expect(scm.code, scm.err).toBe(0);
    const bad = await cli(["profile", "add", "scm", "--id", "git3", "--env", "sandbox", "--api-url", gh.url, "--scope", "acme/pay ments"], env);
    expect(bad.code).toBe(1);
    expect(bad.err).toMatch(/depo kapsamı geçersiz/);
    const http = await cli(["profile", "add", "scm", "--id", "git4", "--env", "sandbox", "--api-url", "http://api.example", "--scope", "acme/x"], env);
    expect(http.code).toBe(1);
    expect(http.err).toMatch(/https olmalı/);
  });
});
