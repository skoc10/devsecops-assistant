import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { OrchestratorEvent } from "@ops/core";
import { CaptureSink, ScriptedProvider, say, toolUse } from "@ops/testkit";
import { TtyApprovalGate, createRuntime, readAuditRecords, renderEvent, runCli } from "../src/index.ts";
import type { TtyIo } from "../src/index.ts";
import { idsIn, makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

/** Kullanıcı yanıtlarını sırayla yazan sahte kontrol terminali. */
function fakeTty(answers: string[]): { open: () => Promise<TtyIo>; shown: () => string } {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  let i = 0;
  output.on("data", (b: Buffer) => {
    chunks.push(b.toString());
    const joined = chunks.join("");
    if (/: $|> $/.test(joined.slice(-12))) {
      const a = answers[i++];
      if (a !== undefined) setTimeout(() => input.write(`${a}\n`), 0);
    }
  });
  return { open: async () => ({ input, output }), shown: () => chunks.join("") };
}

describe("Faz 2b: Kubernetes değişikliği uçtan uca (scripted model, gerçek TLS sahte API, TTY onayı)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    // aynı profil, mutate tavanıyla yeniden eklenir
    await fx.rt.profiles.addKubeconfig({ id: "payments-sbx", environment: "sandbox", kubeconfigText: fx.kubeconfigText, allowedScopes: ["payments"], displayName: "Payments sandbox", classCeiling: "mutate", replace: true });
    await fx.rt.close();
  });
  afterEach(async () => {
    await fx.cleanup();
  });

  const cli = async (argv: string[]) => {
    const io = { input: new PassThrough(), output: new PassThrough(), error: new PassThrough() };
    const code = await runCli({ argv, env: {}, io, paths: fx.rt.paths, store: fx.store, sandbox: null });
    return { code, out: (io.output.read() as Buffer | null)?.toString() ?? "", err: (io.error.read() as Buffer | null)?.toString() ?? "" };
  };

  it("sağlık → ölçekle (TTY'de 'evet') → doğrula → ChangeSet; reddedilen onay hiçbir şey yazmaz; CLI ile incele/dışa aktar; canary yok; zincir doğru", async () => {
    const tty = fakeTty(["evet", "", "e"]); // 1: scale onay, 2: ikinci scale RET (Enter), 3: change.propose (yerel yazma) onayı
    const gate = new TtyApprovalGate({ openTty: tty.open, sleep: async () => undefined });
    const rt = await createRuntime({ paths: fx.rt.paths, store: fx.store, sandbox: null, approval: gate });
    const ev: OrchestratorEvent[] = [];
    let provider!: ScriptedProvider;
    try {
      expect((await rt.bindProfile("payments-sbx")).bindable).toBe(true);
      const scale = (replicas: number, ids: string[]) => ({ kind: "Deployment", namespace: "payments", name: "api", replicas, cited: [ids[1]] });
      provider = new ScriptedProvider(
        [
          toolUse([{ name: "skill.load", args: { name: "kubernetes-change" } }]),
          toolUse([{ name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" } }]),
          (req) => toolUse([{ name: "k8s.scale", args: scale(3, idsIn(req.messages)) }]),
          (req) => toolUse([{ name: "k8s.scale", args: scale(9, idsIn(req.messages)) }]),
          toolUse([{ name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" } }]),
          (req) => {
            const ids = idsIn(req.messages);
            return toolUse([
              {
                name: "change.propose",
                args: {
                  title: "api: bellek sınırını 512Mi yap",
                  summary: "OOMKilled; limits.memory 128Mi → 512Mi",
                  kind: "k8s-manifest",
                  filename: "api-memory.yaml",
                  content: "apiVersion: apps/v1\nkind: Deployment\nmetadata: { name: api, namespace: payments }\nspec:\n  template:\n    spec:\n      containers:\n        - name: api\n          resources: { limits: { memory: 512Mi } }\n",
                  evidence: [ids[1]],
                  rollback: "limits.memory değerini 128Mi'ye geri alın",
                },
              },
            ]);
          },
          (req) => say(`3 replikaya ölçeklendi [${idsIn(req.messages)[1]}]; ikinci ölçekleme reddedildi; öneri ChangeSet olarak kaydedildi.`),
        ],
        { trustZone: "tenant-cloud" },
      );
      const orch = rt.createOrchestrator(provider, { maxIterations: 20 });
      for await (const e of orch.send("api'yi 3 replikaya çıkar ve bellek sınırı için öneri kaydet")) ev.push(e);

      const results = ev.filter((e): e is Extract<OrchestratorEvent, { type: "tool_result" }> => e.type === "tool_result");
      const scales = results.filter((r) => r.name === "k8s.scale");
      expect(scales.map((r) => [r.status, r.reasonCode])).toEqual([["ok", undefined], ["denied", "approval_denied"]]);
      // yalnız ilk ölçekleme sunucuya yazıldı
      const writes = fx.api.requests.filter((q) => q.method !== "GET" && !q.path.includes("selfsubject"));
      expect(writes.map((w) => [w.method, w.path])).toEqual([["PATCH", "/apis/apps/v1/namespaces/payments/deployments/api/scale"]]);
      expect(fx.api.peek("Deployment", "payments", "api")?.spec).toMatchObject({ replicas: 3 });
      // onay ekranı: diff, etki, geri alma, sürüm, sınıf ve ortam
      const shown = tty.shown();
      expect(shown).toContain("ONAY GEREKİYOR");
      expect(shown).toContain("k8s.scale");
      expect(shown).toContain("replika 2 → 3");
      expect(shown).toContain("Geri alma: k8s.scale Deployment/payments/api replicas=2");
      expect(shown).toMatch(/Hedef sürüm: \d+/);
      expect(shown).toContain("Onaylamak için 'evet' yazın");
      // ChangeSet kaydedildi (yerel yazma onayı 'e')
      const final = ev.find((e) => e.type === "final");
      if (final?.type === "final") expect(final.citations.invalid).toEqual([]);
      const cp = results.find((r) => r.name === "change.propose");
      expect(cp?.status, JSON.stringify(cp)).toBe("ok");

      // canary yok: denetim, kanıt, sağlayıcı, arayüz, onay ekranı
      const sink = new CaptureSink();
      sink.push("audit", await readFile(rt.paths.auditLog, "utf8"));
      for (const e of rt.evidence.all()) sink.push("evidence", e.text);
      sink.push("sağlayıcı", provider.serialized.join("\n"));
      sink.push("ui", ev.map((e) => renderEvent(e) ?? "").join("\n"));
      sink.push("onay", shown);
      expect(sink.leaks(fx.all)).toEqual([]);
      // denetimde atıf ve onay kayıtları
      const recs = await readAuditRecords(rt.paths.auditLog);
      expect(recs.some((r) => r.event === "intent" && r.tool === "k8s.scale" && typeof r.message === "string" && r.message.startsWith("atıf: ev-"))).toBe(true);
      expect(recs.filter((r) => r.event === "approval").map((r) => r.decision)).toEqual(["allow", "deny", "allow"]);
    } finally {
      await rt.close();
    }

    // CLI: değişiklik önerilerini gör / dışa aktar / sonradan değiştirilirse reddet
    const list = await cli(["change", "list"]);
    expect(list.code, list.err).toBe(0);
    const id = /^(cs-\S+)/m.exec(list.out)?.[1] as string;
    expect(list.out).toMatch(/k8s-manifest/);
    const show = await cli(["change", "show", id]);
    expect(show.out).toContain("api: bellek sınırını 512Mi yap");
    expect(show.out).toMatch(/kanıt ev-\d+ \(k8s\.workload\.health\)/);
    expect(show.out).toContain("memory: 512Mi");
    expect(show.out).toContain("geri alma: limits.memory");
    const outFile = join(fx.home, "api-memory.yaml");
    const exp = await cli(["change", "export", id, "--out", outFile]);
    expect(exp.code, exp.err).toBe(0);
    expect(await readFile(outFile, "utf8")).toContain("memory: 512Mi");
    expect((await cli(["change", "export", id, "--out", outFile])).err).toMatch(/zaten var/);
    await writeFile(join(fx.rt.paths.changesDir, id, "api-memory.yaml"), "spec: {}\n");
    expect((await cli(["change", "show", id])).err).toMatch(/changeset_tampered/);
    expect((await cli(["change", "show", "../x"])).err).toMatch(/changeset_invalid/);
    expect((await cli(["audit", "verify"])).code).toBe(0);
  }, 60_000);

  it("prod ortamında yazma: ortam adı yazdırılmadan onay verilmez (deploy); yanlış metin = ret", async () => {
    await fx.rt.profiles.addKubeconfig({ id: "payments-prod", environment: "prod", kubeconfigText: fx.kubeconfigText, allowedScopes: ["payments"], displayName: "Payments PROD", classCeiling: "deploy" });
    const tty = fakeTty(["evet", "prod"]);
    const gate = new TtyApprovalGate({ openTty: tty.open, sleep: async () => undefined });
    const rt = await createRuntime({ paths: fx.rt.paths, store: fx.store, sandbox: null, approval: gate });
    try {
      await rt.bindProfile("payments-prod");
      const get = await rt.gateway.invoke({ tool: "k8s.resources.get", profile: "payments-prod", args: { kind: "Deployment", namespace: "payments", name: "api" }, providerZone: "local" });
      const m = "apiVersion: apps/v1\nkind: Deployment\nmetadata: { name: api, namespace: payments }\nspec: { replicas: 4 }\n";
      const bad = await rt.gateway.invoke({ tool: "k8s.apply", profile: "payments-prod", args: { manifest: m }, citedEvidence: [get.evidenceId as string], providerZone: "local" });
      expect(bad).toMatchObject({ status: "denied", reasonCode: "approval_denied" }); // 'evet' yetmez: ortam adı gerekli
      expect(fx.api.peek("Deployment", "payments", "api")?.spec).toMatchObject({ replicas: 2 });
      const ok = await rt.gateway.invoke({ tool: "k8s.apply", profile: "payments-prod", args: { manifest: m }, citedEvidence: [get.evidenceId as string], providerZone: "local" });
      expect(ok.status, JSON.stringify(ok)).toBe("ok");
      expect(fx.api.peek("Deployment", "payments", "api")?.spec).toMatchObject({ replicas: 4 });
      expect(tty.shown()).toContain("Onaylamak için 'prod' yazın");
      expect(gate.summaryLine()).toBe("Bu oturumda 1 onay verdiniz, 1 tanesi prod.");
    } finally {
      await rt.close();
    }
  }, 60_000);
});
