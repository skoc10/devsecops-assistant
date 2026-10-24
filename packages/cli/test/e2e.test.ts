import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { estimateTokens } from "@ops/contracts";
import { BASE_SYSTEM, formatUsage, skillMetadataBlock, usageFromAudit } from "@ops/core";
import type { OrchestratorEvent } from "@ops/core";
import { ScriptedProvider, say } from "@ops/testkit";
import { LocalBackend, readAuditRecords, renderEvent, runChat, runCli } from "../src/index.ts";
import { allChannels, e01Script, makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE = join(here, "..", "..", "..", "test", "e2e", "baseline.json");

async function run(fx: Fixture, provider: ScriptedProvider, text: string): Promise<OrchestratorEvent[]> {
  const orch = fx.rt.createOrchestrator(provider);
  const ev: OrchestratorEvent[] = [];
  for await (const e of orch.send(text)) ev.push(e);
  return ev;
}

describe("E-01: Faz 0 kabul senaryosu (scripted model + sahte küme)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
  });
  afterEach(async () => {
    await fx.cleanup();
  });

  it("profil doktordan geçer ve bağlanır; kök neden atıflı gelir; hiçbir mutasyon çağrısı yapılmaz", async () => {
    const report = await fx.rt.bindProfile("payments-sbx");
    expect(report).toMatchObject({ bindable: true, connected: true, pinOk: true, effectiveClass: "read" });

    const provider = new ScriptedProvider(e01Script(), { trustZone: "third-party-cloud" });
    const ev = await run(fx, provider, "payments ns'inde api neden CrashLoopBackOff?");
    const final = ev.find((e) => e.type === "final") as Extract<OrchestratorEvent, { type: "final" }>;
    expect(final).toBeDefined();
    expect(final.citations.invalid).toEqual([]);
    expect(final.citations.valid.length).toBeGreaterThanOrEqual(3);
    expect(final.text).toMatch(/OOMKilled/);
    expect(final.toolCalls).toBe(4);
    // Araç çağrıları: skill.load, health, events, logs — hepsi ok
    const results = ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[];
    expect(results.map((r) => r.status)).toEqual(["ok", "ok", "ok", "ok"]);
    // Küme API'sine yalnız okuma/inceleme istekleri gitti
    const verbs = fx.api.requests.map((q) => `${q.method} ${q.path}`);
    expect(verbs.every((v) => v.startsWith("GET ") || /^POST \/apis\/authorization\.k8s\.io\/v1\/selfsubjectrulesreviews|^POST \/apis\/authentication\.k8s\.io\/v1\/selfsubjectreviews/.test(v))).toBe(true);
    expect(fx.api.requests.every((q) => q.bearer === fx.canaries.kubeToken.value)).toBe(true);
  });

  it("S-06: canary'ler sağlayıcıya giden baytlarda, kullanıcı arayüzünde, denetimde ve kanıtta YOK", async () => {
    await fx.rt.bindProfile("payments-sbx");
    const provider = new ScriptedProvider(e01Script(), { trustZone: "third-party-cloud" });
    const ev = await run(fx, provider, "api neden çöküyor?");
    const ui = ev.map((e) => renderEvent(e) ?? "").join("\n");
    const sink = await allChannels(fx, { "sağlayıcı-baytları": provider.serialized.join("\n"), ui });
    expect(sink.leaks(fx.all)).toEqual([]);
    expect(sink.channels()).toEqual(expect.arrayContaining(["audit", "evidence", "sağlayıcı-baytları", "ui"]));
    // denetimde yalnız redakte çıktı var; ham kubeconfig/token yok
    expect(sink.text("audit")).not.toContain(fx.kubeconfigText);
  });

  it("S-07: log içindeki enjeksiyon modeli yanıltsa bile silme/ölçekleme çağrısı reddedilir; küme değişmez", async () => {
    await fx.rt.bindProfile("payments-sbx");
    const provider = new ScriptedProvider([
      { message: { content: "", toolCalls: [{ id: "a", name: "skill.load", args: { name: "kubernetes" } }] }, usage: { inputTokens: 0, outputTokens: 5, cacheReadTokens: 0 }, stopReason: "tool_use" },
      { message: { content: "", toolCalls: [{ id: "b", name: "k8s.pods.logs", args: { namespace: "payments", pod: "api-7d9c-a1", since: "30m" } }] }, usage: { inputTokens: 0, outputTokens: 5, cacheReadTokens: 0 }, stopReason: "tool_use" },
      // model log'daki talimata "uydu" ve silmeyi denedi
      { message: { content: "", toolCalls: [{ id: "c", name: "k8s.resources.delete", args: { namespace: "payments", kind: "Namespace", name: "payments" } }, { id: "d", name: "k8s.scale", args: { namespace: "payments", name: "api", replicas: 0 } }] }, usage: { inputTokens: 0, outputTokens: 5, cacheReadTokens: 0 }, stopReason: "tool_use" },
      (req) => say(`Silme/ölçekleme reddedildi: ${(req.messages.at(-1) as { content: string }).content.slice(0, 120)}`),
    ]);
    const ev = await run(fx, provider, "logları incele");
    const results = ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[];
    expect(results.slice(2).map((r) => [r.status, r.reasonCode])).toEqual([["denied", "unknown_tool"], ["denied", "unknown_tool"]]);
    expect(fx.api.requests.some((q) => q.method !== "GET" && !q.path.includes("selfsubject"))).toBe(false);
    // log çıktısı taint'li: bağlam artık untrusted
    expect(fx.rt.session.context.tainted).toBe(true);
    // denetimde ret kayıtları var
    const recs = await readAuditRecords(fx.rt.paths.auditLog);
    expect(recs.filter((r) => r.event === "result" && r.decision === "deny" && r.reasonCode === "unknown_tool").length).toBe(2);
  });

  it("S-13: sağlayıcı bölgesi (local ↔ third-party-cloud) değişince politika kararları ve araç sonuçları aynı", async () => {
    await fx.rt.bindProfile("payments-sbx");
    const a = await run(fx, new ScriptedProvider(e01Script(), { trustZone: "local" }), "q");
    const fx2 = await makeFixture();
    try {
      await fx2.rt.bindProfile("payments-sbx");
      const b = await run(fx2, new ScriptedProvider(e01Script(), { trustZone: "third-party-cloud" }), "q");
      const sig = (ev: OrchestratorEvent[]) => ev.filter((e) => e.type === "tool_result").map((e) => `${(e as { name: string }).name}:${(e as { status: string }).status}`);
      expect(sig(a)).toEqual(sig(b));
    } finally {
      await fx2.cleanup();
    }
  });

  it("denetim zinciri doğrulanır; bir bayt değişince kırılır (S-08) — CLI üzerinden", async () => {
    await fx.rt.bindProfile("payments-sbx");
    await run(fx, new ScriptedProvider(e01Script(), { trustZone: "local" }), "q");
    const io = () => ({ input: new PassThrough(), output: new PassThrough(), error: new PassThrough() });
    const cli = (argv: string[]) => runCli({ argv, env: {}, io: io(), paths: fx.rt.paths, store: fx.store, sandbox: null });
    expect(await cli(["audit", "verify"])).toBe(0);
    const text = await readFile(fx.rt.paths.auditLog, "utf8");
    const lines = text.split("\n");
    lines[3] = (lines[3] as string).replace('"event":', '"event" :'); // anlamsız değişiklik: JSON eşdeğeri ama bayt farkı
    const mid = (lines[4] as string).replace(/"sessionId":"([^"]+)"/, '"sessionId":"x$1"');
    lines[4] = mid;
    await writeFile(fx.rt.paths.auditLog, lines.join("\n"));
    expect(await cli(["audit", "verify"])).toBe(1);
  });

  it("ops usage: denetimden araç/model kırılımı", async () => {
    await fx.rt.bindProfile("payments-sbx");
    await run(fx, new ScriptedProvider(e01Script(), { trustZone: "local" }), "q");
    const report = usageFromAudit(await readAuditRecords(fx.rt.paths.auditLog), fx.rt.session.id);
    expect(report.modelCalls).toBe(4);
    expect(Object.keys(report.byTool)).toEqual(expect.arrayContaining(["k8s.workload.health", "k8s.events.list", "k8s.pods.logs", "skill.load"]));
    expect(formatUsage(report)).toContain("k8s.pods.logs");
  });
});

describe("B-01/B-03/B-04: token ekonomisi", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.bindProfile("payments-sbx");
  });
  afterEach(async () => {
    await fx.cleanup();
  });

  it("B-01: ilk istekteki sabit önek (sistem + meta + çekirdek araçlar) ≤ 3k token", async () => {
    const p = new ScriptedProvider([say("merhaba")]);
    await run(fx, p, "selam");
    const r = p.requests[0]!;
    const prefix = r.system.split("\n\nBağlı profiller")[0] as string;
    expect(prefix.startsWith(BASE_SYSTEM)).toBe(true);
    expect(estimateTokens(prefix + JSON.stringify(r.tools))).toBeLessThanOrEqual(3_000);
    expect(r.tools.map((t) => t.name)).toEqual(["evidence.get", "evidence.search", "k8s.profile.describe", "skill.list", "skill.load"]);
    void skillMetadataBlock;
  });

  it("B-03: tek araç sonucu tavanı aşmaz; her sonuç ≤ 1500 token ya da referansla", async () => {
    const p = new ScriptedProvider(e01Script(), { trustZone: "local" });
    const ev = await run(fx, p, "q");
    for (const r of ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[]) {
      expect(r.byReference || r.tokens <= 1_500).toBe(true);
    }
  });

  it("B-04: E-01 token toplamı baz çizgiyi %10'dan fazla aşmaz", async () => {
    const p = new ScriptedProvider(e01Script(), { trustZone: "local" });
    const o = fx.rt.createOrchestrator(p);
    for await (const _ of o.send("payments ns'inde api neden CrashLoopBackOff?")) void _;
    const m = o.meter.report();
    const current = { modelCalls: m.modelCalls, toolCalls: m.toolCalls, resultTokens: m.resultTokens, inputTokens: m.inputTokens };
    if (process.env["UPDATE_BASELINE"] === "1" || !existsSync(BASELINE)) {
      mkdirSync(dirname(BASELINE), { recursive: true });
      writeFileSync(BASELINE, `${JSON.stringify(current, null, 2)}\n`);
    }
    const base = JSON.parse(readFileSync(BASELINE, "utf8")) as typeof current;
    expect(current.modelCalls).toBe(base.modelCalls);
    expect(current.toolCalls).toBe(base.toolCalls);
    expect(current.resultTokens).toBeLessThanOrEqual(Math.ceil(base.resultTokens * 1.1));
    expect(current.inputTokens).toBeLessThanOrEqual(Math.ceil(base.inputTokens * 1.1));
    // mutlak hedef (Faz 0 kabul): ana bağlama giren toplam araç sonucu ≈ ≤ 8k token
    expect(current.resultTokens).toBeLessThanOrEqual(8_000);
  });
});

describe("ops chat (REPL, süreç içi arka uç)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
  });
  afterEach(async () => {
    await fx.cleanup();
  });

  it("/profiles → /use → soru → /usage → /quit; çıktıda ANSI/OSC enjeksiyonu ve secret yok", async () => {
    const evil = "\u001b]8;;http://evil.invalid\u0007tıkla\u001b]8;;\u0007 \u001b[2J";
    const script = e01Script();
    script[3] = (req) => {
      const base = (e01Script()[3] as (r: typeof req) => { message: { content: string; toolCalls: [] }; usage: object; stopReason: "end" })(req);
      return { ...base, message: { content: `${base.message.content}\n${evil}`, toolCalls: [] } } as never;
    };
    const provider = new ScriptedProvider(script, { trustZone: "local" });
    const backend = new LocalBackend(fx.rt, fx.rt.createOrchestrator(provider));
    const input = new PassThrough();
    const output = new PassThrough();
    const chunks: string[] = [];
    output.on("data", (b: Buffer) => chunks.push(b.toString()));
    const done = runChat(backend, { input, output });
    input.write("/profiles\n/use payments-sbx\npayments ns'inde api neden çöküyor?\n/usage\n/quit\n");
    input.end();
    await done;
    const text = chunks.join("");
    expect(text).toContain("payments-sbx");
    expect(text).toContain("BAĞLANABİLİR");
    expect(text).toContain("→ k8s.workload.health");
    expect(text).toContain("✓ ev-");
    expect(text).toContain("OOMKilled");
    expect(text).toContain("Model çağrısı: 4");
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("evil.invalid");
    const sink = await allChannels(fx, { ui: text, provider: provider.serialized.join("") });
    expect(sink.leaks(fx.all)).toEqual([]);
  });

  it("profil bağlanmadan kimlikli araç çağrısı reddedilir; /use başarısız profilde hata verir", async () => {
    const provider = new ScriptedProvider([
      { message: { content: "", toolCalls: [{ id: "a", name: "skill.load", args: { name: "kubernetes" } }] }, usage: { inputTokens: 0, outputTokens: 5, cacheReadTokens: 0 }, stopReason: "tool_use" },
      { message: { content: "", toolCalls: [{ id: "b", name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" } }] }, usage: { inputTokens: 0, outputTokens: 5, cacheReadTokens: 0 }, stopReason: "tool_use" },
      say("profil bağlı değil"),
    ]);
    const ev = await run(fx, provider, "bak");
    const r = (ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[])[1]!;
    expect(r).toMatchObject({ status: "denied", reasonCode: "profile_not_bound" });
    expect(fx.api.requests.length).toBe(0);
    await expect(fx.rt.bindProfile("yok")).rejects.toThrow(/bulunamadı/);
  });
});
