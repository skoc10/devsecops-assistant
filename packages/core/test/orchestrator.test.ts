import { describe, expect, it } from "vitest";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import { ScriptedProvider, say, toolUse } from "@ops/testkit";
import type { GenerateRequest } from "@ops/contracts";
import { Orchestrator } from "../src/index.ts";
import type { OrchestratorEvent, SkillCatalog } from "../src/index.ts";
import { makeHarness } from "./harness.ts";
import type { Harness } from "./harness.ts";

const catalog: SkillCatalog = {
  metadata: () => [
    { name: "kubernetes", description: "Kubernetes teşhisi. Pod/Deployment sorunlarında kullan.", tier: "builtin" },
    { name: "generic-diagnosis", description: "Runbook yokken genel teşhis akışı.", tier: "builtin" },
  ],
};

function make(h: Harness, provider: ScriptedProvider, over: { policy?: PolicyEngine; options?: ConstructorParameters<typeof Orchestrator>[0]["options"] } = {}) {
  // gerçek akışta araç setini skill.load açar
  h.session.activateSkill({ name: "kubernetes", tier: "builtin", body: "K8S REHBERİ", tokens: 3, toolsets: ["k8s-core"] });
  return new Orchestrator({
    provider,
    gateway: h.gateway,
    registry: h.registry,
    session: h.session,
    evidence: h.evidence,
    policy: over.policy ?? h.policy,
    audit: h.audit,
    known: h.known,
    skills: catalog,
    ...(over.options ? { options: over.options } : {}),
  });
}

async function collect(o: Orchestrator, text: string): Promise<OrchestratorEvent[]> {
  const out: OrchestratorEvent[] = [];
  for await (const e of o.send(text)) out.push(e);
  return out;
}
const types = (ev: OrchestratorEvent[]) => ev.map((e) => e.type);
const finalOf = (ev: OrchestratorEvent[]) => ev.find((e) => e.type === "final") as Extract<OrchestratorEvent, { type: "final" }> | undefined;

describe("Orchestrator: temel döngü", () => {
  it("araç çağrısı → sonuç → atıflı final; profil otomatik enjekte edilir; denetimde model_call yazılır", async () => {
    const h = await makeHarness();
    const p = new ScriptedProvider([
      toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]),
      say("api-2 Failed durumda [ev-1]."),
    ]);
    const o = make(h, p);
    const ev = await collect(o, "payments'ta pod'lar nasıl?");
    expect(types(ev)).toEqual(["usage", "tool_call", "tool_result", "usage", "final"]);
    const f = finalOf(ev)!;
    expect(f.citations).toMatchObject({ valid: ["ev-1"], invalid: [] });
    expect(f.toolCalls).toBe(1);
    // ikinci istekte araç sonucu mesajı kanıt kimliğini taşır
    const secondReq = p.requests[1] as GenerateRequest;
    expect(secondReq.messages.at(-1)).toMatchObject({ role: "tool", name: "k8s.resources.list" });
    expect((secondReq.messages.at(-1) as { content: string }).content).toContain("ev-1");
    // denetim: her model çağrısı için istek+yanıt kaydı, sağlayıcı/model/bölge
    const recs = await h.records();
    const mc = recs.filter((r) => r["event"] === "model_call");
    expect(mc.length).toBe(4);
    expect(mc[0]).toMatchObject({ provider: "scripted", model: "scripted-1", trustZone: "local" });
    expect((mc[1] as { tokens?: unknown }).tokens).toBeDefined();
    expect(o.meter.report()).toMatchObject({ modelCalls: 2, toolCalls: 1 });
    expect(h.session.usage.sessionTokens).toBeGreaterThan(0);
  });

  it("araç seti etkin değilse çağrı reddedilir ve istekte o aracın şeması yoktur", async () => {
    const h = await makeHarness();
    const p = new ScriptedProvider([
      toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]),
      say("tamam"),
    ]);
    const o = new Orchestrator({ provider: p, gateway: h.gateway, registry: h.registry, session: h.session, evidence: h.evidence, policy: h.policy, audit: h.audit, known: h.known, skills: catalog });
    const ev = await collect(o, "listele");
    const tr = ev.find((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>;
    expect(tr).toMatchObject({ status: "denied", reasonCode: "unknown_tool" });
    expect((p.requests[0] as GenerateRequest).tools.map((t) => t.name)).toEqual(["evidence.get", "evidence.search"]);
    expect(h.k8s.calls.length).toBe(0);
  });

  it("bağlı profil yoksa kimlikli araç reddedilir (profile_not_bound)", async () => {
    const h = await makeHarness();
    h.session.unbind("k8s");
    const p = new ScriptedProvider([toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]), say("profil yok")]);
    const o = make(h, p);
    const ev = await collect(o, "listele");
    expect(ev.find((e) => e.type === "tool_result")).toMatchObject({ status: "denied", reasonCode: "profile_not_bound" });
    expect(h.k8s.calls.length).toBe(0);
    const recs = await h.records();
    expect(recs.some((r) => r["event"] === "intent" && r["reasonCode"] === "profile_not_bound")).toBe(true);
  });

  it("model uydurma araç adı: PEP unknown_tool ile reddeder ve denetler", async () => {
    const h = await makeHarness();
    const p = new ScriptedProvider([toolUse([{ name: "k8s.hack.everything", args: {} }]), say("olmadı")]);
    const o = make(h, p);
    const ev = await collect(o, "x");
    expect(ev.find((e) => e.type === "tool_result")).toMatchObject({ status: "denied", reasonCode: "unknown_tool" });
  });

  it("aynı turdaki okuma çağrıları paralel çalışır; sonuç sırası çağrı sırasıdır", async () => {
    const h = await makeHarness();
    let inFlight = 0;
    let maxInFlight = 0;
    const slow = async () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 30));
      inFlight -= 1;
      return { data: [{ metadata: { name: "x" } }] };
    };
    const h2 = await makeHarness({ handlers: { "k8s.resources.list": slow, "k8s.pods.logs": slow } });
    void h;
    const p = new ScriptedProvider([
      toolUse([
        { id: "a", name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } },
        { id: "b", name: "k8s.pods.logs", args: { namespace: "payments", pod: "api-1" } },
      ]),
      say("bitti [ev-1] [ev-2]"),
    ]);
    const o = make(h2, p);
    const ev = await collect(o, "ikisini de getir");
    expect(maxInFlight).toBe(2);
    const toolMsgs = (p.requests[1] as GenerateRequest).messages.filter((m) => m.role === "tool");
    expect(toolMsgs.map((m) => (m as { toolCallId: string }).toolCallId)).toEqual(["a", "b"]);
    expect(finalOf(ev)?.citations.valid.sort()).toEqual(["ev-1", "ev-2"]);
  });

  it("mutasyon önerisi PEP'te reddedilir ve model ret kodunu görür (Faz 0)", async () => {
    const h = await makeHarness();
    const p = new ScriptedProvider([
      toolUse([{ name: "k8s.resources.delete", args: { namespace: "payments", kind: "Deployment", name: "api" } }]),
      (req) => {
        const last = req.messages.at(-1) as { content: string };
        return say(`Silme reddedildi: ${last.content}`);
      },
    ]);
    const o = make(h, p);
    const ev = await collect(o, "payments/api deployment'ını sil");
    expect(ev.find((e) => e.type === "tool_result")).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    expect(h.k8s.calls.length).toBe(0);
    expect(finalOf(ev)?.text).toContain("REDDEDİLDİ [ceiling_exceeded]");
  });
});

describe("Orchestrator: kanıt atıf doğrulaması", () => {
  it("geçersiz kimlik → düzeltme isteği → geçerli cevap", async () => {
    const h = await makeHarness();
    const p = new ScriptedProvider([
      toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]),
      say("Sorun [ev-99]'da görünüyor."),
      (req) => {
        expect((req.messages.at(-1) as { content: string }).content).toContain("ev-99");
        expect((req.messages.at(-1) as { content: string }).content).toContain("ev-1");
        return say("Düzeltildi [ev-1].");
      },
    ]);
    const ev = await collect(make(h, p), "bak");
    expect(ev.some((e) => e.type === "warning" && e.code === "citation_invalid")).toBe(true);
    expect(finalOf(ev)?.text).toBe("Düzeltildi [ev-1].");
  });

  it("düzeltmeden sonra da geçersizse cevap uyarıyla işaretlenir", async () => {
    const h = await makeHarness();
    const p = new ScriptedProvider([say("Bence [ev-7]."), say("Yine [ev-7].")]);
    const ev = await collect(make(h, p), "bak");
    expect(finalOf(ev)?.text).toContain("Doğrulanamayan kanıt kimlikleri: ev-7");
  });

  it("araç çağrıldı ama atıf yoksa uyarı eklenir; araç çağrılmadıysa eklenmez", async () => {
    const h = await makeHarness();
    const p = new ScriptedProvider([toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]), say("Her şey yolunda.")]);
    const ev = await collect(make(h, p), "bak");
    expect(finalOf(ev)?.text).toContain("kanıt kimliği içermiyor");
    const h2 = await makeHarness();
    const ev2 = await collect(make(h2, new ScriptedProvider([say("Merhaba!")])), "selam");
    expect(finalOf(ev2)?.text).toBe("Merhaba!");
  });
});

describe("Orchestrator: egress, bütçe, denetim", () => {
  it("bağlam sağlayıcıya gidemiyorsa model ÇAĞRILMAZ (no_eligible_provider)", async () => {
    const h = await makeHarness();
    h.session.noteResult({ sensitivity: "secret-adjacent", tainted: false });
    const p = new ScriptedProvider([say("gönderilmemeli")], { trustZone: "third-party-cloud" });
    const ev = await collect(make(h, p), "devam");
    expect(ev.at(-1)).toMatchObject({ type: "error", code: "no_eligible_provider" });
    expect(p.turns).toBe(0);
    const recs = await h.records();
    expect(recs.some((r) => r["event"] === "model_call" && r["reasonCode"] === "no_eligible_provider")).toBe(true);
  });

  it("yerel sağlayıcı aynı bağlamda çalışır", async () => {
    const h = await makeHarness();
    h.session.noteResult({ sensitivity: "secret-adjacent", tainted: false });
    const p = new ScriptedProvider([say("yerel cevap")], { trustZone: "local" });
    const ev = await collect(make(h, p), "devam");
    expect(finalOf(ev)?.text).toBe("yerel cevap");
  });

  it("sert token bütçesi aşılınca tur durur", async () => {
    const h = await makeHarness();
    const policy = new PolicyEngine({ ...DEFAULT_POLICY, budgets: { ...DEFAULT_POLICY.budgets, hardSessionTokens: 50, softSessionTokens: 20 } });
    const p = new ScriptedProvider([toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]), say("ulaşılmamalı")]);
    const ev = await collect(make(h, p, { policy }), "bak");
    expect(ev.at(-1)).toMatchObject({ type: "error", code: "token_budget_exceeded" });
    expect(p.turns).toBe(1);
  });

  it("tur başına model turu sınırı (sonsuz araç döngüsü)", async () => {
    const h = await makeHarness();
    const loop = toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]);
    const p = new ScriptedProvider(Array.from({ length: 10 }, () => loop));
    const ev = await collect(make(h, p, { options: { maxIterations: 3 } }), "döngü");
    expect(ev.at(-1)).toMatchObject({ type: "error", code: "iteration_limit" });
    expect(p.turns).toBe(3);
  });

  it("denetim yazılamıyorsa model çağrılmaz (fail-closed)", async () => {
    const h = await makeHarness();
    h.storage.failNext = true;
    const p = new ScriptedProvider([say("gönderilmemeli")]);
    const ev = await collect(make(h, p), "merhaba");
    expect(ev.at(-1)).toMatchObject({ type: "error", code: "audit_unavailable" });
    expect(p.turns).toBe(0);
  });

  it("sağlayıcı hatası kullanıcıya secret'sız iletilir", async () => {
    const h = await makeHarness();
    h.known.add("sağlayıcı", h.secret);
    const bad = new ScriptedProvider([() => { throw new Error(`401 key=${h.secret}`); }]);
    const ev = await collect(make(h, bad), "x");
    const e = ev.at(-1) as Extract<OrchestratorEvent, { type: "error" }>;
    expect(e.code).toBe("provider_error");
    expect(e.message).not.toContain(h.secret);
  });
});

describe("Orchestrator: kullanıcı girdisi, defter, önek kararlılığı", () => {
  it("kullanıcının yapıştırdığı bilinen secret modele gitmez ve uyarı verilir", async () => {
    const h = await makeHarness();
    h.known.add("kullanici", "super-secret-token-12345");
    const p = new ScriptedProvider([say("ok")]);
    const ev = await collect(make(h, p), "şu token'ı kullan: super-secret-token-12345");
    expect(ev.some((e) => e.type === "warning" && e.code === "user_input_redacted")).toBe(true);
    expect(p.serialized.join("")).not.toContain("super-secret-token-12345");
  });

  it("eşik aşılınca eski turlar defter özetiyle değişir; kanıt kimlikleri korunur ve evidence.get çalışır", async () => {
    const h = await makeHarness();
    const call = () => toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]);
    const p = new ScriptedProvider([call(), say("birinci [ev-1]"), call(), say("ikinci [ev-2]"), call(), say("üçüncü [ev-3]")]);
    const o = make(h, p, { options: { compact: { thresholdTokens: 250, summaryTokens: 200, keepToolMessages: 1 } } });
    await collect(o, "ilk soru");
    await collect(o, "ikinci soru");
    const ev = await collect(o, "üçüncü soru");
    expect(ev.some((e) => e.type === "warning" && e.code === "context_compacted")).toBe(true);
    const first = o.history[0] as { role: string; content: string };
    expect(first.content).toContain("ÖNCEKİ TURLARIN ÖZETİ");
    expect(first.content).toContain("ev-1");
    expect(first.content).toContain("Hedef: ilk soru");
    expect(h.evidence.get("ev-1")).toBeDefined();
  });

  it("B-05 önek kararlılığı: skill etkinleşince sistem istemi ve araç listesi yalnız SONA büyür", async () => {
    const h = await makeHarness();
    const p = new ScriptedProvider([say("bir"), say("iki")]);
    const o = make(h, p);
    await collect(o, "ilk");
    h.session.activateSkill({ name: "db-skill", tier: "builtin", body: "DB GÖVDESİ", tokens: 5, toolsets: ["db"] });
    await collect(o, "ikinci");
    const [r1, r2] = p.requests as [GenerateRequest, GenerateRequest];
    expect(r2.system.startsWith(r1.system)).toBe(true);
    expect(r2.system).toContain("## Etkin skill: db-skill");
    expect(r2.tools.length).toBeGreaterThan(r1.tools.length);
    expect(r2.tools.slice(0, r1.tools.length)).toEqual(r1.tools);
    // sistem istemi iki çağrıda da aynı sabit önekle başlar
    const prefix = r1.system.split("\n\nBağlı profiller")[0];
    expect(r2.system.startsWith(prefix as string)).toBe(true);
  });

  it("araç sırası deterministik: aynı kümede iki kez aynı", async () => {
    const h = await makeHarness();
    const a = h.registry.specsFor(["core", "k8s-core"]).map((t) => t.name);
    const b = h.registry.specsFor(["core", "k8s-core"]).map((t) => t.name);
    expect(a).toEqual(b);
    expect(a.slice(0, 2)).toEqual(["evidence.get", "evidence.search"]);
    expect(h.registry.specsFor(["k8s-core", "core"]).map((t) => t.name).slice(0, 2)).not.toEqual(["evidence.get", "evidence.search"]);
  });
});
