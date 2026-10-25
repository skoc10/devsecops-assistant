import { describe, expect, it } from "vitest";
import type { GenerateRequest, GenerateResult, ModelProvider, TrustZone } from "@ops/contracts";
import { ScriptedProvider, say, toolUse } from "@ops/testkit";
import { Orchestrator } from "../src/index.ts";
import type { OrchestratorEvent } from "../src/index.ts";
import { makeHarness } from "./harness.ts";
import type { Harness } from "./harness.ts";

/** Kimliği/modeli ayarlanabilir sarmalayıcı (ScriptedProvider kimliği sabit). */
class Named implements ModelProvider {
  readonly id: string;
  readonly model: string;
  readonly capabilities: ModelProvider["capabilities"];
  readonly inner: ScriptedProvider;
  constructor(id: string, model: string, inner: ScriptedProvider, zone: TrustZone = "local", tier: "small" | "large" = "large") {
    this.id = id;
    this.model = model;
    this.inner = inner;
    this.capabilities = { ...inner.capabilities, trustZone: zone, tier };
  }
  generate(req: GenerateRequest): Promise<GenerateResult> {
    return this.inner.generate(req);
  }
}

const skill = (name: string, modelHint?: "small" | "large") => ({ name, tier: "user" as const, body: `${name} gövdesi`, tokens: 3, toolsets: ["k8s-core"], ...(modelHint ? { modelHint } : {}) });

async function collect(o: Orchestrator, text: string): Promise<OrchestratorEvent[]> {
  const out: OrchestratorEvent[] = [];
  for await (const e of o.send(text)) out.push(e);
  return out;
}
const mk = (h: Harness, large: ModelProvider, small?: ModelProvider) =>
  new Orchestrator({ provider: large, ...(small ? { smallProvider: small } : {}), gateway: h.gateway, registry: h.registry, session: h.session, evidence: h.evidence, policy: h.policy, audit: h.audit, known: h.known });
const models = async (h: Harness): Promise<string[]> => (await h.records()).filter((r) => r["event"] === "model_call" && String(r["message"]).startsWith("request")).map((r) => String(r["model"]));

describe("model kademesi yönlendirme (skill model_hint)", () => {
  it("küçük sağlayıcı yoksa her tur ana modelle (varsayılan davranış değişmez)", async () => {
    const h = await makeHarness();
    h.session.activateSkill(skill("a", "small"));
    const large = new Named("L", "büyük", new ScriptedProvider([say("tamam")]));
    await collect(mk(h, large), "soru");
    expect(await models(h)).toEqual(["büyük"]);
  });

  it("tüm etkin skill'ler 'small' ise küçük model; biri 'large' veya hint'siz ise ana model", async () => {
    const run = async (skills: ReturnType<typeof skill>[]): Promise<string[]> => {
      const h = await makeHarness();
      for (const s of skills) h.session.activateSkill(s);
      const large = new Named("L", "büyük", new ScriptedProvider([say("L")]));
      const small = new Named("S", "küçük", new ScriptedProvider([say("S")]), "local", "small");
      await collect(mk(h, large, small), "soru");
      return models(h);
    };
    expect(await run([skill("a", "small")])).toEqual(["küçük"]);
    expect(await run([skill("a", "small"), skill("b", "small")])).toEqual(["küçük"]);
    expect(await run([skill("a", "small"), skill("b", "large")])).toEqual(["büyük"]);
    expect(await run([skill("a", "small"), skill("b")])).toEqual(["büyük"]);
    expect(await run([])).toEqual(["büyük"]); // etkin skill yok → ana model
  });

  it("tur ortasında skill etkinleşince kademe değişir; uyarı verilir; sağlayıcıya özgü opak veri (providerData) yeni modele GİTMEZ", async () => {
    let h!: Harness;
    h = await makeHarness({
      handlers: {
        "k8s.resources.list": () => {
          h.session.activateSkill(skill("ucuz", "small")); // araç çağrısı skill'i etkinleştirdi
          return { data: [{ metadata: { name: "api" } }], subjects: ["Deployment/payments/api"] };
        },
      },
    });
    h.session.activeToolsets.add("k8s-core");
    const first: GenerateResult = { ...toolUse([{ name: "k8s.resources.list", args: { kind: "Pod", namespace: "payments" } }]) };
    const withData: GenerateResult = { ...first, message: { ...first.message, providerData: [{ type: "thinking", signature: "SADECE-BUYUK-MODEL" }] } };
    const largeInner = new ScriptedProvider([withData]);
    const smallInner = new ScriptedProvider([say("küçük model özetledi [ev-1]")]);
    const o = mk(h, new Named("L", "büyük", largeInner), new Named("S", "küçük", smallInner, "local", "small"));
    const ev = await collect(o, "listele");
    expect(await models(h)).toEqual(["büyük", "küçük"]);
    expect(ev.some((e) => e.type === "warning" && e.code === "model_tier" && e.message.includes("S/küçük"))).toBe(true);
    expect(ev.find((e) => e.type === "final")).toBeDefined();
    // küçük modele giden baytlarda büyük modelin opak verisi YOK
    expect(smallInner.serialized.join("\n")).not.toContain("SADECE-BUYUK-MODEL");
    expect(JSON.stringify(smallInner.requests[0]!.messages)).not.toContain("providerData");
    // araç çağrısının kendisi (toolCalls) korunur
    expect(smallInner.requests[0]!.messages.some((m) => m.role === "assistant" && (m.toolCalls?.length ?? 0) === 1)).toBe(true);
  });

  it("egress: küçük sağlayıcının bölgesi bağlamın sınırını aşıyorsa ana model kullanılır (fail-closed yönde)", async () => {
    const h = await makeHarness();
    h.session.activateSkill(skill("a", "small"));
    h.session.noteResult({ sensitivity: "secret-adjacent", tainted: false }); // bağlam yalnız yerel sağlayıcıya gidebilir
    const large = new Named("L", "büyük", new ScriptedProvider([say("L")]), "local");
    const small = new Named("S", "küçük-bulut", new ScriptedProvider([say("S")]), "third-party-cloud", "small");
    await collect(mk(h, large, small), "soru");
    expect(await models(h)).toEqual(["büyük"]);
    expect(small.inner.requests).toHaveLength(0);
  });
});
