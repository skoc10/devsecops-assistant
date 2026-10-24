import { describe, expect, it } from "vitest";
import { ScriptedProvider, say, toolUse } from "../src/index.ts";

describe("ScriptedProvider", () => {
  it("adımları sırayla oynatır ve her isteği kaydeder", async () => {
    const p = new ScriptedProvider([toolUse([{ name: "k8s.resources.list", args: { kind: "Pod" } }]), say("bitti")]);
    const req = { system: "sys", messages: [{ role: "user", content: "merhaba" }] as const, tools: [] };
    const r1 = await p.generate(req);
    expect(r1.stopReason).toBe("tool_use");
    expect(r1.message.toolCalls[0]?.name).toBe("k8s.resources.list");
    const r2 = await p.generate(req);
    expect(r2.message.content).toBe("bitti");
    expect(p.requests).toHaveLength(2);
    expect(p.serialized[0]).toContain("merhaba");
    expect(p.turns).toBe(2);
  });

  it("girdi token tahmini isteğin boyutundan türetilir", async () => {
    const p = new ScriptedProvider([say("a")]);
    const r = await p.generate({ system: "x".repeat(700), messages: [], tools: [] });
    expect(r.usage.inputTokens).toBeGreaterThan(150);
  });

  it("script bitince net hata verir", async () => {
    const p = new ScriptedProvider([]);
    await expect(p.generate({ system: "", messages: [], tools: [] })).rejects.toThrow(/adım yok/);
  });

  it("varsayılan bölge local, host döngüsü", () => {
    const p = new ScriptedProvider([]);
    expect(p.capabilities.loopOwner).toBe("host");
    expect(p.capabilities.trustZone).toBe("local");
    expect(new ScriptedProvider([], { trustZone: "third-party-cloud" }).capabilities.trustZone).toBe("third-party-cloud");
  });
});
