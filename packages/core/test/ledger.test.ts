import { describe, expect, it } from "vitest";
import type { Message } from "@ops/contracts";
import { Ledger, compactMessages, messagesTokens, usageFromAudit, formatUsage, verifyCitations, EvidenceStore } from "../src/index.ts";

describe("Ledger / compactMessages", () => {
  const big = "x".repeat(4000);
  const history = (): Message[] => [
    { role: "user", content: "ilk soru" },
    { role: "assistant", content: "", toolCalls: [{ id: "1", name: "t", args: {} }] },
    { role: "tool", toolCallId: "1", name: "t", content: JSON.stringify({ id: "ev-1", view: big }) },
    { role: "assistant", content: "cevap 1 [ev-1]" },
    { role: "user", content: "ikinci soru" },
    { role: "assistant", content: "", toolCalls: [{ id: "2", name: "t", args: {} }, { id: "3", name: "t", args: {} }] },
    { role: "tool", toolCallId: "2", name: "t", content: JSON.stringify({ id: "ev-2", view: big }) },
    { role: "tool", toolCallId: "3", name: "t", content: JSON.stringify({ id: "ev-3", view: big }) },
  ];

  it("eşik altında dokunmaz", () => {
    const l = new Ledger();
    const r = compactMessages(history(), l, { thresholdTokens: 100_000, summaryTokens: 500, keepToolMessages: 2 });
    expect(r.compacted).toBe(false);
  });

  it("eski turlar özetlenir, mevcut tur korunur, eski araç gövdeleri referansa döner; eşleşme bozulmaz", () => {
    const l = new Ledger();
    l.noteGoal("ilk soru");
    l.noteEvidence({ id: "ev-1", tool: "t", summary: "özet bir", subjects: ["Pod/ns/a"] });
    l.noteConclusion("cevap 1");
    const r = compactMessages(history(), l, { thresholdTokens: 800, summaryTokens: 300, keepToolMessages: 1 });
    expect(r.compacted).toBe(true);
    expect(r.messages[0]).toMatchObject({ role: "user" });
    expect((r.messages[0] as { content: string }).content).toContain("ev-1 t: özet bir");
    expect(r.messages[1]).toMatchObject({ role: "user", content: "ikinci soru" });
    const tools = r.messages.filter((m) => m.role === "tool") as { content: string; toolCallId: string }[];
    expect(tools.map((t) => t.toolCallId)).toEqual(["2", "3"]);
    expect(tools[0]?.content).toBe("(sonuç ev-2 olarak saklandı; evidence.get ile alın)");
    expect(tools[1]?.content).toContain("ev-3"); // en yeni korunur
    expect(messagesTokens(r.messages)).toBeLessThan(messagesTokens(history()));
  });

  it("özet token tavanını aşmaz (en eski kanıt satırları düşer)", () => {
    const l = new Ledger();
    for (let i = 1; i <= 200; i++) l.noteEvidence({ id: `ev-${i}`, tool: "k8s.pods.logs", summary: "log özeti ".repeat(5), subjects: [] });
    expect(l.summarize(300).length).toBeLessThan(300 * 4.5);
  });
});

describe("verifyCitations", () => {
  it("var olan ve olmayan kimlikleri ayırır", () => {
    const s = new EvidenceStore();
    s.put({ callId: "c", tool: "t", profileId: undefined, epoch: 0, observedAt: "x", subjects: [], sensitivity: "none", taint: "trusted", summary: "s", text: "{}" });
    const c = verifyCitations("bkz [ev-1] ve [ev-5], ev-1 tekrar", s);
    expect(c).toEqual({ cited: ["ev-1", "ev-5"], valid: ["ev-1"], invalid: ["ev-5"] });
    expect(verifyCitations("atıf yok", s).cited).toEqual([]);
  });
});

describe("usage raporu", () => {
  it("denetim kaydından rapor üretir ve biçimler", () => {
    const rec = (o: object) => ({ seq: 0, prevHash: "0".repeat(64), hash: "0".repeat(64), ts: "t", principal: "p", sessionId: "s1", ...o }) as never;
    const r = usageFromAudit([
      rec({ event: "model_call", tokens: { input: 100, output: 20, cacheRead: 50 } }),
      rec({ event: "model_call", tokens: { input: 200, output: 30, cacheRead: 150 } }),
      rec({ event: "model_call", message: "request" }),
      rec({ event: "result", tool: "k8s.pods.logs", resultTokensEstimate: 700 }),
      rec({ event: "result", tool: "k8s.resources.list", resultTokensEstimate: 300 }),
      rec({ event: "result", tool: "k8s.resources.list", resultTokensEstimate: 100, sessionId: "s2" }),
    ], "s1");
    expect(r).toMatchObject({ modelCalls: 2, inputTokens: 300, outputTokens: 50, cacheReadTokens: 200, toolCalls: 2, resultTokens: 1000 });
    expect(r.top[0]).toMatchObject({ tool: "k8s.pods.logs", resultTokens: 700 });
    expect(formatUsage(r)).toContain("k8s.pods.logs: 1 çağrı, 700 token");
  });
});
