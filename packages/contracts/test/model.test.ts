import { describe, expect, it } from "vitest";
import { AuditBodySchema, runtimeIsSafe, ToolResultSchema } from "../src/index.ts";

describe("runtimeIsSafe", () => {
  it("yerleşik araçlar kapatılamıyorsa veya sandbox yoksa güvenli değildir", () => {
    const ok = { builtinToolsDisableable: true, osSandboxed: true, trustZone: "third-party-cloud", statelessSupported: true } as const;
    expect(runtimeIsSafe(ok)).toBe(true);
    expect(runtimeIsSafe({ ...ok, builtinToolsDisableable: false })).toBe(false);
    expect(runtimeIsSafe({ ...ok, osSandboxed: false })).toBe(false);
    expect(runtimeIsSafe({ ...ok, statelessSupported: false })).toBe(false);
  });
});

describe("denetim ve sonuç şemaları", () => {
  it("AuditBody katıdır: bilinmeyen (ham çıktı) alan reddedilir", () => {
    const base = { ts: "2026-01-01T00:00:00Z", event: "intent", sessionId: "s", principal: "local-user" };
    expect(AuditBodySchema.safeParse(base).success).toBe(true);
    expect(AuditBodySchema.safeParse({ ...base, rawOutput: "..." }).success).toBe(false);
  });

  it("ToolResult sebep kodu ve belirteç tahmini taşır", () => {
    const r = {
      callId: "c1", tool: "k8s.resources.list", status: "ok", summary: "3 öğe", byReference: false, truncated: false,
      redactions: [], provenance: { source: "k8s", observedAt: "2026-01-01T00:00:00Z" },
      sensitivity: "internal", taint: "trusted", subjects: [], tokens: { estimate: 12 },
    };
    expect(ToolResultSchema.safeParse(r).success).toBe(true);
    expect(ToolResultSchema.safeParse({ ...r, tokens: { estimate: -1 } }).success).toBe(false);
  });
});
