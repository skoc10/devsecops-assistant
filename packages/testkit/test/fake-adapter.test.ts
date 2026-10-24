import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineTool } from "@ops/contracts";
import type { Adapter } from "@ops/contracts";
import { adapterConformance } from "../src/conformance.ts";
import { checkAdapterStructure, FakeAdapter, makeTestProfile } from "../src/index.ts";

const listTool = defineTool(
  {
    name: "fake.items.list",
    description: "Sahte listeleme.",
    class: "read",
    profileKind: "k8s",
    sensitivity: "internal",
    idempotent: true,
    limits: { timeoutMs: 1000, maxBytes: 10_000, maxItems: 50, maxOutputTokens: 1000 },
    untrustedOutput: false,
    toolset: "fake",
    typicalOutputTokens: 100,
  },
  z.strictObject({ namespace: z.string().optional() }),
);

function make(): FakeAdapter {
  return new FakeAdapter("fake", "kubernetes", "k8s", [
    { def: listTool, handler: () => ({ data: [{ ad: "a" }], subjects: ["Pod/default/a"] }) },
  ]);
}

adapterConformance("FakeAdapter", make);

describe("FakeAdapter", () => {
  it("hedefi profilin pininden ve namespace argümanından çözer", () => {
    const a = make();
    const t = a.resolveTarget("fake.items.list", { namespace: "payments" }, makeTestProfile());
    expect(t.scopes).toEqual(["payments"]);
    expect(t.endpoint).toBe("https://k8s.test.invalid:6443");
  });

  it("endpointOverride pin uyuşmazlığı senaryosunu mümkün kılar", () => {
    const a = make();
    a.endpointOverride = "https://baska.invalid:6443";
    expect(a.resolveTarget("fake.items.list", {}, makeTestProfile()).endpoint).toBe("https://baska.invalid:6443");
  });

  it("çağrıları kaydeder", async () => {
    const a = make();
    const out = await a.invoke({
      tool: "fake.items.list", args: {}, profile: makeTestProfile(), handle: null,
      callId: "c1", signal: new AbortController().signal, limits: listTool.descriptor.limits,
    });
    expect(out.subjects).toEqual(["Pod/default/a"]);
    expect(a.calls).toHaveLength(1);
  });

  it("farklı türdeki profili reddeder", () => {
    expect(make().validateProfile(makeTestProfile({ id: "x", kind: "db" }))).not.toEqual([]);
  });
});

describe("checkAdapterStructure", () => {
  it("bozuk adapter'ı yakalar", () => {
    const bad = make();
    const broken = {
      ...bad,
      manifest: { ...bad.manifest, tools: [{ ...listTool.descriptor, inputSchema: { type: "object", additionalProperties: true } }] },
    } as unknown as Adapter;
    expect(checkAdapterStructure(broken).join("\n")).toMatch(/additionalProperties/);
  });

  it("çok yüksek çıktı tavanını işaretler", () => {
    const bad = make();
    const tool = { ...listTool.descriptor, limits: { ...listTool.descriptor.limits, maxOutputTokens: 50_000 } };
    const broken = { ...bad, manifest: { ...bad.manifest, tools: [tool] } } as unknown as Adapter;
    expect(checkAdapterStructure(broken).join("\n")).toMatch(/tavanı çok yüksek/);
  });
});
