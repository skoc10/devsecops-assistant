import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineTool, ToolDescriptorSchema } from "../src/index.ts";
import type { ToolDescriptorMeta } from "../src/index.ts";

const meta: ToolDescriptorMeta = {
  name: "k8s.resources.list",
  description: "Kaynakları listeler.",
  class: "read",
  profileKind: "k8s",
  sensitivity: "internal",
  idempotent: true,
  limits: { timeoutMs: 5000, maxBytes: 100_000, maxItems: 200, maxOutputTokens: 1500 },
  untrustedOutput: false,
  toolset: "k8s-core",
  typicalOutputTokens: 400,
};

describe("defineTool", () => {
  it("strictObject girdisinden additionalProperties:false JSON Schema üretir", () => {
    const t = defineTool(meta, z.strictObject({ kind: z.string(), limit: z.number().int().optional() }));
    expect(t.descriptor.inputSchema["additionalProperties"]).toBe(false);
    expect(t.descriptor.inputSchema["$schema"]).toBeUndefined();
    expect((t.descriptor.inputSchema["properties"] as Record<string, unknown>)["kind"]).toBeDefined();
  });

  it("strict olmayan nesne girdisini reddeder (argüman enjeksiyonu savunması)", () => {
    expect(() => defineTool(meta, z.object({ kind: z.string() }))).toThrow(/strictObject/);
  });

  it("varsayılanları uygular (scope=target, network=none, localWrite=false)", () => {
    const t = defineTool(meta, z.strictObject({}));
    expect(t.descriptor.scope).toBe("target");
    expect(t.descriptor.network).toBe("none");
    expect(t.descriptor.localWrite).toBe(false);
    expect(t.descriptor.redactionProfile).toBe("default");
  });

  it("geçersiz araç adını reddeder", () => {
    expect(() => defineTool({ ...meta, name: "Bad Name" }, z.strictObject({}))).toThrow();
    expect(() => defineTool({ ...meta, name: "noprefix" }, z.strictObject({}))).toThrow();
  });
});

describe("ToolDescriptorSchema kuralları", () => {
  const base = defineTool(meta, z.strictObject({})).descriptor;

  it("read sınıfı network:open aracı kabul etmez", () => {
    expect(ToolDescriptorSchema.safeParse({ ...base, network: "open" }).success).toBe(false);
    expect(ToolDescriptorSchema.safeParse({ ...base, network: "allowlisted" }).success).toBe(true);
  });

  it("localWrite yalnız scope:local araçlarda", () => {
    expect(ToolDescriptorSchema.safeParse({ ...base, localWrite: true }).success).toBe(false);
    expect(
      ToolDescriptorSchema.safeParse({ ...base, scope: "local", localWrite: true, profileKind: null }).success,
    ).toBe(true);
  });

  it("scope:local araç profil kullanamaz", () => {
    expect(ToolDescriptorSchema.safeParse({ ...base, scope: "local" }).success).toBe(false);
  });

  it("fazladan alanı reddeder", () => {
    expect(ToolDescriptorSchema.safeParse({ ...base, extra: 1 }).success).toBe(false);
  });
});
