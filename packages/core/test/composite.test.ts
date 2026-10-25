import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineTool } from "@ops/contracts";
import type { AdapterCall, ToolResult } from "@ops/contracts";
import { FakeAdapter } from "@ops/testkit";
import { makeHarness } from "./harness.ts";

const lim = { timeoutMs: 5000, maxBytes: 100_000, maxItems: 50, maxOutputTokens: 1000 };
const local = { class: "read", scope: "local", profileKind: null, sensitivity: "none", idempotent: true, toolset: "core", untrustedOutput: false, limits: lim, typicalOutputTokens: 50 } as const;
const chain = defineTool({ ...local, name: "demo.chain.run", description: "Bileşik test aracı.", composite: true }, z.strictObject({ plan: z.array(z.string()).max(5) }));
const plain = defineTool({ ...local, name: "demo.plain.run", description: "Bileşik olmayan." }, z.strictObject({}));

async function setup() {
  const seen: { nested: AdapterCall["nested"] | undefined }[] = [];
  const results: ToolResult[] = [];
  const h = await makeHarness({ handlers: { "k8s.resources.list": () => ({ data: [{ metadata: { name: "api" } }], subjects: ["Deployment/payments/api"] }) } });
  const fake = new FakeAdapter("demo", "cli", "k8s", [
    {
      def: chain,
      handler: async (c) => {
        const nested = c.nested;
        if (!nested) throw new Error("nested yok");
        for (const t of (c.args as { plan: string[] }).plan) {
          const [tool, ns] = t.split("@");
          results.push(await nested({ tool: tool as string, args: tool === "demo.chain.run" ? { plan: [] } : tool === "k8s.resources.list" ? { kind: "Deployment", namespace: ns ?? "payments" } : {} }));
        }
        return { data: { n: results.length }, summary: `${results.length} iç çağrı` };
      },
    },
    {
      def: plain,
      handler: async (c) => {
        seen.push({ nested: c.nested });
        return { data: {} };
      },
    },
  ]);
  h.registry.register(fake, [chain, plain]);
  h.session.activeToolsets.add("k8s-core");
  const invoke = (tool: string, args: unknown, zone: "local" | "tenant-cloud" | "third-party-cloud" = "local") =>
    h.gateway.invoke({ tool, args, providerZone: zone, provider: { id: "p", model: "m" } });
  return { h, results, seen, invoke };
}

describe("bileşik araç (composite): iç çağrılar tam PEP'ten geçer", () => {
  it("iç çağrı çalışır: bağlı profil enjekte edilir, sonuç kanıt kimliğiyle döner, denetim iç çağrıyı üst çağrıya bağlar", async () => {
    const { h, results, invoke } = await setup();
    const r = await invoke("demo.chain.run", { plan: ["k8s.resources.list@payments"] });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(results[0]).toMatchObject({ status: "ok", tool: "k8s.resources.list" });
    expect(results[0]!.evidenceId).toBeDefined();
    const recs = await h.records();
    const outer = recs.find((x) => x["event"] === "intent" && x["tool"] === "demo.chain.run")!;
    const inner = recs.find((x) => x["event"] === "intent" && x["tool"] === "k8s.resources.list")!;
    expect(inner["message"]).toBe(`iç çağrı (üst: ${String(outer["callId"])})`);
    expect(inner["profile"]).toBe("test-k8s"); // ToolExecutor tür başına bağlı profili enjekte etti
    expect(inner["provider"]).toBe("p");
  });

  it("sağlayıcı bölgesi iç çağrıya taşınır (egress/hassasiyet denetimi aynı)", async () => {
    const { h, invoke } = await setup();
    await invoke("demo.chain.run", { plan: ["k8s.resources.list@payments"] }, "tenant-cloud");
    const inner = (await h.records()).find((x) => x["event"] === "intent" && x["tool"] === "k8s.resources.list")!;
    expect(inner["trustZone"]).toBe("tenant-cloud");
  });

  it("iç içe bileşik araç REDDEDİLİR (policy_deny); sonsuz özyineleme yok", async () => {
    const { results, invoke } = await setup();
    const r = await invoke("demo.chain.run", { plan: ["demo.chain.run"] });
    expect(r.status).toBe("ok"); // dış araç çalıştı…
    expect(results[0]).toMatchObject({ status: "denied", reasonCode: "policy_deny" }); // …iç içe olan reddedildi
    expect(results[0]!.summary).toContain("iç içe bileşik araç");
  });

  it("etkin olmayan araç setindeki iç çağrı reddedilir (executor kuralı)", async () => {
    const { h, results, invoke } = await setup();
    h.session.activeToolsets.delete("k8s-core");
    await invoke("demo.chain.run", { plan: ["k8s.resources.list@payments"] });
    expect(results[0]).toMatchObject({ status: "denied", reasonCode: "unknown_tool" });
  });

  it("kapsam dışı hedef iç çağrıda da reddedilir (profil kapsamı PEP'te)", async () => {
    const { results, invoke } = await setup();
    await invoke("demo.chain.run", { plan: ["k8s.resources.list@baska-ns"] });
    expect(results[0]).toMatchObject({ status: "denied", reasonCode: "scope_violation" });
  });

  it("bileşik OLMAYAN araca nested verilmez", async () => {
    const { seen, invoke } = await setup();
    await invoke("demo.plain.run", {});
    expect(seen).toEqual([{ nested: undefined }]);
  });

  it("iç çağrı mutasyon sınıfındaysa onay kapısı olmadan çalışmaz (approval_unavailable): bileşik araç yetki kazandırmaz", async () => {
    const { results, h, invoke } = await setup();
    h.session.activeToolsets.add("k8s-core");
    // harness'ın scale aracı: mutate, onay kapısı yok
    await invoke("demo.chain.run", { plan: ["k8s.scale"] });
    expect(results[0]!.status).toBe("denied");
    expect(["approval_unavailable", "schema_invalid", "ceiling_exceeded", "citation_missing"]).toContain(results[0]!.reasonCode);
    expect(h.k8s.calls.filter((c) => c.tool === "k8s.scale")).toHaveLength(0);
  });
});
