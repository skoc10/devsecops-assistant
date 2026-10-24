import { describe, expect, it } from "vitest";
import { FakeApprovalGate } from "@ops/testkit";
import { ToolExecutor } from "../src/index.ts";
import { makeHarness } from "./harness.ts";

const profile = { classCeiling: "mutate" as const };
const handlers = { "k8s.resources.list": () => ({ data: [{ metadata: { name: "api" } }], subjects: ["Deployment/payments/api"] }) };

async function exec() {
  const h = await makeHarness({ profile, handlers, approval: new FakeApprovalGate() });
  h.session.activeToolsets.add("k8s-core");
  const ex = new ToolExecutor({ gateway: h.gateway, registry: h.registry, session: h.session, audit: h.audit, provider: { id: "t", model: "t" }, zone: "local" });
  return { h, ex };
}

describe("model atfı: ayrılmış `cited` alanı", () => {
  it("mutasyon+ araç şemasına `cited` eklenir; okuma araçlarına eklenmez; manifest şeması değişmez", async () => {
    const { h } = await exec();
    const specs = h.registry.specsFor(["k8s-core"]);
    const scale = specs.find((s) => s.name === "k8s.scale")!;
    const list = specs.find((s) => s.name === "k8s.resources.list")!;
    expect((scale.inputSchema["properties"] as Record<string, unknown>)["cited"]).toMatchObject({ type: "array", maxItems: 10 });
    expect((list.inputSchema["properties"] as Record<string, unknown>)["cited"]).toBeUndefined();
    expect(h.registry.get("k8s.scale")!.def.descriptor.inputSchema["properties"]).not.toHaveProperty("cited");
  });

  it("executor `cited`ı şemadan ÖNCE ayırıp PEP'e atıf olarak verir; onay özeti kanıtı gösterir; denetim atıfı kaydeder", async () => {
    const { h, ex } = await exec();
    const ev = await ex.execute({ id: "1", name: "k8s.resources.list", args: { kind: "Deployment", namespace: "payments" } });
    expect(ev.evidenceId).toBeTruthy();
    const r = await ex.execute({ id: "2", name: "k8s.scale", args: { namespace: "payments", name: "api", replicas: 3, cited: [ev.evidenceId] } });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    const intent = (await h.records()).find((x) => x["tool"] === "k8s.scale" && x["event"] === "intent")!;
    expect(intent["message"]).toBe(`atıf: ${ev.evidenceId}`);
    expect(JSON.stringify(intent["argsRedacted"])).not.toContain("cited");
  });

  it("atıfsız, bozuk biçimli, çok uzun veya başka kaynağa ait atıf reddedilir", async () => {
    const { ex } = await exec();
    const ev = (await ex.execute({ id: "1", name: "k8s.resources.list", args: { kind: "Deployment", namespace: "payments" } })).evidenceId;
    const base = { namespace: "payments", name: "api", replicas: 3 };
    expect(await ex.execute({ id: "2", name: "k8s.scale", args: base })).toMatchObject({ reasonCode: "citation_missing" });
    expect(await ex.execute({ id: "3", name: "k8s.scale", args: { ...base, cited: "ev-1" } })).toMatchObject({ reasonCode: "schema_invalid" });
    expect(await ex.execute({ id: "4", name: "k8s.scale", args: { ...base, cited: ["kanit-1"] } })).toMatchObject({ reasonCode: "schema_invalid" });
    expect(await ex.execute({ id: "5", name: "k8s.scale", args: { ...base, cited: Array.from({ length: 11 }, (_, i) => `ev-${i}`) } })).toMatchObject({ reasonCode: "schema_invalid" });
    expect(await ex.execute({ id: "6", name: "k8s.scale", args: { ...base, name: "baska", cited: [ev] } })).toMatchObject({ reasonCode: "citation_missing" });
    expect(await ex.execute({ id: "7", name: "k8s.scale", args: { ...base, cited: ["ev-999"] } })).toMatchObject({ reasonCode: "citation_missing" });
  });

  it("okuma araçlarında `cited` şema ihlalidir (ayrılmış alan yalnız mutasyon+ içindir)", async () => {
    const { ex } = await exec();
    expect(await ex.execute({ id: "1", name: "k8s.resources.list", args: { kind: "Deployment", namespace: "payments", cited: ["ev-1"] } })).toMatchObject({ reasonCode: "schema_invalid" });
  });
});
