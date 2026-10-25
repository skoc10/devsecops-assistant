import { describe, expect, it } from "vitest";
import { FakeApprovalGate } from "@ops/testkit";
import { makeHarness } from "./harness.ts";

const handlers = { "k8s.resources.list": () => ({ data: [{ metadata: { name: "api" } }], subjects: ["Deployment/payments/api"] }) };

describe("egress: local-only (PEP, sağlayıcıdan bağımsız fail-closed)", () => {
  it("yerel sağlayıcı bölgesi + okuma sınıfı çalışır", async () => {
    const h = await makeHarness({ localOnly: true, handlers });
    const r = await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" }, { zone: "local" });
    expect(r.status, JSON.stringify(r)).toBe("ok");
  });

  it("yerel olmayan sağlayıcı bölgesi HER çağrıda reddedilir (local_only), kimlik bağlanmaz, intent yazılmaz", async () => {
    const h = await makeHarness({ localOnly: true, handlers });
    for (const zone of ["tenant-cloud", "third-party-cloud"] as const) {
      const r = await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" }, { zone });
      expect(r, zone).toMatchObject({ status: "denied", reasonCode: "local_only" });
    }
    expect(h.broker.acquired).toHaveLength(0);
    expect((await h.records()).some((x) => x["event"] === "intent")).toBe(false);
  });

  it("mutate/deploy/destroy sınıfı, profil tavanı yeterli olsa ve onay verilecek olsa bile reddedilir; adapter çağrılmaz", async () => {
    const gate = new FakeApprovalGate();
    const h = await makeHarness({ localOnly: true, handlers, profile: { classCeiling: "destroy" }, approval: gate });
    const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
    for (const [tool, args] of [
      ["k8s.scale", { namespace: "payments", name: "api", replicas: 3 }],
      ["k8s.resources.delete", { namespace: "payments", kind: "Deployment", name: "api" }],
    ] as const) {
      expect(await h.call(tool, args, { cited: [ev] }), tool).toMatchObject({ status: "denied", reasonCode: "local_only" });
    }
    expect(gate.requests).toHaveLength(0);
    expect(h.k8s.calls.filter((c) => c.tool === "k8s.scale" || c.tool === "k8s.resources.delete")).toHaveLength(0);
  });

  it("kapalıyken (varsayılan) aynı çağrılar normal akışta çalışır: kip yalnız açıkça etkinleşir", async () => {
    const h = await makeHarness({ handlers, profile: { classCeiling: "mutate" }, approval: new FakeApprovalGate() });
    const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" }, { zone: "tenant-cloud" })).evidenceId!;
    expect((await h.call("k8s.scale", { namespace: "payments", name: "api", replicas: 3 }, { cited: [ev], zone: "tenant-cloud" })).status).toBe("ok");
  });
});
