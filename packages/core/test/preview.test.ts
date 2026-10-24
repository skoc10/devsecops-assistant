import { describe, expect, it } from "vitest";
import type { ActionPreview } from "@ops/contracts";
import { FakeApprovalGate } from "@ops/testkit";
import { makeHarness } from "./harness.ts";

const profile = { classCeiling: "mutate" as const };
const handlers = { "k8s.resources.list": () => ({ data: [{ metadata: { name: "api" } }], subjects: ["Deployment/payments/api"] }) };
const scale = { namespace: "payments", name: "api", replicas: 5 };

async function setup(preview: (n: number) => ActionPreview | Error, gate = new FakeApprovalGate()) {
  const h = await makeHarness({ profile, handlers, approval: gate });
  let n = 0;
  h.k8s.preview = async () => {
    const r = preview(++n);
    if (r instanceof Error) throw r;
    return r;
  };
  const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
  return { h, gate, ev, count: () => n };
}

describe("Faz 2a: önizleme + TOCTOU (PEP)", () => {
  it("onay özeti redakte diff/etki/geri alma/sürüm taşır; araç yalnız yeniden doğrulamadan sonra çalışır ve onaylanan sürümü ön koşul olarak alır", async () => {
    const { h, gate, ev, count } = await setup(() => ({
      targetVersion: "rv-100",
      diff: "--- canlı\n+++ önerilen\n-  replicas: 2\n+  replicas: 5\n",
      impact: ["2 replika → 5"],
      rollback: "kubectl scale deploy/api --replicas=2",
    }));
    const r = await h.call("k8s.scale", scale, { cited: [ev] });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    const req = gate.requests[0]!;
    expect(req.summary.preview).toEqual({ targetVersion: "rv-100", diff: "--- canlı\n+++ önerilen\n-  replicas: 2\n+  replicas: 5\n", impact: ["2 replika → 5"], rollback: "kubectl scale deploy/api --replicas=2" });
    expect(count()).toBe(2); // onay öncesi + çalıştırma öncesi
    const call = h.k8s.calls.find((c) => c.tool === "k8s.scale")!;
    expect(call.approvedVersion).toBe("rv-100");
    // önizleme ve çalıştırma ayrı lease'ler; hepsi bırakıldı
    expect(h.broker.acquired.map((a) => a.purpose)).toEqual(["k8s.resources.list", "k8s.scale:preview", "k8s.scale"]);
    expect(h.broker.active).toBe(0);
  });

  it("önizleme canlı durumdaki secret'ı (M3) ve secret desenlerini (M2) göstermeden önce maskeler", async () => {
    const { h, gate, ev } = await setup(() => ({ diff: `-  token: ${"placeholder"}\n+  token: AKIAABCDEFGHIJKLMNOP\n` }));
    // M3: broker'ın verdiği değer diff'te geçerse maskelenir
    h.k8s.preview = async () => ({ targetVersion: "v", diff: `-  pw: ${h.secret}\n+  note: AKIAABCDEFGHIJKLMNOP\n` });
    const r = await h.call("k8s.scale", scale, { cited: [ev] });
    expect(r.status).toBe("ok");
    const shown = JSON.stringify(gate.requests[0]!.summary.preview);
    expect(shown).not.toContain(h.secret);
    expect(shown).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(shown).toContain("diff");
    expect((await h.lines()).join("\n")).not.toContain(h.secret);
  });

  it("S-09 TOCTOU: onaydan sonra hedef sürümü değişirse ÇALIŞMAZ (target_changed), onay bir kez istendi, denetimde ret", async () => {
    const { h, gate, ev } = await setup((n) => ({ targetVersion: n === 1 ? "rv-1" : "rv-2", diff: "d" }));
    const r = await h.call("k8s.scale", scale, { cited: [ev] });
    expect(r).toMatchObject({ status: "denied", reasonCode: "target_changed" });
    expect(gate.requests).toHaveLength(1);
    expect(h.k8s.calls.filter((c) => c.tool === "k8s.scale")).toHaveLength(0);
    expect(h.broker.active).toBe(0);
    const recs = await h.records();
    const last = recs.at(-1)!;
    expect(last).toMatchObject({ event: "result", decision: "deny", reasonCode: "target_changed", exitStatus: "denied" });
    // intent (write-ahead) yazılmıştı ama sonuç ret
    expect(recs.some((x) => x["event"] === "intent" && x["tool"] === "k8s.scale")).toBe(true);
  });

  it("sürüm aynı kalsa bile diff değişirse ÇALIŞMAZ", async () => {
    const { h, ev } = await setup((n) => ({ targetVersion: "rv-1", diff: n === 1 ? "+a\n" : "+b\n" }));
    expect(await h.call("k8s.scale", scale, { cited: [ev] })).toMatchObject({ reasonCode: "target_changed" });
    expect(h.k8s.calls.filter((c) => c.tool === "k8s.scale")).toHaveLength(0);
  });

  it("önizleme hatası: onay İSTENMEZ, çağrı reddedilir (preview_failed)", async () => {
    const { h, gate, ev } = await setup(() => new Error("API 500"));
    expect(await h.call("k8s.scale", scale, { cited: [ev] })).toMatchObject({ status: "denied", reasonCode: "preview_failed" });
    expect(gate.requests).toHaveLength(0);
    expect(h.k8s.calls.filter((c) => c.tool === "k8s.scale")).toHaveLength(0);
    expect(h.broker.active).toBe(0);
  });

  it("çalıştırma öncesi yeniden doğrulama HATA verirse de ÇALIŞMAZ", async () => {
    const { h, ev } = await setup((n) => (n === 1 ? { targetVersion: "v", diff: "d" } : new Error("bağlantı koptu")));
    expect(await h.call("k8s.scale", scale, { cited: [ev] })).toMatchObject({ reasonCode: "preview_failed" });
    expect(h.k8s.calls.filter((c) => c.tool === "k8s.scale")).toHaveLength(0);
  });

  it("eylem hash'i diff'e/sürüme bağlıdır: farklı önizleme farklı hash; onay başka önizlemeye taşınamaz", async () => {
    let first: string | undefined;
    const gate = new FakeApprovalGate((req) => {
      if (first === undefined) {
        first = req.actionHash;
        return true;
      }
      // ikinci çağrıda ESKİ onayı (ilk hash) sunmaya çalış
      return { approved: true, approvalId: "replay", actionHash: first };
    });
    let v = 1;
    const { h, ev } = await setup(() => ({ targetVersion: `rv-${v}`, diff: `+v${v}\n` }), gate);
    expect((await h.call("k8s.scale", scale, { cited: [ev] })).status).toBe("ok");
    v = 2;
    const r = await h.call("k8s.scale", scale, { cited: [ev] });
    expect(r).toMatchObject({ status: "denied", reasonCode: "approval_denied" });
    expect(gate.requests[0]!.actionHash).not.toBe(gate.requests[1]!.actionHash);
  });

  it("read araçlar önizlenmez; önizleme desteklemeyen adapter'ın mutasyonu eskisi gibi çalışır", async () => {
    const { h, ev, count } = await setup(() => ({ targetVersion: "v" }));
    await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" });
    expect(count()).toBe(0);
    const plain = await makeHarness({ profile, handlers, approval: new FakeApprovalGate() });
    const e2 = (await plain.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
    expect((await plain.call("k8s.scale", scale, { cited: [e2] })).status).toBe("ok");
    expect(plain.k8s.calls.find((c) => c.tool === "k8s.scale")?.approvedVersion).toBeUndefined();
    void ev;
  });
});
