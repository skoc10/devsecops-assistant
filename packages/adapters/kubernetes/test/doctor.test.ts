import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FakeK8sApi, READONLY_RULES, makeCanary } from "@ops/testkit";
import type { FakeRule } from "@ops/testkit";
import { buildKubeconfig } from "@ops/testkit";
import { credentialKey, importKubeconfig } from "@ops/broker";
import { makeK8sHarness } from "./harness.ts";
import type { K8sHarness } from "./harness.ts";

async function check(h: K8sHarness, profile = h.profile) {
  const lease = await h.broker.acquire({ profile, purpose: "doctor", callId: "d1", ttlSec: 30 }, h.known);
  try {
    return await h.adapter.doctor!(lease.handle, profile);
  } finally {
    await lease.release();
  }
}
const withRules = (extra: FakeRule[]) => ({ resourceRules: [...READONLY_RULES.resourceRules, ...extra] });

describe("profil doktoru (k8s)", () => {
  let h: K8sHarness;
  beforeEach(async () => {
    h = await makeK8sHarness();
  });
  afterEach(async () => {
    await h.stop();
  });

  it("salt okunur kimlik: bağlanabilir, kimlik yankısı, fiili sınıf read", async () => {
    const r = await check(h);
    expect(r).toMatchObject({ connected: true, pinOk: true, identity: "ops-test-user", effectiveClass: "read", bindable: true, scopesChecked: ["payments"] });
    expect(r.findings.filter((f) => f.severity === "error")).toEqual([]);
  });

  it.each([
    ["yazma (create pods)", [{ verbs: ["create"], apiGroups: [""], resources: ["pods"] }], ["write_access", "ceiling_exceeded_by_rbac"]],
    ["exec", [{ verbs: ["create"], apiGroups: [""], resources: ["pods/exec"] }], ["exec_access", "ceiling_exceeded_by_rbac"]],
    ["silme", [{ verbs: ["delete"], apiGroups: [""], resources: ["configmaps"] }], ["delete_access", "ceiling_exceeded_by_rbac"]],
    ["Secret okuma", [{ verbs: ["get", "list"], apiGroups: [""], resources: ["secrets"] }], ["secrets_readable"]],
    ["joker kaynak (okuma)", [{ verbs: ["get"], apiGroups: ["*"], resources: ["*"] }], ["wildcard_resources", "secrets_readable"]],
    ["joker fiil", [{ verbs: ["*"], apiGroups: [""], resources: ["pods"] }], ["wildcard_verbs", "ceiling_exceeded_by_rbac"]],
    ["impersonate", [{ verbs: ["impersonate"], apiGroups: [""], resources: ["users"] }], ["privilege_escalation_verb", "ceiling_exceeded_by_rbac"]],
    ["node proxy", [{ verbs: ["get"], apiGroups: [""], resources: ["nodes/proxy"] }], ["proxy_access", "ceiling_exceeded_by_rbac"]],
    ["token üretme", [{ verbs: ["create"], apiGroups: [""], resources: ["serviceaccounts/token"] }], ["token_mint", "ceiling_exceeded_by_rbac"]],
  ])("read beyanlı profil + %s → bağlanamaz (S-14)", async (_n, extra, codes) => {
    h.api.setRules("payments", withRules(extra as FakeRule[]));
    const r = await check(h);
    expect(r.bindable).toBe(false);
    expect(r.findings.map((f) => f.code)).toEqual(expect.arrayContaining(codes as string[]));
  });

  it("RBAC sonradan genişletilirse aynı profil artık bağlanamaz (yetki kayması)", async () => {
    expect((await check(h)).bindable).toBe(true);
    h.api.setRules("payments", withRules([{ verbs: ["patch"], apiGroups: ["apps"], resources: ["deployments"] }]));
    const after = await check(h);
    expect(after.bindable).toBe(false);
    expect(after.effectiveClass).toBe("deploy");
  });

  it("tavan beyanı yazmaya izin veriyorsa yazma bulguları uyarıdır, profil bağlanır", async () => {
    const h2 = await makeK8sHarness({ profile: { classCeiling: "deploy" } });
    try {
      h2.api.setRules("payments", withRules([{ verbs: ["patch"], apiGroups: ["apps"], resources: ["deployments"] }]));
      const r = await check(h2, h2.profile);
      expect(r.bindable).toBe(true);
      expect(r.effectiveClass).toBe("deploy");
      expect(r.findings.find((f) => f.code === "write_access")?.severity).toBe("warn");
    } finally {
      await h2.stop();
    }
  });

  it("eksik kural listesi uyarıdır; hiç kural okunamazsa 'rbac_unverified' hata", async () => {
    h.api.setRules("payments", { ...READONLY_RULES, incomplete: true, evaluationError: "webhook zaman aşımı" });
    const inc = await check(h);
    expect(inc.bindable).toBe(true);
    expect(inc.findings.map((f) => f.code)).toEqual(expect.arrayContaining(["rules_incomplete", "rules_evaluation_error"]));

    h.api.fault("/apis/authorization.k8s.io", (res) => {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ kind: "Status", reason: "Forbidden", code: 403, message: "forbidden" }));
    });
    const bad = await check(h);
    expect(bad.bindable).toBe(false);
    expect(bad.findings.map((f) => f.code)).toContain("rbac_unverified");
  });

  it("pin uyuşmazlığı: kimlik gönderilmez, pinOk=false, bağlanamaz", async () => {
    const attacker = await makeK8sHarness();
    const hh = await makeK8sHarness({ vaultServer: attacker.api.url });
    try {
      const r = await check(hh);
      expect(r).toMatchObject({ pinOk: false, connected: false, bindable: false });
      expect(attacker.api.requests.length).toBe(0);
      expect(hh.api.requests.length).toBe(0);
    } finally {
      await hh.stop();
      await attacker.stop();
    }
  });

  it("yanlış token: connect_failed; mesajlarda token yok", async () => {
    const wrong = makeCanary("dr-wrong");
    const imp = await importKubeconfig(buildKubeconfig({ server: h.api.url, caPem: h.pki.caPem, token: wrong.value }));
    await h.store.set(credentialKey(h.profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));
    const r = await check(h);
    expect(r).toMatchObject({ connected: false, bindable: false });
    expect(r.findings.map((f) => f.code)).toContain("connect_failed");
    expect(JSON.stringify(r)).not.toContain(wrong.value);
  });

  it("kapsam '*' veya 'cluster' ise 'default' örneklenir (info)", async () => {
    const h3 = await makeK8sHarness({ profile: { allowedScopes: ["*"] } });
    try {
      const r = await check(h3, h3.profile);
      expect(r.scopesChecked).toEqual(["default"]);
      expect(r.findings.map((f) => f.code)).toContain("scope_sampled");
    } finally {
      await h3.stop();
    }
  });

  it("anonim kimlik reddedilir", async () => {
    const pki = h.pki;
    const anon = await FakeK8sApi.start({ pki, token: h.canaries.kubeToken.value, username: "system:anonymous" });
    try {
      const imp = await importKubeconfig(buildKubeconfig({ server: anon.url, caPem: pki.caPem, token: h.canaries.kubeToken.value }));
      await h.store.set(credentialKey(h.profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));
      const profile = { ...h.profile, targetPin: { endpoint: anon.url, caFingerprint: pki.caFingerprint } };
      const r = await check(h, profile);
      expect(r.bindable).toBe(false);
      expect(r.findings.map((f) => f.code)).toContain("anonymous_identity");
    } finally {
      await anon.stop();
    }
  });

  it("rapor secret içermez", async () => {
    const r = await check(h);
    const sink = await h.sinkFor([]);
    sink.push("report", JSON.stringify(r));
    expect(sink.leaks(h.allCanaries)).toEqual([]);
  });
});
