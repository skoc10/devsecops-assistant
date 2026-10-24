import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adapterConformance } from "@ops/testkit/conformance";
import { checkAdapterStructure } from "@ops/testkit";
import type { ToolResult } from "@ops/contracts";
import { LocalBroker, MemorySecretStore } from "@ops/broker";
import { KubernetesAdapter } from "../src/index.ts";
import { makeK8sHarness } from "./harness.ts";
import type { K8sHarness } from "./harness.ts";

adapterConformance("kubernetes", () => new KubernetesAdapter(new LocalBroker({ store: new MemorySecretStore() }).resolver));

describe("KubernetesAdapter yapısı", () => {
  it("araç adları, toolset'ler ve sınıflar beklenen gibi; hepsi read", () => {
    const a = new KubernetesAdapter(new LocalBroker({ store: new MemorySecretStore() }).resolver);
    expect(checkAdapterStructure(a)).toEqual([]);
    const names = a.manifest.tools.map((t) => t.name).sort();
    expect(names).toEqual(["k8s.events.list", "k8s.pods.logs", "k8s.profile.describe", "k8s.resources.describe", "k8s.resources.get", "k8s.resources.list"]);
    expect(a.manifest.tools.every((t) => t.class === "read")).toBe(true);
    expect(a.manifest.tools.filter((t) => t.toolset === "core").map((t) => t.name)).toEqual(["k8s.profile.describe"]);
    // log/olay/describe çıktıları untrusted
    for (const n of ["k8s.pods.logs", "k8s.events.list", "k8s.resources.describe"]) {
      expect(a.manifest.tools.find((t) => t.name === n)?.untrustedOutput).toBe(true);
    }
  });

  it("araç şemaları katı ve küçük: tüm şemalar toplamı ≤ 2.5k token tahmini", async () => {
    const { estimateTokens } = await import("@ops/contracts");
    const a = new KubernetesAdapter(new LocalBroker({ store: new MemorySecretStore() }).resolver);
    const specs = JSON.stringify(a.manifest.tools.map((t) => ({ n: t.name, d: t.description, s: t.inputSchema })));
    expect(estimateTokens(specs)).toBeLessThanOrEqual(2_500);
  });

  it("sabit olmayan girdiler: kapsamsız namespace, bilinmeyen tür, kötü since çözümlemede reddedilir", async () => {
    const h = await makeK8sHarness();
    try {
      const r1 = await h.call("k8s.resources.list", { kind: "Pod" });
      expect(r1).toMatchObject({ status: "denied", reasonCode: "target_unresolved" });
      const r2 = await h.call("k8s.resources.list", { kind: "Frobnicator", namespace: "payments" });
      expect(r2).toMatchObject({ status: "denied", reasonCode: "target_unresolved" });
      expect(r2.summary).toContain("Desteklenenler");
      const r3 = await h.call("k8s.events.list", { namespace: "payments", since: "30 minutes" });
      expect(r3).toMatchObject({ status: "denied", reasonCode: "schema_invalid" });
      const r4 = await h.call("k8s.events.list", { namespace: "payments", since: "99999d" });
      expect(r4.status).toBe("denied");
      const r5 = await h.call("k8s.resources.get", { kind: "Node", name: "node-1", namespace: "payments" });
      expect(r5).toMatchObject({ status: "denied", reasonCode: "target_unresolved" });
      expect(h.api.requests.length).toBe(0);
    } finally {
      await h.stop();
    }
  });

  it("yol enjeksiyonu: namespace/ad alanları DNS biçimi dışında şemada reddedilir", async () => {
    const h = await makeK8sHarness();
    try {
      for (const bad of ["../kube-system", "payments/pods", "payments?x=1", "Payments", "a b"]) {
        const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: bad });
        expect(r.status, bad).toBe("denied");
      }
      const r = await h.call("k8s.resources.get", { kind: "Pod", namespace: "payments", name: "../../secrets" });
      expect(r.status).toBe("denied");
      expect(h.api.requests.length).toBe(0);
    } finally {
      await h.stop();
    }
  });
});

describe("KubernetesAdapter okuma araçları (sahte API, gerçek TLS)", () => {
  let h: K8sHarness;
  beforeEach(async () => {
    h = await makeK8sHarness();
  });
  afterEach(async () => {
    await h.stop();
  });

  it("k8s.profile.describe: ağa gitmez, secret içermez", async () => {
    const r = await h.call("k8s.profile.describe", {});
    expect(r.status).toBe("ok");
    expect(JSON.stringify(r.view)).toContain("payments");
    expect(h.api.requests.length).toBe(0);
    const sink = await h.sinkFor([r]);
    expect(sink.leaks(h.allCanaries)).toEqual([]);
  });

  it("pods listesi: kompakt görünüm; managedFields yok; yeniden başlatma sayısı görünür", async () => {
    const r = await h.call("k8s.resources.list", { kind: "pods", namespace: "payments" });
    expect(r.status).toBe("ok");
    const text = JSON.stringify(r.view);
    expect(text).toContain("api-7d9c-a1");
    expect(text).toContain("CrashLoopBackOff");
    expect(text).toContain("14");
    expect(text).not.toContain("managedFields");
    expect(text).not.toContain("worker-x1"); // başka namespace
    expect(r.tokens.estimate).toBeLessThan(700);
    expect(r.subjects).toEqual(expect.arrayContaining(["Pod/payments/api-7d9c-a1", "Pod/payments/api-7d9c-b2"]));
    // doğru kimlikle, yalnız GET ile gidildi
    expect(h.api.requests.every((q) => q.method === "GET" && q.bearer === h.canaries.kubeToken.value)).toBe(true);
  });

  it("labelSelector/fieldSelector sunucuya iletilir; limit sunucuya ve sonuca yansır", async () => {
    const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments", fieldSelector: "metadata.name=api-7d9c-a1" });
    expect(r.status).toBe("ok");
    expect(JSON.stringify(r.view)).not.toContain("api-7d9c-b2");
    const r2 = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments", limit: 1 });
    expect(r2.truncated).toBe(true);
    expect(r2.summary).toMatch(/\+1 daha var/);
  });

  it("küme kapsamlı tür: profil 'cluster' veya '*' izinli değilse kapsam reddi", async () => {
    const denied = await h.call("k8s.resources.list", { kind: "Node" });
    expect(denied).toMatchObject({ status: "denied", reasonCode: "scope_violation" });
    expect(h.api.requests.length).toBe(0);

    const h2 = await makeK8sHarness({ profile: { allowedScopes: ["payments", "cluster"] } });
    try {
      const ok = await h2.call("k8s.resources.list", { kind: "Node" });
      expect(ok.status).toBe("ok");
      expect(JSON.stringify(ok.view)).toContain("node-1");
    } finally {
      await h2.stop();
    }
  });

  it("kapsam dışı namespace PEP'te reddedilir; API'ye istek gitmez", async () => {
    const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "other" });
    expect(r).toMatchObject({ status: "denied", reasonCode: "scope_violation" });
    expect(h.api.requests.length).toBe(0);
  });

  it("Secret: değerler sunucudan HİÇ çekilmez (Table), yalnız ad/tür/anahtar sayısı döner", async () => {
    const list = await h.call("k8s.resources.list", { kind: "Secret", namespace: "payments" });
    const get = await h.call("k8s.resources.get", { kind: "Secret", name: "db-credentials", namespace: "payments" });
    const desc = await h.call("k8s.resources.describe", { kind: "Secret", name: "db-credentials", namespace: "payments" });
    for (const r of [list, get, desc]) expect(r.status, r.summary).toBe("ok");
    expect(JSON.stringify(list.view)).toContain("db-credentials");
    expect(JSON.stringify(list.view)).toContain("Opaque");
    expect(list.sensitivity).toBe("secret-adjacent");
    const secretReqs = h.api.requests.filter((q) => q.path.includes("/secrets"));
    expect(secretReqs.length).toBeGreaterThan(0);
    expect(secretReqs.every((q) => /as=Table/.test(q.accept))).toBe(true);
    const sink = await h.sinkFor([list, get, desc]);
    expect(sink.leaks(h.allCanaries)).toEqual([]);
    expect(sink.text()).not.toContain("cGF5bWVudHM"); // base64("payments") = Secret kullanıcı adı
  });

  it("ConfigMap: secret benzeri anahtarların değerleri maskeli; diğerleri select ile görünür; çıktı untrusted", async () => {
    const r = await h.call("k8s.resources.get", { kind: "cm", name: "app-config", namespace: "payments", select: ["data", "binaryData"] });
    expect(r.status).toBe("ok");
    const text = JSON.stringify(r.view);
    expect(text).toContain("debug");
    expect(text).toContain("redacted:configmap-key");
    expect(r.taint).toBe("untrusted");
    const sink = await h.sinkFor([r]);
    expect(sink.leaks(h.allCanaries)).toEqual([]);
  });

  it("Deployment get: last-applied-configuration atılır, pod env şifresi maskeli", async () => {
    const r = await h.call("k8s.resources.get", {
      kind: "Deployment",
      name: "api",
      namespace: "payments",
      select: ["metadata.annotations", "spec.template.spec.containers"],
    });
    expect(r.status).toBe("ok");
    const text = JSON.stringify(r.view);
    expect(text).toContain("deployment.kubernetes.io/revision");
    expect(text).not.toContain("last-applied-configuration");
    expect(text).toContain("secretKeyRef");
    const sink = await h.sinkFor([r]);
    expect(sink.leaks(h.allCanaries)).toEqual([]);
  });

  it("describe: nesne + ilgili olaylar (son ilk), untrusted", async () => {
    const r = await h.call("k8s.resources.describe", { kind: "Pod", name: "api-7d9c-a1", namespace: "payments" });
    expect(r.status).toBe("ok");
    expect(r.taint).toBe("untrusted");
    const text = JSON.stringify(r.view);
    expect(text).toContain("BackOff");
    expect(text).toContain("OOMKilling");
    expect(text).not.toContain("api-7d9c-b2"); // başka podun olayı
    const sink = await h.sinkFor([r]);
    expect(sink.leaks(h.allCanaries)).toEqual([]);
  });

  it("events.list: zaman penceresi uygulanır; type ve involved ile daraltılır", async () => {
    const recent = await h.call("k8s.events.list", { namespace: "payments", since: "2h" });
    const rt = JSON.stringify(recent.view);
    expect(rt).toContain("BackOff");
    expect(rt).not.toContain("FailedScheduling"); // 5 gün önce
    const wide = await h.call("k8s.events.list", { namespace: "payments", since: "7d" });
    expect(JSON.stringify(wide.view)).toContain("FailedScheduling");
    const warn = await h.call("k8s.events.list", { namespace: "payments", since: "2h", type: "Warning" });
    expect(JSON.stringify(warn.view)).not.toContain("Pulled");
    const one = await h.call("k8s.events.list", { namespace: "payments", since: "2h", involvedKind: "Pod", involvedName: "api-7d9c-b2" });
    expect(JSON.stringify(one.view)).not.toContain("OOMKilling");
    expect(recent.taint).toBe("untrusted");
    const sink = await h.sinkFor([recent, wide, warn, one]);
    expect(sink.leaks(h.allCanaries)).toEqual([]);
  });

  it("pods.logs: tekrar kümeleme ile kompakt; enjeksiyon satırı kaybolmaz ama untrusted zarfta; secret maskeli", async () => {
    const r = await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-7d9c-a1", since: "30m" });
    expect(r.status).toBe("ok");
    expect(r.taint).toBe("untrusted");
    const text = JSON.stringify(r.view);
    expect(text).toContain("db connection refused");
    expect(text).toContain("out of memory");
    // 40 benzer ERROR satırı kümelenmeli: görünüm ham metinden belirgin küçük
    expect(r.tokens.estimate).toBeLessThan(900);
    const sink = await h.sinkFor([r]);
    expect(sink.leaks(h.allCanaries)).toEqual([]);
    expect(h.session.context.tainted).toBe(true);
  });

  it("pods.logs previous=true önceki kapsayıcı logunu getirir; sunucuya since/tail/limitBytes gider", async () => {
    const r = await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-7d9c-a1", since: "1h", previous: true, tailLines: 5 });
    expect(JSON.stringify(r.view)).toContain("previous container started");
    const q = h.api.requests.at(-1)!;
    expect(q.query).toMatchObject({ previous: "true", tailLines: "5", sinceSeconds: "3600", timestamps: "true" });
    expect(Number(q.query["limitBytes"])).toBeGreaterThan(0);
  });

  it("API hataları anlamlı ve secret içermez: 404 ve RBAC 403", async () => {
    const nf = await h.call("k8s.resources.get", { kind: "Pod", name: "yok", namespace: "payments" });
    expect(nf.status).toBe("error");
    expect(nf.summary).toMatch(/bulunamadı \(404\)/);
    h.api.fault("/api/v1/namespaces/payments/services", (res) => {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ kind: "Status", status: "Failure", reason: "Forbidden", code: 403, message: 'services is forbidden: User "u" cannot list resource "services"' }));
    });
    const fb = await h.call("k8s.resources.list", { kind: "Service", namespace: "payments" });
    expect(fb.status).toBe("error");
    expect(fb.summary).toMatch(/yetki yok \(403, RBAC\)/);
    const sink = await h.sinkFor([nf, fb]);
    expect(sink.leaks(h.allCanaries)).toEqual([]);
  });
});

describe("KubernetesAdapter bağlantı güvenliği (T10, S-04, S-12)", () => {
  it("kasadaki kimliğin sunucusu profil pininden farklıysa kimlik HİÇ gönderilmez", async () => {
    const attacker = await makeK8sHarness(); // ikinci sahte sunucu: kimliği çalmaya çalışan
    const h = await makeK8sHarness({ vaultServer: attacker.api.url });
    try {
      // profil h.api'ye pinli; kasadaki kubeconfig attacker.api'yi gösteriyor
      const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
      expect(r.status).toBe("error");
      expect(r.summary).toMatch(/pinli uç noktasıyla eşleşmiyor/);
      expect(h.api.requests.length).toBe(0);
      expect(attacker.api.requests.length).toBe(0);
    } finally {
      await h.stop();
      await attacker.stop();
    }
  });

  it("CA parmak izi pini farklıysa kimlik gönderilmez", async () => {
    const h = await makeK8sHarness({ profile: { targetPin: { endpoint: "https://127.0.0.1:1", caFingerprint: "0".repeat(64) } } });
    try {
      const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
      expect(r.status).toBe("error");
      expect(h.api.requests.length).toBe(0);
    } finally {
      await h.stop();
    }
  });

  it("sunucu sertifikası kimlikteki CA'ya zincirlenmiyorsa TLS hatası; token iletilmez", async () => {
    // Kimliğe, sunucu zincirini doğrulayamayacak bir "CA" veriyoruz (istemci sertifikası):
    const h = await makeK8sHarness();
    try {
      const store = new MemorySecretStore();
      const { importKubeconfig } = await import("@ops/broker");
      const { buildKubeconfig } = await import("@ops/testkit");
      const imp = await importKubeconfig(buildKubeconfig({ server: h.api.url, caPem: h.pki.clientCertPem, token: h.canaries.kubeToken.value }));
      const { credentialKey } = await import("@ops/broker");
      await store.set(credentialKey(h.profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));
      const broker = new LocalBroker({ store });
      const adapter = new KubernetesAdapter(broker.resolver);
      const lease = await broker.acquire({ profile: { ...h.profile, targetPin: { endpoint: h.api.url } }, purpose: "t", callId: "c", ttlSec: 30 }, h.known);
      await expect(adapter.connectCheck(lease.handle, { ...h.profile, targetPin: { endpoint: h.api.url } })).rejects.toThrow();
      expect(h.api.requests.length).toBe(0); // TLS el sıkışması başarısız: HTTP isteği yok
      await lease.release();
    } finally {
      await h.stop();
    }
  });

  it("yönlendirme izlenmez (kimlik başka hosta gitmesin)", async () => {
    const h = await makeK8sHarness();
    try {
      h.api.fault("/api/v1/namespaces/payments/pods", (res) => {
        res.writeHead(307, { location: "https://evil.invalid/steal" });
        res.end();
      });
      const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
      expect(r.status).toBe("error");
      expect(r.summary).toMatch(/yönlendirme/);
    } finally {
      await h.stop();
    }
  });

  it("dev yanıt bayt sınırında kesilir (response_too_large)", async () => {
    const h = await makeK8sHarness();
    try {
      h.api.fault("/api/v1/namespaces/payments/configmaps", (res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("x".repeat(5_000_000));
      });
      const r = await h.call("k8s.resources.list", { kind: "ConfigMap", namespace: "payments" });
      expect(r.status).toBe("error");
      expect(r.summary).toMatch(/sınırını aştı/);
    } finally {
      await h.stop();
    }
  });

  it("istemci sertifikası kimliği: mTLS ile okuma çalışır", async () => {
    const h = await makeK8sHarness({ auth: "cert" });
    try {
      const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
      expect(r.status).toBe("ok");
      expect(h.api.requests.every((q) => q.clientCertVerified)).toBe(true);
      const sink = await h.sinkFor([r]);
      expect(sink.leaks(h.allCanaries)).toEqual([]);
    } finally {
      await h.stop();
    }
  });

  it("connectCheck: kimlik yankısı ve CA parmak izi", async () => {
    const h = await makeK8sHarness();
    try {
      const lease = await h.broker.acquire({ profile: h.profile, purpose: "doctor", callId: "c", ttlSec: 30 }, h.known);
      const res = await h.adapter.connectCheck(lease.handle, h.profile);
      expect(res).toEqual({ identity: "ops-test-user", targetFingerprint: h.pki.caFingerprint });
      await lease.release();
    } finally {
      await h.stop();
    }
  });

  it("yanlış token: 401 anlamlı mesajla döner; token mesajda yok", async () => {
    const h = await makeK8sHarness();
    try {
      const { importKubeconfig, credentialKey } = await import("@ops/broker");
      const { buildKubeconfig, makeCanary } = await import("@ops/testkit");
      const wrong = makeCanary("yanlis-token");
      const imp = await importKubeconfig(buildKubeconfig({ server: h.api.url, caPem: h.pki.caPem, token: wrong.value }));
      await h.store.set(credentialKey(h.profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));
      const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
      expect(r.status).toBe("error");
      expect(r.summary).toMatch(/401/);
      const sink = await h.sinkFor([r]);
      expect(sink.leaks([wrong, ...h.allCanaries])).toEqual([]);
    } finally {
      await h.stop();
    }
  });
});

describe("Faz 0 güvenlik: tüm araçlar × tüm kanallar canary taraması (S-06 adapter ayağı)", () => {
  it("hiçbir araç/kanal broker token'ını veya kümedeki canary'leri sızdırmaz", async () => {
    const h = await makeK8sHarness();
    try {
      const results: ToolResult[] = [];
      const calls: [string, Record<string, unknown>][] = [
        ["k8s.profile.describe", {}],
        ["k8s.resources.list", { kind: "Pod", namespace: "payments" }],
        ["k8s.resources.list", { kind: "Secret", namespace: "payments" }],
        ["k8s.resources.list", { kind: "ConfigMap", namespace: "payments", select: ["items.data"] }],
        ["k8s.resources.get", { kind: "Deployment", name: "api", namespace: "payments", select: ["metadata", "spec"] }],
        ["k8s.resources.get", { kind: "Pod", name: "api-7d9c-a1", namespace: "payments", select: ["spec", "status"] }],
        ["k8s.resources.describe", { kind: "Pod", name: "api-7d9c-a1", namespace: "payments" }],
        ["k8s.events.list", { namespace: "payments", since: "7d" }],
        ["k8s.pods.logs", { namespace: "payments", pod: "api-7d9c-b2", since: "1h", tailLines: 1000 }],
      ];
      for (const [tool, args] of calls) results.push(await h.call(tool, args));
      expect(results.map((r) => r.status)).toEqual(results.map(() => "ok"));
      const sink = await h.sinkFor(results);
      expect(sink.leaks(h.allCanaries)).toEqual([]);
      // araç hatası/denetim kanalı da temiz
      expect(sink.text("audit")).not.toContain(h.canaries.kubeToken.value);
    } finally {
      await h.stop();
    }
  });
});
