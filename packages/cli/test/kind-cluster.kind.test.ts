/**
 * GERÇEK Kubernetes kümesine (CI'da `kind`) karşı uçtan uca testler. Sahte API'nin göremediklerini sınar:
 * gerçek RBAC (SelfSubjectRulesReview), server-side apply alan sahipliği, resourceVersion/uid ön koşulları,
 * json-patch `test`, Pod Security admission, gerçek Table biçimi, gerçek olay/log uçları.
 *
 * Küme: `OPS_TEST_KUBECONFIG` (yönetici kubeconfig yolu). Yoksa tüm dosya atlanır (`pnpm test:kind`). Yönetici kimliği
 * YALNIZ test kurulumu/doğrulaması içindir; ürünün kimliği ServiceAccount token'lı kubeconfig'lerden
 * `ops profile add k8s` ile izole bir `OPS_HOME`'daki şifreli kasaya alınır.
 */
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { stringify } from "yaml";
import { READONLY_NAMESPACED_RULES, generateReadOnlyRbac } from "@ops/adapter-kubernetes";
import type { ApprovalGate, ApprovalOutcome, ApprovalRequest, ToolResult } from "@ops/contracts";
import { CaptureSink, makeCanary } from "@ops/testkit";
import type { Canary } from "@ops/testkit";
import { connectKindCluster } from "@ops/testkit/kind";
import { createRuntime, readAuditRecords, resolvePaths, runCli } from "../src/index.ts";
import type { Runtime } from "../src/index.ts";

const cluster = await connectKindCluster();

/** Kümede çekilen tek imaj: registry.k8s.io (oran sınırı yok), özetle sabit. */
const IMAGE = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9";
const SCRYPT = { N: 1 << 10, r: 8, p: 1 };
const SUFFIX = randomBytes(3).toString("hex");
const NS = `ops-it-${SUFFIX}`;
const READER = `ops-reader-${SUFFIX}`;
const WRITER = "ops-writer";
const OVERPRIV = "ops-edit-like";
const LOG_MARKER = `ops-it-log-${SUFFIX}`;

type Obj = Record<string, any>;

/** Onay kapısı: her isteği onaylar; `before` verilmişse onaydan ÖNCE (onay ekranı açıkken) çalıştırır. */
class HookGate implements ApprovalGate {
  readonly requests: ApprovalRequest[] = [];
  before: (() => Promise<void>) | undefined;
  async request(req: ApprovalRequest): Promise<ApprovalOutcome> {
    this.requests.push(req);
    const hook = this.before;
    this.before = undefined;
    if (hook) await hook();
    return { approved: true, approvalId: `appr-${this.requests.length}`, actionHash: req.actionHash };
  }
}

const deployment = (name: string, o: { replicas?: number; version?: string; privileged?: boolean } = {}): Obj => ({
  apiVersion: "apps/v1",
  kind: "Deployment",
  metadata: { name, namespace: NS, labels: { app: name } },
  spec: {
    replicas: o.replicas ?? 0,
    selector: { matchLabels: { app: name } },
    template: {
      metadata: { labels: { app: name } },
      spec: {
        terminationGracePeriodSeconds: 1,
        containers: [
          {
            name: "main",
            image: IMAGE,
            command: ["sh", "-c", `echo ${LOG_MARKER}; sleep 3600`],
            env: [{ name: "VERSION", value: o.version ?? "v1" }],
            ...(o.privileged ? { securityContext: { privileged: true } } : {}),
          },
        ],
      },
    },
  },
});
/** Ürünün `k8s.apply` manifesti (yalnız izinli alanlar). */
const manifestOf = (o: Obj): string => stringify(o);

describe.skipIf(!cluster)("gerçek küme (kind)", () => {
  const k = cluster!;
  let home: string;
  let pwFile: string;
  const PW = randomBytes(18).toString("base64url");
  const paths = () => resolvePaths(join(home, "ops"));
  const canaries: Canary[] = [];
  const cmToken = makeCanary("configmap-token");
  const secretValue = makeCanary("secret-value");

  const cli = async (argv: string[]) => {
    const io = { input: new PassThrough(), output: new PassThrough(), error: new PassThrough() };
    const code = await runCli({ argv, env: { OPS_PASSPHRASE_FILE: pwFile }, io, paths: paths(), scryptParams: SCRYPT, sandbox: null });
    const read = (s: PassThrough) => (s.read() as Buffer | null)?.toString() ?? "";
    return { code, out: read(io.output), err: read(io.error) };
  };
  const openRuntime = (gate?: ApprovalGate): Promise<Runtime> =>
    createRuntime({ paths: paths(), passphrase: async () => new Uint8Array(Buffer.from(PW)), scryptParams: SCRYPT, sandbox: null, ...(gate ? { approval: gate } : {}) });

  const call = (rt: Runtime, profile: string, tool: string, args: unknown, cited?: string[]): Promise<ToolResult> =>
    rt.gateway.invoke({ tool, args, profile, providerZone: "local", ...(cited ? { citedEvidence: cited } : {}) });
  const evidence = (rt: Runtime, r: ToolResult): any => {
    const e = r.evidenceId ? rt.evidence.get(r.evidenceId) : undefined;
    if (!e) throw new Error(`kanıt yok: ${JSON.stringify(r)}`);
    try {
      return JSON.parse(e.text);
    } catch {
      return e.text;
    }
  };
  let directId = 0;
  /** PEP'i atlayıp adapter'ı doğrudan çağırır (API düzeyi ön koşul testleri; onaylanan sürüm elle verilir). */
  const direct = async (rt: Runtime, profileId: string, tool: string, args: unknown, approvedVersion?: string) => {
    const profile = rt.registry.get(profileId);
    if (!profile) throw new Error(`profil yok: ${profileId}`);
    const callId = `direct-${++directId}`;
    await rt.broker.prime?.(profile, rt.known);
    const lease = await rt.broker.acquire({ profile, purpose: "kind-it", callId, ttlSec: 60 }, rt.known);
    try {
      const def = rt.adapter.definitions.find((d) => d.descriptor.name === tool);
      if (!def) throw new Error(`araç yok: ${tool}`);
      return await rt.adapter.invoke({ tool, args, profile, handle: lease.handle, callId, signal: new AbortController().signal, limits: def.descriptor.limits, ...(approvedVersion !== undefined ? { approvedVersion } : {}) });
    } finally {
      await lease.release();
    }
  };
  const live = (kind: string, name: string): Promise<Obj | null> => k.get(kind === "ConfigMap" ? "v1" : "apps/v1", kind, NS, name);
  /**
   * Deployment denetleyicisi her değişiklikten hemen sonra durum yazar (resourceVersion değişir). Ürünün önizleme ↔
   * yeniden önizleme sürüm karşılaştırması bu yarışa girmesin diye test adımları nesne durağanlaşınca başlar.
   */
  const settled = (name: string): Promise<Obj> =>
    k.waitFor(`${name} durağan`, async () => {
      const d = await live("Deployment", name);
      const s = d?.status ?? {};
      const want = d?.spec?.replicas ?? 0;
      return d && s.observedGeneration === d.metadata.generation && (s.replicas ?? 0) === want && (s.updatedReplicas ?? 0) === want && (s.readyReplicas ?? 0) === want ? d : null;
    });
  const touch = async (kind: "Deployment" | "ConfigMap", name: string): Promise<void> => {
    const r = await k.api("PATCH", `/${kind === "ConfigMap" ? "api/v1" : "apis/apps/v1"}/namespaces/${NS}/${kind === "ConfigMap" ? "configmaps" : "deployments"}/${name}`, { metadata: { labels: { touched: String(Date.now()) } } }, "application/merge-patch+json");
    expect(r.status, r.body).toBe(200);
  };

  beforeAll(async () => {
    home = await mkdtemp(join(tmpdir(), "ops-kind-"));
    pwFile = join(home, "passphrase");
    await writeFile(pwFile, PW, { mode: 0o600 });

    // Namespace: Pod Security 'baseline' ZORUNLU (privileged pod reddedilir) + uyarı.
    await k.apply({
      apiVersion: "v1",
      kind: "Namespace",
      metadata: { name: NS, labels: { "pod-security.kubernetes.io/enforce": "baseline", "pod-security.kubernetes.io/enforce-version": "latest", "pod-security.kubernetes.io/warn": "baseline" } },
    });
    await k.apply({ apiVersion: "v1", kind: "ConfigMap", metadata: { name: "app-config", namespace: NS }, data: { mode: "blue", api_token: cmToken.value } });
    await k.apply({ apiVersion: "v1", kind: "Secret", metadata: { name: "db-cred", namespace: NS }, type: "Opaque", stringData: { password: secretValue.value } });
    await k.apply(deployment("web", { replicas: 1 }));

    // Kimlikler: (1) ürünün ÜRETTİĞİ salt okunur RBAC, (2) yazıcı (Role), (3) aşırı yetkili (ClusterRole 'edit').
    await k.applyYaml(generateReadOnlyRbac({ name: READER, serviceAccountNamespace: NS, namespaces: [NS] }));
    await k.apply({ apiVersion: "v1", kind: "ServiceAccount", metadata: { name: WRITER, namespace: NS } });
    await k.apply({
      apiVersion: "rbac.authorization.k8s.io/v1",
      kind: "Role",
      metadata: { name: WRITER, namespace: NS },
      rules: [
        ...READONLY_NAMESPACED_RULES,
        { apiGroups: ["apps"], resources: ["deployments", "deployments/scale"], verbs: ["create", "patch", "update", "delete"] },
        { apiGroups: [""], resources: ["configmaps"], verbs: ["create", "patch", "update", "delete"] },
      ],
    });
    await k.apply({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: { name: WRITER, namespace: NS }, roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: WRITER }, subjects: [{ kind: "ServiceAccount", name: WRITER, namespace: NS }] });
    await k.apply({ apiVersion: "v1", kind: "ServiceAccount", metadata: { name: OVERPRIV, namespace: NS } });
    await k.apply({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: { name: OVERPRIV, namespace: NS }, roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: "edit" }, subjects: [{ kind: "ServiceAccount", name: OVERPRIV, namespace: NS }] });

    // Kubeconfig'ler: yalnız ServiceAccount token'ı + küme CA'sı (yönetici sertifikası yok) → `ops profile add k8s`.
    const kdir = join(home, "kube");
    await mkdir(kdir, { mode: 0o700 });
    const r0 = await cli(["init"]);
    expect(r0.code, r0.err).toBe(0);
    for (const [id, sa, ceiling] of [["reader", READER, "read"], ["writer", WRITER, "destroy"], ["overpriv", OVERPRIV, "read"]] as const) {
      const token = await k.token(NS, sa);
      canaries.push({ label: `sa-token-${id}`, value: token });
      const file = join(kdir, `${id}.yaml`);
      await writeFile(file, k.kubeconfigFor(token, { namespace: NS, contextName: `kind-${id}` }), { mode: 0o600 });
      const r = await cli(["profile", "add", "k8s", "--id", id, "--kubeconfig", file, "--env", "dev", "--scope", NS, "--ceiling", ceiling]);
      expect(r.code, `${id}: ${r.err}`).toBe(0);
      expect(r.out).toContain(`Profil eklendi: ${id}`);
    }
    canaries.push(cmToken, secretValue, { label: "vault-passphrase", value: PW });

    await k.waitFor("web Deployment hazır", async () => (await live("Deployment", "web"))?.status?.availableReplicas === 1, 180_000);
  });

  afterAll(async () => {
    if (!home) return;
    await k.remove("v1", "Namespace", undefined, NS).catch(() => undefined);
    await k.remove("rbac.authorization.k8s.io/v1", "ClusterRole", undefined, READER).catch(() => undefined);
    k.close();
    await rm(home, { recursive: true, force: true });
  });

  /** Denetim + kanıt kanallarında hiçbir kimlik/secret canary'si yok. */
  const assertNoLeaks = async (rt: Runtime, extra: Record<string, string> = {}) => {
    const sink = new CaptureSink();
    sink.push("audit", JSON.stringify(await readAuditRecords(rt.paths.auditLog)));
    for (const e of rt.evidence.all()) sink.push("evidence", e.text);
    for (const [c, v] of Object.entries(extra)) sink.push(c, v);
    expect(sink.leaks(canaries)).toEqual([]);
  };

  describe("profil doktoru: gerçek RBAC (SelfSubjectRulesReview)", () => {
    it("generateReadOnlyRbac ile kurulan SA: `ops profile doctor` geçer, kimlik yankısı SA adı, fiili sınıf read", async () => {
      const r = await cli(["profile", "doctor", "reader"]);
      expect(r.code, r.out + r.err).toBe(0);
      const rt = await openRuntime();
      try {
        const rep = await rt.diagnose("reader");
        expect(rep).toMatchObject({ connected: true, pinOk: true, bindable: true, effectiveClass: "read", identity: `system:serviceaccount:${NS}:${READER}`, scopesChecked: [NS] });
        expect(rep.findings.filter((f) => f.severity === "error"), JSON.stringify(rep.findings)).toEqual([]);
        expect(rt.registry.get("reader")?.targetPin.caFingerprint).toMatch(/^[0-9a-f]{64}$/);
      } finally {
        await rt.close();
      }
    });

    it("aşırı yetkili SA ('edit': Secret okuma, exec, yazma) read beyanıyla BAĞLANAMAZ", async () => {
      const r = await cli(["profile", "doctor", "overpriv"]);
      expect(r.code).toBe(1);
      const rt = await openRuntime();
      try {
        const rep = await rt.bindProfile("overpriv");
        expect(rep.bindable).toBe(false);
        expect(rep.findings.map((f) => f.code)).toEqual(expect.arrayContaining(["secrets_readable", "write_access", "exec_access", "ceiling_exceeded_by_rbac"]));
        expect(rt.session.boundProfiles().map((p) => p.id)).not.toContain("overpriv");
        // bağlanmamış profille araç çağrılamaz
        expect((await call(rt, "overpriv", "k8s.resources.list", { kind: "Pod", namespace: NS })).status).toBe("denied");
      } finally {
        await rt.close();
      }
    });

    it("yazıcı SA (Role: deployments/configmaps yazma+silme) destroy tavanıyla bağlanır; yazma bulguları uyarıdır", async () => {
      const rt = await openRuntime();
      try {
        const rep = await rt.bindProfile("writer");
        expect(rep, JSON.stringify(rep.findings)).toMatchObject({ bindable: true, effectiveClass: "destroy" });
        expect(rep.findings.find((f) => f.code === "write_access")?.severity).toBe("warn");
        expect(rep.findings.map((f) => f.code)).not.toContain("secrets_readable");
      } finally {
        await rt.close();
      }
    });
  });

  describe("okuma araçları (salt okunur SA, PEP üzerinden)", () => {
    let rt: Runtime;
    beforeAll(async () => {
      rt = await openRuntime();
      expect((await rt.bindProfile("reader")).bindable).toBe(true);
    });
    afterAll(async () => {
      await rt.close();
    });

    it("k8s.resources.list / get: gerçek nesneler; ConfigMap'in secret adlı anahtarı maskeli", async () => {
      const deps = await call(rt, "reader", "k8s.resources.list", { kind: "Deployment", namespace: NS });
      expect(deps.status, JSON.stringify(deps)).toBe("ok");
      expect(evidence(rt, deps).items.map((i: Obj) => i.metadata.name)).toContain("web");
      const pods = await call(rt, "reader", "k8s.resources.list", { kind: "Pod", namespace: NS, labelSelector: "app=web" });
      expect(pods.status).toBe("ok");
      const items = evidence(rt, pods).items as Obj[];
      expect(items).toHaveLength(1);
      expect(items[0]?.status?.phase).toBe("Running");
      const cm = await call(rt, "reader", "k8s.resources.get", { kind: "ConfigMap", namespace: NS, name: "app-config" });
      expect(cm.status).toBe("ok");
      const j = evidence(rt, cm);
      expect(j.data.mode).toBe("blue");
      expect(j.data.api_token).toMatch(/redacted/);
      expect(JSON.stringify(j)).not.toContain("managedFields");
    });

    it("k8s.resources.describe ve k8s.events.list: gerçek olaylar (ScalingReplicaSet, Scheduled/Pulled/Started)", async () => {
      const d = await call(rt, "reader", "k8s.resources.describe", { kind: "Deployment", namespace: NS, name: "web" });
      expect(d.status, JSON.stringify(d)).toBe("ok");
      expect((evidence(rt, d).events as Obj[]).map((e) => e.reason)).toContain("ScalingReplicaSet");
      const ev = await call(rt, "reader", "k8s.events.list", { namespace: NS, since: "1h" });
      expect(ev.status).toBe("ok");
      const reasons = (evidence(rt, ev).items as Obj[]).map((e) => e.reason);
      expect(reasons).toEqual(expect.arrayContaining(["Scheduled", "Started"]));
    });

    it("k8s.pods.logs: gerçek kubelet logu (since + tailLines)", async () => {
      const pods = evidence(rt, await call(rt, "reader", "k8s.resources.list", { kind: "Pod", namespace: NS, labelSelector: "app=web" })).items as Obj[];
      const pod = pods[0]?.metadata?.name as string;
      const r = await call(rt, "reader", "k8s.pods.logs", { namespace: NS, pod, since: "30m", tailLines: 20 });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      expect(String(evidence(rt, r))).toContain(LOG_MARKER);
    });

    it("k8s.workload.health: 1/1 hazır, yayılım tamam, imaj özeti (sha256) kubelet'ten; düğümler kapsam dışı", async () => {
      const r = await call(rt, "reader", "k8s.workload.health", { kind: "Deployment", namespace: NS, name: "web" });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = evidence(rt, r);
      expect(j.workload).toMatchObject({ desired: 1, ready: 1, rollout: "complete" });
      expect(j.images[0].digest).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(j.nodes).toBe("kapsam-dışı");
      expect((j.findings as Obj[]).filter((f) => f.severity === "critical")).toEqual([]);
    });

    it("salt okunur SA Secret listeleyemez: PEP önce durdurur (taint + secret-adjacent), küme de gerçek 403 verir; can_i tutarlı", async () => {
      // Birinci hat (tasarım gereği): bağlam güvenilmez ConfigMap/olay içeriği aldı; secret-adjacent okuma onay ister,
      // bu çalışma zamanında onay kapısı yok → API'ye hiç gidilmez.
      const s = await call(rt, "reader", "k8s.resources.list", { kind: "Secret", namespace: NS });
      expect(s).toMatchObject({ status: "denied", reasonCode: "approval_unavailable" });
      // İkinci hat: AYNI ServiceAccount kimliğiyle API'ye doğrudan gidildiğinde kümenin RBAC'ı reddeder (gerçek 403)
      await expect(direct(rt, "reader", "k8s.resources.list", { kind: "Secret", namespace: NS })).rejects.toThrow(/403/);
      const yes = evidence(rt, await call(rt, "reader", "k8s.auth.can_i", { namespace: NS, verb: "list", resource: "pods" }));
      const no = evidence(rt, await call(rt, "reader", "k8s.auth.can_i", { namespace: NS, verb: "delete", resource: "pods" }));
      const sec = evidence(rt, await call(rt, "reader", "k8s.auth.can_i", { namespace: NS, verb: "get", resource: "secrets" }));
      expect([yes.allowed, no.allowed, sec.allowed]).toEqual([true, false, false]);
      const all = evidence(rt, await call(rt, "reader", "k8s.auth.can_i", { namespace: NS }));
      expect(all).toMatchObject({ effectiveClass: "read", secretsReadable: false });
    });

    it("Secret, gerçek Table biçimiyle okunur: ad/tür/anahtar sayısı var, DEĞER sunucudan hiç gelmez", async () => {
      // Secret okuyabilen kimlik yalnız aşırı yetkili SA (doktor bağlamaz) → adapter doğrudan, PEP'siz
      const out = await direct(rt, "overpriv", "k8s.resources.list", { kind: "Secret", namespace: NS });
      const item = ((out.data as Obj).items as Obj[]).find((i) => i.metadata.name === "db-cred");
      expect(item).toMatchObject({ type: "Opaque", dataKeyCount: 1 });
      const sink = new CaptureSink();
      sink.push("secret-list", JSON.stringify(out));
      expect(sink.leaks([secretValue])).toEqual([]);
    });

    it("hiçbir kanalda kimlik/secret canary'si yok", async () => {
      await assertNoLeaks(rt);
    });
  });

  describe("değişiklik araçları (yazıcı SA, önizleme + onay + TOCTOU)", () => {
    let rt: Runtime;
    const gate = new HookGate();
    const W = "writer";
    const getEv = async (kind: string, name: string): Promise<string> => {
      const r = await call(rt, W, "k8s.resources.get", { kind, namespace: NS, name });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      return r.evidenceId as string;
    };
    beforeAll(async () => {
      rt = await openRuntime(gate);
      expect((await rt.bindProfile(W)).bindable).toBe(true);
    });
    afterAll(async () => {
      await rt.close();
    });

    it("k8s.apply: yeni nesne de server-side apply ile oluşur; sonraki değişiklik kendi alanlarıyla çakışmaz (alan yöneticisi ops-assistant/Apply)", async () => {
      const m1 = manifestOf(deployment("ops-new", { version: "v1" }));
      const d = await call(rt, W, "k8s.apply.diff", { manifest: m1 });
      expect(d.status, JSON.stringify(d)).toBe("ok");
      expect(evidence(rt, d)).toMatchObject({ exists: false, version: "yok" });
      const c = await call(rt, W, "k8s.apply", { manifest: m1 }, [d.evidenceId as string]);
      expect(c.status, JSON.stringify(c)).toBe("ok");
      const created = await settled("ops-new");
      expect(created.spec.template.spec.containers[0].env).toEqual([{ name: "VERSION", value: "v1" }]);
      // oluşturma Apply işlemiyle: ops-assistant için Update girdisi YOK (POST+Apply aynı yöneticiyle çakışıyordu)
      expect((created.metadata.managedFields as Obj[]).filter((f) => f.manager === "ops-assistant").map((f) => f.operation)).toEqual(["Apply"]);

      // "yalnız yoksa oluştur": 'yok' onayıyla var olan nesneye gidilirse gerçek sunucu uid koşuluyla reddeder, nesne değişmez
      await expect(direct(rt, W, "k8s.apply", { manifest: manifestOf(deployment("ops-new", { version: "v9" })) }, "yok")).rejects.toMatchObject({ code: "target_changed" });
      expect((await live("Deployment", "ops-new"))?.spec?.template?.spec?.containers?.[0]?.env).toEqual([{ name: "VERSION", value: "v1" }]);

      const m2 = manifestOf(deployment("ops-new", { version: "v2" }));
      const u = await call(rt, W, "k8s.apply", { manifest: m2 }, [await getEv("Deployment", "ops-new")]);
      expect(u.status, JSON.stringify(u)).toBe("ok");
      const after = await live("Deployment", "ops-new");
      expect(after?.spec?.template?.spec?.containers?.[0]?.env).toEqual([{ name: "VERSION", value: "v2" }]);
      expect((after?.metadata?.managedFields as Obj[]).some((f) => f.manager === "ops-assistant" && f.operation === "Apply")).toBe(true);
      // aynı manifest yeniden: diff boş
      expect(evidence(rt, await call(rt, W, "k8s.apply.diff", { manifest: m2 }))).toMatchObject({ exists: true, changed: false });
    });

    it("k8s.apply: başka bir alan yöneticisinin ('gitops') alanını değiştirmek gerçek SSA çakışması verir; hiçbir şey uygulanmaz, zorla devralınmaz", async () => {
      await k.apply(deployment("contested", { replicas: 0 }), "gitops");
      await settled("contested");
      const r = await call(rt, W, "k8s.apply", { manifest: manifestOf(deployment("contested", { replicas: 1 })) }, [await getEv("Deployment", "contested")]);
      expect(r.status, JSON.stringify(r)).toBe("error");
      expect(r.summary).toContain("alan sahipliği çakışması");
      expect(r.summary).toContain(".spec.replicas → 'gitops'");
      const after = await live("Deployment", "contested");
      expect(after?.spec?.replicas).toBe(0);
      expect((after?.metadata?.managedFields as Obj[]).map((f) => f.manager)).not.toContain("ops-assistant");
      // çakışmayan değişiklik (aynı değerler) uygulanabilir: ortak sahiplik
      const same = await call(rt, W, "k8s.apply", { manifest: manifestOf(deployment("contested", { replicas: 0 })) }, [await getEv("Deployment", "contested")]);
      expect(same.status, JSON.stringify(same)).toBe("ok");
    });

    it("k8s.scale: onaylı ölçekleme yazılır; onay sırasında nesne değişirse target_changed; bayat resourceVersion API'de 409", async () => {
      await k.apply(deployment("scaled", { replicas: 0 }));
      await settled("scaled");
      const ok = await call(rt, W, "k8s.scale", { kind: "Deployment", namespace: NS, name: "scaled", replicas: 1 }, [await getEv("Deployment", "scaled")]);
      expect(ok.status, JSON.stringify(ok)).toBe("ok");
      expect((await live("Deployment", "scaled"))?.spec?.replicas).toBe(1);
      await settled("scaled");

      // PEP düzeyi: onay ekranı açıkken başkası düzenler → yeniden önizleme sürümü farklı → çalışmaz
      const ev = await getEv("Deployment", "scaled");
      gate.before = () => touch("Deployment", "scaled");
      const changed = await call(rt, W, "k8s.scale", { kind: "Deployment", namespace: NS, name: "scaled", replicas: 3 }, [ev]);
      expect(changed).toMatchObject({ status: "denied", reasonCode: "target_changed" });
      expect((await live("Deployment", "scaled"))?.spec?.replicas).toBe(1);

      // API düzeyi: gerçek /scale yaması resourceVersion ön koşulunu uygular
      const stale = (await live("Deployment", "scaled"))?.metadata?.resourceVersion as string;
      await touch("Deployment", "scaled");
      await expect(direct(rt, W, "k8s.scale", { kind: "Deployment", namespace: NS, name: "scaled", replicas: 3 }, stale)).rejects.toMatchObject({ code: "target_changed" });
      expect((await live("Deployment", "scaled"))?.spec?.replicas).toBe(1);
    });

    it("k8s.rollout.undo: gerçek ReplicaSet revizyonlarından önceki şablona döner (json-patch test+replace); bayat sürüm reddedilir", async () => {
      await k.apply(deployment("rev", { version: "v1" }));
      await k.waitFor("rev revizyon 1", async () => (await live("Deployment", "rev"))?.metadata?.annotations?.["deployment.kubernetes.io/revision"] === "1");
      await k.apply(deployment("rev", { version: "v2" }));
      await k.waitFor("rev revizyon 2", async () => (await live("Deployment", "rev"))?.metadata?.annotations?.["deployment.kubernetes.io/revision"] === "2");
      await settled("rev");

      gate.requests.length = 0;
      const r = await call(rt, W, "k8s.rollout.undo", { namespace: NS, name: "rev" }, [await getEv("Deployment", "rev")]);
      expect(r.status, JSON.stringify(r)).toBe("ok");
      expect(gate.requests[0]?.summary.preview?.impact?.join("\n")).toContain("revizyon 2 → 1");
      const after = await k.waitFor("rev revizyon 3", async () => {
        const d = await live("Deployment", "rev");
        return d?.metadata?.annotations?.["deployment.kubernetes.io/revision"] === "3" ? d : null;
      });
      expect(after.spec.template.spec.containers[0].env).toEqual([{ name: "VERSION", value: "v1" }]);
      expect(after.spec.template.metadata.labels["pod-template-hash"]).toBeUndefined();

      const stale = after.metadata.resourceVersion as string;
      await touch("Deployment", "rev");
      await expect(direct(rt, W, "k8s.rollout.undo", { namespace: NS, name: "rev" }, stale)).rejects.toMatchObject({ code: "target_changed" });
      expect((await live("Deployment", "rev"))?.spec?.template?.spec?.containers?.[0]?.env).toEqual([{ name: "VERSION", value: "v1" }]);
    });

    it("k8s.resources.delete: uid+resourceVersion ön koşullu silme; bayat sürüm ve yeniden oluşturulmuş nesne (yeni uid) SİLİNMEZ", async () => {
      const cm = (name: string, v: string): Obj => ({ apiVersion: "v1", kind: "ConfigMap", metadata: { name, namespace: NS }, data: { v } });
      await k.apply(cm("to-delete", "1"));
      const ok = await call(rt, W, "k8s.resources.delete", { kind: "ConfigMap", namespace: NS, name: "to-delete" }, [await getEv("ConfigMap", "to-delete")]);
      expect(ok.status, JSON.stringify(ok)).toBe("ok");
      expect(await live("ConfigMap", "to-delete")).toBeNull();

      await k.apply(cm("guarded", "1"));
      const g0 = (await live("ConfigMap", "guarded"))!;
      const uid0 = g0.metadata.uid as string;
      await touch("ConfigMap", "guarded");
      await expect(direct(rt, W, "k8s.resources.delete", { kind: "ConfigMap", namespace: NS, name: "guarded" }, `${uid0}@${g0.metadata.resourceVersion}`)).rejects.toMatchObject({ code: "target_changed" });
      expect(await live("ConfigMap", "guarded")).not.toBeNull();

      // sil + aynı adla yeniden oluştur: eski uid ile (güncel resourceVersion olsa bile) silinmez
      await k.remove("v1", "ConfigMap", NS, "guarded");
      await k.apply(cm("guarded", "2"));
      const g1 = (await live("ConfigMap", "guarded"))!;
      expect(g1.metadata.uid).not.toBe(uid0);
      await expect(direct(rt, W, "k8s.resources.delete", { kind: "ConfigMap", namespace: NS, name: "guarded" }, `${uid0}@${g1.metadata.resourceVersion}`)).rejects.toMatchObject({ code: "target_changed" });
      expect((await live("ConfigMap", "guarded"))?.data).toEqual({ v: "2" });
    });

    it("Pod Security admission: privileged pod reddedilir; ürün riski önizlemede işaretler, sağlık ve olaylar reddi gösterir", async () => {
      // küme yapılandırması: doğrudan privileged Pod gerçekten reddediliyor
      const pod = { apiVersion: "v1", kind: "Pod", metadata: { name: "priv-direct", namespace: NS }, spec: { containers: [{ name: "c", image: IMAGE, securityContext: { privileged: true } }] } };
      const direct403 = await k.api("POST", `/api/v1/namespaces/${NS}/pods`, pod);
      expect(direct403.status).toBe(403);
      expect(direct403.body).toContain("violates PodSecurity");

      // ürün Pod uygulamaz; Deployment kabul edilir (PSA iş yükü nesnesinde yalnız uyarır), pod'ları reddedilir
      const m = manifestOf(deployment("priv", { replicas: 1, privileged: true }));
      const d = await call(rt, W, "k8s.apply.diff", { manifest: m });
      expect((evidence(rt, d).impact as string[]).join("\n")).toMatch(/main: privileged/);
      gate.requests.length = 0;
      const r = await call(rt, W, "k8s.apply", { manifest: m }, [d.evidenceId as string]);
      expect(r.status, JSON.stringify(r)).toBe("ok");
      expect(gate.requests[0]?.summary.preview?.impact?.join("\n")).toMatch(/privileged/);

      await k.waitFor("priv ReplicaSet FailedCreate olayı", async () => {
        const e = await k.api("GET", `/api/v1/namespaces/${NS}/events?fieldSelector=${encodeURIComponent("reason=FailedCreate")}`);
        return (e.json?.items as Obj[] | undefined)?.some((x) => String(x.message).includes("violates PodSecurity")) ?? false;
      }, 90_000);
      const h = evidence(rt, await call(rt, W, "k8s.workload.health", { kind: "Deployment", namespace: NS, name: "priv" }));
      expect(h.workload).toMatchObject({ desired: 1, ready: 0 });
      expect((h.findings as Obj[]).map((f) => f.code)).toContain("no_ready_replicas");
      const ev = evidence(rt, await call(rt, W, "k8s.events.list", { namespace: NS, since: "30m", type: "Warning", involvedKind: "ReplicaSet" }));
      const failed = (ev.items as Obj[]).filter((e) => e.reason === "FailedCreate");
      expect(failed.length).toBeGreaterThan(0);
      expect(String(failed[0]?.message)).toContain("PodSecurity");
    });

    it("hiçbir kanalda kimlik/secret canary'si yok; onay özetlerinde de yok", async () => {
      await assertNoLeaks(rt, { onay: JSON.stringify(gate.requests) });
    });
  });
});
