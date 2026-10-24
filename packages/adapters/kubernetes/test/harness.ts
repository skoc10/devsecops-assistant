import { randomBytes } from "node:crypto";
import { AuditLog, MemoryAuditStorage, MemoryHeadAnchor } from "@ops/audit";
import { ExecCredentialRunner, LocalBroker, MemorySecretStore, ambientFor, credentialKey, importKubeconfig } from "@ops/broker";
import type { ExecTemplate } from "@ops/broker";
import type { Sandbox } from "@ops/sandbox";
import { EvidenceStore, Session, ToolGateway, ToolRegistry, createLocalAdapter, formatForModel } from "@ops/core";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import {
  CaptureSink,
  FakeK8sApi,
  buildKubeconfig,
  generateTestPki,
  makeCanary,
  makeTestProfile,
  seedPaymentsOutage,
} from "@ops/testkit";
import type { Canary, TestPki } from "@ops/testkit";
import type { ApprovalGate, Profile, ProfileInput, ToolResult } from "@ops/contracts";
import { KubernetesAdapter } from "../src/index.ts";

export interface ExecHarnessOpts {
  readonly template: ExecTemplate;
  readonly binaryPath: string;
  readonly args: readonly string[];
  readonly sandbox: Sandbox | null;
  readonly homeDir: string;
}

export interface K8sHarnessOpts {
  /** API'nin beklediği bearer değeri (exec eklentisi bunu üretir). Verilmezse rastgele canary. */
  readonly kubeToken?: string;
  /** Kimlik exec eklentisiyle üretilir (token/sertifika kasada değildir). */
  readonly exec?: ExecHarnessOpts;
  readonly auth?: "token" | "cert";
  readonly profile?: Partial<ProfileInput>;
  /** Kasadaki kubeconfig'in sunucusunu değiştirir (pin uyuşmazlığı testi). */
  readonly vaultServer?: string;
  readonly noCaPin?: boolean;
  /** Onay kapısı (yazma araçları testleri). */
  readonly approval?: ApprovalGate;
  /** Sahte API yazma fiillerine 403 döner (salt okunur RBAC). */
  readonly apiReadOnly?: boolean;
}

export async function makeK8sHarness(opts: K8sHarnessOpts = {}) {
  const pki: TestPki = await generateTestPki();
  const canaries = {
    kubeToken: opts.kubeToken ? { label: "kube-token", value: opts.kubeToken } : makeCanary("kube-token"),
    secretData: makeCanary("secret-data"),
    configToken: makeCanary("config-token"),
    envPassword: makeCanary("env-password"),
    logSecret: makeCanary("log-secret"),
    eventSecret: makeCanary("event-secret"),
  };
  const api = await FakeK8sApi.start(
    opts.auth === "cert" ? { pki, requireClientCert: true } : { pki, token: canaries.kubeToken.value, ...(opts.apiReadOnly ? { readOnly: true } : {}) },
  );
  seedPaymentsOutage(api, canaries);

  const kubeconfig = buildKubeconfig({
    server: opts.vaultServer ?? api.url,
    caPem: pki.caPem,
    ...(opts.exec
      ? {
          userExtra: {
            exec: { apiVersion: "client.authentication.k8s.io/v1", command: opts.exec.binaryPath, args: [...opts.exec.args] },
          },
        }
      : opts.auth === "cert"
        ? { clientCertPem: pki.clientCertPem, clientKeyPem: pki.clientKeyPem }
        : { token: canaries.kubeToken.value }),
    namespace: "payments",
  });
  const imp = await importKubeconfig(kubeconfig, opts.exec ? { execCatalog: [opts.exec.template] } : {});
  const store = new MemorySecretStore();
  const profile: Profile = makeTestProfile({
    id: "k1",
    displayName: "Payments sandbox",
    targetPin: { endpoint: api.url, ...(opts.noCaPin ? {} : { caFingerprint: pki.caFingerprint }) },
    allowedScopes: ["payments"],
    ...(opts.exec
      ? { credentialSource: { kind: "exec" as const, execTemplateId: opts.exec.template.id, ambientDependencies: ambientFor(opts.exec.template) } }
      : {}),
    ...(opts.profile ?? {}),
  });
  await store.set(credentialKey(profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));

  const storage = new MemoryAuditStorage();
  const known = new KnownSecrets();
  const audit = await AuditLog.open({ storage, key: randomBytes(32), anchor: new MemoryHeadAnchor(), scrub: (s) => scrubText(s, known) });
  const evidence = new EvidenceStore();
  const session = new Session("s-k8s");
  const registry = new ToolRegistry();
  const local = createLocalAdapter(evidence);
  registry.register(local.adapter, local.definitions);
  const broker = new LocalBroker({
    store,
    ...(opts.exec
      ? { exec: new ExecCredentialRunner({ sandbox: opts.exec.sandbox, catalog: [opts.exec.template], homeDir: opts.exec.homeDir }) }
      : {}),
  });
  const adapter = new KubernetesAdapter(broker.resolver);
  registry.register(adapter, adapter.definitions);
  const gateway = new ToolGateway({ registry, session, policy: new PolicyEngine(DEFAULT_POLICY), audit, broker, evidence, known, ...(opts.approval ? { approval: opts.approval } : {}) });
  session.bind(profile);

  const call = (tool: string, args: unknown, over: { profile?: string; cited?: string[] } = {}): Promise<ToolResult> =>
    gateway.invoke({ tool, args, profile: over.profile ?? profile.id, providerZone: "local", ...(over.cited ? { citedEvidence: over.cited } : {}) });

  /** Gözlenebilir tüm kanallar: model görünümü, kanıt, denetim. */
  const sinkFor = async (results: readonly ToolResult[]): Promise<CaptureSink> => {
    const sink = new CaptureSink();
    sink.push("audit", (await storage.readLines()).join("\n"));
    for (const e of evidence.all()) sink.push("evidence", e.text);
    for (const r of results) sink.push("model", formatForModel(r));
    return sink;
  };

  /** Tam redakte kanıt gövdesi (model görünümü tabloya sıkıştırılmış olabilir). */
  const evidenceJson = (r: ToolResult): any => {
    const e = r.evidenceId ? evidence.get(r.evidenceId) : undefined;
    if (!e) throw new Error("kanıt yok");
    return JSON.parse(e.text);
  };

  const allCanaries: Canary[] = Object.values(canaries);
  return { pki, api, canaries, allCanaries, profile, store, broker, adapter, registry, gateway, session, evidence, storage, known, call, sinkFor, evidenceJson, stop: () => api.stop() };
}

export type K8sHarness = Awaited<ReturnType<typeof makeK8sHarness>>;
