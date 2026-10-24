import { randomBytes } from "node:crypto";
import { AuditLog, MemoryAuditStorage, MemoryHeadAnchor } from "@ops/audit";
import { LocalBroker, MemorySecretStore, credentialKey, importKubeconfig } from "@ops/broker";
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
import type { Profile, ProfileInput, ToolResult } from "@ops/contracts";
import { KubernetesAdapter } from "../src/index.ts";

export interface K8sHarnessOpts {
  readonly auth?: "token" | "cert";
  readonly profile?: Partial<ProfileInput>;
  /** Kasadaki kubeconfig'in sunucusunu değiştirir (pin uyuşmazlığı testi). */
  readonly vaultServer?: string;
  readonly noCaPin?: boolean;
}

export async function makeK8sHarness(opts: K8sHarnessOpts = {}) {
  const pki: TestPki = await generateTestPki();
  const canaries = {
    kubeToken: makeCanary("kube-token"),
    secretData: makeCanary("secret-data"),
    configToken: makeCanary("config-token"),
    envPassword: makeCanary("env-password"),
    logSecret: makeCanary("log-secret"),
    eventSecret: makeCanary("event-secret"),
  };
  const api = await FakeK8sApi.start(
    opts.auth === "cert" ? { pki, requireClientCert: true } : { pki, token: canaries.kubeToken.value },
  );
  seedPaymentsOutage(api, canaries);

  const kubeconfig = buildKubeconfig({
    server: opts.vaultServer ?? api.url,
    caPem: pki.caPem,
    ...(opts.auth === "cert"
      ? { clientCertPem: pki.clientCertPem, clientKeyPem: pki.clientKeyPem }
      : { token: canaries.kubeToken.value }),
    namespace: "payments",
  });
  const imp = await importKubeconfig(kubeconfig);
  const store = new MemorySecretStore();
  const profile: Profile = makeTestProfile({
    id: "k1",
    displayName: "Payments sandbox",
    targetPin: { endpoint: api.url, ...(opts.noCaPin ? {} : { caFingerprint: pki.caFingerprint }) },
    allowedScopes: ["payments"],
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
  const broker = new LocalBroker({ store });
  const adapter = new KubernetesAdapter(broker.resolver);
  registry.register(adapter, adapter.definitions);
  const gateway = new ToolGateway({ registry, session, policy: new PolicyEngine(DEFAULT_POLICY), audit, broker, evidence, known });
  session.bind(profile);

  const call = (tool: string, args: unknown, over: { profile?: string } = {}): Promise<ToolResult> =>
    gateway.invoke({ tool, args, profile: over.profile ?? profile.id, providerZone: "local" });

  /** Gözlenebilir tüm kanallar: model görünümü, kanıt, denetim. */
  const sinkFor = async (results: readonly ToolResult[]): Promise<CaptureSink> => {
    const sink = new CaptureSink();
    sink.push("audit", (await storage.readLines()).join("\n"));
    for (const e of evidence.all()) sink.push("evidence", e.text);
    for (const r of results) sink.push("model", formatForModel(r));
    return sink;
  };

  const allCanaries: Canary[] = Object.values(canaries);
  return { pki, api, canaries, allCanaries, profile, store, broker, adapter, registry, gateway, session, evidence, storage, known, call, sinkFor, stop: () => api.stop() };
}

export type K8sHarness = Awaited<ReturnType<typeof makeK8sHarness>>;
