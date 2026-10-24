import { randomBytes } from "node:crypto";
import { AuditLog, MemoryAuditStorage, MemoryHeadAnchor } from "@ops/audit";
import { LocalBroker, MemorySecretStore, buildTokenCredential, credentialKey } from "@ops/broker";
import { EvidenceStore, Session, ToolGateway, ToolRegistry, createLocalAdapter, formatForModel } from "@ops/core";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { BUILD_REPO, CaptureSink, FakeGithubApi, generateTestPki, makeCanary, makeTestProfile, seedBuildDeploy } from "@ops/testkit";
import type { Canary } from "@ops/testkit";
import type { ApprovalGate, Profile, ProfileInput, ToolResult } from "@ops/contracts";
import { GithubActionsAdapter, GithubScmAdapter } from "../src/index.ts";

export interface GhHarnessOpts {
  readonly logRedirect?: "blob" | "evil" | "none";
  readonly oauthScopes?: string;
  readonly profile?: Partial<ProfileInput>;
  readonly kind?: "pipeline" | "scm";
  /** Kasadaki belirteç sunucunun beklediğinden farklı. */
  readonly wrongToken?: boolean;
  /** Kasadaki apiBase farklı (pin uyuşmazlığı). */
  readonly vaultApiBase?: string;
  readonly noCaPin?: boolean;
  readonly injection?: string;
  readonly approval?: ApprovalGate;
  readonly forbidWrites?: boolean;
}

export async function makeGhHarness(opts: GhHarnessOpts = {}) {
  const pki = await generateTestPki();
  const canaries = {
    token: makeCanary("gh-token"),
    logSecret: makeCanary("log-secret"),
    workflowSecret: makeCanary("workflow-secret"),
    envFileSecret: makeCanary("envfile-secret"),
  };
  const api = await FakeGithubApi.start({ pki, token: canaries.token.value, ...(opts.logRedirect ? { logRedirect: opts.logRedirect } : {}), ...(opts.oauthScopes !== undefined ? { oauthScopes: opts.oauthScopes } : {}), ...(opts.forbidWrites ? { forbidWrites: true } : {}) });
  seedBuildDeploy(api, canaries, opts.injection ? { injection: opts.injection } : {});
  const kind = opts.kind ?? "pipeline";
  const imp = buildTokenCredential({ apiBase: opts.vaultApiBase ?? api.url, token: opts.wrongToken ? makeCanary("wrong").value : canaries.token.value, caPem: pki.caPem });
  const profile: Profile = makeTestProfile({
    id: kind === "pipeline" ? "ci" : "git",
    kind,
    displayName: `GitHub ${kind}`,
    targetPin: { endpoint: api.url, ...(opts.noCaPin ? {} : { caFingerprint: pki.caFingerprint }) },
    allowedScopes: [BUILD_REPO],
    attributes: { role: "reader", logHosts: "" },
    ...(opts.profile ?? {}),
  });
  const store = new MemorySecretStore();
  await store.set(credentialKey(profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));

  const storage = new MemoryAuditStorage();
  const known = new KnownSecrets();
  const audit = await AuditLog.open({ storage, key: randomBytes(32), anchor: new MemoryHeadAnchor(), scrub: (s) => scrubText(s, known) });
  const evidence = new EvidenceStore();
  const session = new Session("s-gh");
  const registry = new ToolRegistry();
  const local = createLocalAdapter(evidence);
  registry.register(local.adapter, local.definitions);
  const broker = new LocalBroker({ store });
  const adapter = kind === "pipeline" ? new GithubActionsAdapter(broker.resolver) : new GithubScmAdapter(broker.resolver);
  registry.register(adapter, adapter.definitions);
  const gateway = new ToolGateway({ registry, session, policy: new PolicyEngine(DEFAULT_POLICY), audit, broker, evidence, known, ...(opts.approval ? { approval: opts.approval } : {}) });
  session.bind(profile);

  const call = (tool: string, args: unknown, over: { cited?: string[] } = {}): Promise<ToolResult> =>
    gateway.invoke({ tool, args, profile: profile.id, providerZone: "local", ...(over.cited ? { citedEvidence: over.cited } : {}) });
  const sinkFor = async (results: readonly ToolResult[]): Promise<CaptureSink> => {
    const sink = new CaptureSink();
    sink.push("audit", (await storage.readLines()).join("\n"));
    for (const e of evidence.all()) sink.push("evidence", e.text);
    for (const r of results) sink.push("model", formatForModel(r));
    return sink;
  };
  const evidenceJson = (r: ToolResult): any => {
    const e = r.evidenceId ? evidence.get(r.evidenceId) : undefined;
    if (!e) throw new Error("kanıt yok");
    return JSON.parse(e.text);
  };
  const doctor = async () => {
    const lease = await broker.acquire({ profile, purpose: "doctor", callId: "doctor", ttlSec: 60 }, known);
    try {
      return await adapter.doctor!(lease.handle, profile);
    } finally {
      await lease.release();
    }
  };
  const all: Canary[] = Object.values(canaries);
  return { pki, api, canaries, all, profile, store, broker, adapter, registry, gateway, session, evidence, storage, known, call, sinkFor, evidenceJson, doctor, stop: () => api.stop() };
}

export type GhHarness = Awaited<ReturnType<typeof makeGhHarness>>;
