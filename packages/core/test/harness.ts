import { randomBytes } from "node:crypto";
import { z } from "zod";
import { AuditLog, MemoryAuditStorage, MemoryHeadAnchor } from "@ops/audit";
import { defineTool } from "@ops/contracts";
import type { ApprovalGate, Profile, ProfileInput, RawToolOutput, ToolDefinition, ToolDescriptorMeta } from "@ops/contracts";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import type { PolicyDocument } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { CaptureSink, FakeAdapter, FakeBroker, makeCanary, makeTestProfile } from "@ops/testkit";
import type { Canary } from "@ops/testkit";
import { createLocalAdapter, EvidenceStore, Session, ToolGateway, ToolRegistry, formatForModel } from "../src/index.ts";
import type { CommandClassifier } from "../src/index.ts";

export const AUDIT_KEY = randomBytes(32);

const lim = { timeoutMs: 2000, maxBytes: 200_000, maxItems: 100, maxOutputTokens: 1500 };
const meta: Omit<ToolDescriptorMeta, "name" | "description" | "class"> = {
  profileKind: "k8s",
  sensitivity: "internal",
  idempotent: true,
  limits: lim,
  untrustedOutput: false,
  toolset: "k8s-core",
  typicalOutputTokens: 300,
  projection: { defaultFields: ["metadata.name", "status.phase"], selectable: true },
};

export const listTool = defineTool(
  { ...meta, name: "k8s.resources.list", description: "Kaynakları listeler.", class: "read" },
  z.strictObject({ kind: z.string(), namespace: z.string().optional(), select: z.array(z.string()).optional() }),
);
export const logsTool = defineTool(
  { ...meta, name: "k8s.pods.logs", description: "Pod logu.", class: "read", untrustedOutput: true, projection: undefined },
  z.strictObject({ namespace: z.string(), pod: z.string() }),
);
export const scaleTool = defineTool(
  { ...meta, name: "k8s.scale", description: "Replika sayısını değiştirir.", class: "mutate", idempotent: false },
  z.strictObject({ namespace: z.string(), name: z.string(), replicas: z.number().int().min(0) }),
);
export const deleteTool = defineTool(
  { ...meta, name: "k8s.resources.delete", description: "Kaynak siler.", class: "destroy", idempotent: false },
  z.strictObject({ namespace: z.string(), kind: z.string(), name: z.string() }),
);
export const nodesTool = defineTool(
  { ...meta, name: "k8s.nodes.list", description: "Düğümleri listeler (küme kapsamlı).", class: "read" },
  z.strictObject({}),
);
export const dbTool = defineTool(
  { ...meta, name: "db.query.read", description: "Salt okunur sorgu.", class: "read", profileKind: "db", sensitivity: "pii", toolset: "db", projection: undefined },
  z.strictObject({ sql: z.string() }),
);

export interface HarnessOpts {
  policy?: PolicyDocument;
  profile?: Partial<ProfileInput>;
  approval?: ApprovalGate;
  classifiers?: readonly CommandClassifier[];
  handlers?: Partial<Record<string, (args: Record<string, unknown>) => RawToolOutput | Promise<RawToolOutput>>>;
  providerSecret?: string;
  /** Saat enjeksiyonu (break-glass süre testleri). */
  now?: () => Date;
  localOnly?: boolean;
}

export async function makeHarness(opts: HarnessOpts = {}) {
  const storage = new MemoryAuditStorage();
  const anchor = new MemoryHeadAnchor();
  const known = new KnownSecrets();
  const audit = await AuditLog.open({ storage, key: AUDIT_KEY, anchor, scrub: (s) => scrubText(s, known) });
  const evidence = new EvidenceStore();
  const session = new Session("s-test");
  const registry = new ToolRegistry();
  const local = createLocalAdapter(evidence);
  registry.register(local.adapter, local.definitions);

  const h = opts.handlers ?? {};
  const spec = (
    def: ToolDefinition,
    dflt: RawToolOutput | ((a: Record<string, unknown>) => RawToolOutput),
    targetOf?: (a: Record<string, unknown>) => { scopes?: string[]; refs?: string[] },
  ) => ({
    def,
    handler: async (c: { args: unknown }) => {
      const a = c.args as Record<string, unknown>;
      const custom = h[def.descriptor.name];
      if (custom) return custom(a);
      return typeof dflt === "function" ? dflt(a) : dflt;
    },
    targetOf:
      targetOf ??
      ((a: Record<string, unknown>) => ({
        scopes: typeof a["namespace"] === "string" ? [a["namespace"]] : [],
        refs: typeof a["name"] === "string" ? [`${String(a["kind"] ?? "Deployment")}/${String(a["namespace"])}/${a["name"]}`] : [],
      })),
  });
  const k8s = new FakeAdapter("fake-k8s", "kubernetes", "k8s", [
    spec(listTool, { data: [{ metadata: { name: "api-1" }, status: { phase: "Running" } }, { metadata: { name: "api-2" }, status: { phase: "Failed" } }], subjects: ["Pod/payments/api-1"] }),
    spec(logsTool, { data: "2026-01-01T00:00:00Z ERROR baglanti reddedildi\n2026-01-01T00:00:01Z ERROR baglanti reddedildi", subjects: ["Pod/payments/api-1"] }),
    spec(scaleTool, { data: { scaled: true } }),
    spec(deleteTool, { data: { deleted: true } }),
    spec(nodesTool, { data: [{ name: "n1" }] }),
  ]);
  const dbAdapter = new FakeAdapter("fake-db", "database", "db", [spec(dbTool, { data: { columns: [{ name: "id" }], rows: [[1]] } }, () => ({ scopes: ["public"], refs: [] }))]);
  registry.register(k8s, [listTool, logsTool, scaleTool, deleteTool, nodesTool]);
  registry.register(dbAdapter, [dbTool]);

  const secret = opts.providerSecret ?? `cnry-broker-${randomBytes(6).toString("hex")}-x`;
  const broker = new FakeBroker({ secretFor: () => secret });
  const policy = new PolicyEngine(opts.policy ?? DEFAULT_POLICY);
  const gateway = new ToolGateway({
    registry, session, policy, audit, broker, evidence, known,
    ...(opts.approval ? { approval: opts.approval } : {}),
    ...(opts.classifiers ? { classifiers: opts.classifiers } : {}),
    ...(opts.now ? { now: opts.now } : {}),
    ...(opts.localOnly ? { localOnly: true } : {}),
  });

  const profile: Profile = makeTestProfile({ id: "test-k8s", ...(opts.profile ?? {}) });
  session.bind(profile);
  const dbProfile: Profile = makeTestProfile({
    id: "orders-db", kind: "db", displayName: "Orders DB", environment: "prod",
    targetPin: { endpoint: "orders.db.test.invalid:5432" }, allowedScopes: ["public"], egressClass: "tenant-cloud",
    attributes: { role: "reader" },
  });

  const lines = async (): Promise<string[]> => storage.readLines();
  const records = async () => (await lines()).map((l) => JSON.parse(l) as Record<string, unknown>);
  const call = (tool: string, args: unknown, over: { profile?: string; cited?: string[]; zone?: "local" | "tenant-cloud" | "third-party-cloud" } = {}) =>
    gateway.invoke({
      tool, args,
      ...(over.profile === undefined ? (tool.startsWith("evidence.") ? {} : { profile: "test-k8s" }) : { profile: over.profile }),
      ...(over.cited ? { citedEvidence: over.cited } : {}),
      providerZone: over.zone ?? "local",
    });

  return { storage, anchor, audit, known, evidence, session, registry, k8s, dbAdapter, broker, policy, gateway, profile, dbProfile, secret, lines, records, call, formatForModel };
}

export type Harness = Awaited<ReturnType<typeof makeHarness>>;

/** Tüm gözlenebilir kanalları toplar (modele görünen metin, denetim, kanıt). */
export async function collect(h: Harness, results: { formatted?: string[] } = {}): Promise<CaptureSink> {
  const sink = new CaptureSink();
  sink.push("audit", (await h.lines()).join("\n"));
  for (const e of h.evidence.all()) sink.push("evidence", e.text);
  for (const f of results.formatted ?? []) sink.push("model", f);
  return sink;
}

export { makeCanary };
export type { Canary };
