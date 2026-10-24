import { randomBytes } from "node:crypto";
import { AuditLog, MemoryAuditStorage, MemoryHeadAnchor } from "@ops/audit";
import { LocalBroker, MemorySecretStore, buildDbCredential, credentialKey } from "@ops/broker";
import { EvidenceStore, Session, ToolGateway, ToolRegistry, createLocalAdapter, formatForModel } from "@ops/core";
import { initSqlClassifier } from "@ops/classifiers";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { CaptureSink, makeCanary, makeTestProfile } from "@ops/testkit";
import type { Canary } from "@ops/testkit";
import { SHOP_ROLES, seedShop, startTestPostgres } from "@ops/testkit/postgres";
import type { TestPostgres } from "@ops/testkit/postgres";
import type { Profile, ProfileInput, ReadLimits, ToolResult } from "@ops/contracts";
import { EMPTY_MASKING_CONFIG, PostgresAdapter, maskingRulesFor } from "../src/index.ts";
import type { MaskingConfig, PgDriverApi } from "../src/index.ts";

await initSqlClassifier();

/** Tüm test dosyası için tek PostgreSQL sunucusu; yoksa `null` (testler atlanır). */
export const pg: TestPostgres | null = await startTestPostgres().catch(() => null);

export interface PgCanaries {
  readonly readerPw: Canary;
  readonly otherPw: Canary;
  /** İzinli şemalar DIŞINDAki tabloda. */
  readonly vaultToken: Canary;
}
export const canaries: PgCanaries = {
  readerPw: makeCanary("reader-pw"),
  otherPw: makeCanary("other-pw"),
  vaultToken: makeCanary("vault-token"),
};

export const ROLES = SHOP_ROLES;

let seeded: Promise<void> | null = null;
export function seed(): Promise<void> {
  if (!pg) return Promise.resolve();
  seeded ??= seedShop(pg, { readerPassword: canaries.readerPw.value, otherPassword: canaries.otherPw.value, vaultToken: canaries.vaultToken.value });
  return seeded;
}

export interface PgHarnessOpts {
  readonly role?: string;
  readonly profile?: Partial<ProfileInput>;
  readonly masking?: MaskingConfig;
  readonly tlsMode?: "verify-full" | "disable";
  /** Kasadaki sunucu portunu değiştirir (pin uyuşmazlığı). */
  readonly vaultPort?: number;
  /** Kasadaki CA'yı değiştirir. */
  readonly vaultCaPem?: string;
  readonly noCaPin?: boolean;
  /** Kasadaki parolayı değiştirir (yanlış parola testi). */
  readonly password?: string;
  readonly driver?: (real: PgDriverApi) => PgDriverApi;
}

export async function makePgHarness(opts: PgHarnessOpts = {}) {
  if (!pg) throw new Error("PostgreSQL yok");
  await seed();
  const role = opts.role ?? ROLES.reader;
  const password = opts.password ?? (role === ROLES.reader ? canaries.readerPw.value : canaries.otherPw.value);
  const imp = buildDbCredential({
    host: pg.host,
    port: opts.vaultPort ?? pg.port,
    database: "shop",
    user: role,
    password,
    ...(opts.tlsMode === "disable" ? { tlsMode: "disable" as const } : { caPem: opts.vaultCaPem ?? pg.pki.caPem }),
  });
  const profile: Profile = makeTestProfile({
    id: "shop",
    kind: "db",
    displayName: "Shop (test)",
    environment: "sandbox",
    targetPin: { endpoint: `${pg.host}:${pg.port}`, ...(opts.noCaPin || opts.tlsMode === "disable" ? {} : { caFingerprint: pg.pki.caFingerprint }) },
    classCeiling: "read",
    allowedScopes: ["public", "sales"],
    egressClass: "tenant-cloud",
    attributes: { role: "reader", datasource: "shop", defaultSchema: "public" },
    ...(opts.profile ?? {}),
  });
  const store = new MemorySecretStore();
  await store.set(credentialKey(profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));

  const storage = new MemoryAuditStorage();
  const known = new KnownSecrets();
  const audit = await AuditLog.open({ storage, key: randomBytes(32), anchor: new MemoryHeadAnchor(), scrub: (s) => scrubText(s, known) });
  const evidence = new EvidenceStore();
  const session = new Session("s-pg");
  const registry = new ToolRegistry();
  const local = createLocalAdapter(evidence);
  registry.register(local.adapter, local.definitions);
  const broker = new LocalBroker({ store });
  const masking = opts.masking ?? EMPTY_MASKING_CONFIG;
  const { PgDriver } = await import("../src/index.ts");
  const real = new PgDriver(broker.resolver);
  const adapter = new PostgresAdapter(broker.resolver, { masking, driver: opts.driver ? opts.driver(real) : real });
  registry.register(adapter, adapter.definitions);
  const gateway = new ToolGateway({
    registry,
    session,
    policy: new PolicyEngine(DEFAULT_POLICY),
    audit,
    broker,
    evidence,
    known,
    maskingFor: (tool, p) => (tool.profileKind === "db" && p ? maskingRulesFor(masking, p.id) : null),
  });
  session.bind(profile);

  const call = (tool: string, args: unknown): Promise<ToolResult> => gateway.invoke({ tool, args, profile: profile.id, providerZone: "local" });
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

  /** Doğrudan sürücü oturumu (PEP/AST ATLANARAK): katman bağımsızlığı ve sürücü davranışı testleri için. */
  const openSession = async (limits: ReadLimits = { maxRows: 100, maxBytes: 256 * 1024, timeoutMs: 10_000 }) => {
    const lease = await broker.acquire({ profile, purpose: "test", callId: "direct", ttlSec: 60 }, known);
    const s = await real.connect(lease.handle, "reader", {
      pin: { endpoint: profile.targetPin.endpoint, ...(profile.targetPin.caFingerprint ? { caFingerprint: profile.targetPin.caFingerprint } : {}) },
      defaultSchema: "public",
    });
    await s.applyReaderGuards(limits);
    return {
      session: s,
      limits,
      lease,
      close: async (): Promise<void> => {
        await s.close();
        await lease.release();
      },
    };
  };
  const doctor = async () => {
    const lease = await broker.acquire({ profile, purpose: "doctor", callId: "doctor", ttlSec: 60 }, known);
    try {
      return await adapter.doctor(lease.handle, profile);
    } finally {
      await lease.release();
    }
  };
  return { pg, profile, store, broker, adapter, registry, gateway, session, evidence, storage, known, call, sinkFor, evidenceJson, masking, openSession, doctor, real };
}

export type PgHarness = Awaited<ReturnType<typeof makePgHarness>>;
