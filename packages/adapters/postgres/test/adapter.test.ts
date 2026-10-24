import { afterAll, describe, expect, it } from "vitest";
import { adapterConformance } from "@ops/testkit/conformance";
import { checkAdapterStructure } from "@ops/testkit";
import { LocalBroker, MemorySecretStore } from "@ops/broker";
import { estimateTokens } from "@ops/contracts";
import { PostgresAdapter, parseMaskingConfig } from "../src/index.ts";
import { canaries, makePgHarness, pg } from "./harness.ts";

const mk = () => new PostgresAdapter(new LocalBroker({ store: new MemorySecretStore() }).resolver);

adapterConformance("postgres", mk);

describe("PostgresAdapter yapısı", () => {
  it("5 araç, hepsi read ve db profili; sınıflar/toolset/untrusted beklenen gibi", () => {
    const a = mk();
    expect(checkAdapterStructure(a)).toEqual([]);
    expect(a.manifest.tools.map((t) => t.name).sort()).toEqual(["db.datasource.describe", "db.query.explain", "db.query.read", "db.schema.describe", "db.stats.summary"]);
    expect(a.manifest.tools.every((t) => t.class === "read" && t.profileKind === "db" && t.toolset === "database")).toBe(true);
    expect(a.manifest.tools.find((t) => t.name === "db.query.read")).toMatchObject({ sensitivity: "pii", untrustedOutput: true });
  });

  it("araç şemaları küçük: toplam ≤ 1.5k token tahmini", () => {
    const a = mk();
    const specs = JSON.stringify(a.manifest.tools.map((t) => ({ n: t.name, d: t.description, s: t.inputSchema })));
    expect(estimateTokens(specs)).toBeLessThanOrEqual(1_500);
  });

  it("validateProfile: db türü, reader rolü, read tavanı, host:port pini", () => {
    const a = mk();
    const base = { id: "x", kind: "db" as const, displayName: "x", environment: "stage" as const, targetPin: { endpoint: "db.invalid:5432" }, classCeiling: "read" as const, allowedScopes: ["public"], credentialSource: { kind: "static" as const, ambientDependencies: [] }, maxLeaseTtlSec: 120, egressClass: "local" as const, attributes: { role: "reader" } };
    expect(a.validateProfile(base)).toEqual([]);
    expect(a.validateProfile({ ...base, kind: "k8s" }).join()).toMatch(/'db' olmalı/);
    expect(a.validateProfile({ ...base, attributes: { role: "writer" } }).join()).toMatch(/reader/);
    expect(a.validateProfile({ ...base, classCeiling: "mutate" }).join()).toMatch(/yalnız 'read'/);
    expect(a.validateProfile({ ...base, targetPin: { endpoint: "postgres://u:p@h/db" } }).join()).toMatch(/host:port/);
    expect(a.validateProfile({ ...base, attributes: { role: "reader", defaultSchema: "Bad Schema" } }).join()).toMatch(/defaultSchema/);
  });

  it("masking.yaml şeması katıdır", () => {
    expect(() => parseMaskingConfig("version: 2")).toThrow();
    expect(() => parseMaskingConfig("version: 1\nprofiles:\n  '*':\n    maskedColumns: {users: [email]}\n    extra: 1")).toThrow();
    expect(parseMaskingConfig("version: 1\nprofiles:\n  '*':\n    maskedColumns:\n      customers: [email]").profiles["*"]?.maskedColumns).toEqual({ customers: ["email"] });
  });
});

describe.skipIf(!pg)("gerçek PostgreSQL: okuma araçları (PEP üzerinden)", () => {
  afterAll(async () => {
    /* sunucu dosya sonunda kapanır (aşağıdaki) */
  });

  it("db.datasource.describe: bağlantı bilgisi/host/parola içermez", async () => {
    const h = await makePgHarness();
    const r = await h.call("db.datasource.describe", {});
    expect(r.status).toBe("ok");
    const j = h.evidenceJson(r);
    expect(j).toMatchObject({ datasource: "shop", dialect: "postgresql", role: "reader", allowedSchemas: ["public", "sales"], defaultSchema: "public", tlsPinned: true });
    const sink = await h.sinkFor([r]);
    expect(sink.leaks([canaries.readerPw])).toEqual([]);
    expect(JSON.stringify(j)).not.toContain("127.0.0.1");
  });

  it("db.query.read: basit SELECT, kolonlar+satırlar, kaynak tablolar subject olur", async () => {
    const h = await makePgHarness();
    const r = await h.call("db.query.read", { sql: "SELECT id, status, total FROM public.orders WHERE status = 'failed' ORDER BY id LIMIT 5" });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    const j = h.evidenceJson(r);
    expect(j.columns).toEqual(["id", "status", "total"]);
    expect(j.rows.length).toBe(5);
    expect(j.rows[0]).toEqual([3, "failed", "31.50"]);
    expect(j.rowCount).toBe(5);
  });
});

afterAll(async () => {
  await pg?.stop();
});
