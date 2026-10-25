import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { FakeApprovalGate } from "@ops/testkit";
import type { ApprovalGate, ApprovalOutcome, ApprovalRequest, RiskClass, ToolResult } from "@ops/contracts";
import { parseMaskingConfig } from "../src/index.ts";
import { ROLES, canaries, makePgHarness, pg, seed } from "./harness.ts";
import type { PgHarness } from "./harness.ts";

type Ceiling = "mutate" | "deploy" | "destroy";

const RESET_ORDERS =
  "TRUNCATE public.orders; INSERT INTO public.orders SELECT g, 1 + (g % 2), CASE WHEN g % 3 = 0 THEN 'failed' ELSE 'paid' END, g * 10.5, now() - (g || ' minutes')::interval FROM generate_series(1, 30) g";
const count = (sql: string): Promise<string> => pg!.admin(sql, "shop");

let h: PgHarness | undefined;
beforeEach(async () => {
  if (!pg) return;
  await seed();
  await count(RESET_ORDERS);
});
afterEach(async () => {
  h = undefined;
  if (!pg) return;
  await pg.admin("DROP TABLE IF EXISTS work.notes, work.t1", "shop").catch(() => undefined);
  await pg.admin("ALTER TABLE public.orders DROP COLUMN IF EXISTS drift", "shop").catch(() => undefined);
  await pg.admin("DELETE FROM public.customers WHERE id >= 10", "shop").catch(() => undefined);
  await pg.admin("TRUNCATE work.items; INSERT INTO work.items VALUES (1,'a'),(2,'b'),(3,'c')", "shop").catch(() => undefined);
});

/** Okuma kanıtı (schema.describe) toplayıp atıf yapılabilir hâle getirir. */
async function setup(ceiling: Ceiling = "mutate", opts: { gate?: ApprovalGate; role?: string; scopes?: string[]; schema?: string; masking?: string } = {}) {
  const gate = opts.gate ?? new FakeApprovalGate();
  const x = await makePgHarness({
    role: opts.role ?? ROLES.writer,
    writerCeiling: ceiling,
    approval: gate,
    ...(opts.scopes ? { profile: { allowedScopes: opts.scopes } } : {}),
    ...(opts.masking ? { masking: parseMaskingConfig(opts.masking) } : {}),
  });
  h = x;
  const d = await x.call("db.schema.describe", opts.schema ? { schema: opts.schema } : {});
  expect(d.status, JSON.stringify(d)).toBe("ok");
  return { h: x, gate, ev: d.evidenceId as string };
}

const apply = (x: PgHarness, ev: string, sql: string, maxRows?: number): Promise<ToolResult> =>
  x.call("db.change.apply", { sql, ...(maxRows !== undefined ? { maxRows } : {}) }, { cited: [ev] });

describe.skipIf(!pg)("db.change.propose (çalıştırmadan sınıflar)", () => {
  it("ifade türü, sınıf, hedef, tahmini satır ve ifade seti özetini verir; veri değişmez, satır verisi yok", async () => {
    const { h: x } = await setup();
    await pg!.admin("ANALYZE public.orders", "shop");
    const r = await x.call("db.change.propose", { sql: "UPDATE public.orders SET status = 'x' WHERE status = 'failed'; DELETE FROM public.orders WHERE id = 999", maxRows: 50 });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    const j = x.evidenceJson(r);
    expect(j.statements).toHaveLength(2);
    expect(j.statements[0]).toMatchObject({ index: 1, kind: "update", class: "mutate", targets: ["public.orders"] });
    expect(typeof j.statements[0].estimatedRows).toBe("number");
    expect(j.statements[1]).toMatchObject({ kind: "delete", class: "mutate" });
    expect(j).toMatchObject({ requiredClass: "mutate", profileCeiling: "mutate" });
    expect(j.statementSetSha256).toMatch(/^[0-9a-f]{16}$/);
    expect(JSON.stringify(j)).not.toMatch(/Ayse|ayse@/);
    expect(await count("SELECT count(*) FROM public.orders WHERE status = 'x'")).toBe("0");
    expect(r.status).toBe("ok");
  });

  it("gereken sınıf tavanı aşıyorsa not düşer; WHERE'siz DELETE destroy, WHERE'siz UPDATE deploy", async () => {
    const { h: x } = await setup("mutate");
    const r1 = await x.call("db.change.propose", { sql: "DELETE FROM public.orders" });
    expect(x.evidenceJson(r1)).toMatchObject({ requiredClass: "destroy" });
    expect(x.evidenceJson(r1).notes.join()).toMatch(/ceiling_exceeded/);
    expect(x.evidenceJson(r1).statements[0]).toMatchObject({ whereless: true, class: "destroy" });
    const r2 = await x.call("db.change.propose", { sql: "UPDATE public.orders SET status = 'z'" });
    expect(x.evidenceJson(r2)).toMatchObject({ requiredClass: "deploy" });
  });

  it("reader profilinde de çalışır (yalnız statik analiz + tahmin yok notu); uygulamak için writer gerektiğini söyler", async () => {
    const x = await makePgHarness();
    h = x;
    const r = await x.call("db.change.propose", { sql: "UPDATE public.orders SET status = 'x' WHERE id = 1" });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    const j = x.evidenceJson(r);
    expect(j.statements[0].estimatedRows).toBeNull();
    expect(j.notes.join()).toMatch(/writer profili/);
  });

  it("reddedilen SQL kimlik alınmadan target_unresolved ile reddedilir (nedeniyle)", async () => {
    const { h: x } = await setup();
    for (const sql of [
      "COPY public.orders TO PROGRAM 'id'",
      "SELECT 1",
      "UPDATE public.orders SET status = 'x' WHERE id = 1 RETURNING id",
      "DROP SCHEMA public",
      "UPDATE public.orders SET status = pg_read_file('/etc/passwd')",
      "DROP TABLE public.orders CASCADE",
      "GRANT ALL ON public.orders TO PUBLIC",
    ]) {
      const r = await x.call("db.change.propose", { sql });
      expect(r, sql).toMatchObject({ status: "denied", reasonCode: "target_unresolved" });
    }
  });

  it("maskeli sütun WHERE/alt sorguda kullanılamaz (etkilenen-satır oracle'ı yok); yazmak serbest", async () => {
    const { h: x } = await setup("mutate", { masking: "version: 1\nprofiles:\n  \"*\":\n    maskedColumns:\n      customers: [email]\n" });
    const bad = await x.call("db.change.propose", { sql: "UPDATE public.customers SET name = 'x' WHERE email LIKE 'a%'" });
    expect(bad, JSON.stringify(bad)).toMatchObject({ status: "denied", reasonCode: "target_unresolved" });
    const ok = await x.call("db.change.propose", { sql: "UPDATE public.customers SET email = 'n@example.invalid' WHERE id = 1" });
    expect(ok.status, JSON.stringify(ok)).toBe("ok");
  });
});

describe.skipIf(!pg)("db.change.apply (mutate tavanı)", () => {
  it("onay → ÖNİZLEME (ifadeler, etki, sürüm) gösterilir → tek işlemde uygulanır; yazıcı parolası hiçbir kanalda yok", async () => {
    const gate = new FakeApprovalGate();
    const { h: x, ev } = await setup("mutate", { gate });
    const sql = "UPDATE public.orders SET status = 'refunded' WHERE status = 'failed'; DELETE FROM public.orders WHERE id = 1";
    const failed = Number(await count("SELECT count(*) FROM public.orders WHERE status = 'failed'"));
    const r = await apply(x, ev, sql, 50);
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(gate.requests).toHaveLength(1);
    const pv = gate.requests[0]?.summary.preview;
    expect(pv?.targetVersion).toMatch(/^pgchg1:[0-9a-f]{64}$/);
    expect(pv?.diff).toContain("TEK işlem");
    expect(pv?.diff).toContain("UPDATE public.orders SET status = 'refunded' WHERE status = 'failed'");
    expect(pv?.diff).toContain("onaylı üst sınır: toplam 50");
    expect(pv?.impact?.join("\n")).toMatch(/tahmini etkilenen satır/);
    expect(pv?.rollback).toMatch(/ROLLBACK/);
    expect(gate.requests[0]?.summary.citedEvidence).toHaveLength(1);
    const j = x.evidenceJson(r);
    expect(j).toMatchObject({ committed: true, maxRows: 50 });
    expect(j.statements.map((s: { rows: number }) => s.rows)).toEqual([failed, 1]);
    expect(j.totalRows).toBe(failed + 1);
    expect(await count("SELECT count(*) FROM public.orders WHERE status = 'refunded'")).toBe(String(failed));
    expect(await count("SELECT count(*) FROM public.orders WHERE id = 1")).toBe("0");
    const sink = await x.sinkFor([r]);
    expect(sink.leaks([canaries.otherPw, canaries.readerPw])).toEqual([]);
    const audit = (await x.storage.readLines()).join("\n");
    expect(audit).toContain("db.change.apply");
    expect(audit).toContain("refunded");
  });

  it("satır üst sınırı aşılırsa TAMAMI geri alınır (hiçbir değişiklik kalmaz)", async () => {
    const { h: x, ev } = await setup();
    const r = await apply(x, ev, "UPDATE public.orders SET status = 'x' WHERE id <= 20", 5);
    expect(r.status).toBe("error");
    expect(JSON.stringify(r)).toMatch(/row_limit_exceeded|üst sınırı aştı/);
    expect(await count("SELECT count(*) FROM public.orders WHERE status = 'x'")).toBe("0");
    expect(await count("SELECT count(*) FROM pg_stat_activity WHERE usename = '" + ROLES.writer + "'")).toBe("0"); // bağlantı kapandı
  });

  it("toplam sınır TÜM ifadeler üzerindedir: iki küçük ifade birlikte aşarsa ROLLBACK", async () => {
    const { h: x, ev } = await setup();
    const r = await apply(x, ev, "UPDATE public.orders SET status = 'x' WHERE id <= 3; DELETE FROM public.orders WHERE id BETWEEN 10 AND 12", 5);
    expect(r.status).toBe("error");
    expect(await count("SELECT count(*) FROM public.orders")).toBe("30");
    expect(await count("SELECT count(*) FROM public.orders WHERE status = 'x'")).toBe("0");
  });

  it("çok ifadeli kümede bir ifade hata verirse öncekiler de geri alınır; hata ifade numarasını söyler, veri değeri sızmaz", async () => {
    const { h: x, ev } = await setup();
    const r = await apply(x, ev, "UPDATE public.orders SET status = 'x' WHERE id = 1; INSERT INTO public.orders (id, customer_id, status, total) VALUES (2, 1, 'dup', 1)");
    expect(r.status).toBe("error");
    const msg = JSON.stringify(r);
    expect(msg).toMatch(/ifade 2\/2/);
    expect(msg).toMatch(/23505/);
    expect(msg).not.toMatch(/Key \(id\)=\(2\)/); // PG `detail` iletilmez
    expect(await count("SELECT status FROM public.orders WHERE id = 1")).toBe("paid");
  });

  it("rol yetkisi bağımsız son katmandır: yetkisiz tabloya yazma PG tarafından reddedilir ve geri alınır", async () => {
    const { h: x, ev } = await setup("mutate", { scopes: ["public", "sales"], schema: "sales" });
    const r = await apply(x, ev, "UPDATE sales.invoices SET amount = 0 WHERE id = 1");
    expect(r.status).toBe("error");
    expect(JSON.stringify(r)).toMatch(/42501|permission denied/);
    expect(await count("SELECT amount FROM sales.invoices WHERE id = 1")).toBe("10.50");
  });

  it("INSERT çalışır; satır sayısı sınırdan sayılır", async () => {
    const { h: x, ev } = await setup();
    const ok = await apply(x, ev, "INSERT INTO public.customers (id, name, email) VALUES (10, 'Zeynep', 'z@example.invalid'), (11, 'Can', NULL)", 2);
    expect(ok.status, JSON.stringify(ok)).toBe("ok");
    expect(await count("SELECT count(*) FROM public.customers WHERE id >= 10")).toBe("2");
    const over = await apply(x, ev, "INSERT INTO public.customers (id, name) VALUES (12, 'a'), (13, 'b'), (14, 'c')", 2);
    expect(over.status).toBe("error");
    expect(await count("SELECT count(*) FROM public.customers WHERE id >= 12")).toBe("0");
  });

  it("sınıf tavanı: WHERE'siz UPDATE (deploy) ve DDL mutate profilinde ceiling_exceeded; onay istenmez, DB'ye dokunulmaz", async () => {
    const gate = new FakeApprovalGate();
    const { h: x, ev } = await setup("mutate", { gate });
    for (const sql of ["UPDATE public.orders SET status = 'x'", "DELETE FROM public.orders", "ALTER TABLE public.orders ADD COLUMN z int", "TRUNCATE public.orders", "CREATE TABLE public.zz (a int)", "DROP TABLE public.orders"]) {
      const r = await apply(x, ev, sql, 1000);
      expect(r, sql).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    }
    expect(gate.requests).toHaveLength(0);
    expect(await count("SELECT count(*) FROM public.orders WHERE status = 'x'")).toBe("0");
    expect(await count("SELECT count(*) FROM public.orders")).toBe("30");
  });

  it("kullanıcı reddederse hiçbir şey çalışmaz; atıf yoksa citation_missing", async () => {
    const gate = new FakeApprovalGate(() => false);
    const { h: x, ev } = await setup("mutate", { gate });
    const denied = await apply(x, ev, "UPDATE public.orders SET status = 'x' WHERE id = 1");
    expect(denied).toMatchObject({ status: "denied", reasonCode: "approval_denied" });
    const noCite = await x.call("db.change.apply", { sql: "UPDATE public.orders SET status = 'x' WHERE id = 1" });
    expect(noCite).toMatchObject({ status: "denied", reasonCode: "citation_missing" });
    expect(await count("SELECT count(*) FROM public.orders WHERE status = 'x'")).toBe("0");
  });

  it("ilgisiz kanıta atıf reddedilir (hedef tablo kanıtın subject'inde değil)", async () => {
    const { h: x } = await setup("mutate", { scopes: ["public", "sales"] });
    const other = await x.call("db.schema.describe", { schema: "sales" });
    expect(other.status).toBe("ok");
    const r = await x.call("db.change.apply", { sql: "UPDATE public.orders SET status = 'x' WHERE id = 1" }, { cited: [other.evidenceId as string] });
    expect(r).toMatchObject({ status: "denied", reasonCode: "citation_missing" });
  });

  it("propose kanıtı apply için atıf olabilir (aynı hedef)", async () => {
    const { h: x } = await setup();
    const p = await x.call("db.change.propose", { sql: "UPDATE public.orders SET status = 'x' WHERE id = 2" });
    const r = await x.call("db.change.apply", { sql: "UPDATE public.orders SET status = 'x' WHERE id = 2" }, { cited: [p.evidenceId as string] });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(await count("SELECT status FROM public.orders WHERE id = 2")).toBe("x");
  });

  it("TOCTOU: onay beklenirken tablonun şeması değişirse target_changed ve HİÇBİR ifade çalışmaz", async () => {
    let drifted = false;
    const gate: ApprovalGate = {
      async request(req: ApprovalRequest): Promise<ApprovalOutcome> {
        await pg!.admin("ALTER TABLE public.orders ADD COLUMN drift int", "shop");
        drifted = true;
        return { approved: true, approvalId: "appr-1", actionHash: req.actionHash };
      },
    };
    const { h: x, ev } = await setup("mutate", { gate });
    const r = await apply(x, ev, "UPDATE public.orders SET status = 'x' WHERE id = 1");
    expect(drifted).toBe(true);
    expect(r).toMatchObject({ status: "denied", reasonCode: "target_changed" });
    expect(await count("SELECT status FROM public.orders WHERE id = 1")).toBe("paid");
  });

  it("işlem İÇİNDE de sürüm doğrulanır (PEP atlanarak): yanlış onaylı sürüm → target_changed, hiçbir ifade çalışmaz", async () => {
    const { h: x } = await setup();
    const lease = await x.broker.acquire({ profile: x.profile, purpose: "test", callId: "direct", ttlSec: 60 }, x.known);
    try {
      const mk = (approvedVersion?: string) => ({
        tool: "db.change.apply",
        args: { sql: "UPDATE public.orders SET status = 'x' WHERE id = 1", maxRows: 10 },
        profile: x.profile,
        handle: lease.handle,
        callId: "direct",
        signal: new AbortController().signal,
        limits: { timeoutMs: 20_000, maxBytes: 64_000, maxItems: 20, maxOutputTokens: 800 },
        ...(approvedVersion ? { approvedVersion } : {}),
      });
      await expect(x.adapter.invoke(mk("pgchg1:" + "0".repeat(64)))).rejects.toThrow(/şeması değişti|target_changed/);
      await expect(x.adapter.invoke(mk())).rejects.toThrow(/onaylanan sürüm yok/);
      expect(await count("SELECT status FROM public.orders WHERE id = 1")).toBe("paid");
      // doğru sürümle çalışır
      const pv = await x.adapter.preview!(mk());
      const ok = await x.adapter.invoke(mk(pv.targetVersion));
      expect((ok.data as { committed: boolean }).committed).toBe(true);
      expect(await count("SELECT status FROM public.orders WHERE id = 1")).toBe("x");
    } finally {
      await lease.release();
    }
  });

  it("reader oturumu uygulama yapamaz (sürücü düzeyinde writer_required)", async () => {
    const x = await makePgHarness();
    h = x;
    const lease = await x.broker.acquire({ profile: x.profile, purpose: "test", callId: "direct", ttlSec: 60 }, x.known);
    try {
      const s = await x.real.connect(lease.handle, "reader", { pin: { endpoint: x.profile.targetPin.endpoint, caFingerprint: x.pg.pki.caFingerprint }, defaultSchema: "public" });
      await expect(s.applyWriterGuards({ timeoutMs: 1000 })).rejects.toThrow(/yazıcı oturumu/);
      await s.close();
    } finally {
      await lease.release();
    }
  });
});

describe.skipIf(!pg)("db.change.apply (DDL: deploy / destroy tavanı, sahip rol)", () => {
  const DDL_SCOPES = ["public", "work"];

  it("deploy tavanı: CREATE TABLE + INSERT + CREATE INDEX + ALTER ADD COLUMN tek işlemde; DROP ise ceiling_exceeded", async () => {
    const { h: x, ev } = await setup("deploy", { role: ROLES.ddl, scopes: DDL_SCOPES, schema: "work" });
    const sql =
      "CREATE TABLE work.notes (id int PRIMARY KEY, body text NOT NULL DEFAULT ''); INSERT INTO work.notes (id, body) VALUES (1, 'a'), (2, 'b'); CREATE INDEX ix_notes_body ON work.notes (body); ALTER TABLE work.items ADD COLUMN IF NOT EXISTS extra int";
    const r = await apply(x, ev, sql, 10);
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(await count("SELECT count(*) FROM work.notes")).toBe("2");
    expect(await count("SELECT count(*) FROM pg_indexes WHERE indexname = 'ix_notes_body'")).toBe("1");
    expect(await count("SELECT count(*) FROM information_schema.columns WHERE table_schema='work' AND table_name='items' AND column_name='extra'")).toBe("1");
    await pg!.admin("ALTER TABLE work.items DROP COLUMN extra", "shop");
    const drop = await apply(x, ev, "DROP TABLE work.notes");
    expect(drop).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    expect(await count("SELECT count(*) FROM work.notes")).toBe("2");
  });

  it("DDL kümesi tek işlemdir: sınır aşımında CREATE TABLE de geri alınır", async () => {
    const { h: x, ev } = await setup("deploy", { role: ROLES.ddl, scopes: DDL_SCOPES, schema: "work" });
    const r = await apply(x, ev, "CREATE TABLE work.t1 (id int PRIMARY KEY); INSERT INTO work.t1 VALUES (1), (2), (3)", 2);
    expect(r.status).toBe("error");
    expect(await count("SELECT to_regclass('work.t1') IS NULL")).toBe("t");
  });

  it("destroy tavanı: DROP TABLE / TRUNCATE / WHERE'siz DELETE çalışır; ön izleme WHERE YOK ve kilit uyarısı gösterir", async () => {
    const gate = new FakeApprovalGate();
    const { h: x, ev } = await setup("destroy", { role: ROLES.ddl, scopes: DDL_SCOPES, schema: "work", gate });
    await pg!.admin("CREATE TABLE work.notes (id int); ALTER TABLE work.notes OWNER TO " + ROLES.ddl + "; INSERT INTO work.notes VALUES (1),(2)", "shop");
    const ev2 = await x.call("db.schema.describe", { schema: "work" });
    const del = await apply(x, ev2.evidenceId as string, "DELETE FROM work.items", 10);
    expect(del.status, JSON.stringify(del)).toBe("ok");
    expect(gate.requests[0]?.summary.preview?.impact?.join("\n")).toMatch(/WHERE yok/);
    expect(gate.requests[0]?.summary.class).toBe("destroy");
    expect(await count("SELECT count(*) FROM work.items")).toBe("0");
    const trunc = await apply(x, ev2.evidenceId as string, "TRUNCATE work.notes");
    expect(trunc.status, JSON.stringify(trunc)).toBe("ok");
    expect(gate.requests[1]?.summary.preview?.impact?.join("\n")).toMatch(/ACCESS EXCLUSIVE/);
    const drop = await apply(x, ev2.evidenceId as string, "DROP TABLE work.notes");
    expect(drop.status, JSON.stringify(drop)).toBe("ok");
    expect(await count("SELECT to_regclass('work.notes') IS NULL")).toBe("t");
  });

  it("CASCADE / CONCURRENTLY / izinli olmayan DDL kimlik alınmadan reddedilir", async () => {
    const { h: x, ev } = await setup("destroy", { role: ROLES.ddl, scopes: DDL_SCOPES, schema: "work" });
    for (const sql of ["DROP TABLE work.items CASCADE", "CREATE INDEX CONCURRENTLY i ON work.items (label)", "CREATE FUNCTION work.f() RETURNS int LANGUAGE sql AS 'select 1'", "ALTER TABLE work.items OWNER TO postgres", "GRANT ALL ON work.items TO PUBLIC", "DROP SCHEMA work"]) {
      const r = await apply(x, ev, sql);
      expect(r, sql).toMatchObject({ status: "denied", reasonCode: "target_unresolved" });
    }
    expect(await count("SELECT count(*) FROM work.items")).toBe("3");
  });
});

describe.skipIf(!pg)("yazıcı profili doktoru", () => {
  const find = (r: { findings: { code: string; severity: string }[] }, code: string) => r.findings.find((f) => f.code === code);

  it("DML yetkili rol + mutate tavanı: bağlanabilir, fiili sınıf mutate", async () => {
    const x = await makePgHarness({ role: ROLES.writer, writerCeiling: "mutate", profile: { allowedScopes: ["public"] } });
    const r = await x.doctor();
    expect(r, JSON.stringify(r.findings)).toMatchObject({ connected: true, bindable: true, effectiveClass: "mutate", declaredCeiling: "mutate" });
    expect(find(r, "write_privilege")).toBeUndefined();
  });

  it("izinli şemalar dışında yazma yetkisi → write_outside_scopes (bağlanamaz)", async () => {
    const x = await makePgHarness({ role: ROLES.writerWide, writerCeiling: "mutate", profile: { allowedScopes: ["public"] } });
    const r = await x.doctor();
    expect(find(r, "write_outside_scopes")).toMatchObject({ severity: "error" });
    expect(r.bindable).toBe(false);
  });

  it("tablo SAHİBİ rol: yok etme sınıfı; mutate/deploy tavanında ceiling_exceeded_by_grants, destroy tavanında bağlanır", async () => {
    for (const ceiling of ["mutate", "deploy"] as const) {
      const x = await makePgHarness({ role: ROLES.ddl, writerCeiling: ceiling, profile: { allowedScopes: ["public", "work"] } });
      const r = await x.doctor();
      expect(find(r, "owns_relations")).toBeDefined();
      expect(find(r, "ceiling_exceeded_by_grants"), ceiling).toMatchObject({ severity: "error" });
      expect(r.bindable).toBe(false);
      expect(r.effectiveClass).toBe("destroy");
    }
    const ok = await makePgHarness({ role: ROLES.ddl, writerCeiling: "destroy", profile: { allowedScopes: ["public", "work"] } });
    const r = await ok.doctor();
    expect(r, JSON.stringify(r.findings)).toMatchObject({ bindable: true, effectiveClass: "destroy" });
    expect(find(r, "schema_create")).toMatchObject({ severity: "warn" }); // deploy+ tavanda CREATE beklenir
  });

  it("süper kullanıcı ve dosya okuma rolleri writer profilinde de reddedilir", async () => {
    for (const role of [ROLES.superuser, ROLES.fileReader, ROLES.bypass]) {
      const x = await makePgHarness({ role, writerCeiling: "destroy", profile: { allowedScopes: ["public"] } });
      const r = await x.doctor();
      expect(r.bindable, role).toBe(false);
    }
  });

  it("writer profilinde yazma yetkisi hiç yoksa uyarır (reader olarak etiketlenmeli)", async () => {
    const x = await makePgHarness({ role: ROLES.reader, writerCeiling: "mutate", password: canaries.readerPw.value, profile: { allowedScopes: ["public"] } });
    const r = await x.doctor();
    expect(find(r, "no_write_privilege")).toMatchObject({ severity: "warn" });
  });
});

describe("db.change sınıf eşlemesi (adapter.classify, bağlantısız)", () => {
  const risk = async (sql: string): Promise<RiskClass | undefined> => {
    const { PostgresAdapter } = await import("../src/index.ts");
    const { LocalBroker, MemorySecretStore } = await import("@ops/broker");
    return new PostgresAdapter(new LocalBroker({ store: new MemorySecretStore() }).resolver).classify("db.change.apply", { sql });
  };
  it("sınıf ifade kümesinin en yükseğidir; reddedilen/eksik SQL destroy muamelesi görür", async () => {
    await import("./harness.ts");
    expect(await risk("INSERT INTO t (a) VALUES (1)")).toBe("mutate");
    expect(await risk("UPDATE t SET a = 1 WHERE b = 2; CREATE TABLE u (a int)")).toBe("deploy");
    expect(await risk("UPDATE t SET a = 1 WHERE b = 2; DROP TABLE u")).toBe("destroy");
    expect(await risk("COPY t TO PROGRAM 'id'")).toBe("destroy");
    expect(await risk("")).toBe("destroy");
  });
});

// Dosyanın sunucusu: durdurulmazsa her koşu bir PostgreSQL süreci (ve SysV paylaşımlı bellek) sızdırır.
afterAll(async () => {
  await pg?.stop();
});
