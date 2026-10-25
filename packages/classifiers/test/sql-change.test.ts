import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import { classifySqlChange, initSqlClassifier, maskedViolations, strongerLock } from "../src/index.ts";

beforeAll(async () => {
  await initSqlClassifier();
});

const ok = (s: string) => {
  const r = classifySqlChange(s);
  expect(r.allowed, `${s} → ${r.reason ?? ""}`).toBe(true);
  return r;
};
const bad = (s: string, why?: RegExp) => {
  const r = classifySqlChange(s);
  expect(r.allowed, s).toBe(false);
  if (why) expect(r.reason, s).toMatch(why);
};

describe("db.change SQL sınıflayıcı (gerçek PostgreSQL ayrıştırıcısı, allowlist)", () => {
  it("DML ve DDL ifadeleri doğru sınıf ve hedefle kabul edilir", () => {
    const cases: [string, string, string][] = [
      ["INSERT INTO public.orders (id, customer_id, status, total) VALUES (100, 1, 'paid', 5), (101, 2, 'paid', 6)", "insert", "mutate"],
      ["INSERT INTO orders SELECT id + 1000, customer_id, status, total, created_at FROM orders WHERE id < 5", "insert", "mutate"],
      ["UPDATE orders SET status = lower(status), total = total * 2 WHERE id = 3", "update", "mutate"],
      ["UPDATE orders SET status = 'x'", "update", "deploy"],
      ["DELETE FROM orders WHERE status = 'failed' AND created_at < now() - interval '30 days'", "delete", "mutate"],
      ["DELETE FROM orders", "delete", "destroy"],
      ["CREATE TABLE public.notes (id serial PRIMARY KEY, body text NOT NULL DEFAULT '', n int CHECK (n > 0), o int REFERENCES public.orders(id))", "create_table", "deploy"],
      ["CREATE UNIQUE INDEX ix_orders_status ON orders USING btree (lower(status)) WHERE id > 1", "create_index", "deploy"],
      ["CREATE VIEW v_paid AS SELECT id, total FROM orders WHERE status = 'paid'", "create_view", "deploy"],
      ["ALTER TABLE orders ADD COLUMN note text DEFAULT 'x', ALTER COLUMN status SET NOT NULL", "alter_table", "deploy"],
      ["ALTER TABLE orders DROP COLUMN note", "alter_table", "destroy"],
      ["DROP TABLE IF EXISTS public.notes", "drop", "destroy"],
      ["TRUNCATE public.notes RESTART IDENTITY", "truncate", "destroy"],
    ];
    for (const [sql, kind, risk] of cases) {
      const r = ok(sql);
      expect(r.statements).toHaveLength(1);
      expect(r.statements[0]?.kind, sql).toBe(kind);
      expect(r.risk, sql).toBe(risk);
      expect(r.statements[0]?.targets.length, sql).toBeGreaterThan(0);
    }
  });

  it("sütuna başvurmayan WHERE (1=1, true, EXISTS) WHERE'siz sayılır: sınıf düşürülemez", () => {
    const cases: [string, string][] = [
      ["DELETE FROM customers WHERE 1=1", "destroy"],
      ["DELETE FROM customers WHERE true", "destroy"],
      ["DELETE FROM customers WHERE 'a' = 'a' OR false", "destroy"],
      ["DELETE FROM customers WHERE EXISTS (SELECT 1 FROM orders WHERE orders.id = 1)", "destroy"],
      ["UPDATE customers SET name = 'x' WHERE true", "deploy"],
      ["UPDATE customers SET name = 'x' WHERE NOT false", "deploy"],
      // yalnız başka tablonun sütunu: hedefin her satırı (çapraz birleşim)
      ["UPDATE customers SET name = 'x' FROM orders WHERE orders.status = 'paid'", "deploy"],
      ["DELETE FROM customers USING orders o WHERE o.id = 1", "destroy"],
      // hedef sütunlu koşullar sınırlı sayılır (takma ad, nitelenmemiş ad, alt sorgunun dış ifadesi)
      ["DELETE FROM customers WHERE id = 1", "mutate"],
      ["DELETE FROM customers WHERE id IN (SELECT customer_id FROM orders WHERE status = 'failed')", "mutate"],
      ["UPDATE customers SET name = 'x' WHERE id = 1 AND true", "mutate"],
      ["UPDATE customers c SET name = 'x' FROM orders o WHERE o.customer_id = c.id", "mutate"],
      ["DELETE FROM public.customers WHERE customers.id = 2", "mutate"],
    ];
    for (const [sql, risk] of cases) {
      const r = ok(sql);
      expect(r.risk, sql).toBe(risk);
      expect(r.statements[0]?.unbounded, sql).toBe(risk !== "mutate");
    }
  });

  it("çok ifadeli kümeyi böler, her metni aynen korur ve en yüksek sınıfı verir", () => {
    const r = ok("UPDATE orders SET status = 'x' WHERE id = 1;\n  DELETE FROM orders WHERE id = 2 ;\nINSERT INTO orders (id, customer_id, status, total) VALUES (1, 1, 'ü', 1);");
    expect(r.statements.map((s) => s.kind)).toEqual(["update", "delete", "insert"]);
    expect(r.statements.map((s) => s.text)).toEqual(["UPDATE orders SET status = 'x' WHERE id = 1", "DELETE FROM orders WHERE id = 2", "INSERT INTO orders (id, customer_id, status, total) VALUES (1, 1, 'ü', 1)"]);
    expect(r.risk).toBe("mutate");
    expect(r.digest).toMatch(/^[0-9a-f]{64}$/);
    const r2 = ok("UPDATE orders SET status = 'x' WHERE id = 1; DROP TABLE notes");
    expect(r2.risk).toBe("destroy");
    // aynı küme aynı özet, farklı sıra/metin farklı özet
    expect(ok("UPDATE orders SET status = 'x' WHERE id = 1; DROP TABLE notes").digest).toBe(r2.digest);
    expect(ok("DROP TABLE notes; UPDATE orders SET status = 'x' WHERE id = 1").digest).not.toBe(r2.digest);
  });

  it("çok baytlı karakterlerde ifade sınırları doğru kesilir", () => {
    const r = ok("INSERT INTO t (a) VALUES ('çğıöşü€😀'); INSERT INTO t (a) VALUES ('ş')");
    expect(r.statements.map((s) => s.text)).toEqual(["INSERT INTO t (a) VALUES ('çğıöşü€😀')", "INSERT INTO t (a) VALUES ('ş')"]);
  });

  it("hedef ve okunan ilişkiler ayrılır; kilit kipi ifade türüne göre", () => {
    const r = ok("UPDATE orders SET total = 0 WHERE customer_id IN (SELECT id FROM customers WHERE name = 'a')");
    expect(r.statements[0]?.targets).toEqual([{ name: "orders" }]);
    expect(r.statements[0]?.reads).toEqual([{ name: "customers" }]);
    expect(r.statements[0]?.lockMode).toBe("ROW EXCLUSIVE");
    expect(ok("ALTER TABLE sales.invoices ADD COLUMN x int").statements[0]?.lockMode).toBe("ACCESS EXCLUSIVE");
    expect(ok("CREATE INDEX i ON sales.invoices (amount)").statements[0]?.lockMode).toBe("SHARE");
    expect(ok("CREATE INDEX i ON sales.invoices (amount)").statements[0]?.targets).toEqual([{ schema: "sales", name: "invoices" }]);
    expect(strongerLock("SHARE", "ROW EXCLUSIVE")).toBe("SHARE");
    expect(ok("CREATE TABLE t (o int REFERENCES orders(id))").statements[0]?.reads).toEqual([{ name: "orders" }]);
    expect(ok("CREATE TABLE t2 (a int)").statements[0]?.creates).toBe(true);
  });

  it("izinli olmayan ifade türleri reddedilir (bilinmeyen = ret)", () => {
    for (const s of [
      "SELECT 1",
      "COPY orders TO PROGRAM 'id'",
      "COPY orders FROM '/etc/passwd'",
      "DO $$ begin perform 1; end $$",
      "CALL p()",
      "SET ROLE postgres",
      "RESET ALL",
      "GRANT ALL ON orders TO public",
      "REVOKE ALL ON orders FROM public",
      "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'select 1'",
      "CREATE EXTENSION dblink",
      "CREATE ROLE r SUPERUSER",
      "ALTER ROLE r SUPERUSER",
      "CREATE SCHEMA s",
      "DROP SCHEMA s",
      "DROP DATABASE shop",
      "DROP INDEX ix",
      "VACUUM orders",
      "ANALYZE orders",
      "LOCK TABLE orders",
      "BEGIN",
      "COMMIT",
      "ROLLBACK",
      "SAVEPOINT s",
      "PREPARE p AS SELECT 1",
      "EXECUTE p",
      "LISTEN c",
      "NOTIFY c",
      "COMMENT ON TABLE orders IS 'x'",
      "ALTER TABLE orders RENAME TO o2",
      "ALTER SYSTEM SET work_mem = '1GB'",
      "CREATE TRIGGER t BEFORE INSERT ON orders FOR EACH ROW EXECUTE FUNCTION f()",
      "CREATE POLICY p ON orders USING (true)",
      "EXPLAIN ANALYZE UPDATE orders SET status = 'x'",
      "MERGE INTO orders o USING customers c ON o.customer_id = c.id WHEN MATCHED THEN DELETE",
      "REFRESH MATERIALIZED VIEW mv",
      "REINDEX TABLE orders",
      "CLUSTER orders",
      "DISCARD ALL",
      "CHECKPOINT",
      "ALTER TABLE orders OWNER TO postgres",
      "ALTER TABLE orders ENABLE ROW LEVEL SECURITY",
      "ALTER TABLE orders DISABLE TRIGGER ALL",
    ]) {
      bad(s);
    }
  });

  it("DML kısıtları: RETURNING, ON CONFLICT, WITH, geçici tablo, CASCADE, CONCURRENTLY, çoklu sorun", () => {
    bad("INSERT INTO orders (id) VALUES (1) RETURNING id", /returning/);
    bad("UPDATE orders SET status = 'x' WHERE id = 1 RETURNING *", /returning/);
    bad("DELETE FROM orders WHERE id = 1 RETURNING id", /returning/);
    bad("INSERT INTO orders (id) VALUES (1) ON CONFLICT DO NOTHING", /onConflict/);
    bad("WITH d AS (DELETE FROM orders RETURNING id) INSERT INTO t SELECT id FROM d");
    bad("WITH x AS (SELECT 1) UPDATE orders SET status = 'x' WHERE id = 1", /withClause/);
    bad("INSERT INTO orders OVERRIDING SYSTEM VALUE VALUES (1)", /OVERRIDING/);
    bad("CREATE TEMP TABLE t (a int)", /geçici|unlogged/);
    bad("CREATE UNLOGGED TABLE t (a int)", /geçici|unlogged/);
    bad("DROP TABLE orders CASCADE", /CASCADE/);
    bad("TRUNCATE orders CASCADE", /CASCADE/);
    bad("ALTER TABLE orders DROP COLUMN x CASCADE", /CASCADE/);
    bad("CREATE INDEX CONCURRENTLY i ON orders (id)", /concurrent/);
    bad("CREATE TABLE t (a int) PARTITION BY RANGE (a)", /partspec/);
    bad("CREATE TABLE t (a int) INHERITS (orders)", /inhRelations/);
    bad("CREATE TABLE t (a int) WITH (fillfactor = 50)", /options/);
    bad("CREATE TABLE t (a int) TABLESPACE pg_default", /tablespacename/);
    bad("CREATE TABLE t (a int, EXCLUDE USING gist (a WITH =))", /kısıt/);
    bad("CREATE TABLE t (a regclass)", /reg/);
    bad("CREATE TABLE t (a int GENERATED ALWAYS AS (a + 1) STORED)", /kısıt/);
    bad("ALTER TABLE orders ADD COLUMN c int GENERATED ALWAYS AS (1) STORED", /kısıt/);
    bad("CREATE INDEX i ON orders USING nope (id)");
    bad("CREATE INDEX i ON orders (id) WITH (fillfactor = 10)", /options/);
    bad("CREATE VIEW v WITH (security_barrier) AS SELECT 1", /options/);
    bad("CREATE VIEW v AS SELECT 1 WITH CHECK OPTION", /CHECK OPTION|check/i);
    bad("UPDATE orders SET x = 1 WHERE CURRENT OF c", /CurrentOf|izinli/);
  });

  it("ifade içi tehlikeli yapılar reddedilir (SELECT allowlist'iyle aynı kurallar)", () => {
    for (const s of [
      "UPDATE orders SET status = pg_read_file('/etc/passwd') WHERE id = 1",
      "UPDATE orders SET status = (SELECT token FROM pg_catalog.pg_shadow LIMIT 1) WHERE id = 1",
      "UPDATE orders SET status = current_user WHERE id = 1",
      "INSERT INTO orders (status) VALUES (nextval('s'))",
      "INSERT INTO orders (status) VALUES (set_config('a','b',false))",
      "UPDATE orders SET status = 'x' WHERE id = 1::regclass",
      "DELETE FROM orders WHERE id IN (SELECT id FROM pg_stat_activity)",
      "UPDATE orders SET status = 'x' FROM pg_catalog.pg_class WHERE true",
      "UPDATE orders SET total = lo_import('/etc/passwd') WHERE id = 1",
      "INSERT INTO orders SELECT * FROM dblink('x', 'select 1') AS t(a int)",
      "INSERT INTO pg_catalog.pg_class VALUES (1)",
      "UPDATE pg_authid SET rolsuper = true",
      "UPDATE information_schema.tables SET table_name = 'x'",
      "DELETE FROM pg_tables",
      "DROP TABLE pg_catalog.pg_class",
      "TRUNCATE pg_catalog.pg_class",
      "ALTER TABLE pg_catalog.pg_class ADD COLUMN x int",
      "UPDATE db.public.orders SET status = 'x' WHERE id = 1",
    ]) {
      bad(s);
    }
  });

  it("katı ilişki adı: tırnaklı/büyük harfli adlar reddedilir", () => {
    bad('UPDATE "Orders" SET status = \'x\' WHERE id = 1', /küçük harf/);
    bad('INSERT INTO "my table" (a) VALUES (1)', /küçük harf/);
    ok("INSERT INTO Orders (a) VALUES (1)"); // ayrıştırıcı katlama: Orders → orders
  });

  it("sınır koşulları: boş, NUL, çok uzun, ayrıştırılamayan, çok fazla ifade, başlatılmadan önce ret", () => {
    bad("", /boş/);
    bad("   ", /boş/);
    bad("UPDATE orders SET a = 1\0", /NUL/);
    bad(`INSERT INTO t VALUES ('${"a".repeat(21_000)}')`, /uzun/);
    bad("UPDATE UPDATE", /ayrıştırılamadı/);
    bad(Array.from({ length: 21 }, (_, i) => `UPDATE t SET a = ${i} WHERE id = 1`).join(";"), /en çok/);
    expect(classifySqlChange(Array.from({ length: 20 }, (_, i) => `UPDATE t SET a = ${i} WHERE id = 1`).join(";")).allowed).toBe(true);
  });

  it("maskeli sütun kuralı değişikliklere de uygulanır (WHERE/alt sorgu üzerinden okuma oracle'ı yok)", () => {
    const masked = new Map([["customers", new Set(["email"])]]);
    const v = (sql: string) => maskedViolations({ allowed: true, explain: false, classification: ok(sql).classification }, masked);
    expect(v("UPDATE customers SET name = 'x' WHERE email LIKE 'a%'")).not.toEqual([]);
    expect(v("DELETE FROM customers WHERE lower(email) = 'a'")).not.toEqual([]);
    expect(v("INSERT INTO t SELECT email FROM customers")).not.toEqual([]);
    expect(v("INSERT INTO t SELECT * FROM customers")).not.toEqual([]);
    expect(v("UPDATE customers SET name = 'x' WHERE id = 1")).toEqual([]);
    expect(v("UPDATE customers SET email = 'x' WHERE id = 1")).toEqual([]); // yazmak okuma değil
  });

  it("özellik: rastgele metin hiçbir zaman istisna fırlatmaz ve izinli ise her ifade metni tek ifadedir", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 120 }), (s) => {
        const r = classifySqlChange(s);
        if (r.allowed) {
          expect(r.statements.length).toBeGreaterThan(0);
          for (const st of r.statements) expect(st.text.includes(";")).toBe(false);
        }
      }),
      { numRuns: 300 },
    );
    fc.assert(
      fc.property(fc.constantFrom("UPDATE", "DELETE FROM", "INSERT INTO", "DROP TABLE", "TRUNCATE", "ALTER TABLE", "CREATE TABLE"), fc.string({ maxLength: 40 }), (head, tail) => {
        expect(() => classifySqlChange(`${head} ${tail}`)).not.toThrow();
      }),
      { numRuns: 300 },
    );
  });
});
