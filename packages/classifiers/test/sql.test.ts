import fc from "fast-check";
import { parseSync } from "libpg-query";
import { beforeAll, describe, expect, it } from "vitest";
import { RENAMED_JOIN, classifySql, initSqlClassifier, maskedViolations } from "../src/index.ts";

beforeAll(async () => {
  await initSqlClassifier();
});

const ok = (s: string) => {
  const r = classifySql(s);
  expect(r.allowed, `${s} → ${r.reason ?? ""}`).toBe(true);
  return r;
};
const bad = (s: string, why?: RegExp) => {
  const r = classifySql(s);
  expect(r.allowed, s).toBe(false);
  if (why) expect(r.reason, s).toMatch(why);
};

describe("S-02: SQL AST allowlist (gerçek PostgreSQL ayrıştırıcısı)", () => {
  it("meşru okuma sorguları kabul edilir", () => {
    for (const s of [
      "SELECT 1",
      "SELECT id, status, created_at FROM orders WHERE status = 'failed' AND created_at > now() - interval '1 day' ORDER BY created_at DESC LIMIT 50",
      "SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.total BETWEEN 10 AND 100",
      "SELECT status, count(*) AS n, avg(total) FROM orders GROUP BY status HAVING count(*) > 5",
      "WITH recent AS (SELECT * FROM orders WHERE created_at > now() - interval '1 hour') SELECT count(*) FROM recent",
      "SELECT * FROM a UNION ALL SELECT * FROM b",
      "SELECT DISTINCT ON (customer_id) customer_id, total FROM orders ORDER BY customer_id, created_at DESC",
      "SELECT lower(email) FROM users",
      "SELECT x FROM generate_series(1, 10) AS x",
      "SELECT row_number() OVER (PARTITION BY a ORDER BY b) FROM t",
      "SELECT CASE WHEN a > 1 THEN 'x' ELSE 'y' END, coalesce(b, 0), nullif(c, 0) FROM t",
      "SELECT a::text, extract(epoch FROM ts), date_trunc('day', ts), substring(s from 1 for 3), trim(s) FROM t",
      "SELECT * FROM t WHERE a IN (1, 2, 3) AND b LIKE 'x%' AND c ILIKE '%y' AND d IS NOT NULL AND e SIMILAR TO 'a%'",
      "SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.t_id = t.id)",
      "SELECT j->>'name', j #>> '{a,b}', jsonb_array_length(j->'items') FROM docs",
      "SELECT array_agg(id), string_agg(name, ',') FROM t",
      "SELECT current_date, current_timestamp",
      "SELECT /* yorum */ 1 -- satır sonu",
      "EXPLAIN SELECT * FROM orders WHERE id = 1",
      "EXPLAIN (VERBOSE, COSTS, FORMAT JSON) SELECT * FROM orders",
      "SELECT $$dolar$$",
      "VALUES (1, 'a'), (2, 'b')",
    ]) {
      ok(s);
    }
  });

  it("EXPLAIN işaretlenir ve sınıflama bilgisi çıkarılır", () => {
    const e = ok("EXPLAIN SELECT id FROM public.orders o JOIN customers c ON c.id = o.cid WHERE lower(c.email) = 'x'");
    expect(e.explain).toBe(true);
    expect(e.classification.statementKinds).toEqual(["ExplainStmt", "SelectStmt"]);
    expect([...e.classification.relations].sort()).toEqual(["customers", "public.orders"]);
    expect(e.classification.functions).toEqual(["lower"]);
    expect(e.classification.columnRefs.some((c) => c.column === "email" && c.insideExpression)).toBe(true);
    const s = ok("SELECT id, status FROM orders");
    expect(s.classification.columnRefs.filter((c) => !c.insideExpression).map((c) => c.column)).toEqual(["id", "status"]);
  });

  it.each([
    ["çoklu ifade", "SELECT 1; SELECT 2", /tek ifade/],
    ["çoklu ifade + DROP", "SELECT * FROM a; DROP TABLE a", /tek ifade/],
    ["yorumla gizlenmiş ikinci ifade", "SELECT 1; /* x */ DELETE FROM t", /tek ifade/],
    ["dolar-quote içinde ikinci ifade denemesi", "SELECT $$; DROP TABLE t; --$$; DELETE FROM t", /tek ifade/],
    ["CTE içinde DELETE", "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x", /CTE/],
    ["CTE içinde INSERT", "WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x", /CTE/],
    ["CTE içinde UPDATE", "WITH x AS (UPDATE t SET a=1 RETURNING *) SELECT * FROM x", /CTE/],
    ["SELECT FOR UPDATE", "SELECT * FROM t FOR UPDATE", /kilit/],
    ["SELECT FOR SHARE", "SELECT * FROM t FOR SHARE", /kilit/],
    ["SELECT FOR UPDATE alt sorguda", "SELECT * FROM (SELECT * FROM t FOR UPDATE) s", /kilit/],
    ["SELECT INTO", "SELECT * INTO newt FROM t", /INTO/],
    ["COPY TO PROGRAM", "COPY t TO PROGRAM 'id'", /ifade türü/],
    ["COPY FROM", "COPY t FROM '/etc/passwd'", /ifade türü/],
    ["pg_terminate_backend", "SELECT pg_terminate_backend(123)", /fonksiyon/],
    ["pg_cancel_backend", "SELECT pg_cancel_backend(1)", /fonksiyon/],
    ["pg_sleep", "SELECT pg_sleep(100)", /fonksiyon/],
    ["pg_read_file", "SELECT pg_read_file('/etc/passwd')", /fonksiyon/],
    ["pg_ls_dir", "SELECT pg_ls_dir('/')", /fonksiyon/],
    ["lo_import", "SELECT lo_import('/etc/passwd')", /fonksiyon/],
    ["lo_export", "SELECT lo_export(1, '/tmp/x')", /fonksiyon/],
    ["dblink", "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)", /fonksiyon/],
    ["nextval (mutasyon)", "SELECT nextval('s')", /fonksiyon/],
    ["setval (mutasyon)", "SELECT setval('s', 1)", /fonksiyon/],
    ["set_config", "SELECT set_config('default_transaction_read_only', 'off', false)", /fonksiyon/],
    ["current_setting", "SELECT current_setting('server_version')", /fonksiyon/],
    ["query_to_xml (SQL çalıştırır)", "SELECT query_to_xml('delete from t', true, true, '')", /fonksiyon/],
    ["şema nitelikli fonksiyon", "SELECT public.my_func(1)", /şema nitelikli/],
    ["pg_catalog nitelikli ama izinsiz", "SELECT pg_catalog.pg_sleep(1)", /fonksiyon/],
    ["SET ROLE", "SET ROLE postgres", /ifade türü/],
    ["SET read_only kapatma", "SET default_transaction_read_only=off", /ifade türü/],
    ["SET SESSION AUTHORIZATION", "SET SESSION AUTHORIZATION postgres", /ifade türü/],
    ["RESET", "RESET ALL", /ifade türü/],
    ["DO bloğu", "DO $$ BEGIN PERFORM pg_sleep(1); END $$", /ifade türü/],
    ["CALL", "CALL p()", /ifade türü/],
    ["EXPLAIN ANALYZE DELETE", "EXPLAIN ANALYZE DELETE FROM t", /EXPLAIN|ANALYZE/],
    ["EXPLAIN ANALYZE SELECT (çalıştırır)", "EXPLAIN ANALYZE SELECT * FROM t", /ANALYZE/],
    ["EXPLAIN (ANALYZE false)", "EXPLAIN (ANALYZE false) SELECT 1", /ANALYZE/],
    ["EXPLAIN (BUFFERS)", "EXPLAIN (BUFFERS) SELECT 1", /izinli değil/],
    ["EXPLAIN DELETE", "EXPLAIN DELETE FROM t", /yalnız SELECT/],
    ["INSERT", "INSERT INTO t VALUES (1)", /ifade türü/],
    ["UPDATE", "UPDATE t SET a = 1", /ifade türü/],
    ["DELETE", "DELETE FROM t", /ifade türü/],
    ["TRUNCATE", "TRUNCATE t", /ifade türü/],
    ["DROP", "DROP TABLE t", /ifade türü/],
    ["CREATE TABLE AS", "CREATE TABLE x AS SELECT * FROM t", /ifade türü/],
    ["ALTER SYSTEM", "ALTER SYSTEM SET work_mem = '1GB'", /ifade türü/],
    ["GRANT", "GRANT ALL ON t TO public", /ifade türü/],
    ["VACUUM", "VACUUM t", /ifade türü/],
    ["LOCK", "LOCK TABLE t", /ifade türü/],
    ["LISTEN", "LISTEN ch", /ifade türü/],
    ["NOTIFY", "NOTIFY ch", /ifade türü/],
    ["PREPARE", "PREPARE p AS SELECT 1", /ifade türü/],
    ["EXECUTE", "EXECUTE p", /ifade türü/],
    ["DECLARE CURSOR", "DECLARE c CURSOR FOR SELECT 1", /ifade türü/],
    ["BEGIN", "BEGIN", /ifade türü/],
    ["COMMIT", "COMMIT", /ifade türü/],
    ["SHOW", "SHOW ALL", /ifade türü/],
    ["DISCARD", "DISCARD ALL", /ifade türü/],
    ["CHECKPOINT", "CHECKPOINT", /ifade türü/],
    ["pg_shadow (parola özetleri)", "SELECT usename, passwd FROM pg_shadow", /sistem kataloğu/],
    ["pg_authid", "SELECT * FROM pg_authid", /sistem kataloğu/],
    ["pg_catalog.pg_user", "SELECT * FROM pg_catalog.pg_user", /sistem kataloğu/],
    ["information_schema", "SELECT * FROM information_schema.columns", /sistem kataloğu/],
    ["pg_stat_activity", "SELECT query FROM pg_stat_activity", /sistem kataloğu/],
    ["regclass dönüşümü", "SELECT 'pg_shadow'::regclass", /reg\*/],
    ["regproc dönüşümü", "SELECT 'now'::regproc", /reg\*/],
    ["kullanıcı tanımlı operatör", "SELECT 1 OPERATOR(public.+) 2", /operatör/],
    ["bilinmeyen operatör", "SELECT a <-> b FROM t", /operatör/],
    ["parametre", "SELECT * FROM t WHERE a = $1", /düğüm/],
    ["TABLESAMPLE", "SELECT * FROM t TABLESAMPLE SYSTEM (10)", /düğüm/],
    ["XMLTABLE", "SELECT * FROM XMLTABLE('/a' PASSING '<a/>' COLUMNS x text)", /düğüm/],
    ["CURRENT_USER", "SELECT current_user", /SQL değer fonksiyonu/],
    ["SESSION_USER", "SELECT session_user", /SQL değer fonksiyonu/],
    ["ayrıştırılamayan", "SELEKT 1", /ayrıştırılamadı/],
    ["boş", "   ", /boş/],
    ["yalnız yorum", "-- merhaba", /tek ifade|boş/],
  ])("reddedilir: %s", (_n, sql, why) => {
    bad(sql as string, why as RegExp);
  });

  it("çok uzun ve NUL içeren girdi reddedilir; başlatılmamış sınıflayıcı fail-closed", () => {
    bad(`SELECT ${"1,".repeat(20_000)}1`, /uzun/);
    bad("SELECT 1\0", /NUL|ayrıştırılamadı/);
  });

  it("tam-satır başvuruları: to_jsonb(t), row_to_json(t), SELECT t, t.*", () => {
    expect(ok("SELECT to_jsonb(u) FROM users u").classification.wholeRowRefs).toEqual(["u"]);
    expect(ok("SELECT row_to_json(users) FROM users").classification.wholeRowRefs).toEqual(["users"]);
    expect(ok("SELECT u FROM users u").classification.wholeRowRefs).toEqual(["u"]);
    expect(ok("SELECT u.* FROM users u").classification.hasStarSelect).toBe(true);
    expect(ok("SELECT to_jsonb(u.*) FROM users u").classification.wholeRowRefs).toContain("*");
    expect(ok("SELECT id FROM users").classification.wholeRowRefs).toEqual([]);
  });
});

describe("M4 AST kuralı: maskeli sütunlar", () => {
  const masked = new Map([["users", new Set(["email", "phone"])]]);
  const viol = (s: string) => maskedViolations(ok(s), masked);
  it("doğrudan seçim öğesi serbest", () => {
    expect(viol("SELECT id, email FROM users")).toEqual([]);
    expect(viol("SELECT u.email, u.phone FROM users u")).toEqual([]);
    expect(viol("SELECT id FROM orders")).toEqual([]); // maskeli tabloya dokunmuyor
  });
  it.each([
    ["fonksiyon içinde", "SELECT lower(email) FROM users"],
    ["WHERE koşulunda (varlık sızdırır)", "SELECT id FROM users WHERE email = 'a@b.invalid'"],
    ["JOIN koşulunda", "SELECT o.id FROM orders o JOIN users u ON u.email = o.contact"],
    ["ORDER BY içinde", "SELECT id FROM users ORDER BY email"],
    ["alt sorgu içinde", "SELECT * FROM (SELECT email FROM users) s"],
    ["SELECT *", "SELECT * FROM users"],
    ["u.*", "SELECT u.* FROM users u"],
    ["to_jsonb(u)", "SELECT to_jsonb(u) FROM users u"],
    ["ifade", "SELECT email || 'x' FROM users"],
    ["concat", "SELECT concat(phone, '-') FROM users"],
    ["CASE", "SELECT CASE WHEN email IS NULL THEN 0 ELSE 1 END FROM users"],
  ])("ihlal: %s", (_n, sql) => {
    expect(viol(sql as string).length).toBeGreaterThan(0);
  });
});

describe("M4 AST kuralı: kökensiz çıktılar (tam satır, hesaplanan, küme işlemi) ve birleştirme oracle'ı", () => {
  const masked = new Map([["customers", new Set(["name", "email"])]]);
  const viol = (s: string) => maskedViolations(ok(s), masked);

  it("çıplak FROM öğesi adı her konumda tam-satır başvurusudur (fonksiyon, dönüşüm, ROW, dizi, CASE, alt sorgu, alan seçimi)", () => {
    for (const [sql, ref] of [
      ["SELECT json_build_object('r', c) FROM customers c", "c"],
      ["SELECT json_agg(c) FROM customers c", "c"],
      ["SELECT array_agg(c)::text FROM customers c", "c"],
      ["SELECT c::text FROM customers c", "c"],
      ["SELECT format('%s', c) FROM customers c", "c"],
      ["SELECT ROW(c) FROM customers c", "c"],
      ["SELECT ARRAY[c] FROM customers c", "c"],
      ["SELECT coalesce(c, c) FROM customers c", "c"],
      ["SELECT CASE WHEN true THEN c END FROM customers c", "c"],
      ["SELECT c || 'x' FROM customers c", "c"],
      ["SELECT (SELECT c) FROM customers c", "c"],
      ["SELECT lower((c).email) FROM customers c", "c"],
      ["SELECT count(*) FROM customers WHERE customers::text LIKE '%Ayse%'", "customers"],
      ["SELECT json_agg(j) FROM (customers c JOIN orders o ON o.customer_id = c.id) j", "j"],
      ["SELECT u FROM customers JOIN v USING (id) AS u", "u"],
    ] as const) {
      expect(ok(sql).classification.wholeRowRefs, sql).toContain(ref);
      expect(viol(sql), sql).toContainEqual(expect.stringMatching(/tam-satır/));
    }
  });

  it("öznitelik gösterimi `t.f` = `f(t)`: satırı döndürenler tam-satır sayılır, allowlist dışındakiler reddedilir", () => {
    for (const sql of ["SELECT c.to_jsonb FROM customers c", "SELECT customers.row_to_json FROM customers", "SELECT public.customers.json_agg FROM public.customers", "SELECT c.concat FROM customers c"]) {
      expect(ok(sql).classification.wholeRowRefs.length, sql).toBeGreaterThan(0);
      expect(viol(sql), sql).toContainEqual(expect.stringMatching(/tam-satır/));
    }
    for (const fn of ["quote_literal", "quote_nullable", "record_out", "record_send", "hash_record"]) {
      bad(`SELECT c.${fn} FROM customers c`, /öznitelik gösterimi/);
      bad(`SELECT id FROM t WHERE length(t.${fn}::text) > 1`, /öznitelik gösterimi/);
    }
    // sıradan nitelikli sütunlar ve allowlist'teki satır dışı fonksiyon adları etkilenmez
    expect(ok("SELECT c.id, c.status FROM orders c").classification.wholeRowRefs).toEqual([]);
    expect(ok("SELECT s.count FROM stats s").classification.wholeRowRefs).toEqual([]);
  });

  it("küme işlemleri maskeli tabloya dokunuyorsa reddedilir (sonuç sütununun kökeni bildirilmez)", () => {
    for (const sql of [
      "SELECT 'x' UNION ALL SELECT name FROM customers",
      "SELECT name FROM customers INTERSECT SELECT 'Ayse'",
      "SELECT id FROM customers EXCEPT SELECT 1",
      "SELECT id FROM orders WHERE customer_id IN (SELECT id FROM customers UNION SELECT 0)",
    ]) {
      expect(ok(sql).classification.setOperation, sql).toBe(true);
      expect(viol(sql), sql).toContainEqual(expect.stringMatching(/küme işlemi/));
    }
    expect(ok("SELECT id FROM customers").classification.setOperation).toBe(false);
    expect(viol("SELECT 1 UNION SELECT 2")).toEqual([]);
    expect(viol("SELECT id FROM orders UNION ALL SELECT id FROM orders")).toEqual([]);
  });

  it("JOIN … USING (maskeli sütun) ve maskeli tabloyla NATURAL JOIN reddedilir", () => {
    expect(viol("SELECT count(*) FROM customers JOIN (VALUES ('Ayse')) v(name) USING (name)")).toContainEqual(expect.stringMatching(/maskeli sütun ifade\/koşul içinde: name/));
    expect(viol("SELECT o.id FROM orders o JOIN customers c USING (email)")).not.toEqual([]);
    const nat = "SELECT count(*) FROM customers NATURAL JOIN (VALUES ('Ayse')) v(name)";
    expect(ok(nat).classification.naturalJoin).toBe(true);
    expect(viol(nat)).toContainEqual(expect.stringMatching(/NATURAL JOIN/));
    // maskeli olmayan sütunla USING ve maskeli tabloya dokunmayan NATURAL JOIN serbest
    expect(viol("SELECT o.id, c.name FROM orders o JOIN customers c USING (id)")).toEqual([]);
    expect(viol("SELECT count(*) FROM orders NATURAL JOIN invoices")).toEqual([]);
  });

  it("sütun takma adı listesiyle yeniden adlandırma: maskeli tabloda ve birleşim takma adında reddedilir", () => {
    const rv = ok("SELECT lower(c) FROM customers AS x(a, b, c)");
    expect(rv.classification.renamedRelations).toEqual(["customers"]);
    expect(maskedViolations(rv, masked)).toContainEqual(expect.stringMatching(/takma adı listesi/));
    const j = ok("SELECT lower(e) FROM (customers c JOIN orders o ON true) AS j(a, b, e)");
    expect(j.classification.renamedRelations).toEqual([RENAMED_JOIN]);
    expect(maskedViolations(j, masked)).toContainEqual(expect.stringMatching(/takma adı listesi/));
    // maskeli olmayan tablo, VALUES ve alt sorgu sütun adları serbest (alt sorgu hedefleri zaten ifade sayılır)
    expect(viol("SELECT o.n FROM orders AS o(n) JOIN customers c ON c.id = o.n")).toEqual([]);
    expect(viol("SELECT c.name, v.x FROM customers c JOIN (VALUES (1)) v(x) ON v.x = c.id")).toEqual([]);
  });

  it("doğrudan seçim ve maskeli sütunsuz koşullar serbest kalır", () => {
    for (const sql of [
      "SELECT id, name, email FROM customers",
      "SELECT c.id, c.name FROM customers c WHERE c.id = 1",
      "SELECT o.id, c.email FROM orders o JOIN customers c ON c.id = o.customer_id ORDER BY o.id",
      "SELECT x FROM generate_series(1, 3) AS x",
    ]) {
      expect(viol(sql), sql).toEqual([]);
    }
  });
});

describe("özellik testleri", () => {
  const FORBIDDEN_KINDS = /"(?:InsertStmt|UpdateStmt|DeleteStmt|MergeStmt|CopyStmt|DoStmt|CallStmt|VariableSetStmt|CreateStmt|DropStmt|TruncateStmt|IntoClause|LockingClause|ParamRef|AlterSystemStmt|TransactionStmt)":/;
  const seeds = [
    "SELECT a FROM t",
    "SELECT a, b FROM t WHERE c = 1",
    "WITH x AS (SELECT 1) SELECT * FROM x",
    "SELECT count(*) FROM t GROUP BY a",
    "EXPLAIN SELECT 1",
    "SELECT lower(a) FROM t",
    "SELECT * FROM t WHERE a IN (SELECT b FROM u)",
  ];
  const frag = ["DELETE FROM t", "; DROP TABLE t", "INTO x", "FOR UPDATE", "ANALYZE", "pg_sleep(1)", "$1", "/*", "*/", "--", "$$", "'", "\"", "COPY t TO PROGRAM 'x'", "UNION SELECT 1", "RETURNING *", "SET x = 1", "OPERATOR(a.+)", "::regclass"];

  it("kabul edilen her sorguda ayrıştırma ağacında yazan/yasak düğüm yok; sınıflayıcı asla çökmez", () => {
    fc.assert(
      fc.property(fc.constantFrom(...seeds), fc.constantFrom(...frag), fc.nat(), (seed, f, pos) => {
        const i = pos % (seed.length + 1);
        const sql = `${seed.slice(0, i)} ${f} ${seed.slice(i)}`;
        const r = classifySql(sql);
        if (!r.allowed) return true;
        let tree: string;
        try {
          tree = JSON.stringify(parseSync(sql));
        } catch {
          return false; // sınıflayıcı kabul etti ama ayrıştırılamıyor: tutarsız
        }
        return !FORBIDDEN_KINDS.test(tree) && r.classification.statementCount === 1;
      }),
      { numRuns: 1500 },
    );
  });

  it("rastgele metin çökertmez", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 80 }), (s) => {
        const r = classifySql(s);
        return typeof r.allowed === "boolean";
      }),
      { numRuns: 1500 },
    );
  });
});
