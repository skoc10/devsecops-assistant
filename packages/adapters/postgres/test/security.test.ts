import pg_ from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { makeCanary } from "@ops/testkit";
import { parseMaskingConfig } from "../src/index.ts";
import type { PgDriverApi } from "../src/index.ts";
import { ROLES, canaries, makePgHarness, pg } from "./harness.ts";

const masking = parseMaskingConfig(["version: 1", "profiles:", "  '*':", "    maskedColumns:", "      customers: [email, phone]"].join("\n"));

/** connect çağrılarını sayan sürücü: reddedilen SQL'in kimlik/bağlantıya HİÇ ulaşmadığını gösterir. */
function counting() {
  const state = { connects: 0 };
  return { state, wrap: (real: PgDriverApi): PgDriverApi => ({ dialect: real.dialect, capabilities: real.capabilities, classify: (s) => real.classify(s), connect: (h, r, o) => (state.connects++, real.connect(h, r, o)) }) };
}

describe.skipIf(!pg)("S-02 (DB ayağı): reddedilen SQL kimliğe/bağlantıya ulaşmaz", () => {
  const BAD: [string, string, RegExp][] = [
    ["çoklu ifade", "SELECT 1; SELECT 2", /tek ifade/],
    ["ikinci ifade DROP", "SELECT 1; DROP TABLE public.orders", /tek ifade/],
    ["INSERT", "INSERT INTO public.orders VALUES (999, 1, 'x', 1, now())", /ifade türü/],
    ["UPDATE", "UPDATE public.orders SET status = 'x'", /ifade türü/],
    ["DELETE", "DELETE FROM public.orders", /ifade türü/],
    ["TRUNCATE", "TRUNCATE public.orders", /ifade türü/],
    ["DROP", "DROP TABLE public.orders", /ifade türü/],
    ["CREATE TABLE AS", "CREATE TABLE public.x AS SELECT 1", /ifade türü/],
    ["CTE içinde DELETE", "WITH d AS (DELETE FROM public.orders RETURNING *) SELECT * FROM d", /CTE/],
    ["FOR UPDATE", "SELECT * FROM public.orders FOR UPDATE", /kilit/],
    ["SELECT INTO", "SELECT * INTO public.copy FROM public.orders", /INTO/],
    ["COPY TO PROGRAM", "COPY public.orders TO PROGRAM 'id'", /ifade türü/],
    ["pg_terminate_backend", "SELECT pg_terminate_backend(1)", /fonksiyon/],
    ["pg_read_file", "SELECT pg_read_file('/etc/passwd')", /fonksiyon/],
    ["lo_import", "SELECT lo_import('/etc/passwd')", /fonksiyon/],
    ["dblink", "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)", /fonksiyon/],
    ["set_config", "SELECT set_config('default_transaction_read_only', 'off', false)", /fonksiyon/],
    ["SET ROLE", "SET ROLE postgres", /ifade türü/],
    ["SET read_only off", "SET default_transaction_read_only = off", /ifade türü/],
    ["DO bloğu", "DO $$ BEGIN PERFORM 1; END $$", /ifade türü/],
    ["pg_shadow", "SELECT usename, passwd FROM pg_shadow", /sistem kataloğu/],
    ["information_schema", "SELECT * FROM information_schema.columns", /sistem kataloğu/],
    ["regclass dönüşümü", "SELECT 'pg_shadow'::regclass", /reg\*/],
    ["EXPLAIN ANALYZE (read aracında EXPLAIN)", "EXPLAIN ANALYZE SELECT 1", /EXPLAIN|ANALYZE/],
    ["dolar-quote hilesi", "SELECT $$; DROP TABLE public.orders; --$$; DELETE FROM public.orders", /tek ifade/],
  ];

  it.each(BAD)("reddedilir: %s", async (_n, sql, why) => {
    const c = counting();
    const h = await makePgHarness({ driver: c.wrap });
    const r = await h.call("db.query.read", { sql });
    expect(r.status).toBe("denied");
    expect(r.reasonCode).toBe("target_unresolved");
    expect(r.summary).toMatch(why);
    expect(c.state.connects).toBe(0);
    // veri değişmedi
    const ok = await h.call("db.query.read", { sql: "SELECT count(*) AS n FROM public.orders" });
    expect(h.evidenceJson(ok).rows[0]).toEqual(["30"]);
  });

  it("explain aracı: ANALYZE ve DML reddedilir; düz SELECT planı döner", async () => {
    const c = counting();
    const h = await makePgHarness({ driver: c.wrap });
    for (const sql of ["EXPLAIN ANALYZE SELECT 1", "DELETE FROM public.orders", "SELECT 1; SELECT 2"]) {
      const r = await h.call("db.query.explain", { sql });
      expect(r.status, sql).toBe("denied");
    }
    expect(c.state.connects).toBe(0);
    const r = await h.call("db.query.explain", { sql: "SELECT * FROM public.orders WHERE id = 1" });
    expect(r.status).toBe("ok");
    const plan: string[] = h.evidenceJson(r).plan;
    expect(plan.join("\n")).toMatch(/orders/);
    expect(plan.join("\n")).not.toMatch(/actual time|Execution Time/i);
    // sorgu ÇALIŞMADI: tablo istatistiğinde okuma artışı yok (seq_scan/idx_scan sayaçları EXPLAIN'de artmaz)
  });
});

describe.skipIf(!pg)("S-03 (DB ayağı): katmanlar tek tek devre dışı bırakılır, kalanlar yine durdurur", () => {
  it("(2) AST yok + (3) yok, (4) rol yetkisi VAR: reader olarak doğrudan UPDATE → permission denied", async () => {
    const c = new pg_.Client({ host: pg!.host, port: pg!.port, user: ROLES.reader, password: canaries.readerPw.value, database: "shop", ssl: { ca: pg!.pki.caPem } });
    await c.connect();
    try {
      await expect(c.query("UPDATE public.orders SET status = 'hacked'")).rejects.toThrow(/permission denied/);
      await expect(c.query("INSERT INTO public.orders VALUES (1000, 1, 'x', 1, now())")).rejects.toThrow(/permission denied/);
      await expect(c.query("TRUNCATE public.orders")).rejects.toThrow(/permission denied/);
      await expect(c.query("CREATE TABLE public.t (a int)")).rejects.toThrow(/permission denied/);
      await expect(c.query("SELECT pg_read_file('/etc/passwd')")).rejects.toThrow(/permission denied/);
      await expect(c.query("SELECT * FROM secret.vault")).rejects.toThrow(/permission denied/);
    } finally {
      await c.end();
    }
  });

  it("(2) AST yok + (4) rol yetkisi YOK (yazma yetkili rol): sürücü yolundaki (3) READ ONLY işlem yine yazdırmaz", async () => {
    const h = await makePgHarness({ role: ROLES.writerLike });
    const d = await h.openSession();
    try {
      await expect(d.session.executeRead("UPDATE public.orders SET status = 'hacked' WHERE id = 1", d.limits)).rejects.toThrow(/read-only transaction/);
      await expect(d.session.executeRead("INSERT INTO public.orders VALUES (1001, 1, 'x', 1, now())", d.limits)).rejects.toThrow(/read-only transaction/);
      // oturum düzeyi korumayı SET ile kapatmak sonraki çağrıyı yazılabilir YAPMAZ: her sorgu açık BEGIN READ ONLY içinde
      await d.session.executeRead("SET default_transaction_read_only = off", d.limits);
      await expect(d.session.executeRead("UPDATE public.orders SET status = 'hacked' WHERE id = 1", d.limits)).rejects.toThrow(/read-only transaction/);
    } finally {
      await d.close();
    }
    // sunucuda yazma gerçekleşmedi
    expect(await pg!.admin("SELECT count(*) FROM public.orders WHERE status = 'hacked' OR id >= 1000", "shop")).toBe("0");
  });

  it("sunucu çoklu ifadeyi ayrıca reddeder (genişletilmiş protokol): AST atlansa bile tek ifade", async () => {
    const h = await makePgHarness();
    const d = await h.openSession();
    try {
      await expect(d.session.executeRead("SELECT 1; SELECT 2", d.limits)).rejects.toThrow(/multiple commands/);
      await expect(d.session.executeRead("SELECT 1; DROP TABLE public.orders", d.limits)).rejects.toThrow(/multiple commands/);
    } finally {
      await d.close();
    }
    expect(await pg!.admin("SELECT count(*) FROM public.orders", "shop")).toBe("30");
  });

  it("(1) reader profilde yazma yolu yok: okuma araçları read sınıfında; yazma aracı ayrı toolset'te ve reader'da reddedilir", async () => {
    const h = await makePgHarness();
    const reads = h.adapter.manifest.tools.filter((t) => t.toolset === "database");
    expect(reads.every((t) => t.class === "read")).toBe(true);
    expect(reads.map((t) => t.name).join()).not.toMatch(/apply|write|exec|change/);
    expect(h.adapter.manifest.tools.filter((t) => t.class !== "read").map((t) => t.name)).toEqual(["db.change.apply"]);
    const r = await h.call("db.change.apply", { sql: "DELETE FROM public.orders WHERE id = 1" });
    expect(r.status).toBe("denied");
    expect(await pg!.admin("SELECT count(*) FROM public.orders", "shop")).toBe("30");
  });
});

describe.skipIf(!pg)("kapsam ve katalog", () => {
  it("izinli şema dışı tablo: scope_violation; sistem kataloğu: sınıflayıcı reddi; ilişkisiz SELECT 1 serbest", async () => {
    const h = await makePgHarness();
    const r1 = await h.call("db.query.read", { sql: "SELECT * FROM secret.vault" });
    expect(r1).toMatchObject({ status: "denied", reasonCode: "scope_violation" });
    const r2 = await h.call("db.query.read", { sql: "SELECT 1 AS one" });
    expect(r2.status).toBe("ok");
    const r3 = await h.call("db.query.read", { sql: "SELECT o.id, i.amount FROM public.orders o JOIN sales.invoices i ON i.order_id = o.id" });
    expect(r3.status, JSON.stringify(r3)).toBe("ok");
    const sink = await h.sinkFor([r1, r2, r3]);
    expect(sink.leaks([canaries.vaultToken])).toEqual([]);
  });

  it("db.schema.describe: izinli şemalar, maskeli sütun işareti; dışarıdaki şema reddedilir", async () => {
    const h = await makePgHarness({ masking });
    const r = await h.call("db.schema.describe", {});
    expect(r.status).toBe("ok");
    const j = h.evidenceJson(r);
    const names = j.schemas.map((s: { name: string }) => s.name).sort();
    expect(names).toEqual(["public", "sales"]);
    const customers = j.schemas.find((s: { name: string }) => s.name === "public").tables.find((t: { name: string }) => t.name === "customers");
    expect(customers.columns).toContain("email:text [maskeli]");
    expect(customers.columns).toContain("id:integer");
    const r2 = await h.call("db.schema.describe", { schema: "secret" });
    expect(r2).toMatchObject({ status: "denied", reasonCode: "scope_violation" });
    const r3 = await h.call("db.schema.describe", { schema: "public", table: "orders" });
    expect(h.evidenceJson(r3).schemas[0].tables.map((t: { name: string }) => t.name)).toEqual(["orders"]);
    const r4 = await h.call("db.schema.describe", { schema: "Public; DROP" });
    expect(r4.status).toBe("denied");
  });
});

describe.skipIf(!pg)("M4: maskeli sütunlar (AST kuralı + köken + dedektörler)", () => {
  it("doğrudan seçim serbest; değer maskelenir (kayıt kuralı); takma ad köken ile yakalanır", async () => {
    const h = await makePgHarness({ masking });
    const r1 = await h.call("db.query.read", { sql: "SELECT id, email FROM public.customers ORDER BY id" });
    expect(r1.status, JSON.stringify(r1)).toBe("ok");
    const r2 = await h.call("db.query.read", { sql: "SELECT email AS contact, phone AS gsm FROM public.customers ORDER BY id" });
    expect(r2.status).toBe("ok");
    const sink = await h.sinkFor([r1, r2]);
    expect(sink.leaks([])).toEqual([]);
    const all = JSON.stringify([h.evidenceJson(r1), h.evidenceJson(r2)]);
    expect(all).not.toContain("ayse@example.invalid");
    expect(all).not.toContain("mehmet@example.invalid");
    expect(all).not.toContain("555 111 22 33");
    expect(all).toContain("redacted");
  });

  it.each([
    ["fonksiyon içinde", "SELECT lower(email) FROM public.customers"],
    ["WHERE içinde (varlık sızdırır)", "SELECT id FROM public.customers WHERE email = 'ayse@example.invalid'"],
    ["JOIN koşulunda", "SELECT o.id FROM public.orders o JOIN public.customers c ON c.email = 'a'"],
    ["ORDER BY içinde", "SELECT id FROM public.customers ORDER BY email"],
    ["alt sorgu içinde", "SELECT * FROM (SELECT email FROM public.customers) s"],
    ["SELECT *", "SELECT * FROM public.customers"],
    ["tablo.*", "SELECT c.* FROM public.customers c"],
    ["to_jsonb(satır)", "SELECT to_jsonb(c) FROM public.customers c"],
    ["row_to_json", "SELECT row_to_json(customers) FROM public.customers"],
    ["tam satır", "SELECT c FROM public.customers c"],
    ["birleştirme", "SELECT email || 'x' FROM public.customers"],
    ["CASE", "SELECT CASE WHEN phone IS NULL THEN 0 ELSE 1 END FROM public.customers"],
  ])("AST kuralı reddeder: %s", async (_n, sql) => {
    const c = counting();
    const h = await makePgHarness({ masking, driver: c.wrap });
    const r = await h.call("db.query.read", { sql });
    expect(r.status).toBe("denied");
    expect(r.summary).toMatch(/maskeli/);
    expect(c.state.connects).toBe(0);
  });

  it("kolon kuralı olmayan serbest metin hücresinde dedektörler (email/telefon) ve M3 (bilinen parola) çalışır", async () => {
    const h = await makePgHarness();
    const r = await h.call("db.query.read", { sql: "SELECT id, note FROM public.customers ORDER BY id" });
    expect(r.status).toBe("ok");
    const text = JSON.stringify(h.evidenceJson(r));
    expect(text).not.toContain("ayse@example.invalid");
    expect(text).not.toContain("555 111 22 33");
    expect(text).not.toContain(canaries.readerPw.value);
    const sink = await h.sinkFor([r]);
    expect(sink.leaks([canaries.readerPw])).toEqual([]);
  });
});

describe.skipIf(!pg)("limitler ve sürücü davranışı", () => {
  it("satır sınırı: varsayılan 100 ve maxRows; kesildi işareti", async () => {
    const h = await makePgHarness();
    const r = await h.call("db.query.read", { sql: "SELECT g FROM generate_series(1, 1000) AS g", maxRows: 7 });
    expect(r.status).toBe("ok");
    const j = h.evidenceJson(r);
    expect(j.rows.length).toBe(7);
    expect(j.truncated).toBe(true);
    expect(j.note).toMatch(/kesildi/);
    const r2 = await h.call("db.query.read", { sql: "SELECT g FROM generate_series(1, 1000) AS g" });
    expect(h.evidenceJson(r2).rows.length).toBe(100);
    const r3 = await h.call("db.query.read", { sql: "SELECT 1", maxRows: 501 });
    expect(r3).toMatchObject({ status: "denied", reasonCode: "schema_invalid" });
  });

  it("bayt sınırı: büyük hücreler satırı keser", async () => {
    const h = await makePgHarness();
    const d = await h.openSession({ maxRows: 100, maxBytes: 2_000, timeoutMs: 10_000 });
    try {
      const r = await d.session.executeRead("SELECT repeat('x', 500) AS big FROM generate_series(1, 50)", d.limits);
      expect(r.truncated).toBe(true);
      expect(r.rows.length).toBeLessThan(10);
    } finally {
      await d.close();
    }
  });

  it("sunucu tarafı zaman aşımı: statement_timeout sorguyu iptal eder", async () => {
    const h = await makePgHarness();
    const d = await h.openSession({ maxRows: 10, maxBytes: 10_000, timeoutMs: 400 });
    try {
      const t0 = Date.now();
      await expect(d.session.executeRead("SELECT count(*) FROM generate_series(1, 1000000000)", d.limits)).rejects.toThrow(/\[57014\]|statement timeout/);
      expect(Date.now() - t0).toBeLessThan(5_000);
      // bağlantı hata sonrası kullanılabilir
      const ok = await d.session.executeRead("SELECT 1 AS one", d.limits);
      expect(ok.rows).toEqual([[1]]);
    } finally {
      await d.close();
    }
  });

  it("sütun kökeni: doğrudan başvuru kökenli, hesaplanan sütun kökensiz", async () => {
    const h = await makePgHarness();
    const d = await h.openSession();
    try {
      const r = await d.session.executeRead("SELECT o.id, c.email AS contact, count(*) OVER () AS n FROM public.orders o JOIN public.customers c ON c.id = o.customer_id LIMIT 3", d.limits);
      expect(r.columns).toEqual([
        { name: "id", origin: { relation: "public.orders", column: "id" } },
        { name: "contact", origin: { relation: "public.customers", column: "email" } },
        { name: "n" },
      ]);
      // view sütunu view kökenli
      const v = await d.session.executeRead("SELECT status FROM public.orders_recent LIMIT 1", d.limits);
      expect(v.columns[0]?.origin).toEqual({ relation: "public.orders_recent", column: "status" });
    } finally {
      await d.close();
    }
  });

  it("değer türleri: bool/int/float sayı, bigint/numeric/timestamp metin (kayıpsız)", async () => {
    const h = await makePgHarness();
    const d = await h.openSession();
    try {
      const r = await d.session.executeRead("SELECT true AS b, 7::int AS i, 1.5::float8 AS f, 9007199254740993::bigint AS big, 12.50::numeric(10,2) AS num, null AS nul", d.limits);
      expect(r.rows[0]).toEqual([true, 7, 1.5, "9007199254740993", "12.50", null]);
    } finally {
      await d.close();
    }
  });

  it("db.stats.summary: sayılar döner; uzun çalışan KENDİ sorgumuzun metni normalleştirilir (değişmez yok)", async () => {
    const h = await makePgHarness();
    // aynı rolle ikinci bağlantıda uzun sorgu başlat
    const bg = new pg_.Client({ host: pg!.host, port: pg!.port, user: ROLES.reader, password: canaries.readerPw.value, database: "shop", ssl: { ca: pg!.pki.caPem } });
    await bg.connect();
    const lit = makeCanary("literal");
    const running = bg.query(`SELECT pg_sleep(7), '${lit.value.replace(/'/g, "''")}' AS lit`).catch(() => undefined);
    await new Promise((r) => setTimeout(r, 6_200));
    try {
      const r = await h.call("db.stats.summary", {});
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.evidenceJson(r);
      expect(typeof j.databaseSizeBytes).toBe("number");
      expect(j.connections).toBeTypeOf("object");
      expect(j.longQueries.length).toBeGreaterThanOrEqual(1);
      const q = j.longQueries[0].query as string;
      expect(q).toMatch(/pg_sleep\(\$1\)/);
      const sink = await h.sinkFor([r]);
      expect(sink.leaks([lit])).toEqual([]);
    } finally {
      await running;
      await bg.end();
    }
  }, 30_000);
});

describe.skipIf(!pg)("bağlantı güvenliği: pin, TLS, ortam değişkenleri, parola", () => {
  it("kasadaki sunucu pinli uç noktayla uyuşmuyorsa kimlik GÖNDERİLMEDEN reddedilir", async () => {
    const h = await makePgHarness({ vaultPort: pg!.port + 1 });
    const r = await h.call("db.query.read", { sql: "SELECT 1" });
    expect(r.status).toBe("error");
    expect(r.summary).toMatch(/pinli uç noktasıyla eşleşmiyor/);
    // sunucu hiç parola denemesi görmedi
    const log = await pg!.admin("SELECT count(*) FROM pg_stat_activity WHERE usename = 'ops_reader'", "shop");
    expect(log).toBe("0");
    const d = await h.doctor();
    expect(d).toMatchObject({ pinOk: false, bindable: false });
  });

  it("CA pini: kasadaki CA'nın parmak izi pine uymuyorsa reddedilir; pin yokken yanlış CA TLS doğrulamasında düşer", async () => {
    const h1 = await makePgHarness({ vaultCaPem: pg!.pki.clientCertPem });
    const r1 = await h1.call("db.query.read", { sql: "SELECT 1" });
    expect(r1.status).toBe("error");
    expect(r1.summary).toMatch(/CA parmak izi/);
    const h2 = await makePgHarness({ vaultCaPem: pg!.pki.clientCertPem, noCaPin: true });
    const r2 = await h2.call("db.query.read", { sql: "SELECT 1" });
    expect(r2.status).toBe("error");
    expect(r2.summary).toMatch(/bağlanılamadı/);
  });

  it("TLS'siz bağlantı sunucuca reddedilir (pg_hba hostnossl reject); istemci TLS'yi düşüremez", async () => {
    const h = await makePgHarness({ tlsMode: "disable" });
    const r = await h.call("db.query.read", { sql: "SELECT 1" });
    expect(r.status).toBe("error");
    expect(r.summary).toMatch(/bağlanılamadı/);
  });

  it("ortam değişkenleri bağlantıyı değiştiremez (PGOPTIONS, PGREPLICATION, PGSSLMODE, PGPASSWORD, PGDATABASE, PGUSER...)", async () => {
    const saved: Record<string, string | undefined> = {};
    const poison = {
      PGOPTIONS: "-c default_transaction_read_only=off -c search_path=secret",
      PGREPLICATION: "database",
      PGSSLMODE: "disable",
      PGPASSWORD: "wrong-password",
      PGDATABASE: "postgres",
      PGUSER: "postgres",
      PGHOST: "/tmp",
      PGPORT: "1",
      PGAPPNAME: "evil",
      PGSSLNEGOTIATION: "direct",
      PGPASSFILE: "/nonexistent",
      PGSERVICE: "evil",
    };
    for (const [k, v] of Object.entries(poison)) {
      saved[k] = process.env[k];
      process.env[k] = v;
    }
    try {
      const h = await makePgHarness();
      const r = await h.call("db.query.read", { sql: "SELECT current_database() AS db, current_user AS usr, current_setting('transaction_read_only') AS ro" });
      // current_database()/current_user/current_setting izinli değil → fonksiyonlar listesinde yok; bu yüzden doğrudan sürücüyle sınanır
      expect(r.status).toBe("denied");
      const d = await h.openSession();
      try {
        const res = await d.session.executeRead("SELECT 1 AS one", d.limits);
        expect(res.rows).toEqual([[1]]);
        const facts = await d.session.privilegeFacts(["public"]);
        expect(facts.role.name).toBe("ops_reader");
        expect(facts.database).toBe("shop");
        expect(facts.transactionReadOnly).toBe(true);
        expect(facts.tls).toBe(true);
        expect(facts.role.replication).toBe(false);
      } finally {
        await d.close();
      }
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it("yanlış parola: hata mesajı/denetim/kanıtta parola YOK; sunucu kimlik doğrulama hatası kısa kodla döner", async () => {
    const wrong = makeCanary("wrong-pw");
    const h = await makePgHarness({ password: wrong.value });
    const r = await h.call("db.query.read", { sql: "SELECT 1" });
    expect(r.status).toBe("error");
    expect(r.summary).toMatch(/28P01|password authentication failed/);
    const sink = await h.sinkFor([r]);
    expect(sink.leaks([wrong, canaries.readerPw])).toEqual([]);
  });

  it("canary taraması: parola; çağrı dizisi (başarı + sözdizimi hatası + izin hatası + red) boyunca hiçbir kanalda görünmez", async () => {
    const h = await makePgHarness({ masking });
    const results = [
      await h.call("db.datasource.describe", {}),
      await h.call("db.schema.describe", {}),
      await h.call("db.query.read", { sql: "SELECT id, note FROM public.customers" }),
      await h.call("db.query.read", { sql: "SELEKT 1" }),
      await h.call("db.query.read", { sql: "SELECT * FROM public.nonexistent_table" }),
      await h.call("db.query.read", { sql: "SELECT * FROM secret.vault" }),
      await h.call("db.query.read", { sql: "SELECT 1 / 0" }),
    ];
    expect(results.map((r) => r.status)).toEqual(["ok", "ok", "ok", "denied", "error", "denied", "error"]);
    const sink = await h.sinkFor(results);
    expect(sink.leaks([canaries.readerPw, canaries.vaultToken])).toEqual([]);
    // hata mesajları kısa SQLSTATE'li
    expect(results[4]?.summary).toMatch(/\[42P01\]/);
    expect(results[6]?.summary).toMatch(/\[22012\]/);
  });
});

afterAll(async () => {
  await pg?.stop();
});
