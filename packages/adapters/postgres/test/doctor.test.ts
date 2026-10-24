import { afterAll, describe, expect, it } from "vitest";
import { OpsError } from "@ops/contracts";
import { makeTestProfile } from "@ops/testkit";
import { diagnose } from "../src/index.ts";
import type { PrivilegeFacts } from "../src/index.ts";
import { ROLES, makePgHarness, pg } from "./harness.ts";

const codes = (r: { findings: { code: string }[] }): string[] => r.findings.map((f) => f.code);
const errorsOf = (r: { findings: { severity: string; code: string }[] }): string[] => r.findings.filter((f) => f.severity === "error").map((f) => f.code);

const CLEAN: PrivilegeFacts = {
  role: { name: "r", superuser: false, createRole: false, createDb: false, replication: false, bypassRls: false },
  dangerousRoles: [],
  broadReadRoles: [],
  databaseCreate: false,
  databaseTemp: false,
  schemaCreate: [],
  writableRelations: [],
  writableRelationCount: 0,
  writableSequences: [],
  dangerousFunctions: [],
  readableOutsideScopes: [],
  missingScopes: [],
  transactionReadOnly: true,
  tls: true,
  serverVersion: "16.0",
  database: "shop",
};
const profile = makeTestProfile({ id: "p", kind: "db", targetPin: { endpoint: "db.invalid:5432" }, allowedScopes: ["public"], attributes: { role: "reader", datasource: "shop", defaultSchema: "public" } });
const run = (facts: PrivilegeFacts, loopback = false) => diagnose(profile, { inspect: async () => ({ identity: "r@shop", facts, loopback }) });

describe("diagnose (saf mantık)", () => {
  it("temiz reader: bağlanabilir, effective read", async () => {
    const r = await run(CLEAN);
    expect(r).toMatchObject({ connected: true, pinOk: true, bindable: true, effectiveClass: "read", identity: "r@shop", scopesChecked: ["public"] });
    expect(errorsOf(r)).toEqual([]);
  });

  it.each<[string, Partial<PrivilegeFacts>, string, string]>([
    ["süper kullanıcı", { role: { ...CLEAN.role, superuser: true } }, "superuser", "destroy"],
    ["createrole", { role: { ...CLEAN.role, createRole: true } }, "createrole", "deploy"],
    ["createdb", { role: { ...CLEAN.role, createDb: true } }, "createdb", "deploy"],
    ["replication", { role: { ...CLEAN.role, replication: true } }, "replication", "destroy"],
    ["bypassrls", { role: { ...CLEAN.role, bypassRls: true } }, "bypassrls", "destroy"],
    ["tehlikeli rol", { dangerousRoles: ["pg_write_server_files"] }, "dangerous_role", "mutate"],
    ["db CREATE", { databaseCreate: true }, "database_create", "deploy"],
    ["şema CREATE", { schemaCreate: ["public"] }, "schema_create", "deploy"],
    ["yazma yetkisi", { writableRelations: ["public.orders"], writableRelationCount: 1 }, "write_privilege", "mutate"],
    ["tehlikeli fonksiyon", { dangerousFunctions: ["pg_read_file(text)"] }, "dangerous_function", "destroy"],
    ["salt-okunur koruma başarısız", { transactionReadOnly: false }, "read_only_guard_failed", "read"],
    ["TLS yok (uzak)", { tls: false }, "no_tls", "read"],
  ])("hata → bağlanamaz: %s", async (_n, over, code, effective) => {
    const r = await run({ ...CLEAN, ...over });
    expect(errorsOf(r)).toContain(code);
    expect(r.bindable).toBe(false);
    expect(r.effectiveClass).toBe(effective);
  });

  it("uyarılar bağlanmayı engellemez; TLS yok + loopback yalnız bilgi", async () => {
    const r = await run({ ...CLEAN, broadReadRoles: ["pg_read_all_data"], databaseTemp: true, writableSequences: ["public.s"], readableOutsideScopes: [{ schema: "secret", tables: 2 }], missingScopes: ["ghost"], tls: false }, true);
    expect(r.bindable).toBe(true);
    expect(codes(r)).toEqual(expect.arrayContaining(["reads_all_data", "temp_privilege", "sequence_privilege", "readable_outside_scopes", "scope_missing", "no_tls_loopback"]));
  });

  it("pin uyuşmazlığı ve bağlantı hatası", async () => {
    const pin = await diagnose(profile, { inspect: () => Promise.reject(new OpsError("target_pin_mismatch", "adres pine uymuyor")) });
    expect(pin).toMatchObject({ pinOk: false, connected: false, bindable: false });
    expect(codes(pin)).toEqual(["pin_mismatch"]);
    const conn = await diagnose(profile, { inspect: () => Promise.reject(new Error("ECONNREFUSED")) });
    expect(conn).toMatchObject({ connected: false, bindable: false });
    expect(codes(conn)).toEqual(["connect_failed"]);
  });

  it("beyan edilen tavan fiili yetkiden düşükse ceiling_exceeded_by_grants", async () => {
    const r = await run({ ...CLEAN, writableRelations: ["public.t"], writableRelationCount: 1 });
    expect(codes(r)).toContain("ceiling_exceeded_by_grants");
  });
});

describe.skipIf(!pg)("S-14 (DB ayağı): gerçek rollerle fiili yetki ↔ beyan", () => {
  it("reader: temiz; bağlanabilir; kimlik yankısı rol@veritabanı; effective read", async () => {
    const h = await makePgHarness();
    const r = await h.doctor();
    expect(errorsOf(r), JSON.stringify(r.findings)).toEqual([]);
    expect(r).toMatchObject({ connected: true, pinOk: true, bindable: true, effectiveClass: "read", identity: "ops_reader@shop" });
    expect(r.scopesChecked).toEqual(["public", "sales"]);
  });

  it("yazma yetkili rol: write_privilege + ceiling_exceeded → bağlanmaz (effective mutate)", async () => {
    const r = await (await makePgHarness({ role: ROLES.writerLike })).doctor();
    expect(errorsOf(r)).toEqual(expect.arrayContaining(["write_privilege", "ceiling_exceeded_by_grants"]));
    expect(r).toMatchObject({ bindable: false, effectiveClass: "mutate" });
    expect(r.findings.find((f) => f.code === "write_privilege")?.message).toContain("public.orders");
  });

  it("şemada CREATE yetkili rol: schema_create → deploy", async () => {
    const r = await (await makePgHarness({ role: ROLES.creator })).doctor();
    expect(errorsOf(r)).toContain("schema_create");
    expect(r).toMatchObject({ bindable: false, effectiveClass: "destroy".replace("destroy", "deploy") });
  });

  it("süper kullanıcı: superuser + dangerous_function (pg_read_file...) → destroy", async () => {
    const r = await (await makePgHarness({ role: ROLES.superuser })).doctor();
    expect(errorsOf(r)).toEqual(expect.arrayContaining(["superuser", "dangerous_function"]));
    expect(r).toMatchObject({ bindable: false, effectiveClass: "destroy" });
  });

  it("pg_read_server_files üyesi: dangerous_role", async () => {
    const r = await (await makePgHarness({ role: ROLES.fileReader })).doctor();
    expect(errorsOf(r)).toContain("dangerous_role");
    expect(r.bindable).toBe(false);
  });

  it("BYPASSRLS: bypassrls hatası", async () => {
    const r = await (await makePgHarness({ role: ROLES.bypass })).doctor();
    expect(errorsOf(r)).toContain("bypassrls");
  });

  it("izinli şemalar dışında okuma yetkisi: uyarı (bağlanır); olmayan şema: scope_missing", async () => {
    const r = await (await makePgHarness({ role: ROLES.outsideReader, profile: { allowedScopes: ["public", "ghost"] } })).doctor();
    expect(errorsOf(r), JSON.stringify(r.findings)).toEqual([]);
    expect(r.bindable).toBe(true);
    expect(codes(r)).toEqual(expect.arrayContaining(["readable_outside_scopes", "scope_missing"]));
    expect(r.findings.filter((f) => f.code === "readable_outside_scopes").map((f) => f.message).join()).toMatch(/secret/);
  });

  it("yetki kayması: reader'a sonradan INSERT verilince doktor yakalar (S-14)", async () => {
    const h = await makePgHarness();
    expect((await h.doctor()).bindable).toBe(true);
    await pg!.admin(`GRANT INSERT ON public.customers TO ${ROLES.reader}`, "shop");
    try {
      const after = await h.doctor();
      expect(after.bindable).toBe(false);
      expect(errorsOf(after)).toContain("write_privilege");
    } finally {
      await pg!.admin(`REVOKE INSERT ON public.customers FROM ${ROLES.reader}`, "shop");
    }
    expect((await h.doctor()).bindable).toBe(true);
  });

  it("doktor raporu parola/bağlantı bilgisi içermez", async () => {
    const h = await makePgHarness({ role: ROLES.writerLike });
    const r = await h.doctor();
    const text = JSON.stringify(r);
    expect(text).not.toContain("127.0.0.1");
    const { canaries } = await import("./harness.ts");
    expect(text).not.toContain(canaries.otherPw.value);
    expect(text).not.toContain(canaries.readerPw.value);
  });
});

afterAll(async () => {
  await pg?.stop();
});
