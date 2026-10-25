import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CaptureSink, generateTestPki, makeCanary } from "@ops/testkit";
import {
  LocalBroker,
  MemorySecretStore,
  ProfileRegistry,
  ProfileService,
  buildDbCredential,
  credentialKey,
  dbEndpoint,
} from "../src/index.ts";

const base = { host: "db.internal.invalid", database: "orders", user: "ops_reader", password: "x".repeat(12) };

describe("buildDbCredential", () => {
  it("geçerli alanlar: endpoint host:port, CA pini, varsayılan verify-full", async () => {
    const pki = await generateTestPki();
    const r = buildDbCredential({ ...base, port: 6432, caPem: pki.caPem });
    expect(r.endpoint).toBe("db.internal.invalid:6432");
    expect(r.caFingerprint).toBe(pki.caFingerprint);
    expect(r.blob.tls.mode).toBe("verify-full");
    expect(buildDbCredential(base).warnings.join()).toMatch(/CA pini yok/);
    expect(dbEndpoint("::1", 5432)).toBe("[::1]:5432");
  });

  it.each([
    ["host: şema", { host: "postgres://u:p@h/db" }, /host geçersiz/],
    ["host: yol", { host: "/var/run/postgresql" }, /host geçersiz/],
    ["host: kullanıcı bilgisi", { host: "user@host" }, /host geçersiz/],
    ["host: boşluk", { host: "a b" }, /host geçersiz/],
    ["port: 0", { port: 0 }, /port/],
    ["port: 70000", { port: 70000 }, /port/],
    ["port: ondalık", { port: 5432.5 }, /port/],
    ["veritabanı: boş", { database: "" }, /veritabanı/],
    ["veritabanı: kontrol karakteri", { database: "a\nb" }, /veritabanı/],
    ["kullanıcı: 64 karakter", { user: "u".repeat(64) }, /kullanıcı/],
    ["parola: boş", { password: "" }, /parola/],
    ["parola: NUL", { password: "a\0b" }, /parola/],
  ])("reddedilir: %s", (_n, over, why) => {
    expect(() => buildDbCredential({ ...base, ...(over as object) })).toThrow(why as RegExp);
  });

  it("TLS yalnız loopback için kapatılabilir; CA ile birlikte kapatılamaz; geçersiz CA reddedilir", () => {
    expect(() => buildDbCredential({ ...base, tlsMode: "disable" })).toThrow(/TLS yalnız loopback/);
    expect(buildDbCredential({ ...base, host: "127.0.0.1", tlsMode: "disable" }).blob.tls.mode).toBe("disable");
    expect(buildDbCredential({ ...base, host: "localhost", tlsMode: "disable" }).warnings.join()).toMatch(/TLS kapalı/);
    expect(() => buildDbCredential({ ...base, host: "127.0.0.1", tlsMode: "disable", caPem: "x" })).toThrow(/CA verilemez/);
    expect(() => buildDbCredential({ ...base, caPem: "not a pem" })).toThrow(/sertifika yok/);
  });

  it("hata iletileri parolayı içermez", () => {
    const pw = makeCanary("dbpw");
    for (const over of [{ host: "bad host" }, { port: 0 }, { database: "" }, { caPem: "zzz" }]) {
      try {
        buildDbCredential({ ...base, password: pw.value, ...over });
      } catch (e) {
        expect(String((e as Error).message)).not.toContain(pw.value);
      }
    }
  });
});

describe("ProfileService.addDatabase + LocalBroker", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-dbsvc-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("parola yalnız kasada; profil/uyarı/kayıt dosyası canary içermez; lease malzemeyi çözer ve bırakınca düşer", async () => {
    const store = new MemorySecretStore();
    const registry = await ProfileRegistry.open({ path: join(dir, "profiles.json"), testMode: false });
    const svc = new ProfileService({ store, registry });
    const pki = await generateTestPki();
    const pw = makeCanary("dbpw");
    const r = await svc.addDatabase({
      id: "orders-stage",
      environment: "stage",
      host: "db.internal.invalid",
      database: "orders",
      user: "ops_reader",
      password: pw.value,
      caPem: pki.caPem,
      allowedScopes: ["public", "sales"],
    });
    expect(r.profile).toMatchObject({
      kind: "db",
      classCeiling: "read",
      allowedScopes: ["public", "sales"],
      targetPin: { endpoint: "db.internal.invalid:5432", caFingerprint: pki.caFingerprint },
      attributes: { role: "reader", datasource: "orders", defaultSchema: "public" },
      egressClass: "tenant-cloud",
    });
    expect(Buffer.from((await store.get(credentialKey("orders-stage")))!).toString()).toContain(pw.value);

    const sink = new CaptureSink();
    sink.push("result", JSON.stringify(r));
    sink.push("registry", JSON.stringify(registry.list()));
    sink.push("file", await readFile(join(dir, "profiles.json"), "utf8"));
    expect(sink.leaks([pw])).toEqual([]);

    const broker = new LocalBroker({ store });
    const added: string[] = [];
    const secretSink = { add: (_name: string, v: string): boolean => (added.push(v), true) };
    await broker.prime(r.profile, secretSink);
    expect(added).toContain(pw.value);
    const lease = await broker.acquire({ profile: r.profile, purpose: "test", callId: "c1", ttlSec: 30 }, secretSink);
    const cred = broker.resolver.db(lease.handle);
    expect(cred).toMatchObject({ host: "db.internal.invalid", port: 5432, database: "orders", user: "ops_reader", password: pw.value });
    expect(() => broker.resolver.k8s(lease.handle)).toThrow(/k8s kimliği taşımıyor/);
    await lease.release();
    expect(() => broker.resolver.db(lease.handle)).toThrow(/geçersiz|süresi/);
  });

  it("prod varsayılan egress 'local'; geçersiz şema reddedilir; kopya profil engellenir; read-üstü tavan = writer rolü + uyarı", async () => {
    const store = new MemorySecretStore();
    const registry = await ProfileRegistry.open({ path: join(dir, "p.json"), testMode: false });
    const svc = new ProfileService({ store, registry });
    const req = { id: "orders-prod", environment: "prod" as const, ...base, allowedScopes: ["public"] };
    expect((await svc.addDatabase(req)).profile.egressClass).toBe("local");
    await expect(svc.addDatabase(req)).rejects.toThrow(/zaten var/);
    const w = await svc.addDatabase({ ...req, id: "w", classCeiling: "mutate" });
    expect(w.profile).toMatchObject({ classCeiling: "mutate", attributes: { role: "writer" } });
    expect(w.warnings.join()).toMatch(/yazıcı profili.*AYRI.*kullanıcı/s);
    expect(w.warnings.join()).not.toContain(base.password);
    expect((await svc.addDatabase({ ...req, id: "r1" })).profile.attributes["role"]).toBe("reader");
    expect((await svc.addDatabase({ ...req, id: "d1", classCeiling: "destroy" })).profile).toMatchObject({ classCeiling: "destroy", attributes: { role: "writer" } });
    await expect(svc.addDatabase({ ...req, id: "s1", allowedScopes: ["Bad-Schema"] })).rejects.toThrow(/şema adı geçersiz/);
    await expect(svc.addDatabase({ ...req, id: "s2", allowedScopes: [] })).rejects.toThrow(/izinli şema/);
    await expect(svc.addDatabase({ ...req, id: "s3", allowedScopes: ["a"], defaultSchema: "b" })).rejects.toThrow(/izinli şemalar arasında/);
    expect((await svc.addDatabase({ ...req, id: "s4", allowedScopes: ["*"] })).warnings.join()).toMatch(/tüm şemalar/);
    // kayıt hatasında kasa geri alınır
    await expect(svc.addDatabase({ ...req, id: "BAD ID" })).rejects.toThrow();
    expect(await store.get(credentialKey("BAD ID"))).toBeNull();
  });
});
