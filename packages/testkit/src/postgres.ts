import { execFile, spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { chmod, chown, mkdtemp, rm, writeFile, appendFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { generateTestPki } from "./pki.ts";
import type { TestPki } from "./pki.ts";

const run = promisify(execFile);

export interface TestPostgres {
  readonly host: "127.0.0.1";
  readonly port: number;
  /** Sunucu sertifikasını imzalayan test CA'sı (depoda yok, çalışma anında üretilir). */
  readonly pki: TestPki;
  readonly version: string;
  /** Süper kullanıcı olarak (unix soketi, trust) SQL çalıştırır; stdout döner. */
  admin(sql: string, database?: string): Promise<string>;
  stop(): Promise<void>;
}

function findBinDir(): string | null {
  const env = process.env["OPS_TEST_PG_BIN"];
  if (env && existsSync(join(env, "pg_ctl"))) return env;
  try {
    const versions = readdirSync("/usr/lib/postgresql")
      .filter((v) => /^\d+$/.test(v))
      .sort((a, b) => Number(b) - Number(a));
    for (const v of versions) {
      const d = join("/usr/lib/postgresql", v, "bin");
      if (existsSync(join(d, "pg_ctl")) && existsSync(join(d, "initdb")) && existsSync(join(d, "postgres"))) return d;
    }
  } catch {
    /* yok */
  }
  const w = spawnSync("which", ["pg_ctl"], { encoding: "utf8" });
  return w.status === 0 && w.stdout.trim() ? w.stdout.trim().replace(/\/pg_ctl$/, "") : null;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

/**
 * Gerçek bir PostgreSQL sunucusunu geçici bir dizinde başlatır (TLS zorunlu, scram-sha-256).
 * PostgreSQL ikilileri yoksa `null` döner (testler uyarıyla atlanır). Kök olarak çalışırken sunucu
 * `postgres` kullanıcısıyla başlatılır (initdb kök kabul etmez).
 */
export async function startTestPostgres(): Promise<TestPostgres | null> {
  const bin = findBinDir();
  if (!bin) return null;
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  let uid: number | undefined;
  let gid: number | undefined;
  if (isRoot) {
    const id = spawnSync("id", ["postgres"], { encoding: "utf8" });
    const m = /uid=(\d+).*gid=(\d+)/.exec(id.stdout ?? "");
    if (id.status !== 0 || !m) return null;
    uid = Number(m[1]);
    gid = Number(m[2]);
  }
  const asPg = (cmd: string, args: string[]): [string, string[]] => (isRoot ? ["runuser", ["-u", "postgres", "--", cmd, ...args]] : [cmd, args]);

  const dir = await mkdtemp(join(tmpdir(), "ops-pg-"));
  const data = join(dir, "data");
  let started = false;
  const cleanup = async (): Promise<void> => {
    if (started) {
      const [c, a] = asPg(join(bin, "pg_ctl"), ["-D", data, "-m", "immediate", "-w", "stop"]);
      await run(c, a).catch(() => undefined);
    }
    await rm(dir, { recursive: true, force: true });
  };
  try {
    if (isRoot) {
      await chown(dir, uid as number, gid as number);
      await chmod(dir, 0o700);
    }
    const pki = await generateTestPki();
    const certFile = join(dir, "server.crt");
    const keyFile = join(dir, "server.key");
    await writeFile(certFile, pki.serverCertPem, { mode: 0o600 });
    await writeFile(keyFile, pki.serverKeyPem, { mode: 0o600 });
    if (isRoot) {
      await chown(certFile, uid as number, gid as number);
      await chown(keyFile, uid as number, gid as number);
    }
    const [ic, ia] = asPg(join(bin, "initdb"), ["-D", data, "-A", "trust", "-U", "postgres", "-E", "UTF8", "--no-locale"]);
    await run(ic, ia);
    const port = await freePort();
    await appendFile(
      join(data, "postgresql.conf"),
      [
        "listen_addresses = '127.0.0.1'",
        `port = ${port}`,
        `unix_socket_directories = '${dir}'`,
        "ssl = on",
        `ssl_cert_file = '${certFile}'`,
        `ssl_key_file = '${keyFile}'`,
        "password_encryption = scram-sha-256",
        "fsync = off",
        "synchronous_commit = off",
        "full_page_writes = off",
        "shared_buffers = 16MB",
        "max_connections = 40",
        "log_min_messages = warning",
        "",
      ].join("\n"),
    );
    // TLS'siz TCP reddedilir; yerel yönetim soketi yalnız süper kullanıcı (trust).
    await writeFile(
      join(data, "pg_hba.conf"),
      ["local all postgres trust", "hostnossl all all 127.0.0.1/32 reject", "hostssl all all 127.0.0.1/32 scram-sha-256", ""].join("\n"),
    );
    const [sc, sa] = asPg(join(bin, "pg_ctl"), ["-D", data, "-l", join(dir, "server.log"), "-w", "-t", "30", "start"]);
    await run(sc, sa);
    started = true;

    const admin = async (sql: string, database = "postgres"): Promise<string> => {
      const { stdout } = await run(join(bin, "psql"), ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-h", dir, "-p", String(port), "-U", "postgres", "-d", database, "-c", sql], {
        env: { PATH: process.env["PATH"] ?? "" },
      });
      return stdout.trim();
    };
    const version = await admin("SHOW server_version");
    return {
      host: "127.0.0.1",
      port,
      pki,
      version,
      admin,
      stop: cleanup,
    };
  } catch (e) {
    await cleanup();
    throw e;
  }
}

export const SHOP_ROLES = {
  reader: "ops_reader",
  writerLike: "ops_writer_like",
  creator: "ops_creator",
  superuser: "ops_super",
  fileReader: "ops_filereader",
  bypass: "ops_bypass",
  outsideReader: "ops_outside_reader",
} as const;

const sqlLit = (s: string): string => `'${s.replace(/'/g, "''")}'`;

export interface ShopSeed {
  /** `ops_reader` parolası; ayrıca bir müşteri notu hücresinin içinde de yer alır (M3 sınaması). */
  readonly readerPassword: string;
  /** Diğer rollerin parolası. */
  readonly otherPassword: string;
  /** İzinli şemalar DIŞINDaki `secret.vault` tablosundaki değer. */
  readonly vaultToken: string;
}

/**
 * Test veritabanı `shop`: public (customers, orders, orders_recent), sales (invoices), secret (vault) şemaları
 * ve doktor testleri için farklı yetkilere sahip roller. `ops_reader` yalnız public+sales SELECT yetkilidir.
 */
export async function seedShop(pg: TestPostgres, seed: ShopSeed): Promise<void> {
  await pg.admin("CREATE DATABASE shop");
  await pg.admin("REVOKE ALL ON DATABASE shop FROM PUBLIC");
  const R = SHOP_ROLES;
  for (const [name, extra] of [
    [R.reader, ""],
    [R.writerLike, ""],
    [R.creator, ""],
    [R.superuser, "SUPERUSER"],
    [R.fileReader, ""],
    [R.bypass, "BYPASSRLS"],
    [R.outsideReader, ""],
  ] as const) {
    await pg.admin(`CREATE ROLE ${name} LOGIN ${extra} PASSWORD ${sqlLit(name === R.reader ? seed.readerPassword : seed.otherPassword)}`);
    await pg.admin(`GRANT CONNECT ON DATABASE shop TO ${name}`);
  }
  await pg.admin(
    [
      "CREATE SCHEMA sales",
      "CREATE SCHEMA secret",
      "CREATE TABLE public.customers (id int PRIMARY KEY, name text NOT NULL, email text, phone text, note text)",
      "CREATE TABLE public.orders (id int PRIMARY KEY, customer_id int REFERENCES public.customers(id), status text NOT NULL, total numeric(10,2) NOT NULL, created_at timestamptz NOT NULL DEFAULT now())",
      "CREATE TABLE sales.invoices (id int PRIMARY KEY, order_id int, amount numeric(10,2))",
      "CREATE TABLE secret.vault (id int PRIMARY KEY, token text)",
      "INSERT INTO public.customers VALUES (1,'Ayse','ayse@example.invalid','+90 555 111 22 33','call +90 555 111 22 33 or ayse@example.invalid'),(2,'Mehmet','mehmet@example.invalid','+90 555 222 33 44'," +
        sqlLit(`legacy pw=${seed.readerPassword}`) + ")",
      "INSERT INTO public.orders SELECT g, 1 + (g % 2), CASE WHEN g % 3 = 0 THEN 'failed' ELSE 'paid' END, g * 10.5, now() - (g || ' minutes')::interval FROM generate_series(1, 30) g",
      "INSERT INTO sales.invoices VALUES (1, 1, 10.50)",
      "INSERT INTO secret.vault VALUES (1, " + sqlLit(seed.vaultToken) + ")",
      "CREATE VIEW public.orders_recent AS SELECT id, status, total FROM public.orders WHERE created_at > now() - interval '1 hour'",
      `GRANT USAGE ON SCHEMA public, sales TO ${R.reader}`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${R.reader}`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA sales TO ${R.reader}`,
      `GRANT USAGE ON SCHEMA public TO ${R.writerLike}, ${R.creator}, ${R.superuser}, ${R.fileReader}, ${R.bypass}, ${R.outsideReader}`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${R.writerLike}, ${R.creator}, ${R.fileReader}, ${R.bypass}, ${R.outsideReader}`,
      `GRANT INSERT, UPDATE ON public.orders TO ${R.writerLike}`,
      `GRANT CREATE ON SCHEMA public TO ${R.creator}`,
      `GRANT pg_read_server_files TO ${R.fileReader}`,
      `GRANT USAGE ON SCHEMA sales, secret TO ${R.outsideReader}`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA sales TO ${R.outsideReader}`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA secret TO ${R.outsideReader}`,
    ].join(";\n"),
    "shop",
  );
}
