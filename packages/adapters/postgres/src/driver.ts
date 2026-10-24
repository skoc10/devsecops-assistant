import pg from "pg";
import Cursor from "pg-cursor";
import { OpsError, normalizeEndpoint } from "@ops/contracts";
import type {
  ColumnInfo,
  CredentialHandle,
  DatabaseDriver,
  DbCapabilities,
  DbConnectOptions,
  DbRole,
  DbSession,
  ReadLimits,
  ReadResult,
  SchemaDescription,
  SqlClassification,
} from "@ops/contracts";
import { caFingerprintOf, dbEndpoint, isLoopbackHost } from "@ops/broker";
import type { CredentialResolver } from "@ops/broker";
import { classifySql, normalizeSqlForDisplay } from "@ops/classifiers";
import { dbError } from "./errors.ts";
import type { PgStats, PrivilegeFacts } from "./facts.ts";
import { quoteIdent } from "./identifiers.ts";

/** Tüm hücreler metin biçiminde gelir; yalnız güvenli sayısal/bool türleri JS değerine çevrilir. */
const PARSERS: Readonly<Record<number, (v: string) => unknown>> = {
  16: (v) => v === "t", // bool
  21: (v) => Number.parseInt(v, 10), // int2
  23: (v) => Number.parseInt(v, 10), // int4
  700: (v) => Number.parseFloat(v), // float4
  701: (v) => Number.parseFloat(v), // float8
};
const identity = (v: string): string => v;
const TYPES = { getTypeParser: (oid: number) => PARSERS[oid] ?? identity } as unknown as pg.CustomTypesConfig;

const DANGEROUS_ROLES = ["pg_write_server_files", "pg_read_server_files", "pg_execute_server_program", "pg_write_all_data", "pg_signal_backend", "pg_checkpoint", "pg_maintain"];
const BROAD_READ_ROLES = ["pg_read_all_data"];
const DANGEROUS_FUNCTIONS = [
  "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "pg_ls_logdir", "pg_ls_waldir", "pg_ls_tmpdir",
  "lo_import", "lo_export", "pg_reload_conf", "pg_rotate_logfile", "pg_promote", "pg_switch_wal", "pg_create_restore_point",
  "pg_file_write", "dblink", "dblink_exec", "dblink_connect", "dblink_connect_u",
];
// Not: varsayılan olarak PUBLIC'e açık olanlar (pg_sleep, set_config, nextval, pg_logical_emit_message, pg_cancel_backend...)
// listede YOK; doktorun amacı varsayılanın ÖTESİNDE verilmiş yetkileri yakalamaktır. Bunları AST allowlist engeller.

interface FieldDef {
  name: string;
  tableID: number;
  columnID: number;
}

function readCursor(cursor: Cursor<unknown[]>, n: number): Promise<{ rows: unknown[][]; fields: FieldDef[] }> {
  return new Promise((resolve, reject) => {
    cursor.read(n, (err: Error | undefined, rows: unknown[][], result: { fields?: FieldDef[] }) => {
      if (err) reject(err);
      else resolve({ rows, fields: result?.fields ?? [] });
    });
  });
}

function closeCursor(cursor: Cursor<unknown[]>): Promise<void> {
  return new Promise((resolve) => {
    cursor.close(() => resolve());
  });
}

const intMs = (n: number): number => Math.max(1, Math.min(600_000, Math.floor(n)));

export class PgSession implements DbSession {
  private closed = false;
  private readonly client: pg.Client;
  private readonly opts: { readonly defaultSchema: string; readonly tls: boolean };

  constructor(client: pg.Client, opts: { readonly defaultSchema: string; readonly tls: boolean }) {
    this.client = client;
    this.opts = opts;
  }

  private async simple(sql: string): Promise<pg.QueryResult> {
    return this.client.query(sql);
  }

  async applyReaderGuards(limits: ReadLimits): Promise<void> {
    try {
      await this.simple("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY");
      await this.simple(`SET statement_timeout = ${intMs(limits.timeoutMs)}`);
      await this.simple(`SET lock_timeout = ${intMs(Math.min(limits.timeoutMs, 5_000))}`);
      await this.simple(`SET idle_in_transaction_session_timeout = ${intMs(limits.timeoutMs * 2)}`);
      await this.simple(`SET search_path = ${quoteIdent(this.opts.defaultSchema)}`);
      const r = await this.simple("SHOW default_transaction_read_only");
      if (r.rows[0]?.["default_transaction_read_only"] !== "on") throw new OpsError("reader_guard_failed", "oturum salt-okunur kipe alınamadı");
    } catch (e) {
      throw dbError(e, "okuyucu korumaları uygulanamadı");
    }
  }

  /** Tek ifadelik genişletilmiş protokol imleci: sunucu çoklu ifadeyi ayrıca reddeder. */
  private async runCursor(sql: string, limit: number, limits: ReadLimits): Promise<{ rows: unknown[][]; fields: FieldDef[] }> {
    await this.simple("BEGIN READ ONLY");
    let cursor: Cursor<unknown[]> | undefined;
    try {
      await this.simple(`SET LOCAL statement_timeout = ${intMs(limits.timeoutMs)}`);
      cursor = this.client.query(new Cursor<unknown[]>(sql, [], { rowMode: "array", types: TYPES }));
      return await readCursor(cursor, limit);
    } finally {
      if (cursor) await closeCursor(cursor).catch(() => undefined);
      await this.simple("ROLLBACK").catch(() => undefined);
    }
  }

  async executeRead(sql: string, limits: ReadLimits): Promise<ReadResult> {
    let raw: { rows: unknown[][]; fields: FieldDef[] };
    try {
      raw = await this.runCursor(sql, limits.maxRows + 1, limits);
    } catch (e) {
      throw dbError(e, "sorgu başarısız");
    }
    let truncated = raw.rows.length > limits.maxRows;
    let rows = truncated ? raw.rows.slice(0, limits.maxRows) : raw.rows;
    // bayt sınırı (tahmini: JSON uzunluğu)
    let bytes = 0;
    const kept: unknown[][] = [];
    for (const r of rows) {
      bytes += Buffer.byteLength(JSON.stringify(r) ?? "", "utf8");
      if (bytes > limits.maxBytes) {
        truncated = true;
        break;
      }
      kept.push(r);
    }
    rows = kept;
    const columns = await this.originsFor(raw.fields);
    return { columns, rows, truncated, totalRowsSeen: raw.rows.length };
  }

  /** Doğrudan sütun başvurularının kaynak tablo/sütununu (`şema.tablo`, `sütun`) çözer; başarısızlık ölümcül değildir. */
  private async originsFor(fields: FieldDef[]): Promise<ColumnInfo[]> {
    const ids = [...new Set(fields.map((f) => f.tableID).filter((n) => n > 0))];
    const map = new Map<string, { relation: string; column: string }>();
    if (ids.length > 0) {
      try {
        const r = await this.client.query({
          text:
            "SELECT c.oid::text AS oid, n.nspname AS schema, c.relname AS rel, a.attnum::int AS attnum, a.attname AS col " +
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace " +
            "JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid WHERE c.oid = ANY($1::oid[]) AND a.attnum > 0 AND NOT a.attisdropped",
          values: [ids],
        });
        for (const row of r.rows as { oid: string; schema: string; rel: string; attnum: number; col: string }[]) {
          map.set(`${row.oid}:${row.attnum}`, { relation: `${row.schema}.${row.rel}`, column: row.col });
        }
      } catch {
        /* köken çözülemedi: değer dedektörleri ikinci hat olarak kalır */
      }
    }
    return fields.map((f) => {
      const o = f.tableID > 0 ? map.get(`${f.tableID}:${f.columnID}`) : undefined;
      return o ? { name: f.name, origin: o } : { name: f.name };
    });
  }

  async explain(sql: string): Promise<string> {
    const limits: ReadLimits = { maxRows: 300, maxBytes: 64 * 1024, timeoutMs: 10_000 };
    try {
      const raw = await this.runCursor(`EXPLAIN (VERBOSE false, COSTS true, FORMAT TEXT) ${sql}`, limits.maxRows, limits);
      return raw.rows.map((r) => String(r[0] ?? "")).join("\n").slice(0, limits.maxBytes);
    } catch (e) {
      throw dbError(e, "EXPLAIN başarısız");
    }
  }

  async describeSchema(scopes: readonly string[]): Promise<SchemaDescription> {
    const wildcard = scopes.includes("*");
    try {
      const r = await this.client.query({
        text:
          "SELECT n.nspname AS schema, c.relname AS tbl, a.attname AS col, format_type(a.atttypid, a.atttypmod) AS typ " +
          "FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid " +
          "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace " +
          "WHERE c.relkind IN ('r','p','v','m','f') AND a.attnum > 0 AND NOT a.attisdropped " +
          "AND has_column_privilege(c.oid, a.attnum, 'SELECT') " +
          (wildcard
            ? "AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema' "
            : "AND n.nspname = ANY($1::text[]) ") +
          "ORDER BY n.nspname, c.relname, a.attnum LIMIT 5001",
        values: wildcard ? [] : [[...scopes]],
      });
      const schemas = new Map<string, Map<string, { name: string; type: string }[]>>();
      for (const row of (r.rows as { schema: string; tbl: string; col: string; typ: string }[]).slice(0, 5000)) {
        const s = schemas.get(row.schema) ?? new Map<string, { name: string; type: string }[]>();
        const t = s.get(row.tbl) ?? [];
        t.push({ name: row.col, type: row.typ });
        s.set(row.tbl, t);
        schemas.set(row.schema, s);
      }
      return {
        schemas: [...schemas].map(([name, tbls]) => ({
          name,
          tables: [...tbls].map(([tname, columns]) => ({ name: tname, columns })),
        })),
      };
    } catch (e) {
      throw dbError(e, "şema okunamadı");
    }
  }

  // ---- yalnız PostgreSQL: istatistik ve doktor -----------------------------------------------

  async stats(): Promise<PgStats> {
    const one = async <T>(text: string): Promise<T[]> => (await this.client.query(text)).rows as T[];
    try {
      const conns = await one<{ state: string | null; n: number }>(
        "SELECT coalesce(state, 'background') AS state, count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() GROUP BY 1",
      );
      const act = (await one<{ waiting: number; blocked: number; longest: number | null; oldest: number | null }>(
        "SELECT count(*) FILTER (WHERE wait_event_type = 'Lock')::int AS waiting, " +
          "count(*) FILTER (WHERE cardinality(pg_blocking_pids(pid)) > 0)::int AS blocked, " +
          "max(extract(epoch FROM now() - query_start)) FILTER (WHERE state = 'active' AND pid <> pg_backend_pid())::float8 AS longest, " +
          "max(extract(epoch FROM now() - xact_start))::float8 AS oldest " +
          "FROM pg_stat_activity WHERE datname = current_database()",
      ))[0];
      const size = (await one<{ size: string }>("SELECT pg_database_size(current_database())::text AS size"))[0];
      const rec = (await one<{ rec: boolean; lag: number | null }>(
        "SELECT pg_is_in_recovery() AS rec, extract(epoch FROM now() - pg_last_xact_replay_timestamp())::float8 AS lag",
      ))[0];
      let replicas = 0;
      try {
        replicas = (await one<{ n: number }>("SELECT count(*)::int AS n FROM pg_stat_replication"))[0]?.n ?? 0;
      } catch {
        /* görünmeyebilir */
      }
      const db = (await one<{ xc: string; xr: string; dl: string; tf: string; tb: string; hit: string; read: string }>(
        "SELECT xact_commit::text AS xc, xact_rollback::text AS xr, deadlocks::text AS dl, temp_files::text AS tf, temp_bytes::text AS tb, " +
          "blks_hit::text AS hit, blks_read::text AS read FROM pg_stat_database WHERE datname = current_database()",
      ))[0];
      const longq = await one<{ dur: number; state: string; wait: string | null; q: string | null }>(
        "SELECT extract(epoch FROM now() - query_start)::float8 AS dur, state, wait_event AS wait, query AS q FROM pg_stat_activity " +
          "WHERE datname = current_database() AND state <> 'idle' AND pid <> pg_backend_pid() AND query_start < now() - interval '5 seconds' " +
          "ORDER BY query_start LIMIT 5",
      );
      const hit = Number(db?.hit ?? 0);
      const read = Number(db?.read ?? 0);
      return {
        connections: Object.fromEntries(conns.map((c) => [c.state ?? "background", c.n])),
        waitingOnLocks: act?.waiting ?? 0,
        blockedSessions: act?.blocked ?? 0,
        longestActiveSec: act?.longest !== null && act?.longest !== undefined ? Math.round(act.longest) : null,
        oldestTransactionSec: act?.oldest !== null && act?.oldest !== undefined ? Math.round(act.oldest) : null,
        databaseSizeBytes: Number(size?.size ?? 0),
        inRecovery: rec?.rec ?? false,
        replayLagSec: rec?.lag !== null && rec?.lag !== undefined ? Math.round(rec.lag) : null,
        replicas,
        counters: {
          commits: Number(db?.xc ?? 0),
          rollbacks: Number(db?.xr ?? 0),
          deadlocks: Number(db?.dl ?? 0),
          tempFiles: Number(db?.tf ?? 0),
          tempBytes: Number(db?.tb ?? 0),
          cacheHitRatio: hit + read > 0 ? Math.round((hit / (hit + read)) * 1000) / 1000 : null,
        },
        longQueries: longq.map((q) => ({
          durationSec: Math.round(q.dur),
          state: q.state,
          wait: q.wait,
          // başka kullanıcıların sorguları '<insufficient privilege>' gelir; metin yalnız normalleştirilip gösterilir
          query: q.q ? normalizeSqlForDisplay(q.q) : null,
        })),
        note: "sorgu metinleri değişmezsiz (normalleştirilmiş); başka kullanıcıların sorguları pg_monitor olmadan görünmez",
      };
    } catch (e) {
      throw dbError(e, "istatistik okunamadı");
    }
  }

  async privilegeFacts(scopes: readonly string[]): Promise<PrivilegeFacts> {
    const q = async <T>(text: string, values: unknown[] = []): Promise<T[]> => (await this.client.query({ text, values })).rows as T[];
    try {
      const role = (await q<{ rolname: string; rolsuper: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolreplication: boolean; rolbypassrls: boolean }>(
        "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user",
      ))[0];
      if (!role) throw new OpsError("db_error", "geçerli rol okunamadı");
      const member = async (names: string[]): Promise<string[]> =>
        (await q<{ rolname: string }>("SELECT r.rolname FROM pg_catalog.pg_roles r WHERE r.rolname = ANY($1::text[]) AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER') ORDER BY 1", [names])).map((r) => r.rolname);
      const dangerousRoles = await member(DANGEROUS_ROLES);
      const broadReadRoles = await member(BROAD_READ_ROLES);
      const dbp = (await q<{ c: boolean; t: boolean; name: string }>("SELECT has_database_privilege(current_database(), 'CREATE') AS c, has_database_privilege(current_database(), 'TEMPORARY') AS t, current_database() AS name"))[0];
      const nsp = await q<{ nspname: string; can_create: boolean }>(
        "SELECT n.nspname, has_schema_privilege(n.oid, 'CREATE') AS can_create FROM pg_catalog.pg_namespace n WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema' ORDER BY 1",
      );
      const wildcard = scopes.includes("*");
      const existing = new Set(nsp.map((n) => n.nspname));
      const writable = await q<{ nspname: string; relname: string }>(
        "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace " +
          "WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema' " +
          "AND (has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE') OR has_table_privilege(c.oid, 'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE') " +
          "OR has_any_column_privilege(c.oid, 'INSERT') OR has_any_column_privilege(c.oid, 'UPDATE')) ORDER BY 1, 2 LIMIT 500",
      );
      const seqs = await q<{ nspname: string; relname: string }>(
        "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace " +
          "WHERE c.relkind = 'S' AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema' " +
          "AND (has_sequence_privilege(c.oid, 'UPDATE') OR has_sequence_privilege(c.oid, 'USAGE')) ORDER BY 1, 2 LIMIT 20",
      );
      const funcs = await q<{ f: string }>(
        "SELECT p.oid::regprocedure::text AS f FROM pg_catalog.pg_proc p WHERE p.proname = ANY($1::text[]) AND has_function_privilege(p.oid, 'EXECUTE') ORDER BY 1",
        [DANGEROUS_FUNCTIONS],
      );
      const outside = wildcard
        ? []
        : await q<{ nspname: string; n: number }>(
            "SELECT n.nspname, count(*)::int AS n FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace " +
              "WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema' " +
              "AND NOT (n.nspname = ANY($1::text[])) AND has_table_privilege(c.oid, 'SELECT') GROUP BY 1 ORDER BY 1 LIMIT 20",
            [[...scopes]],
          );
      const ro = (await q<{ v: string }>("SELECT current_setting('transaction_read_only') AS v"))[0];
      const ver = (await q<{ v: string }>("SELECT current_setting('server_version') AS v"))[0];
      const ssl = (await q<{ ssl: boolean }>("SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid = pg_backend_pid()"))[0];
      return {
        role: { name: role.rolname, superuser: role.rolsuper, createRole: role.rolcreaterole, createDb: role.rolcreatedb, replication: role.rolreplication, bypassRls: role.rolbypassrls },
        dangerousRoles,
        broadReadRoles,
        databaseCreate: dbp?.c ?? false,
        databaseTemp: dbp?.t ?? false,
        schemaCreate: nsp.filter((n) => n.can_create).map((n) => n.nspname),
        writableRelations: writable.slice(0, 20).map((w) => `${w.nspname}.${w.relname}`),
        writableRelationCount: writable.length,
        writableSequences: seqs.map((s) => `${s.nspname}.${s.relname}`),
        dangerousFunctions: funcs.map((f) => f.f),
        readableOutsideScopes: outside.map((o) => ({ schema: o.nspname, tables: o.n })),
        missingScopes: wildcard ? [] : scopes.filter((s) => !existing.has(s)),
        transactionReadOnly: ro?.v === "on",
        tls: ssl?.ssl ?? false,
        serverVersion: ver?.v ?? "?",
        database: dbp?.name ?? "?",
      };
    } catch (e) {
      throw dbError(e, "yetkiler okunamadı");
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.client.end().catch(() => undefined);
  }

  /** Bağlantıyı hemen düşürür (iptal/zaman aşımı). */
  destroy(): void {
    this.closed = true;
    const stream = (this.client as unknown as { connection?: { stream?: { destroy(): void } } }).connection?.stream;
    stream?.destroy();
  }
}

export interface PgSessionHandle extends DbSession {
  stats(): Promise<PgStats>;
  privilegeFacts(scopes: readonly string[]): Promise<PrivilegeFacts>;
}

/** Adapter'ın ihtiyaç duyduğu sürücü yüzü (DatabaseDriver + PostgreSQL'e özgü oturum yetenekleri). */
export interface PgDriverApi {
  readonly dialect: "postgresql";
  readonly capabilities: DbCapabilities;
  classify(sql: string): SqlClassification;
  connect(handle: CredentialHandle, role: DbRole, opts: DbConnectOptions): Promise<PgSessionHandle>;
}

export class PgDriver implements DatabaseDriver, PgDriverApi {
  readonly dialect = "postgresql" as const;
  readonly capabilities: DbCapabilities = { readOnlyTx: true, statementTimeout: true, columnOrigin: true };

  private readonly resolver: CredentialResolver;

  constructor(resolver: CredentialResolver) {
    this.resolver = resolver;
  }

  classify(sql: string): SqlClassification {
    return classifySql(sql).classification;
  }

  async connect(handle: CredentialHandle, role: DbRole, opts: DbConnectOptions): Promise<PgSession> {
    if (role !== "reader") throw new OpsError("writer_unsupported", "yazıcı kimliği bu sürümde desteklenmiyor (Faz 2)");
    const cred = this.resolver.db(handle);
    // Kimlik gönderilmeden ÖNCE: sunucu adresi ve (varsa) CA parmak izi profilin pinine uymalı.
    if (normalizeEndpoint(dbEndpoint(cred.host, cred.port)) !== normalizeEndpoint(opts.pin.endpoint)) {
      throw new OpsError("target_pin_mismatch", "veritabanı adresi profilin pinli uç noktasıyla eşleşmiyor");
    }
    if (opts.pin.caFingerprint && (!cred.tls.caPem || caFingerprintOf(cred.tls.caPem) !== opts.pin.caFingerprint)) {
      throw new OpsError("target_pin_mismatch", "CA parmak izi profilin pinine uymuyor");
    }
    if (cred.tls.mode === "disable" && !isLoopbackHost(cred.host)) throw new OpsError("db_tls_required", "uzak veritabanı için TLS zorunlu");
    if (opts.signal?.aborted) throw new OpsError("aborted", "çağrı iptal edildi");

    // Ortam değişkenleri (PGOPTIONS, PGREPLICATION, PGSSLMODE...) devre dışı: her alan açıkça verilir.
    const config: pg.ClientConfig & { replication?: string; sslnegotiation?: string } = {
      host: cred.host,
      port: cred.port,
      user: cred.user,
      password: cred.password,
      database: cred.database,
      ssl:
        cred.tls.mode === "disable"
          ? false
          : {
              rejectUnauthorized: true,
              minVersion: "TLSv1.2",
              ...(cred.tls.caPem ? { ca: [cred.tls.caPem] } : {}),
              ...(cred.tls.serverName ? { servername: cred.tls.serverName } : {}),
            },
      connectionTimeoutMillis: 10_000,
      application_name: "ops-assistant",
      options: "-c client_min_messages=warning",
      client_encoding: "UTF8",
      replication: "false",
      sslnegotiation: "postgres",
      keepAlive: false,
      types: TYPES,
    };
    const client = new pg.Client(config);
    client.on("error", () => undefined); // soket hataları çağrı yolunda yakalanır; süreç çökmesin
    const onAbort = (): void => {
      (client as unknown as { connection?: { stream?: { destroy(): void } } }).connection?.stream?.destroy();
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });
    try {
      await client.connect();
    } catch (e) {
      opts.signal?.removeEventListener("abort", onAbort);
      throw dbError(e, "veritabanına bağlanılamadı");
    }
    return new PgSession(client, { defaultSchema: opts.defaultSchema ?? "public", tls: cred.tls.mode !== "disable" });
  }
}
