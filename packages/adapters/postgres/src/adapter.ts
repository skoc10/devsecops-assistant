import { ADAPTER_CONTRACT, AdapterManifestSchema, OpsError, riskRank } from "@ops/contracts";
import type {
  ActionPreview,
  Adapter,
  AdapterCall,
  AdapterManifest,
  CredentialHandle,
  DbConnectOptions,
  DbRole,
  DoctorReport,
  Profile,
  RawToolOutput,
  RiskClass,
  Sensitivity,
  Target,
} from "@ops/contracts";
import type { CredentialResolver } from "@ops/broker";
import { classifySql, classifySqlChange, maskedViolations } from "@ops/classifiers";
import type { ChangeAnalysis, SqlAnalysis } from "@ops/classifiers";
import { PgDriver } from "./driver.ts";
import type { PgDriverApi, PgSessionHandle } from "./driver.ts";
import { diagnose } from "./doctor.ts";
import { EMPTY_MASKING_CONFIG, maskedMapFor } from "./masking.ts";
import type { MaskingConfig } from "./masking.ts";
import { DB_ALL_TOOLS } from "./tools.ts";
import { DEFAULT_CHANGE_MAX_ROWS, MAX_APPROVED_ROWS, buildPlan, changeRefs, changeScopes, renderPreview } from "./change.ts";
import type { ChangePlan } from "./change.ts";
import { SIMPLE_IDENT } from "./identifiers.ts";
import { isLoopbackHost } from "@ops/broker";

type Args = Record<string, unknown>;
const str = (a: Args, k: string): string | undefined => (typeof a[k] === "string" ? (a[k] as string) : undefined);

export interface PostgresAdapterOptions {
  readonly masking?: MaskingConfig;
  /** Test için; verilmezse gerçek `pg` sürücüsü. */
  readonly driver?: PgDriverApi;
  readonly now?: () => Date;
}

const DEFAULT_MAX_ROWS = 100;

/**
 * PostgreSQL reader adapter'ı. SQL, PEP öncesi (resolveTarget) gerçek PostgreSQL ayrıştırıcısıyla
 * AST allowlist'ten geçer; reddedilen sorgu kimlik alınmadan, nedeniyle birlikte reddedilir.
 * Katmanlar: (1) araç yüzünde yazma aracı yok, (2) AST allowlist, (3) oturum READ ONLY + zaman
 * aşımları, (4) rol yetkisi (doktor sınar). (3) kullanıcı düzeyinde SET ile geri alınabildiğinden
 * (2)'ye bağımlı savunma derinliğidir; bağımsız katman sayılmaz (tasarım §8.4).
 */
export class PostgresAdapter implements Adapter {
  readonly manifest: AdapterManifest;
  private readonly driver: PgDriverApi;
  private readonly masking: MaskingConfig;
  private readonly now: () => Date;

  constructor(resolver: CredentialResolver, opts: PostgresAdapterOptions = {}) {
    this.driver = opts.driver ?? new PgDriver(resolver);
    this.masking = opts.masking ?? EMPTY_MASKING_CONFIG;
    this.now = opts.now ?? (() => new Date());
    this.manifest = AdapterManifestSchema.parse({
      id: "postgres",
      version: "0.1.0",
      contract: ADAPTER_CONTRACT,
      kind: "database",
      profileKinds: ["db"],
      credentialKinds: ["static"],
      capabilities: ["read-only", "column-origin", "statement-timeout", "ast-allowlist", "change-transaction", "row-limit-rollback"],
      tools: DB_ALL_TOOLS.map((t) => t.descriptor),
    });
  }

  get definitions(): typeof DB_ALL_TOOLS {
    return DB_ALL_TOOLS;
  }

  validateProfile(profile: Profile): string[] {
    const problems: string[] = [];
    if (profile.kind !== "db") problems.push(`profil türü 'db' olmalı: ${profile.kind}`);
    if (profile.credentialSource.kind !== "static") problems.push(`kimlik kaynağı henüz desteklenmiyor: ${profile.credentialSource.kind}`);
    const role = profile.attributes["role"];
    if (role !== "reader" && role !== "writer") problems.push("profil rolü 'reader' veya 'writer' olmalı");
    else if (role === "reader" && profile.classCeiling !== "read") problems.push("reader profil yalnız 'read' tavanlı olabilir");
    else if (role === "writer" && profile.classCeiling === "read") problems.push("writer profil 'mutate', 'deploy' veya 'destroy' tavanlı olmalı");
    if (/^https?:\/\//i.test(profile.targetPin.endpoint) || !/^(\[[0-9a-f:]+\]|[a-z0-9.-]+):\d{1,5}$/i.test(profile.targetPin.endpoint)) problems.push("pin uç noktası 'host:port' biçiminde olmalı");
    const defaultSchema = profile.attributes["defaultSchema"];
    if (defaultSchema !== undefined && !SIMPLE_IDENT.test(defaultSchema)) problems.push("defaultSchema geçersiz");
    const host = profile.targetPin.endpoint.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
    if (!profile.targetPin.caFingerprint && !isLoopbackHost(host)) problems.push("uyarı: CA pini yok (sistem kökleri kullanılır)");
    return problems.filter((p) => !p.startsWith("uyarı:"));
  }

  // ---- SQL analizi --------------------------------------------------------------------------

  private defaultSchemaOf(profile: Profile): string {
    return profile.attributes["defaultSchema"] ?? profile.allowedScopes.find((s) => s !== "*") ?? "public";
  }

  /** Sorguyu sınıflar ve reddedilirse nedeniyle OpsError atar. */
  private analyze(tool: string, a: Args, profile: Profile): { analysis: SqlAnalysis; sql: string } {
    const sql = str(a, "sql");
    if (sql === undefined) throw new OpsError("sql_missing", "sql gerekli");
    const analysis = classifySql(sql);
    if (!analysis.allowed) throw new OpsError("sql_rejected", `SQL reddedildi: ${analysis.reason ?? "izinli değil"}`);
    if (analysis.explain) throw new OpsError("sql_rejected", "SQL reddedildi: EXPLAIN ayrı araçtır (db.query.explain); yalnız SELECT verin");
    if (tool === "db.query.explain") {
      const composed = classifySql(`EXPLAIN (VERBOSE false, COSTS true, FORMAT TEXT) ${sql}`);
      if (!composed.allowed || !composed.explain || composed.classification.statementCount !== 1) {
        throw new OpsError("sql_rejected", `SQL reddedildi: EXPLAIN sarmalayıcısı geçersiz (${composed.reason ?? "?"})`);
      }
    }
    const violations = maskedViolations(analysis, maskedMapFor(this.masking, profile.id));
    if (violations.length > 0) {
      throw new OpsError("masked_column_violation", `maskeli sütun kuralı: ${violations.slice(0, 3).join("; ")} — maskeli sütun yalnız doğrudan seçilebilir`);
    }
    return { analysis, sql };
  }

  private roleOf(profile: Profile): DbRole {
    return profile.attributes["role"] === "writer" ? "writer" : "reader";
  }

  /** Değişiklik ifade kümesini sınıflar; reddedilirse nedeniyle OpsError. Yazma aracı yalnız writer profilinde. */
  private analyzeChange(tool: string, a: Args, profile: Profile): { analysis: ChangeAnalysis; maxRows: number } {
    const sql = str(a, "sql");
    if (sql === undefined) throw new OpsError("sql_missing", "sql gerekli");
    if (tool === "db.change.apply" && this.roleOf(profile) !== "writer") {
      throw new OpsError("writer_required", "db.change.apply yalnız 'writer' rollü profilde çalışır (reader profilde yazma yok)");
    }
    const analysis = classifySqlChange(sql);
    if (!analysis.allowed) throw new OpsError("sql_rejected", `SQL reddedildi: ${analysis.reason ?? "izinli değil"}`);
    const violations = maskedViolations({ allowed: true, explain: false, classification: analysis.classification }, maskedMapFor(this.masking, profile.id));
    if (violations.length > 0) {
      throw new OpsError("masked_column_violation", `maskeli sütun kuralı: ${violations.slice(0, 3).join("; ")} — maskeli sütun değişiklikte yalnız yazılabilir, okunamaz (koşul/ifade/alt sorgu yasak)`);
    }
    const maxRows = typeof a["maxRows"] === "number" ? (a["maxRows"] as number) : DEFAULT_CHANGE_MAX_ROWS;
    return { analysis, maxRows };
  }

  private scopesOf(analysis: SqlAnalysis, profile: Profile): string[] {
    const def = this.defaultSchemaOf(profile);
    const out = new Set<string>();
    for (const rel of analysis.classification.relations) {
      const parts = rel.split(".");
      out.add(parts.length > 1 ? (parts[0] as string) : def);
    }
    if (out.size === 0) out.add(def); // ilişkisiz sorgu (SELECT 1) varsayılan şemada sayılır
    return [...out];
  }

  // ---- hedef / sınıf ------------------------------------------------------------------------

  resolveTarget(tool: string, args: unknown, profile: Profile): Target {
    const a = (args ?? {}) as Args;
    const t = (scopes: string[], refs: string[] = []): Target => ({ profileId: profile.id, kind: profile.kind, endpoint: profile.targetPin.endpoint, scopes, refs });
    const ds = profile.attributes["datasource"] ?? profile.id;
    switch (tool) {
      case "db.datasource.describe":
      case "db.stats.summary":
        return t([...profile.allowedScopes], [`Datasource/${ds}`]);
      case "db.schema.describe": {
        const schema = str(a, "schema");
        return t(schema ? [schema] : [...profile.allowedScopes], [`Datasource/${ds}`]);
      }
      case "db.query.read":
      case "db.query.explain": {
        const { analysis } = this.analyze(tool, a, profile);
        return t(this.scopesOf(analysis, profile), analysis.classification.relations.map((r) => `Table/${r.includes(".") ? r : `${this.defaultSchemaOf(profile)}.${r}`}`));
      }
      case "db.change.propose":
      case "db.change.apply": {
        const { analysis } = this.analyzeChange(tool, a, profile);
        const def = this.defaultSchemaOf(profile);
        return t(changeScopes(analysis, def), changeRefs(analysis, def));
      }
      default:
        throw new OpsError("unknown_tool", `bilinmeyen araç: ${tool}`);
    }
  }

  /** Savunma derinliği: reddedilen SQL `destroy` muamelesi görür (resolveTarget zaten reddeder). */
  classify(tool: string, args: unknown): RiskClass | undefined {
    if (tool === "db.change.apply") {
      const sql = str((args ?? {}) as Args, "sql");
      if (sql === undefined) return "destroy";
      const r = classifySqlChange(sql);
      return r.allowed ? r.risk : "destroy";
    }
    if (tool !== "db.query.read" && tool !== "db.query.explain") return undefined;
    const sql = str((args ?? {}) as Args, "sql");
    if (sql === undefined) return "destroy";
    const r = classifySql(sql);
    return r.allowed && (tool === "db.query.explain" || !r.explain) ? undefined : "destroy";
  }

  sensitivityOf(tool: string): Sensitivity | undefined {
    return tool === "db.query.read" ? "pii" : undefined;
  }

  // ---- bağlantı / doktor --------------------------------------------------------------------

  private connectOpts(profile: Profile, signal?: AbortSignal): DbConnectOptions {
    return {
      pin: { endpoint: profile.targetPin.endpoint, ...(profile.targetPin.caFingerprint ? { caFingerprint: profile.targetPin.caFingerprint } : {}) },
      defaultSchema: this.defaultSchemaOf(profile),
      ...(signal ? { signal } : {}),
    };
  }

  async connectCheck(handle: CredentialHandle, profile: Profile): Promise<{ identity: string; targetFingerprint: string }> {
    const s = await this.driver.connect(handle, "reader", this.connectOpts(profile));
    try {
      await s.applyReaderGuards({ maxRows: 1, maxBytes: 4096, timeoutMs: 10_000 });
      const f = await s.privilegeFacts(profile.allowedScopes);
      return { identity: `${f.role.name}@${f.database}`, targetFingerprint: profile.targetPin.caFingerprint ?? "system-roots" };
    } finally {
      await s.close();
    }
  }

  async doctor(handle: CredentialHandle, profile: Profile): Promise<DoctorReport> {
    const host = profile.targetPin.endpoint.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
    return diagnose(profile, {
      now: this.now,
      inspect: async () => {
        const s = await this.driver.connect(handle, "reader", this.connectOpts(profile));
        try {
          await s.applyReaderGuards({ maxRows: 1, maxBytes: 4096, timeoutMs: 10_000 });
          const facts = await s.privilegeFacts(profile.allowedScopes);
          return { identity: `${facts.role.name}@${facts.database}`, facts, loopback: isLoopbackHost(host) };
        } finally {
          await s.close();
        }
      },
    });
  }

  // ---- araçlar ------------------------------------------------------------------------------

  /** Mutasyon önizlemesi: ifade kümesi + tahmini etki + şema sürümü (TOCTOU). Salt OKUNUR işlemlerle. */
  async preview(call: AdapterCall): Promise<ActionPreview> {
    if (call.tool !== "db.change.apply") throw new OpsError("no_preview", `araç önizleme desteklemiyor: ${call.tool}`);
    if (!call.handle) throw new OpsError("lease_inactive", "kimlik tutamacı yok");
    const p = call.profile;
    const { analysis, maxRows } = this.analyzeChange(call.tool, (call.args ?? {}) as Args, p);
    const plan = buildPlan(analysis, this.defaultSchemaOf(p), maxRows, call.limits.timeoutMs);
    return this.withSession(call, "reader", async (session) => {
      const version = await session.changeVersion(plan);
      const estimates = await session.estimateChange(plan);
      return renderPreview(plan, estimates, version);
    });
  }

  /** Oturumu açar, okuma korumalarını uygular, `fn`i çalıştırır; her durumda kapatır (zaman aşımında bağlantıyı düşürür). */
  private async withSession<T>(call: AdapterCall, role: DbRole, fn: (s: PgSessionHandle) => Promise<T>, guard: "reader" | "writer" = "reader"): Promise<T> {
    if (!call.handle) throw new OpsError("lease_inactive", "kimlik tutamacı yok");
    const p = call.profile;
    const session = await this.driver.connect(call.handle, role, this.connectOpts(p, call.signal));
    const deadline = setTimeout(() => (session as unknown as { destroy?: () => void }).destroy?.(), call.limits.timeoutMs + 3_000);
    deadline.unref();
    try {
      if (guard === "writer") await session.applyWriterGuards({ timeoutMs: call.limits.timeoutMs });
      else await session.applyReaderGuards({ maxRows: 1, maxBytes: 4096, timeoutMs: Math.min(call.limits.timeoutMs, 20_000) });
      return await fn(session);
    } finally {
      clearTimeout(deadline);
      await session.close();
    }
  }

  private async proposeChange(call: AdapterCall): Promise<RawToolOutput> {
    const p = call.profile;
    const { analysis, maxRows } = this.analyzeChange(call.tool, (call.args ?? {}) as Args, p);
    const def = this.defaultSchemaOf(p);
    const plan = buildPlan(analysis, def, maxRows, call.limits.timeoutMs);
    const estimates = await this.withSession(call, "reader", (s) => s.estimateChange(plan));
    const known = estimates.filter((e): e is number => typeof e === "number");
    const dmlCount = plan.statements.filter((s) => s.dml).length;
    const total = known.reduce((x, y) => x + y, 0);
    const complete = known.length === dmlCount;
    const suggestedMaxRows = complete && dmlCount > 0 ? Math.min(MAX_APPROVED_ROWS, Math.max(10, Math.ceil(total * 1.2))) : DEFAULT_CHANGE_MAX_ROWS;
    const notes: string[] = [];
    if (!complete) notes.push("bazı ifadeler için satır tahmini yok (yetki, henüz yaratılmamış tablo veya DDL); üst sınırı bilerek seçin");
    const needed = analysis.risk;
    if (riskRank(needed) > riskRank(p.classCeiling)) notes.push(`bu profilin tavanı '${p.classCeiling}', küme '${needed}' gerektirir: uygulanamaz (ceiling_exceeded)`);
    if (this.roleOf(p) !== "writer") notes.push("bu profil reader: uygulamak için writer profili bağlayın (aynı kanıtlara atıf yapılamaz; yeniden okuyun)");
    return {
      data: {
        statements: analysis.statements.map((s) => ({
          index: s.index + 1,
          kind: s.kind,
          class: s.risk,
          targets: s.targets.map((t) => (t.schema ? `${t.schema}.${t.name}` : `${def}.${t.name}`)),
          estimatedRows: estimates[s.index] ?? null,
          ...(s.unbounded ? { whereless: true } : {}),
        })),
        requiredClass: needed,
        profileCeiling: p.classCeiling,
        estimatedTotalRows: complete ? total : undefined,
        suggestedMaxRows,
        statementSetSha256: analysis.digest.slice(0, 16),
        notes: notes.length ? notes : undefined,
      },
      summary: `${analysis.statements.length} ifade, gereken sınıf ${needed}${complete && dmlCount > 0 ? `, tahmini ≈${total} satır` : ""}`,
      subjects: changeRefs(analysis, def).slice(0, 20),
    };
  }

  private async applyChange(call: AdapterCall): Promise<RawToolOutput> {
    const p = call.profile;
    if (!call.approvedVersion) throw new OpsError("approval_version_missing", "onaylanan sürüm yok: uygulama reddedildi");
    const { analysis, maxRows } = this.analyzeChange(call.tool, (call.args ?? {}) as Args, p);
    const def = this.defaultSchemaOf(p);
    // Kimlik kullanılmadan ÖNCE, PEP'e güvenmeden: sınıf profil tavanını aşamaz.
    if (riskRank(analysis.risk) > riskRank(p.classCeiling)) throw new OpsError("ceiling_exceeded", `ifade kümesi '${analysis.risk}' gerektirir, profil tavanı '${p.classCeiling}'`);
    const plan = buildPlan(analysis, def, maxRows, call.limits.timeoutMs);
    const approved = call.approvedVersion;
    const res = await this.withSession(call, "writer", (s) => s.applyChange(plan, approved), "writer");
    return {
      data: { committed: true, statements: res.statements.map((s) => ({ index: s.index + 1, kind: s.kind, rows: s.rows })), totalRows: res.totalRows, maxRows, schemaVersion: res.version.slice(0, 22), statementSetSha256: analysis.digest.slice(0, 16) },
      summary: `${res.statements.length} ifade uygulandı (COMMIT), toplam ${res.totalRows} satır etkilendi (üst sınır ${maxRows})`,
      subjects: changeRefs(analysis, def).slice(0, 20),
    };
  }

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    const a = (call.args ?? {}) as Args;
    const p = call.profile;
    if (call.tool === "db.datasource.describe") return this.describeDatasource(p);
    if (call.tool === "db.change.propose") return this.proposeChange(call);
    if (call.tool === "db.change.apply") return this.applyChange(call);
    if (!call.handle) throw new OpsError("lease_inactive", "kimlik tutamacı yok");
    // SQL araçları: kimlik kullanılmadan ÖNCE tekrar sınıflanır (PEP'e güvenmeden).
    const sqlInfo = call.tool === "db.query.read" || call.tool === "db.query.explain" ? this.analyze(call.tool, a, p) : null;
    const limits = {
      maxRows: Math.min(typeof a["maxRows"] === "number" ? (a["maxRows"] as number) : DEFAULT_MAX_ROWS, call.limits.maxItems),
      maxBytes: call.limits.maxBytes,
      timeoutMs: call.limits.timeoutMs,
    };
    const session = await this.driver.connect(call.handle, "reader", this.connectOpts(p, call.signal));
    const deadline = setTimeout(() => (session as unknown as { destroy?: () => void }).destroy?.(), call.limits.timeoutMs + 3_000);
    deadline.unref();
    try {
      await session.applyReaderGuards(limits);
      switch (call.tool) {
        case "db.schema.describe":
          return await this.schemaDescribe(session, a, p);
        case "db.query.read": {
          const r = await session.executeRead((sqlInfo as { sql: string }).sql, limits);
          return {
            data: { columns: r.columns, rows: r.rows, rowCount: r.rows.length, truncated: r.truncated || undefined, note: r.truncated ? `sonuç kesildi (en çok ${limits.maxRows} satır / ${Math.round(limits.maxBytes / 1024)} KiB)` : undefined },
            summary: `${r.rows.length} satır${r.truncated ? " (kesildi)" : ""}`,
            truncated: r.truncated,
            subjects: (sqlInfo as { analysis: SqlAnalysis }).analysis.classification.relations.slice(0, 20).map((rel) => `Table/${rel.includes(".") ? rel : `${this.defaultSchemaOf(p)}.${rel}`}`),
            sensitivity: "pii",
          };
        }
        case "db.query.explain": {
          const plan = await session.explain((sqlInfo as { sql: string }).sql);
          const lines = plan.split("\n");
          return { data: { plan: lines, note: "EXPLAIN (ANALYZE yok): sorgu çalıştırılmadı" }, summary: `plan (${lines.length} satır)`, sensitivity: "internal" };
        }
        case "db.stats.summary": {
          const st = await session.stats();
          return { data: st, summary: `${Object.values(st.connections).reduce((x, y) => x + y, 0)} bağlantı, ${st.waitingOnLocks} kilit beklemesi`, sensitivity: "internal", taint: "untrusted" };
        }
        default:
          throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
      }
    } finally {
      clearTimeout(deadline);
      await session.close();
    }
  }

  private describeDatasource(p: Profile): RawToolOutput {
    return {
      data: {
        datasource: p.attributes["datasource"] ?? p.id,
        dialect: "postgresql",
        role: this.roleOf(p),
        environment: p.environment,
        allowedSchemas: p.allowedScopes,
        defaultSchema: this.defaultSchemaOf(p),
        tlsPinned: p.targetPin.caFingerprint !== undefined,
        classCeiling: p.classCeiling,
        egressClass: p.egressClass,
        limits: { maxRows: 500, maxKiB: 256, timeoutSec: 10 },
        maskedTables: [...maskedMapFor(this.masking, p.id).keys()],
      },
      summary: `veri kaynağı ${p.attributes["datasource"] ?? p.id} (${p.environment}), ${this.roleOf(p)}`,
    };
  }

  private async schemaDescribe(session: PgSessionHandle, a: Args, p: Profile): Promise<RawToolOutput> {
    const schema = str(a, "schema");
    const table = str(a, "table");
    const limit = typeof a["limit"] === "number" ? (a["limit"] as number) : 100;
    const scopes = schema ? [schema] : p.allowedScopes;
    const d = await session.describeSchema(scopes);
    const masked = maskedMapFor(this.masking, p.id);
    let total = 0;
    let shown = 0;
    const schemas = d.schemas.map((s) => ({
      name: s.name,
      tables: s.tables
        .filter((t) => !table || t.name === table)
        .filter(() => {
          total += 1;
          return true;
        })
        .slice(0, Math.max(0, limit - shown))
        .map((t) => {
          shown += 1;
          const m = masked.get(t.name.toLowerCase());
          return { name: t.name, columns: t.columns.map((c) => `${c.name}:${c.type}${m?.has(c.name.toLowerCase()) ? " [maskeli]" : ""}`) };
        }),
    }));
    const truncated = total > shown;
    return {
      data: { schemas, truncated: truncated || undefined, note: truncated ? `${total} tablodan ${shown} tanesi gösterildi; schema/table ile daraltın` : undefined },
      summary: `${shown} tablo`,
      truncated,
      subjects: [...schemas.map((s) => `Schema/${s.name}`), ...schemas.flatMap((s) => s.tables.slice(0, 20).map((t) => `Table/${s.name}.${t.name}`))],
      sensitivity: "internal",
    };
  }
}
