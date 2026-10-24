import type { CredentialHandle } from "./adapter.ts";

export type SqlDialect = "postgresql" | "mysql" | "sqlserver";
export type DbRole = "reader" | "writer";

/** Diyalekte özgü AST'den çıkarılan sınıflama girdisi; allowlist kararı politikada/PEP'te verilir. */
export interface SqlClassification {
  /** Parse edilemeyen girdi `parsed: false` olur ve reddedilir. */
  readonly parsed: boolean;
  /** Üst düzey ifade sayısı (çoklu ifade reddi için). */
  readonly statementCount: number;
  /** Düğüm türleri, ör. `SelectStmt`, `InsertStmt`, `DoStmt`... */
  readonly statementKinds: readonly string[];
  readonly relations: readonly string[];
  readonly columnRefs: readonly { readonly relation?: string; readonly column: string; readonly insideExpression: boolean }[];
  readonly functions: readonly string[];
  /** `to_jsonb(t)`, `row_to_json(t)`, `t.*` gibi tam-satır başvuruları. */
  readonly wholeRowRefs: readonly string[];
  readonly hasStarSelect: boolean;
}

export interface DbCapabilities {
  readonly readOnlyTx: boolean;
  readonly statementTimeout: boolean;
  /** Sonuç sütunlarının kaynak tablo/sütun bilgisi (yalnız doğrudan başvurularda). */
  readonly columnOrigin: boolean;
}

export interface ReadLimits {
  readonly maxRows: number;
  readonly maxBytes: number;
  readonly timeoutMs: number;
}

export interface ColumnInfo {
  readonly name: string;
  readonly origin?: { readonly relation: string; readonly column: string };
}

export interface ReadResult {
  readonly columns: readonly ColumnInfo[];
  readonly rows: readonly (readonly unknown[])[];
  readonly truncated: boolean;
  readonly totalRowsSeen: number;
}

export interface SchemaDescription {
  readonly schemas: readonly {
    readonly name: string;
    readonly tables: readonly {
      readonly name: string;
      readonly columns: readonly { readonly name: string; readonly type: string }[];
    }[];
  }[];
}

export interface DbConnectOptions {
  /** Profilin pini: kimlik gönderilmeden ÖNCE sunucu adresi (ve varsa CA parmak izi) bununla doğrulanır. */
  readonly pin: { readonly endpoint: string; readonly caFingerprint?: string };
  readonly signal?: AbortSignal;
  /** Nitelendirilmemiş adların çözüleceği şema (`search_path`). */
  readonly defaultSchema?: string;
}

/** Veritabanı adapter'ının sürücü yüzü (PostgreSQL ilk; MySQL/SQL Server aynı arayüz). */
export interface DatabaseDriver {
  readonly dialect: SqlDialect;
  readonly capabilities: DbCapabilities;
  connect(handle: CredentialHandle, role: DbRole, opts: DbConnectOptions): Promise<DbSession>;
  classify(sql: string): SqlClassification;
}

export interface DbSession {
  applyReaderGuards(limits: ReadLimits): Promise<void>;
  executeRead(sql: string, limits: ReadLimits): Promise<ReadResult>;
  describeSchema(scopes: readonly string[]): Promise<SchemaDescription>;
  explain(sql: string): Promise<string>;
  close(): Promise<void>;
}
