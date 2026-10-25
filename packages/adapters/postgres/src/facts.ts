/** Rolün fiili yetkileri (sunucudan okunur). Doktor bunları beyan edilen tavanla karşılaştırır. */
export interface PrivilegeFacts {
  readonly role: {
    readonly name: string;
    readonly superuser: boolean;
    readonly createRole: boolean;
    readonly createDb: boolean;
    readonly replication: boolean;
    readonly bypassRls: boolean;
  };
  /** Yazma/yürütme yetkisi veren önceden tanımlı rol üyelikleri (ör. pg_write_server_files). */
  readonly dangerousRoles: readonly string[];
  /** Tüm şemaları okutan üyelikler (pg_read_all_data). */
  readonly broadReadRoles: readonly string[];
  readonly databaseCreate: boolean;
  readonly databaseTemp: boolean;
  /** CREATE yetkisi olan, sistem dışı şemalar. */
  readonly schemaCreate: readonly string[];
  /** INSERT/UPDATE/DELETE/TRUNCATE yetkisi olan ilişkiler (en çok 20) ve toplam. */
  readonly writableRelations: readonly string[];
  readonly writableRelationCount: number;
  /** İzinli şemalar DIŞINDA yazma yetkisi olan şemalar ve ilişki sayıları (yazıcı profili için kapsam aşımı). */
  readonly writableOutsideScopes: readonly { readonly schema: string; readonly tables: number }[];
  /** TRUNCATE yetkisi olan ilişki sayısı (yok etme sınıfı). */
  readonly truncatableRelations: number;
  /** Rolün sahibi olduğu ilişki sayısı: sahiplik DROP/ALTER/TRUNCATE'i örtük verir (yok etme sınıfı). */
  readonly ownedRelations: number;
  readonly writableSequences: readonly string[];
  /** Çalıştırma yetkisi olan tehlikeli yerleşik/eklenti fonksiyonları. */
  readonly dangerousFunctions: readonly string[];
  /** İzinli şemalar DIŞINDA okunabilen şemalar ve tablo sayıları. */
  readonly readableOutsideScopes: readonly { readonly schema: string; readonly tables: number }[];
  /** Beyan edilmiş ama sunucuda bulunmayan şemalar. */
  readonly missingScopes: readonly string[];
  readonly transactionReadOnly: boolean;
  readonly tls: boolean;
  readonly serverVersion: string;
  readonly database: string;
}

export interface PgStats {
  readonly connections: Readonly<Record<string, number>>;
  readonly waitingOnLocks: number;
  readonly blockedSessions: number;
  readonly longestActiveSec: number | null;
  readonly oldestTransactionSec: number | null;
  readonly databaseSizeBytes: number;
  readonly inRecovery: boolean;
  readonly replayLagSec: number | null;
  readonly replicas: number;
  readonly counters: {
    readonly commits: number;
    readonly rollbacks: number;
    readonly deadlocks: number;
    readonly tempFiles: number;
    readonly tempBytes: number;
    readonly cacheHitRatio: number | null;
  };
  /** 5 sn'den uzun süredir çalışan sorgular; metin NORMALLEŞTİRİLMİŞ (değişmezsiz) veya yok. */
  readonly longQueries: readonly { readonly durationSec: number; readonly state: string; readonly wait: string | null; readonly query: string | null }[];
  readonly note?: string;
}
