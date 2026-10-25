import { z } from "zod";
import { defineTool } from "@ops/contracts";
import type { ToolDefinition, ToolDescriptorMeta } from "@ops/contracts";
import { MAX_SQL_CHARS } from "@ops/classifiers";
import { SIMPLE_IDENT } from "./identifiers.ts";
import { MAX_APPROVED_ROWS } from "./change.ts";

const base = {
  profileKind: "db",
  scope: "target",
  network: "allowlisted",
  class: "read",
  idempotent: true,
  toolset: "database",
  redactionProfile: "default",
} as const satisfies Partial<ToolDescriptorMeta>;

const ident = z.string().regex(SIMPLE_IDENT);
const sql = z.string().min(1).max(MAX_SQL_CHARS);

export const datasourceDescribe = defineTool(
  {
    ...base,
    name: "db.datasource.describe",
    description: "Veri kaynağının bağlantısız özeti: ad, ortam, rol (reader), izinli şemalar, limitler.",
    sensitivity: "none",
    limits: { timeoutMs: 5_000, maxBytes: 20_000, maxItems: 50, maxOutputTokens: 600 },
    untrustedOutput: false,
    typicalOutputTokens: 150,
  },
  z.strictObject({}),
);

export const schemaDescribe = defineTool(
  {
    ...base,
    name: "db.schema.describe",
    description: "Şema kataloğu: tablolar ve sütun türleri (yalnız okunabilir sütunlar; veri yok). schema/table ile daralt.",
    sensitivity: "internal",
    limits: { timeoutMs: 15_000, maxBytes: 200_000, maxItems: 100, maxOutputTokens: 1_500 },
    untrustedOutput: false,
    projection: { defaultFields: ["schemas", "note", "truncated"], selectable: false },
    typicalOutputTokens: 700,
  },
  z.strictObject({ schema: ident.optional(), table: ident.optional(), limit: z.number().int().min(1).max(100).optional() }),
);

export const queryRead = defineTool(
  {
    ...base,
    name: "db.query.read",
    description: "Tek bir SELECT çalıştırır (salt okunur; satır/süre/bayt sınırlı; maskeli sütunlar yalnız doğrudan seçilebilir). Şema nitelikli adlar kullanın.",
    sensitivity: "pii",
    limits: { timeoutMs: 10_000, maxBytes: 256 * 1024, maxItems: 500, maxOutputTokens: 1_500 },
    untrustedOutput: true,
    projection: { defaultFields: ["columns", "rows", "rowCount", "truncated", "note", "_total", "_shown"], selectable: false },
    typicalOutputTokens: 800,
  },
  z.strictObject({ sql, maxRows: z.number().int().min(1).max(500).optional() }),
);

export const queryExplain = defineTool(
  {
    ...base,
    name: "db.query.explain",
    description: "SELECT için EXPLAIN planı (ANALYZE yok: sorgu çalıştırılmaz). Yalnız SELECT metnini verin.",
    sensitivity: "internal",
    limits: { timeoutMs: 10_000, maxBytes: 64 * 1024, maxItems: 300, maxOutputTokens: 2_500 },
    untrustedOutput: false,
    projection: { defaultFields: ["plan", "note"], selectable: false },
    typicalOutputTokens: 600,
  },
  z.strictObject({ sql }),
);

export const statsSummary = defineTool(
  {
    ...base,
    name: "db.stats.summary",
    description: "Bağlantı/kilit/uzun sorgu/boyut/replikasyon özeti. Sorgu metinleri değişmezsiz (normalleştirilmiş) gösterilir.",
    sensitivity: "internal",
    limits: { timeoutMs: 10_000, maxBytes: 64 * 1024, maxItems: 20, maxOutputTokens: 1_200 },
    untrustedOutput: true,
    typicalOutputTokens: 400,
  },
  z.strictObject({}),
);

export const DB_READ_TOOLS: readonly ToolDefinition[] = [datasourceDescribe, schemaDescribe, queryRead, queryExplain, statsSummary];

const changeBase = { ...base, toolset: "database-change", sensitivity: "internal" } as const satisfies Partial<ToolDescriptorMeta>;
const maxRows = z.number().int().min(1).max(MAX_APPROVED_ROWS).optional();

export const changePropose = defineTool(
  {
    ...changeBase,
    name: "db.change.propose",
    description: "INSERT/UPDATE/DELETE/DDL ifade kümesini ÇALIŞTIRMADAN sınıflar: ifade türü, etkilenecek tablolar, gereken sınıf, tahmini satır sayısı, ifade seti özeti. Önce bunu çağırın.",
    limits: { timeoutMs: 20_000, maxBytes: 64 * 1024, maxItems: 20, maxOutputTokens: 1_200 },
    untrustedOutput: false,
    typicalOutputTokens: 400,
  },
  z.strictObject({ sql, maxRows }),
);

export const changeApply = defineTool(
  {
    ...changeBase,
    name: "db.change.apply",
    description: "Onaylanan ifade kümesini TEK işlemde uygular (yazıcı profili). Etkilenen satır `maxRows`ı aşarsa veya hata olursa tamamı ROLLBACK. propose ile AYNI sql/maxRows verilir.",
    class: "mutate",
    idempotent: false,
    limits: { timeoutMs: 60_000, maxBytes: 64 * 1024, maxItems: 20, maxOutputTokens: 800 },
    untrustedOutput: false,
    typicalOutputTokens: 250,
  },
  z.strictObject({ sql, maxRows }),
);

export const DB_CHANGE_TOOLS: readonly ToolDefinition[] = [changePropose, changeApply];
export const DB_ALL_TOOLS: readonly ToolDefinition[] = [...DB_READ_TOOLS, ...DB_CHANGE_TOOLS];
export const DB_WRITE_TOOL_NAMES: ReadonlySet<string> = new Set(["db.change.apply"]);
