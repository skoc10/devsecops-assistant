import { readFile } from "node:fs/promises";
import { parse } from "yaml";
import { z } from "zod";
import { DEFAULT_MASKING } from "@ops/redaction";
import type { ColumnRule, MaskAction, MaskingRules } from "@ops/redaction";

/**
 * `masking.yaml` — maskeli sütun bildirimi. İKİ yerde kullanılır:
 *  1. AST kuralı (`maskedViolations`): maskeli sütun yalnız doğrudan seçim öğesi olabilir; ifade/koşul/
 *     JOIN (ON/USING)/`SELECT *`/tam-satır başvurusu (`f(t)`, `t::text`, `t.to_jsonb`) ve maskeli tabloyla küme
 *     işlemi, NATURAL JOIN, sütun takma adı listesi sorgu çalışmadan REDDEDİLİR (köken bildirilmeyen çıktılar).
 *  2. Köken kuralı (M4 b): sonuç sütununun kökeni biliniyorsa değer maskelenir (hash/kısalt/at/redakte).
 * Bu iki katman Best-effort'tur; en güçlü savunma reader rolünü yalnız maskeli view'lara yetkilendirmektir.
 */
const ActionSchema = z.enum(["hash", "truncate", "drop", "redact"]);

export const MaskingConfigSchema = z.strictObject({
  version: z.literal(1),
  /** Anahtar: profil kimliği veya `*`. Değer: tablo (şemasız ad) → sütunlar. */
  profiles: z
    .record(
      z.string().min(1),
      z.strictObject({
        maskedColumns: z.record(z.string().min(1), z.array(z.string().min(1)).min(1)),
        action: ActionSchema.optional(),
        keep: z.number().int().min(0).max(8).optional(),
      }),
    )
    .default({}),
});
export type MaskingConfig = z.infer<typeof MaskingConfigSchema>;

export const EMPTY_MASKING_CONFIG: MaskingConfig = { version: 1, profiles: {} };

export function parseMaskingConfig(text: string): MaskingConfig {
  return MaskingConfigSchema.parse(parse(text) ?? { version: 1 });
}

export async function loadMaskingConfig(path: string): Promise<MaskingConfig> {
  return parseMaskingConfig(await readFile(path, "utf8"));
}

function entriesFor(cfg: MaskingConfig, profileId: string): { table: string; column: string; action: MaskAction; keep?: number }[] {
  const out: { table: string; column: string; action: MaskAction; keep?: number }[] = [];
  for (const key of ["*", profileId]) {
    const p = cfg.profiles[key];
    if (!p) continue;
    for (const [table, cols] of Object.entries(p.maskedColumns)) {
      for (const column of cols) out.push({ table: (table.split(".").pop() as string).toLowerCase(), column: column.toLowerCase(), action: p.action ?? "redact", ...(p.keep !== undefined ? { keep: p.keep } : {}) });
    }
  }
  return out;
}

/** AST kuralı için: tablo (küçük harf, şemasız) → maskeli sütunlar. */
export function maskedMapFor(cfg: MaskingConfig, profileId: string): ReadonlyMap<string, ReadonlySet<string>> {
  const m = new Map<string, Set<string>>();
  for (const e of entriesFor(cfg, profileId)) {
    const set = m.get(e.table) ?? new Set<string>();
    set.add(e.column);
    m.set(e.table, set);
  }
  return m;
}

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** M4 için kural kümesi: varsayılan sütun adı kuralları + maskeli sütunların köken (`şema.tablo.sütun`) eşleşmesi. */
export function maskingRulesFor(cfg: MaskingConfig, profileId: string): MaskingRules {
  const extra: ColumnRule[] = entriesFor(cfg, profileId).map((e) => ({
    match: new RegExp(`(?:^|\\.)${esc(e.table)}\\.${esc(e.column)}$`, "i"),
    action: e.action,
    ...(e.keep !== undefined ? { keep: e.keep } : {}),
  }));
  return { ...DEFAULT_MASKING, columns: [...extra, ...DEFAULT_MASKING.columns] };
}
