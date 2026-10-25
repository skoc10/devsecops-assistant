import { createHmac, randomBytes } from "node:crypto";
import type { ColumnInfo } from "@ops/contracts";
import { Counter, redacted } from "./counter.ts";
import { globalRegExp, statelessRegExp } from "./regex.ts";

/**
 * M4: alan/kolon maskesi. Sütun adı kuralları + değer dedektörleri.
 * Sınır (Best-effort): ifade/köken hileleri (`lower(email)`, `to_jsonb(t)`) için asıl kontrol
 * DB adapter'ındaki AST kuralı ve maskeli view'lardır; bu katman ikinci hattır.
 */
export type MaskAction = "hash" | "truncate" | "drop" | "redact";

export interface ColumnRule {
  /** Sütun adı (veya `tablo.sütun` kökeni) üzerinde eşleşen desen. */
  readonly match: RegExp;
  readonly action: MaskAction;
  /** `truncate` için korunacak karakter sayısı. */
  readonly keep?: number;
}

export interface MaskingRules {
  readonly columns: readonly ColumnRule[];
  /** Değer dedektörleri (email, kart, IBAN, telefon) açık mı? Varsayılan: evet. */
  readonly detectors?: boolean;
  readonly extraDetectors?: readonly { readonly id: string; readonly regex: RegExp }[];
}

export const DEFAULT_COLUMN_RULES: readonly ColumnRule[] = [
  { match: /(?:^|[._])(?:e?mail|eposta)(?:$|[._])/i, action: "hash" },
  { match: /(?:phone|telefon|msisdn|mobile|gsm)/i, action: "truncate", keep: 3 },
  { match: /(?:card|kart)[_-]?(?:no|number|num)?$|^pan$|iban/i, action: "redact" },
  { match: /(?:password|passwd|parola|sifre|şifre|secret|token|api[_-]?key|credential|salt|hash)/i, action: "redact" },
  { match: /(?:ssn|national[_-]?id|tckn|tc[_-]?kimlik|passport|pasaport)/i, action: "redact" },
];

export const DEFAULT_MASKING: MaskingRules = { columns: DEFAULT_COLUMN_RULES, detectors: true };

/** Oturum başına rastgele tuz: aynı değer aynı oturumda aynı hash'e gider (join mümkün), oturumlar arası değil. */
export class MaskingContext {
  private readonly salt = randomBytes(16);

  hash(value: string): string {
    return `h:${createHmac("sha256", this.salt).update(value).digest("hex").slice(0, 10)}`;
  }
}

function luhn(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function ibanValid(raw: string): boolean {
  const s = raw.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = ch >= "A" ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48;
    rem = Number(`${rem}${v}`) % 97;
  }
  return rem === 1;
}

// yerel kısım ≤ 64, alan adı ≤ 253 (RFC 5321/1035): sınırsız `+` her konumda satır sonuna kadar tarıyordu
// (`a`×n tek satırda karesel). Daha uzun bir koşuda eşleşme yine bulunur, yalnız baştaki fazlalık kalır.
const EMAIL = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}/g;
const CARD = /\b(?:\d[ -]?){13,19}\b/g;
const IBAN = /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}\s?[A-Z0-9]{1,4}\b/g;
const PHONE = /(?:\+\d{1,3}[ -]?)(?:\(?\d{2,4}\)?[ -]?){2,4}\d{2,4}\b/g;

/** Serbest metin/hücre içinde PII dedektörleri. */
export function maskByDetectors(text: string, counter: Counter, rules: MaskingRules = DEFAULT_MASKING): string {
  if (rules.detectors === false) return text;
  let out = text.replace(EMAIL, () => {
    counter.add("m4:email");
    return redacted("email");
  });
  out = out.replace(CARD, (m) => {
    const digits = m.replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhn(digits)) {
      counter.add("m4:card");
      return redacted("card");
    }
    return m;
  });
  out = out.replace(IBAN, (m) => {
    if (!ibanValid(m)) return m;
    counter.add("m4:iban");
    return redacted("iban");
  });
  out = out.replace(PHONE, () => {
    counter.add("m4:phone");
    return redacted("phone");
  });
  for (const d of rules.extraDetectors ?? []) {
    // `g`siz/`y`li dedektör yalnız ilk/ardışık geçişi maskelerdi
    out = out.replace(globalRegExp(d.regex), () => {
      counter.add(`m4:${d.id}`);
      return redacted(d.id);
    });
  }
  return out;
}

function applyAction(action: ColumnRule, value: unknown, ctx: MaskingContext, counter: Counter, col: string): unknown {
  if (value === null || value === undefined) return value;
  const s = typeof value === "string" ? value : JSON.stringify(value);
  counter.add(`m4:column:${action.action}`);
  switch (action.action) {
    case "drop":
      return undefined;
    case "hash":
      return ctx.hash(s);
    case "truncate": {
      const keep = action.keep ?? 2;
      return s.length <= keep ? redacted(col) : `${s.slice(0, keep)}…`;
    }
    default:
      return redacted(col);
  }
}

export interface Table {
  readonly columns: readonly ColumnInfo[];
  readonly rows: readonly (readonly unknown[])[];
}

/** Hücre içi iç içelik sınırı (M1 tüm değeri 48'de keser; doğrudan `maskTable` çağrısında yığın koruması). */
const MAX_CELL_DEPTH = 32;

/**
 * Kural eşleşmeyen hücre: dizge değilse de (jsonb nesnesi, dizi) içindeki dizgelere ve nesne anahtarlarına
 * dedektörler uygulanır (`processOutput`'un tablo dışı yolundaki `mapStrings` ile aynı kapsam). Sayı,
 * boolean, null ve düz olmayan nesneler (Date, Buffer) olduğu gibi kalır.
 */
function maskCell(v: unknown, counter: Counter, rules: MaskingRules, depth = 0): unknown {
  if (typeof v === "string") return maskByDetectors(v, counter, rules);
  if (v === null || typeof v !== "object" || rules.detectors === false) return v;
  if (depth >= MAX_CELL_DEPTH) {
    counter.add("m4:max-depth");
    return "‹dropped:max-depth›";
  }
  if (Array.isArray(v)) return v.map((x) => maskCell(x, counter, rules, depth + 1));
  const proto: unknown = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) return v;
  // `Object.fromEntries`: `__proto__` anahtarı prototip atamaz, düz özellik olarak kalır
  return Object.fromEntries(
    Object.entries(v).map(([k, x]) => [maskByDetectors(k, counter, rules), maskCell(x, counter, rules, depth + 1)]),
  );
}

/**
 * Tabloya sütun kuralları + (kural eşleşmeyen veya kökeni bilinmeyen sütunlar için) değer
 * dedektörleri uygulanır. `drop` eylemi sütunu tümüyle kaldırır.
 */
export function maskTable(table: Table, rules: MaskingRules, ctx: MaskingContext, counter: Counter): Table {
  const ruleFor = (c: ColumnInfo): ColumnRule | undefined => {
    const names = [c.name, c.origin ? `${c.origin.relation}.${c.origin.column}` : ""];
    // `g`/`y`li kural `lastIndex` taşır: aynı adlı ikinci sütun maskesiz kalırdı
    return rules.columns.find((r) => names.some((n) => n !== "" && statelessRegExp(r.match).test(n)));
  };
  const plan = table.columns.map((c) => ({ col: c, rule: ruleFor(c) }));
  const keepIdx = plan.map((p, i) => ({ p, i })).filter(({ p }) => p.rule?.action !== "drop");
  const columns = keepIdx.map(({ p }) => p.col);
  const rows = table.rows.map((row) =>
    keepIdx.map(({ p, i }) => {
      const v = row[i];
      if (p.rule) return applyAction(p.rule, v, ctx, counter, p.col.name);
      return maskCell(v, counter, rules);
    }),
  );
  for (const p of plan) if (p.rule?.action === "drop") counter.add("m4:column:drop");
  return { columns, rows };
}
