import { estimateTokens } from "@ops/contracts";
import type { RedactionSummary } from "@ops/contracts";
import { clampListsDeep, compactForModel } from "./compact.ts";
import { Counter, mapStrings } from "./counter.ts";
import { stripControlChars } from "./envelope.ts";
import { KnownSecrets } from "./known.ts";
import { truncateString } from "./limits.ts";
import { DEFAULT_MASKING, MaskingContext, maskByDetectors, maskTable } from "./masking.ts";
import type { MaskingRules, Table } from "./masking.ts";
import { applyPatternRules } from "./patterns.ts";
import type { PatternRule } from "./patterns.ts";
import { applyStructural, getProfile } from "./structural.ts";

export interface OutputPolicy {
  /** M1 profil adı (`default` veya adapter'ın kaydettiği). */
  readonly structuralProfile: string;
  /** Kanıt (tam redakte sonuç) için bayt üst sınırı. */
  readonly maxBytes: number;
  readonly maxItems: number;
  /** Modele giden kompakt görünüm için token tavanı. */
  readonly maxOutputTokens: number;
  readonly projection?: { readonly defaultFields: readonly string[]; readonly selectable: boolean };
  readonly select?: readonly string[];
  /** `null`/yok: M4 uygulanmaz. */
  readonly masking?: MaskingRules | null;
  readonly maskingContext?: MaskingContext;
  readonly known: KnownSecrets;
  readonly entropy?: boolean;
  readonly extraPatternRules?: readonly PatternRule[];
  readonly logLike?: boolean;
}

export interface ProcessedOutput {
  /** Tam redakte kanıt gövdesi (Evidence Store'a). */
  readonly evidence: unknown;
  readonly evidenceText: string;
  /** Modele giden kompakt görünüm; `byReference` ise yok. */
  readonly view?: unknown;
  readonly viewText: string;
  readonly summary: string;
  readonly byReference: boolean;
  readonly truncated: boolean;
  readonly redactions: RedactionSummary[];
  /** Modele giden görünümün token tahmini. */
  readonly tokens: number;
  /** Tam kanıtın token tahmini. */
  readonly fullTokens: number;
}

/** M2 + M3 + kontrol karakteri temizliği: serbest metin (hata mesajı, kullanıcı girdisi, denetim) için. */
export function scrubText(
  text: string,
  known: KnownSecrets,
  counter: Counter = new Counter(),
  opts: { entropy?: boolean; extraPatternRules?: readonly PatternRule[] } = {},
): string {
  const cleaned = stripControlChars(text);
  const patterned = applyPatternRules(cleaned, counter, opts);
  return known.scrub(patterned, counter);
}

function isTable(v: unknown): v is Table {
  if (v === null || typeof v !== "object") return false;
  const t = v as { columns?: unknown; rows?: unknown };
  return (
    Array.isArray(t.columns) &&
    t.columns.every((c) => c !== null && typeof c === "object" && typeof (c as { name?: unknown }).name === "string") &&
    Array.isArray(t.rows)
  );
}

function limitEvidence(value: unknown, maxBytes: number, maxItems: number): { value: unknown; truncated: boolean } {
  let truncated = false;
  let cur = clampListsDeep(value, maxItems);
  if (JSON.stringify(cur) !== JSON.stringify(value)) truncated = true;
  let cap = 4096;
  while (Buffer.byteLength(JSON.stringify(cur) ?? "", "utf8") > maxBytes && cap >= 128) {
    cur = mapStrings(cur, (s) => {
      const r = truncateString(s, cap);
      if (r.truncated) truncated = true;
      return r.text;
    });
    cap = Math.floor(cap / 2);
  }
  const text = JSON.stringify(cur) ?? "";
  if (Buffer.byteLength(text, "utf8") > maxBytes) {
    const r = truncateString(text, maxBytes);
    return { value: { _truncated: true, preview: r.text }, truncated: true };
  }
  return { value: cur, truncated };
}

/**
 * Çıktı boru hattı (PEP adım 12): M1 → M2 → M3 → (M4) → M5 → kompaktlaştırma.
 * Kompaktlaştırma redaksiyondan SONRA ve redakte veri üzerindedir: modele giden görünüm tam
 * redakte kanıtın türevidir.
 */
export function processOutput(data: unknown, summary: string | undefined, policy: OutputPolicy): ProcessedOutput {
  const counter = new Counter();
  const patternOpts = { entropy: policy.entropy ?? true, extraPatternRules: policy.extraPatternRules ?? [] };

  // M1
  let value = applyStructural(data, getProfile(policy.structuralProfile), counter);
  // M2 + M3 (+ kontrol karakterleri) her string ve anahtar üzerinde
  value = mapStrings(value, (s) => scrubText(s, policy.known, counter, patternOpts));
  // M4
  if (policy.masking) {
    const rules = policy.masking ?? DEFAULT_MASKING;
    const ctx = policy.maskingContext ?? new MaskingContext();
    value = isTable(value)
      ? maskTable(value, rules, ctx, counter)
      : mapStrings(value, (s) => maskByDetectors(s, counter, rules));
  }
  // M5
  const limited = limitEvidence(value, policy.maxBytes, policy.maxItems);
  const evidence = limited.value;
  const evidenceText = JSON.stringify(evidence) ?? "null";

  // kompaktlaştırma (redakte kanıttan)
  const compact = compactForModel(evidence, {
    ...(policy.projection ? { projection: policy.projection } : {}),
    ...(policy.select ? { select: policy.select } : {}),
    maxTokens: policy.maxOutputTokens,
    maxItems: policy.maxItems,
    ...(policy.logLike !== undefined ? { logLike: policy.logLike } : {}),
  });

  const safeSummary = scrubText(summary ?? "", policy.known, counter, patternOpts);
  return {
    evidence,
    evidenceText,
    ...(compact.byReference ? {} : { view: compact.view }),
    viewText: compact.text,
    summary: safeSummary,
    byReference: compact.byReference,
    truncated: limited.truncated || compact.truncated,
    redactions: counter.toSummary(),
    tokens: compact.tokens,
    fullTokens: estimateTokens(evidenceText),
  };
}
