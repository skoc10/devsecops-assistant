import { Counter, isRedactedToken, redacted } from "./counter.ts";

/**
 * M2: desen + entropi. Kural seti gitleaks tarzı bakımlı listelerden esinlenir ve KASITLI olarak
 * dardır (yanlış pozitif = kanıt kaybı). Genişletme: kullanıcı kuralları `extraRules` ile eklenir.
 * Sınır (Best-effort): bilinmeyen biçimdeki secret kaçabilir → M3 ve egress kontrolü ikinci hat.
 */
export interface PatternRule {
  readonly id: string;
  readonly regex: RegExp;
  /** Yalnız bu yakalama grubu maskelenir (yoksa tüm eşleşme). */
  readonly group?: number;
  /** Eşleşen değeri doğrulayan ek süzgeç (false → maskeleme). */
  readonly accept?: (value: string) => boolean;
}

const TEMPLATE_VALUE = /^(?:true|false|null|nil|none|undefined|\*+|x+|<[^>]*>|\$\{?[A-Za-z_][^}]*\}?|\{\{.*\}\}|%[sd]|\[.*\]|\{.*\})$/i;

function plausibleSecretValue(v: string): boolean {
  if (isRedactedToken(v)) return false;
  if (TEMPLATE_VALUE.test(v)) return false;
  if (/^\d{1,8}$/.test(v)) return false; // kısa saf sayılar: sayaç/port/süre
  return v.length >= 6 || /[A-Za-z]/.test(v) && v.length >= 4;
}

export const PATTERN_RULES: readonly PatternRule[] = [
  {
    id: "private-key-block",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  {
    // BEGIN var, END yok (kırpılmış çıktı): başlıktan sonraki makul uzunlukta base64'ü de maskele
    id: "private-key-block",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[A-Za-z0-9+/=\s]{0,6000}/g,
  },
  { id: "jwt", regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { id: "aws-access-key-id", regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g },
  { id: "github-token", regex: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/g },
  { id: "gitlab-token", regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { id: "slack-token", regex: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { id: "google-api-key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "stripe-key", regex: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { id: "npm-token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "bearer-token", regex: /\b(Bearer\s+)([A-Za-z0-9._~+/=-]{16,})/gi, group: 2 },
  { id: "basic-auth", regex: /\b(Basic\s+)([A-Za-z0-9+/=]{12,})/g, group: 2 },
  // scheme://user:PAROLA@host
  { id: "url-credentials", regex: /\b([a-z][a-z0-9+.-]*:\/\/[^\s:/?#@]+:)([^\s@/]+)(@)/gi, group: 2 },
  { id: "azure-storage-key", regex: /(AccountKey=)([A-Za-z0-9+/=]{20,})/g, group: 2 },
  { id: "sas-signature", regex: /([?&]sig=)([A-Za-z0-9%+/=]{16,})/g, group: 2 },
  {
    id: "kv-secret",
    regex:
      /((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential)[A-Za-z0-9_.-]*["']?\s*[:=]\s*["']?)([^\s"',;]{4,})/gi,
    group: 2,
    accept: plausibleSecretValue,
  },
];

/** PEM sertifika blokları secret değildir; token ekonomisi için sıkıştırılır (kompaktlaştırma). */
const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

function shannon(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Karışık harf+rakam, hash/UUID/yol olmayan, yüksek entropili uzun jeton mu? */
export function looksLikeHighEntropySecret(token: string): boolean {
  if (token.length < 28 || token.length > 512) return false;
  if (/^[0-9a-f]+$/i.test(token)) return false; // özet/hash/commit
  if (/^[0-9a-f-]{36}$/i.test(token)) return false; // UUID
  const hasUpper = /[A-Z]/.test(token);
  const hasLower = /[a-z]/.test(token);
  const hasDigit = /\d/.test(token);
  if (!(hasUpper && hasLower && hasDigit)) return false;
  return shannon(token) >= 4.2;
}

const TOKEN_CANDIDATE = /[A-Za-z0-9+/_=-]{28,512}/g;

export interface PatternOptions {
  readonly entropy?: boolean;
  readonly extraRules?: readonly PatternRule[];
}

export function applyPatternRules(text: string, counter: Counter, opts: PatternOptions = {}): string {
  let out = text;

  out = out.replace(PEM_CERT, (m) => {
    counter.add("compact:pem-certificate");
    return `‹pem:CERTIFICATE ${m.length}B›`;
  });

  for (const rule of [...PATTERN_RULES, ...(opts.extraRules ?? [])]) {
    out = out.replace(rule.regex, (...args: unknown[]) => {
      const match = args[0] as string;
      if (rule.group === undefined) {
        counter.add(rule.id);
        return redacted(rule.id);
      }
      const groups = args.slice(1, 1 + 9) as (string | undefined)[];
      const value = groups[rule.group - 1];
      if (value === undefined) return match;
      if (rule.accept && !rule.accept(value)) return match;
      if (isRedactedToken(value)) return match;
      counter.add(rule.id);
      return match.replace(value, redacted(rule.id));
    });
  }

  if (opts.entropy ?? true) {
    out = out.replace(TOKEN_CANDIDATE, (tok) => {
      if (isRedactedToken(tok)) return tok;
      if (!looksLikeHighEntropySecret(tok)) return tok;
      counter.add("high-entropy");
      return redacted("high-entropy");
    });
  }
  return out;
}
