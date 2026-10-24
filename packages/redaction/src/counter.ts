import type { RedactionSummary } from "@ops/contracts";

/** Kural başına redaksiyon sayacı. */
export class Counter {
  private readonly counts = new Map<string, number>();

  add(rule: string, n = 1): void {
    if (n <= 0) return;
    this.counts.set(rule, (this.counts.get(rule) ?? 0) + n);
  }

  total(): number {
    let t = 0;
    for (const v of this.counts.values()) t += v;
    return t;
  }

  toSummary(): RedactionSummary[] {
    return [...this.counts.entries()]
      .map(([rule, count]) => ({ rule, count }))
      .sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule));
  }
}

export function redacted(id: string): string {
  return `‹redacted:${id}›`;
}

export function isRedactedToken(s: string): boolean {
  return s.includes("‹redacted:") || s.includes("‹pem:") || s.includes("‹dropped:");
}

/** Metin içindeki tüm string'leri (ve nesne anahtarlarını) dönüştürür. */
export function mapStrings(value: unknown, fn: (s: string) => string): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((v) => mapStrings(v, fn));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[fn(k)] = mapStrings(v, fn);
    }
    return out;
  }
  return value;
}
