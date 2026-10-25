import { canonicalViews, foldCanonical } from "./canonical.ts";
import { Counter, redacted } from "./counter.ts";

/** Bu uzunluğun altındaki değerler (ör. "123456") güvenle maskelenemez: yanlış pozitif seli. */
export const MIN_KNOWN_SECRET_BYTES = 8;

/** Kanonik taramada en çok kaç katman kaçış çözülür (çift kodlama: `%2526`, `&amp;amp;`, JSON içinde JSON). */
const MAX_DECODE_ROUNDS = 2;

/** Bir secret değerinin sızabileceği tüm biçimler (ham, base64 hizalamaları, url, hex, json, satırlar). */
export function secretNeedles(value: Uint8Array | string): string[] {
  const raw = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
  const needles = new Set<string>();
  const text = raw.toString("utf8");
  const roundTrips = Buffer.from(text, "utf8").equals(raw);

  if (roundTrips) {
    needles.add(text);
    needles.add(encodeURIComponent(text));
    needles.add(JSON.stringify(text).slice(1, -1));
    // çok satırlı materyal (PEM, kubeconfig alanları): her uzun satır ayrı iğne
    for (const line of text.split(/\r?\n/)) {
      const t = line.trim();
      if (t.length >= 16) needles.add(t);
    }
  }
  needles.add(raw.toString("hex"));
  needles.add(raw.toString("hex").toUpperCase());

  for (let offset = 0; offset < 3; offset++) {
    const shifted = Buffer.concat([Buffer.alloc(offset), raw]);
    const b64 = shifted.toString("base64");
    const first = Math.ceil((offset * 8) / 6);
    const last = Math.floor((shifted.length * 8) / 6);
    const core = b64.slice(first, Math.max(first, last));
    if (core.length >= 8) {
      needles.add(core);
      needles.add(core.replace(/\+/g, "-").replace(/\//g, "_"));
    }
  }
  return [...needles].filter((n) => n.length >= 8);
}

/**
 * Metin biçimli değerin kanonik iğneleri (katlanmış değer + çok satırlı materyalin uzun satırları).
 * Metin tarafı kanonik görünümlerde çözülür; böylece secret başına iğne sayısı kodlama birleşimlerinden
 * bağımsız kalır. Geçersiz UTF-8 baytları için yok (yalnız bayt tabanlı biçimler).
 */
export function canonicalNeedles(value: Uint8Array | string): string[] {
  const raw = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
  const text = raw.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(raw)) return [];
  const needles = new Set<string>([foldCanonical(text)]);
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (t.length >= 16) needles.add(foldCanonical(t));
  }
  return [...needles].filter((n) => n.length >= 8);
}

interface Needle {
  readonly needle: string;
  readonly label: string;
}

/** Özgün metinde maskelenecek `[a, b)` aralığı. */
interface Span {
  readonly a: number;
  b: number;
  readonly label: string;
}

const byLengthDesc = (a: Needle, b: Needle): number => b.needle.length - a.needle.length;

/**
 * M3: bilinen-secret taraması. Broker'ın oturumda verdiği her değer buraya kaydedilir; çıktı,
 * hata mesajı, denetim ve kullanıcı girdisi bu değerlerin HERHANGİ bir biçimi için taranır:
 *  1. birebir iğneler (ham, url, json, hex, base64 hizalamaları, uzun satırlar);
 *  2. kanonik tarama (`canonical.ts`): metin katlanır ve en çok MAX_DECODE_ROUNDS katman çözülür; harf
 *     büyüklüğü, form/yüzde kodlaması, `\uXXXX`/`\/` kaçışları ve HTML varlıkları (iç içe olanlar dahil)
 *     ile yeniden kodlanmış değer özgün metindeki aralığıyla maskelenir.
 * Bellekte tutulan iğneler secret türevidir: nesne sızdırılmaz, yalnız `scrub` açığa çıkar.
 */
export class KnownSecrets {
  private readonly byLabel = new Map<string, { exact: string[]; canonical: string[] }>();
  private sorted: Needle[] = [];
  private canonical: Needle[] = [];
  private minCanonical = Number.POSITIVE_INFINITY;

  /** Eklenirse `true`; çok kısa değer maskelenemez ve `false` döner (çağıran uyarmalı). */
  add(label: string, value: Uint8Array | string): boolean {
    const byteLen = typeof value === "string" ? Buffer.byteLength(value) : value.length;
    if (byteLen < MIN_KNOWN_SECRET_BYTES) return false;
    this.byLabel.set(label, { exact: secretNeedles(value), canonical: canonicalNeedles(value) });
    this.rebuild();
    return true;
  }

  remove(label: string): void {
    this.byLabel.delete(label);
    this.rebuild();
  }

  clear(): void {
    this.byLabel.clear();
    this.rebuild();
  }

  get size(): number {
    return this.byLabel.size;
  }

  private rebuild(): void {
    const exact: Needle[] = [];
    const canonical: Needle[] = [];
    for (const [label, n] of this.byLabel) {
      for (const needle of n.exact) exact.push({ needle, label });
      for (const needle of n.canonical) canonical.push({ needle, label });
    }
    this.sorted = exact.sort(byLengthDesc);
    this.canonical = canonical.sort(byLengthDesc);
    this.minCanonical = canonical.reduce((min, n) => Math.min(min, n.needle.length), Number.POSITIVE_INFINITY);
  }

  scrub(text: string, counter: Counter = new Counter()): string {
    let out = text;
    for (const { needle, label } of this.sorted) {
      if (!out.includes(needle)) continue;
      const parts = out.split(needle);
      counter.add("known-secret", parts.length - 1);
      out = parts.join(redacted(`known:${label}`));
    }
    return this.scrubCanonical(out, counter);
  }

  /** Kanonik görünümlerde bulunan eşleşmeler özgün metindeki aralıklarıyla (örtüşenler birleşerek) maskelenir. */
  private scrubCanonical(text: string, counter: Counter): string {
    if (text.length < this.minCanonical) return text;
    const spans: Span[] = [];
    for (const view of canonicalViews(text, MAX_DECODE_ROUNDS, this.minCanonical)) {
      for (const { needle, label } of this.canonical) {
        for (let at = view.text.indexOf(needle); at !== -1; at = view.text.indexOf(needle, at + needle.length)) {
          const [a, b] = view.span(at, at + needle.length);
          spans.push({ a, b, label });
        }
      }
    }
    if (spans.length === 0) return text;
    spans.sort((x, y) => x.a - y.a || y.b - x.b);
    const merged: Span[] = [];
    for (const s of spans) {
      const last = merged.at(-1);
      if (last && s.a < last.b) last.b = Math.max(last.b, s.b);
      else merged.push({ ...s });
    }
    let out = "";
    let pos = 0;
    for (const s of merged) {
      out += text.slice(pos, s.a) + redacted(`known:${s.label}`);
      pos = s.b;
    }
    counter.add("known-secret", merged.length);
    return out + text.slice(pos);
  }
}
