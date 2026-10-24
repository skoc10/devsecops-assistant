import { Counter, redacted } from "./counter.ts";

/** Bu uzunluğun altındaki değerler (ör. "123456") güvenle maskelenemez: yanlış pozitif seli. */
export const MIN_KNOWN_SECRET_BYTES = 8;

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
 * M3: bilinen-secret taraması. Broker'ın oturumda verdiği her değer buraya kaydedilir; çıktı,
 * hata mesajı, denetim ve kullanıcı girdisi bu değerlerin HERHANGİ bir biçimi için taranır.
 * Bellekte tutulan iğneler secret türevidir: nesne sızdırılmaz, yalnız `scrub` açığa çıkar.
 */
export class KnownSecrets {
  private readonly byLabel = new Map<string, string[]>();
  private sorted: { needle: string; label: string }[] = [];

  /** Eklenirse `true`; çok kısa değer maskelenemez ve `false` döner (çağıran uyarmalı). */
  add(label: string, value: Uint8Array | string): boolean {
    const byteLen = typeof value === "string" ? Buffer.byteLength(value) : value.length;
    if (byteLen < MIN_KNOWN_SECRET_BYTES) return false;
    this.byLabel.set(label, secretNeedles(value));
    this.rebuild();
    return true;
  }

  remove(label: string): void {
    this.byLabel.delete(label);
    this.rebuild();
  }

  clear(): void {
    this.byLabel.clear();
    this.sorted = [];
  }

  get size(): number {
    return this.byLabel.size;
  }

  private rebuild(): void {
    const all: { needle: string; label: string }[] = [];
    for (const [label, needles] of this.byLabel) for (const needle of needles) all.push({ needle, label });
    all.sort((a, b) => b.needle.length - a.needle.length);
    this.sorted = all;
  }

  scrub(text: string, counter: Counter = new Counter()): string {
    let out = text;
    for (const { needle, label } of this.sorted) {
      if (!out.includes(needle)) continue;
      const parts = out.split(needle);
      counter.add("known-secret", parts.length - 1);
      out = parts.join(redacted(`known:${label}`));
    }
    return out;
  }
}
