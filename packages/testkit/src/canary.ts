import { randomBytes } from "node:crypto";

/**
 * Canary: test sırasında rastgele üretilen, gerçek olmayan "secret" değeri. Depoya ASLA yazılmaz.
 * Değer, base64/URL kodlamasında biçim değiştiren karakterler (`/`, `+`, `=`) içerir.
 */
export interface Canary {
  readonly label: string;
  readonly value: string;
}

export function makeCanary(label = "secret"): Canary {
  const a = randomBytes(9).toString("base64url");
  const b = randomBytes(9).toString("base64url");
  return { label, value: `cnry_${a}/${b}+${label}=` };
}

function stripNoise(s: string): string {
  return s.replace(/[\s"'`\\+]/g, "");
}

/** Aynı değerin sızabileceği biçimler (ham, base64 hizalamaları, URL, hex, JSON). */
export function canaryVariants(c: Canary): { name: string; needle: string }[] {
  const raw = Buffer.from(c.value, "utf8");
  const out: { name: string; needle: string }[] = [{ name: "raw", needle: c.value }];
  out.push({ name: "url-encoded", needle: encodeURIComponent(c.value) });
  out.push({ name: "json-escaped", needle: JSON.stringify(c.value).slice(1, -1) });
  out.push({ name: "hex", needle: raw.toString("hex") });
  for (let offset = 0; offset < 3; offset++) {
    const shifted = Buffer.concat([Buffer.alloc(offset), raw]);
    const b64 = shifted.toString("base64");
    // Yalnızca değerin baytlarıyla TAM belirlenen karakterler: öndeki dolgu ve sondaki kısmi grup atılır.
    const first = Math.ceil((offset * 8) / 6);
    const last = Math.floor((shifted.length * 8) / 6);
    const core = b64.slice(first, Math.max(first, last));
    if (core.length >= 12) {
      out.push({ name: `base64@${offset}`, needle: core });
      out.push({ name: `base64url@${offset}`, needle: core.replace(/\+/g, "-").replace(/\//g, "_") });
    }
  }
  return out;
}

/** Metinde canary'nin herhangi bir biçimi geçiyorsa biçim adını döndürür (değeri DEĞİL). */
export function findCanary(text: string, c: Canary): string | null {
  for (const v of canaryVariants(c)) {
    if (text.includes(v.needle)) return v.name;
  }
  // Boşluk/tırnak/birleştirme ile bölünmüş sızıntı
  const noise = stripNoise(text);
  if (noise.includes(stripNoise(c.value))) return "split-or-concatenated";
  return null;
}
