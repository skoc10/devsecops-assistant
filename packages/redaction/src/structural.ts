import { Counter, redacted } from "./counter.ts";

/**
 * M1: yapısal reddet listesi. Alan/tür düzeyinde, desenden bağımsız: değer neye benzerse benzesin
 * bu alanlar modele gitmez. Adapter'lar kendi profillerini `registerProfile` ile kaydeder.
 */
export interface StructuralProfile {
  readonly name: string;
  /** Anahtar adı eşleşirse alan tümüyle atılır. */
  readonly dropKeys?: RegExp;
  /** Anahtar adı eşleşirse değer maskelenir (nesne/dizi dahil). */
  readonly maskKeys?: RegExp;
  /** `{name|key: SECRET_ADI, value: "..."}` çiftlerinde `value` maskelenir. */
  readonly nameValueSecretNames?: RegExp;
  /** `string` döndürürse nesne `‹dropped:sebep›` ile değiştirilir. */
  readonly dropObject?: (node: Record<string, unknown>, path: readonly string[]) => string | null;
}

const SECRETISH_KEY =
  /^(?:.*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization|cookie).*)$/i;

export const DEFAULT_PROFILE: StructuralProfile = {
  name: "default",
  dropKeys: /^managedFields$/,
  maskKeys: SECRETISH_KEY,
  nameValueSecretNames: SECRETISH_KEY,
};

function union(a: RegExp | undefined, b: RegExp | undefined): RegExp | undefined {
  if (!a) return b;
  if (!b) return a;
  const flags = [...new Set([...a.flags, ...b.flags])].join("");
  return new RegExp(`(?:${a.source})|(?:${b.source})`, flags);
}

/**
 * Kayıtlı bir profil varsayılan kuralları KALDIRAMAZ, yalnız ekleyebilir: bir adapter'ın
 * `maskKeys` unutması `password` alanlarını sessizce açığa çıkarmamalıdır.
 */
function withDefaults(p: StructuralProfile): StructuralProfile {
  if (p === DEFAULT_PROFILE) return p;
  const merged: {
    -readonly [K in keyof StructuralProfile]: StructuralProfile[K];
  } = { name: p.name };
  const dropKeys = union(DEFAULT_PROFILE.dropKeys, p.dropKeys);
  const maskKeys = union(DEFAULT_PROFILE.maskKeys, p.maskKeys);
  const nameValue = union(DEFAULT_PROFILE.nameValueSecretNames, p.nameValueSecretNames);
  if (dropKeys) merged.dropKeys = dropKeys;
  if (maskKeys) merged.maskKeys = maskKeys;
  if (nameValue) merged.nameValueSecretNames = nameValue;
  if (p.dropObject) merged.dropObject = p.dropObject;
  return merged;
}

const profiles = new Map<string, StructuralProfile>([[DEFAULT_PROFILE.name, DEFAULT_PROFILE]]);

export function registerProfile(profile: StructuralProfile): void {
  profiles.set(profile.name, withDefaults(profile));
}

export function getProfile(name: string): StructuralProfile {
  return profiles.get(name) ?? DEFAULT_PROFILE;
}

const MAX_DEPTH = 48;

export function applyStructural(value: unknown, profile: StructuralProfile, counter: Counter): unknown {
  return walk(value, profile, counter, [], 0);
}

function walk(value: unknown, p: StructuralProfile, c: Counter, path: readonly string[], depth: number): unknown {
  if (depth > MAX_DEPTH) {
    c.add("m1:max-depth");
    return "‹dropped:max-depth›";
  }
  if (Array.isArray(value)) return value.map((v, i) => walk(v, p, c, [...path, String(i)], depth + 1));
  if (value === null || typeof value !== "object") return value;

  const node = value as Record<string, unknown>;
  const reason = p.dropObject?.(node, path);
  if (reason) {
    c.add(`m1:drop-object:${reason}`);
    return `‹dropped:${reason}›`;
  }

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(node)) {
    if (p.dropKeys?.test(k)) {
      c.add(`m1:drop-key:${k}`);
      continue;
    }
    // `tokens: 1200` gibi SAYAÇ alanları (LLM token sayısı) secret değildir; sayısal parola/PIN alanları yine maskelenir
    const isCounter = typeof v === "number" && /tokens?(?:_?count|_?limit|_?usage|_?estimate)?$/i.test(k);
    if (p.maskKeys?.test(k) && v !== null && v !== undefined && v !== "" && typeof v !== "boolean" && !isCounter) {
      // yalnız değer taşıyan alanları maskele (boş/boolean alan bilgi sızdırmaz)
      c.add("m1:mask-key");
      out[k] = redacted("field");
      continue;
    }
    out[k] = walk(v, p, c, [...path, k], depth + 1);
  }

  // {name: DB_PASSWORD, value: "..."} (k8s env, CI değişkenleri, ansible vars...)
  const label = typeof node["name"] === "string" ? node["name"] : typeof node["key"] === "string" ? node["key"] : null;
  if (label !== null && p.nameValueSecretNames?.test(label) && typeof out["value"] === "string" && out["value"] !== "") {
    c.add("m1:mask-name-value");
    out["value"] = redacted("field");
  }
  return out;
}
