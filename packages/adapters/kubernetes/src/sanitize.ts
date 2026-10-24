import { registerProfile } from "@ops/redaction";

const CONFIGMAP_SECRETISH = /(token|password|passwd|secret|key|credential|cert|auth)/i;
export const CONFIGMAP_PLACEHOLDER = "‹redacted:configmap-key›";
const LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Adapter düzeyi ön temizlik (M1'den ÖNCE; savunma derinliği + token tasarrufu):
 *  - `managedFields` ve `last-applied-configuration` (eski secret/env kopyalarını taşıyabilir) atılır;
 *  - ConfigMap: secret benzeri ANAHTAR adlarının değerleri maskelenir; `binaryData` yalnız anahtar adı + boyut.
 * Secret nesneleri bu fonksiyona HİÇ gelmez (Table biçiminde okunur, değer sunucudan hiç çekilmez).
 */
export function sanitizeObject(kind: string, input: unknown): unknown {
  if (!isObj(input)) return input;
  const out: Obj = { ...input };
  if (isObj(out["metadata"])) {
    const meta: Obj = { ...out["metadata"] };
    delete meta["managedFields"];
    if (isObj(meta["annotations"])) {
      const ann: Obj = { ...meta["annotations"] };
      delete ann[LAST_APPLIED];
      meta["annotations"] = ann;
    }
    out["metadata"] = meta;
  }
  if (kind === "ConfigMap") {
    if (isObj(out["data"])) {
      out["data"] = Object.fromEntries(
        Object.entries(out["data"]).map(([k, v]) => [k, CONFIGMAP_SECRETISH.test(k) ? CONFIGMAP_PLACEHOLDER : v]),
      );
    }
    if (isObj(out["binaryData"])) {
      out["binaryData"] = Object.fromEntries(
        Object.entries(out["binaryData"]).map(([k, v]) => [k, `‹binary ${typeof v === "string" ? Math.floor((v.length * 3) / 4) : 0} bayt›`]),
      );
    }
  }
  return out;
}

let registered = false;

/**
 * M1 `k8s` profili: adapter hatası yaparsa son hat. Secret türü bir nesne (data/stringData ile)
 * görülürse tümüyle atılır; kayıtlı profil varsayılan maskeleri kaybedemez (withDefaults).
 */
export function registerK8sRedactionProfile(): void {
  if (registered) return;
  registered = true;
  registerProfile({
    name: "k8s",
    dropKeys: new RegExp(`^(?:managedFields|${LAST_APPLIED.replace(/[.]/g, "\\.")})$`),
    dropObject: (node) =>
      node["kind"] === "Secret" && ("data" in node || "stringData" in node) ? "k8s-secret-object" : null,
  });
}
