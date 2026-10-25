import { OpsError } from "@ops/contracts";

/** `sahip/ad`. Depo adı `.` veya `..` olamaz (GitHub de yasaklar): ad API yoluna girer, `encodeURIComponent` noktaları kaçışlamaz. */
export const REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/(?!\.\.?$)[A-Za-z0-9._-]{1,100}$/;

/** Dal/etiket/SHA karakter kümesi (araç şemasındaki desen). */
export const GIT_REF = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;

/**
 * `git check-ref-format` kuralları, karakter kümesine ek olarak: `..` ve `//` yok, `/` veya `.` ile bitmez, hiçbir
 * bileşen `.` ile başlamaz ya da `.lock` ile bitmez. Ref API yollarına girer (`.../git/ref/heads/<ref>`, compare):
 * nokta bölümleri yol gezinmesine dönüşmesin.
 */
export function isGitRef(v: string): boolean {
  return GIT_REF.test(v) && !v.includes("..") && !v.includes("//") && !v.endsWith("/") && !v.endsWith(".") && v.split("/").every((c) => !c.startsWith(".") && !c.endsWith(".lock"));
}

export const GIT_REF_MESSAGE = "geçersiz git ref: '..', '//', sonda '/' veya '.', '.' ile başlayan ya da '.lock' ile biten bileşen olamaz";

/**
 * Depoya özgü adlar (iş/adım/workflow/dal adı...) KALIP-DOĞRULAMALI KISA TANIMLAYICIYA indirgenir:
 * en çok 48 karakter, boşluk yok (`_`), yalnız `[A-Za-z0-9._/@#+:,=-]`; kalan her karakter `?` olur.
 * Böylece depoya yazabilen biri (ör. fork PR yazarı) adlara doğal dil cümlesi koyamaz. ARTIK RİSK:
 * boşluksuz ≤48 karakterlik sözcük dizisi yine de okunabilir; asıl savunma politikadır (tavan `read`,
 * taint → onay). Tasarım §4.2: "kalıp-doğrulamalı kısa tanımlayıcı" taint'siz sayılır.
 */
export function safeName(v: unknown, max = 48): string | undefined {
  if (typeof v !== "string") return undefined;
  const cleaned = v.trim().slice(0, max * 2).replace(/\s+/gu, "_").slice(0, max).replace(/[^A-Za-z0-9._/@#+:,=-]/gu, "?");
  return cleaned === "" ? undefined : cleaned;
}

export const isoOrUndefined = (v: unknown): string | undefined => {
  if (typeof v !== "string") return undefined;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
};

export const sha40 = (v: unknown): string | undefined => (typeof v === "string" && /^[0-9a-f]{40}$/.test(v) ? v : undefined);

export const int = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);

/** Gizli dosya desenleri (okuma/diff reddi). Küçük harfe çevrilmiş yol üzerinde çalışır. */
const SECRET_PATH: readonly [RegExp, string][] = [
  [/(^|\/)\.env(\..*)?$/, ".env dosyası"],
  [/\.(pem|key|p12|pfx|jks|keystore|kdbx|ppk|asc|gpg)$/, "özel anahtar/sertifika dosyası"],
  [/(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/, "SSH anahtarı"],
  [/\.tfstate(\.backup)?$/, "Terraform state"],
  [/\.tfvars(\.json)?$/, "Terraform değişken dosyası"],
  [/(^|\/)\.git(\/|$)/, ".git içeriği"],
  [/(^|\/)\.aws\/(credentials|config)$/, "AWS kimlik dosyası"],
  [/(^|\/)\.(npmrc|netrc|pypirc|git-credentials)$/, "kimlik dosyası"],
  [/(^|\/)\.docker\/config\.json$/, "docker kimlik dosyası"],
  [/(^|\/)\.kube\/config$|(^|\/)kubeconfig(\.|$)/, "kubeconfig"],
  [/(^|\/)secrets?\.(ya?ml|json|toml|env)$/, "secrets dosyası"],
  [/(^|\/)credentials?(\.|$)/, "credentials dosyası"],
  [/vault[^/]*\.ya?ml$|(^|\/)\.vault[^/]*$/, "vault dosyası"],
];

/** Yol geçersiz/gizli ise nedenini döner (yoksa `null`). */
export function pathProblem(path: string): string | null {
  if (path.length === 0 || path.length > 300) return "yol boş veya çok uzun";
  if (/[\u0000-\u001f\u007f\\]/u.test(path)) return "yol denetim karakteri/ters eğik çizgi içeriyor";
  if (path.startsWith("/") || path.split("/").some((s) => s === ".." || s === ".")) return "yol göreli ve '..' içermeyen bir depo yolu olmalı";
  const lower = path.toLowerCase();
  for (const [re, why] of SECRET_PATH) if (re.test(lower)) return `gizli dosya deseni: ${why}`;
  return null;
}

export function assertRepo(v: string): string {
  if (!REPO.test(v)) throw new OpsError("repo_invalid", "depo 'sahip/ad' biçiminde olmalı");
  return v.toLowerCase();
}
