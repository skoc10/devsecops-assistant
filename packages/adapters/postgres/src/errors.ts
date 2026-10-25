import { OpsError } from "@ops/contracts";

/**
 * Mesajında hücre/girdi DEĞERİ taşıyabilen SQLSTATE sınıfları: 22 (veri istisnası: `invalid input syntax for type
 * integer: "<hücre>"`, `value "<hücre>" is out of range…`) ve 23 (bütünlük kısıtı). Böyle bir mesaj, satır sınırını
 * ve M4 dedektörlerini atlayan sorgu başına bir değerlik sızıntı kanalıdır (`SELECT note::int …`).
 */
const VALUE_BEARING = /^2[23]/;
/** Metni tümüyle kullanıcı/rutin biçimli sınıflar (PL/pgSQL RAISE, dış rutin istisnaları): metin hiç iletilmez. */
const OPAQUE = /^(P0|38|39)/;

/**
 * Değer taşıyabilen mesajın sabit kısmı: ilk `: ` sonrası (değer genellikle orada) atılır; kalan tırnaklı parçalar
 * ve bayt dizileri `…` olur. Hata türü ve (SQLSTATE ile birlikte) neyin yanlış olduğu korunur.
 */
export function staticMessage(message: string): string {
  const head = message.split(/:\s/, 1)[0] ?? "";
  return head
    .replace(/"(?:[^"]|"")*"?/g, '"…"')
    .replace(/'(?:[^']|'')*'?/g, "'…'")
    .replace(/\b0x[0-9a-f]+\b/gi, "0x…")
    .trim();
}

/**
 * PostgreSQL/pg hatasını kısa, SQLSTATE kodlu ve tek satırlık bir OpsError'a çevirir. Hata gövdesindeki
 * `detail`/`where`/`hint` (veri değerleri taşıyabilir) ASLA iletilmez; değer taşıyabilen sınıflarda ilk satırın
 * da yalnız sabit kısmı kalır. Mesaj ayrıca PEP'te M2/M3'ten geçer.
 */
export function dbError(e: unknown, what: string): OpsError {
  if (e instanceof OpsError) return e;
  const err = e as { code?: unknown; message?: unknown } | null;
  const code = typeof err?.code === "string" ? err.code : "";
  let first = (typeof err?.message === "string" ? err.message : "bilinmeyen hata").split("\n")[0] as string;
  if (OPAQUE.test(code)) first = "rutin hatası (metin değer taşıyabileceği için iletilmez)";
  else if (VALUE_BEARING.test(code)) {
    const fixed = staticMessage(first);
    if (fixed !== first) first = `${fixed} (değer gizlendi)`;
  }
  return new OpsError("db_error", `${what}: ${code ? `[${code}] ` : ""}${first.slice(0, 200)}`);
}
