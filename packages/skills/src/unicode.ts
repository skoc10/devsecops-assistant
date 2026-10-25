/**
 * Talimat metninde (skill, runbook) meşru kullanımı olmayan GÖRÜNMEZ karakterler:
 *  - `Cf` (biçim): sıfır genişlikli boşluklar, çift yönlü kontroller (Trojan Source), kelime birleştirici, BOM,
 *    ve ETİKET karakterleri U+E0000–E007F ("ASCII smuggling": görünmez metin);
 *  - `Co` (özel kullanım);
 *  - dolgu/birleştirme ve boş glifler: U+034F, U+115F, U+1160, U+17B4–17B5, U+2800 (Braille boşluğu), U+3164,
 *    U+FFA0, U+1D159 (boş nota başı) — boşluk gibi görünür ama `\s` değildir; satır dolgusu ve kalıp bölmede kullanılır.
 * Baştaki BOM yok sayılır.
 */
const INVISIBLE = /[\p{Cf}\p{Co}\u{34F}\u{115F}\u{1160}\u{17B4}\u{17B5}\u{2800}\u{3164}\u{FFA0}\u{1D159}]/u;
/** Varyasyon seçicileri: VS1–16 (U+FE00–FE0F), VS17–256 (U+E0100–E01EF), Moğol serbest seçicileri (U+180B–180D, U+180F). */
const VARIATION_SELECTOR = /[\u{180B}-\u{180D}\u{180F}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/u;
const EMOJI_BASE = /^\p{Emoji}$/u;
/** `\p{Emoji}` rakam, `#` ve `*` içerir: bunlarda sunum seçicisi yalnız tuş başlığı dizisinde (U+20E3) meşrudur. */
const KEYCAP_BASE = /^[0-9#*]$/;
const VS15_TEXT = "\u{FE0E}";
const VS16_EMOJI = "\u{FE0F}";
const KEYCAP = "\u{20E3}";

export const hasInvisible = (text: string): boolean => INVISIBLE.test(text.replace(/^\u{FEFF}/u, ""));

/**
 * Meşru tek kullanım: emoji tabanının hemen ardından TEK sunum seçicisi (U+FE0E metin / U+FE0F emoji). Gerisi —
 * emoji olmayan karakterin ardından, art arda, VS1–14, VS17–256, Moğol seçicileri — veri gizleme işaretidir: her
 * seçici bir bayt taşıyabilir ("emoji smuggling"); görünür her harfin ardına tek seçici koymak eskiden temiz geçiyordu.
 */
export function hasStrayVariationSelector(text: string): boolean {
  if (!VARIATION_SELECTOR.test(text)) return false;
  const cps = [...text];
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i] as string;
    if (!VARIATION_SELECTOR.test(ch)) continue;
    const base = cps[i - 1];
    const presentation = ch === VS15_TEXT || ch === VS16_EMOJI;
    if (!presentation || base === undefined || !EMOJI_BASE.test(base) || (KEYCAP_BASE.test(base) && cps[i + 1] !== KEYCAP)) return true;
  }
  return false;
}

/**
 * Latin harflerine benzeyen Kiril, Yunan ve birkaç Ermeni/Latin-ek harfi → Latin (UTS #39 "confusables" alt kümesi).
 * Bilerek yalnız kaçış dizisiyle yazılır: harflerin kendisi kaynakta Latin'den ayırt edilemez. Yalnız sezgisel
 * taramalar içindir.
 */
const CONFUSABLES: Readonly<Record<string, string>> = {
  // Kiril büyük harfler
  "\u{405}": "S", "\u{406}": "I", "\u{408}": "J", "\u{410}": "A", "\u{412}": "B", "\u{415}": "E", "\u{41A}": "K", "\u{41C}": "M",
  "\u{41D}": "H", "\u{41E}": "O", "\u{420}": "P", "\u{421}": "C", "\u{422}": "T", "\u{423}": "Y", "\u{425}": "X", "\u{42C}": "b",
  "\u{4AE}": "Y", "\u{4BA}": "H", "\u{4C0}": "l", "\u{51A}": "Q", "\u{51C}": "W", "\u{474}": "V", "\u{4E6}": "Ö", "\u{4AA}": "Ç",
  // Kiril küçük harfler
  "\u{430}": "a", "\u{433}": "r", "\u{435}": "e", "\u{43A}": "k", "\u{43E}": "o", "\u{440}": "p", "\u{441}": "c", "\u{443}": "y",
  "\u{445}": "x", "\u{455}": "s", "\u{456}": "i", "\u{458}": "j", "\u{44C}": "b", "\u{4BB}": "h", "\u{4AF}": "y", "\u{4CF}": "l",
  "\u{501}": "d", "\u{51B}": "q", "\u{51D}": "w", "\u{475}": "v", "\u{4E7}": "ö", "\u{4AB}": "ç",
  // Yunan büyük harfler (U+03F9 ay biçimli sigma, U+037F yot)
  "\u{391}": "A", "\u{392}": "B", "\u{395}": "E", "\u{396}": "Z", "\u{397}": "H", "\u{399}": "I", "\u{39A}": "K", "\u{39C}": "M",
  "\u{39D}": "N", "\u{39F}": "O", "\u{3A1}": "P", "\u{3A4}": "T", "\u{3A5}": "Y", "\u{3A7}": "X", "\u{3F9}": "C", "\u{37F}": "J",
  // Yunan küçük harfler (U+03F2 ay biçimli sigma, U+03F3 yot)
  "\u{3B1}": "a", "\u{3B3}": "y", "\u{3B5}": "e", "\u{3B7}": "n", "\u{3B9}": "i", "\u{3BA}": "k", "\u{3BC}": "u", "\u{3BD}": "v",
  "\u{3BF}": "o", "\u{3C1}": "p", "\u{3C4}": "t", "\u{3C5}": "u", "\u{3C7}": "x", "\u{3C9}": "w", "\u{3F2}": "c", "\u{3F3}": "j",
  // Ermeni (oh, seh, vo) ve Latin-ek (alfa, el yazısı g)
  "\u{585}": "o", "\u{57D}": "u", "\u{578}": "n", "\u{251}": "a", "\u{261}": "g",
};
const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join("")}]`, "gu");
const foldConfusables = (text: string): string => text.replace(CONFUSABLE_RE, (ch) => CONFUSABLES[ch] ?? ch);

/**
 * Sezgisel taramaların (curl|sh, dış URL, enjeksiyon kalıbı) ikinci geçişte gördüğü "iskelet": NFKC (tam genişlik
 * ve matematik harfleri, ligatürler, uyumluluk boşlukları → ASCII) + benzer harf katlaması. Katlama NFKC'den önce
 * de yapılır (NFKC ay biçimli sigmayı başka harfe çevirir), sonra da (matematik Yunan harfleri NFKC'den Yunan harfi
 * olarak çıkar). Kiril "es" ile yazılmış "curl … | sh" veya tam genişlikli harfler artık kalıba takılır. Metin
 * gösterilmez/değiştirilmez.
 */
export const foldForScan = (text: string): string => foldConfusables(foldConfusables(text).normalize("NFKC"));
