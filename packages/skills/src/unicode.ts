/**
 * Talimat metninde (skill, runbook) meşru kullanımı olmayan GÖRÜNMEZ karakterler:
 *  - `Cf` (biçim): sıfır genişlikli boşluklar, çift yönlü kontroller (Trojan Source), kelime birleştirici, BOM,
 *    ve ETİKET karakterleri U+E0000–E007F ("ASCII smuggling": görünmez metin);
 *  - `Co` (özel kullanım);
 *  - dolgu/birleştirme: U+034F, U+115F, U+1160, U+17B4–17B5, U+3164, U+FFA0.
 * Baştaki BOM yok sayılır.
 */
const INVISIBLE = /[\p{Cf}\p{Co}\u034F\u115F\u1160\u17B4\u17B5\u3164\uFFA0]/u;
/** Varyasyon seçicileri emoji için meşrudur (tek `U+FE0F`); art arda dizilmeleri veya genişletilmiş seçiciler veri gizleme işaretidir. */
const VARIATION_RUN = /[\u{FE00}-\u{FE0F}]{2,}|[\u{E0100}-\u{E01EF}]/u;

export const hasInvisible = (text: string): boolean => INVISIBLE.test(text.replace(/^\uFEFF/, ""));
export const hasVariationRun = (text: string): boolean => VARIATION_RUN.test(text);
