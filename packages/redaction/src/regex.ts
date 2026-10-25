/**
 * Dışarıdan gelen düzenli ifadeler (adapter profilleri, kullanıcı kuralları) için bayrak normalizasyonu.
 * `g`/`y` bayraklı bir RegExp `lastIndex` durumu taşır; `g`siz bir kural `replace()`te yalnız ilk eşleşmeyi,
 * `y`li kural yalnız ardışık eşleşmeleri gezer. Çağıranın nesnesi değiştirilmez (kopya önbelleklenir).
 */

const globalCache = new WeakMap<RegExp, RegExp>();
const statelessCache = new WeakMap<RegExp, RegExp>();

/** Bayrak kümesinden durum taşıyan `g`/`y` atılır. */
export const withoutStateFlags = (re: RegExp): string => re.flags.replace(/[gy]/g, "");

/** `test()` için durumsuz kopya: aynı nesneyle art arda `test()` (`g`/`y`) eşleşme atlatırdı. */
export function statelessRegExp(re: RegExp): RegExp {
  if (!re.global && !re.sticky) return re;
  let out = statelessCache.get(re);
  if (!out) {
    out = new RegExp(re.source, withoutStateFlags(re));
    statelessCache.set(re, out);
  }
  return out;
}

/** `replace()` için tüm eşleşmeleri gezen kopya (`g` yoksa yalnız İLK eşleşme maskelenirdi). */
export function globalRegExp(re: RegExp): RegExp {
  if (re.global && !re.sticky) return re;
  let out = globalCache.get(re);
  if (!out) {
    out = new RegExp(re.source, `${withoutStateFlags(re)}g`);
    globalCache.set(re, out);
  }
  return out;
}
