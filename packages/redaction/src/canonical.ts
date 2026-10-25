/**
 * M3 kanonik biçim. Kayıtlı bir secret çıktıda yeniden KODLANMIŞ olarak geçebilir: form/yüzde kodlaması
 * (`+`, küçük harfli `%2f`, `/` korunmuş), JSON/JS `\uXXXX` ve `\/` kaçışları (Go `\u0026`, Python
 * ensure_ascii, PHP), HTML varlıkları (`&amp;`, `&#39;`), büyük harfe çevrilmiş değer... Her birleşim için
 * ayrı iğne üretmek kombinasyon patlamasıdır; bunun yerine metin sınırlı sayıda turda ÇÖZÜLÜR, iki taraf
 * da aynı biçimde KATLANIR ve kanonik eşleşme özgün metindeki aralığa geri eşlenir.
 *
 * - Katlama (uzunluk korur, konumlar birebir): harf büyüklüğü ve form kodlamasındaki `+`/boşluk farkı.
 * - Çözme (tur başına tek katman; çıktı girdiden uzun olamaz): `%XX` ve `\xXX` dizileri (onaltılık harf
 *   büyüklüğünden bağımsız; UTF-8, geçersizse latin1), `\uXXXX`, JSON/JS kaçışları (`\/ \" \\ \' \b \f
 *   \n \r \t`), HTML/XML varlıkları (`&amp; &lt; &gt; &quot; &apos;`, `&#39;`, `&#x27;`).
 * Hepsi tek geçişli ve doğrusal zamanlıdır (geri izleme yok); tur sayısını çağıran sınırlar.
 */

const NON_ASCII = /[^\x00-\x7f]/;
const MAYBE_ESCAPED = /[%\\&]/;

const foldCache = new Map<number, number>();

function foldUnit(c: number): number {
  if (c < 0x80) {
    if (c >= 0x41 && c <= 0x5a) return c + 0x20;
    return c === 0x2b ? 0x20 : c; // form kodlaması: `+` ≡ boşluk
  }
  let f = foldCache.get(c);
  if (f === undefined) {
    const ch = String.fromCharCode(c);
    const up = ch.toUpperCase();
    // büyük harf üzerinden: "ı" → "I" → "i", "ſ" → "S" → "s"
    const low = (up.length === 1 ? up : ch).toLowerCase();
    // tek birime inmeyen eşleme konumları kaydırırdı: olduğu gibi kalır (Türkçe "İ" → "i" hariç)
    f = low.length === 1 ? low.charCodeAt(0) : c === 0x130 ? 0x69 : c;
    foldCache.set(c, f);
  }
  return f;
}

const CHUNK = 8192;

function fromUnits(units: Uint16Array, len: number): string {
  let out = "";
  for (let i = 0; i < len; i += CHUNK) out += String.fromCharCode(...units.subarray(i, Math.min(len, i + CHUNK)));
  return out;
}

/** Kanonik katlama. Uzunluk DEĞİŞMEZ: katlanmış metindeki konum özgün metindeki konumdur. */
export function foldCanonical(s: string): string {
  if (!NON_ASCII.test(s)) return s.toLowerCase().replaceAll("+", " ");
  const units = new Uint16Array(s.length);
  for (let i = 0; i < s.length; i++) units[i] = foldUnit(s.charCodeAt(i));
  return fromUnits(units, s.length);
}

function hexVal(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  const l = c | 0x20;
  return l >= 0x61 && l <= 0x66 ? l - 0x57 : -1;
}

function hex4(s: string, p: number): number {
  let v = 0;
  for (let k = 0; k < 4; k++) {
    const h = hexVal(s.charCodeAt(p + k));
    if (h < 0) return -1;
    v = (v << 4) | h;
  }
  return v;
}

/** `i`deki `%XX` / `\xXX` kaçışının baytı; kaçış değilse -1. */
function byteAt(s: string, i: number): number {
  const c = s.charCodeAt(i);
  let p: number;
  if (c === 0x25) p = i + 1;
  else if (c === 0x5c && s.charCodeAt(i + 1) === 0x78) p = i + 2;
  else return -1;
  const h = hexVal(s.charCodeAt(p));
  const l = hexVal(s.charCodeAt(p + 1));
  return h < 0 || l < 0 ? -1 : (h << 4) | l;
}

/** `b[k]`den başlayan UTF-8 dizisi: [kod noktası, bayt sayısı]; geçersizse bayt sayısı 0. */
function utf8At(b: readonly number[], k: number): [number, number] {
  const b0 = b[k] as number;
  if (b0 < 0x80) return [b0, 1];
  const len = b0 >= 0xc2 && b0 <= 0xdf ? 2 : b0 >= 0xe0 && b0 <= 0xef ? 3 : b0 >= 0xf0 && b0 <= 0xf4 ? 4 : 0;
  if (len === 0) return [b0, 0];
  let cp = b0 & (0x7f >> len);
  for (let t = 1; t < len; t++) {
    const bt = b[k + t];
    if (bt === undefined || (bt & 0xc0) !== 0x80) return [b0, 0];
    cp = (cp << 6) | (bt & 0x3f);
  }
  const min = len === 2 ? 0x80 : len === 3 ? 0x800 : 0x10000;
  if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return [b0, 0];
  return [cp, len];
}

/** JSON/JS tek karakterlik kaçışın karşılığı; değilse -1. */
function simpleEscape(d: number): number {
  switch (d) {
    case 0x22: // "
    case 0x27: // '
    case 0x2f: // /
    case 0x5c: // \
      return d;
    case 0x62: // b
      return 0x08;
    case 0x66: // f
      return 0x0c;
    case 0x6e: // n
      return 0x0a;
    case 0x72: // r
      return 0x0d;
    case 0x74: // t
      return 0x09;
    default:
      return -1;
  }
}

const NAMED_ENTITIES: readonly (readonly [string, number])[] = [
  ["amp", 0x26],
  ["lt", 0x3c],
  ["gt", 0x3e],
  ["quot", 0x22],
  ["apos", 0x27],
];

/** `i`deki (`&`) HTML/XML varlığı: [kod noktası, uzunluk]; değilse null. Tarama en çok 10 karakter. */
function entityAt(s: string, i: number): [number, number] | null {
  if (s.charCodeAt(i + 1) === 0x23) {
    let j = i + 2;
    const hex = (s.charCodeAt(j) | 0x20) === 0x78;
    if (hex) j++;
    const from = j;
    let cp = 0;
    for (; j - from < 7; j++) {
      const c = s.charCodeAt(j);
      const v = hex ? hexVal(c) : c >= 0x30 && c <= 0x39 ? c - 0x30 : -1;
      if (v < 0) break;
      cp = cp * (hex ? 16 : 10) + v;
    }
    if (j === from || s.charCodeAt(j) !== 0x3b || cp > 0x10ffff) return null;
    return [cp, j + 1 - i];
  }
  for (const [name, cp] of NAMED_ENTITIES) {
    const end = i + 1 + name.length;
    if (s.charCodeAt(end) === 0x3b && s.slice(i + 1, end).toLowerCase() === name) return [cp, end + 1 - i];
  }
  return null;
}

export interface DecodedLevel {
  readonly text: string;
  /** `text[i]`, girdinin `[start[i], end[i])` aralığından çözüldü. */
  readonly start: Int32Array;
  readonly end: Int32Array;
}

/** Tek katman kaçış çözer; çözülecek kaçış yoksa `null`. */
export function decodeEscapesOnce(s: string): DecodedLevel | null {
  if (!MAYBE_ESCAPED.test(s)) return null;
  const n = s.length;
  // çıktı girdiden uzun olamaz: kaçış ≥ 2 karakter tüketip 1 birim, vekil çifti (2 birim) üreten kaçış ≥ 8 karakter
  const units = new Uint16Array(n);
  const start = new Int32Array(n);
  const end = new Int32Array(n);
  let m = 0;
  let changed = false;
  const emit = (cp: number, a: number, b: number): void => {
    if (cp > 0xffff) {
      // BMP dışı: vekil çifti; iki birim de aynı kaynak aralığına eşlenir
      cp -= 0x10000;
      units[m] = 0xd800 + (cp >> 10);
      start[m] = a;
      end[m] = b;
      m++;
      cp = 0xdc00 + (cp & 0x3ff);
    }
    units[m] = cp;
    start[m] = a;
    end[m] = b;
    m++;
  };

  let i = 0;
  while (i < n) {
    const c = s.charCodeAt(i);
    if ((c === 0x25 || c === 0x5c) && byteAt(s, i) >= 0) {
      // ardışık bayt kaçışları birlikte çözülür (çok baytlı UTF-8 karakterleri)
      const bytes: number[] = [];
      const pos: number[] = [];
      let j = i;
      for (let b = byteAt(s, j); b >= 0; b = byteAt(s, j)) {
        bytes.push(b);
        pos.push(j);
        j += s.charCodeAt(j) === 0x25 ? 3 : 4;
      }
      pos.push(j);
      for (let k = 0; k < bytes.length; ) {
        const [cp, len] = utf8At(bytes, k);
        const step = len === 0 ? 1 : len; // geçersiz UTF-8: bayt latin1 karakter sayılır
        emit(len === 0 ? (bytes[k] as number) : cp, pos[k] as number, pos[k + step] as number);
        k += step;
      }
      i = j;
      changed = true;
      continue;
    }
    if (c === 0x5c) {
      const d = s.charCodeAt(i + 1);
      const u = d === 0x75 ? hex4(s, i + 2) : -1;
      if (u >= 0) {
        emit(u, i, i + 6);
        i += 6;
        changed = true;
        continue;
      }
      const e = simpleEscape(d);
      if (e >= 0) {
        emit(e, i, i + 2);
        i += 2;
        changed = true;
        continue;
      }
    } else if (c === 0x26) {
      const ent = entityAt(s, i);
      if (ent) {
        emit(ent[0], i, i + ent[1]);
        i += ent[1];
        changed = true;
        continue;
      }
    }
    emit(c, i, i + 1);
    i++;
  }
  if (!changed) return null;
  return { text: fromUnits(units, m), start: start.subarray(0, m), end: end.subarray(0, m) };
}

export interface CanonicalView {
  /** Katlanmış (ve ilk turdan sonra çözülmüş) metin. */
  readonly text: string;
  /** Kanonik `[a, b)` aralığının özgün metindeki karşılığı. */
  span(a: number, b: number): [number, number];
}

/**
 * Özgün metnin kanonik görünümleri: tur 0 yalnız katlama; sonraki her tur bir katman daha çözer
 * (en çok `maxDecodeRounds`; iç içe kodlama, ör. `%2526` veya `&amp;amp;`). Çözülecek kaçış kalmayınca
 * ya da metin `minLength`ten kısalınca durur.
 */
export function* canonicalViews(text: string, maxDecodeRounds: number, minLength = 0): Generator<CanonicalView> {
  let cur = text;
  let start: Int32Array | null = null;
  let end: Int32Array | null = null;
  for (let round = 0; ; round++) {
    const s0 = start;
    const e0 = end;
    yield {
      text: foldCanonical(cur),
      span: (a, b) => (s0 && e0 ? [s0[a] as number, e0[b - 1] as number] : [a, b]),
    };
    if (round >= maxDecodeRounds) return;
    const d = decodeEscapesOnce(cur);
    if (!d || d.text.length < minLength) return;
    // eşlemeleri özgün metne bağla
    const ns = new Int32Array(d.text.length);
    const ne = new Int32Array(d.text.length);
    for (let k = 0; k < ns.length; k++) {
      const a = d.start[k] as number;
      const b = d.end[k] as number;
      ns[k] = s0 ? (s0[a] as number) : a;
      ne[k] = e0 ? (e0[b - 1] as number) : b;
    }
    cur = d.text;
    start = ns;
    end = ne;
  }
}
