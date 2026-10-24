/** Şema/tablo/sütun adları için KATI desen: küçük harf, rakam, `_`, `$`; tırnaklı/Unicode ad yok. */
export const SIMPLE_IDENT = /^[a-z_][a-z0-9_$]{0,62}$/;

/** Tanımlayıcıyı çift tırnaklar. Yalnız doğrulanmış adlar için kullanılır; yine de `"` kaçışlanır. */
export function quoteIdent(name: string): string {
  if (typeof name !== "string" || name.length === 0 || name.length > 63 || /[\u0000-\u001f\u007f]/u.test(name)) {
    throw new Error("geçersiz tanımlayıcı");
  }
  return `"${name.replace(/"/g, '""')}"`;
}
