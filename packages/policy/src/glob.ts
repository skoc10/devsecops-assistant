/** `*` (tümü) ve `?` destekleyen küçük glob eşleyici; regex enjeksiyonuna kapalı. */
export function globMatch(pattern: string, value: string): boolean {
  const re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
  return re.test(value);
}
