/** M5: boyut/satır limiti. Kesme her zaman açık işaretle yapılır. */
export function truncateString(s: string, maxBytes: number): { text: string; truncated: boolean } {
  if (Buffer.byteLength(s, "utf8") <= maxBytes) return { text: s, truncated: false };
  // UTF-8 sınırını bozmadan kes
  let cut = Math.max(0, maxBytes);
  const buf = Buffer.from(s, "utf8");
  while (cut > 0 && (buf[cut] ?? 0) >> 6 === 0b10) cut--;
  return { text: `${buf.subarray(0, cut).toString("utf8")}…[kesildi: toplam ${buf.length} bayt]`, truncated: true };
}

export function clampList<T>(items: readonly T[], maxItems: number): { items: T[]; total: number; truncated: boolean } {
  if (items.length <= maxItems) return { items: [...items], total: items.length, truncated: false };
  return { items: items.slice(0, maxItems), total: items.length, truncated: true };
}
