import { OpsError } from "@ops/contracts";

const MAX_SECONDS = 7 * 86_400;

/** `90s`, `30m`, `2h`, `1d` → saniye. Zaman penceresi ZORUNLUDUR ve üst sınırlıdır (7 gün). */
export function parseSince(v: string): number {
  const m = /^(\d{1,6})([smhd])$/.exec(v.trim());
  if (!m) throw new OpsError("since_invalid", "since biçimi '90s', '30m', '2h' veya '1d' olmalı");
  const n = Number(m[1]);
  const mult = { s: 1, m: 60, h: 3600, d: 86_400 }[m[2] as "s" | "m" | "h" | "d"];
  const sec = n * mult;
  if (sec < 1 || sec > MAX_SECONDS) throw new OpsError("since_invalid", "since 1 saniye ile 7 gün arasında olmalı");
  return sec;
}
