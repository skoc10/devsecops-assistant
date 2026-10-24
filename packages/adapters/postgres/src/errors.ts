import { OpsError } from "@ops/contracts";

/**
 * PostgreSQL/pg hatasını kısa, SQLSTATE kodlu ve tek satırlık bir OpsError'a çevirir. Hata gövdesindeki
 * `detail`/`where`/`hint` (veri değerleri taşıyabilir) ASLA iletilmez; mesaj ayrıca PEP'te M2/M3'ten geçer.
 */
export function dbError(e: unknown, what: string): OpsError {
  if (e instanceof OpsError) return e;
  const err = e as { code?: unknown; message?: unknown } | null;
  const code = typeof err?.code === "string" ? err.code : "";
  const first = (typeof err?.message === "string" ? err.message : "bilinmeyen hata").split("\n")[0] as string;
  return new OpsError("db_error", `${what}: ${code ? `[${code}] ` : ""}${first.slice(0, 200)}`);
}
