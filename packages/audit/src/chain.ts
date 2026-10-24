import { createHmac } from "node:crypto";
import { canonicalJson } from "./canonical.ts";

export const GENESIS_HASH = "0".repeat(64);

/** Kayıt gövdesi (hash alanı hariç) üzerinde, anahtarlı zincir hash'i. */
export function chainHash(key: Uint8Array, prevHash: string, recordWithoutHash: unknown): string {
  return createHmac("sha256", key).update(prevHash).update("\n").update(canonicalJson(recordWithoutHash)).digest("hex");
}
