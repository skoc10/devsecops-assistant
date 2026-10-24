import { randomBytes } from "node:crypto";
import type { SecretStore } from "@ops/contracts";

export const AUDIT_KEY_NAME = "audit/hmac-key";

/** Denetim zincirinin HMAC anahtarı kasadadır; yoksa üretilir. */
export async function ensureAuditKey(store: SecretStore): Promise<Uint8Array> {
  const existing = await store.get(AUDIT_KEY_NAME);
  if (existing && existing.length >= 16) return existing;
  const key = new Uint8Array(randomBytes(32));
  await store.set(AUDIT_KEY_NAME, key);
  return key;
}
