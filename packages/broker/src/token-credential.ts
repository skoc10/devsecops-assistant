import { OpsError } from "@ops/contracts";
import { caFingerprintOf } from "./db-credential.ts";

/**
 * Kasadaki taşıyıcı (bearer) belirteç kimliği: GitHub gibi HTTPS API'leri için (`token-static`).
 * `apiBase` profilin pin uç noktasıyla aynı olmalıdır; belirteç yalnız bu adrese ve doğrulanmış TLS ile gider.
 */
export interface TokenCredentialBlob {
  readonly v: 1;
  readonly kind: "token-static";
  readonly apiBase: string;
  readonly token: string;
  readonly caPem?: string;
}

export type TokenCredential = Omit<TokenCredentialBlob, "v" | "kind">;

export interface TokenImportInput {
  /** `https://api.github.com` veya GHES `https://ghe.example/api/v3`. Yalnız https. */
  readonly apiBase: string;
  readonly token: string;
  readonly caPem?: string;
}

export interface TokenImportResult {
  readonly blob: TokenCredentialBlob;
  /** Pin uç noktası: normalleştirilmiş `https://host[:port][/yol]`. */
  readonly endpoint: string;
  readonly caFingerprint?: string;
  readonly warnings: string[];
}

/** Alanları doğrular, kasaya yazılacak gövdeyi kurar. Hata iletileri belirteci içermez. */
export function buildTokenCredential(input: TokenImportInput): TokenImportResult {
  let u: URL;
  try {
    u = new URL(input.apiBase.trim());
  } catch {
    throw new OpsError("api_base_invalid", "API adresi geçersiz");
  }
  if (u.protocol !== "https:") throw new OpsError("api_base_insecure", "API adresi https olmalı");
  if (u.username || u.password || u.search || u.hash) throw new OpsError("api_base_invalid", "API adresi kullanıcı bilgisi/sorgu/parça içeremez");
  if (input.token.length < 8 || input.token.length > 4096 || /[\s\u0000-\u001f\u007f]/u.test(input.token)) {
    throw new OpsError("token_invalid", "belirteç boş/çok kısa/çok uzun veya boşluk/denetim karakteri içeriyor");
  }
  const warnings: string[] = [];
  const path = u.pathname.replace(/\/+$/, "");
  const endpoint = `https://${u.hostname.toLowerCase()}${u.port && u.port !== "443" ? `:${u.port}` : ""}${path}`;
  let caFingerprint: string | undefined;
  if (input.caPem !== undefined) caFingerprint = caFingerprintOf(input.caPem);
  else warnings.push("CA pini yok: sistem kök sertifikaları kullanılacak (özel sunucu için CA verin)");
  const blob: TokenCredentialBlob = { v: 1, kind: "token-static", apiBase: endpoint, token: input.token, ...(input.caPem !== undefined ? { caPem: input.caPem } : {}) };
  return { blob, endpoint, ...(caFingerprint ? { caFingerprint } : {}), warnings };
}
