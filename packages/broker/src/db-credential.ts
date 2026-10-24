import { X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import { OpsError } from "@ops/contracts";

/**
 * Kasadaki veritabanı kimliği (`db-static`). Bağlantı DİZESİ asla kabul edilmez/üretilmez: alanlar tek
 * tek doğrulanır. Gövde yalnız kasada durur; adapter'a yalnız `CredentialResolver.db` ile, lease
 * etkinken verilir.
 */
export interface DbCredentialBlob {
  readonly v: 1;
  readonly kind: "db-static";
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly password: string;
  readonly tls: { readonly mode: "verify-full" | "disable"; readonly caPem?: string; readonly serverName?: string };
}

/** `CredentialResolver.db` çıktısı. */
export type DbCredential = Omit<DbCredentialBlob, "v" | "kind">;

export interface DbImportInput {
  readonly host: string;
  readonly port?: number;
  readonly database: string;
  readonly user: string;
  readonly password: string;
  /** PEM; verilirse tek güven çıpası ve CA parmak izi pini olur. */
  readonly caPem?: string;
  /** `disable` yalnız loopback için. */
  readonly tlsMode?: "verify-full" | "disable";
  readonly serverName?: string;
}

export interface DbImportResult {
  readonly blob: DbCredentialBlob;
  /** `host:port` (IPv6 için `[::1]:5432`). Secret değildir. */
  readonly endpoint: string;
  readonly caFingerprint?: string;
  readonly warnings: string[];
}

const HOSTNAME = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
/** PostgreSQL tanımlayıcı sınırı 63 bayttır; denetim/komut satırı karakterleri yasak. */
const NAME = /^[^\u0000-\u001f\u007f]{1,63}$/u;

export const isLoopbackHost = (host: string): boolean => {
  const h = host.toLowerCase();
  if (h === "localhost") return true;
  if (isIP(h) === 4) return h.startsWith("127.");
  return h === "::1";
};

export function dbEndpoint(host: string, port: number): string {
  return `${isIP(host) === 6 ? `[${host}]` : host}:${port}`.toLowerCase();
}

export function caFingerprintOf(pem: string): string {
  const m = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(pem);
  if (!m) throw new OpsError("ca_invalid", "CA PEM içinde sertifika yok");
  try {
    return new X509Certificate(m[0]).fingerprint256.replace(/:/g, "").toLowerCase();
  } catch {
    throw new OpsError("ca_invalid", "CA sertifikası okunamadı");
  }
}

/** Alanları doğrular ve kasaya yazılacak gövdeyi kurar. Hata iletileri parola içermez. */
export function buildDbCredential(input: DbImportInput): DbImportResult {
  const warnings: string[] = [];
  const host = input.host.trim();
  const v6 = isIP(host) === 6;
  if (!v6 && !HOSTNAME.test(host)) throw new OpsError("db_host_invalid", "host geçersiz (yalnız ad, IPv4 veya IPv6; yol/şema/kullanıcı bilgisi yok)");
  const port = input.port ?? 5432;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new OpsError("db_port_invalid", "port 1-65535 olmalı");
  if (!NAME.test(input.database)) throw new OpsError("db_name_invalid", "veritabanı adı geçersiz");
  if (!NAME.test(input.user)) throw new OpsError("db_user_invalid", "kullanıcı adı geçersiz");
  if (input.password.length < 1 || input.password.length > 1024 || input.password.includes("\0")) {
    throw new OpsError("db_password_invalid", "parola boş, çok uzun veya NUL içeriyor");
  }
  const mode = input.tlsMode ?? "verify-full";
  if (mode === "disable") {
    if (!isLoopbackHost(host)) throw new OpsError("db_tls_required", "TLS yalnız loopback için kapatılabilir; uzak veritabanı TLS (verify-full) ister");
    warnings.push("TLS kapalı (loopback)");
  }
  let caFingerprint: string | undefined;
  if (input.caPem !== undefined) {
    if (mode === "disable") throw new OpsError("db_tls_conflict", "TLS kapalıyken CA verilemez");
    caFingerprint = caFingerprintOf(input.caPem);
  } else if (mode === "verify-full") {
    warnings.push("CA pini yok: sistem kök sertifikaları kullanılacak (pin için CA verin)");
  }
  const blob: DbCredentialBlob = {
    v: 1,
    kind: "db-static",
    host,
    port,
    database: input.database,
    user: input.user,
    password: input.password,
    tls: { mode, ...(input.caPem !== undefined ? { caPem: input.caPem } : {}), ...(input.serverName ? { serverName: input.serverName } : {}) },
  };
  return { blob, endpoint: dbEndpoint(host, port), ...(caFingerprint ? { caFingerprint } : {}), warnings };
}
