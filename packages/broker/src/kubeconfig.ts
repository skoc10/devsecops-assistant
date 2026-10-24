import { X509Certificate } from "node:crypto";
import { createHash } from "node:crypto";
import { access, constants, readFile, realpath } from "node:fs/promises";
import { basename, isAbsolute, join, resolve } from "node:path";
import { OpsError } from "@ops/contracts";
import { parse } from "yaml";
import { BUILTIN_EXEC_TEMPLATES, matchExecSpec } from "./exec-templates.ts";
import type { ExecTemplate } from "./exec-templates.ts";

/** Kasaya yazılan, normalize edilmiş TEK bağlam. Başka bağlamlar ve gereksiz alanlar atılır. */
export interface KubeExecSpec {
  readonly templateId: string;
  /** Gerçek (symlink'siz) mutlak yol; çalıştırmadan önce hash'i yeniden doğrulanır. */
  readonly binaryPath: string;
  readonly binarySha256: string;
  /** `binary` hariç, şablonca doğrulanmış argümanlar. */
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
}

export interface KubeCredentialBlob {
  readonly v: 1;
  /** `k8s-static`: token/sertifika kasada. `k8s-exec`: kimlik her lease'te sandbox'lı eklentiyle üretilir. */
  readonly kind: "k8s-static" | "k8s-exec";
  readonly server: string;
  readonly exec?: KubeExecSpec;
  readonly caPem?: string;
  readonly token?: string;
  readonly clientCertPem?: string;
  readonly clientKeyPem?: string;
  readonly tlsServerName?: string;
}

export interface ResolvedBinary {
  readonly path: string;
  readonly sha256: string;
}

export async function hashFile(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

/** Komut adını PATH'ten (veya mutlak yoldan) çözer, symlink'leri açar ve SHA-256'sını alır. */
export async function resolveBinaryDefault(command: string, pathEnv = process.env["PATH"] ?? ""): Promise<ResolvedBinary> {
  const candidates = isAbsolute(command) ? [command] : pathEnv.split(":").filter(Boolean).map((d) => join(d, command));
  for (const c of candidates) {
    try {
      await access(c, constants.X_OK);
      const real = await realpath(c);
      return { path: real, sha256: await hashFile(real) };
    } catch {
      /* sonraki */
    }
  }
  throw new OpsError("kubeconfig_exec_unsupported", `eklenti ikilisi bulunamadı: ${basename(command).slice(0, 40)}`);
}

export interface KubeImportOptions {
  /** `exec` kimlik eklentileri için izinli şablonlar; varsayılan ürünle gelen katalog. */
  readonly execCatalog?: readonly ExecTemplate[];
  readonly resolveBinary?: (command: string) => Promise<ResolvedBinary>;
  readonly context?: string;
  /** Göreli dosya başvurularının çözüleceği dizin (kubeconfig'in bulunduğu dizin). */
  readonly baseDir?: string;
  readonly readFile?: (path: string) => Promise<Buffer>;
}

export interface KubeImportResult {
  readonly contextName: string;
  readonly server: string;
  readonly namespace?: string;
  /** İlk CA sertifikasının SHA-256 parmak izi (küçük harf hex). CA yoksa yok. */
  readonly caFingerprint?: string;
  readonly auth: "token" | "client-cert" | "token+client-cert" | "exec" | "none";
  /** `exec` kimliği için şablon bilgisi (profilin `credentialSource`'unu kurmak için). */
  readonly exec?: { readonly template: ExecTemplate };
  readonly blob: KubeCredentialBlob;
  /** Secret içermez. */
  readonly warnings: string[];
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

function pemBlocks(pem: string): string[] {
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

function fingerprintOf(pem: string): string {
  const first = pemBlocks(pem)[0];
  if (!first) throw new OpsError("kubeconfig_invalid", "CA verisinde sertifika bulunamadı");
  try {
    return new X509Certificate(first).fingerprint256.replace(/:/g, "").toLowerCase();
  } catch {
    throw new OpsError("kubeconfig_invalid", "CA sertifikası ayrıştırılamadı");
  }
}

function decodeData(b64: string, what: string): string {
  const s = Buffer.from(b64, "base64").toString("utf8");
  if (!s.includes("-----BEGIN") && what !== "token") throw new OpsError("kubeconfig_invalid", `${what} verisi PEM değil`);
  return s;
}

/**
 * Kubeconfig'i içe aktarma ve normalleştirme. Yalnız TEK bağlam çıkarılır; harici dosyalar
 * (CA, istemci sertifikası/anahtarı, tokenFile) satır içine alınır ki kasa kendi kendine yeterli
 * olsun. Reddedilenler: TLS doğrulamasını kapatma, proxy, düz http, şablon dışı exec, auth-provider, basic
 * auth. Hata ve uyarı mesajları secret veya dosya içeriği taşımaz.
 */
export async function importKubeconfig(text: string, opts: KubeImportOptions = {}): Promise<KubeImportResult> {
  let doc: unknown;
  try {
    doc = parse(text);
  } catch {
    throw new OpsError("kubeconfig_invalid", "kubeconfig okunamadı (YAML geçersiz)");
  }
  if (!isObj(doc) || doc["kind"] !== "Config") throw new OpsError("kubeconfig_invalid", "kubeconfig bir 'Config' değil");
  const clusters = Array.isArray(doc["clusters"]) ? (doc["clusters"] as unknown[]).filter(isObj) : [];
  const users = Array.isArray(doc["users"]) ? (doc["users"] as unknown[]).filter(isObj) : [];
  const contexts = Array.isArray(doc["contexts"]) ? (doc["contexts"] as unknown[]).filter(isObj) : [];
  if (contexts.length === 0) throw new OpsError("kubeconfig_invalid", "kubeconfig'de bağlam yok");

  const wanted = opts.context ?? str(doc["current-context"]);
  if (!wanted) throw new OpsError("kubeconfig_context_required", "current-context yok: bağlam adı verin");
  const ctx = contexts.find((c) => c["name"] === wanted);
  if (!ctx || !isObj(ctx["context"])) throw new OpsError("kubeconfig_context_missing", `bağlam bulunamadı: ${wanted}`);
  const cx = ctx["context"] as Obj;

  const cluster = clusters.find((c) => c["name"] === cx["cluster"]);
  const user = users.find((u) => u["name"] === cx["user"]);
  if (!cluster || !isObj(cluster["cluster"])) throw new OpsError("kubeconfig_invalid", "bağlamın kümesi bulunamadı");
  if (!user || !isObj(user["user"])) throw new OpsError("kubeconfig_invalid", "bağlamın kullanıcısı bulunamadı");
  const cl = cluster["cluster"] as Obj;
  const us = user["user"] as Obj;

  const warnings: string[] = [];
  if (contexts.length > 1) warnings.push(`${contexts.length - 1} diğer bağlam atıldı; yalnız '${wanted}' içe aktarıldı`);

  // Reddedilen güvensiz yapılandırmalar
  if (cl["insecure-skip-tls-verify"] === true) throw new OpsError("kubeconfig_insecure_tls", "insecure-skip-tls-verify reddedilir (TLS doğrulaması kapatılamaz)");
  if (str(cl["proxy-url"])) throw new OpsError("kubeconfig_proxy", "proxy-url reddedilir (kimlik başka bir uca yönlenebilir)");
  if (us["auth-provider"] !== undefined) throw new OpsError("kubeconfig_auth_provider", "auth-provider (eski) desteklenmiyor");
  if (us["username"] !== undefined || us["password"] !== undefined) throw new OpsError("kubeconfig_basic_auth", "basic auth reddedilir");

  const server = str(cl["server"]);
  if (!server) throw new OpsError("kubeconfig_invalid", "küme sunucu adresi yok");
  let url: URL;
  try {
    url = new URL(server);
  } catch {
    throw new OpsError("kubeconfig_invalid", "sunucu adresi geçersiz");
  }
  if (url.protocol !== "https:") throw new OpsError("kubeconfig_insecure_tls", "sunucu adresi https olmalı");

  // exec kimlik eklentisi: yalnız şablon kataloğundaki ikili + argv + env
  let execSpec: KubeExecSpec | undefined;
  let execTemplate: ExecTemplate | undefined;
  if (us["exec"] !== undefined) {
    const ex = us["exec"];
    if (!isObj(ex)) throw new OpsError("kubeconfig_invalid", "exec girdisi geçersiz");
    if (us["token"] !== undefined || us["tokenFile"] !== undefined || us["client-certificate"] !== undefined || us["client-certificate-data"] !== undefined) {
      throw new OpsError("kubeconfig_invalid", "exec ile statik kimlik birlikte olamaz");
    }
    const apiVersion = str(ex["apiVersion"]) ?? "";
    if (!/^client\.authentication\.k8s\.io\/v1(?:beta1)?$/.test(apiVersion)) throw new OpsError("kubeconfig_exec_unsupported", "exec apiVersion desteklenmiyor (v1/v1beta1 beklenir)");
    if (ex["interactiveMode"] === "Always") throw new OpsError("kubeconfig_exec_unsupported", "etkileşimli exec eklentileri desteklenmiyor");
    const command = str(ex["command"]);
    if (!command) throw new OpsError("kubeconfig_invalid", "exec.command yok");
    const args = Array.isArray(ex["args"]) ? (ex["args"] as unknown[]).map((a) => (typeof a === "string" ? a : "\u0000")) : [];
    const envList = (Array.isArray(ex["env"]) ? (ex["env"] as unknown[]) : []).filter(isObj).map((e) => ({ name: String(e["name"] ?? ""), value: String(e["value"] ?? "") }));
    const m = matchExecSpec({ command, args, env: envList }, opts.execCatalog ?? BUILTIN_EXEC_TEMPLATES);
    const bin = await (opts.resolveBinary ?? resolveBinaryDefault)(command);
    execTemplate = m.template;
    execSpec = { templateId: m.template.id, binaryPath: bin.path, binarySha256: bin.sha256, args: m.args, env: m.env };
    warnings.push(`kimlik exec eklentisiyle üretilir: ${m.template.id}. Bulut CLI'sının kendi kimlik deposu kasa DIŞINDA kalır (ortam kimliği); eklenti yalnız OS sandbox içinde çalışır`);
  }

  const baseDir = opts.baseDir ?? process.cwd();
  const read = opts.readFile ?? ((p: string) => readFile(p));
  const fromFile = async (p: string): Promise<string> => {
    const full = isAbsolute(p) ? p : resolve(baseDir, p);
    try {
      return (await read(full)).toString("utf8");
    } catch {
      throw new OpsError("kubeconfig_file_unreadable", `başvurulan dosya okunamadı: ${basename(p)}`);
    }
  };

  let caPem: string | undefined;
  if (str(cl["certificate-authority-data"])) caPem = decodeData(cl["certificate-authority-data"] as string, "CA");
  else if (str(cl["certificate-authority"])) caPem = await fromFile(cl["certificate-authority"] as string);
  let caFingerprint: string | undefined;
  if (caPem) caFingerprint = fingerprintOf(caPem);
  else warnings.push("CA verisi yok: sistem kök sertifikaları kullanılır ve CA parmak izi pini oluşturulamaz");

  let token = str(us["token"]);
  if (!token && str(us["tokenFile"])) token = (await fromFile(us["tokenFile"] as string)).trim();
  let clientCertPem: string | undefined;
  let clientKeyPem: string | undefined;
  if (str(us["client-certificate-data"])) clientCertPem = decodeData(us["client-certificate-data"] as string, "istemci sertifikası");
  else if (str(us["client-certificate"])) clientCertPem = await fromFile(us["client-certificate"] as string);
  if (str(us["client-key-data"])) clientKeyPem = decodeData(us["client-key-data"] as string, "istemci anahtarı");
  else if (str(us["client-key"])) clientKeyPem = await fromFile(us["client-key"] as string);
  if (Boolean(clientCertPem) !== Boolean(clientKeyPem)) throw new OpsError("kubeconfig_invalid", "istemci sertifikası ve anahtarı birlikte olmalı");
  if (clientCertPem) {
    try {
      new X509Certificate(pemBlocks(clientCertPem)[0] ?? "");
    } catch {
      throw new OpsError("kubeconfig_invalid", "istemci sertifikası ayrıştırılamadı");
    }
  }

  const hasToken = Boolean(token);
  const hasCert = Boolean(clientCertPem);
  const auth: KubeImportResult["auth"] = execSpec ? "exec" : hasToken && hasCert ? "token+client-cert" : hasToken ? "token" : hasCert ? "client-cert" : "none";
  if (auth === "none") warnings.push("kimlik doğrulama bilgisi yok (anonim erişim)");

  const tlsServerName = str(cl["tls-server-name"]);
  const namespace = str(cx["namespace"]);
  const blob: KubeCredentialBlob = {
    v: 1,
    kind: execSpec ? "k8s-exec" : "k8s-static",
    server,
    ...(execSpec ? { exec: execSpec } : {}),
    ...(caPem ? { caPem } : {}),
    ...(token ? { token } : {}),
    ...(clientCertPem ? { clientCertPem } : {}),
    ...(clientKeyPem ? { clientKeyPem } : {}),
    ...(tlsServerName ? { tlsServerName } : {}),
  };
  return {
    contextName: wanted,
    server,
    ...(namespace ? { namespace } : {}),
    ...(caFingerprint ? { caFingerprint } : {}),
    auth,
    ...(execTemplate ? { exec: { template: execTemplate } } : {}),
    blob,
    warnings,
  };
}
