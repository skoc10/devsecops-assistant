import { X509Certificate, createPrivateKey } from "node:crypto";
import { createHash } from "node:crypto";
import { access, constants, open, readFile, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
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
  /** Göreli dosya başvurularının çözüleceği dizin (kubeconfig'in bulunduğu dizin). `tokenFile` bu dizinin dışına çıkamaz. */
  readonly baseDir?: string;
  /** Test: dosya okuyucu. Varsayılan yalnız normal dosyaları, boyut sınırıyla okur. */
  readonly readFile?: (path: string) => Promise<Buffer>;
  /** Test: symlink çözücü (varsayılan `fs.realpath`). Dizin sınırı symlink'in HEDEFİNE göre denetlenir. */
  readonly realpath?: (path: string) => Promise<string>;
  /**
   * `tokenFile` kubeconfig dizininin DIŞINDAYSA (symlink hedefi dahil; kubeconfig ev dizininde veya üstündeyse her
   * konum dış sayılır) içe aktarma reddedilir: başkasının hazırladığı bir kubeconfig yerel bir secret'ı (ör.
   * `~/.vault-token`) kendi sunucusuna Bearer olarak taşıtamasın. Dış bir belirteç dosyasını bilerek kullanan (ör.
   * in-cluster `/var/run/secrets/...`) kullanıcı açıkça `true` verir; okunan yol yine uyarılarda raporlanır.
   */
  readonly allowExternalTokenFile?: boolean;
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

// ---- Başvurulan dosyalar (düşmanca olabilir: paylaşılan kubeconfig) ----------------------------------

type RefField = "certificate-authority" | "client-certificate" | "client-key" | "tokenFile";

/** Satır içine alınabilecek dosyanın üst sınırı (büyük CA demetleri dahil). */
const MAX_REF_FILE_BYTES = 1024 * 1024;
/** Taşıyıcı belirteç üst sınırı (JWT'ler birkaç KiB). */
const MAX_TOKEN_CHARS = 16 * 1024;
/** Gövde yalnız base64 + boşluk: blok içine/arasına karışmış başka içerik eşleşmez. */
const CERT_PEM = /-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----/g;
const KEY_PEM = /-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\s]+?-----END \1PRIVATE KEY-----/g;

/** Uyarı/hata metnine giren yol parçaları: denetim ve görünmez biçim karakterleri (ANSI kaçışı, bidi) görünür kaçışa çevrilir. */
const shown = (s: string): string => s.replace(/[\p{Cc}\p{Cf}]/gu, (ch) => `\\u{${(ch.codePointAt(0) ?? 0).toString(16)}}`);

/** `p`, `dir`'in kendisi veya altında mı (ikisi de mutlak ve symlink'leri çözülmüş). */
function inside(dir: string, p: string): boolean {
  const rel = relative(dir, p);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Varsayılan okuyucu: yalnız NORMAL dosya. FIFO/aygıt/dizin açılırken bloklanmaz (O_NONBLOCK) ve reddedilir; son
 * bileşen symlink olamaz (yol zaten realpath'ten gelir). stat boyutuna güvenilmez (procfs dosyaları 0 bildirip
 * sınırsız akabilir): okuma sınırda kesilir.
 */
async function readRegularFile(path: string): Promise<Buffer> {
  const fh = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    if (!(await fh.stat()).isFile()) throw new Error("normal dosya değil");
    const buf = Buffer.alloc(MAX_REF_FILE_BYTES + 1);
    let n = 0;
    while (n < buf.length) {
      const { bytesRead } = await fh.read(buf, n, buf.length - n, null);
      if (bytesRead === 0) break;
      n += bytesRead;
    }
    return buf.subarray(0, n);
  } finally {
    await fh.close();
  }
}

const invalidFile = (field: RefField, name: string, why: string): OpsError =>
  new OpsError("kubeconfig_file_invalid", `başvurulan dosya beklenen türde değil (${field}: ${name}): ${why}`);

/**
 * Sertifika dosyasından YALNIZ `CERTIFICATE` PEM blokları alınır ve her biri ayrıştırılır; blok dışındaki içerik
 * kasaya girmez. Hiç blok yoksa veya biri ayrıştırılamazsa ret: başka bir yerel dosya sertifika diye satır içine alınamaz.
 */
function certificatesFrom(text: string, field: RefField, name: string): string {
  const blocks = text.match(CERT_PEM) ?? [];
  if (blocks.length === 0) throw invalidFile(field, name, "PEM sertifika (CERTIFICATE) bloğu yok");
  for (const b of blocks) {
    try {
      new X509Certificate(b);
    } catch {
      throw invalidFile(field, name, "sertifika ayrıştırılamadı");
    }
  }
  return `${blocks.join("\n")}\n`;
}

/** İstemci anahtarı dosyasından TEK özel anahtar bloğu (PKCS#8, PKCS#1 RSA veya SEC1 EC) alınır ve ayrıştırılır. */
function privateKeyFrom(text: string, field: RefField, name: string): string {
  const blocks = text.match(KEY_PEM) ?? [];
  const [block] = blocks;
  if (blocks.length !== 1 || block === undefined) {
    throw invalidFile(field, name, blocks.length === 0 ? "PEM özel anahtar bloğu yok (PKCS#8, RSA veya EC; parolasız)" : "birden fazla özel anahtar bloğu");
  }
  try {
    createPrivateKey({ key: block, format: "pem" });
  } catch {
    throw invalidFile(field, name, "özel anahtar ayrıştırılamadı (parolalı anahtar desteklenmez)");
  }
  return `${block}\n`;
}

/** Belirteç dosyası tek bir taşıyıcı belirteç olmalı: boşluk/denetim karakteri yok (çok satırlı kimlik dosyaları ret). Boş dosya: belirteç yok. */
function tokenFrom(text: string, field: RefField, name: string): string | undefined {
  const t = text.trim();
  if (t === "") return undefined;
  if (t.length > MAX_TOKEN_CHARS || /[\s\p{Cc}]/u.test(t)) throw invalidFile(field, name, "tek satırlık bir belirteç değil");
  return t;
}

/** Alanın beklediği içerik türü: dosyadan yalnız bu doğrulayıcının döndürdüğü kasaya girer. */
const ACCEPT: Readonly<Record<RefField, (text: string, field: RefField, name: string) => string | undefined>> = {
  "certificate-authority": certificatesFrom,
  "client-certificate": certificatesFrom,
  "client-key": privateKeyFrom,
  tokenFile: tokenFrom,
};

/**
 * Kubeconfig'i içe aktarma ve normalleştirme. Yalnız TEK bağlam çıkarılır; harici dosyalar
 * (CA, istemci sertifikası/anahtarı, tokenFile) satır içine alınır ki kasa kendi kendine yeterli
 * olsun. Başvurular düşmanca olabilir (paylaşılan kubeconfig): sertifika/anahtar dosyasından yalnız ayrıştırılan,
 * beklenen türdeki PEM blokları alınır; `tokenFile` kubeconfig dizinine hapsedilir (açık izin hariç); okunan her
 * dosya uyarılarda YALNIZ yoluyla raporlanır. Reddedilenler: TLS doğrulamasını kapatma, proxy, düz http, şablon dışı
 * exec, auth-provider, basic auth. Hata ve uyarı mesajları secret veya dosya içeriği taşımaz.
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
    warnings.push(`kimlik exec eklentisiyle üretilir: ${m.template.id} (ikili ${shown(bin.path)}, SHA-256 pinli). Bulut CLI'sının kendi kimlik deposu kasa DIŞINDA kalır (ortam kimliği); eklenti yalnız OS sandbox içinde çalışır`);
  }

  const baseDir = resolve(opts.baseDir ?? process.cwd());
  const read = opts.readFile ?? readRegularFile;
  const real = opts.realpath ?? ((p: string) => realpath(p));

  /** `tokenFile` kubeconfig dizininde (veya altında) değilse yalnız açık izinle; kubeconfig ev dizinindeyse/üstündeyse sınır bir şey korumaz. */
  const guardTokenFile = async (full: string, name: string): Promise<void> => {
    let base: string;
    try {
      base = await real(baseDir);
    } catch {
      throw new OpsError("kubeconfig_file_unreadable", "kubeconfig dizini çözülemedi");
    }
    let homeUnderBase = false;
    try {
      homeUnderBase = inside(base, await real(homedir()));
    } catch {
      /* ev dizini yok/çözülemedi: yalnız dizin sınırı */
    }
    if (!homeUnderBase && full !== base && inside(base, full)) return;
    if (!opts.allowExternalTokenFile) {
      throw new OpsError(
        "kubeconfig_token_file_outside",
        `tokenFile kubeconfig dizininin dışında (symlink hedefi dahil${homeUnderBase ? "; kubeconfig ev dizininde veya üstünde olduğundan her konum dış sayılır" : ""}): ${name}. ` +
          "Başkasının hazırladığı bir kubeconfig yerel bir secret dosyasını kendi sunucusuna Bearer olarak taşıtabilir; dosyayı bilerek kullanıyorsanız açıkça izin verin (`ops profile add k8s --allow-external-token-file`)",
      );
    }
    warnings.push(`tokenFile kubeconfig dizininin DIŞINDA; açık izinle kabul edildi: ${shown(full)}`);
  };

  /**
   * Başvurulan dosyayı okur ve alanın beklediği türe göre doğrular (yalnız doğrulananı döndürür). Yol symlink'leri
   * çözülerek raporlanır: okunan her dosya uyarılara YALNIZ yoluyla girer (içerik asla); hata iletileri yalnız dosya
   * adını taşır.
   */
  const fromFile = async (field: RefField, p: string): Promise<string | undefined> => {
    const name = shown(basename(p));
    const unreadable = (): OpsError => new OpsError("kubeconfig_file_unreadable", `başvurulan dosya okunamadı veya normal bir dosya değil (${field}): ${name}`);
    let full: string;
    try {
      full = await real(resolve(baseDir, p));
    } catch {
      throw unreadable();
    }
    if (field === "tokenFile") await guardTokenFile(full, name);
    let buf: Buffer;
    try {
      buf = await read(full);
    } catch {
      throw unreadable();
    }
    const text = buf.length > MAX_REF_FILE_BYTES ? null : buf.toString("utf8");
    buf.fill(0);
    if (text === null) throw unreadable();
    warnings.push(`başvurulan dosya okundu ve satır içine alındı (${field}): ${shown(full)}`);
    return ACCEPT[field](text, field, name);
  };

  let caPem: string | undefined;
  if (str(cl["certificate-authority-data"])) caPem = decodeData(cl["certificate-authority-data"] as string, "CA");
  else if (str(cl["certificate-authority"])) caPem = await fromFile("certificate-authority", cl["certificate-authority"] as string);
  let caFingerprint: string | undefined;
  if (caPem) caFingerprint = fingerprintOf(caPem);
  else warnings.push("CA verisi yok: sistem kök sertifikaları kullanılır ve CA parmak izi pini oluşturulamaz");

  let token = str(us["token"]);
  if (!token && str(us["tokenFile"])) token = await fromFile("tokenFile", us["tokenFile"] as string);
  let clientCertPem: string | undefined;
  let clientKeyPem: string | undefined;
  if (str(us["client-certificate-data"])) clientCertPem = decodeData(us["client-certificate-data"] as string, "istemci sertifikası");
  else if (str(us["client-certificate"])) clientCertPem = await fromFile("client-certificate", us["client-certificate"] as string);
  if (str(us["client-key-data"])) clientKeyPem = decodeData(us["client-key-data"] as string, "istemci anahtarı");
  else if (str(us["client-key"])) clientKeyPem = await fromFile("client-key", us["client-key"] as string);
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
