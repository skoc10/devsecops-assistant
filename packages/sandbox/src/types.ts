/** Sandbox içinde çalıştırılacak tek bir komutun tam tanımı. Başka hiçbir şey görünmez. */
export interface SandboxSpec {
  /** Mutlak yol + argümanlar. Kabuk YOK: argv doğrudan exec edilir. */
  readonly argv: readonly string[];
  /** Sandbox'a verilen TEK ortam (host ortamı miras alınmaz). */
  readonly env: Readonly<Record<string, string>>;
  /** Salt okunur bağlanacak host yolları (aynı yolda görünür). */
  readonly roBinds?: readonly string[];
  /** Yazılabilir bağlanacak host yolları (nadir; gerekçelendirilmeli). */
  readonly rwBinds?: readonly string[];
  /** `none`: ağ ad alanı ayrı (varsayılan). `host`: host ağı (bulut CLI eklentileri). */
  readonly network?: "none" | "host";
  /** Sandbox içinde boş (tmpfs) oluşturulacak ev dizini; `HOME` bu yola ayarlanır. */
  readonly home?: string;
  readonly cwd?: string;
  readonly stdin?: Uint8Array;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

export interface SandboxResult {
  readonly code: number | null;
  readonly signal: string | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly timedOut: boolean;
  /** Çıktı `maxOutputBytes`'i aştı ve süreç öldürüldü. */
  readonly truncated: boolean;
}

import type { Readable, Writable } from "node:stream";

/** Akışlı (çift yönlü) sandbox süreci: stdin/stdout üzerinden satır tabanlı protokol için. */
export interface SandboxProcess {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  /** Süreç grubunu öldürür (idempotent). */
  kill(): void;
  readonly exited: Promise<{ code: number | null; signal: string | null }>;
}

/** `vm`: Vagrant yönetimli Linux VM içinde bubblewrap (ADR-0011; macOS). */
export type SandboxKind = "bwrap" | "seatbelt" | "vm" | "none";

/**
 * Sandbox'lı sürecin İKİLİLERİNİ gördüğü dosya sistemi (ADR-0011 §6). Yerel sandbox'larda host dosya sistemidir;
 * VM'de konuğunki. Araç çözümleme, venv yorumlayıcı zinciri ve ikili sha256 pinleri BU görünümle sorulur:
 * host'ta var olan bir ikili konukta yoktur (ve tersi).
 */
export interface SandboxFs {
  /** Yol var ve çalıştırılabilir mi (X_OK)? */
  executable(path: string): Promise<boolean>;
  exists(path: string): Promise<boolean>;
  /** Çözülmüş gerçek yol; yoksa `null`. */
  realpath(path: string): Promise<string | null>;
  /** Sembolik bağ hedefi (ham, çözülmemiş); bağ değilse/yoksa `null`. */
  readlink(path: string): Promise<string | null>;
  /** Dosyanın sha256 (hex); okunamazsa `null`. */
  sha256(path: string): Promise<string | null>;
}

export interface Sandbox {
  readonly kind: SandboxKind;
  run(spec: SandboxSpec): Promise<SandboxResult>;
  /** Akışlı çalıştırma. `timeoutMs` toplam ömürdür; `maxOutputBytes` uygulanmaz (tüketici sınırlar). */
  spawn(spec: SandboxSpec): Promise<SandboxProcess>;
  /** İkililerin bulunduğu dosya sistemi görünümü; verilmezse host dosya sistemi. */
  readonly fs?: SandboxFs;
  /** Sandbox'ın kendi getirdiği araç dizinleri (`OPS_TOOL_DIRS` karşılığı; VM'de konuk dizinleri). */
  readonly toolDirs?: readonly string[];
}

const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Ortak girdi doğrulaması: backend'ler çalıştırmadan önce çağırır. */
export function validateSpec(spec: SandboxSpec): void {
  if (spec.argv.length === 0) throw new Error("sandbox: argv boş");
  const bin = spec.argv[0] as string;
  if (!bin.startsWith("/")) throw new Error("sandbox: ikili yolu mutlak olmalı");
  for (const a of spec.argv) if (a.includes("\0")) throw new Error("sandbox: argv NUL içeremez");
  for (const [k, v] of Object.entries(spec.env)) {
    if (!ENV_KEY.test(k)) throw new Error(`sandbox: geçersiz ortam değişkeni adı: ${k.slice(0, 40)}`);
    if (v.includes("\0")) throw new Error("sandbox: ortam değeri NUL içeremez");
  }
  for (const p of [...(spec.roBinds ?? []), ...(spec.rwBinds ?? []), ...(spec.home ? [spec.home] : []), ...(spec.cwd ? [spec.cwd] : [])]) {
    if (!p.startsWith("/") || p.includes("\0") || p.split("/").includes("..")) throw new Error("sandbox: yollar mutlak olmalı ve '..' içermemeli");
  }
  if (!(spec.timeoutMs > 0) || !(spec.maxOutputBytes > 0)) throw new Error("sandbox: timeoutMs ve maxOutputBytes pozitif olmalı");
}

export const DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin";
