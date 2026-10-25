import { homedir } from "node:os";
import { dirname, isAbsolute, join, normalize } from "node:path";
import { stat } from "node:fs/promises";
import { OpsError } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";
import { BUILTIN_EXEC_TEMPLATES, matchExecSpec } from "./exec-templates.ts";
import type { ExecTemplate } from "./exec-templates.ts";
import { hashFile } from "./kubeconfig.ts";
import type { KubeExecSpec } from "./kubeconfig.ts";

export interface ExecCredentialResult {
  readonly token?: string;
  readonly clientCertPem?: string;
  readonly clientKeyPem?: string;
  /** Eklentinin bildirdiği bitiş; yoksa önbelleğe alınmaz. */
  readonly expiresAt?: Date;
}

export interface ExecRunnerOptions {
  /** `null`: OS sandbox yok → eklenti ÇALIŞTIRILMAZ (fail-closed). */
  readonly sandbox: Sandbox | null;
  readonly catalog?: readonly ExecTemplate[];
  /** Host ortamı (yalnız profilde BEYAN EDİLEN ambient adlar buradan alınır). */
  readonly hostEnv?: () => NodeJS.ProcessEnv;
  readonly homeDir?: string;
  readonly timeoutMs?: number;
  readonly now?: () => Date;
}

const HOME_PREFIX = "home:";
const ENV_PREFIX = "env:";
const PATH_PREFIX = "path:";
const FORBIDDEN_BINDS = new Set(["/", "/home", "/root", "/etc", "/var", "/usr", "/proc", "/sys", "/dev", "/run"]);

/** Profildeki `ambientDependencies` girdisi: `env:AD`, `home:.aws/config`, `path:/mutlak/dizin`. */
export function parseAmbient(deps: readonly string[]): { env: string[]; home: string[]; paths: string[] } {
  const out = { env: [] as string[], home: [] as string[], paths: [] as string[] };
  for (const d of deps) {
    if (d.startsWith(ENV_PREFIX)) out.env.push(d.slice(ENV_PREFIX.length));
    else if (d.startsWith(HOME_PREFIX)) out.home.push(d.slice(HOME_PREFIX.length));
    else if (d.startsWith(PATH_PREFIX)) out.paths.push(d.slice(PATH_PREFIX.length));
  }
  return out;
}

export function ambientFor(template: ExecTemplate, extra: { optInEnv?: readonly string[]; paths?: readonly string[] } = {}): string[] {
  const optIn = (extra.optInEnv ?? []).filter((n) => template.ambient.optInEnv.includes(n));
  return [
    ...template.ambient.defaultEnv.map((n) => `${ENV_PREFIX}${n}`),
    ...optIn.map((n) => `${ENV_PREFIX}${n}`),
    ...template.ambient.homeFiles.map((f) => `${HOME_PREFIX}${f}`),
    ...(extra.paths ?? []).map((p) => `${PATH_PREFIX}${p}`),
  ];
}

export function validateBindPath(p: string): void {
  const n = normalize(p);
  if (!isAbsolute(n) || n.split("/").includes("..") || FORBIDDEN_BINDS.has(n.replace(/\/+$/, "") || "/")) {
    throw new OpsError("exec_bind_refused", "ambient yolu geçersiz veya çok geniş");
  }
}

/** ExecCredential (client.authentication.k8s.io) çıktısını doğrular. */
export function parseExecCredential(stdout: Buffer): ExecCredentialResult {
  let j: unknown;
  try {
    j = JSON.parse(stdout.toString("utf8"));
  } catch {
    throw new OpsError("exec_output_invalid", "eklenti çıktısı JSON değil");
  }
  const o = j as { apiVersion?: unknown; kind?: unknown; status?: Record<string, unknown> } | null;
  if (!o || o.kind !== "ExecCredential" || typeof o.apiVersion !== "string" || !o.apiVersion.startsWith("client.authentication.k8s.io/")) {
    throw new OpsError("exec_output_invalid", "eklenti çıktısı ExecCredential değil");
  }
  const st = o.status ?? {};
  const token = typeof st["token"] === "string" && st["token"] ? (st["token"] as string) : undefined;
  const cert = typeof st["clientCertificateData"] === "string" ? (st["clientCertificateData"] as string) : undefined;
  const key = typeof st["clientKeyData"] === "string" ? (st["clientKeyData"] as string) : undefined;
  if (!token && !(cert && key)) throw new OpsError("exec_output_invalid", "eklenti kimlik üretmedi (token veya sertifika yok)");
  let expiresAt: Date | undefined;
  if (typeof st["expirationTimestamp"] === "string") {
    const t = Date.parse(st["expirationTimestamp"] as string);
    if (!Number.isNaN(t)) expiresAt = new Date(t);
  }
  return { ...(token ? { token } : {}), ...(cert && key ? { clientCertPem: cert, clientKeyPem: key } : {}), ...(expiresAt ? { expiresAt } : {}) };
}

/**
 * kubeconfig `exec` kimlik eklentisini YALNIZ OS sandbox içinde ve şablona uygun çalıştırır:
 *  - sandbox yoksa çalıştırmaz (fail-closed);
 *  - argv/env her çalıştırmada şablon kataloğuna karşı YENİDEN doğrulanır;
 *  - ikilinin SHA-256'sı import'taki ile eşleşmezse çalıştırmaz;
 *  - sandbox ortamı temizdir; yalnız profilin beyan ettiği ambient env/dosyalar geçer;
 *  - stderr hiçbir yere taşınmaz (hata mesajında yalnız çıkış kodu).
 */
export class ExecCredentialRunner {
  private readonly o: ExecRunnerOptions;
  constructor(opts: ExecRunnerOptions) {
    this.o = opts;
  }

  get sandboxKind(): string {
    return this.o.sandbox?.kind ?? "yok";
  }

  async run(exec: KubeExecSpec, ambientDeps: readonly string[]): Promise<ExecCredentialResult> {
    const sandbox = this.o.sandbox;
    if (!sandbox) {
      throw new OpsError("sandbox_unavailable", "OS sandbox yok (bubblewrap/seatbelt): exec kimlik eklentisi çalıştırılamaz");
    }
    // Pin host ikilisine aittir; konukta ne ikili ne bulut CLI kimlik deposu vardır (ADR-0011 sınırlar).
    if (sandbox.kind === "vm") throw new OpsError("sandbox_unavailable", "exec kimlik eklentileri VM sandbox'ında desteklenmiyor (host ikilisi konukta çalışamaz; ADR-0011)");
    // şablon + argv yeniden doğrulama
    const catalog = this.o.catalog ?? BUILTIN_EXEC_TEMPLATES;
    const binName = exec.binaryPath.split("/").pop() ?? "";
    const m = matchExecSpec({ command: binName, args: exec.args, env: Object.entries(exec.env).map(([name, value]) => ({ name, value })) }, catalog);
    if (m.template.id !== exec.templateId) throw new OpsError("exec_template_changed", "kayıtlı şablon artık katalogda yok veya değişti; profili yeniden içe aktarın");
    // ikili bütünlüğü
    let digest: string;
    try {
      digest = await hashFile(exec.binaryPath);
    } catch {
      throw new OpsError("exec_binary_missing", "eklenti ikilisi bulunamadı");
    }
    if (digest !== exec.binarySha256) throw new OpsError("exec_binary_changed", "eklenti ikilisi içe aktarmadan beri değişti (hash uyuşmuyor); profili yeniden içe aktarın");

    // ambient: yalnız profilin beyan ettikleri
    const amb = parseAmbient(ambientDeps);
    const host = (this.o.hostEnv ?? (() => process.env))();
    const allowedEnv = new Set([...m.template.ambient.defaultEnv, ...m.template.ambient.optInEnv]);
    const env: Record<string, string> = {};
    for (const name of amb.env) {
      const v = host[name];
      if (allowedEnv.has(name) && typeof v === "string" && v !== "") env[name] = v;
    }
    Object.assign(env, exec.env); // kubeconfig'teki (şablonca doğrulanmış) değerler önceliklidir

    const home = this.o.homeDir ?? homedir();
    const roBinds = new Set<string>([dirname(exec.binaryPath)]);
    for (const rel of amb.home) {
      if (rel.includes("..") || isAbsolute(rel)) throw new OpsError("exec_bind_refused", "home ambient yolu göreli olmalı");
      const abs = join(home, rel);
      try {
        await stat(abs);
        roBinds.add(abs);
      } catch {
        /* yok: bağlanmaz */
      }
    }
    for (const p of amb.paths) {
      validateBindPath(p);
      roBinds.add(p);
    }

    const r = await sandbox.run({
      argv: [exec.binaryPath, ...exec.args],
      env,
      roBinds: [...roBinds],
      network: m.template.network,
      home,
      timeoutMs: this.o.timeoutMs ?? 30_000,
      maxOutputBytes: 64 * 1024,
    });
    try {
      if (r.timedOut) throw new OpsError("exec_plugin_failed", `eklenti zaman aşımına uğradı (${m.template.id})`);
      if (r.truncated) throw new OpsError("exec_plugin_failed", `eklenti çıktısı sınırı aştı (${m.template.id})`);
      if (r.code !== 0) throw new OpsError("exec_plugin_failed", `eklenti hata ile çıktı (${m.template.id}, kod ${r.code ?? r.signal ?? "?"})`);
      return parseExecCredential(r.stdout);
    } finally {
      r.stdout.fill(0);
      r.stderr.fill(0);
    }
  }
}
