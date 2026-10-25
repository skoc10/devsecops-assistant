import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { OpsError } from "@ops/contracts";
import { LAYOUT_PATHS, buildBwrapArgs } from "./bwrap.ts";
import type { HostLayout, LayoutEntry } from "./bwrap.ts";
import { spawnLimited, spawnStreaming } from "./spawn.ts";
import { DEFAULT_PATH, validateSpec } from "./types.ts";
import type { Sandbox, SandboxFs, SandboxProcess, SandboxResult, SandboxSpec } from "./types.ts";

/**
 * VM sandbox'ı (ADR-0011): komutlar Vagrant yönetimli Linux konukta, orada da bubblewrap altında koşar.
 * Host'ta argümanlar Linux'taki AYNI kurucu (`buildBwrapArgs`) ile üretilir; farklı olan yalnız dizin düzeni
 * (konuktan okunur) ve yolların paylaşım köklerine ZORLANMASI. VM asla buradan başlatılmaz (`ops vm up`).
 */

export interface VmShare {
  /** Host dizini (mutlak). */
  readonly host: string;
  /** Konuktaki bağlama noktası (mutlak; bugün host ile aynı). */
  readonly guest: string;
  readonly mode: "rw" | "ro";
}

export interface VmState {
  readonly version: 1;
  readonly box: string;
  readonly boxVersion: string;
  readonly provider: string;
  readonly shares: readonly VmShare[];
  /** Konuk araç dizinleri (`OPS_TOOL_DIRS` karşılığı). */
  readonly toolDirs: readonly string[];
  /** Paylaşım dışı ama bağlanabilir konuk kökleri (araç kurulumları). */
  readonly guestRoots: readonly string[];
  /** `ops vm up`'ın yazdığı sertleştirilmiş ssh yapılandırması (`Host default`). */
  readonly sshConfig: string;
  readonly createdAt: string;
}

export const VM_STATE_FILE = "state.json";
/** Konukta araçların kurulu olduğu kök (provision.sh ile aynı). */
export const GUEST_TOOL_ROOT = "/opt/ops-tools";
export const GUEST_TOOL_DIRS: readonly string[] = [`${GUEST_TOOL_ROOT}/bin`, `${GUEST_TOOL_ROOT}/venv/bin`];
export const GUEST_NODE = `${GUEST_TOOL_ROOT}/node/bin/node`;
/** Varsayılan bağlanabilir konuk kökleri: araçlar ve venv yorumlayıcı zincirinin `/etc/alternatives`'i. */
export const DEFAULT_GUEST_ROOTS: readonly string[] = [GUEST_TOOL_ROOT, "/etc/alternatives"];
/** Uzak komut dizgesi tavanı (Linux `MAX_ARG_STRLEN` 128 KiB; pay bırakılır). */
export const MAX_REMOTE_COMMAND_BYTES = 100 * 1024;

/**
 * VM durum dizini: `OPS_VM_DIR` verilmişse o (ayrı/geçici OPS_HOME ile koşan testler gerçek kullanıcının VM'ini bu
 * yolla bulur); yoksa `OPS_HOME/vm` (varsayılan `~/.ops-assistant/vm`). İçerik: durum dosyası, ssh yapılandırması,
 * Vagrant `.vagrant/`.
 */
export function defaultVmStateDir(env: Readonly<Record<string, string | undefined>> = process.env, opsHomeVmDir?: string): string {
  return env["OPS_VM_DIR"] ?? opsHomeVmDir ?? join(env["OPS_HOME"] ?? join(homedir(), ".ops-assistant"), "vm");
}

const isAbs = (p: unknown): p is string => typeof p === "string" && p.startsWith("/") && !p.includes("\0") && !p.split("/").includes("..");

/** `state.json` içeriğini doğrular; bozuk/eksik alan = hata (sessizce gevşetilmez). */
export function parseVmState(text: string): VmState {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new OpsError("vm_state_invalid", "VM durum dosyası JSON değil");
  }
  const o = v as Partial<Record<keyof VmState, unknown>>;
  const fail = (why: string): never => {
    throw new OpsError("vm_state_invalid", `VM durum dosyası geçersiz: ${why}`);
  };
  if (!o || typeof o !== "object" || o.version !== 1) fail("version");
  for (const k of ["box", "boxVersion", "provider", "sshConfig", "createdAt"] as const) if (typeof o[k] !== "string" || o[k] === "") fail(k);
  if (!isAbs(o.sshConfig)) fail("sshConfig mutlak olmalı");
  if (!Array.isArray(o.shares)) fail("shares");
  const shares: VmShare[] = (o.shares as unknown[]).map((s) => {
    const x = s as Partial<VmShare>;
    if (!isAbs(x.host) || !isAbs(x.guest) || (x.mode !== "rw" && x.mode !== "ro")) fail("shares[] {host, guest, mode}");
    return { host: stripSlash(x.host as string), guest: stripSlash(x.guest as string), mode: x.mode as "rw" | "ro" };
  });
  const strs = (k: "toolDirs" | "guestRoots"): string[] => {
    if (!Array.isArray(o[k]) || !(o[k] as unknown[]).every(isAbs)) fail(`${k}: mutlak yollar`);
    return (o[k] as string[]).map(stripSlash);
  };
  return {
    version: 1,
    box: o.box as string,
    boxVersion: o.boxVersion as string,
    provider: o.provider as string,
    shares,
    toolDirs: strs("toolDirs"),
    guestRoots: strs("guestRoots"),
    sshConfig: o.sshConfig as string,
    createdAt: o.createdAt as string,
  };
}

function stripSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, "") : p;
}

/** Durum dosyasını okur; yoksa `null` (VM "yok" sayılır), bozuksa hata. */
export async function loadVmState(stateDir: string): Promise<VmState | null> {
  let text: string;
  try {
    text = await readFile(join(stateDir, VM_STATE_FILE), "utf8");
  } catch {
    return null;
  }
  return parseVmState(text);
}

const under = (p: string, root: string): boolean => p === root || p.startsWith(`${root}/`);

/**
 * Host yolunu konuk yoluna çevirir. Yol bir paylaşımın altındaysa paylaşımın konuk önekiyle; bir konuk kökünün
 * altındaysa aynen; aksi halde `null` (paylaşılmamış = konukta YOK, uydurulmaz).
 */
export function mapGuestPath(path: string, state: Pick<VmState, "shares" | "guestRoots">): string | null {
  const p = stripSlash(path);
  // en uzun eşleşen paylaşım kazanır (iç içe paylaşımlar)
  const share = [...state.shares].filter((s) => under(p, s.host)).sort((a, b) => b.host.length - a.host.length)[0];
  if (share) return share.guest + p.slice(share.host.length);
  if (state.guestRoots.some((r) => under(p, r))) return p;
  return null;
}

function requireGuest(path: string, state: VmState, what: string, wantWrite: boolean): string {
  const g = mapGuestPath(path, state);
  if (g === null) {
    throw new OpsError(
      "vm_path_not_shared",
      `${what} VM ile paylaşılmamış bir host yolu: ${path.slice(0, 160)} — yalnız ${state.shares.map((s) => `${s.host} (${s.mode})`).join(", ") || "(paylaşım yok)"} ve konuk araç kökleri görünür (ADR-0011 §4)`,
    );
  }
  if (wantWrite) {
    const share = state.shares.find((s) => under(stripSlash(path), s.host));
    if (!share || share.mode !== "rw") throw new OpsError("vm_path_not_shared", `${what} yazılabilir bağlanmak istendi ama paylaşım salt okunur / konuk kökü: ${path.slice(0, 160)}`);
  }
  return g;
}

/** Dizge bir paylaşım host yoluyla başlıyorsa (veya `=` sonrasında öyle bir yol varsa) konuk karşılığına çevirir. */
function mapEmbedded(s: string, state: VmState): string {
  const tr = (seg: string): string => {
    if (!seg.startsWith("/")) return seg;
    for (const sh of [...state.shares].sort((a, b) => b.host.length - a.host.length)) {
      if (under(stripSlash(seg), sh.host)) return sh.guest + seg.slice(sh.host.length);
    }
    return seg;
  };
  const eq = s.indexOf("=");
  if (s.startsWith("/")) return tr(s);
  if (eq > 0 && s[eq + 1] === "/") return `${s.slice(0, eq + 1)}${tr(s.slice(eq + 1))}`;
  return s;
}

/**
 * Spec'teki yolları konuk yollarına çevirir ve ZORLAR: `roBinds`/`rwBinds` paylaşım ya da konuk kökü altında olmalı
 * (`rwBinds` için `rw` paylaşım); `cwd` bunlardan biri, ev dizini (tmpfs) ya da `/tmp` altında olmalı; `home` olduğu
 * gibi kalır (sandbox içinde yaratılır). `argv[0]` paylaşım altındaysa çevrilir, değilse konuk ikilisi sayılır.
 */
export function translateSpec(spec: SandboxSpec, state: VmState): SandboxSpec {
  validateSpec(spec);
  const roBinds = (spec.roBinds ?? []).map((p) => requireGuest(p, state, "salt-okunur bağ", false));
  const rwBinds = (spec.rwBinds ?? []).map((p) => requireGuest(p, state, "yazılabilir bağ", true));
  let cwd = spec.cwd;
  if (cwd !== undefined) {
    const c = stripSlash(cwd);
    const virtual = (spec.home && under(c, stripSlash(spec.home))) || under(c, "/tmp");
    cwd = virtual ? cwd : requireGuest(cwd, state, "çalışma dizini", false);
  }
  const [bin, ...rest] = spec.argv as [string, ...string[]];
  const argv = [mapGuestPath(bin, state) ?? bin, ...rest.map((a) => mapEmbedded(a, state))];
  const env = Object.fromEntries(Object.entries(spec.env).map(([k, v]) => [k, mapEmbedded(v, state)]));
  return { ...spec, argv, env, roBinds, rwBinds, ...(cwd !== undefined ? { cwd } : {}) };
}

/** POSIX tek tırnak kaçışı: kabuk hiçbir şeyi yorumlamaz. */
export function shellQuote(s: string): string {
  if (s.includes("\0")) throw new OpsError("vm_bad_argument", "uzak komut argümanı NUL içeremez");
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Çağrı işareti: bwrap `--hostname ops-<jeton>` — konuktaki süreçleri `pkill -f` ile BULMAK için (ADR-0011 §3). */
export function callMarker(token: string): string {
  if (!/^[a-f0-9]{16}$/.test(token)) throw new OpsError("vm_bad_argument", "çağrı jetonu 16 hex karakter olmalı");
  return `ops-${token}`;
}

/** `--unshare-all`dan hemen sonra çağrı işaretini ekler (UTS ad alanı ayrı: hostname sandbox'a özeldir). */
export function withCallMarker(bwrapArgs: readonly string[], token: string): string[] {
  const i = bwrapArgs.indexOf("--unshare-all");
  if (i < 0) throw new OpsError("vm_bad_argument", "bwrap argümanlarında --unshare-all yok");
  return [...bwrapArgs.slice(0, i + 1), "--hostname", callMarker(token), ...bwrapArgs.slice(i + 1)];
}

/**
 * Konukta çalışacak tek komut dizgesi: `exec timeout -s KILL <s> bwrap <argümanlar>`. `timeout`, host süreci kill
 * yolunu çalıştıramadan ölse bile konukta kalıntı bırakmaz; bwrap `--die-with-parent` ile birlikte iki bağımsız kilit.
 */
export function buildRemoteCommand(bwrapArgs: readonly string[], opts: { readonly timeoutMs: number; readonly bwrapPath?: string }): string {
  const secs = Math.max(1, Math.ceil(opts.timeoutMs / 1000) + 2);
  const cmd = ["exec", "timeout", "-s", "KILL", String(secs), opts.bwrapPath ?? "bwrap", ...bwrapArgs.map(shellQuote)].join(" ");
  const n = Buffer.byteLength(cmd, "utf8");
  if (n > MAX_REMOTE_COMMAND_BYTES) throw new OpsError("vm_command_too_long", `uzak komut ${n} bayt: tavan ${MAX_REMOTE_COMMAND_BYTES} (argüman/bağ sayısını azaltın)`);
  return cmd;
}

/** Konuktaki `pkill` komutu: desen `[o]ps-…` kendisiyle eşleşmez (klasik hile), bwrap ve `timeout` süreçleriyle eşleşir. */
export function remoteKillCommand(token: string): string {
  const m = callMarker(token);
  return `pkill -KILL -f -- ${shellQuote(`[${m[0]}]${m.slice(1)}`)}; exit 0`;
}

/** Konuk düzen yoklaması: her yol için `symlink <hedef>` | `dir` | `file` | `none`. */
export function layoutProbeCommand(paths: readonly string[] = LAYOUT_PATHS): string {
  const list = paths.map(shellQuote).join(" ");
  return `for p in ${list}; do if [ -L "$p" ]; then printf '%s\\tsymlink\\t%s\\n' "$p" "$(readlink "$p")"; elif [ -d "$p" ]; then printf '%s\\tdir\\n' "$p"; elif [ -e "$p" ]; then printf '%s\\tfile\\n' "$p"; else printf '%s\\tnone\\n' "$p"; fi; done`;
}

export function parseLayoutProbe(text: string): Map<string, LayoutEntry> {
  const m = new Map<string, LayoutEntry>();
  for (const line of text.split("\n")) {
    if (!line) continue;
    const [p, type, target] = line.split("\t");
    if (!p || !type) continue;
    if (type === "symlink" && target !== undefined) m.set(p, { type: "symlink", target });
    else if (type === "dir") m.set(p, { type: "dir" });
    else if (type === "file") m.set(p, { type: "file" });
  }
  return m;
}

export interface VmSandboxOptions {
  readonly state: VmState;
  /** `ssh` ikilisi (mutlak). */
  readonly sshPath?: string;
  /** ssh_config'teki host adı. */
  readonly host?: string;
}

export class VmSandbox implements Sandbox {
  readonly kind = "vm" as const;
  readonly state: VmState;
  readonly toolDirs: readonly string[];
  readonly fs: SandboxFs;
  private readonly ssh: string;
  private readonly host: string;
  private layoutCache: Promise<HostLayout> | undefined;

  constructor(opts: VmSandboxOptions) {
    this.state = opts.state;
    this.toolDirs = opts.state.toolDirs;
    this.ssh = opts.sshPath ?? "/usr/bin/ssh";
    this.host = opts.host ?? "default";
    this.fs = new VmFs((cmd, timeoutMs) => this.remote(cmd, timeoutMs));
  }

  private sshArgs(): string[] {
    // Her şey yapılandırma dosyasındadır (`ops vm up` yazar); burada yalnız etkileşimsizlik zorlanır.
    return ["-F", this.state.sshConfig, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ClearAllForwardings=yes", this.host, "--"];
  }

  /** Konukta ham bir komut (bwrap'sız): yalnız düzen yoklaması, dosya sistemi soruları ve kalıntı temizliği için. */
  async remote(command: string, timeoutMs = 15_000, maxOutputBytes = 1_048_576): Promise<SandboxResult> {
    return spawnLimited(this.ssh, [...this.sshArgs(), command], { timeoutMs, maxOutputBytes, env: { PATH: DEFAULT_PATH } });
  }

  /** Konuk dizin düzeni; örnek ömrünce önbellek (başarısızsa bir sonraki çağrı yeniden dener). */
  layout(): Promise<HostLayout> {
    if (!this.layoutCache) {
      this.layoutCache = (async () => {
        const r = await this.remote(layoutProbeCommand());
        if (r.code !== 0) throw new OpsError("vm_unreachable", `VM'e erişilemedi veya düzen okunamadı (ssh çıkış ${r.code ?? r.signal}): ${r.stderr.toString("utf8").split("\n")[0]?.slice(0, 160) ?? ""} — \`ops vm status\``);
        const entries = parseLayoutProbe(r.stdout.toString("utf8"));
        return { entry: async (p: string) => entries.get(p) };
      })().catch((e: unknown) => {
        this.layoutCache = undefined;
        throw e;
      });
    }
    return this.layoutCache;
  }

  private async prepare(spec: SandboxSpec): Promise<{ cmd: string; token: string }> {
    const tspec = translateSpec(spec, this.state);
    const args = await buildBwrapArgs(tspec, await this.layout());
    const token = randomBytes(8).toString("hex");
    return { cmd: buildRemoteCommand(withCallMarker(args, token), { timeoutMs: spec.timeoutMs }), token };
  }

  /** Yerel ssh öldürüldüğünde konukta süreç KALIR (sshd sinyal göndermez): işaretle bulup öldürürüz. Arka planda, hata yutulur. */
  private remoteKill(token: string): void {
    void this.remote(remoteKillCommand(token), 10_000, 4096).catch(() => undefined);
  }

  async run(spec: SandboxSpec): Promise<SandboxResult> {
    const { cmd, token } = await this.prepare(spec);
    return spawnLimited(this.ssh, [...this.sshArgs(), cmd], {
      timeoutMs: spec.timeoutMs,
      maxOutputBytes: spec.maxOutputBytes,
      env: { PATH: DEFAULT_PATH },
      onKill: () => this.remoteKill(token),
      ...(spec.stdin ? { stdin: spec.stdin } : {}),
    });
  }

  async spawn(spec: SandboxSpec): Promise<SandboxProcess> {
    const { cmd, token } = await this.prepare(spec);
    return spawnStreaming(this.ssh, [...this.sshArgs(), cmd], { env: { PATH: DEFAULT_PATH }, lifetimeMs: spec.timeoutMs, onKill: () => this.remoteKill(token) });
  }

  /** VM erişilebilir ve bwrap konukta ÇALIŞIYOR mu? Gecikme ms cinsinden (sıcak bağlantıda ölçüm için). */
  async probe(timeoutMs = 20_000): Promise<{ ok: boolean; ms: number; error?: string }> {
    const t0 = Date.now();
    try {
      const r = await this.run({ argv: ["/bin/sh", "-c", "exit 0"], env: {}, timeoutMs, maxOutputBytes: 4096 });
      const ms = Date.now() - t0;
      if (r.code === 0) return { ok: true, ms };
      return { ok: false, ms, error: `çıkış ${r.code ?? r.signal}: ${r.stderr.toString("utf8").split("\n")[0]?.slice(0, 160) ?? ""}` };
    } catch (e) {
      return { ok: false, ms: Date.now() - t0, error: e instanceof Error ? e.message : String(e) };
    }
  }
}

/** Konuk dosya sistemi görünümü: her soru tek bir ssh komutu (bwrap'sız; yalnız meta veri/sha256, içerik taşınmaz). */
class VmFs implements SandboxFs {
  private readonly remote: (cmd: string, timeoutMs?: number) => Promise<SandboxResult>;
  constructor(remote: (cmd: string, timeoutMs?: number) => Promise<SandboxResult>) {
    this.remote = remote;
  }
  private async ok(cmd: string): Promise<boolean> {
    const r = await this.remote(cmd).catch(() => null);
    return r?.code === 0;
  }
  private async line(cmd: string): Promise<string | null> {
    const r = await this.remote(cmd).catch(() => null);
    if (!r || r.code !== 0) return null;
    const s = r.stdout.toString("utf8").replace(/\n$/, "");
    return s === "" ? null : s;
  }
  executable(path: string): Promise<boolean> {
    return this.ok(`test -f ${shellQuote(path)} && test -x ${shellQuote(path)}`);
  }
  exists(path: string): Promise<boolean> {
    return this.ok(`test -e ${shellQuote(path)} || test -L ${shellQuote(path)}`);
  }
  realpath(path: string): Promise<string | null> {
    return this.line(`realpath -e -- ${shellQuote(path)}`);
  }
  readlink(path: string): Promise<string | null> {
    return this.line(`readlink -- ${shellQuote(path)}`);
  }
  async sha256(path: string): Promise<string | null> {
    const s = await this.line(`sha256sum -- ${shellQuote(path)}`);
    const m = s ? /^([0-9a-f]{64}) /.exec(s) : null;
    return m ? (m[1] as string) : null;
  }
}
