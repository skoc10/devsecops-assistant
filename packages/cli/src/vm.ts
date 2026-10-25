import { spawn } from "node:child_process";
import { access, chmod, constants, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import type { Writable } from "node:stream";
import { OpsError } from "@ops/contracts";
import { stripControlChars } from "@ops/redaction";
import { DEFAULT_GUEST_ROOTS, GUEST_TOOL_DIRS, GUEST_TOOL_ROOT, VM_STATE_FILE, VmSandbox, loadVmState } from "@ops/sandbox";
import type { VmShare, VmState } from "@ops/sandbox";
import { WorkspaceRegistry } from "@ops/workspace";
import { MAX_SOCKET_PATH_BYTES, VM_VAGRANT_DIR, assertPrivateDir, ensureHome } from "./paths.ts";
import type { OpsPaths } from "./paths.ts";

/**
 * `ops vm …` (ADR-0011 §1): sandbox VM'i yalnız bu komutlarla başlar/durur. Vagrant depodaki `vm/Vagrantfile`
 * ile, makine durumu `OPS_HOME/vm/.vagrant` ile çalışır; paylaşımlar her `up`/`reload`da yeniden hesaplanır.
 */

export interface VmCliIo {
  readonly output: Writable;
  readonly error: Writable;
}

export interface VmCliOptions {
  readonly paths: OpsPaths;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly io: VmCliIo;
  /** Test: `vagrant` yerine çalıştırılacak ikili. */
  readonly vagrantPath?: string;
}

const VM_BOX = "bento/ubuntu-24.04";
const VM_BOX_VERSION = "202502.21.0";
const PROVIDERS = ["vmware_desktop", "virtualbox", "parallels", "utm"] as const;

async function exists(p: string): Promise<boolean> {
  try {
    await access(p, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function findVagrant(env: VmCliOptions["env"], explicit?: string): Promise<string> {
  const candidates = [explicit, env["OPS_VAGRANT"], ...(env["PATH"] ?? "").split(":").map((d) => join(d, "vagrant")), "/usr/local/bin/vagrant", "/opt/homebrew/bin/vagrant", "/usr/bin/vagrant"].filter((x): x is string => !!x);
  for (const c of candidates) {
    try {
      await access(c, constants.X_OK);
      return c;
    } catch {
      /* sonraki */
    }
  }
  throw new OpsError("vagrant_missing", "vagrant bulunamadı (PATH veya OPS_VAGRANT); https://developer.hashicorp.com/vagrant/install");
}

/** Vagrant'a geçen ortam: yalnız gerekenler (kasa/sağlayıcı anahtarları gibi OPS_* değişkenleri GEÇMEZ). */
function vagrantEnv(o: VmCliOptions, shares: readonly VmShare[], provider: string): Record<string, string> {
  const keep = ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "SSH_AUTH_SOCK"];
  const env: Record<string, string> = {};
  for (const k of keep) if (o.env[k]) env[k] = o.env[k] as string;
  for (const [k, v] of Object.entries(o.env)) if (k.startsWith("VAGRANT_") && v) env[k] = v;
  env["VAGRANT_CWD"] = VM_VAGRANT_DIR;
  env["VAGRANT_DOTFILE_PATH"] = join(o.paths.vmDir, ".vagrant");
  env["VAGRANT_NO_COLOR"] = "1";
  env["OPS_VM_SHARES"] = JSON.stringify(shares);
  env["OPS_VM_PROVIDER"] = provider;
  for (const k of ["OPS_VM_MEMORY", "OPS_VM_CPUS"]) if (o.env[k]) env[k] = o.env[k] as string;
  return env;
}

interface RunResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/** Alt süreç; `stream` verilirse çıktı canlı aktarılır (vagrant up dakikalar sürer). */
function run(file: string, args: readonly string[], env: Record<string, string>, stream?: VmCliIo, stdin?: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, [...args], { env, stdio: ["pipe", "pipe", "pipe"], shell: false });
    let out = "";
    let err = "";
    child.stdout.on("data", (b: Buffer) => {
      out += b.toString("utf8");
      if (stream) stream.output.write(stripControlChars(b.toString("utf8")));
    });
    child.stderr.on("data", (b: Buffer) => {
      err += b.toString("utf8");
      if (stream) stream.error.write(stripControlChars(b.toString("utf8")));
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: out, stderr: err }));
    child.stdin.on("error", () => undefined);
    child.stdin.end(stdin ?? "");
  });
}

/** Paylaşımlar (ADR-0011 §5): anlık kopya kökü (rw) + kayıtlı çalışma alanı depoları (ro). Başka hiçbir şey. */
export async function computeShares(paths: OpsPaths, env: VmCliOptions["env"]): Promise<VmShare[]> {
  await mkdir(paths.worktreesDir, { recursive: true, mode: 0o700 });
  await chmod(paths.worktreesDir, 0o700);
  const shares: VmShare[] = [{ host: paths.worktreesDir, guest: paths.worktreesDir, mode: "rw" }];
  if (await exists(paths.workspacesFile)) {
    const reg = await WorkspaceRegistry.open(paths.workspacesFile);
    for (const ws of reg.list()) if (!shares.some((s) => s.host === ws.path)) shares.push({ host: ws.path, guest: ws.path, mode: "ro" });
  }
  const home = env["HOME"] ?? homedir();
  const isAncestorOrSelf = (a: string, b: string): boolean => a === b || b.startsWith(`${a.replace(/\/+$/, "")}/`);
  for (const s of shares) {
    if (s.host === "/" || isAncestorOrSelf(s.host, home)) throw new OpsError("vm_share_refused", `paylaşım ev dizini/kök veya atası olamaz: ${s.host}`);
    if (s.host !== paths.worktreesDir && isAncestorOrSelf(s.host, paths.home)) throw new OpsError("vm_share_refused", `paylaşım OPS_HOME'u (kasa/denetim) kapsıyor: ${s.host}`);
  }
  return shares;
}

interface SshInfo {
  readonly hostName: string;
  readonly port: string;
  readonly user: string;
  readonly identityFile: string;
}

export function parseSshConfig(text: string): SshInfo {
  const get = (k: string): string | undefined => {
    const m = new RegExp(`^\\s*${k}\\s+(.+?)\\s*$`, "m").exec(text);
    return m?.[1];
  };
  const hostName = get("HostName");
  const port = get("Port");
  const user = get("User");
  const identityFile = get("IdentityFile")?.replace(/^"(.*)"$/, "$1");
  if (!hostName || !port || !user || !identityFile) throw new OpsError("vm_ssh_config_invalid", "vagrant ssh-config çıktısı eksik (HostName/Port/User/IdentityFile)");
  if (!/^[A-Za-z0-9.:-]+$/.test(hostName) || !/^\d{1,5}$/.test(port) || !/^[a-z_][a-z0-9_-]*$/.test(user) || !identityFile.startsWith("/")) throw new OpsError("vm_ssh_config_invalid", "vagrant ssh-config değerleri beklenmedik biçimde");
  return { hostName, port, user, identityFile };
}

/** Sertleştirilmiş ssh_config (ADR-0011 §7): sabit sunucu anahtarı, yalnız anahtar kimliği, iletim yok, çoğullama. */
export function renderSshConfig(info: SshInfo, knownHosts: string, controlPath: string): string {
  return [
    "# ops vm up tarafından üretildi; elle düzenlemeyin (ops vm reload yeniden yazar)",
    "Host default",
    `  HostName ${info.hostName}`,
    `  Port ${info.port}`,
    `  User ${info.user}`,
    `  IdentityFile ${info.identityFile}`,
    "  IdentitiesOnly yes",
    `  UserKnownHostsFile ${knownHosts}`,
    "  StrictHostKeyChecking yes",
    "  PasswordAuthentication no",
    "  KbdInteractiveAuthentication no",
    "  PubkeyAuthentication yes",
    "  ForwardAgent no",
    "  ForwardX11 no",
    "  ClearAllForwardings yes",
    "  RequestTTY no",
    "  ControlMaster auto",
    `  ControlPath ${controlPath}`,
    "  ControlPersist 600",
    "  ServerAliveInterval 15",
    "  ServerAliveCountMax 3",
    "  LogLevel ERROR",
    "",
  ].join("\n");
}

function controlPathFor(paths: OpsPaths): string {
  const p = join(paths.runDir, "vm.sock");
  const n = Buffer.byteLength(p, "utf8");
  if (n > MAX_SOCKET_PATH_BYTES) throw new OpsError("socket_path_too_long", `ssh ControlPath çok uzun (${n} bayt; sınır ${MAX_SOCKET_PATH_BYTES}): daha kısa bir OPS_HOME kullanın`);
  return p;
}

async function writePrivate(file: string, content: string): Promise<void> {
  await writeFile(file, content, { mode: 0o600 });
  await chmod(file, 0o600);
}

/** `vagrant up/reload` sonrası: ssh yapılandırması, sunucu anahtarı, durum dosyası ve konuk yoklaması. */
async function finishUp(o: VmCliOptions, vagrant: string, env: Record<string, string>, shares: readonly VmShare[], provider: string): Promise<VmSandbox> {
  const cfg = await run(vagrant, ["ssh-config"], env);
  if (cfg.code !== 0) throw new OpsError("vm_up_failed", `vagrant ssh-config başarısız: ${stripControlChars(cfg.stderr).split("\n")[0]?.slice(0, 200) ?? ""}`);
  const info = parseSshConfig(cfg.stdout);
  const knownHosts = join(o.paths.vmDir, "known_hosts");
  const scan = await run("/usr/bin/ssh-keyscan", ["-T", "15", "-p", info.port, info.hostName], { PATH: "/usr/bin:/bin" });
  const keys = scan.stdout.split("\n").filter((l) => l && !l.startsWith("#"));
  if (scan.code !== 0 || keys.length === 0) throw new OpsError("vm_up_failed", "VM sunucu anahtarı alınamadı (ssh-keyscan)");
  await writePrivate(knownHosts, `${keys.join("\n")}\n`);
  const sshConfig = join(o.paths.vmDir, "ssh_config");
  await writePrivate(sshConfig, renderSshConfig(info, knownHosts, controlPathFor(o.paths)));
  const state: VmState = {
    version: 1,
    box: VM_BOX,
    boxVersion: VM_BOX_VERSION,
    provider,
    shares,
    toolDirs: GUEST_TOOL_DIRS,
    guestRoots: DEFAULT_GUEST_ROOTS,
    sshConfig,
    createdAt: new Date().toISOString(),
  };
  const sb = new VmSandbox({ state });
  const probe = await sb.probe(60_000);
  if (!probe.ok) throw new OpsError("vm_up_failed", `VM açıldı ama konukta bwrap yoklaması geçmedi: ${probe.error ?? "?"} — \`ops vm provision\` deneyin`);
  await writePrivate(join(o.paths.vmDir, VM_STATE_FILE), `${JSON.stringify(state, null, 2)}\n`);
  return sb;
}

/** Konuk araç sürümleri (doktor ve `vm up` çıktısı için); her biri bwrap içinde, ağsız. */
export async function guestToolVersions(sb: VmSandbox): Promise<string[]> {
  const probes: [string, string[], string[]][] = [
    ["bwrap", ["/usr/bin/bwrap", "--version"], []],
    ["git", ["/usr/bin/git", "--version"], []],
    ["tofu", [`${GUEST_TOOL_ROOT}/bin/tofu`, "version"], [GUEST_TOOL_ROOT]],
    ["terraform", [`${GUEST_TOOL_ROOT}/bin/terraform`, "version"], [GUEST_TOOL_ROOT]],
    ["ansible", [`${GUEST_TOOL_ROOT}/venv/bin/ansible`, "--version"], [GUEST_TOOL_ROOT, "/etc/alternatives"]],
    ["ansible-lint", [`${GUEST_TOOL_ROOT}/venv/bin/ansible-lint`, "--version"], [GUEST_TOOL_ROOT, "/etc/alternatives"]],
    ["node", [`${GUEST_TOOL_ROOT}/node/bin/node`, "--version"], [GUEST_TOOL_ROOT]],
  ];
  const lines: string[] = [];
  for (const [name, argv, roBinds] of probes) {
    try {
      const r = await sb.run({ argv, env: { HOME: "/home/ops-doctor", LC_ALL: "C.UTF-8" }, roBinds, home: "/home/ops-doctor", network: "none", timeoutMs: 30_000, maxOutputBytes: 64 * 1024 });
      const first = stripControlChars(r.stdout.toString("utf8")).split("\n").find((l) => l.trim() !== "") ?? "";
      lines.push(r.code === 0 ? `  ${name}: ${first.slice(0, 120)}` : `  ${name}: ✗ (çıkış ${r.code ?? r.signal})`);
    } catch (e) {
      lines.push(`  ${name}: ✗ ${e instanceof Error ? e.message.slice(0, 120) : "?"}`);
    }
  }
  return lines;
}

const USAGE = [
  "kullanım: ops vm up [--provider vmware_desktop|virtualbox|parallels|utm] | status | halt | destroy | reload | provision | ssh-config",
  "  up        VM'i (gerekirse kutuyu indirip) başlatır, provizyonu ve paylaşımları uygular, bwrap'ı yoklar, OPS_HOME/vm/state.json yazar",
  "  status    Vagrant durumu + konuk erişimi/gecikme + paylaşımlar",
  "  halt      VM'i kapatır (durum dosyası kalır; araçlar VM açılana dek kapalı)",
  "  destroy   VM'i siler ve durum dosyasını kaldırır",
  "  reload    paylaşım listesini yeniden hesaplar (yeni çalışma alanı kaydı) ve VM'i yeniden başlatır",
  "  provision provizyon betiğini yeniden çalıştırır (araç sürümleri)",
  "  (ortam) OPS_VM_PROVIDER, OPS_VM_MEMORY=MB, OPS_VM_CPUS=N, OPS_VAGRANT=/yol/vagrant",
].join("\n");

export async function vmCommand(o: VmCliOptions, sub: string | undefined, rest: readonly string[]): Promise<number> {
  const out = (s: string): void => void o.io.output.write(`${s}\n`);
  if (!sub || sub === "help") {
    out(USAGE);
    return sub ? 0 : 2;
  }
  const { values } = parseArgs({ args: [...rest], options: { provider: { type: "string" } }, strict: true });
  const provider = values.provider ?? o.env["OPS_VM_PROVIDER"] ?? "vmware_desktop";
  if (!(PROVIDERS as readonly string[]).includes(provider)) throw new OpsError("usage", `--provider şunlardan biri olmalı: ${PROVIDERS.join(", ")}`);
  await ensureHome(o.paths);
  if ((await mkdir(o.paths.vmDir, { recursive: true, mode: 0o700 })) !== undefined) await chmod(o.paths.vmDir, 0o700);
  await assertPrivateDir(o.paths.vmDir);
  const vagrant = await findVagrant(o.env, o.vagrantPath);
  const stateFile = join(o.paths.vmDir, VM_STATE_FILE);

  switch (sub) {
    case "up":
    case "reload": {
      const shares = await computeShares(o.paths, o.env);
      const env = vagrantEnv(o, shares, provider);
      out(`Paylaşımlar (konukta aynı yolda):\n${shares.map((s) => `  ${s.host}  [${s.mode}]`).join("\n")}`);
      // Durum dosyası geçersizleşir: VM yeniden açılırken araçlar fail-closed kalır.
      await rm(stateFile, { force: true });
      const r = await run(vagrant, sub === "up" ? ["up", `--provider=${provider}`] : ["reload"], env, o.io);
      if (r.code !== 0) throw new OpsError("vm_up_failed", `vagrant ${sub} başarısız (çıkış ${r.code ?? "?"})`);
      const sb = await finishUp(o, vagrant, env, shares, provider);
      out(`VM hazır: ${VM_BOX} ${VM_BOX_VERSION} (${provider}); durum ${stateFile}`);
      for (const l of await guestToolVersions(sb)) out(l);
      out("Sandbox gerektiren araçlar artık VM içinde çalışır (bwrap). Kapatmak: `ops vm halt`.");
      return 0;
    }
    case "status": {
      const env = vagrantEnv(o, [], provider);
      const r = await run(vagrant, ["status", "--machine-readable"], env);
      const st = r.stdout.split("\n").map((l) => l.split(",")).find((f) => f[2] === "state")?.[3] ?? "bilinmiyor";
      out(`Vagrant: ${st} (${provider}; makine durumu ${join(o.paths.vmDir, ".vagrant")})`);
      const state = await loadVmState(o.paths.vmDir).catch((e: Error) => {
        out(`Durum dosyası: ✗ ${e.message}`);
        return null;
      });
      if (!state) {
        out("Durum dosyası yok: sandbox VM kurulu sayılmaz (`ops vm up`).");
        return st === "running" ? 1 : 0;
      }
      out(`Paylaşımlar:\n${state.shares.map((s) => `  ${s.host}  [${s.mode}]`).join("\n")}`);
      const sb = new VmSandbox({ state });
      const p1 = await sb.probe();
      if (!p1.ok) {
        out(`Konuk yoklaması: ✗ ${p1.error ?? "?"}`);
        return 1;
      }
      const p2 = await sb.probe();
      out(`Konuk yoklaması: ✓ bwrap çalışıyor (soğuk ${p1.ms} ms, sıcak ${p2.ms} ms)`);
      for (const l of await guestToolVersions(sb)) out(l);
      return 0;
    }
    case "halt": {
      const r = await run(vagrant, ["halt"], vagrantEnv(o, [], provider), o.io);
      return r.code === 0 ? 0 : 1;
    }
    case "destroy": {
      const r = await run(vagrant, ["destroy", "-f"], vagrantEnv(o, [], provider), o.io);
      for (const f of [stateFile, join(o.paths.vmDir, "ssh_config"), join(o.paths.vmDir, "known_hosts")]) await rm(f, { force: true });
      await rm(join(o.paths.runDir, "vm.sock"), { force: true });
      out("Durum dosyası silindi; sandbox gerektiren araçlar macOS'ta yeniden kapalı.");
      return r.code === 0 ? 0 : 1;
    }
    case "provision": {
      const state = await loadVmState(o.paths.vmDir);
      const shares = state?.shares ?? (await computeShares(o.paths, o.env));
      const env = vagrantEnv(o, shares, provider);
      const r = await run(vagrant, ["provision"], env, o.io);
      if (r.code !== 0) return 1;
      if (state) for (const l of await guestToolVersions(new VmSandbox({ state }))) out(l);
      return 0;
    }
    case "ssh-config": {
      const f = join(o.paths.vmDir, "ssh_config");
      out((await readFile(f, "utf8").catch(() => null)) ?? `(yok: ${f})`);
      return 0;
    }
    default:
      throw new OpsError("usage", USAGE);
  }
}
