import { access, constants, mkdir, readFile, readdir, readlink, realpath, rm, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { OpsError } from "@ops/contracts";
import type { Sandbox, SandboxResult } from "@ops/sandbox";

export interface ResolvedTool {
  readonly path: string;
  /** Sandbox'a salt-okunur bağlanacak kökler (venv veya ikilinin dizini). */
  readonly binds: string[];
}

const SYSTEM_DIRS = ["/usr/local/bin", "/usr/bin", "/bin"];

async function exists(p: string): Promise<boolean> {
  try {
    await access(p, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Venv yorumlayıcısının sembolik bağ zinciri sandbox'ta da çözülmeli: Debian/Ubuntu'da
 * `python3 -> /usr/bin/python3 -> /etc/alternatives/python3 -> /usr/bin/python3.13`. `/etc` sandbox'ta
 * boştur; yalnız `/etc/alternatives` (yalnızca sembolik bağlar) salt-okunur eklenir. `/usr` dışındaki
 * yorumlayıcı kurulumunun (pyenv, /opt) öneki de bağlanır.
 */
async function interpreterBinds(venvRoot: string): Promise<string[]> {
  const out = new Set<string>();
  let cur = join(venvRoot, "bin", "python3");
  for (let i = 0; i < 8; i++) {
    let target: string;
    try {
      target = await readlink(cur);
    } catch {
      break;
    }
    cur = isAbsolute(target) ? target : join(dirname(cur), target);
    if (cur.startsWith("/etc/alternatives/")) out.add("/etc/alternatives");
  }
  try {
    const real = await realpath(cur);
    if (!real.startsWith("/usr/") && !real.startsWith(venvRoot + "/")) out.add(dirname(dirname(real)));
  } catch {
    /* yorumlayıcı yok: araç zaten çalışmaz */
  }
  return [...out];
}

/**
 * IaC ikililerini YALNIZ yapılandırılmış dizinlerde (kullanıcı `toolDirs` + sistem dizinleri) arar;
 * `PATH`'e güvenilmez. Python venv'lerinin (ansible) kökü de bağlanır.
 */
export async function resolveTool(name: string, toolDirs: readonly string[]): Promise<ResolvedTool | null> {
  for (const d of [...toolDirs, ...SYSTEM_DIRS]) {
    const p = join(d, name);
    try {
      await access(p, constants.X_OK);
    } catch {
      continue;
    }
    const real = await realpath(p);
    const binds = new Set<string>();
    // venv kökünü bul: .../bin/<ad> ile aynı üst dizinde pyvenv.cfg
    const lexicalRoot = dirname(dirname(p));
    if (await exists(join(lexicalRoot, "pyvenv.cfg"))) {
      binds.add(lexicalRoot);
      for (const b of await interpreterBinds(lexicalRoot)) binds.add(b);
    } else binds.add(dirname(real));
    return { path: p, binds: [...binds].filter((b) => !b.startsWith("/usr/") && b !== "/usr") };
  }
  return null;
}

export const IAC_HOME = "/home/ops-iac";

export interface RunOptions {
  readonly sandbox: Sandbox;
  readonly tool: ResolvedTool;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly rwBinds: readonly string[];
  readonly roBinds?: readonly string[];
  readonly env?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
}

/** Sandbox içinde, ağsız, temiz ortamla bir IaC aracı çalıştırır. */
export async function runInSandbox(o: RunOptions): Promise<SandboxResult> {
  if (o.sandbox.kind === "none") throw new OpsError("sandbox_required", "IaC araçları yalnız OS sandbox içinde çalışır");
  return o.sandbox.run({
    argv: [o.tool.path, ...o.args],
    env: { LC_ALL: "C.UTF-8", NO_COLOR: "1", ...(o.env ?? {}) },
    roBinds: [...o.tool.binds, ...(o.roBinds ?? [])],
    rwBinds: [...o.rwBinds],
    cwd: o.cwd,
    network: "none",
    home: IAC_HOME,
    timeoutMs: o.timeoutMs ?? 120_000,
    maxOutputBytes: o.maxOutputBytes ?? 4_000_000,
  });
}

/** Terraform/OpenTofu için ürünün kendi CLI yapılandırması: ağdan sağlayıcı indirme YOK; isteğe bağlı yerel ayna. */
export async function writeTfRc(file: string, mirrorDir?: string): Promise<void> {
  const lines = ["disable_checkpoint = true", "provider_installation {"];
  if (mirrorDir) lines.push("  filesystem_mirror {", `    path    = "${mirrorDir.replace(/["\\]/g, "")}"`, '    include = ["*/*/*"]', "  }");
  lines.push("  direct {", '    exclude = ["*/*/*"]', "  }", "}", "");
  await writeFile(file, lines.join("\n"), { mode: 0o600 });
}

/** Araçların çalışma kopyasında bıraktığı önbellek dizinlerini siler (kullanıcıya/ajana sızmasın). */
export async function cleanWorkDir(workDir: string): Promise<string[]> {
  const removed: string[] = [];
  for (const d of [".terraform", ".ansible", ".cache", ".ansible-lint-cache", "__pycache__"]) {
    const p = join(workDir, d);
    try {
      await stat(p);
      await rm(p, { recursive: true, force: true });
      removed.push(d);
    } catch {
      /* yok */
    }
  }
  return removed;
}

export async function ensureDir(p: string): Promise<string> {
  await mkdir(p, { recursive: true, mode: 0o700 });
  return p;
}

export async function listTop(workDir: string): Promise<string[]> {
  return (await readdir(workDir)).sort();
}

export async function readIfExists(p: string): Promise<string | null> {
  try {
    return await readFile(p, "utf8");
  } catch {
    return null;
  }
}
