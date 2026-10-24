import { lstat, readlink } from "node:fs/promises";
import { DEFAULT_PATH, validateSpec } from "./types.ts";
import type { Sandbox, SandboxProcess, SandboxResult, SandboxSpec } from "./types.ts";
import { spawnLimited, spawnStreaming } from "./spawn.ts";

/** Host dizin düzeni (merged-usr symlink'leri vb.). Test için enjekte edilebilir. */
export interface HostLayout {
  /** `/bin` gibi yol → `usr/bin` (symlink hedefi) veya `dir` ya da yok (undefined). */
  entry(path: string): Promise<{ type: "symlink"; target: string } | { type: "dir" } | undefined>;
}

export const fsLayout: HostLayout = {
  async entry(path) {
    try {
      const st = await lstat(path);
      if (st.isSymbolicLink()) return { type: "symlink", target: await readlink(path) };
      if (st.isDirectory()) return { type: "dir" };
    } catch {
      /* yok */
    }
    return undefined;
  },
};

const SYSTEM_DIRS = ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"] as const;
/** Ağ KAPALIYKEN bile TLS doğrulaması için gereken sertifika deposu (kimlik değil). */
const ETC_COMMON = ["/etc/ssl", "/etc/ca-certificates", "/etc/pki", "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime"] as const;
const ETC_NET = ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/host.conf"] as const;

/**
 * `bwrap` argümanlarını kurar. Tasarım:
 *  - her ad alanı ayrı (`--unshare-all`); ağ yalnız `network: "host"` ise paylaşılır;
 *  - `--clearenv` + yalnız verilen ortam;
 *  - kök dosya sistemi boş: yalnız `/usr` ve sistem dizinleri SALT OKUNUR, `/etc` içinden yalnız
 *    sertifika deposu/çözümleyici dosyaları; `/home`, `/root`, `/run`, `/var` YOK (D-Bus/keyring
 *    soketleri, kimlik dizinleri bağlanmaz);
 *  - `--die-with-parent --new-session` (TIOCSTI/terminal kaçışı yok).
 */
export async function buildBwrapArgs(spec: SandboxSpec, layout: HostLayout = fsLayout): Promise<string[]> {
  validateSpec(spec);
  const a: string[] = ["--die-with-parent", "--new-session", "--unshare-all"];
  if (spec.network === "host") a.push("--share-net");
  a.push("--clearenv");
  const env: Record<string, string> = { PATH: DEFAULT_PATH, ...(spec.home ? { HOME: spec.home } : {}), ...spec.env };
  for (const [k, v] of Object.entries(env)) a.push("--setenv", k, v);

  a.push("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp");
  if (spec.home) a.push("--tmpfs", spec.home);

  a.push("--ro-bind", "/usr", "/usr");
  for (const d of SYSTEM_DIRS) {
    const e = await layout.entry(d);
    if (!e) continue;
    if (e.type === "symlink") a.push("--symlink", e.target, d);
    else a.push("--ro-bind", d, d);
  }
  const etc = [...ETC_COMMON, ...(spec.network === "host" ? ETC_NET : [])];
  for (const p of etc) {
    const e = await layout.entry(p);
    // dosyalar `lstat`ta "dir" değil: yalnız varlığını sormak için sabit liste deneriz
    if (e || (await existsFile(p))) a.push("--ro-bind-try", p, p);
  }
  for (const p of spec.roBinds ?? []) a.push("--ro-bind", p, p);
  for (const p of spec.rwBinds ?? []) a.push("--bind", p, p);
  if (spec.cwd) a.push("--chdir", spec.cwd);
  a.push("--", ...spec.argv);
  return a;
}

async function existsFile(p: string): Promise<boolean> {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

export class BwrapSandbox implements Sandbox {
  readonly kind = "bwrap" as const;
  private readonly bwrap: string;
  private readonly layout: HostLayout;

  constructor(bwrapPath: string, layout: HostLayout = fsLayout) {
    this.bwrap = bwrapPath;
    this.layout = layout;
  }

  async run(spec: SandboxSpec): Promise<SandboxResult> {
    const args = await buildBwrapArgs(spec, this.layout);
    return spawnLimited(this.bwrap, args, {
      timeoutMs: spec.timeoutMs,
      maxOutputBytes: spec.maxOutputBytes,
      env: { PATH: DEFAULT_PATH },
      ...(spec.stdin ? { stdin: spec.stdin } : {}),
    });
  }

  async spawn(spec: SandboxSpec): Promise<SandboxProcess> {
    const args = await buildBwrapArgs(spec, this.layout);
    return spawnStreaming(this.bwrap, args, { env: { PATH: DEFAULT_PATH }, lifetimeMs: spec.timeoutMs });
  }
}
