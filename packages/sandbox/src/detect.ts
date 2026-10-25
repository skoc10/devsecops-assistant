import { access, constants } from "node:fs/promises";
import { join } from "node:path";
import { BwrapSandbox } from "./bwrap.ts";
import type { Sandbox } from "./types.ts";
import { VmSandbox, defaultVmStateDir, loadVmState } from "./vm.ts";

export interface DetectOptions {
  readonly platform?: NodeJS.Platform;
  readonly pathEnv?: string;
  /** Çalışır durumda olduğunu sınayan yoklama; varsayılan: gerçek bir `true` çalıştırır. */
  readonly probe?: (sb: Sandbox) => Promise<boolean>;
  /** `OPS_SANDBOX` ve `OPS_HOME` buradan okunur (varsayılan `process.env`). */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** VM durum dizini (varsayılan `OPS_HOME/vm`); `OPS_VM_DIR` ortam değişkeni her ikisini de geçersiz kılar. */
  readonly vmStateDir?: string;
}

export interface DetectResult {
  readonly sandbox: Sandbox | null;
  /** İnsan için neden (doktor/denetim). */
  readonly reason: string;
}

async function findInPath(bin: string, pathEnv: string): Promise<string | undefined> {
  for (const dir of pathEnv.split(":").filter(Boolean)) {
    const p = join(dir, bin);
    try {
      await access(p, constants.X_OK);
      return p;
    } catch {
      /* sonraki */
    }
  }
  return undefined;
}

async function defaultProbe(sb: Sandbox): Promise<boolean> {
  try {
    const r = await sb.run({ argv: ["/bin/sh", "-c", "exit 0"], env: {}, timeoutMs: 20_000, maxOutputBytes: 1024 });
    return r.code === 0;
  } catch {
    return false;
  }
}

/**
 * Bu makinede çalışan OS sandbox'ı bulur; yoksa `null` (çağıran fail-closed davranmalı).
 * Kurulu olması yetmez: yoklama gerçekten bir süreç çalıştırır (kullanıcı ad alanları kapalı olabilir).
 *
 * Sıra (ADR-0011 §2): `OPS_SANDBOX=none` → yok; `OPS_SANDBOX=vm` → yalnız VM; `OPS_SANDBOX=bwrap` → yalnız bwrap;
 * verilmediyse Linux'ta bwrap, macOS'ta VM durum dosyası varsa VM. macOS seatbelt yoklanmaz (macOS 27'de çalışmıyor).
 * VM hiçbir zaman buradan BAŞLATILMAZ.
 */
export async function detectSandboxDetailed(opts: DetectOptions = {}): Promise<DetectResult> {
  const platform = opts.platform ?? process.platform;
  const probe = opts.probe ?? defaultProbe;
  const env = opts.env ?? process.env;
  const mode = env["OPS_SANDBOX"];
  if (mode === "none") return { sandbox: null, reason: "OPS_SANDBOX=none: sandbox kapatıldı" };
  if (mode !== undefined && mode !== "" && mode !== "vm" && mode !== "bwrap") return { sandbox: null, reason: `OPS_SANDBOX geçersiz ('${mode.slice(0, 20)}'): vm | bwrap | none` };

  const vm = async (): Promise<DetectResult> => {
    const dir = defaultVmStateDir(env, opts.vmStateDir);
    const state = await loadVmState(dir);
    if (!state) return { sandbox: null, reason: `VM kurulu değil (${dir}/state.json yok): \`ops vm up\`` };
    const sb = new VmSandbox({ state });
    return (await probe(sb)) ? { sandbox: sb, reason: `VM (${state.box} ${state.boxVersion}, ${state.provider})` } : { sandbox: null, reason: "VM erişilemiyor ya da konukta bwrap çalışmıyor: `ops vm status` / `ops vm up`" };
  };
  const bwrap = async (): Promise<DetectResult> => {
    const p = await findInPath("bwrap", opts.pathEnv ?? env["PATH"] ?? "");
    if (!p) return { sandbox: null, reason: "bwrap PATH'te yok (bubblewrap kurun)" };
    const sb = new BwrapSandbox(p);
    return (await probe(sb)) ? { sandbox: sb, reason: `bubblewrap (${p})` } : { sandbox: null, reason: `bwrap çalışmıyor (${p}): kullanıcı ad alanları kapalı olabilir (kernel.apparmor_restrict_unprivileged_userns)` };
  };

  if (mode === "vm") return vm();
  if (mode === "bwrap") return bwrap();
  if (platform === "linux") return bwrap();
  if (platform === "darwin") {
    if (await loadVmState(defaultVmStateDir(env, opts.vmStateDir)).catch(() => null)) return vm();
    return { sandbox: null, reason: "macOS: seatbelt profili macOS 27'de çalışmıyor; Linux VM kurun: `ops vm up` (ADR-0011)" };
  }
  return { sandbox: null, reason: `desteklenmeyen platform: ${platform}` };
}

export async function detectSandbox(opts: DetectOptions = {}): Promise<Sandbox | null> {
  return (await detectSandboxDetailed(opts)).sandbox;
}
