import { access, constants } from "node:fs/promises";
import { join } from "node:path";
import { BwrapSandbox } from "./bwrap.ts";
import { SeatbeltSandbox } from "./seatbelt.ts";
import type { Sandbox } from "./types.ts";

export interface DetectOptions {
  readonly platform?: NodeJS.Platform;
  readonly pathEnv?: string;
  /** Çalışır durumda olduğunu sınayan yoklama; varsayılan: gerçek bir `true` çalıştırır. */
  readonly probe?: (sb: Sandbox) => Promise<boolean>;
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
    const r = await sb.run({ argv: ["/bin/sh", "-c", "exit 0"], env: {}, timeoutMs: 5_000, maxOutputBytes: 1024 });
    return r.code === 0;
  } catch {
    return false;
  }
}

/**
 * Bu makinede çalışan OS sandbox'ı bulur; yoksa `null` (çağıran fail-closed davranmalı).
 * Kurulu olması yetmez: yoklama gerçekten bir süreç çalıştırır (kullanıcı ad alanları kapalı olabilir).
 */
export async function detectSandbox(opts: DetectOptions = {}): Promise<Sandbox | null> {
  const platform = opts.platform ?? process.platform;
  const probe = opts.probe ?? defaultProbe;
  if (platform === "linux") {
    const p = await findInPath("bwrap", opts.pathEnv ?? process.env["PATH"] ?? "");
    if (!p) return null;
    const sb = new BwrapSandbox(p);
    return (await probe(sb)) ? sb : null;
  }
  if (platform === "darwin") {
    const sb = new SeatbeltSandbox();
    try {
      await access("/usr/bin/sandbox-exec", constants.X_OK);
    } catch {
      return null;
    }
    return (await probe(sb)) ? sb : null;
  }
  return null;
}
