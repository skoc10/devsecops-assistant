import { localSandboxFs } from "./fs.ts";
import { DEFAULT_PATH, validateSpec } from "./types.ts";
import type { Sandbox, SandboxProcess, SandboxResult, SandboxSpec } from "./types.ts";
import { spawnLimited, spawnStreaming } from "./spawn.ts";

/**
 * İZOLASYONSUZ çalıştırıcı: yalnız ortamı temizler. Dosya sistemi, ağ ve süreç görünürlüğü
 * KORUNMAZ. Yalnız (a) testlerde, (b) kullanıcı bunu açıkça kabul ederse kullanılır; aksi halde
 * sandbox yoksa çağrı fail-closed reddedilir.
 */
export class UnsafeDirectRunner implements Sandbox {
  readonly kind = "none" as const;
  readonly fs = localSandboxFs;

  constructor(opts: { acknowledgeNoIsolation: true }) {
    if (opts.acknowledgeNoIsolation !== true) throw new Error("izolasyonsuz çalıştırıcı açık onay ister");
  }

  run(spec: SandboxSpec): Promise<SandboxResult> {
    validateSpec(spec);
    const [file, ...args] = spec.argv as [string, ...string[]];
    return spawnLimited(file, args, {
      timeoutMs: spec.timeoutMs,
      maxOutputBytes: spec.maxOutputBytes,
      env: { PATH: DEFAULT_PATH, ...(spec.home ? { HOME: spec.home } : {}), ...spec.env },
      ...(spec.stdin ? { stdin: spec.stdin } : {}),
    });
  }

  async spawn(spec: SandboxSpec): Promise<SandboxProcess> {
    validateSpec(spec);
    const [file, ...args] = spec.argv as [string, ...string[]];
    return spawnStreaming(file, args, { env: { PATH: DEFAULT_PATH, ...(spec.home ? { HOME: spec.home } : {}), ...spec.env }, lifetimeMs: spec.timeoutMs });
  }
}
