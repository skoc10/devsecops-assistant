import { DEFAULT_PATH, validateSpec } from "./types.ts";
import type { Sandbox, SandboxResult, SandboxSpec } from "./types.ts";
import { spawnLimited } from "./spawn.ts";

/**
 * İZOLASYONSUZ çalıştırıcı: yalnız ortamı temizler. Dosya sistemi, ağ ve süreç görünürlüğü
 * KORUNMAZ. Yalnız (a) testlerde, (b) kullanıcı bunu açıkça kabul ederse kullanılır; aksi halde
 * sandbox yoksa çağrı fail-closed reddedilir.
 */
export class UnsafeDirectRunner implements Sandbox {
  readonly kind = "none" as const;

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
}
