import { DEFAULT_PATH, validateSpec } from "./types.ts";
import type { Sandbox, SandboxResult, SandboxSpec } from "./types.ts";
import { spawnLimited } from "./spawn.ts";

/** Seatbelt (SBPL) dizge sabiti için güvenli kaçış: yalnız kontrollü karakterler kabul edilir. */
export function sbplString(s: string): string {
  if (/[\0\n\r"\\]/.test(s)) throw new Error("sandbox: yolda geçersiz karakter");
  return `"${s}"`;
}

const READ_SYSTEM = ["/usr", "/bin", "/sbin", "/System", "/Library/Apple", "/private/var/db/dyld", "/private/etc/ssl", "/private/etc/resolv.conf", "/etc/ssl"] as const;

/**
 * macOS `sandbox-exec` profili. UYARI: bu ortamda (Linux) ÇALIŞTIRILAMADI; yalnız profil
 * kurucusu birim testlidir. Gerçek davranış macOS'ta elle doğrulanmalıdır (tasarım §15).
 * `sandbox-exec` Apple tarafından "deprecated" işaretlidir [doğrulanacak].
 */
export function buildSeatbeltProfile(spec: SandboxSpec): string {
  validateSpec(spec);
  const reads = [...READ_SYSTEM, ...(spec.roBinds ?? []), ...(spec.rwBinds ?? []), ...(spec.argv[0] ? [spec.argv[0]] : [])];
  const writes = ["/private/tmp", "/private/var/tmp", ...(spec.home ? [spec.home] : []), ...(spec.rwBinds ?? [])];
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-exec*)",
    "(allow process-fork)",
    "(allow signal (target self))",
    "(allow sysctl-read)",
    '(allow file-read* (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (literal "/dev/zero"))',
    '(allow file-write* (literal "/dev/null"))',
    `(allow file-read* ${reads.map((p) => `(subpath ${sbplString(p)})`).join(" ")})`,
    `(allow file-write* ${writes.map((p) => `(subpath ${sbplString(p)})`).join(" ")})`,
  ];
  if (spec.network === "host") {
    lines.push("(allow network*)", '(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo") (global-name "com.apple.dnssd.service") (global-name "com.apple.SystemConfiguration.configd"))');
  } else {
    lines.push("(deny network*)");
  }
  return lines.join("\n");
}

export class SeatbeltSandbox implements Sandbox {
  readonly kind = "seatbelt" as const;
  private readonly sandboxExec: string;

  constructor(sandboxExecPath = "/usr/bin/sandbox-exec") {
    this.sandboxExec = sandboxExecPath;
  }

  /** `env -i` ile ortam temizlenir ve yalnız verilenler aktarılır. */
  buildCommand(spec: SandboxSpec): { file: string; args: string[] } {
    const profile = buildSeatbeltProfile(spec);
    const env: Record<string, string> = { PATH: DEFAULT_PATH, ...(spec.home ? { HOME: spec.home } : {}), ...spec.env };
    const kv = Object.entries(env).map(([k, v]) => `${k}=${v}`);
    return { file: this.sandboxExec, args: ["-p", profile, "/usr/bin/env", "-i", ...kv, ...spec.argv] };
  }

  async run(spec: SandboxSpec): Promise<SandboxResult> {
    const { file, args } = this.buildCommand(spec);
    return spawnLimited(file, args, {
      timeoutMs: spec.timeoutMs,
      maxOutputBytes: spec.maxOutputBytes,
      env: { PATH: DEFAULT_PATH },
      ...(spec.stdin ? { stdin: spec.stdin } : {}),
    });
  }
}
