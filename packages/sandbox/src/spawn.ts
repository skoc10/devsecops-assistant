import { spawn } from "node:child_process";
import type { SandboxProcess, SandboxResult } from "./types.ts";

export interface SpawnOpts {
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly stdin?: Uint8Array;
  /** spawn edilen sürecin KENDİ ortamı (sandbox ikilisi için asgari). */
  readonly env: Record<string, string>;
}

/** Zaman aşımı ve çıktı sınırı olan, kabuksuz spawn. Aşımda süreç öldürülür. */
export function spawnLimited(file: string, args: readonly string[], opts: SpawnOpts): Promise<SandboxResult> {
  return new Promise((resolve, reject) => {
    // Kendi süreç grubu: zaman aşımında torunlar da öldürülür (pipe'ları açık tutup `close`u geciktirmesinler).
    const child = spawn(file, [...args], { stdio: ["pipe", "pipe", "pipe"], env: opts.env, shell: false, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let size = 0;
    let truncated = false;
    let timedOut = false;
    const kill = (): void => {
      try {
        if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, opts.timeoutMs);
    const take = (into: Buffer[]) => (c: Buffer) => {
      size += c.length;
      if (size > opts.maxOutputBytes) {
        truncated = true;
        kill();
        return;
      }
      into.push(c);
    };
    child.stdout.on("data", take(out));
    child.stderr.on("data", take(err));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout: Buffer.concat(out), stderr: Buffer.concat(err), timedOut, truncated });
    });
    child.stdin.on("error", () => undefined); // süreç stdin'i okumadan çıkabilir
    if (opts.stdin) child.stdin.end(Buffer.from(opts.stdin));
    else child.stdin.end();
  });
}

/** Akışlı spawn: ömür sınırı dolunca süreç grubu öldürülür. */
export function spawnStreaming(file: string, args: readonly string[], opts: { env: Record<string, string>; lifetimeMs: number }): SandboxProcess {
  const child = spawn(file, [...args], { stdio: ["pipe", "pipe", "pipe"], env: opts.env, shell: false, detached: true });
  const kill = (): void => {
    try {
      if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
      else child.kill("SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
  };
  const timer = setTimeout(kill, opts.lifetimeMs);
  const exited = new Promise<{ code: number | null; signal: string | null }>((resolve) => {
    child.on("error", () => {
      clearTimeout(timer);
      resolve({ code: null, signal: "spawn_error" });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
  child.stdin.on("error", () => undefined);
  return { stdin: child.stdin, stdout: child.stdout, stderr: child.stderr, kill, exited };
}
