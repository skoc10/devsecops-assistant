import { createInterface } from "node:readline";
import { OpsError } from "@ops/contracts";
import type { AgentRuntime, RuntimeCapabilities, RuntimeEvent, RuntimeTask, ToolBridge } from "@ops/contracts";
import type { Sandbox, SandboxProcess } from "@ops/sandbox";
import { encodeName } from "./launch.ts";
import { MAX_LINE_BYTES } from "./protocol.ts";
import type { HostToParent, ParentToHost } from "./protocol.ts";

export interface CursorRuntimeConfig {
  /** `null`/`none` ise çalışma zamanı ÇALIŞMAZ (fail-closed): SDK kullanıcının ortamını miras alır. */
  readonly sandbox: Sandbox | null;
  readonly model: string;
  /** Sandbox içinde çalışacak host komutu (mutlak ikili + argümanlar). */
  readonly hostArgv: readonly string[];
  /** Host'un ihtiyaç duyduğu salt-okunur dizinler (node ikilisi, host betiği, SDK). */
  readonly hostRoBinds: readonly string[];
  /** Host'a verilen SECRET OLMAYAN ortam (ör. SDK modül yolu). */
  readonly hostEnv?: Readonly<Record<string, string>>;
  /** Kasadan okunan Cursor API anahtarı; ilk stdin mesajıyla iletilir. */
  readonly apiKey?: () => Promise<string | undefined>;
  /**
   * ADR-0004 spike'ı (araç allowlist'i, sandbox, `request` olayı, hook) GERÇEK SDK ile elle
   * geçildiyse `true`. Aksi halde `builtinToolsDisableable: false` ve TAVSİYE KİPİ.
   */
  readonly spikePassed?: boolean;
  readonly lifetimeMs?: number;
  /** Sandbox içindeki çalışma dizini (tmpfs). */
  readonly cwd?: string;
}

const HOME = "/home/ops-sandbox";

/** SDK'nın raporladığı araç adı, köprüden verdiğimiz izinli adlardan biri mi? (ön ek tolere edilir) */
export function isAllowedToolName(reported: string, allowed: ReadonlySet<string>): boolean {
  for (const a of allowed) {
    const enc = encodeName(a);
    if (reported === a || reported === enc) return true;
    if (reported.endsWith(`__${enc}`) || reported.endsWith(`:${enc}`) || reported.endsWith(`/${enc}`) || reported.endsWith(`.${enc}`)) return true;
  }
  return false;
}

/**
 * Cursor `AgentRuntime`. SDK ayrı bir OS sürecinde (`cursor-host`), OS sandbox içinde koşar;
 * araçları yalnız bizim köprümüzdür (her çağrı PEP'e gider). Her `runTask` YENİ bir host/Agent
 * başlatır (stateless; resume'a güvenilmez). Çalışma zamanı bekçisi TESPİT EDİCİDİR: izinli
 * olmayan bir `tool_call` adı görürse görevi iptal eder, host'u öldürür ve alarm verir.
 */
export class CursorRuntime implements AgentRuntime {
  readonly id = "cursor";
  readonly model: string;
  readonly capabilities: RuntimeCapabilities;
  private readonly c: CursorRuntimeConfig;

  constructor(cfg: CursorRuntimeConfig) {
    this.c = cfg;
    this.model = cfg.model;
    this.capabilities = {
      builtinToolsDisableable: cfg.spikePassed === true,
      osSandboxed: cfg.sandbox !== null && cfg.sandbox.kind !== "none",
      trustZone: "third-party-cloud",
      statelessSupported: true,
    };
  }

  async *runTask(task: RuntimeTask, bridge: ToolBridge, signal?: AbortSignal): AsyncGenerator<RuntimeEvent> {
    const sandbox = this.c.sandbox;
    if (!sandbox || sandbox.kind === "none") {
      throw new OpsError("sandbox_unavailable", "OS sandbox yok: Cursor SDK kullanıcının ortamını miras alır, sandbox'sız çalıştırılmaz");
    }
    const specs = bridge.specs();
    const allowed = new Set(specs.map((s) => s.name));

    const apiKey = await this.c.apiKey?.();
    const proc: SandboxProcess = await sandbox.spawn({
      argv: this.c.hostArgv,
      env: { ...(this.c.hostEnv ?? {}) },
      roBinds: this.c.hostRoBinds,
      network: "host",
      home: HOME,
      cwd: this.c.cwd ?? "/tmp",
      timeoutMs: this.c.lifetimeMs ?? 10 * 60_000,
      maxOutputBytes: 1,
    });

    const queue: (HostToParent | { t: "closed" })[] = [];
    let wake: (() => void) | undefined;
    const push = (m: HostToParent | { t: "closed" }): void => {
      queue.push(m);
      wake?.();
    };
    const rl = createInterface({ input: proc.stdout, crlfDelay: Infinity });
    rl.on("line", (line) => {
      if (Buffer.byteLength(line) > MAX_LINE_BYTES) {
        push({ t: "error", message: "host satırı boyut sınırını aştı" });
        proc.kill();
        return;
      }
      try {
        push(JSON.parse(line) as HostToParent);
      } catch {
        /* host'tan gelen JSON olmayan satırlar yok sayılır (stderr değil, protokol dışı) */
      }
    });
    proc.stderr.resume(); // içeriği ASLA taşınmaz (secret içerebilir)
    void proc.exited.then(() => push({ t: "closed" }));
    const write = (m: ParentToHost): void => {
      if (!proc.stdin.destroyed) proc.stdin.write(`${JSON.stringify(m)}\n`);
    };
    const onAbort = (): void => {
      write({ t: "cancel" });
      setTimeout(() => proc.kill(), 200);
    };
    signal?.addEventListener("abort", onAbort, { once: true });

    write({
      t: "task",
      model: this.c.model,
      ...(apiKey ? { apiKey } : {}),
      system: task.system,
      prompt: task.prompt,
      ...(task.ledgerSummary ? { ledgerSummary: task.ledgerSummary } : {}),
      tools: specs,
      cwd: this.c.cwd ?? "/tmp",
    });

    let alarmed = false;
    try {
      for (;;) {
        while (queue.length === 0) await new Promise<void>((r) => (wake = r));
        const m = queue.shift() as HostToParent | { t: "closed" };
        if (m.t === "closed") {
          if (!alarmed && signal?.aborted !== true) throw new OpsError("provider_error", "cursor-host beklenmedik şekilde sonlandı");
          return;
        }
        if (m.t === "done") return;
        if (m.t === "error") throw new OpsError("provider_error", `cursor-host: ${m.message}`);
        if (m.t === "tool_request") {
          if (!allowed.has(m.name)) {
            alarmed = true;
            write({ t: "cancel" });
            proc.kill();
            yield { type: "alarm", code: "provider-shell-bypass", detail: `izinli olmayan köprü aracı istendi: ${m.name.slice(0, 60)}` };
            return;
          }
          const r = await bridge.invoke(m.name, m.args);
          write({ t: "tool_result", id: m.id, text: r.text, isError: r.isError });
          continue;
        }
        const ev = m.event as RuntimeEvent;
        if (ev.type === "tool_call") {
          // Bekçi (tespit edici): SDK'nın raporladığı her araç adı köprü araçlarından biri olmalı.
          if (!isAllowedToolName(ev.name, allowed)) {
            alarmed = true;
            write({ t: "cancel" });
            proc.kill();
            yield { type: "alarm", code: "provider-shell-bypass", detail: `SDK izinli olmayan araç çalıştırdı: ${ev.name.slice(0, 60)}` };
            return;
          }
        }
        yield ev;
      }
    } finally {
      signal?.removeEventListener("abort", onAbort);
      rl.close();
      proc.kill();
      await proc.exited;
    }
  }
}
