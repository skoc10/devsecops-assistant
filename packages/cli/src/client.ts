import { connect } from "node:net";
import type { Socket } from "node:net";
import { createInterface } from "node:readline";
import type { DoctorReport } from "@ops/contracts";
import type { OrchestratorEvent } from "@ops/core";
import type { BreakGlassStartArgs, ChatBackend, ProfileRow } from "./chat.ts";

interface Frame {
  id: number;
  ok?: boolean;
  result?: unknown;
  error?: { code: string; message: string };
  event?: OrchestratorEvent;
}

/** `opsd` istemcisi (NDJSON / UDS). `ChatBackend` uygular. */
export class OpsdClient implements ChatBackend {
  private readonly sock: Socket;
  private nextId = 1;
  private readonly waiters = new Map<number, (f: Frame) => void>();

  private constructor(sock: Socket) {
    this.sock = sock;
    const rl = createInterface({ input: sock, crlfDelay: Infinity });
    rl.on("line", (line) => {
      let f: Frame;
      try {
        f = JSON.parse(line) as Frame;
      } catch {
        return;
      }
      this.waiters.get(f.id)?.(f);
    });
    sock.on("close", () => {
      for (const w of this.waiters.values()) w({ id: -1, ok: false, error: { code: "closed", message: "bağlantı kapandı" } });
    });
  }

  static connect(path: string): Promise<OpsdClient> {
    return new Promise((resolve, reject) => {
      const s = connect(path);
      s.once("connect", () => resolve(new OpsdClient(s)));
      s.once("error", reject);
    });
  }

  close(): void {
    this.sock.destroy();
  }

  private async *frames(method: string, params?: Record<string, unknown>): AsyncGenerator<Frame> {
    const id = this.nextId++;
    const queue: Frame[] = [];
    let wake: (() => void) | undefined;
    this.waiters.set(id, (f) => {
      queue.push(f);
      wake?.();
    });
    this.sock.write(`${JSON.stringify({ id, method, ...(params ? { params } : {}) })}\n`);
    try {
      while (true) {
        while (queue.length === 0) await new Promise<void>((r) => (wake = r));
        const f = queue.shift() as Frame;
        yield f;
        if (f.ok !== undefined) return;
      }
    } finally {
      this.waiters.delete(id);
    }
  }

  async call<T>(method: string, params?: Record<string, unknown>): Promise<T> {
    for await (const f of this.frames(method, params)) {
      if (f.ok === true) return f.result as T;
      if (f.ok === false) throw new Error(`${f.error?.code ?? "hata"}: ${f.error?.message ?? ""}`);
    }
    throw new Error("yanıt yok");
  }

  async *send(text: string): AsyncGenerator<OrchestratorEvent> {
    for await (const f of this.frames("chat.send", { text })) {
      if (f.event) yield f.event;
      else if (f.ok === false) {
        yield { type: "error", code: f.error?.code ?? "hata", message: f.error?.message ?? "" };
        return;
      }
    }
  }

  bind(profileId: string): Promise<DoctorReport> {
    return this.call<DoctorReport>("profile.bind", { id: profileId });
  }
  profiles(): Promise<ProfileRow[]> {
    return this.call<ProfileRow[]>("profile.list");
  }
  usage(): Promise<string> {
    return this.call<string>("usage.get");
  }
  evidenceShow(id: string): Promise<string> {
    return this.call<string>("evidence.show", { id });
  }
  evidenceRelease(id: string): Promise<string> {
    return this.call<string>("evidence.release", { id });
  }
  breakGlassStatus(): Promise<string[]> {
    return this.call<string[]>("breakglass.status");
  }
  breakGlassStart(a: BreakGlassStartArgs): Promise<string[]> {
    return this.call<string[]>("breakglass.start", { ...a });
  }
  breakGlassEnd(profileId: string): Promise<string> {
    return this.call<string>("breakglass.end", { profile: profileId });
  }
  ping(): Promise<{ pong: boolean; session: string; localOnly: boolean; quarantine: "off" | "digest" | "model" }> {
    return this.call("ping");
  }
}
