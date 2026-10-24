import { chmod, mkdir, rm } from "node:fs/promises";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { dirname } from "node:path";
import { createInterface } from "node:readline";
import { z } from "zod";
import { usageFromAudit, formatUsage } from "@ops/core";
import type { Orchestrator } from "@ops/core";
import { readAuditRecords } from "./backend.ts";
import type { ProfileRow } from "./chat.ts";
import type { Runtime } from "./runtime.ts";

const MAX_LINE = 1 << 20;

const Request = z.strictObject({
  id: z.number().int().nonnegative(),
  method: z.enum(["ping", "profile.list", "profile.bind", "chat.send", "usage.get", "shutdown"]),
  params: z.record(z.string(), z.unknown()).optional(),
});

export interface OpsdOptions {
  readonly runtime: Runtime;
  readonly orchestrator: Orchestrator;
  readonly socketPath: string;
  readonly onShutdown?: () => void;
}

/**
 * Yerel çekirdek servisi. UDS 0600 (dizin 0700); yalnız aynı kullanıcı bağlanır. ONAY KANALI BU
 * SOKETTE YOKTUR: onay yalnız UI sürecinin kontrol terminalinden (Faz 1). Bu soket sohbet ve
 * yönetim içindir; araç köprüsü (Cursor) ayrı, `tool.invoke` kapsamlı bir kanaldır (WP8).
 * Aynı anda tek `chat.send`.
 */
export class Opsd {
  private readonly o: OpsdOptions;
  private server: Server | undefined;
  private busy = false;
  private readonly sockets = new Set<Socket>();

  constructor(opts: OpsdOptions) {
    this.o = opts;
  }

  async listen(): Promise<void> {
    await mkdir(dirname(this.o.socketPath), { recursive: true, mode: 0o700 });
    await chmod(dirname(this.o.socketPath), 0o700);
    await rm(this.o.socketPath, { force: true }); // eski soket (süreç ölmüş olabilir)
    this.server = createServer((sock) => this.onConnection(sock));
    await new Promise<void>((resolve, reject) => {
      this.server?.once("error", reject);
      this.server?.listen(this.o.socketPath, resolve);
    });
    await chmod(this.o.socketPath, 0o600);
  }

  async close(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
    await rm(this.o.socketPath, { force: true });
  }

  private onConnection(sock: Socket): void {
    this.sockets.add(sock);
    sock.on("close", () => this.sockets.delete(sock));
    sock.on("error", () => undefined);
    const send = (obj: unknown): void => {
      if (!sock.destroyed) sock.write(`${JSON.stringify(obj)}\n`);
    };
    const rl = createInterface({ input: sock, crlfDelay: Infinity });
    rl.on("line", (line) => {
      if (line.length > MAX_LINE) {
        send({ id: -1, ok: false, error: { code: "too_large", message: "istek çok büyük" } });
        sock.destroy();
        return;
      }
      void this.handle(line, send);
    });
  }

  private async handle(line: string, send: (o: unknown) => void): Promise<void> {
    let id = -1;
    try {
      const json: unknown = JSON.parse(line);
      // geçersiz istekte de varsa sayısal kimlik yansıtılır: istemci sonsuza dek beklemesin
      const rawId = (json as { id?: unknown } | null)?.id;
      if (typeof rawId === "number" && Number.isInteger(rawId) && rawId >= 0) id = rawId;
      const parsed = Request.safeParse(json);
      if (!parsed.success) {
        send({ id, ok: false, error: { code: "bad_request", message: "geçersiz istek" } });
        return;
      }
      const req = parsed.data;
      id = req.id;
      const rt = this.o.runtime;
      switch (req.method) {
        case "ping":
          send({ id, ok: true, result: { pong: true, session: rt.session.id } });
          return;
        case "profile.list": {
          const rows: ProfileRow[] = rt.registry.list().map((p) => ({
            id: p.id, kind: p.kind, environment: p.environment, classCeiling: p.classCeiling, displayName: p.displayName,
            bound: rt.session.getBound(p.id) !== undefined,
          }));
          send({ id, ok: true, result: rows });
          return;
        }
        case "profile.bind": {
          const pid = String(req.params?.["id"] ?? "");
          send({ id, ok: true, result: await rt.bindProfile(pid) });
          return;
        }
        case "usage.get": {
          send({ id, ok: true, result: formatUsage(usageFromAudit(await readAuditRecords(rt.paths.auditLog), rt.session.id)) });
          return;
        }
        case "chat.send": {
          if (this.busy) {
            send({ id, ok: false, error: { code: "busy", message: "başka bir mesaj işleniyor" } });
            return;
          }
          this.busy = true;
          try {
            const text = String(req.params?.["text"] ?? "");
            for await (const ev of this.o.orchestrator.send(text)) send({ id, event: ev });
            send({ id, ok: true, result: { done: true } });
          } finally {
            this.busy = false;
          }
          return;
        }
        case "shutdown":
          send({ id, ok: true, result: { bye: true } });
          this.o.onShutdown?.();
          return;
      }
    } catch (e) {
      send({ id, ok: false, error: { code: "internal", message: e instanceof Error ? e.message.slice(0, 300) : "hata" } });
    }
  }
}
