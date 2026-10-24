import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface WireChatRequest {
  model: string;
  messages: { role: string; content: string | null; tool_calls?: { id: string; function: { name: string; arguments: string } }[]; tool_call_id?: string }[];
  tools?: { type: string; function: { name: string; description: string; parameters: unknown } }[];
  tool_choice?: string;
  max_tokens?: number;
}

export interface RecordedOpenAiRequest {
  readonly path: string;
  readonly authorization: string | null;
  readonly raw: string;
  readonly body: WireChatRequest;
}

export type FakeOpenAiStep = (req: WireChatRequest, turn: number) => { status?: number; json?: unknown; raw?: string; hang?: boolean; redirectTo?: string };

/** OpenAI Chat Completions uyumlu sahte uç (loopback, düz http). Gelen baytları kaydeder. */
export class FakeOpenAiServer {
  readonly requests: RecordedOpenAiRequest[] = [];
  readonly url: string;
  private turn = 0;
  private readonly server: Server;
  private readonly steps: FakeOpenAiStep[];
  private readonly sockets = new Set<import("node:net").Socket>();

  private constructor(server: Server, port: number, steps: FakeOpenAiStep[]) {
    this.server = server;
    this.steps = steps;
    this.url = `http://127.0.0.1:${port}/v1`;
    server.on("connection", (s) => {
      this.sockets.add(s);
      s.on("close", () => this.sockets.delete(s));
    });
  }

  static async start(steps: FakeOpenAiStep[]): Promise<FakeOpenAiServer> {
    let self: FakeOpenAiServer | undefined;
    const server = createServer((req, res) => void self?.handle(req, res));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    self = new FakeOpenAiServer(server, (server.address() as AddressInfo).port, steps);
    return self;
  }

  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((r) => this.server.close(() => r()));
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = JSON.parse(raw || "{}") as WireChatRequest;
    this.requests.push({ path: req.url ?? "", authorization: (req.headers.authorization as string | undefined) ?? null, raw, body });
    const step = this.steps[Math.min(this.turn, this.steps.length - 1)];
    const t = this.turn++;
    const out = step ? step(body, t) : { status: 500, raw: "adım yok" };
    if (out.hang) return;
    if (out.redirectTo) {
      res.writeHead(307, { location: out.redirectTo });
      res.end();
      return;
    }
    res.writeHead(out.status ?? 200, { "content-type": "application/json" });
    res.end(out.raw ?? JSON.stringify(out.json));
  }
}

/** Yanıt kurucuları. */
export const openAiText = (content: string, usage = { prompt_tokens: 100, completion_tokens: 20 }) => ({
  json: { choices: [{ message: { role: "assistant", content }, finish_reason: "stop" }], usage },
});
export const openAiToolCalls = (calls: { id?: string; name: string; args: unknown }[], usage = { prompt_tokens: 100, completion_tokens: 20 }) => ({
  json: {
    choices: [
      {
        message: {
          role: "assistant",
          content: null,
          tool_calls: calls.map((c, i) => ({ id: c.id ?? `call_${i + 1}`, type: "function", function: { name: c.name.replaceAll(".", "__"), arguments: typeof c.args === "string" ? c.args : JSON.stringify(c.args) } })),
        },
        finish_reason: "tool_calls",
      },
    ],
    usage,
  },
});
