import type { Readable } from "node:stream";
import type { SandboxProcess } from "@ops/sandbox";
import { stripControlChars } from "@ops/redaction";

/**
 * Asgari MCP stdio istemcisi (JSON-RPC 2.0, satır sınırlı). Tasarım:
 *  - istemci yetenekleri BOŞ (`roots`/`sampling`/`elicitation` yok); sunucunun her isteği
 *    (`ping` hariç) `-32601` ile reddedilir ve sayılır → sunucu istemci üzerinden model/kullanıcıya ulaşamaz;
 *  - sunucu bildirimleri (log, ilerleme, `tools/list_changed`) YOK SAYILIR (modele gitmez);
 *  - satır ve toplam bayt tavanı; ayrıştırılamayan satır = protokol hatası (fail-closed);
 *  - tek çağrı = tek süreç: oturum durumu, süreç ömrü boyunca bile paylaşılmaz.
 */

/** Spesifikasyon sürümleri (doğrulanacak: https://modelcontextprotocol.io/specification/latest). Sunucu bunların dışında bir sürüm seçerse bağlantı kesilir. */
export const SUPPORTED_PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"] as const;

export class McpProtocolError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "McpProtocolError";
    this.code = code;
  }
}

type Json = Record<string, unknown>;

/** Sunucu kaynaklı serbest metni hata iletisine güvenle taşımak için: yalnız zararsız karakterler, kısa. */
export function safeSnippet(s: unknown, max = 160): string {
  return typeof s === "string" ? stripControlChars(s).replace(/[^A-Za-z0-9 .,:_'"()/-]/g, "?").slice(0, max) : "";
}

interface Limits {
  readonly maxLineBytes: number;
  readonly maxTotalBytes: number;
}

/** stdout'u satırlara ayırır; sınırlar aşılırsa hata verir. */
class LineWire {
  private buf: Buffer = Buffer.alloc(0);
  private total = 0;
  private readonly queue: Json[] = [];
  private waiter: { resolve: (m: Json) => void; reject: (e: Error) => void } | undefined;
  private failure: Error | undefined;
  private readonly limits: Limits;

  constructor(stream: Readable, limits: Limits) {
    this.limits = limits;
    stream.on("data", (chunk: Buffer) => this.onData(chunk));
    stream.on("end", () => this.fail(new McpProtocolError("mcp_server_exited", "sunucu yanıt vermeden stdout'u kapattı")));
    stream.on("error", () => this.fail(new McpProtocolError("mcp_server_exited", "sunucu çıktı akışı hatası")));
  }

  fail(e: Error): void {
    if (this.failure) return;
    this.failure = e;
    const w = this.waiter;
    this.waiter = undefined;
    w?.reject(e);
  }

  private onData(chunk: Buffer): void {
    if (this.failure) return;
    this.total += chunk.length;
    if (this.total > this.limits.maxTotalBytes) return this.fail(new McpProtocolError("mcp_output_too_large", "sunucu çıktısı toplam bayt tavanını aştı"));
    this.buf = Buffer.concat([this.buf, chunk]);
    for (;;) {
      const nl = this.buf.indexOf(0x0a);
      if (nl < 0) {
        if (this.buf.length > this.limits.maxLineBytes) this.fail(new McpProtocolError("mcp_line_too_long", "sunucu satırı bayt tavanını aştı"));
        return;
      }
      const line = this.buf.subarray(0, nl);
      this.buf = this.buf.subarray(nl + 1);
      if (line.length > this.limits.maxLineBytes) return this.fail(new McpProtocolError("mcp_line_too_long", "sunucu satırı bayt tavanını aştı"));
      const text = line.toString("utf8").trim();
      if (text === "") continue;
      let msg: unknown;
      try {
        msg = JSON.parse(text);
      } catch {
        return this.fail(new McpProtocolError("mcp_bad_json", "sunucu JSON olmayan satır yazdı (stdout yalnız MCP iletileri içermeli)"));
      }
      if (msg === null || typeof msg !== "object" || Array.isArray(msg) || (msg as Json)["jsonrpc"] !== "2.0") {
        return this.fail(new McpProtocolError("mcp_bad_message", "geçersiz JSON-RPC iletisi"));
      }
      const w = this.waiter;
      if (w) {
        this.waiter = undefined;
        w.resolve(msg as Json);
      } else this.queue.push(msg as Json);
    }
  }

  next(): Promise<Json> {
    const q = this.queue.shift();
    if (q) return Promise.resolve(q);
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      this.waiter = { resolve, reject };
    });
  }
}

export interface McpSessionOptions {
  readonly timeoutMs: number;
  readonly maxLineBytes?: number;
  readonly maxTotalBytes: number;
  readonly signal?: AbortSignal;
  readonly clientName?: string;
  readonly clientVersion?: string;
}

export interface McpToolListing {
  readonly names: string[];
  readonly total: number;
}

export interface McpCallResult {
  readonly isError: boolean;
  readonly texts: string[];
  readonly structured?: unknown;
  readonly resourceLinks: string[];
  readonly droppedBlocks: number;
  readonly truncated: boolean;
}

const TEXT_BLOCK_MAX = 20_000;
const TEXT_TOTAL_MAX = 40_000;
const STRUCTURED_MAX = 40_000;

/** Bir MCP sunucu sürecine karşı tek oturum. `close()` süreci öldürür; her yolda çağrılmalıdır. */
export class McpSession {
  private readonly proc: SandboxProcess;
  private readonly opts: McpSessionOptions;
  private readonly wire: LineWire;
  private readonly timer: NodeJS.Timeout;
  private nextId = 1;
  private closed = false;
  private stderrHead = "";
  serverRequests = 0;
  protocolVersion = "";
  serverName = "";

  constructor(proc: SandboxProcess, opts: McpSessionOptions) {
    this.proc = proc;
    this.opts = opts;
    this.wire = new LineWire(proc.stdout, { maxLineBytes: opts.maxLineBytes ?? 1_000_000, maxTotalBytes: opts.maxTotalBytes });
    proc.stderr.on("data", (c: Buffer) => {
      if (this.stderrHead.length < 400) this.stderrHead += c.toString("utf8").slice(0, 400);
    });
    proc.stderr.on("error", () => undefined);
    this.timer = setTimeout(() => this.wire.fail(new McpProtocolError("mcp_timeout", "sunucu zaman aşımına uğradı")), opts.timeoutMs);
    void proc.exited.then(() => this.wire.fail(new McpProtocolError("mcp_server_exited", "sunucu süreci sonlandı")));
    const onAbort = (): void => this.wire.fail(new McpProtocolError("mcp_aborted", "çağrı iptal edildi"));
    if (opts.signal?.aborted) onAbort();
    else opts.signal?.addEventListener("abort", onAbort, { once: true });
  }

  /** Hata ayıklama için (modele GİTMEZ): sunucu stderr'inin güvenli başı. */
  get stderrSnippet(): string {
    return safeSnippet(this.stderrHead, 200);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.timer);
    try {
      this.proc.stdin.end();
    } catch {
      /* kapalı */
    }
    this.proc.kill();
  }

  private send(msg: Json): void {
    this.proc.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...msg })}\n`);
  }

  private async request(method: string, params: Json): Promise<Json> {
    const id = this.nextId++;
    this.send({ id, method, params });
    for (;;) {
      const m = await this.wire.next();
      if ("method" in m && typeof m["method"] === "string") {
        if ("id" in m && m["id"] !== undefined && m["id"] !== null) {
          // sunucudan istemciye istek
          this.serverRequests++;
          if (m["method"] === "ping") this.send({ id: m["id"], result: {} });
          else this.send({ id: m["id"], error: { code: -32601, message: "method not supported by this client" } });
        }
        continue; // bildirimler yok sayılır
      }
      if (m["id"] !== id) continue; // beklenmeyen yanıt kimliği: yok say
      if (m["error"] !== undefined) {
        const e = (m["error"] ?? {}) as Json;
        throw new McpProtocolError("mcp_error", `sunucu hata döndürdü (${typeof e["code"] === "number" ? e["code"] : "?"}): ${safeSnippet(e["message"])}`);
      }
      const r = m["result"];
      if (r === null || typeof r !== "object" || Array.isArray(r)) throw new McpProtocolError("mcp_bad_message", "yanıtta result nesnesi yok");
      return r as Json;
    }
  }

  async initialize(): Promise<void> {
    const r = await this.request("initialize", {
      protocolVersion: SUPPORTED_PROTOCOLS[0],
      capabilities: {},
      clientInfo: { name: this.opts.clientName ?? "ops-assistant", version: this.opts.clientVersion ?? "0.0.0" },
    });
    const v = r["protocolVersion"];
    if (typeof v !== "string" || !(SUPPORTED_PROTOCOLS as readonly string[]).includes(v)) {
      throw new McpProtocolError("mcp_version_unsupported", `sunucu desteklenmeyen protokol sürümü seçti: ${safeSnippet(v, 40)}`);
    }
    this.protocolVersion = v;
    const info = r["serverInfo"];
    if (info && typeof info === "object") this.serverName = safeSnippet((info as Json)["name"], 60);
    this.send({ method: "notifications/initialized" });
  }

  /** `tools/list` (sayfalı, en çok 10 sayfa). Yalnız ADLAR alınır: açıklama/şema/annotation güvenilmez ve kullanılmaz. */
  async listTools(): Promise<McpToolListing> {
    const names: string[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 10; page++) {
      const r = await this.request("tools/list", cursor ? { cursor } : {});
      const tools = Array.isArray(r["tools"]) ? r["tools"] : [];
      for (const t of tools) {
        const n = t && typeof t === "object" ? (t as Json)["name"] : undefined;
        if (typeof n === "string" && n.length <= 100) names.push(n);
      }
      cursor = typeof r["nextCursor"] === "string" ? r["nextCursor"] : undefined;
      if (!cursor) break;
    }
    return { names, total: names.length };
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<McpCallResult> {
    const r = await this.request("tools/call", { name, arguments: args });
    const content = Array.isArray(r["content"]) ? r["content"] : [];
    const texts: string[] = [];
    const resourceLinks: string[] = [];
    let dropped = 0;
    let truncated = false;
    let total = 0;
    const addText = (t: string): void => {
      let s = stripControlChars(t);
      if (s.length > TEXT_BLOCK_MAX) {
        s = s.slice(0, TEXT_BLOCK_MAX);
        truncated = true;
      }
      if (total + s.length > TEXT_TOTAL_MAX) {
        s = s.slice(0, Math.max(0, TEXT_TOTAL_MAX - total));
        truncated = true;
      }
      if (s !== "") texts.push(s);
      total += s.length;
    };
    for (const b of content) {
      if (!b || typeof b !== "object") {
        dropped++;
        continue;
      }
      const blk = b as Json;
      if (blk["type"] === "text" && typeof blk["text"] === "string") addText(blk["text"]);
      else if (blk["type"] === "resource_link" && typeof blk["uri"] === "string") resourceLinks.push(safeSnippet(blk["uri"], 300));
      else if (blk["type"] === "resource" && blk["resource"] && typeof blk["resource"] === "object" && typeof (blk["resource"] as Json)["text"] === "string") addText((blk["resource"] as Json)["text"] as string);
      else dropped++; // image/audio/ikili kaynak: modele gitmez
    }
    let structured: unknown;
    if (r["structuredContent"] !== undefined) {
      const j = JSON.stringify(r["structuredContent"]);
      if (j !== undefined && j.length <= STRUCTURED_MAX) structured = JSON.parse(j);
      else truncated = true;
    }
    return { isError: r["isError"] === true, texts, ...(structured !== undefined ? { structured } : {}), resourceLinks: resourceLinks.slice(0, 20), droppedBlocks: dropped, truncated };
  }
}
