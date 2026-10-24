import type { SdkMessage } from "./sdk.ts";

/** Ana sürece iletilen, SDK'dan bağımsız olay şekli (contracts.RuntimeEvent ile uyumlu). */
export type MappedEvent =
  | { type: "text"; text: string }
  | { type: "tool_call"; name: string; status: "running" | "completed" | "error" }
  | { type: "usage"; usage: { inputTokens: number; outputTokens: number; cacheReadTokens: number } }
  | { type: "status"; status: string };

const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
const obj = (v: unknown): Record<string, unknown> => (v !== null && typeof v === "object" ? (v as Record<string, unknown>) : {});

function textOf(m: Record<string, unknown>): string {
  const msg = obj(m["message"]);
  const content = msg["content"] ?? m["content"] ?? m["text"];
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map((b) => (typeof b === "string" ? b : typeof obj(b)["text"] === "string" ? (obj(b)["text"] as string) : "")).join("");
  return "";
}

/**
 * SDK mesajını olaya çevirir. "Tool call schema is not stable": ayrıştırıcı TOLERANSLIDIR ama
 * güvenlik açısından MUHAFAZAKÂRDIR — adı okunamayan `tool_call`, `<unknown>` adıyla iletilir
 * (bekçi bunu izinsiz sayıp alarm verir). Bilinmeyen tipler yok sayılır.
 */
export function mapSdkMessage(msg: SdkMessage): MappedEvent | null {
  const m = msg as Record<string, unknown>;
  switch (m["type"]) {
    case "assistant": {
      const t = textOf(m);
      return t ? { type: "text", text: t } : null;
    }
    case "tool_call": {
      const name = typeof m["name"] === "string" ? m["name"] : typeof obj(m["tool"])["name"] === "string" ? (obj(m["tool"])["name"] as string) : "<unknown>";
      const st = m["status"];
      return { type: "tool_call", name, status: st === "completed" ? "completed" : st === "error" ? "error" : "running" };
    }
    case "usage": {
      const u = obj(m["usage"] ?? m);
      return {
        type: "usage",
        usage: {
          inputTokens: num(u["inputTokens"] ?? u["input_tokens"]),
          outputTokens: num(u["outputTokens"] ?? u["output_tokens"]),
          cacheReadTokens: num(u["cacheReadTokens"] ?? u["cache_read_tokens"] ?? u["cacheRead"]),
        },
      };
    }
    case "status":
      return { type: "status", status: String(m["status"] ?? "") };
    default:
      return null;
  }
}
