import { OpsError, estimateTokens, TRUST_ZONES } from "@ops/contracts";
import type {
  GenerateRequest,
  GenerateResult,
  Message,
  ModelProvider,
  ModelTier,
  ProviderCapabilities,
  ToolCall,
  TrustZone,
} from "@ops/contracts";

export interface OpenAiCompatibleConfig {
  /** Örn. `https://api.example.invalid/v1` veya yerel `http://127.0.0.1:11434/v1`. */
  readonly baseUrl: string;
  readonly model: string;
  /** VERİNİN gideceği bölge: AÇIKÇA verilir. Varsayılan: loopback → `local`, aksi halde `third-party-cloud`. */
  readonly trustZone?: TrustZone;
  /** API anahtarı (kasadan). Yerel sunucularda yok. */
  readonly apiKey?: string;
  readonly tier?: ModelTier;
  readonly contextWindow?: number;
  readonly requestTimeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly fetch?: typeof fetch;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/** Araç adlarındaki `.` OpenAI işlev adlarında geçersizdir: `.` ↔ `__` (tersinir, çakışma denetimli). */
export function encodeToolName(name: string): string {
  if (name.includes("__")) throw new OpsError("tool_name_unencodable", `araç adı '__' içeremez: ${name.slice(0, 60)}`);
  return name.replaceAll(".", "__");
}
export function decodeToolName(name: string): string {
  return name.replaceAll("__", ".");
}

type WireMessage =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string | null; tool_calls?: { id: string; type: "function"; function: { name: string; arguments: string } }[] }
  | { role: "tool"; tool_call_id: string; content: string };

export function toWireMessages(system: string, messages: readonly Message[]): WireMessage[] {
  const out: WireMessage[] = [{ role: "system", content: system }];
  for (const m of messages) {
    if (m.role === "user") out.push({ role: "user", content: m.content });
    else if (m.role === "assistant") {
      out.push({
        role: "assistant",
        content: m.content === "" && m.toolCalls?.length ? null : m.content,
        ...(m.toolCalls?.length
          ? { tool_calls: m.toolCalls.map((c) => ({ id: c.id, type: "function" as const, function: { name: encodeToolName(c.name), arguments: JSON.stringify(c.args ?? {}) } })) }
          : {}),
      });
    } else out.push({ role: "tool", tool_call_id: m.toolCallId, content: m.content });
  }
  return out;
}

export function defaultZone(baseUrl: string): TrustZone {
  try {
    return LOOPBACK.has(new URL(baseUrl).hostname) ? "local" : "third-party-cloud";
  } catch {
    return "third-party-cloud";
  }
}

/**
 * OpenAI Chat Completions uyumlu uç (OpenAI, Azure OpenAI uyumlu uçlar, Ollama, vLLM, llama.cpp).
 * `loopOwner: host`: tek tur üretir, araçları ÇALIŞTIRMAZ. Güvenlik özellikleri:
 *  - uzak uç yalnız https; düz http yalnız loopback;
 *  - yönlendirme izlenmez (anahtar başka hosta gitmesin);
 *  - istek/yanıt boyutu ve süre sınırlı; hata mesajlarında anahtar yok;
 *  - `trust_zone` yapılandırmadan gelir ve egress denetiminde kullanılır.
 */
export class OpenAiCompatibleProvider implements ModelProvider {
  readonly id = "openai-compatible";
  readonly model: string;
  readonly capabilities: ProviderCapabilities;
  private readonly cfg: OpenAiCompatibleConfig;
  private readonly url: URL;

  constructor(cfg: OpenAiCompatibleConfig) {
    let url: URL;
    try {
      url = new URL(cfg.baseUrl.replace(/\/+$/, ""));
    } catch {
      throw new OpsError("provider_config", "baseUrl geçersiz");
    }
    const loopback = LOOPBACK.has(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
      throw new OpsError("provider_config", "uzak sağlayıcı uçları yalnız https olmalı (düz http yalnız loopback)");
    }
    if (url.username || url.password) throw new OpsError("provider_config", "baseUrl kimlik bilgisi içeremez");
    const zone = cfg.trustZone ?? defaultZone(cfg.baseUrl);
    if (!TRUST_ZONES.includes(zone)) throw new OpsError("provider_config", "trustZone geçersiz");
    this.cfg = cfg;
    this.url = url;
    this.model = cfg.model;
    this.capabilities = {
      loopOwner: "host",
      toolCalling: true,
      structuredOutput: false,
      trustZone: zone,
      contextWindow: cfg.contextWindow ?? 128_000,
      tier: cfg.tier ?? "large",
      costClass: "mid",
    };
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const body = {
      model: this.cfg.model,
      messages: toWireMessages(req.system, req.messages),
      ...(req.tools.length > 0
        ? {
            tools: req.tools.map((t) => ({ type: "function", function: { name: encodeToolName(t.name), description: t.description, parameters: t.inputSchema } })),
            tool_choice: "auto",
          }
        : {}),
      ...(req.maxOutputTokens ? { max_tokens: req.maxOutputTokens } : {}),
    };
    const timeout = AbortSignal.timeout(this.cfg.requestTimeoutMs ?? 120_000);
    const signal = req.signal ? AbortSignal.any([req.signal, timeout]) : timeout;
    const f = this.cfg.fetch ?? fetch;
    let res: Response;
    try {
      res = await f(`${this.url.toString().replace(/\/+$/, "")}/chat/completions`, {
        method: "POST",
        redirect: "error",
        signal,
        headers: { "content-type": "application/json", ...(this.cfg.apiKey ? { authorization: `Bearer ${this.cfg.apiKey}` } : {}) },
        body: JSON.stringify(body),
      });
    } catch (e) {
      throw new OpsError("provider_error", `sağlayıcıya erişilemedi (${e instanceof Error ? e.name : "hata"})`);
    }
    const text = await readLimited(res, this.cfg.maxResponseBytes ?? 8_000_000);
    if (!res.ok) {
      // sağlayıcılar hata gövdesinde (kısmen) anahtarı yansıtabilir: anahtar asla mesaja girmez
      const body = this.cfg.apiKey ? text.replaceAll(this.cfg.apiKey, "‹redacted›") : text;
      throw new OpsError("provider_error", `sağlayıcı HTTP ${res.status}: ${body.slice(0, 200)}`);
    }
    return parseResponse(text, estimateTokens(JSON.stringify(body)));
  }
}

async function readLimited(res: Response, max: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > max) {
      await reader.cancel();
      throw new OpsError("provider_error", "sağlayıcı yanıtı boyut sınırını aştı");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

interface WireResponse {
  choices?: { message?: { content?: string | null; tool_calls?: { id?: string; function?: { name?: string; arguments?: string } }[] }; finish_reason?: string }[];
  usage?: { prompt_tokens?: number; completion_tokens?: number; prompt_tokens_details?: { cached_tokens?: number } };
}

export function parseResponse(text: string, promptEstimate = 0): GenerateResult {
  let j: WireResponse;
  try {
    j = JSON.parse(text) as WireResponse;
  } catch {
    throw new OpsError("provider_error", "sağlayıcı yanıtı JSON değil");
  }
  const choice = j.choices?.[0];
  if (!choice?.message) throw new OpsError("provider_error", "sağlayıcı yanıtında 'choices[0].message' yok");
  const content = choice.message.content ?? "";
  const toolCalls: ToolCall[] = (choice.message.tool_calls ?? []).map((c, i) => {
    let args: unknown;
    try {
      args = JSON.parse(c.function?.arguments || "{}");
    } catch {
      // bozuk argüman JSON'u: katı şema reddeder (schema_invalid) ve model hatayı görür
      args = { _argumentsParseError: true };
    }
    return { id: c.id || `call_${i + 1}`, name: decodeToolName(c.function?.name ?? ""), args };
  });
  const finish = choice.finish_reason;
  const stopReason: GenerateResult["stopReason"] = toolCalls.length > 0 ? "tool_use" : finish === "length" ? "length" : "end";
  const u = j.usage;
  return {
    message: { content, toolCalls },
    usage: {
      // sağlayıcı kullanım bildirmediyse istek gövdesinden tahmin edilir (bütçeler sıfır görmesin)
      inputTokens: u?.prompt_tokens ?? promptEstimate,
      outputTokens: u?.completion_tokens ?? estimateTokens(content + JSON.stringify(toolCalls)),
      cacheReadTokens: u?.prompt_tokens_details?.cached_tokens ?? 0,
    },
    stopReason,
  };
}
