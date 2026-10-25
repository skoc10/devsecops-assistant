import { createHash } from "node:crypto";
import Anthropic from "@anthropic-ai/sdk";
import { OpsError, TRUST_ZONES, estimateTokens } from "@ops/contracts";
import { decodeToolName, encodeToolName } from "./tool-names.ts";
import type { GenerateRequest, GenerateResult, Message, ModelProvider, ModelTier, ProviderCapabilities, ToolCall, TrustZone } from "@ops/contracts";

export type AnthropicEffort = "low" | "medium" | "high" | "xhigh" | "max";

export interface AnthropicProviderConfig {
  /** API anahtarı (kasadan). Hata/denetim metinlerinde ASLA yer almaz. */
  readonly apiKey: string;
  /** Varsayılan `claude-opus-5-5`; hızlı/ucuz kademe için `claude-haiku-5-5`. */
  readonly model?: string;
  /** Test/yerel vekil için; uzak uç yalnız https, düz http yalnız loopback. */
  readonly baseUrl?: string;
  /** VERİNİN gideceği bölge. Varsayılan: loopback → `local`, aksi halde `third-party-cloud`. */
  readonly trustZone?: TrustZone;
  readonly tier?: ModelTier;
  /** `output_config.effort`; Opus 5.5'te sunucu varsayılanı `medium`'dur, burada açıkça verilir. */
  readonly effort?: AnthropicEffort;
  readonly maxTokens?: number;
  readonly requestTimeoutMs?: number;
  readonly contextWindow?: number;
  /** İstem önbelleği (üst düzey otomatik `cache_control`). Varsayılan: açık. */
  readonly promptCache?: boolean;
  /** Test: hazır SDK istemcisi. */
  readonly client?: Anthropic;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const DEFAULT_MODEL = "claude-opus-5-5";
const DEFAULT_BASE_URL = "https://api.anthropic.com";
/** SDK'nın isteğe ekleyebileceği başlıklardan YALNIZ bunlar gider (ortamdan gelen `ANTHROPIC_CUSTOM_HEADERS` vb. elenir). */
const ALLOWED_HEADERS = /^(content-type|content-length|accept|accept-encoding|authorization|x-api-key|anthropic-version|anthropic-beta|user-agent|idempotency-key|x-stainless-[a-z0-9-]+)$/i;

/**
 * SDK'nın `fetch`'i yerine: (1) istek YAPILANDIRILAN uç noktanın kökenine gitmeli (ortam değişkeni/yönlendirme anahtarı
 * başka bir hosta taşıyamaz), (2) yalnız bilinen başlıklar gider.
 */
function guardedFetch(origin: string): typeof fetch {
  return async (input, init) => {
    const href = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
    if (new URL(href).origin !== origin) throw new OpsError("provider_error", "istek yapılandırılan uç noktanın dışına gidiyordu; reddedildi");
    const h = new Headers(init?.headers);
    for (const k of [...h.keys()]) if (!ALLOWED_HEADERS.test(k)) h.delete(k);
    return fetch(input, { ...init, headers: h });
  };
}

/** İleti içeriğinin sağlayıcıdan bağımsız özeti: geçmiş düzenlendi mi? sorusu için (providerData katılmaz). */
function digestOf(m: Message): string {
  const core =
    m.role === "assistant"
      ? ["a", m.content, (m.toolCalls ?? []).map((c) => [c.id, c.name, c.args])]
      : m.role === "tool"
        ? ["t", m.toolCallId, m.name, m.content]
        : ["u", m.content];
  return createHash("sha256").update(JSON.stringify(core)).digest("hex").slice(0, 16);
}

interface WireBlockLike {
  type?: unknown;
}

/** `providerData` olarak saklanan içerik blokları dizisi mi? (biçim güvenmediğimiz bir değerdir.) */
function asBlocks(v: unknown): Anthropic.ContentBlockParam[] | null {
  if (!Array.isArray(v) || v.length === 0) return null;
  for (const b of v) if (b === null || typeof b !== "object" || typeof (b as WireBlockLike).type !== "string") return null;
  return v as Anthropic.ContentBlockParam[];
}

const isThinking = (b: Anthropic.ContentBlockParam): boolean => b.type === "thinking" || b.type === "redacted_thinking";

/**
 * Anthropic Messages API (resmî SDK). `loopOwner: host`: tek tur üretir, araçları ÇALIŞTIRMAZ.
 *  - Düşünme blokları DEĞİŞTİRİLMEDEN geri gönderilir (`providerData` = yanıtın ham içerik blokları).
 *    Geçmiş orkestratör tarafından düzenlenirse (defter sıkıştırması) düşünme blokları o konuşma için
 *    TÜMÜYLE bırakılır: "kenar" blok göndermek 400/düşürme riski taşır (korunmuş düşünme, salt-ekleme kuralı).
 *  - Zorlayıcı `tool_choice` yok (yeni modellerde 400), `temperature` yok, ön-doldurma yok.
 *  - İstem önbelleği: üst düzey otomatik `cache_control`; araç/sistem/mesaj sırası orkestratörde kararlıdır.
 *  - Yönlendirme izlenmez; uzak uç yalnız https; hata mesajlarında anahtar yok.
 */
export class AnthropicProvider implements ModelProvider {
  readonly id = "anthropic";
  readonly model: string;
  readonly capabilities: ProviderCapabilities;
  private readonly cfg: AnthropicProviderConfig;
  private readonly client: Anthropic;
  /** Önceki isteğin gönderdiği iletilerin (+ döndürdüğü asistan iletisinin) özetleri. */
  private lastSeen: string[] = [];
  /** Geçmiş bir kez düzenlendi: düşünme blokları artık HİÇ gönderilmez (yapışkan). */
  private historyEdited = false;

  constructor(cfg: AnthropicProviderConfig) {
    if (!cfg.apiKey || cfg.apiKey.length < 8) throw new OpsError("provider_config", "Anthropic API anahtarı gerekli (`ops provider set-key anthropic`)");
    let zone: TrustZone = "third-party-cloud";
    if (cfg.baseUrl !== undefined) {
      let url: URL;
      try {
        url = new URL(cfg.baseUrl);
      } catch {
        throw new OpsError("provider_config", "baseUrl geçersiz");
      }
      const loopback = LOOPBACK.has(url.hostname);
      if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) throw new OpsError("provider_config", "uzak sağlayıcı uçları yalnız https olmalı (düz http yalnız loopback)");
      if (url.username || url.password) throw new OpsError("provider_config", "baseUrl kimlik bilgisi içeremez");
      if (loopback) zone = "local";
    }
    zone = cfg.trustZone ?? zone;
    if (!TRUST_ZONES.includes(zone)) throw new OpsError("provider_config", "trustZone geçersiz");
    this.cfg = cfg;
    this.model = cfg.model ?? DEFAULT_MODEL;
    this.capabilities = {
      loopOwner: "host",
      toolCalling: true,
      structuredOutput: true,
      trustZone: zone,
      contextWindow: cfg.contextWindow ?? 1_000_000,
      tier: cfg.tier ?? (/haiku/i.test(this.model) ? "small" : "large"),
      costClass: /haiku/i.test(this.model) ? "low" : /sonnet/i.test(this.model) ? "mid" : "high",
    };
    this.client =
      cfg.client ??
      new Anthropic({
        apiKey: cfg.apiKey,
        // Ortam değişkenleri (ANTHROPIC_BASE_URL/AUTH_TOKEN/CUSTOM_HEADERS) ANAHTARI başka uca taşıyamaz: uç HER ZAMAN açık
        authToken: null,
        baseURL: cfg.baseUrl ?? DEFAULT_BASE_URL,
        fetch: guardedFetch(new URL(cfg.baseUrl ?? DEFAULT_BASE_URL).origin),
        maxRetries: 2,
        timeout: cfg.requestTimeoutMs ?? 120_000,
        fetchOptions: { redirect: "error" },
      });
  }

  /** Ortak iletileri Anthropic biçimine çevirir (araç sonuçları TEK kullanıcı iletisinde birleşir). */
  toWire(messages: readonly Message[], keepThinking: boolean): Anthropic.MessageParam[] {
    const out: Anthropic.MessageParam[] = [];
    let pendingResults: Anthropic.ToolResultBlockParam[] = [];
    const flush = (): void => {
      if (pendingResults.length > 0) {
        out.push({ role: "user", content: pendingResults });
        pendingResults = [];
      }
    };
    for (const m of messages) {
      if (m.role === "tool") {
        pendingResults.push({ type: "tool_result", tool_use_id: m.toolCallId, content: m.content });
        continue;
      }
      flush();
      if (m.role === "user") {
        out.push({ role: "user", content: m.content });
        continue;
      }
      const raw = asBlocks(m.providerData);
      if (raw) {
        // yanıtın ham blokları: yalnız düşünme blokları gerekirse ayıklanır, diğer her şey DEĞİŞMEDEN
        const blocks = keepThinking ? raw : raw.filter((b) => !isThinking(b));
        if (blocks.length > 0) {
          out.push({ role: "assistant", content: blocks });
          continue;
        }
      }
      const blocks: Anthropic.ContentBlockParam[] = [];
      if (m.content !== "") blocks.push({ type: "text", text: m.content });
      for (const c of m.toolCalls ?? []) blocks.push({ type: "tool_use", id: c.id, name: encodeToolName(c.name), input: (c.args ?? {}) as Record<string, unknown> });
      if (blocks.length === 0) blocks.push({ type: "text", text: "(boş)" });
      out.push({ role: "assistant", content: blocks });
    }
    flush();
    return out;
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const digests = req.messages.map(digestOf);
    if (!this.historyEdited && this.lastSeen.length > 0) {
      // önceki istek+yanıt bu isteğin ÖNEKİ olmalı (salt-ekleme); değilse geçmiş düzenlenmiştir
      const prefixOk = this.lastSeen.length <= digests.length && this.lastSeen.every((d, i) => d === digests[i]);
      if (!prefixOk) this.historyEdited = true;
    }
    const tools: Anthropic.Tool[] = req.tools.map((t) => ({
      name: encodeToolName(t.name),
      description: t.description,
      input_schema: { ...t.inputSchema, type: "object" } as Anthropic.Tool.InputSchema,
    }));
    const params: Anthropic.MessageCreateParamsNonStreaming = {
      model: this.model,
      max_tokens: req.maxOutputTokens ?? this.cfg.maxTokens ?? 16_000,
      system: req.system,
      messages: this.toWire(req.messages, !this.historyEdited),
      ...(tools.length > 0 ? { tools, tool_choice: { type: "auto" as const } } : {}),
      output_config: { effort: this.cfg.effort ?? "medium" },
      ...(this.cfg.promptCache === false ? {} : { cache_control: { type: "ephemeral" as const } }),
    };
    let msg: Anthropic.Message;
    try {
      msg = await this.client.messages.create(params, req.signal ? { signal: req.signal } : undefined);
    } catch (e) {
      throw this.mapError(e);
    }
    const text: string[] = [];
    const toolCalls: ToolCall[] = [];
    for (const b of msg.content) {
      if (b.type === "text") text.push(b.text);
      else if (b.type === "tool_use") toolCalls.push({ id: b.id, name: decodeToolName(b.name), args: b.input ?? {} });
    }
    if (msg.stop_reason === "refusal") {
      const d = (msg as { stop_details?: { category?: string | null } }).stop_details;
      throw new OpsError("provider_refusal", `model isteği reddetti${d?.category ? ` (kategori: ${String(d.category).slice(0, 40)})` : ""}; sorguyu daraltın veya başka sağlayıcı kullanın`);
    }
    const content = text.join("\n");
    // `max_tokens` ile kesilen yanıtın araç çağrısı argümanları EKSİK olabilir: ÇALIŞTIRILMAZ (yalnız metin döner)
    const truncated = msg.stop_reason === "max_tokens";
    if (truncated) toolCalls.length = 0;
    const stopReason: GenerateResult["stopReason"] = toolCalls.length > 0 ? "tool_use" : truncated ? "length" : "end";
    const u = msg.usage;
    const cacheRead = u.cache_read_input_tokens ?? 0;
    const cacheWrite = u.cache_creation_input_tokens ?? 0;
    // bir sonraki istek için: gönderilenler + bu yanıt
    this.lastSeen = [...digests, digestOf({ role: "assistant", content, toolCalls })];
    return {
      message: { content, toolCalls, providerData: msg.content },
      usage: {
        // OpenAI semantiğiyle tutarlı: girdi = yeni + önbellek yazımı + önbellek okuması; önbellek okuması ayrıca raporlanır
        inputTokens: (u.input_tokens ?? 0) + cacheWrite + cacheRead,
        outputTokens: u.output_tokens ?? estimateTokens(content + JSON.stringify(toolCalls)),
        cacheReadTokens: cacheRead,
      },
      stopReason,
    };
  }

  private mapError(e: unknown): OpsError {
    const redact = (s: string): string => s.replaceAll(this.cfg.apiKey, "‹redacted›");
    if (e instanceof Anthropic.APIUserAbortError) return new OpsError("provider_error", "model çağrısı iptal edildi");
    if (e instanceof Anthropic.APIConnectionTimeoutError) return new OpsError("provider_error", "model çağrısı zaman aşımına uğradı");
    if (e instanceof Anthropic.APIConnectionError) return new OpsError("provider_error", "sağlayıcıya erişilemedi (bağlantı hatası)");
    if (e instanceof Anthropic.APIError) {
      const status = e.status ?? 0;
      const kind = e instanceof Anthropic.AuthenticationError ? "kimlik doğrulama" : e instanceof Anthropic.RateLimitError ? "oran sınırı" : e instanceof Anthropic.BadRequestError ? "geçersiz istek" : "API";
      return new OpsError("provider_error", `sağlayıcı HTTP ${status} (${kind}): ${redact(String(e.message ?? "")).slice(0, 200)}`);
    }
    if (e instanceof Error && (e.name === "AbortError" || e.name === "APIUserAbortError")) return new OpsError("provider_error", "model çağrısı iptal edildi");
    return new OpsError("provider_error", `sağlayıcıya erişilemedi (${e instanceof Error ? redact(e.name) : "hata"})`);
  }
}
