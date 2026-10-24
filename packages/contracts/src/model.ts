import type { TrustZone } from "./classes.ts";

export interface ToolSpec {
  readonly name: string;
  readonly description: string;
  /** JSON Schema. */
  readonly inputSchema: Record<string, unknown>;
}

export interface ToolCall {
  readonly id: string;
  readonly name: string;
  readonly args: unknown;
}

export type Message =
  | { readonly role: "user"; readonly content: string }
  | { readonly role: "assistant"; readonly content: string; readonly toolCalls?: readonly ToolCall[] }
  | { readonly role: "tool"; readonly toolCallId: string; readonly name: string; readonly content: string };

export interface Usage {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadTokens: number;
}

export type ModelTier = "small" | "large";
export type CostClass = "low" | "mid" | "high";

export interface ProviderCapabilities {
  /** `host`: döngüyü biz yürütürüz; `provider`: döngü sağlayıcıdadır (araçlar köprüden gelir). */
  readonly loopOwner: "host" | "provider";
  readonly toolCalling: boolean;
  readonly structuredOutput: boolean;
  readonly trustZone: TrustZone;
  readonly contextWindow: number;
  readonly tier: ModelTier;
  readonly costClass: CostClass;
}

export interface GenerateRequest {
  readonly system: string;
  readonly messages: readonly Message[];
  readonly tools: readonly ToolSpec[];
  readonly maxOutputTokens?: number;
  readonly signal?: AbortSignal;
}

export interface GenerateResult {
  readonly message: { readonly content: string; readonly toolCalls: readonly ToolCall[] };
  readonly usage: Usage;
  readonly stopReason: "end" | "tool_use" | "length" | "error";
}

/** `loopOwner: host` sağlayıcıları: tek tur üretir, araçları çalıştırmaz. */
export interface ModelProvider {
  readonly id: string;
  readonly model: string;
  readonly capabilities: ProviderCapabilities;
  generate(req: GenerateRequest): Promise<GenerateResult>;
}

export interface ToolBridgeResult {
  readonly text: string;
  readonly isError: boolean;
}

/**
 * Dış ajan çalışma zamanlarının tek araç kapısı: her çağrı PEP boru hattından geçer.
 * Taşıyıcı belirteç yalnız `tool.invoke` kapsamlıdır; onay veremez.
 */
export interface ToolBridge {
  specs(): readonly ToolSpec[];
  invoke(name: string, args: unknown): Promise<ToolBridgeResult>;
}

export interface RuntimeTask {
  readonly system: string;
  readonly prompt: string;
  /** Ham transkript değil, bağlam defteri özeti (token ekonomisi). */
  readonly ledgerSummary?: string;
}

export type RuntimeEvent =
  | { readonly type: "text"; readonly text: string }
  | { readonly type: "tool_call"; readonly name: string; readonly status: "running" | "completed" | "error" }
  | { readonly type: "usage"; readonly usage: Usage }
  | { readonly type: "status"; readonly status: string }
  | { readonly type: "alarm"; readonly code: string; readonly detail: string };

export interface RuntimeCapabilities {
  /** Yerleşik kabuk/dosya araçları kapatılabiliyor mu? Hayır ise çalışma zamanı reddedilir. */
  readonly builtinToolsDisableable: boolean;
  readonly osSandboxed: boolean;
  readonly trustZone: TrustZone;
  /** Her tur sıfırdan başlatılabiliyor mu (resume'a güvenmeden)? */
  readonly statelessSupported: boolean;
}

/** `loopOwner: provider` çalışma zamanları (Cursor SDK vb.). */
export interface AgentRuntime {
  readonly id: string;
  readonly model: string;
  readonly capabilities: RuntimeCapabilities;
  runTask(task: RuntimeTask, bridge: ToolBridge, signal?: AbortSignal): AsyncIterable<RuntimeEvent>;
}

/** Bir çalışma zamanının güvenli kullanılabilir olup olmadığını denetleyen ortak kural. */
export function runtimeIsSafe(c: RuntimeCapabilities): boolean {
  return c.builtinToolsDisableable && c.osSandboxed && c.statelessSupported;
}
