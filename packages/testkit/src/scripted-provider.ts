import { estimateTokens } from "@ops/contracts";
import type {
  GenerateRequest,
  GenerateResult,
  ModelProvider,
  ProviderCapabilities,
  ToolCall,
  TrustZone,
} from "@ops/contracts";

export type ScriptStep = GenerateResult | ((req: GenerateRequest, turn: number) => GenerateResult);

/** Metin cevabı ile turu bitirir. */
export function say(text: string, usage?: Partial<GenerateResult["usage"]>): GenerateResult {
  return {
    message: { content: text, toolCalls: [] },
    usage: { inputTokens: 0, outputTokens: estimateTokens(text), cacheReadTokens: 0, ...usage },
    stopReason: "end",
  };
}

/** Bir veya daha fazla araç çağrısı önerir (aynı turda paralel okuma için). */
export function toolUse(
  calls: readonly { name: string; args: unknown; id?: string }[],
  text = "",
): GenerateResult {
  const toolCalls: ToolCall[] = calls.map((c, i) => ({
    id: c.id ?? `call_${i + 1}`,
    name: c.name,
    args: c.args,
  }));
  return {
    message: { content: text, toolCalls },
    usage: { inputTokens: 0, outputTokens: estimateTokens(JSON.stringify(toolCalls)), cacheReadTokens: 0 },
    stopReason: "tool_use",
  };
}

/**
 * Deterministik, "kötü niyetli olabilen" model: önceden yazılmış adımları oynatır. Aldığı her
 * isteği (sağlayıcıya giden baytlar) `serialized` içinde saklar: canary yakalama için.
 */
export class ScriptedProvider implements ModelProvider {
  readonly id = "scripted";
  readonly model = "scripted-1";
  readonly capabilities: ProviderCapabilities;
  readonly requests: GenerateRequest[] = [];
  readonly serialized: string[] = [];
  private readonly steps: readonly ScriptStep[];
  private turn = 0;

  constructor(
    steps: readonly ScriptStep[],
    opts: { trustZone?: TrustZone; capabilities?: Partial<ProviderCapabilities> } = {},
  ) {
    this.steps = steps;
    this.capabilities = {
      loopOwner: "host",
      toolCalling: true,
      structuredOutput: true,
      trustZone: opts.trustZone ?? "local",
      contextWindow: 200_000,
      tier: "large",
      costClass: "low",
      ...opts.capabilities,
    };
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    this.requests.push(req);
    const payload = JSON.stringify({ system: req.system, messages: req.messages, tools: req.tools });
    this.serialized.push(payload);
    const step = this.steps[this.turn];
    const turn = this.turn++;
    if (step === undefined) throw new Error(`scripted sağlayıcı: ${turn}. tur için adım yok`);
    const out = typeof step === "function" ? step(req, turn) : step;
    const inputTokens = out.usage.inputTokens > 0 ? out.usage.inputTokens : estimateTokens(payload);
    return { ...out, usage: { ...out.usage, inputTokens } };
  }

  get turns(): number {
    return this.turn;
  }
}
