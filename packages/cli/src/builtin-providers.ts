import { OpsError, TRUST_ZONES } from "@ops/contracts";
import type { TrustZone } from "@ops/contracts";
import { dirname } from "node:path";
import { createRequire } from "node:module";
import { CURSOR_HOST_PATH, CursorRuntime } from "@ops/runtime-cursor";
import { AnthropicProvider, OpenAiCompatibleProvider } from "@ops/providers";
import type { AnthropicEffort } from "@ops/providers";
import { readProviderKey, registerProvider } from "./providers.ts";

/**
 * Yerleşik sağlayıcılar. Yapılandırma ortamdan (secret OLMAYAN alanlar), anahtar kasadan:
 *   OPS_PROVIDER=openai-compatible
 *   OPS_PROVIDER_BASE_URL  OPS_PROVIDER_MODEL  [OPS_PROVIDER_ZONE]  [OPS_PROVIDER_TIER]  [OPS_PROVIDER_CONTEXT_WINDOW]
 * Bölge verilmezse loopback → local, aksi halde third-party-cloud (en kısıtlayıcı varsayım değil,
 * en az maruz DEĞİL: hassas bağlamlar bu sağlayıcıya egress denetiminde gitmez).
 */
const EFFORTS: readonly AnthropicEffort[] = ["low", "medium", "high", "xhigh", "max"];

export function registerBuiltinProviders(): void {
  registerProvider("openai-compatible", async (ctx) => {
    const baseUrl = ctx.env["OPS_PROVIDER_BASE_URL"];
    const model = ctx.env["OPS_PROVIDER_MODEL"];
    if (!baseUrl || !model) throw new OpsError("provider_not_configured", "OPS_PROVIDER_BASE_URL ve OPS_PROVIDER_MODEL gerekli");
    const zone = ctx.env["OPS_PROVIDER_ZONE"];
    if (zone !== undefined && !TRUST_ZONES.includes(zone as TrustZone)) throw new OpsError("provider_config", `OPS_PROVIDER_ZONE şunlardan biri olmalı: ${TRUST_ZONES.join(", ")}`);
    const tier = ctx.env["OPS_PROVIDER_TIER"];
    const cw = ctx.env["OPS_PROVIDER_CONTEXT_WINDOW"];
    const apiKey = await readProviderKey(ctx, "openai-compatible");
    return new OpenAiCompatibleProvider({
      baseUrl,
      model,
      ...(zone ? { trustZone: zone as TrustZone } : {}),
      ...(apiKey ? { apiKey } : {}),
      ...(tier === "small" || tier === "large" ? { tier } : {}),
      ...(cw && Number(cw) > 0 ? { contextWindow: Number(cw) } : {}),
    });
  });

  /**
   * Anthropic (loopOwner=host, resmî SDK). Anahtar kasadan; yapılandırma ortamdan:
   *   OPS_PROVIDER=anthropic  [OPS_PROVIDER_MODEL]  [OPS_PROVIDER_BASE_URL]  [OPS_PROVIDER_ZONE]  [OPS_PROVIDER_TIER]
   *   [OPS_ANTHROPIC_EFFORT=low|medium|high|xhigh|max]  [OPS_ANTHROPIC_PROMPT_CACHE=0]
   * Uç belirtilmezse üçüncü taraf bulut; loopback → local (ör. test/ağ geçidi).
   */
  registerProvider("anthropic", async (ctx) => {
    const apiKey = await readProviderKey(ctx, "anthropic");
    if (!apiKey) throw new OpsError("provider_not_configured", "Anthropic API anahtarı kasada yok (`ops provider set-key anthropic`)");
    const model = ctx.env["OPS_PROVIDER_MODEL"];
    const baseUrl = ctx.env["OPS_PROVIDER_BASE_URL"];
    const zone = ctx.env["OPS_PROVIDER_ZONE"];
    if (zone !== undefined && !TRUST_ZONES.includes(zone as TrustZone)) throw new OpsError("provider_config", `OPS_PROVIDER_ZONE şunlardan biri olmalı: ${TRUST_ZONES.join(", ")}`);
    const tier = ctx.env["OPS_PROVIDER_TIER"];
    const effort = ctx.env["OPS_ANTHROPIC_EFFORT"];
    if (effort !== undefined && !EFFORTS.includes(effort as AnthropicEffort)) throw new OpsError("provider_config", `OPS_ANTHROPIC_EFFORT şunlardan biri olmalı: ${EFFORTS.join(", ")}`);
    return new AnthropicProvider({
      apiKey,
      ...(model ? { model } : {}),
      ...(baseUrl ? { baseUrl } : {}),
      ...(zone ? { trustZone: zone as TrustZone } : {}),
      ...(tier === "small" || tier === "large" ? { tier } : {}),
      ...(effort ? { effort: effort as AnthropicEffort } : {}),
      ...(ctx.env["OPS_ANTHROPIC_PROMPT_CACHE"] === "0" ? { promptCache: false } : {}),
    });
  });

  /**
   * Cursor (loopOwner=provider). SDK bu depoya BAĞIMLILIK olarak eklenmedi ve gerçek SDK'ya karşı
   * davranış doğrulanmadı (ADR-0004). `OPS_CURSOR_SPIKE_PASSED=1` verilmedikçe TAVSİYE KİPİ.
   *   OPS_PROVIDER=cursor  OPS_CURSOR_MODEL=...  [OPS_CURSOR_SDK_MODULE=/mutlak/yol]  [OPS_CURSOR_SPIKE_PASSED=1]
   */
  registerProvider("cursor", async (ctx) => {
    const model = ctx.env["OPS_CURSOR_MODEL"];
    if (!model) throw new OpsError("provider_not_configured", "OPS_CURSOR_MODEL gerekli");
    if (!ctx.sandbox || ctx.sandbox.kind === "none") {
      throw new OpsError("sandbox_unavailable", "Cursor için OS sandbox (bubblewrap/seatbelt) gerekli: SDK kullanıcının ortamını miras alır");
    }
    // cursor-host betiği, host Node ikilisi ve SDK host dosyalarıdır; konukta yoktur (ADR-0011 sınırlar).
    if (ctx.sandbox.kind === "vm") throw new OpsError("sandbox_unavailable", "Cursor çalışma zamanı VM sandbox'ında desteklenmiyor: cursor-host ve SDK konukta yok (ADR-0011)");
    let sdk = ctx.env["OPS_CURSOR_SDK_MODULE"];
    const binds = new Set<string>([dirname(process.execPath), dirname(CURSOR_HOST_PATH)]);
    if (sdk) binds.add(dirname(sdk));
    else {
      try {
        sdk = createRequire(import.meta.url).resolve("@cursor/sdk");
        const idx = sdk.lastIndexOf("/node_modules/");
        binds.add(idx >= 0 ? sdk.slice(0, idx + "/node_modules".length) : dirname(sdk));
      } catch {
        throw new OpsError("provider_not_configured", "Cursor SDK kurulu değil: `pnpm add @cursor/sdk` ve ADR-0004 spike'ını izleyin (veya OPS_CURSOR_SDK_MODULE)");
      }
    }
    const apiKey = await readProviderKey(ctx, "cursor");
    return new CursorRuntime({
      sandbox: ctx.sandbox,
      model,
      hostArgv: [process.execPath, CURSOR_HOST_PATH],
      hostRoBinds: [...binds],
      hostEnv: { OPS_CURSOR_SDK_MODULE: sdk },
      ...(apiKey ? { apiKey: async () => apiKey } : {}),
      spikePassed: ctx.env["OPS_CURSOR_SPIKE_PASSED"] === "1",
    });
  });
}
