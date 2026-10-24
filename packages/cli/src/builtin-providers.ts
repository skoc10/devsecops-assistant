import { OpsError, TRUST_ZONES } from "@ops/contracts";
import type { TrustZone } from "@ops/contracts";
import { dirname } from "node:path";
import { createRequire } from "node:module";
import { CURSOR_HOST_PATH, CursorRuntime } from "@ops/runtime-cursor";
import { OpenAiCompatibleProvider } from "@ops/providers";
import { readProviderKey, registerProvider } from "./providers.ts";

/**
 * Yerleşik sağlayıcılar. Yapılandırma ortamdan (secret OLMAYAN alanlar), anahtar kasadan:
 *   OPS_PROVIDER=openai-compatible
 *   OPS_PROVIDER_BASE_URL  OPS_PROVIDER_MODEL  [OPS_PROVIDER_ZONE]  [OPS_PROVIDER_TIER]  [OPS_PROVIDER_CONTEXT_WINDOW]
 * Bölge verilmezse loopback → local, aksi halde third-party-cloud (en kısıtlayıcı varsayım değil,
 * en az maruz DEĞİL: hassas bağlamlar bu sağlayıcıya egress denetiminde gitmez).
 */
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
