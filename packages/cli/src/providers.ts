import { OpsError } from "@ops/contracts";
import type { AgentRuntime, ModelProvider, SecretStore } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";
import type { KnownSecrets } from "@ops/redaction";

export interface ProviderContext {
  readonly env: Readonly<Record<string, string | undefined>>;
  /** Sağlayıcı anahtarı kasada tutulur: `provider/<ad>` girdisi. */
  readonly store: SecretStore;
  /** Anahtar M3'e kaydedilir: hata/denetim/çıktıda maskelenir. */
  readonly known: KnownSecrets;
  /** Bu makinede çalışan OS sandbox (yoksa `null`); sağlayıcı-döngülü çalışma zamanları ister. */
  readonly sandbox: Sandbox | null;
}

export const isAgentRuntime = (x: ModelProvider | AgentRuntime): x is AgentRuntime => typeof (x as AgentRuntime).runTask === "function";

/** Ortam/yapılandırmadan model sağlayıcısı üretir. */
export type ProviderFactory = (ctx: ProviderContext) => Promise<ModelProvider | AgentRuntime>;

const registry = new Map<string, ProviderFactory>();

export function registerProvider(name: string, factory: ProviderFactory): void {
  registry.set(name, factory);
}

export function providerNames(): string[] {
  return [...registry.keys()].sort();
}

export const providerKeyName = (provider: string): string => `provider/${provider}`;

export async function readProviderKey(ctx: ProviderContext, provider: string): Promise<string | undefined> {
  const raw = await ctx.store.get(providerKeyName(provider));
  if (!raw) return undefined;
  const key = Buffer.from(raw).toString("utf8");
  ctx.known.add(`provider:${provider}:key`, key);
  return key;
}

export async function createProvider(ctx: ProviderContext): Promise<ModelProvider | AgentRuntime> {
  const name = ctx.env["OPS_PROVIDER"];
  if (!name) {
    throw new OpsError("provider_not_configured", `model sağlayıcısı yapılandırılmadı: OPS_PROVIDER ayarlayın (kayıtlı: ${providerNames().join(", ") || "yok"})`);
  }
  const f = registry.get(name);
  if (!f) throw new OpsError("provider_not_configured", `bilinmeyen sağlayıcı '${name.slice(0, 40)}' (kayıtlı: ${providerNames().join(", ") || "yok"})`);
  return f(ctx);
}
