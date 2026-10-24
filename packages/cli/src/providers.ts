import { OpsError } from "@ops/contracts";
import type { ModelProvider } from "@ops/contracts";

/** Ortam/yapılandırmadan model sağlayıcısı üretir. Sağlayıcılar WP8'de kaydedilir. */
export type ProviderFactory = (env: Readonly<Record<string, string | undefined>>) => Promise<ModelProvider>;

const registry = new Map<string, ProviderFactory>();

export function registerProvider(name: string, factory: ProviderFactory): void {
  registry.set(name, factory);
}

export function providerNames(): string[] {
  return [...registry.keys()].sort();
}

export async function createProvider(env: Readonly<Record<string, string | undefined>>): Promise<ModelProvider> {
  const name = env["OPS_PROVIDER"];
  if (!name) {
    throw new OpsError("provider_not_configured", `model sağlayıcısı yapılandırılmadı: OPS_PROVIDER ayarlayın (kayıtlı: ${providerNames().join(", ") || "yok"})`);
  }
  const f = registry.get(name);
  if (!f) throw new OpsError("provider_not_configured", `bilinmeyen sağlayıcı '${name.slice(0, 40)}' (kayıtlı: ${providerNames().join(", ") || "yok"})`);
  return f(env);
}
