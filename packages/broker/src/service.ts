import { OpsError, ProfileSchema } from "@ops/contracts";
import type { Environment, Profile, RiskClass, SecretStore, TrustZone } from "@ops/contracts";
import { credentialKey } from "./broker.ts";
import { importKubeconfig } from "./kubeconfig.ts";
import type { KubeImportOptions } from "./kubeconfig.ts";
import type { ProfileRegistry } from "./profiles.ts";

/** Bu profil türü ve ortam için çıktının gidebileceği en uzak bölge (kullanıcı değiştirebilir). */
export function defaultEgressFor(kind: Profile["kind"], env: Environment): TrustZone {
  if (kind === "db") return env === "prod" ? "local" : "tenant-cloud";
  if (env === "prod") return "tenant-cloud";
  return "third-party-cloud";
}

export interface AddKubeconfigRequest {
  readonly id: string;
  readonly kubeconfigText: string;
  readonly environment: Environment;
  readonly displayName?: string;
  readonly context?: string;
  readonly baseDir?: string;
  readonly readFile?: KubeImportOptions["readFile"];
  readonly classCeiling?: RiskClass;
  readonly allowedScopes?: readonly string[];
  readonly egressClass?: TrustZone;
  readonly replace?: boolean;
}

export interface AddResult {
  readonly profile: Profile;
  /** Secret içermez. */
  readonly warnings: string[];
}

/**
 * `ops profile add/list/rm` mantığı. DÖNÜŞ DEĞERLERİ VE HATALAR SECRET İÇERMEZ: CLI bunları
 * olduğu gibi yazdırabilir. Kimlik materyali yalnız kasaya gider.
 */
export class ProfileService {
  private readonly registry: ProfileRegistry;
  private readonly store: SecretStore;

  constructor(deps: { registry: ProfileRegistry; store: SecretStore }) {
    this.registry = deps.registry;
    this.store = deps.store;
  }

  async addKubeconfig(req: AddKubeconfigRequest): Promise<AddResult> {
    const imp = await importKubeconfig(req.kubeconfigText, {
      ...(req.context ? { context: req.context } : {}),
      ...(req.baseDir ? { baseDir: req.baseDir } : {}),
      ...(req.readFile ? { readFile: req.readFile } : {}),
    });
    const scopes = req.allowedScopes ? [...req.allowedScopes] : imp.namespace ? [imp.namespace] : [];
    if (scopes.length === 0) {
      throw new OpsError("scope_required", "izinli kapsam belirtilmedi ve bağlamda varsayılan namespace yok (allowedScopes verin; '*' = hepsi)");
    }
    const warnings = [...imp.warnings];
    const ceiling: RiskClass = req.classCeiling ?? "read";
    if (ceiling !== "read") warnings.push(`sınıf tavanı '${ceiling}': yazma araçları Faz 2'de gelir; bu profil o zamana kadar yalnız okuma yapar`);
    if (scopes.includes("*")) warnings.push("allowedScopes '*': tüm namespace'ler izinli");

    const profile = ProfileSchema.parse({
      id: req.id,
      kind: "k8s",
      displayName: req.displayName ?? imp.contextName,
      environment: req.environment,
      targetPin: { endpoint: imp.server, ...(imp.caFingerprint ? { caFingerprint: imp.caFingerprint } : {}) },
      classCeiling: ceiling,
      allowedScopes: scopes,
      credentialSource: { kind: "static" },
      egressClass: req.egressClass ?? defaultEgressFor("k8s", req.environment),
    });

    const key = credentialKey(profile.id);
    const had = await this.store.get(key);
    if (had && !req.replace) throw new OpsError("profile_exists", `kasada bu profil için kimlik zaten var: ${profile.id}`);
    await this.store.set(key, new Uint8Array(Buffer.from(JSON.stringify(imp.blob), "utf8")));
    try {
      await this.registry.add(profile, req.replace ? { replace: true } : {});
    } catch (e) {
      if (!had) await this.store.delete(key);
      throw e;
    }
    return { profile, warnings };
  }

  list(): Profile[] {
    return this.registry.list();
  }

  async remove(id: string): Promise<boolean> {
    const removed = await this.registry.remove(id);
    const deleted = await this.store.delete(credentialKey(id));
    return removed || deleted;
  }
}
