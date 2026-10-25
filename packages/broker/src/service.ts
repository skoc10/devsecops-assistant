import { OpsError, ProfileSchema, riskRank } from "@ops/contracts";
import type { Environment, Profile, RiskClass, SecretStore, TrustZone } from "@ops/contracts";
import { credentialKey } from "./broker.ts";
import { ambientFor, validateBindPath } from "./exec-runner.ts";
import { buildDbCredential } from "./db-credential.ts";
import { buildTokenCredential } from "./token-credential.ts";
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
  /** exec kimlik eklentisi için: kullanıcı şablonları ve ikili çözümleyici (test). */
  readonly execCatalog?: KubeImportOptions["execCatalog"];
  readonly resolveBinary?: KubeImportOptions["resolveBinary"];
  /** Kimlik içerebilen ortam değişkenlerinden sandbox'a geçirilmesine KULLANICININ açıkça onay verdikleri (ör. AWS_ACCESS_KEY_ID). */
  readonly ambientOptInEnv?: readonly string[];
  /** Eklentinin ihtiyaç duyduğu ek salt-okunur mutlak dizinler (ör. ~/google-cloud-sdk). */
  readonly ambientPaths?: readonly string[];
  /** OS sandbox kurulu mu? false ise exec profili eklenir ama uyarılır. */
  readonly sandboxAvailable?: boolean;
  readonly classCeiling?: RiskClass;
  readonly allowedScopes?: readonly string[];
  readonly egressClass?: TrustZone;
  readonly replace?: boolean;
}

export interface AddDatabaseRequest {
  readonly id: string;
  readonly environment: Environment;
  readonly displayName?: string;
  readonly host: string;
  readonly port?: number;
  readonly database: string;
  readonly user: string;
  /** Parola yalnız kasaya gider; CLI 0600 dosyadan/yankısız TTY'den okur. */
  readonly password: string;
  readonly caPem?: string;
  readonly tlsMode?: "verify-full" | "disable";
  readonly serverName?: string;
  /** Mantıksal veri kaynağı adı (denetimde/çıktıda görünür); varsayılan veritabanı adı. */
  readonly datasource?: string;
  /** İzinli şemalar (`*` = hepsi). Boş olamaz. */
  readonly allowedScopes: readonly string[];
  /** Nitelendirilmemiş tabloların çözüleceği şema (`search_path`); varsayılan ilk izinli şema, yoksa `public`. */
  readonly defaultSchema?: string;
  readonly classCeiling?: RiskClass;
  readonly egressClass?: TrustZone;
  readonly replace?: boolean;
}

export interface AddTokenRequest {
  readonly id: string;
  /** `pipeline` (CI/CD okuma) veya `scm` (kaynak deposu okuma). */
  readonly kind: "pipeline" | "scm";
  readonly environment: Environment;
  readonly displayName?: string;
  readonly apiBase: string;
  /** Yalnız kasaya gider; CLI 0600 dosyadan/yankısız TTY'den okur. */
  readonly token: string;
  readonly caPem?: string;
  /** İzinli depolar: `sahip/depo`, `sahip/*` veya `*`. */
  readonly allowedScopes: readonly string[];
  /** Sağlayıcıya özgü secret olmayan öznitelikler (ör. `logHosts`). */
  readonly attributes?: Readonly<Record<string, string>>;
  readonly classCeiling?: RiskClass;
  readonly egressClass?: TrustZone;
  readonly replace?: boolean;
}

const REPO_SCOPE = /^(?:\*|[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/(?:\*|[A-Za-z0-9._-]{1,100}))$/;
const SCHEMA_NAME = /^[a-z_][a-z0-9_$]{0,62}$/;

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
      ...(req.execCatalog ? { execCatalog: req.execCatalog } : {}),
      ...(req.resolveBinary ? { resolveBinary: req.resolveBinary } : {}),
    });
    const scopes = req.allowedScopes ? [...req.allowedScopes] : imp.namespace ? [imp.namespace] : [];
    if (scopes.length === 0) {
      throw new OpsError("scope_required", "izinli kapsam belirtilmedi ve bağlamda varsayılan namespace yok (allowedScopes verin; '*' = hepsi)");
    }
    const warnings = [...imp.warnings];
    const ceiling: RiskClass = req.classCeiling ?? "read";
    if (ceiling !== "read") warnings.push(`sınıf tavanı '${ceiling}': yazma araçları Faz 2'de gelir; bu profil o zamana kadar yalnız okuma yapar`);
    if (scopes.includes("*")) warnings.push("allowedScopes '*': tüm namespace'ler izinli");

    let credentialSource: Profile["credentialSource"] = { kind: "static", ambientDependencies: [] };
    if (imp.exec) {
      for (const p of req.ambientPaths ?? []) validateBindPath(p);
      const ambient = ambientFor(imp.exec.template, {
        ...(req.ambientOptInEnv ? { optInEnv: req.ambientOptInEnv } : {}),
        ...(req.ambientPaths ? { paths: req.ambientPaths } : {}),
      });
      credentialSource = { kind: "exec", execTemplateId: imp.exec.template.id, ambientDependencies: ambient };
      warnings.push(`eklentiye geçirilecek ortam bağımlılıkları (kasa dışı): ${ambient.join(", ")}`);
      if (imp.exec.template.network === "host") warnings.push("eklenti sandbox'ta HOST AĞI kullanır (ağ allowlist'i yok; bulut kimlik servislerine erişmesi gerekir)");
      if (req.sandboxAvailable === false) warnings.push("OS sandbox bulunamadı: bu profil sandbox kurulana kadar kimlik üretemez (bubblewrap/seatbelt)");
    }

    const profile = ProfileSchema.parse({
      id: req.id,
      kind: "k8s",
      displayName: req.displayName ?? imp.contextName,
      environment: req.environment,
      targetPin: { endpoint: imp.server, ...(imp.caFingerprint ? { caFingerprint: imp.caFingerprint } : {}) },
      classCeiling: ceiling,
      allowedScopes: scopes,
      credentialSource,
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

  /**
   * `db` profili. Tavan `read` → reader rolü; `mutate|deploy|destroy` → writer rolü (ayrı DB kullanıcısı
   * olmalıdır; her değişiklik önizleme + onaydan geçer). Parola kasaya yazılır; dönen profil ve uyarılar
   * parola içermez.
   */
  async addDatabase(req: AddDatabaseRequest): Promise<AddResult> {
    const ceiling: RiskClass = req.classCeiling ?? "read";
    const writer = riskRank(ceiling) > riskRank("read");
    const scopes = [...req.allowedScopes];
    if (scopes.length === 0) throw new OpsError("scope_required", "izinli şema belirtilmedi (allowedScopes verin; '*' = hepsi)");
    for (const sc of scopes) if (sc !== "*" && !SCHEMA_NAME.test(sc)) throw new OpsError("scope_invalid", `şema adı geçersiz (küçük harf/rakam/_ ile, ≤63): ${sc.slice(0, 40)}`);
    const defaultSchema = req.defaultSchema ?? scopes.find((x) => x !== "*") ?? "public";
    if (!SCHEMA_NAME.test(defaultSchema)) throw new OpsError("scope_invalid", "varsayılan şema adı geçersiz");
    if (!scopes.includes("*") && !scopes.includes(defaultSchema)) throw new OpsError("scope_invalid", "varsayılan şema izinli şemalar arasında olmalı");
    const imp = buildDbCredential({
      host: req.host,
      ...(req.port !== undefined ? { port: req.port } : {}),
      database: req.database,
      user: req.user,
      password: req.password,
      ...(req.caPem !== undefined ? { caPem: req.caPem } : {}),
      ...(req.tlsMode ? { tlsMode: req.tlsMode } : {}),
      ...(req.serverName ? { serverName: req.serverName } : {}),
    });
    const warnings = [...imp.warnings];
    if (scopes.includes("*")) warnings.push("allowedScopes '*': tüm şemalar izinli");
    if (writer) {
      warnings.push(
        `tavan '${ceiling}': yazıcı profili. Bu profil için reader'dan AYRI, en az yetkili bir DB kullanıcısı kullanın (yalnız gereken tablolarda INSERT/UPDATE/DELETE; tablo SAHİBİ ve süper kullanıcı olmasın` +
          `${ceiling === "mutate" ? "; CREATE/TRUNCATE yetkisi olmasın" : ""}). Her değişiklik önizleme + onaydan geçer, tek işlemde uygulanır ve satır üst sınırı aşılırsa geri alınır. \`ops profile doctor\` fiili yetkiyi tavanla karşılaştırır.`,
      );
    }
    const datasource = (req.datasource ?? req.database).slice(0, 63);
    const profile = ProfileSchema.parse({
      id: req.id,
      kind: "db",
      displayName: req.displayName ?? datasource,
      environment: req.environment,
      targetPin: { endpoint: imp.endpoint, ...(imp.caFingerprint ? { caFingerprint: imp.caFingerprint } : {}) },
      classCeiling: ceiling,
      allowedScopes: scopes,
      credentialSource: { kind: "static", ambientDependencies: [] },
      egressClass: req.egressClass ?? defaultEgressFor("db", req.environment),
      attributes: { role: writer ? "writer" : "reader", datasource, defaultSchema },
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

  /** `pipeline`/`scm` profili (GitHub REST). Belirteç kasaya yazılır; profil/uyarılar belirteç içermez. */
  async addToken(req: AddTokenRequest): Promise<AddResult> {
    const ceiling: RiskClass = req.classCeiling ?? "read";
    if (riskRank(ceiling) > riskRank("deploy")) throw new OpsError("ceiling_unsupported", `${req.kind} profilleri en çok 'deploy' tavanlı olabilir (destroy aracı yok)`);
    const scopes = [...req.allowedScopes].map((x) => x.toLowerCase()); // GitHub depo adları büyük/küçük harfe duyarsızdır
    if (scopes.length === 0) throw new OpsError("scope_required", "izinli depo belirtilmedi (allowedScopes verin: sahip/depo, sahip/* veya *)");
    for (const sc of scopes) if (!REPO_SCOPE.test(sc)) throw new OpsError("scope_invalid", `depo kapsamı geçersiz (sahip/depo | sahip/* | *): ${sc.slice(0, 60)}`);
    const imp = buildTokenCredential({ apiBase: req.apiBase, token: req.token, ...(req.caPem !== undefined ? { caPem: req.caPem } : {}) });
    const warnings = [...imp.warnings];
    if (scopes.includes("*")) warnings.push("allowedScopes '*': erişilebilen tüm depolar izinli");
    if (riskRank(ceiling) > riskRank("read")) warnings.push(`tavan '${ceiling}': yazma araçları (PR açma${ceiling === "deploy" ? ", koşu yeniden çalıştırma" : ""}) belirtecin yazma izni olduğunda çalışır; belirteci yalnız gereken depolara ve izinlere (Contents/Pull requests/Actions) daraltın — her yazma önizleme + onaydan geçer`);
    const profile = ProfileSchema.parse({
      id: req.id,
      kind: req.kind,
      displayName: req.displayName ?? `${req.kind} ${new URL(imp.endpoint).hostname}`,
      environment: req.environment,
      targetPin: { endpoint: imp.endpoint, ...(imp.caFingerprint ? { caFingerprint: imp.caFingerprint } : {}) },
      classCeiling: ceiling,
      allowedScopes: scopes,
      credentialSource: { kind: "static", ambientDependencies: [] },
      egressClass: req.egressClass ?? defaultEgressFor(req.kind, req.environment),
      attributes: { ...(req.attributes ?? {}), role: riskRank(ceiling) > riskRank("read") ? "writer" : "reader" },
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
