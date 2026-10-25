import { HclError, parseHcl, walkBlocks } from "./hcl.ts";
import type { HclBlock } from "./hcl.ts";

export type FindingSeverity = "block" | "warn" | "info";

export interface PrescanFinding {
  readonly severity: FindingSeverity;
  readonly code: string;
  readonly message: string;
  readonly file: string;
  readonly line?: number;
}

export interface DirModel {
  readonly variables: { name: string; type?: string; hasDefault: boolean; sensitive: boolean }[];
  readonly outputs: { name: string; sensitive: boolean }[];
  readonly resources: Record<string, number>;
  readonly dataSources: Record<string, number>;
}

export interface TerraformModel {
  readonly files: number;
  readonly providers: { name: string; source?: string; version?: string }[];
  readonly providerConfigs: string[];
  readonly modules: { name: string; source: string; kind: "local" | "registry" | "remote" | "dynamic"; versionPinned: boolean }[];
  /** Her dizin (modül) için ayrı: kök `"."`. */
  readonly dirs: Record<string, DirModel>;
  /** Tüm dizinlerin toplamı. */
  readonly resources: Record<string, number>;
  readonly dataSources: Record<string, number>;
  readonly backend?: string;
  readonly requiredVersion?: string;
}

export interface TerraformScan {
  readonly model: TerraformModel;
  readonly findings: PrescanFinding[];
  /** Çalıştırma araçlarını (init/validate/plan) engelleyen bulgu var mı, veya dosya çözümlenemedi mi? */
  readonly blocked: boolean;
}

const TRUSTED_REGISTRIES = new Set(["registry.terraform.io", "registry.opentofu.org"]);
const CRED_ATTRS = /^(access_key|secret_key|secret_access_key|token|password|passphrase|client_secret|private_key|api_key|apikey|auth_token|credentials|session_token|bearer_token|subscription_key|access_token|secret|key_secret)$/i;
/** Kamu kayıt defteri adresi: `ad/ad/sağlayıcı` (noktasız bölümler). Diğer her şey (git::, http, host/ad/ad/sağlayıcı...) UZAK sayılır. */
function moduleKind(src: string): "local" | "registry" | "remote" {
  if (src.startsWith("./") || src.startsWith("../")) return "local";
  const base = (src.split("//")[0] as string).split("/");
  if (!src.includes("::") && !src.includes("@") && base.length === 3 && base.every((p) => /^[a-z0-9][a-z0-9_-]*$/i.test(p))) return "registry";
  return "remote";
}

/**
 * Yerel modül kaynağının (`./`, `../`) çalışma alanı köküne göre sözcüksel normalleştirilmiş dizini (kök = `""`);
 * kökün dışına çıkıyorsa undefined. Kaynak, modül bloğunun bulunduğu dosyanın dizinine görelidir.
 */
function localModuleDir(file: string, src: string): string | undefined {
  const segs = file.includes("/") ? file.slice(0, file.lastIndexOf("/")).split("/") : [];
  for (const s of src.split("/")) {
    if (s === "" || s === ".") continue;
    if (s !== "..") segs.push(s);
    else if (segs.pop() === undefined) return undefined;
  }
  return segs.join("/");
}

const str = (b: HclBlock, k: string): string | undefined => b.attrs[k]?.literal;

/** `{ source = "x", version = "y" }` biçimli nesne ifadesinden alan çıkarır. */
function objField(text: string, key: string): string | undefined {
  const m = new RegExp(`\\b${key}\\s*=\\s*"([^"\\\\]*)"`).exec(text);
  return m?.[1];
}

export function scanTerraform(files: readonly { path: string; text: string }[]): TerraformScan {
  const findings: PrescanFinding[] = [];
  const add = (severity: FindingSeverity, code: string, message: string, file: string, line?: number): void => {
    findings.push({ severity, code, message, file, ...(line !== undefined ? { line } : {}) });
  };
  const providers: TerraformModel["providers"] = [];
  const providerConfigs: string[] = [];
  const modules: TerraformModel["modules"] = [];
  const dirs: Record<string, DirModel> = {};
  const dirOf = (path: string): DirModel => {
    const d = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : ".";
    return (dirs[d] ??= { variables: [], outputs: [], resources: {}, dataSources: {} });
  };
  const resources: Record<string, number> = {};
  const dataSources: Record<string, number> = {};
  let backend: string | undefined;
  let requiredVersion: string | undefined;
  let scanned = 0;

  for (const f of files) {
    if (/\.(tf|tofu)\.json$/.test(f.path)) {
      add("block", "json_syntax_unsupported", "JSON sözdizimi (.tf.json/.tofu.json) ön-taramada desteklenmez; HCL kullanın", f.path);
      continue;
    }
    if (!/\.(tf|tofu)$/.test(f.path)) continue;
    scanned++;
    if (/(^|\/)(override|[^/]+_override)\.(tf|tofu)$/.test(f.path)) add("info", "override_file", "override dosyası: diğer tanımları sessizce değiştirir", f.path);
    let tree;
    try {
      tree = parseHcl(f.text);
    } catch (e) {
      const line = e instanceof HclError ? e.line : undefined;
      add("block", "parse_error", `HCL ayrıştırılamadı: ${e instanceof Error ? e.message.replace(/ \(satır \d+\)$/, "") : "hata"} — doğrulanamayan dosya çalıştırılmaz`, f.path, line);
      continue;
    }
    for (const { block: b, parents } of walkBlocks(tree.blocks)) {
      const top = parents.length === 0;
      if (b.type === "provisioner" || (b.type === "dynamic" && b.labels[0] === "provisioner")) {
        add("block", "provisioner", `provisioner '${b.labels[0] ?? "?"}' yerelde/uzakta komut çalıştırır`, f.path, b.line);
      }
      if (!top) {
        if (b.type === "required_providers" && parents.at(-1)?.type === "terraform") {
          for (const [name, a] of Object.entries(b.attrs)) {
            const source = objField(a.text, "source");
            const version = objField(a.text, "version");
            providers.push({ name, ...(source ? { source } : {}), ...(version ? { version } : {}) });
            const parts = (source ?? `hashicorp/${name}`).split("/");
            if (parts.length === 3 && !TRUSTED_REGISTRIES.has((parts[0] as string).toLowerCase())) {
              add("block", "provider_source_untrusted", `sağlayıcı '${name}' güvenilir kayıt defteri dışından: ${(source ?? "").slice(0, 80)}`, f.path, a.line);
            } else if (parts.length > 3 || parts.length < 2 || parts.some((p) => p === "")) {
              add("block", "provider_source_invalid", `sağlayıcı '${name}' kaynak biçimi geçersiz`, f.path, a.line);
            }
            if (!version) add("warn", "provider_unpinned", `sağlayıcı '${name}' sürüm kısıtı yok`, f.path, a.line);
          }
        }
        if (b.type === "backend" && parents.at(-1)?.type === "terraform") backend = b.labels[0] ?? "?";
        if (b.type === "cloud" && parents.at(-1)?.type === "terraform") backend = "cloud";
        continue;
      }
      switch (b.type) {
        case "terraform":
          if (b.attrs["required_version"]?.literal) requiredVersion = b.attrs["required_version"].literal;
          break;
        case "provider": {
          const name = b.labels[0] ?? "?";
          providerConfigs.push(name);
          for (const [k, a] of Object.entries(b.attrs)) {
            if (CRED_ATTRS.test(k) && a.literal !== undefined && a.literal.trim() !== "") {
              add("block", "embedded_credential", `provider '${name}' içinde gömülü kimlik alanı '${k}' (değer bildirilmez)`, f.path, a.line);
            }
          }
          for (const inner of walkBlocks(b.blocks)) {
            for (const [k, a] of Object.entries(inner.block.attrs)) {
              if (CRED_ATTRS.test(k) && a.literal !== undefined && a.literal.trim() !== "") add("block", "embedded_credential", `provider '${name}' içinde gömülü kimlik alanı '${k}' (değer bildirilmez)`, f.path, a.line);
            }
          }
          break;
        }
        case "module": {
          const name = b.labels[0] ?? "?";
          const src = str(b, "source");
          const versionPinned = b.attrs["version"] !== undefined;
          if (src === undefined) {
            modules.push({ name, source: "(dinamik)", kind: "dynamic", versionPinned });
            add("block", "module_source_dynamic", `module '${name}' kaynağı sabit bir dize değil`, f.path, b.line);
          } else {
            const kind = moduleKind(src);
            modules.push({ name, source: src.slice(0, 120), kind, versionPinned });
            if (kind === "registry") {
              add("warn", "registry_module", `module '${name}' kayıt defterinden: init ağ gerektirir (çevrimdışı sandbox'ta desteklenmez)`, f.path, b.line);
              if (!versionPinned) add("warn", "module_unpinned", `module '${name}' sürümü sabitlenmemiş`, f.path, b.line);
            } else if (kind === "remote") {
              add("block", "remote_module", `module '${name}' uzak kaynaktan (${src.slice(0, 60)}): ağ ve üçüncü taraf kod`, f.path, b.line);
            } else if (localModuleDir(f.path, src) === undefined) {
              // kök dışındaki dizin ön-taramaya hiç girmez (provisioner/external içerebilir) ama init onu yükler
              add("block", "local_module_outside", `module '${name}' yerel kaynağı çalışma alanı dışına çıkıyor (${src.slice(0, 60)}): içeriği ön-taramadan geçemez`, f.path, b.line);
            }
          }
          break;
        }
        case "variable": {
          const type = b.attrs["type"]?.text;
          dirOf(f.path).variables.push({ name: b.labels[0] ?? "?", ...(type ? { type: type.slice(0, 60) } : {}), hasDefault: b.attrs["default"] !== undefined, sensitive: b.attrs["sensitive"]?.text === "true" });
          break;
        }
        case "output":
          dirOf(f.path).outputs.push({ name: b.labels[0] ?? "?", sensitive: b.attrs["sensitive"]?.text === "true" });
          break;
        case "resource": {
          const t = b.labels[0] ?? "?";
          resources[t] = (resources[t] ?? 0) + 1;
          const dm = dirOf(f.path);
          dm.resources[t] = (dm.resources[t] ?? 0) + 1;
          if (t === "null_resource" || t === "terraform_data") continue;
          if (t === "local_file" || t === "local_sensitive_file") add("info", "local_file_resource", "yerel dosya yazan kaynak", f.path, b.line);
          break;
        }
        case "data": {
          const t = b.labels[0] ?? "?";
          dataSources[t] = (dataSources[t] ?? 0) + 1;
          const dd = dirOf(f.path);
          dd.dataSources[t] = (dd.dataSources[t] ?? 0) + 1;
          if (t === "external") add("block", "external_data", "data \"external\" yerelde program çalıştırır", f.path, b.line);
          else if (t === "http" || t === "terraform_remote_state") add("info", "network_data_source", `data "${t}" ağ erişimi ister (sandbox'ta ağ kapalı)`, f.path, b.line);
          else if (t === "local_file" || t === "local_sensitive_file") add("info", "local_file_data", "yerel dosya okuyan veri kaynağı", f.path, b.line);
          break;
        }
        default:
          break;
      }
    }
  }
  const blocked = findings.some((x) => x.severity === "block");
  return {
    model: {
      files: scanned,
      providers,
      providerConfigs: [...new Set(providerConfigs)],
      modules,
      dirs,
      resources,
      dataSources,
      ...(backend ? { backend } : {}),
      ...(requiredVersion ? { requiredVersion } : {}),
    },
    findings,
    blocked,
  };
}
