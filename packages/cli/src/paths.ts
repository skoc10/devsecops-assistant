import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface OpsPaths {
  readonly home: string;
  readonly vaultFile: string;
  readonly profilesFile: string;
  readonly auditLog: string;
  readonly auditAnchor: string;
  readonly runDir: string;
  readonly socket: string;
  readonly userSkillsDir: string;
  /** Kullanıcının runbook'ları (`<ad>.md`); yoksa `runbook.*` araçları kayıtlı olmaz. */
  readonly runbooksDir: string;
  readonly policyFile: string;
  /** Kullanıcı komut kataloğu (yerleşiği GENİŞLETİR, geçersiz kılamaz). */
  readonly userCatalogFile: string;
  /** Maskeli sütun bildirimi (`masking.yaml`); yoksa yalnız varsayılan sütun adı kuralları + dedektörler. */
  readonly maskingFile: string;
  /** Kayıtlı IaC çalışma alanları (secret içermez). */
  readonly workspacesFile: string;
  /** Oturum başına kalıcı anlık kopyalar (`<oturum>--<alan>/{work,base}`). */
  readonly worktreesDir: string;
  /** Önerilen değişiklikler (ChangeSet): `<id>/{changeset.json, dosya}`. */
  readonly changesDir: string;
  /** Dış MCP sunucuları için kullanıcı manifesti (`mcp-servers.yaml`); yoksa köprü kapalı. */
  readonly mcpManifestFile: string;
  /** Break-glass inceleme dosyaları: `<oturum>.md` (denetim kayıtlarından üretilir). */
  readonly breakGlassDir: string;
}

/** `OPS_HOME` (varsayılan `~/.ops-assistant`). Tüm durum burada: tek kullanıcı, yerel. */
export function resolvePaths(home: string = process.env["OPS_HOME"] ?? join(homedir(), ".ops-assistant")): OpsPaths {
  return {
    home,
    vaultFile: join(home, "vault", "vault.json"),
    profilesFile: join(home, "profiles.json"),
    auditLog: join(home, "audit", "audit.jsonl"),
    auditAnchor: join(home, "audit", "head.anchor"),
    runDir: join(home, "run"),
    socket: join(home, "run", "opsd.sock"),
    userSkillsDir: join(home, "skills"),
    runbooksDir: join(home, "runbooks"),
    policyFile: join(home, "policy.yaml"),
    userCatalogFile: join(home, "command-catalog.yaml"),
    maskingFile: join(home, "masking.yaml"),
    workspacesFile: join(home, "workspaces.json"),
    worktreesDir: join(home, "worktrees"),
    changesDir: join(home, "changes"),
    mcpManifestFile: join(home, "mcp-servers.yaml"),
    breakGlassDir: join(home, "breakglass-review"),
  };
}

export async function ensureHome(p: OpsPaths): Promise<void> {
  for (const d of [p.home, dirname(p.vaultFile), dirname(p.auditLog), p.runDir]) await mkdir(d, { recursive: true, mode: 0o700 });
}

/** Depodaki yerleşik varlıklar (kaynak ağacından çalışırken). */
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const BUILTIN_SKILLS_DIR = join(REPO_ROOT, "skills");
export const BUILTIN_POLICY_FILE = join(REPO_ROOT, "policies", "policy.yaml");
export const BUILTIN_CATALOG_FILE = join(REPO_ROOT, "policies", "command-catalog", "core.yaml");
