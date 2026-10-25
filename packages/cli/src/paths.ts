import { chmod, lstat, mkdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { OpsError } from "@ops/contracts";

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
  /** macOS sandbox VM'i (ADR-0011): `state.json`, `ssh_config`, `known_hosts`, Vagrant `.vagrant/`. */
  readonly vmDir: string;
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
    vmDir: join(home, "vm"),
  };
}

/**
 * Dizin bu kullanıcıya ait ve grup/diğerleri YAZAMIYOR mu? Değilse başkası kasa/denetim dosyalarını değiştirebilir
 * veya soketi taklit edebilir. Varsayılan yasak bitler grup/diğer yazma (`0o022`); soket dizini `0o077` ister.
 * `allowSymlink`: yalnız OPS_HOME'un kendisi kullanıcıya ait bir sembolik bağ olabilir (hedef aynı denetimden geçer);
 * alt dizinler (vault, audit, run) gerçek dizin olmalı. Windows kapsam dışı (ürün Linux/macOS).
 */
export async function assertPrivateDir(dir: string, opts: { readonly allowSymlink?: boolean; readonly forbiddenMode?: number } = {}): Promise<void> {
  const uid = process.getuid?.();
  if (uid === undefined) return;
  const forbidden = opts.forbiddenMode ?? 0o022;
  const fail = (why: string): never => {
    throw new OpsError("home_insecure", `OPS_HOME güvenli değil: ${dir}: ${why}`);
  };
  let st = await lstat(dir);
  if (st.isSymbolicLink()) {
    if (!opts.allowSymlink) fail("sembolik bağ (gerçek dizin olmalı)");
    if (st.uid !== uid && st.uid !== 0) fail(`sembolik bağ bu kullanıcıya ait değil (sahip uid ${st.uid})`);
    st = await stat(dir);
  }
  if (!st.isDirectory()) fail("dizin değil");
  if (st.uid !== uid) fail(`bu kullanıcıya (uid ${uid}) ait değil (sahip uid ${st.uid})`);
  if ((st.mode & forbidden) !== 0) {
    fail(`mod ${(st.mode & 0o777).toString(8)}: grup/diğerleri ${forbidden === 0o022 ? "yazabiliyor" : "erişebiliyor"} — içeriği gözden geçirip \`chmod 700\` yapın`);
  }
}

/**
 * OPS_HOME ve hassas alt dizinleri (kasa, denetim, soket) oluşturur ve DOĞRULAR (`assertPrivateDir`). `mkdir(mode)`
 * var olan dizine dokunmaz ve umask'a tabidir: bu çağrının oluşturduğu dizin ayrıca 0700 yapılır; önceden var olan
 * güvensiz dizin DÜZELTİLMEZ, reddedilir (başkası içine dosya bırakmış olabilir). OPS_HOME, içinde bir şey
 * oluşturulmadan önce denetlenir.
 */
export async function ensureHome(p: OpsPaths): Promise<void> {
  for (const d of [p.home, dirname(p.vaultFile), dirname(p.auditLog), p.runDir]) {
    if ((await mkdir(d, { recursive: true, mode: 0o700 })) !== undefined) await chmod(d, 0o700);
    await assertPrivateDir(d, { allowSymlink: d === p.home });
  }
}

/**
 * UDS yolunun bayt sınırı (sondaki NUL hariç): `sun_path` macOS/BSD'de 104, Linux'ta 108 bayttır. Daha uzun yolu
 * libuv SESSİZCE KESER: sunucu 0700 dizinin DIŞINDA kesik bir ada bağlanır (ardından chmod ENOENT ile düşer, soket
 * herkese açık kalır), istemci de aynı kesik ada — orada dinleyen sahte bir sürece — bağlanır. Kesilmez, reddedilir.
 */
export const MAX_SOCKET_PATH_BYTES = process.platform === "linux" ? 107 : 103;

export function assertSocketPathFits(socketPath: string): void {
  const n = Buffer.byteLength(socketPath, "utf8");
  if (n > MAX_SOCKET_PATH_BYTES) {
    throw new OpsError("socket_path_too_long", `opsd soket yolu çok uzun (${n} bayt; bu platformda UDS sınırı ${MAX_SOCKET_PATH_BYTES}): ${socketPath} — kesik yola bağlanılmaz; daha kısa bir OPS_HOME kullanın (ör. ~/.ops-assistant)`);
  }
}

/** Depodaki yerleşik varlıklar (kaynak ağacından çalışırken). */
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const BUILTIN_SKILLS_DIR = join(REPO_ROOT, "skills");
export const BUILTIN_POLICY_FILE = join(REPO_ROOT, "policies", "policy.yaml");
export const BUILTIN_CATALOG_FILE = join(REPO_ROOT, "policies", "command-catalog", "core.yaml");
/** Sandbox VM'inin Vagrant dizini (`Vagrantfile` + `provision.sh`); makine durumu OPS_HOME/vm altındadır. */
export const VM_VAGRANT_DIR = join(REPO_ROOT, "vm");
