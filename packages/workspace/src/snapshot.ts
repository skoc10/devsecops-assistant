import { access, constants, lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { OpsError } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";
import { readCheck } from "./paths.ts";
import type { PathPolicy } from "./paths.ts";

export interface SnapshotLimits {
  readonly maxFiles: number;
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
}
export const DEFAULT_LIMITS: SnapshotLimits = { maxFiles: 5_000, maxFileBytes: 1_048_576, maxTotalBytes: 64 * 1_048_576 };

export interface SnapshotManifest {
  readonly version: 1;
  readonly head: string;
  readonly createdAt: string;
  readonly files: Record<string, { readonly oid: string; readonly size: number }>;
  readonly skipped: { readonly path: string; readonly reason: string }[];
}

export interface Snapshot {
  readonly dir: string;
  readonly workDir: string;
  readonly baseDir: string;
  readonly manifest: SnapshotManifest;
}

const GIT_HOME = "/home/ops-git";

async function gitBinary(): Promise<string> {
  for (const p of ["/usr/bin/git", "/usr/local/bin/git", "/bin/git"]) {
    try {
      await access(p, constants.X_OK);
      return p;
    } catch {
      /* sonraki */
    }
  }
  throw new OpsError("git_missing", "git bulunamadı");
}

/**
 * Git'i SANDBOX içinde, depo SALT OKUNUR bağlanarak çalıştırır (yalnız `ls-tree`/`cat-file`: kanca,
 * süzgeç (smudge/clean), fsmonitor ve `.gitattributes` çalıştırmaz). Sandbox yoksa çalışmaz.
 */
async function git(sandbox: Sandbox, repo: string, args: readonly string[], opts: { stdin?: Uint8Array; maxOutputBytes: number }): Promise<Buffer> {
  const bin = await gitBinary();
  const res = await sandbox.run({
    argv: [bin, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never", "-c", "core.untrackedCache=false", "--no-pager", "-C", repo, ...args],
    env: { GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C" },
    roBinds: [repo],
    home: GIT_HOME,
    network: "none",
    ...(opts.stdin ? { stdin: opts.stdin } : {}),
    timeoutMs: 60_000,
    maxOutputBytes: opts.maxOutputBytes,
  });
  if (res.truncated) throw new OpsError("git_output_too_large", "git çıktısı sınırı aştı");
  if (res.timedOut) throw new OpsError("git_timeout", "git zaman aşımına uğradı");
  if (res.code !== 0) throw new OpsError("git_failed", `git başarısız: ${res.stderr.toString("utf8").split("\n")[0]?.slice(0, 160) ?? ""}`);
  return res.stdout;
}

interface TreeEntry {
  readonly mode: string;
  readonly oid: string;
  readonly size: number;
  readonly path: string;
}

function parseLsTree(buf: Buffer): { entries: TreeEntry[]; skipped: SnapshotManifest["skipped"] } {
  const entries: TreeEntry[] = [];
  const skipped: SnapshotManifest["skipped"] = [];
  for (const rec of buf.toString("utf8").split("\0")) {
    if (rec === "") continue;
    const m = /^(\d{6}) (blob|commit|tree) ([0-9a-f]{40,64}) +(\d+|-)\t([\s\S]+)$/.exec(rec);
    if (!m) {
      skipped.push({ path: "?", reason: "ls-tree satırı ayrıştırılamadı" });
      continue;
    }
    const [, mode, type, oid, size, path] = m as unknown as [string, string, string, string, string, string];
    if (type === "commit") {
      skipped.push({ path: path.slice(0, 120), reason: "git alt modülü atlandı" });
      continue;
    }
    if (type !== "blob") continue;
    if (mode === "120000") {
      skipped.push({ path: path.slice(0, 120), reason: "sembolik bağ atlandı" });
      continue;
    }
    if (mode !== "100644" && mode !== "100755") {
      skipped.push({ path: path.slice(0, 120), reason: `desteklenmeyen dosya kipi ${mode}` });
      continue;
    }
    entries.push({ mode, oid, size: Number(size), path });
  }
  return { entries, skipped };
}

/** `git cat-file --batch` çıktısını ayrıştırır: `<oid> blob <size>\n<içerik>\n`. */
function parseBatch(buf: Buffer, want: readonly string[]): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  let pos = 0;
  for (const oid of want) {
    const nl = buf.indexOf(0x0a, pos);
    if (nl < 0) throw new OpsError("git_failed", "cat-file çıktısı beklenmedik biçimde bitti");
    const header = buf.subarray(pos, nl).toString("utf8");
    const m = /^([0-9a-f]+) (blob|missing|tree|commit|tag)(?: (\d+))?$/.exec(header);
    if (!m || m[1] !== oid) throw new OpsError("git_failed", "cat-file başlığı beklenmedik");
    pos = nl + 1;
    if (m[2] === "missing") continue;
    const size = Number(m[3]);
    out.set(oid, buf.subarray(pos, pos + size));
    pos += size + 1;
  }
  return out;
}

/**
 * HEAD'in anlık kopyasını çıkarır: `work/` (ajanın yazdığı) ve `base/` (özgün; fark için). Çalışma
 * kopyasındaki `.git`, state, anahtar, tfvars, `.env`... ASLA kopyalanmaz; semboller, alt modüller ve
 * çalıştırılabilir bit atılır (dosyalar 0600). Kullanıcının çalışma kopyasına dokunulmaz.
 */
export async function createSnapshot(opts: { repoPath: string; destDir: string; sandbox: Sandbox; policy: PathPolicy; limits?: SnapshotLimits; now?: () => Date }): Promise<Snapshot> {
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const { repoPath, destDir, sandbox } = opts;
  if (sandbox.kind === "none") throw new OpsError("sandbox_required", "çalışma alanı anlık kopyası için OS sandbox gerekir (git sandbox içinde çalışır)");

  const head = (await git(sandbox, repoPath, ["rev-parse", "--verify", "HEAD^{commit}"], { maxOutputBytes: 1_000 })).toString("utf8").trim();
  if (!/^[0-9a-f]{40,64}$/.test(head)) throw new OpsError("git_failed", "HEAD çözülemedi (depoda commit yok mu?)");
  const lsOut = await git(sandbox, repoPath, ["ls-tree", "-r", "-z", "-l", "--full-tree", head], { maxOutputBytes: 32 * 1_048_576 });
  const { entries, skipped } = parseLsTree(lsOut);

  const keep: TreeEntry[] = [];
  let total = 0;
  for (const e of entries) {
    const c = readCheck(e.path, opts.policy);
    if (!c.ok) {
      skipped.push({ path: e.path.slice(0, 120), reason: c.reason });
      continue;
    }
    if (e.size > limits.maxFileBytes) {
      skipped.push({ path: e.path.slice(0, 120), reason: `dosya çok büyük (${e.size} bayt)` });
      continue;
    }
    if (keep.length >= limits.maxFiles) throw new OpsError("workspace_too_large", `çalışma alanında ${limits.maxFiles}'den çok dosya var; writePaths/denyPaths ile daraltın veya alt dizini kaydedin`);
    total += e.size;
    if (total > limits.maxTotalBytes) throw new OpsError("workspace_too_large", "çalışma alanı toplam boyut sınırını aştı");
    keep.push(e);
  }

  const workDir = join(destDir, "work");
  const baseDir = join(destDir, "base");
  await mkdir(workDir, { recursive: true, mode: 0o700 });
  await mkdir(baseDir, { recursive: true, mode: 0o700 });

  const files: SnapshotManifest["files"] = {};
  const uniq = [...new Set(keep.map((e) => e.oid))];
  const byOid = new Map<string, Buffer>();
  for (let i = 0; i < uniq.length; ) {
    const chunk: string[] = [];
    let bytes = 0;
    while (i < uniq.length && chunk.length < 400 && bytes < 8 * 1_048_576) {
      const oid = uniq[i] as string;
      chunk.push(oid);
      bytes += keep.find((e) => e.oid === oid)?.size ?? 0;
      i++;
    }
    const out = await git(sandbox, repoPath, ["cat-file", "--batch"], { stdin: new Uint8Array(Buffer.from(`${chunk.join("\n")}\n`)), maxOutputBytes: bytes + chunk.length * 128 + 4096 });
    for (const [k, v] of parseBatch(out, chunk)) byOid.set(k, Buffer.from(v));
  }
  for (const e of keep) {
    const content = byOid.get(e.oid);
    if (!content) {
      skipped.push({ path: e.path.slice(0, 120), reason: "içerik okunamadı" });
      continue;
    }
    for (const root of [workDir, baseDir]) {
      const target = join(root, e.path);
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, content, { mode: 0o600 });
    }
    files[e.path] = { oid: e.oid, size: content.length };
  }
  const manifest: SnapshotManifest = { version: 1, head, createdAt: (opts.now ?? (() => new Date()))().toISOString(), files, skipped: skipped.slice(0, 200) };
  await writeFile(join(destDir, "manifest.json"), `${JSON.stringify(manifest)}\n`, { mode: 0o600 });
  return { dir: destDir, workDir, baseDir, manifest };
}

/** Kalıcı bir anlık kopyayı (`manifest.json` + `work/` + `base/`) yeniden açar. Sembolik bağ ve beklenmeyen yapı reddedilir. */
export async function loadSnapshot(dir: string): Promise<Snapshot> {
  for (const d of [dir, join(dir, "work"), join(dir, "base")]) {
    const st = await lstat(d).catch(() => null);
    if (!st || !st.isDirectory() || st.isSymbolicLink()) throw new OpsError("snapshot_invalid", "anlık kopya yapısı geçersiz");
  }
  let manifest: unknown;
  try {
    manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8"));
  } catch {
    throw new OpsError("snapshot_invalid", "manifest.json okunamadı");
  }
  const m = manifest as Partial<SnapshotManifest>;
  if (m.version !== 1 || typeof m.head !== "string" || !/^[0-9a-f]{40,64}$/.test(m.head) || typeof m.createdAt !== "string" || !m.files || typeof m.files !== "object") {
    throw new OpsError("snapshot_invalid", "manifest.json geçersiz");
  }
  return { dir, workDir: join(dir, "work"), baseDir: join(dir, "base"), manifest: m as SnapshotManifest };
}
