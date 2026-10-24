import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, readFile, readdir, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { OpsError } from "@ops/contracts";
import { Counter, KnownSecrets, scrubText } from "@ops/redaction";
import { diffFile } from "./diff.ts";
import { normalizeRel, readCheck, writeCheck } from "./paths.ts";
import type { PathPolicy } from "./paths.ts";
import type { Snapshot } from "./snapshot.ts";

export interface FsLimits {
  readonly maxReadBytes: number;
  readonly maxWriteBytes: number;
  readonly maxFiles: number;
  readonly maxListEntries: number;
}
export const DEFAULT_FS_LIMITS: FsLimits = { maxReadBytes: 1_048_576, maxWriteBytes: 262_144, maxFiles: 5_000, maxListEntries: 200 };

export interface FileChange {
  readonly path: string;
  readonly status: "added" | "modified";
  readonly additions: number;
  readonly deletions: number;
}

const sha256 = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

/**
 * Anlık kopya (worktree) üzerinde dosya işlemleri. Kullanıcının çalışma kopyasına HİÇBİR yoldan
 * dokunmaz. Her işlem: yol normalleştirme → sert ret / yazma ret / glob politikası → sembolik bağ
 * yok (her bölüm `lstat`) → boyut sınırları. Yazılan içerik M2 desenlerinden geçer: gömülü secret
 * benzeri değer içeren yazım REDDEDİLİR. Dosyalar 0600 (çalıştırılabilir bit yok).
 */
export class WorktreeFs {
  readonly snapshot: Snapshot;
  private readonly policy: PathPolicy;
  private readonly limits: FsLimits;
  private readonly known: KnownSecrets;
  private fileCount: number;

  constructor(snapshot: Snapshot, policy: PathPolicy, opts: { known?: KnownSecrets; limits?: FsLimits } = {}) {
    this.snapshot = snapshot;
    this.policy = policy;
    this.limits = opts.limits ?? DEFAULT_FS_LIMITS;
    this.known = opts.known ?? new KnownSecrets();
    this.fileCount = Object.keys(snapshot.manifest.files).length;
  }

  get root(): string {
    return this.snapshot.workDir;
  }

  /** Kökten itibaren her BÖLÜMÜN sembolik bağ olmadığını doğrular; var olan son bölümün türünü döner. */
  private async walk(rel: string): Promise<"missing" | "file" | "dir"> {
    let cur = this.snapshot.workDir;
    const parts = rel === "" ? [] : rel.split("/");
    for (let i = 0; i < parts.length; i++) {
      cur = join(cur, parts[i] as string);
      let st;
      try {
        st = await lstat(cur);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") return "missing";
        throw e;
      }
      if (st.isSymbolicLink()) throw new OpsError("fs_symlink", "yol sembolik bağ içeriyor");
      const last = i === parts.length - 1;
      if (!last && !st.isDirectory()) throw new OpsError("fs_not_dir", "yolun bir bölümü dizin değil");
      if (last) return st.isDirectory() ? "dir" : st.isFile() ? "file" : (() => { throw new OpsError("fs_special", "özel dosya türü"); })();
    }
    return "dir";
  }

  private checkedRead(path: string): string {
    const c = readCheck(path, this.policy);
    if (!c.ok) throw new OpsError("path_denied", `yol reddedildi: ${c.reason}`);
    return c.rel;
  }

  async read(path: string, opts: { startLine?: number; maxLines?: number } = {}): Promise<{ path: string; totalLines: number; startLine: number; shownLines: number; content: string; bytes: number; sha256: string; truncated: boolean }> {
    const rel = this.checkedRead(path);
    const kind = await this.walk(rel);
    if (kind === "missing") throw new OpsError("fs_not_found", `dosya yok: ${rel}`);
    if (kind === "dir") throw new OpsError("fs_is_dir", `bir dizin: ${rel} (fs.list kullanın)`);
    const buf = await readFile(join(this.snapshot.workDir, rel));
    if (buf.length > this.limits.maxReadBytes) throw new OpsError("fs_too_large", `dosya çok büyük (${buf.length} bayt; sınır ${this.limits.maxReadBytes})`);
    if (buf.includes(0)) throw new OpsError("fs_binary", "ikili dosya okunmaz");
    const lines = buf.toString("utf8").split("\n");
    if (lines.length > 1 && lines.at(-1) === "") lines.pop();
    const start = Math.max(1, opts.startLine ?? 1);
    const max = Math.min(opts.maxLines ?? 300, 400);
    const slice = lines.slice(start - 1, start - 1 + max);
    return { path: rel, totalLines: lines.length, startLine: start, shownLines: slice.length, content: slice.join("\n"), bytes: buf.length, sha256: sha256(buf), truncated: start - 1 + max < lines.length };
  }

  async list(path: string, depth = 1): Promise<{ path: string; entries: { name: string; type: "file" | "dir"; size?: number }[]; truncated: boolean }> {
    const rel = path === "." || path === "" ? "" : this.checkedRead(path);
    const kind = await this.walk(rel);
    if (kind === "missing") throw new OpsError("fs_not_found", `dizin yok: ${rel || "."}`);
    if (kind === "file") throw new OpsError("fs_not_dir", `bir dosya: ${rel}`);
    const entries: { name: string; type: "file" | "dir"; size?: number }[] = [];
    const visit = async (dirRel: string, d: number): Promise<void> => {
      const names = (await readdir(join(this.snapshot.workDir, dirRel), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
      for (const n of names) {
        if (entries.length > this.limits.maxListEntries) return;
        if (n.isSymbolicLink() || (!n.isFile() && !n.isDirectory())) continue;
        const childRel = dirRel === "" ? n.name : `${dirRel}/${n.name}`;
        if (!readCheck(childRel, this.policy).ok) continue;
        if (n.isDirectory()) {
          entries.push({ name: childRel, type: "dir" });
          if (d < depth) await visit(childRel, d + 1);
        } else {
          const st = await lstat(join(this.snapshot.workDir, childRel));
          entries.push({ name: childRel, type: "file", size: st.size });
        }
      }
    };
    await visit(rel, 1);
    const truncated = entries.length > this.limits.maxListEntries;
    return { path: rel || ".", entries: entries.slice(0, this.limits.maxListEntries), truncated };
  }

  /** M2 desenleriyle gömülü secret taraması (entropi kapalı: yanlış pozitifleri sınırlamak için). */
  scanContent(content: string): string[] {
    const counter = new Counter();
    const scrubbed = scrubText(content, this.known, counter, { entropy: false });
    return scrubbed === content ? [] : counter.toSummary().map((s) => s.rule);
  }

  async write(path: string, content: string): Promise<{ path: string; created: boolean; bytes: number; lines: number; sha256: string }> {
    if (typeof content !== "string") throw new OpsError("fs_content_invalid", "içerik metin olmalı");
    const c = writeCheck(path, this.policy);
    if (!c.ok) throw new OpsError("path_denied", `yol reddedildi: ${c.reason}`);
    const rel = c.rel;
    const bytes = Buffer.byteLength(content, "utf8");
    if (bytes > this.limits.maxWriteBytes) throw new OpsError("fs_too_large", `içerik çok büyük (${bytes} bayt; sınır ${this.limits.maxWriteBytes})`);
    if (content.includes("\0")) throw new OpsError("fs_binary", "içerik NUL içeremez");
    const hits = this.scanContent(content);
    if (hits.length > 0) throw new OpsError("secret_in_content", `yazım reddedildi: içerik gömülü secret benzeri değer içeriyor (kural: ${[...new Set(hits)].slice(0, 4).join(", ")}); değeri değişkene/secret deposuna taşıyın`);

    // üst dizinleri bölüm bölüm oluştur (sembolik bağ yok)
    const parts = rel.split("/");
    let cur = this.snapshot.workDir;
    for (const p of parts.slice(0, -1)) {
      cur = join(cur, p);
      let st;
      try {
        st = await lstat(cur);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
        await mkdir(cur, { mode: 0o700 });
        continue;
      }
      if (st.isSymbolicLink()) throw new OpsError("fs_symlink", "yol sembolik bağ içeriyor");
      if (!st.isDirectory()) throw new OpsError("fs_not_dir", "yolun bir bölümü dizin değil");
    }
    const existing = await this.walk(rel);
    if (existing === "dir") throw new OpsError("fs_is_dir", `bir dizin: ${rel}`);
    const created = existing === "missing";
    if (created && this.fileCount >= this.limits.maxFiles) throw new OpsError("workspace_too_large", "çalışma alanı dosya sayısı sınırına ulaştı");
    const target = join(this.snapshot.workDir, rel);
    const tmp = join(dirname(target), `.ops-tmp-${randomBytes(6).toString("hex")}`);
    try {
      await writeFile(tmp, content, { mode: 0o600, flag: "wx" });
      await rename(tmp, target);
    } catch (e) {
      await unlink(tmp).catch(() => undefined);
      throw e;
    }
    if (created) this.fileCount += 1;
    return { path: rel, created, bytes, lines: content === "" ? 0 : content.split("\n").length - (content.endsWith("\n") ? 1 : 0), sha256: sha256(content) };
  }

  /** Okunabilir (politikaya uyan, güvenli adlı) tüm dosyalar; deterministik sıra. */
  async listFiles(): Promise<string[]> {
    return (await this.allFiles()).filter((f) => readCheck(f, this.policy).ok).sort();
  }

  /** Tüm metni okur (satır dilimi yok); aynı yol/boyut/ikili denetimleri. */
  async readText(path: string): Promise<string> {
    const rel = this.checkedRead(path);
    const kind = await this.walk(rel);
    if (kind !== "file") throw new OpsError("fs_not_found", `dosya yok: ${rel}`);
    const buf = await readFile(join(this.snapshot.workDir, rel));
    if (buf.length > this.limits.maxReadBytes) throw new OpsError("fs_too_large", `dosya çok büyük (${buf.length} bayt)`);
    if (buf.includes(0)) throw new OpsError("fs_binary", "ikili dosya okunmaz");
    return buf.toString("utf8");
  }

  private async allFiles(dirRel = ""): Promise<string[]> {
    const out: string[] = [];
    const entries = await readdir(join(this.snapshot.workDir, dirRel), { withFileTypes: true });
    for (const n of entries) {
      const rel = dirRel === "" ? n.name : `${dirRel}/${n.name}`;
      if (n.isSymbolicLink()) continue;
      if (n.isDirectory()) out.push(...(await this.allFiles(rel)));
      else if (n.isFile() && normalizeRel(rel).ok) out.push(rel);
      if (out.length > this.limits.maxFiles + 100) break;
    }
    return out;
  }

  /** Anlık kopyaya göre değişiklikler ve birleşik diff. Gizli/yasak yollar fark dışıdır. */
  async changes(filter?: string): Promise<{ changes: FileChange[]; patch: string }> {
    const rel = filter ? this.checkedRead(filter) : undefined;
    const manifest = this.snapshot.manifest.files;
    const changes: FileChange[] = [];
    const patches: string[] = [];
    for (const f of (await this.allFiles()).sort()) {
      if (!readCheck(f, this.policy).ok) continue;
      if (rel !== undefined && f !== rel && !f.startsWith(`${rel}/`)) continue;
      const cur = await readFile(join(this.snapshot.workDir, f));
      if (cur.includes(0)) continue;
      const base = manifest[f] ? await readFile(join(this.snapshot.baseDir, f)) : null;
      if (base && base.equals(cur)) continue;
      const d = diffFile(f, base ? base.toString("utf8") : null, cur.toString("utf8"));
      if (d.patch === "") continue;
      changes.push({ path: f, status: base ? "modified" : "added", additions: d.additions, deletions: d.deletions });
      patches.push(d.patch);
    }
    return { changes, patch: patches.join("") };
  }
}
