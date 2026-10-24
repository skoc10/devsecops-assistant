import { chmod, lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { OpsError } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";
import type { KnownSecrets } from "@ops/redaction";
import { WorktreeFs } from "./fs.ts";
import type { FsLimits } from "./fs.ts";
import { WorkspaceRegistry } from "./registry.ts";
import type { Workspace } from "./registry.ts";
import { createSnapshot, loadSnapshot } from "./snapshot.ts";
import type { SnapshotLimits } from "./snapshot.ts";

export interface WorkspaceManagerOptions {
  readonly registry: WorkspaceRegistry;
  /** Anlık kopyaların kök dizini (`$OPS_HOME/worktrees`). */
  readonly worktreesDir: string;
  readonly sandbox: Sandbox | null;
  readonly known?: KnownSecrets;
  readonly snapshotLimits?: SnapshotLimits;
  readonly fsLimits?: FsLimits;
  readonly now?: () => Date;
}

export interface SnapshotInfo {
  readonly dir: string;
  readonly sessionId: string;
  readonly workspaceId: string;
  readonly head: string;
  readonly createdAt: string;
}

const SNAPSHOT_DIR = /^([A-Za-z0-9_-]{1,80})--([a-z0-9][a-z0-9._-]{0,62})$/;

/** Oturumun etkin çalışma alanı: kayıtlı bir alandan anlık kopya üretir ve `WorktreeFs` verir. */
export class WorkspaceManager {
  private readonly o: WorkspaceManagerOptions;
  private active: { ws: Workspace; fs: WorktreeFs; sessionId: string } | null = null;

  constructor(opts: WorkspaceManagerOptions) {
    this.o = opts;
  }

  get registry(): WorkspaceRegistry {
    return this.o.registry;
  }

  current(): { ws: Workspace; fs: WorktreeFs; sessionId: string } | null {
    return this.active;
  }

  async activate(id: string, sessionId: string): Promise<{ ws: Workspace; fs: WorktreeFs; dir: string }> {
    const ws = this.o.registry.get(id);
    if (!ws) throw new OpsError("workspace_not_found", `çalışma alanı kayıtlı değil: ${id}`);
    if (!this.o.sandbox || this.o.sandbox.kind === "none") throw new OpsError("sandbox_required", "çalışma alanı için OS sandbox gerekir (bubblewrap/seatbelt)");
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(sessionId)) throw new OpsError("session_id_invalid", "oturum kimliği geçersiz");
    await mkdir(this.o.worktreesDir, { recursive: true, mode: 0o700 });
    await chmod(this.o.worktreesDir, 0o700);
    const dir = join(this.o.worktreesDir, `${sessionId}--${ws.id}`);
    const snap = await createSnapshot({
      repoPath: ws.path,
      destDir: dir,
      sandbox: this.o.sandbox,
      policy: { writePaths: ws.writePaths, denyPaths: ws.denyPaths },
      ...(this.o.snapshotLimits ? { limits: this.o.snapshotLimits } : {}),
      ...(this.o.now ? { now: this.o.now } : {}),
    });
    await writeFile(join(dir, "workspace.json"), `${JSON.stringify({ id: ws.id, engine: ws.engine, path: ws.path, head: snap.manifest.head, sessionId })}\n`, { mode: 0o600 });
    const fs = new WorktreeFs(snap, { writePaths: ws.writePaths, denyPaths: ws.denyPaths }, { ...(this.o.known ? { known: this.o.known } : {}), ...(this.o.fsLimits ? { limits: this.o.fsLimits } : {}) });
    this.active = { ws, fs, sessionId };
    return { ws, fs, dir };
  }

  deactivate(): void {
    this.active = null;
  }

  /** Kalıcı anlık kopyalar (yeniden eskiye). Yalnız `worktreesDir` altındaki, adı kalıba uyan ve `workspace.json`'u tutarlı dizinler. */
  async snapshots(workspaceId?: string): Promise<SnapshotInfo[]> {
    let names: string[];
    try {
      names = await readdir(this.o.worktreesDir);
    } catch {
      return [];
    }
    const out: SnapshotInfo[] = [];
    for (const name of names) {
      const m = SNAPSHOT_DIR.exec(name);
      if (!m) continue;
      if (workspaceId !== undefined && m[2] !== workspaceId) continue;
      const dir = join(this.o.worktreesDir, name);
      try {
        const st = await lstat(dir);
        if (!st.isDirectory() || st.isSymbolicLink()) continue;
        const meta = JSON.parse(await readFile(join(dir, "workspace.json"), "utf8")) as { id?: unknown; sessionId?: unknown; head?: unknown };
        if (meta.id !== m[2] || meta.sessionId !== m[1] || typeof meta.head !== "string") continue;
        const snap = await loadSnapshot(dir);
        out.push({ dir, sessionId: m[1] as string, workspaceId: m[2] as string, head: snap.manifest.head, createdAt: snap.manifest.createdAt });
      } catch {
        /* bozuk/yabancı dizin: listeye alınmaz */
      }
    }
    return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  /** Kayıtlı çalışma alanının (varsayılan: en yeni; ya da `sessionId`) kalıcı anlık kopyasını açar. Sandbox GEREKMEZ (yalnız dosya okur). */
  async openSnapshot(workspaceId: string, sessionId?: string): Promise<{ info: SnapshotInfo; ws: Workspace; fs: WorktreeFs }> {
    const ws = this.o.registry.get(workspaceId);
    if (!ws) throw new OpsError("workspace_not_found", `çalışma alanı kayıtlı değil: ${workspaceId}`);
    const all = await this.snapshots(workspaceId);
    const info = sessionId === undefined ? all[0] : all.find((s) => s.sessionId === sessionId);
    if (!info) throw new OpsError("snapshot_not_found", sessionId ? `oturum '${sessionId}' için anlık kopya yok` : `'${workspaceId}' için anlık kopya yok (önce \`ops chat --workspace ${workspaceId}\`)`);
    const snap = await loadSnapshot(info.dir);
    const fs = new WorktreeFs(snap, { writePaths: ws.writePaths, denyPaths: ws.denyPaths }, { ...(this.o.known ? { known: this.o.known } : {}), ...(this.o.fsLimits ? { limits: this.o.fsLimits } : {}) });
    return { info, ws, fs };
  }
}
