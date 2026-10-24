import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { OpsError } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";
import type { KnownSecrets } from "@ops/redaction";
import { WorktreeFs } from "./fs.ts";
import type { FsLimits } from "./fs.ts";
import { WorkspaceRegistry } from "./registry.ts";
import type { Workspace } from "./registry.ts";
import { createSnapshot } from "./snapshot.ts";
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
}
