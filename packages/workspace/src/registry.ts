import { mkdir, open, readFile, realpath, rename, stat, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import { OpsError } from "@ops/contracts";

export const WORKSPACE_ENGINES = ["terraform", "opentofu", "ansible"] as const;
export type WorkspaceEngine = (typeof WORKSPACE_ENGINES)[number];

export const WorkspaceSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,62}$/),
  /** Kayıt anındaki gerçek yol (realpath). */
  path: z.string().min(1).max(500),
  engine: z.enum(WORKSPACE_ENGINES),
  /** Yazılabilir yollar (glob; `**` her şey). */
  writePaths: z.array(z.string().min(1).max(200)).max(50).default(["**"]),
  /** Ek okuma+yazma yasak yollar (glob). */
  denyPaths: z.array(z.string().min(1).max(200)).max(50).default([]),
});
export type Workspace = z.infer<typeof WorkspaceSchema>;

interface FileShape {
  readonly version: 1;
  readonly workspaces: unknown[];
}

/** `workspaces.json` (0600): secret içermez. Kullanıcının çalışma kopyasına ASLA yazılmaz; yalnız anlık kopya üretilir. */
export class WorkspaceRegistry {
  private items: Workspace[];
  private readonly file: string;
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(file: string, items: Workspace[]) {
    this.file = file;
    this.items = items;
  }

  static async open(file: string): Promise<WorkspaceRegistry> {
    let raw: FileShape | null = null;
    try {
      raw = JSON.parse(await readFile(file, "utf8")) as FileShape;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw new OpsError("workspaces_corrupt", "workspaces.json okunamadı");
    }
    const items: Workspace[] = [];
    for (const w of raw?.workspaces ?? []) {
      const p = WorkspaceSchema.safeParse(w);
      if (!p.success) throw new OpsError("workspaces_corrupt", "workspaces.json geçersiz bir kayıt içeriyor");
      items.push(p.data);
    }
    return new WorkspaceRegistry(file, items);
  }

  list(): Workspace[] {
    return this.items.map((w) => ({ ...w }));
  }

  get(id: string): Workspace | undefined {
    const w = this.items.find((x) => x.id === id);
    return w ? { ...w } : undefined;
  }

  private persist(): Promise<void> {
    const run = async (): Promise<void> => {
      await mkdir(dirname(this.file), { recursive: true, mode: 0o700 });
      const tmp = `${this.file}.${process.pid}.tmp`;
      // Önceden dikilmiş symlink izlenmez: eski geçici dosya silinir (symlink'in kendisi), yenisi O_EXCL ile açılır.
      await unlink(tmp).catch((e: NodeJS.ErrnoException) => {
        if (e.code !== "ENOENT") throw e;
      });
      const fh = await open(tmp, "wx", 0o600);
      try {
        await fh.chmod(0o600);
        await fh.writeFile(`${JSON.stringify({ version: 1, workspaces: this.items }, null, 2)}\n`, "utf8");
      } finally {
        await fh.close();
      }
      await rename(tmp, this.file);
    };
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }

  /**
   * Kayıt: yol bir git deposunun KÖKÜ olmalı (`.git` dizini), ev dizini/kökü/üstü olamaz (kimlik
   * dizinleri görünmesin). Depo içeriği yalnız `git ls-tree`/`cat-file` ile OKUNUR.
   */
  async add(input: { id: string; path: string; engine: WorkspaceEngine; writePaths?: string[]; denyPaths?: string[] }, opts: { replace?: boolean; home?: string } = {}): Promise<Workspace> {
    if (!input.path.startsWith("/")) throw new OpsError("workspace_path_invalid", "yol mutlak olmalı");
    let real: string;
    try {
      real = await realpath(input.path);
    } catch {
      throw new OpsError("workspace_path_invalid", "yol bulunamadı");
    }
    const home = await realpath(opts.home ?? homedir()).catch(() => opts.home ?? homedir());
    const under = (a: string, b: string): boolean => a === b || b.startsWith(`${a.replace(/\/+$/, "")}/`);
    if (real === "/" || under(real, home)) throw new OpsError("workspace_path_invalid", "çalışma alanı kök, ev dizini veya bunların üstü olamaz; ayrı bir proje dizini seçin");
    const git = await stat(join(real, ".git")).catch(() => null);
    if (!git?.isDirectory()) throw new OpsError("workspace_not_git", "çalışma alanı bir git deposunun kökü olmalı (.git dizini)");
    const ws = WorkspaceSchema.parse({ id: input.id, path: real, engine: input.engine, ...(input.writePaths ? { writePaths: input.writePaths } : {}), ...(input.denyPaths ? { denyPaths: input.denyPaths } : {}) });
    const idx = this.items.findIndex((x) => x.id === ws.id);
    if (idx >= 0 && !opts.replace) throw new OpsError("workspace_exists", `çalışma alanı zaten kayıtlı: ${ws.id}`);
    const before = this.items;
    this.items = idx >= 0 ? this.items.map((x, i) => (i === idx ? ws : x)) : [...this.items, ws];
    try {
      await this.persist();
    } catch (e) {
      this.items = before;
      throw e;
    }
    return { ...ws };
  }

  async remove(id: string): Promise<boolean> {
    const n = this.items.length;
    this.items = this.items.filter((x) => x.id !== id);
    if (this.items.length === n) return false;
    await this.persist();
    return true;
  }
}
