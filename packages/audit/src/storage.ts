import { chmod, mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

/** Dayanıklı, yalnız-ekleme satır deposu. */
export interface AuditStorage {
  /** Satırı (sonunda `\n` olmadan) kalıcı olarak ekler; başarısızlıkta fırlatır. */
  append(line: string): Promise<void>;
  readLines(): Promise<string[]>;
}

export class FileAuditStorage implements AuditStorage {
  private readonly path: string;
  private readonly fsync: boolean;

  constructor(path: string, opts: { fsync?: boolean } = {}) {
    this.path = path;
    this.fsync = opts.fsync ?? true;
  }

  async append(line: string): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const fh = await open(this.path, "a", 0o600);
    try {
      await fh.appendFile(`${line}\n`, "utf8");
      if (this.fsync) await fh.datasync();
    } finally {
      await fh.close();
    }
  }

  async readLines(): Promise<string[]> {
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw e;
    }
    return text.split("\n").filter((l) => l.length > 0);
  }
}

/** Test ve geçici kullanım için bellek içi depo. `failNext` ile yazma hatası simüle edilir. */
export class MemoryAuditStorage implements AuditStorage {
  readonly lines: string[] = [];
  failNext = false;

  async append(line: string): Promise<void> {
    if (this.failNext) throw new Error("yazma hatası (simüle)");
    this.lines.push(line);
  }

  async readLines(): Promise<string[]> {
    return [...this.lines];
  }
}

/** Zincir başının ikinci bir konuma yazıldığı çapa (kuyruk kesmeyi tespit için). */
export interface HeadAnchor {
  read(): Promise<{ seq: number; hash: string } | null>;
  write(head: { seq: number; hash: string }): Promise<void>;
}

export class FileHeadAnchor implements HeadAnchor {
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  async read(): Promise<{ seq: number; hash: string } | null> {
    try {
      const j = JSON.parse(await readFile(this.path, "utf8")) as { seq?: unknown; hash?: unknown };
      if (typeof j.seq === "number" && typeof j.hash === "string") return { seq: j.seq, hash: j.hash };
      return null;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
  }

  async write(head: { seq: number; hash: string }): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(head), { mode: 0o600 });
    await chmod(tmp, 0o600);
    await rename(tmp, this.path);
  }
}

export class MemoryHeadAnchor implements HeadAnchor {
  head: { seq: number; hash: string } | null = null;
  failNext = false;

  async read(): Promise<{ seq: number; hash: string } | null> {
    return this.head ? { ...this.head } : null;
  }

  async write(head: { seq: number; hash: string }): Promise<void> {
    if (this.failNext) throw new Error("çapa yazma hatası (simüle)");
    this.head = { ...head };
  }
}
