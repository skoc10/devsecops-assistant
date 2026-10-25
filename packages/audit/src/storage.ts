import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { dirname } from "node:path";
import { OpsError } from "@ops/contracts";
import type { AnchorRecord } from "./anchor.ts";
import { acquireFileLock } from "./lock.ts";
import type { FileLock, FileLockOptions } from "./lock.ts";

/** Dayanıklı, yalnız-ekleme satır deposu. */
export interface AuditStorage {
  /** Satırı (sonunda `\n` olmadan) kalıcı olarak ekler; başarısızlıkta fırlatır. */
  append(line: string): Promise<void>;
  readLines(): Promise<string[]>;
  /** Son (boş olmayan) satır; günlük boşsa `null`. Yazıcı başı her eklemede bununla tazeler (tüm dosya okunmaz). */
  readLastLine(): Promise<string | null>;
  /**
   * `fn`'i, aynı günlüğe yazan öteki yazıcılara (başka süreçler dahil) karşı özel erişimle çalıştırır.
   * Kilit zamanında alınamazsa fırlatır: çağıran yazmaz (fail-closed). Yeniden girişli değildir.
   */
  withLock<T>(fn: () => Promise<T>): Promise<T>;
}

export interface FileAuditStorageOptions {
  fsync?: boolean;
  /** Ekleme kilidi için bekleme üst sınırı (ms); aşılırsa ekleme reddedilir. */
  lockTimeoutMs?: number;
  /** Sahibi yaşıyor görünse de bu yaştan eski kilit bayat sayılır (ms). */
  lockStaleMs?: number;
}

const TAIL_CHUNK = 64 * 1024;
const MAX_LINE_BYTES = 16 * 1024 * 1024;

/**
 * Dosya deposu. Aynı günlüğe birden çok süreç yazar (opsd açıkken her tek seferlik `ops` komutu da
 * `session_start` ekler): eklemeler günlüğün yanındaki `<günlük>.lock` dosyasıyla süreçler arası sıralanır.
 */
export class FileAuditStorage implements AuditStorage {
  private readonly path: string;
  private readonly fsync: boolean;
  private readonly lockOpts: FileLockOptions;
  private lockQueue: Promise<unknown> = Promise.resolve();
  private lock: FileLock | null = null;

  constructor(path: string, opts: FileAuditStorageOptions = {}) {
    this.path = path;
    this.fsync = opts.fsync ?? true;
    this.lockOpts = { timeoutMs: opts.lockTimeoutMs, staleMs: opts.lockStaleMs };
  }

  withLock<T>(fn: () => Promise<T>): Promise<T> {
    // Aynı örnekteki kritik bölgeler önce süreç içinde sıralanır; dosya kilidi süreçler (ve örnekler) arası.
    const run = this.lockQueue.then(async () => {
      const lock = await acquireFileLock(`${this.path}.lock`, this.lockOpts);
      this.lock = lock;
      try {
        return await fn();
      } finally {
        this.lock = null;
        await lock.release();
      }
    });
    this.lockQueue = run.catch(() => undefined);
    return run;
  }

  async append(line: string): Promise<void> {
    // Kilit altındaysa yazmadan hemen önce hâlâ bizim mi bakılır: uzun duraklama (SIGSTOP, uyku) sonrası bayat
    // sayılıp kırılmışsa eski başla yazmak zinciri çatallar. Hiçbir şey yazılmadığı için hata kalıcı değildir.
    if (this.lock && !(await this.lock.held())) throw new OpsError("audit_lock_lost", "denetim kilidi kaybedildi: kayıt yazılmadı");
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

  async readLastLine(): Promise<string | null> {
    let fh: FileHandle;
    try {
      fh = await open(this.path, "r");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
    try {
      // Sondan geriye parça parça okunur; `readLines` ile aynı anlam: sondaki boş satırlar yok sayılır.
      let pos = (await fh.stat()).size;
      let tail = Buffer.alloc(0);
      while (pos > 0) {
        const len = Math.min(TAIL_CHUNK, pos);
        const chunk = Buffer.alloc(len);
        await readExactly(fh, chunk, pos - len);
        pos -= len;
        tail = Buffer.concat([chunk, tail]);
        let end = tail.length;
        while (end > 0 && tail[end - 1] === 0x0a) end--;
        tail = tail.subarray(0, end);
        const nl = tail.lastIndexOf(0x0a);
        if (nl >= 0) return tail.subarray(nl + 1).toString("utf8");
        if (tail.length > MAX_LINE_BYTES) throw new Error("denetim günlüğünün son satırı aşırı uzun");
      }
      return tail.length > 0 ? tail.toString("utf8") : null;
    } finally {
      await fh.close();
    }
  }
}

async function readExactly(fh: FileHandle, buf: Buffer, position: number): Promise<void> {
  for (let off = 0; off < buf.length; ) {
    const { bytesRead } = await fh.read(buf, off, buf.length - off, position + off);
    if (bytesRead === 0) throw new Error("denetim günlüğü okunurken kısaldı");
    off += bytesRead;
  }
}

/** Test ve geçici kullanım için bellek içi depo. `failNext` ile yazma hatası simüle edilir. */
export class MemoryAuditStorage implements AuditStorage {
  readonly lines: string[] = [];
  failNext = false;
  private lockQueue: Promise<unknown> = Promise.resolve();

  async append(line: string): Promise<void> {
    if (this.failNext) throw new Error("yazma hatası (simüle)");
    this.lines.push(line);
  }

  async readLines(): Promise<string[]> {
    return [...this.lines];
  }

  async readLastLine(): Promise<string | null> {
    return this.lines[this.lines.length - 1] ?? null;
  }

  /** Aynı depoyu paylaşan yazıcılar (ör. iki `AuditLog`) için süreç içi kilit. */
  withLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.lockQueue.then(fn);
    this.lockQueue = run.catch(() => undefined);
    return run;
  }
}

/**
 * Zincir başının ikinci bir konuma yazıldığı çapa (kuyruk kesmeyi tespit için). Depo içeriği yorumlamaz:
 * MAC denetimi anahtarı tutan yazıcı/doğrulayıcıdadır (`checkAnchor`).
 */
export interface HeadAnchor {
  /** Ham, güvenilmez içerik (dosyada JSON metni); çapa yoksa `null`. */
  read(): Promise<unknown>;
  write(anchor: AnchorRecord): Promise<void>;
}

export class FileHeadAnchor implements HeadAnchor {
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  async read(): Promise<string | null> {
    try {
      return await readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
  }

  async write(anchor: AnchorRecord): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    // Önceden konmuş geçici dosya izlenmez: bayatı (sembolik bağ dahil; unlink bağı izlemez) kaldırılır ve
    // O_EXCL ile yeniden oluşturulur. Arada yeniden konursa oluşturma EEXIST ile düşer → yazım başarısız
    // (fail-closed); yazma hiçbir zaman bağın hedefine yönlenmez. İzin, yol değil tanıtıcı üzerinden.
    await unlink(tmp).catch((e: unknown) => {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    });
    const fh = await open(tmp, "wx", 0o600);
    try {
      await fh.writeFile(JSON.stringify(anchor), "utf8");
      await fh.chmod(0o600);
    } finally {
      await fh.close();
    }
    await rename(tmp, this.path);
  }
}

export class MemoryHeadAnchor implements HeadAnchor {
  /** Son yazılan çapa. */
  head: AnchorRecord | null = null;
  failNext = false;

  async read(): Promise<AnchorRecord | null> {
    return this.head ? { ...this.head } : null;
  }

  async write(anchor: AnchorRecord): Promise<void> {
    if (this.failNext) throw new Error("çapa yazma hatası (simüle)");
    this.head = { ...anchor };
  }
}
