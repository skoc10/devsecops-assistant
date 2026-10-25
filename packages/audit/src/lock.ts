import { randomBytes } from "node:crypto";
import { mkdir, open, stat, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

export interface FileLockOptions {
  /** Kilit bu süre içinde alınamazsa hata fırlatılır (çağıran yazmaz → fail-closed). Varsayılan 5 sn. */
  readonly timeoutMs?: number;
  /**
   * Sahibi yaşıyor görünse de bu yaştan eski kilit bayattır (PID yeniden kullanımı, takılmış süreç).
   * Bir ekleme milisaniyeler sürer; varsayılan 30 sn.
   */
  readonly staleMs?: number;
}

export interface FileLock {
  /** Kilit dosyası hâlâ bu sahibin mi (uzun bir duraklamada bayat sayılıp başkasınca kırılmadı mı)? */
  held(): Promise<boolean>;
  /** Kilidi bırakır; dosya artık başkasınınsa dokunmaz. En iyi çaba: hata fırlatmaz. */
  release(): Promise<void>;
}

interface LockOwner {
  /** Kimlik (içerik + inode + mtime): bayat kilidi kırarken yerine alınmış TAZE kilidi silmemek için. */
  readonly identity: string;
  readonly raw: string;
  readonly ageMs: number;
  readonly pid?: number;
  readonly host?: string;
  readonly token?: string;
}

/** Bu süreçte şu an tutulan kilitlerin belirteçleri: bizim PID'imizi taşıyıp burada tutulmayan kilit artıktır. */
const heldTokens = new Set<string>();
const MAX_LOCK_BYTES = 1024;

function errCode(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException | null)?.code;
}

/**
 * Süreçler arası özel kilit: `path` O_EXCL ile oluşturulur, içine `{pid, host, token}` yazılır.
 * - Kilit tutuluyorsa artan, rastgele saçılmış aralıklarla `timeoutMs`'e dek yeniden denenir.
 * - Bayat kilit (aynı makinede sahibi ölmüş PID; ya da `staleMs`'ten eski) kırılır. Kırma, `<path>.break`
 *   kılavuz dosyasıyla tekleştirilir: iki bekleyen aynı bayat kilidi görüp biri yenisini aldıktan sonra öteki
 *   onu silemez (çifte sahiplik = zincir çatallanması).
 * Sınır: `staleMs`'ten uzun duraklatılmış (SIGSTOP) bir sahip kilidini kaybedebilir; yazmadan hemen önce
 * `held()` ile denetlenir, bu denetim ile yazma arasındaki pencere kapatılamaz (düz dosya kilidinde çit yok).
 */
export async function acquireFileLock(path: string, opts: FileLockOptions = {}): Promise<FileLock> {
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const staleMs = opts.staleMs ?? 30_000;
  const token = randomBytes(16).toString("hex");
  const body = JSON.stringify({ pid: process.pid, host: hostname(), token });
  const deadline = Date.now() + timeoutMs;
  // Belirteç dosya oluşmadan ÖNCE kaydedilir: aynı süreçteki başka bir örnek, yeni oluşturduğumuz kilidi
  // (bizim PID'imiz, henüz kaydedilmemiş belirteç) "artık" sanıp kıramaz.
  heldTokens.add(token);
  try {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    for (let delay = 2; ; ) {
      if (await tryCreate(path, body)) {
        return {
          held: async () => (await readOwner(path).catch(() => null))?.raw === body,
          release: async () => {
            try {
              if ((await readOwner(path))?.raw === body) await unlink(path);
            } catch {
              /* bırakılamayan kilit bayat sayılınca (PID/yaş) kurtarılır */
            } finally {
              heldTokens.delete(token);
            }
          },
        };
      }
      const owner = await readOwner(path);
      if (owner !== null && isStale(owner, staleMs) && (await breakStale(path, owner.identity, staleMs))) continue;
      if (Date.now() >= deadline) throw new Error(`denetim kilidi ${timeoutMs} ms içinde alınamadı (${path})`);
      if (owner !== null) {
        await sleep(Math.round(delay / 2 + Math.random() * delay));
        delay = Math.min(delay * 2, 50);
      }
    }
  } catch (e) {
    heldTokens.delete(token);
    throw e;
  }
}

async function tryCreate(path: string, body: string): Promise<boolean> {
  let fh: FileHandle;
  try {
    fh = await open(path, "wx", 0o600);
  } catch (e) {
    if (errCode(e) === "EEXIST") return false;
    throw e;
  }
  let written = false;
  try {
    await fh.writeFile(body, "utf8");
    written = true;
  } finally {
    await fh.close().catch(() => undefined);
    if (!written) await unlink(path).catch(() => undefined);
  }
  return true;
}

async function readOwner(path: string): Promise<LockOwner | null> {
  let fh: FileHandle;
  try {
    fh = await open(path, "r");
  } catch (e) {
    if (errCode(e) === "ENOENT") return null;
    throw e;
  }
  try {
    const st = await fh.stat();
    const buf = Buffer.alloc(MAX_LOCK_BYTES);
    const { bytesRead } = await fh.read(buf, 0, MAX_LOCK_BYTES, 0);
    const raw = buf.subarray(0, bytesRead).toString("utf8");
    let j: Record<string, unknown> = {};
    try {
      const v: unknown = JSON.parse(raw);
      if (v !== null && typeof v === "object") j = v as Record<string, unknown>;
    } catch {
      /* biçimsiz (yazılırken çöken sahip): yalnız yaş karar verir */
    }
    return {
      identity: `${st.ino}:${st.mtimeMs}:${st.size}:${raw}`,
      raw,
      ageMs: Date.now() - st.mtimeMs,
      ...(typeof j["pid"] === "number" ? { pid: j["pid"] } : {}),
      ...(typeof j["host"] === "string" ? { host: j["host"] } : {}),
      ...(typeof j["token"] === "string" ? { token: j["token"] } : {}),
    };
  } finally {
    await fh.close();
  }
}

function isStale(o: LockOwner, staleMs: number): boolean {
  if (o.ageMs > staleMs) return true;
  // Sahibi bilinmiyor ya da başka makinede (paylaşımlı dizin): PID denetlenemez, yalnız yaş.
  if (o.pid === undefined || o.host !== hostname()) return false;
  if (o.pid === process.pid) return o.token === undefined || !heldTokens.has(o.token);
  return !pidAlive(o.pid);
}

function pidAlive(pid: number): boolean {
  // 0/negatif PID süreç grubunu hedefler: geçersizse "yaşıyor" say, yaş karar versin.
  if (!Number.isSafeInteger(pid) || pid <= 0) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return errCode(e) === "EPERM";
  }
}

/** Bayat kilidi, kılavuz dosya tutulurken ve hâlâ AYNI dosyaysa siler; sildiyse `true`. */
async function breakStale(path: string, identity: string, staleMs: number): Promise<boolean> {
  const guard = `${path}.break`;
  let g: FileHandle;
  try {
    g = await open(guard, "wx", 0o600);
  } catch (e) {
    if (errCode(e) !== "EEXIST") throw e;
    // Başka bir bekleyen kırıyor. Kılavuz da bayatsa (kırarken çöken süreç) kaldırılır; sonraki turda denenir.
    const age = await stat(guard).then(
      (s) => Date.now() - s.mtimeMs,
      () => null,
    );
    if (age !== null && age > staleMs) await unlink(guard).catch(() => undefined);
    return false;
  }
  try {
    const current = await readOwner(path);
    if (current === null || current.identity !== identity) return false;
    await unlink(path);
    return true;
  } catch (e) {
    if (errCode(e) === "ENOENT") return false;
    throw e;
  } finally {
    await g.close().catch(() => undefined);
    await unlink(guard).catch(() => undefined);
  }
}
