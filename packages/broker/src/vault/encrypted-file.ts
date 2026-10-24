import { createCipheriv, createDecipheriv, randomBytes, scrypt } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { OpsError } from "@ops/contracts";
import type { SecretStore } from "@ops/contracts";

/**
 * Şifreli yerel kasa. AEAD: AES-256-GCM (Node yerleşik); KDF: scrypt (Node yerleşik — Argon2id
 * Node çekirdeğinde yok, tasarımdaki Argon2id tercihi `doğrulanacak`). Girdi adları düz metindir
 * (profil kimlikleri gibi meta veri sızar), DEĞERLER şifrelidir; her girdi kendi adına bağlıdır
 * (AAD) — şifreli bloklar girdiler arasında taşınamaz.
 */
export type PassphraseProvider = () => Promise<Uint8Array>;

interface KdfParams {
  readonly name: "scrypt";
  readonly salt: string;
  readonly N: number;
  readonly r: number;
  readonly p: number;
}

interface Sealed {
  readonly nonce: string;
  readonly ct: string;
  readonly tag: string;
}

interface VaultFile {
  readonly version: 1;
  readonly kdf: KdfParams;
  readonly check: Sealed;
  readonly entries: Record<string, Sealed>;
}

const CHECK_PLAINTEXT = Buffer.from("ops-vault-check-v1");
const CHECK_NAME = "\u0000check";

function deriveKey(passphrase: Uint8Array, kdf: KdfParams): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      Buffer.from(passphrase),
      Buffer.from(kdf.salt, "base64"),
      32,
      { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: 256 * 1024 * 1024 },
      (err, key) => (err ? reject(err) : resolve(key)),
    );
  });
}

function seal(key: Buffer, name: string, plaintext: Uint8Array): Sealed {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(Buffer.from(`ops-vault:${name}`));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return { nonce: nonce.toString("base64"), ct: ct.toString("base64"), tag: c.getAuthTag().toString("base64") };
}

function open(key: Buffer, name: string, s: Sealed): Buffer {
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(s.nonce, "base64"));
  d.setAAD(Buffer.from(`ops-vault:${name}`));
  d.setAuthTag(Buffer.from(s.tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(s.ct, "base64")), d.final()]);
}

export class EncryptedFileStore implements SecretStore {
  readonly kind = "encrypted-file";
  private readonly path: string;
  private key: Buffer | null;
  private data: VaultFile;
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(path: string, key: Buffer, data: VaultFile) {
    this.path = path;
    this.key = key;
    this.data = data;
  }

  /** Kasayı açar; yoksa oluşturur. Yanlış parola `vault_locked`, bozuk dosya `vault_corrupt`. */
  static async open(
    path: string,
    passphrase: PassphraseProvider,
    opts: { kdf?: { N: number; r: number; p: number } } = {},
  ): Promise<EncryptedFileStore> {
    let existing: VaultFile | null = null;
    try {
      existing = JSON.parse(await readFile(path, "utf8")) as VaultFile;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new OpsError("vault_corrupt", "kasa dosyası okunamadı");
      }
    }
    const pass = await passphrase();
    try {
      if (existing) {
        if (existing.version !== 1 || existing.kdf?.name !== "scrypt") throw new OpsError("vault_corrupt", "kasa sürümü/KDF tanınmıyor");
        const key = await deriveKey(pass, existing.kdf);
        try {
          open(key, CHECK_NAME, existing.check);
        } catch {
          key.fill(0);
          throw new OpsError("vault_locked", "kasa parolası yanlış");
        }
        return new EncryptedFileStore(path, key, existing);
      }
      const kdf: KdfParams = {
        name: "scrypt",
        salt: randomBytes(16).toString("base64"),
        N: opts.kdf?.N ?? 1 << 17,
        r: opts.kdf?.r ?? 8,
        p: opts.kdf?.p ?? 1,
      };
      const key = await deriveKey(pass, kdf);
      const data: VaultFile = { version: 1, kdf, check: seal(key, CHECK_NAME, CHECK_PLAINTEXT), entries: {} };
      const store = new EncryptedFileStore(path, key, data);
      await store.persist();
      return store;
    } finally {
      pass.fill(0);
    }
  }

  private requireKey(): Buffer {
    if (!this.key) throw new OpsError("vault_locked", "kasa kilitli");
    return this.key;
  }

  private async persist(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(this.data), { mode: 0o600 });
    await chmod(tmp, 0o600);
    await rename(tmp, this.path);
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  async get(name: string): Promise<Uint8Array | null> {
    const key = this.requireKey();
    const s = this.data.entries[name];
    if (!s) return null;
    try {
      return new Uint8Array(open(key, name, s));
    } catch {
      throw new OpsError("vault_corrupt", `kasa girdisi doğrulanamadı: ${name}`);
    }
  }

  set(name: string, value: Uint8Array): Promise<void> {
    return this.serial(async () => {
      const key = this.requireKey();
      this.data = { ...this.data, entries: { ...this.data.entries, [name]: seal(key, name, value) } };
      await this.persist();
    });
  }

  delete(name: string): Promise<boolean> {
    return this.serial(async () => {
      this.requireKey();
      if (!(name in this.data.entries)) return false;
      const { [name]: _gone, ...rest } = this.data.entries;
      this.data = { ...this.data, entries: rest };
      await this.persist();
      return true;
    });
  }

  async list(prefix: string): Promise<string[]> {
    this.requireKey();
    return Object.keys(this.data.entries).filter((k) => k.startsWith(prefix)).sort();
  }

  /** Anahtarı bellekten siler; sonraki işlemler `vault_locked` verir. */
  close(): void {
    this.key?.fill(0);
    this.key = null;
  }
}
