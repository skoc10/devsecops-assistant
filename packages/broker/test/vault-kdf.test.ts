import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// scrypt'e giden parola girdisini yakala (gerçek scrypt'e iletilir). Ayrı dosya: vi.mock tüm dosyayı etkiler.
const captured: Buffer[] = [];
vi.mock("node:crypto", async (orig) => {
  const real = await orig<typeof import("node:crypto")>();
  return {
    ...real,
    scrypt: (...args: Parameters<typeof real.scrypt>) => {
      captured.push(args[0] as Buffer);
      return real.scrypt(...args);
    },
  };
});
const { EncryptedFileStore } = await import("../src/index.ts");

const FAST = { kdf: { N: 1 << 10, r: 8, p: 1 } };
const zeroed = (b: Uint8Array | undefined): boolean => b !== undefined && b.length > 0 && b.every((x) => x === 0);

describe("EncryptedFileStore: KDF girdisi", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-vault-kdf-"));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  beforeEach(() => {
    captured.length = 0;
  });

  it("R-V1: scrypt'e verilen parola kopyası türetmeden sonra sıfırlanır (oluşturma, açma, verify)", async () => {
    const path = join(dir, "v1", "vault.json");
    const pass = new TextEncoder().encode("correct-horse-battery");
    const s = await EncryptedFileStore.open(path, async () => pass, FAST);
    s.close();
    expect(zeroed(pass)).toBe(true);
    expect(captured.length).toBe(1);
    expect(zeroed(captured[0])).toBe(true);

    const again = await EncryptedFileStore.open(path, async () => new TextEncoder().encode("correct-horse-battery"), FAST);
    again.close();
    expect(await EncryptedFileStore.verify(path, new TextEncoder().encode("yanlis-parola"))).toBe(false);
    expect(captured.length).toBe(3);
    for (const c of captured) expect(zeroed(c)).toBe(true);
  });

  it("geçersiz KDF parametresiyle (eşzamanlı scrypt hatası) de kopya sıfırlanır", async () => {
    const path = join(dir, "v2", "vault.json");
    (await EncryptedFileStore.open(path, async () => new TextEncoder().encode("parola-1"), FAST)).close();
    const j = JSON.parse(await readFile(path, "utf8")) as { kdf: { N: number } };
    j.kdf.N = 1000; // 2'nin kuvveti değil: scrypt eşzamanlı fırlatır
    await writeFile(path, JSON.stringify(j));
    captured.length = 0;
    await expect(EncryptedFileStore.open(path, async () => new TextEncoder().encode("parola-1"), FAST)).rejects.toThrow();
    expect(captured.length).toBe(1);
    expect(zeroed(captured[0])).toBe(true);
  });
});
