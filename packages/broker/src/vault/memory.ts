import type { SecretStore } from "@ops/contracts";

/** Test ve geçici kullanım için bellek içi kasa. Üretimde kullanılmaz. */
export class MemorySecretStore implements SecretStore {
  readonly kind = "memory";
  private readonly m = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | null> {
    const v = this.m.get(key);
    return v ? new Uint8Array(v) : null;
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    this.m.set(key, new Uint8Array(value));
  }

  async delete(key: string): Promise<boolean> {
    const v = this.m.get(key);
    if (v) v.fill(0);
    return this.m.delete(key);
  }

  async list(prefix: string): Promise<string[]> {
    return [...this.m.keys()].filter((k) => k.startsWith(prefix)).sort();
  }
}
