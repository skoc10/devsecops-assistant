/**
 * Kasa soyutlaması. Değerler `Uint8Array` olarak taşınır (mümkün olduğunca JS string'ine çevrilmez).
 * Sohbet, repo, model bağlamı, log ve denetim kaydı kasa DEĞİLDİR.
 */
export interface SecretStore {
  readonly kind: string;
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<boolean>;
  /** Yalnız anahtar adlarını listeler (değer asla). */
  list(prefix: string): Promise<string[]>;
}
