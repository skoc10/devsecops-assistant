import type { CredentialHandle } from "./adapter.ts";
import type { Profile } from "./profile.ts";

export interface LeaseRequest {
  readonly profile: Profile;
  /** Genellikle araç adı; denetime yazılır. */
  readonly purpose: string;
  readonly callId: string;
  readonly ttlSec: number;
}

export interface Lease {
  /** Adapter'a verilen opak tutamaç. */
  readonly handle: CredentialHandle;
  /** Materyali siler/kapatır; her durumda (finally) çağrılır. Tekrar çağrılabilir (idempotent). */
  release(): Promise<void>;
}

/** Broker'ın verdiği secret'ları kaydettiği taraf (M3 bilinen-secret tarayıcısı). */
export interface SecretSink {
  add(label: string, value: Uint8Array | string): boolean;
}

/**
 * Kimlik aracısı: kimlik materyalini yalnızca bu çağrı için bağlar. Dönen `Lease` bırakılınca düşer.
 * Materyal ne `Lease` ne `CredentialHandle` üzerinden okunabilir; yalnız broker'ın sağladığı
 * istemci üreticileri tutamacı çözer.
 */
export interface CredentialBroker {
  /**
   * Profilin secret'larını çağrıdan ÖNCE `sink`'e (M3) kaydeder. Yoksa M3 yalnız ilk lease'ten sonra
   * bilir ve ilk çağrının argüman/denetim kaydı o değeri maskeleyemez. Idempotent olmalı.
   */
  prime?(profile: Profile, sink: SecretSink): Promise<void>;
  acquire(req: LeaseRequest, sink: SecretSink): Promise<Lease>;
}
