import { randomUUID } from "node:crypto";
import { OpsError } from "@ops/contracts";
import type {
  CredentialBroker,
  CredentialHandle,
  Lease,
  LeaseRequest,
  Profile,
  SecretSink,
  SecretStore,
} from "@ops/contracts";
import type { KubeCredentialBlob } from "./kubeconfig.ts";

export const credentialKey = (profileId: string): string => `profile/${profileId}/credential`;

/** Adapter'ın TLS istemcisini kurmak için gereken malzeme. Yalnız `CredentialResolver` ile okunur. */
export type KubeCredential = Omit<KubeCredentialBlob, "v" | "kind">;

/**
 * Tutamaç → malzeme çözücü. Bu yetenek (capability) YALNIZ composition root'ta, birinci taraf
 * adapter'lara enjekte edilir; model, skill ve dış süreçler asla alamaz. Birinci taraf adapter'lar
 * asistanla aynı süreç/heap'te çalışır: "adapter kimliği hiç görmez" iddiası yalnız model, skill,
 * dış süreç ve eklenti adapter'ları içindir (tasarım §3.5).
 */
export interface CredentialResolver {
  k8s(handle: CredentialHandle): KubeCredential;
}

interface Material {
  readonly profileId: string;
  readonly kubeBlob: KubeCredentialBlob | null;
  /** JSON baytlarının kopyası: bırakınca sıfırlanır (JS string kopyaları için en iyi çaba). */
  readonly raw: Buffer;
  active: boolean;
}

function parseBlob(raw: Uint8Array): KubeCredentialBlob {
  let j: unknown;
  try {
    j = JSON.parse(Buffer.from(raw).toString("utf8"));
  } catch {
    throw new OpsError("credential_corrupt", "kasadaki kimlik materyali okunamadı");
  }
  const b = j as Partial<KubeCredentialBlob> | null;
  if (!b || b.v !== 1 || b.kind !== "k8s-static" || typeof b.server !== "string") {
    throw new OpsError("credential_corrupt", "kasadaki kimlik materyali tanınmıyor");
  }
  return b as KubeCredentialBlob;
}

export interface LocalBrokerOptions {
  readonly store: SecretStore;
  readonly maxConcurrentLeases?: number;
}

/**
 * Yerel kimlik aracısı: kasadaki materyali çağrı başına bağlar ve bırakınca düşürür. Statik
 * kimlik de **lease** olarak materyalize edilir (aynı yol, aynı denetim). exec/sts/oidc kaynakları
 * ilgili fazlarda gelir; şimdilik açık hata verir.
 */
export class LocalBroker implements CredentialBroker {
  private readonly store: SecretStore;
  private readonly maxLeases: number;
  private readonly materials = new WeakMap<object, Material>();
  private active = 0;
  readonly resolver: CredentialResolver;

  constructor(opts: LocalBrokerOptions) {
    this.store = opts.store;
    this.maxLeases = opts.maxConcurrentLeases ?? 8;
    this.resolver = {
      k8s: (handle) => {
        const m = this.materials.get(handle);
        if (!m || !m.active) throw new OpsError("lease_inactive", "kimlik tutamacı geçersiz veya süresi dolmuş");
        if (!m.kubeBlob) throw new OpsError("credential_kind_mismatch", "tutamaç k8s kimliği taşımıyor");
        const { v: _v, kind: _k, ...cred } = m.kubeBlob;
        return cred;
      },
    };
  }

  get activeLeases(): number {
    return this.active;
  }

  private async load(profile: Profile): Promise<Buffer> {
    if (profile.credentialSource.kind !== "static") {
      throw new OpsError("credential_source_unsupported", `kimlik kaynağı henüz desteklenmiyor: ${profile.credentialSource.kind}`);
    }
    const raw = await this.store.get(credentialKey(profile.id));
    if (!raw) throw new OpsError("credential_missing", `kasada kimlik yok: ${profile.id}`);
    return Buffer.from(raw);
  }

  /** Profil secret'larını çağrıdan ÖNCE M3'e kaydeder. */
  async prime(profile: Profile, sink: SecretSink): Promise<void> {
    const raw = await this.load(profile);
    try {
      const blob = parseBlob(raw);
      if (blob.token) sink.add(`profile:${profile.id}:token`, blob.token);
      if (blob.clientKeyPem) sink.add(`profile:${profile.id}:client-key`, blob.clientKeyPem);
    } finally {
      raw.fill(0);
    }
  }

  async acquire(req: LeaseRequest, sink: SecretSink): Promise<Lease> {
    if (this.active >= this.maxLeases) throw new OpsError("lease_limit", "eşzamanlı lease sınırı aşıldı");
    const raw = await this.load(req.profile);
    let blob: KubeCredentialBlob;
    try {
      blob = parseBlob(raw);
    } catch (e) {
      raw.fill(0);
      throw e;
    }
    if (blob.token) sink.add(`profile:${req.profile.id}:token`, blob.token);
    if (blob.clientKeyPem) sink.add(`profile:${req.profile.id}:client-key`, blob.clientKeyPem);

    const handle: CredentialHandle = Object.freeze({
      kind: "credential-handle" as const,
      profileId: req.profile.id,
      leaseId: randomUUID(),
    });
    const m: Material = { profileId: req.profile.id, kubeBlob: blob, raw, active: true };
    this.materials.set(handle, m);
    this.active += 1;

    const drop = (): void => {
      if (!m.active) return;
      m.active = false;
      m.raw.fill(0);
      this.materials.delete(handle);
      this.active -= 1;
    };
    const timer = setTimeout(drop, Math.max(1, req.ttlSec) * 1000);
    timer.unref();
    return {
      handle,
      release: async (): Promise<void> => {
        clearTimeout(timer);
        drop();
      },
    };
  }
}
