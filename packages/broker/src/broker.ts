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
import type { ExecCredentialRunner, ExecCredentialResult } from "./exec-runner.ts";
import type { KubeCredentialBlob } from "./kubeconfig.ts";
import type { DbCredential, DbCredentialBlob } from "./db-credential.ts";

export const credentialKey = (profileId: string): string => `profile/${profileId}/credential`;

/** Adapter'ın TLS istemcisini kurmak için gereken malzeme. Yalnız `CredentialResolver` ile okunur. */
export interface KubeCredential {
  readonly server: string;
  readonly caPem?: string;
  readonly token?: string;
  readonly clientCertPem?: string;
  readonly clientKeyPem?: string;
  readonly tlsServerName?: string;
}

/**
 * Tutamaç → malzeme çözücü. Bu yetenek (capability) YALNIZ composition root'ta, birinci taraf
 * adapter'lara enjekte edilir; model, skill ve dış süreçler asla alamaz. Birinci taraf adapter'lar
 * asistanla aynı süreç/heap'te çalışır: "adapter kimliği hiç görmez" iddiası yalnız model, skill,
 * dış süreç ve eklenti adapter'ları içindir (tasarım §3.5).
 */
export interface CredentialResolver {
  k8s(handle: CredentialHandle): KubeCredential;
  db(handle: CredentialHandle): DbCredential;
}

interface Material {
  readonly profileId: string;
  readonly kubeBlob: KubeCredentialBlob | null;
  readonly dbBlob: DbCredentialBlob | null;
  /** JSON baytlarının kopyası: bırakınca sıfırlanır (JS string kopyaları için en iyi çaba). */
  readonly raw: Buffer;
  active: boolean;
}

type AnyBlob = KubeCredentialBlob | DbCredentialBlob;

function parseBlob(raw: Uint8Array): AnyBlob {
  let j: unknown;
  try {
    j = JSON.parse(Buffer.from(raw).toString("utf8"));
  } catch {
    throw new OpsError("credential_corrupt", "kasadaki kimlik materyali okunamadı");
  }
  const b = j as { v?: unknown; kind?: unknown; server?: unknown; host?: unknown; password?: unknown } | null;
  if (b && b.v === 1 && (b.kind === "k8s-static" || b.kind === "k8s-exec") && typeof b.server === "string") return b as KubeCredentialBlob;
  if (b && b.v === 1 && b.kind === "db-static" && typeof b.host === "string" && typeof b.password === "string") return b as DbCredentialBlob;
  throw new OpsError("credential_corrupt", "kasadaki kimlik materyali tanınmıyor");
}

export interface LocalBrokerOptions {
  readonly store: SecretStore;
  readonly maxConcurrentLeases?: number;
  /** `exec` kimlik kaynakları için; yoksa exec profilleri açık hata verir. */
  readonly exec?: ExecCredentialRunner;
  readonly now?: () => Date;
}

interface CachedExec {
  readonly result: ExecCredentialResult;
  readonly validUntil: number;
}
/** Süresi bildirilmeyen eklenti çıktısı en çok bu kadar önbelleğe alınır. */
const NO_EXPIRY_CACHE_MS = 30_000;
/** Bitişe bu kadar kala yenilenir. */
const EXPIRY_SKEW_MS = 30_000;

/**
 * Yerel kimlik aracısı: kasadaki materyali çağrı başına bağlar ve bırakınca düşürür. Statik
 * kimlik de **lease** olarak materyalize edilir (aynı yol, aynı denetim). exec/sts/oidc kaynakları
 * ilgili fazlarda gelir; şimdilik açık hata verir.
 */
export class LocalBroker implements CredentialBroker {
  private readonly store: SecretStore;
  private readonly maxLeases: number;
  private readonly execRunner: ExecCredentialRunner | undefined;
  private readonly now: () => Date;
  private readonly execCache = new Map<string, CachedExec>();
  private readonly materials = new WeakMap<object, Material>();
  private active = 0;
  readonly resolver: CredentialResolver;

  constructor(opts: LocalBrokerOptions) {
    this.store = opts.store;
    this.maxLeases = opts.maxConcurrentLeases ?? 8;
    this.execRunner = opts.exec;
    this.now = opts.now ?? (() => new Date());
    this.resolver = {
      k8s: (handle) => {
        const m = this.materials.get(handle);
        if (!m || !m.active) throw new OpsError("lease_inactive", "kimlik tutamacı geçersiz veya süresi dolmuş");
        if (!m.kubeBlob) throw new OpsError("credential_kind_mismatch", "tutamaç k8s kimliği taşımıyor");
        const b = m.kubeBlob;
        return {
          server: b.server,
          ...(b.caPem ? { caPem: b.caPem } : {}),
          ...(b.token ? { token: b.token } : {}),
          ...(b.clientCertPem ? { clientCertPem: b.clientCertPem } : {}),
          ...(b.clientKeyPem ? { clientKeyPem: b.clientKeyPem } : {}),
          ...(b.tlsServerName ? { tlsServerName: b.tlsServerName } : {}),
        };
      },
      db: (handle) => {
        const m = this.materials.get(handle);
        if (!m || !m.active) throw new OpsError("lease_inactive", "kimlik tutamacı geçersiz veya süresi dolmuş");
        if (!m.dbBlob) throw new OpsError("credential_kind_mismatch", "tutamaç veritabanı kimliği taşımıyor");
        const b = m.dbBlob;
        return { host: b.host, port: b.port, database: b.database, user: b.user, password: b.password, tls: b.tls };
      },
    };
  }

  get activeLeases(): number {
    return this.active;
  }

  private async load(profile: Profile): Promise<Buffer> {
    const kind = profile.credentialSource.kind;
    if (kind !== "static" && kind !== "exec") {
      throw new OpsError("credential_source_unsupported", `kimlik kaynağı henüz desteklenmiyor: ${kind}`);
    }
    const raw = await this.store.get(credentialKey(profile.id));
    if (!raw) throw new OpsError("credential_missing", `kasada kimlik yok: ${profile.id}`);
    return Buffer.from(raw);
  }

  /**
   * Profil secret'larını çağrıdan ÖNCE M3'e kaydeder. `exec` kaynaklarında token henüz YOKTUR
   * (lease anında üretilir): o profiller için `prime` hiçbir şey kaydetmez; token `acquire`'da
   * kaydedilir ve intent denetim kaydı token içeremez (model tokenı bilmez).
   */
  async prime(profile: Profile, sink: SecretSink): Promise<void> {
    const raw = await this.load(profile);
    try {
      const blob = parseBlob(raw);
      if (blob.kind === "db-static") {
        sink.add(`profile:${profile.id}:password`, blob.password);
        return;
      }
      if (blob.kind === "k8s-exec") return;
      if (blob.token) sink.add(`profile:${profile.id}:token`, blob.token);
      if (blob.clientKeyPem) sink.add(`profile:${profile.id}:client-key`, blob.clientKeyPem);
    } finally {
      raw.fill(0);
    }
  }

  /** Eklentiyi (gerekirse) çalıştırır; sonucu bitişe kadar bellekte önbelleğe alır. */
  private async materializeExec(profile: Profile, blob: KubeCredentialBlob): Promise<KubeCredentialBlob> {
    if (!blob.exec) throw new OpsError("credential_corrupt", "exec kimliği eksik");
    if (!this.execRunner) throw new OpsError("sandbox_unavailable", "exec kimlik eklentisi için çalıştırıcı yapılandırılmamış");
    const nowMs = this.now().getTime();
    let hit = this.execCache.get(profile.id);
    if (!hit || hit.validUntil <= nowMs) {
      const result = await this.execRunner.run(blob.exec, profile.credentialSource.ambientDependencies);
      const validUntil = result.expiresAt ? result.expiresAt.getTime() - EXPIRY_SKEW_MS : nowMs + NO_EXPIRY_CACHE_MS;
      hit = { result, validUntil };
      if (validUntil > nowMs) this.execCache.set(profile.id, hit);
    }
    const r = hit.result;
    return {
      ...blob,
      ...(r.token ? { token: r.token } : {}),
      ...(r.clientCertPem ? { clientCertPem: r.clientCertPem } : {}),
      ...(r.clientKeyPem ? { clientKeyPem: r.clientKeyPem } : {}),
    };
  }

  /** Önbelleği düşürür (oturum sonu / profil silme). */
  clearExecCache(profileId?: string): void {
    if (profileId) this.execCache.delete(profileId);
    else this.execCache.clear();
  }

  async acquire(req: LeaseRequest, sink: SecretSink): Promise<Lease> {
    if (this.active >= this.maxLeases) throw new OpsError("lease_limit", "eşzamanlı lease sınırı aşıldı");
    const raw = await this.load(req.profile);
    let parsed: AnyBlob;
    try {
      parsed = parseBlob(raw);
    } catch (e) {
      raw.fill(0);
      throw e;
    }
    let blob: KubeCredentialBlob | null = null;
    let dbBlob: DbCredentialBlob | null = null;
    if (parsed.kind === "db-static") {
      dbBlob = parsed;
      sink.add(`profile:${req.profile.id}:password`, parsed.password);
    } else {
      blob = parsed;
      if (blob.kind === "k8s-exec") {
        try {
          blob = await this.materializeExec(req.profile, blob);
        } catch (e) {
          raw.fill(0);
          throw e;
        }
      }
      if (blob.token) sink.add(`profile:${req.profile.id}:token`, blob.token);
      if (blob.clientKeyPem) sink.add(`profile:${req.profile.id}:client-key`, blob.clientKeyPem);
    }

    const handle: CredentialHandle = Object.freeze({
      kind: "credential-handle" as const,
      profileId: req.profile.id,
      leaseId: randomUUID(),
    });
    const m: Material = { profileId: req.profile.id, kubeBlob: blob, dbBlob, raw, active: true };
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
