import { randomUUID } from "node:crypto";
import {
  emptyContextLabel,
  maxSensitivity,
  OpsError,
  SENSITIVITY_ZONE_CAP,
  stricterZone,
} from "@ops/contracts";
import type { ContextLabel, Profile, ProfileKind, Sensitivity, TrustZone, Usage } from "@ops/contracts";

export interface SessionUsage {
  toolCalls: number;
  /** Model çağrılarının raporladığı toplam (girdi+çıktı) token. */
  sessionTokens: number;
  /** Modele giden araç sonucu görünümlerinin tahmini toplamı. */
  resultTokens: number;
}

/**
 * Oturum durumu: bağlı profiller (tür başına en çok biri), bağlam etiketi, kapsam çağı (epoch),
 * kullanım sayaçları ve etkin araç setleri. Ortamda "current context" YOKTUR: profil her çağrıda
 * açıkça verilir ve yalnız kullanıcının bağladığı profiller çözülür.
 */
export class Session {
  readonly id: string;
  readonly principal = "local-user";
  /** Profil değişimi bir çağ başlatır; eski kanıt mutasyon atfı olarak kullanılamaz. */
  epoch = 0;
  context: ContextLabel = emptyContextLabel();
  readonly usage: SessionUsage = { toolCalls: 0, sessionTokens: 0, resultTokens: 0 };
  readonly activeToolsets = new Set<string>(["core"]);
  private readonly bound = new Map<ProfileKind, Profile>();

  constructor(id: string = randomUUID()) {
    this.id = id;
  }

  /** Kullanıcı eylemi. Aynı türde başka profil bağlıysa `replace` gerekir ve yeni bir çağ başlar. */
  bind(profile: Profile, opts: { replace?: boolean } = {}): void {
    const existing = this.bound.get(profile.kind);
    if (existing && existing.id !== profile.id) {
      if (!opts.replace) {
        throw new OpsError("profile_kind_taken", `'${profile.kind}' türünde '${existing.id}' zaten bağlı`, {
          existing: existing.id,
        });
      }
      this.epoch += 1;
    }
    this.bound.set(profile.kind, profile);
  }

  unbind(kind: ProfileKind): void {
    if (this.bound.delete(kind)) this.epoch += 1;
  }

  getBound(profileId: string): Profile | undefined {
    for (const p of this.bound.values()) if (p.id === profileId) return p;
    return undefined;
  }

  boundProfiles(): Profile[] {
    return [...this.bound.values()];
  }

  /** Bir araç sonucu bağlama girdi: bağlam etiketini günceller. */
  noteResult(info: { profile?: Profile; sensitivity: Sensitivity; tainted: boolean }): void {
    const c = this.context;
    const touched = info.profile && !c.profilesTouched.includes(info.profile.id) ? [...c.profilesTouched, info.profile.id] : c.profilesTouched;
    let cap: TrustZone = stricterZone(c.zoneCap, SENSITIVITY_ZONE_CAP[info.sensitivity]);
    if (info.profile) cap = stricterZone(cap, info.profile.egressClass);
    this.context = {
      tainted: c.tainted || info.tainted,
      profilesTouched: touched,
      maxSensitivity: maxSensitivity(c.maxSensitivity, info.sensitivity),
      zoneCap: cap,
    };
  }

  /** Temiz bağlam (ör. sağlayıcı değişiminde yalnız `none` hassasiyetli özetle yeniden başlama). */
  resetContext(): void {
    this.context = emptyContextLabel();
  }

  addModelUsage(u: Usage): void {
    this.usage.sessionTokens += u.inputTokens + u.outputTokens;
  }
}
