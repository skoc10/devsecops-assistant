import { randomUUID } from "node:crypto";
import {
  emptyContextLabel,
  maxSensitivity,
  OpsError,
  SENSITIVITY_ZONE_CAP,
  stricterZone,
} from "@ops/contracts";
import type { ContextLabel, Profile, ProfileKind, Sensitivity, TrustZone, Usage } from "@ops/contracts";

export interface ActiveSkill {
  readonly name: string;
  readonly tier: "builtin" | "user" | "imported";
  readonly body: string;
  readonly tokens: number;
  /** Skill'in talep ettiği araç setleri (PEP yine her çağrıyı ayrıca karara bağlar). */
  readonly toolsets: readonly string[];
}

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
  /** Etkin skill gövdeleri (en çok `maxActiveSkills`; en eski çıkarılır). */
  readonly activeSkills = new Map<string, ActiveSkill>();
  /**
   * Yerel-yazma araçları (`scope: local`, `localWrite`) için oturum izni: kullanıcı İLK çağrıyı
   * onayladığında aynı araç, bağlam taint'li OLMADIKÇA oturum boyunca yeniden sorulmaz. Dar kapsam:
   * araç adı + bu oturum; hedef sistem araçlarına ve deploy/destroy'a UYGULANMAZ.
   */
  readonly writeGrants = new Set<string>();
  static readonly BASE_TOOLSETS: readonly string[] = ["core"];
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

  /** Tür başına en çok bir profil bağlı olduğundan belirsizlik yoktur. */
  boundByKind(kind: ProfileKind): Profile | undefined {
    return this.bound.get(kind);
  }

  /**
   * Skill gövdesini etkinleştirir ve araç setlerini açar. Aynı anda en çok `max` gövde etkindir
   * (token ekonomisi); fazlası en eskiden başlayarak çıkarılır. Çıkarılanların adlarını döndürür.
   */
  activateSkill(skill: ActiveSkill, max = 2): string[] {
    this.activeSkills.delete(skill.name);
    this.activeSkills.set(skill.name, skill);
    const evicted: string[] = [];
    while (this.activeSkills.size > max) {
      const oldest = this.activeSkills.keys().next().value as string;
      this.activeSkills.delete(oldest);
      evicted.push(oldest);
    }
    this.recomputeToolsets();
    return evicted;
  }

  private recomputeToolsets(): void {
    this.activeToolsets.clear();
    for (const t of Session.BASE_TOOLSETS) this.activeToolsets.add(t);
    for (const s of this.activeSkills.values()) for (const t of s.toolsets) this.activeToolsets.add(t);
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
