import { createHash } from "node:crypto";
import { riskAtLeast, riskRank, sensitivityRank } from "@ops/contracts";
import type {
  ContextLabel,
  PolicyDecision,
  Profile,
  ReasonCode,
  RiskClass,
  Target,
  ToolDescriptor,
} from "@ops/contracts";
import { globMatch } from "./glob.ts";
import type { Budgets, PolicyDocument, PolicyRule } from "./schema.ts";

export interface PolicyInput {
  readonly tool: ToolDescriptor;
  /** max(manifest sınıfı, adapter.classify, komut/SQL sınıflayıcıları). */
  readonly effectiveClass: RiskClass;
  /** Bir sınıflayıcı komutu sınıflayamadı: `destroy` muamelesi (fail-closed). */
  readonly unclassified: boolean;
  /** Yerel (kimliksiz) araçlarda `null`. */
  readonly profile: Profile | null;
  readonly target: Target | null;
  readonly context: ContextLabel;
}

function canonicalJson(v: unknown): string {
  const sort = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(sort);
    if (x !== null && typeof x === "object") {
      return Object.fromEntries(
        Object.entries(x as Record<string, unknown>)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, val]) => [k, sort(val)]),
      );
    }
    return x;
  };
  return JSON.stringify(sort(v));
}

/**
 * Politika karar noktası (PDP). Saf ve deterministiktir: aynı girdi → aynı karar. Model, sağlayıcı
 * veya skill kararı etkilemez (S-13).
 *
 * Sıra: (1) sert kontroller (tavan) → (2) deny kuralları → (3) taban etki → (4) ask kuralları →
 * (5) taint yükseltme → (6) dar allow kuralı. Kurallar sert kontrolleri ve taint yükseltmesini
 * gevşetemez.
 */
export class PolicyEngine {
  readonly versionHash: string;
  readonly budgets: Budgets;
  private readonly rules: readonly PolicyRule[];
  private readonly now: () => Date;

  constructor(doc: PolicyDocument, opts: { now?: () => Date } = {}) {
    this.rules = doc.rules;
    this.budgets = doc.budgets;
    this.now = opts.now ?? (() => new Date());
    this.versionHash = createHash("sha256").update(canonicalJson(doc)).digest("hex");
  }

  decide(input: PolicyInput): PolicyDecision {
    const { tool, profile } = input;
    const cls: RiskClass = input.unclassified ? "destroy" : input.effectiveClass;
    const mk = (effect: PolicyDecision["effect"], reasonCode: ReasonCode, detail?: string): PolicyDecision => ({
      effect,
      reasonCode,
      class: cls,
      ...(detail ? { detail } : {}),
    });

    // 1. Sert kontroller: kurallarla gevşetilemez
    if (profile) {
      if (tool.requiresCeiling && riskRank(profile.classCeiling) < riskRank(tool.requiresCeiling)) {
        return mk("deny", "ceiling_requirement", `araç en az '${tool.requiresCeiling}' tavanı ister, profil '${profile.classCeiling}'`);
      }
      if (riskRank(cls) > riskRank(profile.classCeiling)) {
        return input.unclassified
          ? mk("deny", "unclassified", `sınıflanamayan işlem 'destroy' sayılır; profil tavanı '${profile.classCeiling}'`)
          : mk("deny", "ceiling_exceeded", `sınıf '${cls}' profil tavanı '${profile.classCeiling}' üstünde`);
      }
    } else if (input.unclassified) {
      return mk("deny", "unclassified", "sınıflanamayan işlem");
    } else if (tool.scope === "target") {
      return mk("deny", "kind_mismatch", "hedef araç profil olmadan çağrılamaz");
    }

    // 2. Deny kuralları kazanır
    const matching = this.rules.filter((r) => this.matches(r, input, cls));
    const denyRule = matching.find((r) => r.effect === "deny");
    if (denyRule) return mk("deny", "policy_deny", `kural: ${denyRule.id}`);

    // 3. Taban etki
    let effect: PolicyDecision["effect"] = "allow";
    let reason: ReasonCode = "allowed";
    let detail: string | undefined;
    let baseAskFromClass = false;
    if (riskAtLeast(cls, "mutate") || (tool.scope === "local" && tool.localWrite)) {
      effect = "ask";
      reason = "approval_required";
      baseAskFromClass = true;
    }

    // 4. Ask kuralları sıkılaştırır
    const askRule = matching.find((r) => r.effect === "ask");
    if (askRule && effect === "allow") {
      effect = "ask";
      reason = "policy_ask";
      detail = `kural: ${askRule.id}`;
    }

    // 5. Taint yükseltme: kuralla ve "otomatik izin" ile gevşetilemez
    const escalation = this.taintEscalation(input, cls);
    if (escalation && effect === "allow") return mk("ask", "taint_escalation", escalation);

    // 6. Dar allow kuralı yalnız sınıf kaynaklı taban `ask`'ı gevşetebilir (yalnız mutate, taint dışı)
    if (effect === "ask" && baseAskFromClass && cls === "mutate" && tool.scope === "target" && !escalation) {
      const allowRule = matching.find((r) => r.effect === "allow");
      if (allowRule) return mk("allow", "allowed", `kural: ${allowRule.id}`);
    }

    return mk(effect, reason, detail ?? escalation ?? undefined);
  }

  private taintEscalation(input: PolicyInput, cls: RiskClass): string | null {
    const { context, profile, tool } = input;
    if (!context.tainted) return null;
    if (riskAtLeast(cls, "mutate")) return "bağlamda untrusted içerik varken mutasyon";
    if (tool.network === "open") return "bağlamda untrusted içerik varken dış ağ çıkışı";
    if (profile && context.profilesTouched.length > 0 && !context.profilesTouched.includes(profile.id)) {
      return `bağlamda untrusted içerik varken başka profile okuma (${profile.id})`;
    }
    if (sensitivityRank(tool.sensitivity) > sensitivityRank(context.maxSensitivity)) {
      return "bağlamda untrusted içerik varken daha hassas veriye okuma";
    }
    return null;
  }

  private matches(rule: PolicyRule, input: PolicyInput, cls: RiskClass): boolean {
    if (rule.expires !== undefined && Date.parse(rule.expires) < this.now().getTime()) return false;
    const w = rule.when;
    if (w.tool !== undefined && !globMatch(w.tool, input.tool.name)) return false;
    if (w.profile !== undefined && !(input.profile && globMatch(w.profile, input.profile.id))) return false;
    if (w.environment !== undefined && !(input.profile && w.environment.includes(input.profile.environment))) return false;
    if (w.class !== undefined && !w.class.includes(cls)) return false;
    if (w.tainted !== undefined && w.tainted !== input.context.tainted) return false;
    if (w.scope !== undefined) {
      const scopes = input.target?.scopes ?? [];
      if (!scopes.some((s) => w.scope?.some((p) => globMatch(p, s)))) return false;
    }
    return true;
  }

  /** Oturum bütçesi denetimi: sert eşik aşıldıysa reddeder. */
  checkBudget(usage: { toolCalls: number; sessionTokens: number }): { ok: true; soft: boolean } | { ok: false; reason: ReasonCode } {
    if (usage.toolCalls >= this.budgets.maxToolCalls) return { ok: false, reason: "call_budget_exceeded" };
    if (usage.sessionTokens >= this.budgets.hardSessionTokens) return { ok: false, reason: "token_budget_exceeded" };
    return { ok: true, soft: usage.sessionTokens >= this.budgets.softSessionTokens };
  }

  /** Bir araç sonucunun token tavanı: araç tanımı ve politika tavanının küçüğü. */
  resultTokenCap(tool: ToolDescriptor): number {
    return Math.min(tool.limits.maxOutputTokens, this.budgets.maxResultTokens);
  }
}
