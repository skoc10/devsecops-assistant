import { z } from "zod";
import {
  RiskClassSchema,
  SensitivitySchema,
  TrustZoneSchema,
} from "./classes.ts";

export const POLICY_EFFECTS = ["allow", "ask", "deny"] as const;
export type PolicyEffect = (typeof POLICY_EFFECTS)[number];

/** Makine-okur karar sebepleri. Denetim kaydı ve kullanıcı mesajları bunlara dayanır. */
export const REASON_CODES = [
  "allowed",
  "schema_invalid",
  "unknown_tool",
  "profile_not_bound",
  "profile_unknown",
  "kind_mismatch",
  "target_unresolved",
  "target_pin_mismatch",
  "scope_violation",
  "ceiling_exceeded",
  "ceiling_requirement",
  "unclassified",
  "policy_deny",
  "taint_escalation",
  "approval_unavailable",
  "approval_denied",
  "audit_unavailable",
  "no_eligible_provider",
  "token_budget_exceeded",
  "call_budget_exceeded",
  "adapter_error",
  "timeout",
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

export const PolicyDecisionSchema = z.strictObject({
  effect: z.enum(POLICY_EFFECTS),
  reasonCode: z.enum(REASON_CODES),
  class: RiskClassSchema,
  detail: z.string().optional(),
});
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;

/**
 * Oturum bağlamının etiketi. Politika yalnız tek sonuca değil, bağlamın bütününe bakar:
 * untrusted içerik, dokunulan profiller ve en hassas veri.
 */
export const ContextLabelSchema = z.strictObject({
  tainted: z.boolean(),
  profilesTouched: z.array(z.string()),
  maxSensitivity: SensitivitySchema,
  /** Bağlamın gidebileceği en uzak bölge (hassasiyet ve profil `egressClass` kısıtlarının en sıkısı). */
  zoneCap: TrustZoneSchema,
});
export type ContextLabel = z.infer<typeof ContextLabelSchema>;

export function emptyContextLabel(): ContextLabel {
  return { tainted: false, profilesTouched: [], maxSensitivity: "none", zoneCap: "third-party-cloud" };
}
