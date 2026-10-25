import { z } from "zod";
import { EnvironmentSchema, RiskClassSchema, SensitivitySchema, TrustZoneSchema } from "./classes.ts";
import { POLICY_EFFECTS, REASON_CODES } from "./policy.ts";

export const AUDIT_EVENTS = [
  "session_start",
  "session_end",
  "intent",
  "result",
  "lease",
  "model_call",
  "approval",
  "alarm",
  "break_glass",
  "policy_change",
  "evidence_release",
] as const;
export type AuditEvent = (typeof AUDIT_EVENTS)[number];

/**
 * Politika kararının GİRDİSİ (yeniden oynatma: `ops replay --policy`). Yalnız karar için gereken, hassas olmayan
 * alanlar: bayraklar, hassasiyet sınıfları, profil kimlikleri ve kapsam adları. Araç, profil, ortam ve sınıf
 * zaten kaydın kendi alanlarındadır.
 */
export const DecisionContextSchema = z.strictObject({
  unclassified: z.boolean(),
  sensitivity: SensitivitySchema,
  tainted: z.boolean(),
  maxSensitivity: SensitivitySchema,
  profilesTouched: z.array(z.string().max(100)).max(16),
  scopes: z.array(z.string().max(200)).max(16),
  /** Karar anındaki profil sınıf tavanı (profil yoksa yok). */
  ceiling: RiskClassSchema.optional(),
});
export type DecisionContext = z.infer<typeof DecisionContextSchema>;

/**
 * Denetim kaydı alanları. Hiçbir alan ham secret veya ham çıktı taşımaz: `argsRedacted` ve
 * `outputRedacted` M1–M5 sonrası, üst sınırlıdır.
 */
export const AuditBodySchema = z.strictObject({
  ts: z.string().min(1),
  event: z.enum(AUDIT_EVENTS),
  sessionId: z.string().min(1),
  callId: z.string().optional(),
  principal: z.string().min(1),
  provider: z.string().optional(),
  model: z.string().optional(),
  trustZone: TrustZoneSchema.optional(),
  tool: z.string().optional(),
  class: RiskClassSchema.optional(),
  profile: z.string().optional(),
  environment: EnvironmentSchema.optional(),
  target: z.string().optional(),
  decision: z.enum(POLICY_EFFECTS).optional(),
  reasonCode: z.enum(REASON_CODES).optional(),
  approvalId: z.string().optional(),
  /** Bu kayıt bir break-glass izni (hibe kimliği) süresince yazıldı. */
  breakGlass: z.string().optional(),
  actionHash: z.string().optional(),
  argsRedacted: z.unknown().optional(),
  exitStatus: z.string().optional(),
  outputRedacted: z.string().optional(),
  outputHash: z.string().optional(),
  outputBytesToModel: z.number().int().nonnegative().optional(),
  redactionCounts: z.record(z.string(), z.number().int().nonnegative()).optional(),
  policyVersionHash: z.string().optional(),
  tokens: z
    .strictObject({
      input: z.number().int().nonnegative(),
      output: z.number().int().nonnegative(),
      cacheRead: z.number().int().nonnegative(),
    })
    .optional(),
  resultTokensEstimate: z.number().int().nonnegative().optional(),
  decisionContext: DecisionContextSchema.optional(),
  message: z.string().optional(),
});
export type AuditBody = z.infer<typeof AuditBodySchema>;

export const AuditRecordSchema = AuditBodySchema.extend({
  seq: z.number().int().nonnegative(),
  prevHash: z.string().regex(/^[a-f0-9]{64}$/),
  hash: z.string().regex(/^[a-f0-9]{64}$/),
});
export type AuditRecord = z.infer<typeof AuditRecordSchema>;

/** Yazıcı `ts` ve `principal` alanlarını boşsa kendisi doldurur. */
export type AuditEntry = Omit<AuditBody, "ts" | "principal"> & Partial<Pick<AuditBody, "ts" | "principal">>;

/** Denetim yazıcısı sözleşmesi. `append` başarısız olursa çağıran araç çağrısını ÇALIŞTIRMAZ. */
export interface AuditSink {
  append(entry: AuditEntry): Promise<AuditRecord>;
}
