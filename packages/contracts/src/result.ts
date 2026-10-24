import { z } from "zod";
import { SensitivitySchema } from "./classes.ts";

export const RedactionSummarySchema = z.strictObject({
  rule: z.string().min(1),
  count: z.number().int().positive(),
});
export type RedactionSummary = z.infer<typeof RedactionSummarySchema>;

export const TAINTS = ["trusted", "untrusted"] as const;
export type Taint = (typeof TAINTS)[number];

export const ProvenanceSchema = z.strictObject({
  source: z.string().min(1),
  profileId: z.string().optional(),
  targetFingerprint: z.string().optional(),
  observedAt: z.string().min(1),
  query: z.string().optional(),
});
export type Provenance = z.infer<typeof ProvenanceSchema>;

/**
 * PEP boru hattından çıkan, modele giden sonuç zarfı. `view` redakte ve kompaktlaştırılmıştır;
 * tam redakte sonuç Evidence Store'dadır (`evidenceId`).
 */
export const ToolResultSchema = z.strictObject({
  callId: z.string().min(1),
  tool: z.string().min(1),
  status: z.enum(["ok", "error", "denied"]),
  evidenceId: z.string().optional(),
  summary: z.string(),
  /** Kompakt görünüm (redakte). `byReference` ise yoktur. */
  view: z.unknown().optional(),
  /** Token tavanını aştığı için ham görünüm verilmedi; `evidence.get` ile dilimlenir. */
  byReference: z.boolean(),
  truncated: z.boolean(),
  redactions: z.array(RedactionSummarySchema),
  provenance: ProvenanceSchema,
  sensitivity: SensitivitySchema,
  taint: z.enum(TAINTS),
  /** Kanıt `subject` başvuruları (mutasyon eşleşmesi için). */
  subjects: z.array(z.string()),
  tokens: z.strictObject({ estimate: z.number().int().nonnegative() }),
  /** `denied`/`error` için makine-okur sebep kodu. */
  reasonCode: z.string().optional(),
});
export type ToolResult = z.infer<typeof ToolResultSchema>;
