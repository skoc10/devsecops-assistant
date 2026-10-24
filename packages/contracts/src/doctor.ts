import { z } from "zod";
import { RiskClassSchema } from "./classes.ts";

export const DOCTOR_SEVERITIES = ["error", "warn", "info"] as const;

export const DoctorFindingSchema = z.strictObject({
  severity: z.enum(DOCTOR_SEVERITIES),
  /** Makine-okur kod (ör. `secrets_readable`). */
  code: z.string().min(1),
  /** İnsan-okur; secret içermez. */
  message: z.string().min(1),
});
export type DoctorFinding = z.infer<typeof DoctorFindingSchema>;

/**
 * Profil doktoru çıktısı. `bindable=false` ise profil oturuma BAĞLANMAZ: beyan edilen tavan ile
 * fiili (uzak) yetki arasındaki fark, kimlik yankısı ve pin eşleşmesi burada sınanır.
 */
export const DoctorReportSchema = z.strictObject({
  profileId: z.string().min(1),
  checkedAt: z.string().min(1),
  connected: z.boolean(),
  pinOk: z.boolean(),
  identity: z.string().optional(),
  declaredCeiling: RiskClassSchema,
  /** Fiili yetkiden türetilen en yüksek sınıf. */
  effectiveClass: RiskClassSchema.optional(),
  scopesChecked: z.array(z.string()),
  findings: z.array(DoctorFindingSchema),
  bindable: z.boolean(),
});
export type DoctorReport = z.infer<typeof DoctorReportSchema>;
