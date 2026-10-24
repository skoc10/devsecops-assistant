import { z } from "zod";
import { EnvironmentSchema, RiskClassSchema } from "@ops/contracts";

/**
 * Ürünün ERİŞİM politikası (hedef sistemin politikası değil). Kurallar sert kontrolleri
 * (sınıf tavanı, hedef pini, kapsam, taint) GEVŞETEMEZ; yalnız sıkılaştırabilir veya, dar
 * koşullarda, taban `ask` kararını `allow`'a çekebilir (yalnız `mutate`, taint dışı).
 */
export const RuleWhenSchema = z.strictObject({
  /** Araç adı deseni: `k8s.*`, `db.query.read`. */
  tool: z.string().min(1).optional(),
  /** Profil kimliği deseni. */
  profile: z.string().min(1).optional(),
  environment: z.array(EnvironmentSchema).min(1).optional(),
  class: z.array(RiskClassSchema).min(1).optional(),
  /** Hedef kapsamlarından herhangi biri bu desenlerden birine uyuyorsa. */
  scope: z.array(z.string().min(1)).min(1).optional(),
  tainted: z.boolean().optional(),
});
export type RuleWhen = z.infer<typeof RuleWhenSchema>;

export const PolicyRuleSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/),
  description: z.string().optional(),
  when: RuleWhenSchema,
  effect: z.enum(["allow", "ask", "deny"]),
  /** ISO tarih; `allow` kuralları süreli olmak zorundadır. */
  expires: z.string().optional(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const BudgetsSchema = z.strictObject({
  /** Oturum başına en çok araç çağrısı. */
  maxToolCalls: z.number().int().positive(),
  /** Tek araç sonucunun modele gidebileceği token tavanı (araç tanımındaki tavanla `min`). */
  maxResultTokens: z.number().int().positive(),
  /** Yumuşak eşik: uyarı. */
  softSessionTokens: z.number().int().positive(),
  /** Sert eşik: yeni araç/model çağrısı reddedilir. */
  hardSessionTokens: z.number().int().positive(),
});
export type Budgets = z.infer<typeof BudgetsSchema>;

export const PolicyDocumentSchema = z
  .strictObject({
    version: z.literal(1),
    budgets: BudgetsSchema,
    rules: z.array(PolicyRuleSchema),
  })
  .superRefine((doc, ctx) => {
    if (doc.budgets.softSessionTokens > doc.budgets.hardSessionTokens) {
      ctx.addIssue({ code: "custom", message: "soft eşik sert eşikten büyük olamaz", path: ["budgets"] });
    }
    const ids = new Set<string>();
    doc.rules.forEach((r, i) => {
      if (ids.has(r.id)) ctx.addIssue({ code: "custom", message: `yinelenen kural kimliği: ${r.id}`, path: ["rules", i, "id"] });
      ids.add(r.id);
      if (r.effect === "allow") {
        if (!r.expires) ctx.addIssue({ code: "custom", message: "allow kuralı süreli (expires) olmalı", path: ["rules", i, "expires"] });
        if (r.when.class?.some((c) => c === "deploy" || c === "destroy")) {
          ctx.addIssue({ code: "custom", message: "deploy/destroy için allow kuralı yazılamaz", path: ["rules", i, "when", "class"] });
        }
        if (!r.when.tool || !r.when.profile) {
          ctx.addIssue({ code: "custom", message: "allow kuralı araç ve profil ile daraltılmalı", path: ["rules", i, "when"] });
        }
      }
      if (r.expires !== undefined && Number.isNaN(Date.parse(r.expires))) {
        ctx.addIssue({ code: "custom", message: "expires geçerli bir tarih olmalı", path: ["rules", i, "expires"] });
      }
    });
  });
export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;
