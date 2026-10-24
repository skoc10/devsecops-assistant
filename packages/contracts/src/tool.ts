import { z } from "zod";
import {
  NetworkModeSchema,
  RiskClassSchema,
  ScopeAxisSchema,
  SensitivitySchema,
} from "./classes.ts";
import { ProfileKindSchema } from "./profile.ts";

export const ToolLimitsSchema = z.strictObject({
  timeoutMs: z.number().int().positive(),
  maxBytes: z.number().int().positive(),
  maxItems: z.number().int().positive(),
  /** Modele giden kompakt görünüm için token tavanı; aşan sonuç yalnız referansla döner. */
  maxOutputTokens: z.number().int().positive(),
});
export type ToolLimits = z.infer<typeof ToolLimitsSchema>;

export const TOOL_NAME_PATTERN = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$/;
export const TOOLSET_PATTERN = /^[a-z][a-z0-9-]*$/;

export const ProjectionSchema = z.strictObject({
  /** Varsayılan kompakt alan kümesi. */
  defaultFields: z.array(z.string().min(1)),
  /** Model `select` ile alan kümesini genişletebilir mi? */
  selectable: z.boolean(),
});

const ToolDescriptorBase = z.strictObject({
  /** `<önek>.<noun>.<verb>` — önek adapter'ın kısa kimliği. */
  name: z.string().regex(TOOL_NAME_PATTERN),
  /** Kısa (≤ 2 cümle): her araç tanımı bağlamda yer tutar (token ekonomisi). */
  description: z.string().min(1).max(400),
  /** JSON Schema (additionalProperties:false). */
  inputSchema: z.record(z.string(), z.unknown()),
  outputSchema: z.record(z.string(), z.unknown()).optional(),
  class: RiskClassSchema,
  scope: ScopeAxisSchema.default("target"),
  /** `scope: local` araçlarda yerel dosya yazımı var mı (`local-write`). */
  localWrite: z.boolean().default(false),
  network: NetworkModeSchema.default("none"),
  /** Kimlik gerektirmeyen yerel araçlarda `null`. */
  profileKind: ProfileKindSchema.nullable(),
  sensitivity: SensitivitySchema,
  idempotent: z.boolean(),
  dryRun: z.boolean().default(false),
  limits: ToolLimitsSchema,
  redactionProfile: z.string().min(1).default("default"),
  /** Log/serbest metin dönen araçlar `true`: çıktı taint'lenir. */
  untrustedOutput: z.boolean(),
  /** Skill ile birlikte bağlanan araç grubu. */
  toolset: z.string().regex(TOOLSET_PATTERN),
  projection: ProjectionSchema.optional(),
  typicalOutputTokens: z.number().int().nonnegative(),
  /** Bu aracın çalışabilmesi için profilde gereken asgari sınıf tavanı (ör. sunucu tarafı dry-run). */
  requiresCeiling: RiskClassSchema.optional(),
});

export const ToolDescriptorSchema = ToolDescriptorBase.superRefine((d, ctx) => {
  if (d.class === "read" && d.network === "open" && d.scope === "target") {
    ctx.addIssue({
      code: "custom",
      message: "`read` sınıfı `network: open` aracı kabul etmez",
      path: ["network"],
    });
  }
  if (d.localWrite && d.scope !== "local") {
    ctx.addIssue({
      code: "custom",
      message: "`localWrite` yalnız `scope: local` araçlarda olabilir",
      path: ["localWrite"],
    });
  }
  if (d.scope === "local" && d.profileKind !== null) {
    ctx.addIssue({
      code: "custom",
      message: "`scope: local` araçlar kimlik/profil kullanmaz",
      path: ["profileKind"],
    });
  }
});
export type ToolDescriptor = z.infer<typeof ToolDescriptorSchema>;

export type ToolDescriptorMeta = Omit<z.input<typeof ToolDescriptorBase>, "inputSchema">;

/** Çalışma zamanı araç tanımı: tanımlayıcı + girdiyi doğrulayan zod şeması. */
export interface ToolDefinition {
  readonly descriptor: ToolDescriptor;
  readonly input: z.ZodType;
}

/**
 * Araç tanımı üretir. `input` şeması `z.strictObject` olmalıdır (fazladan alan reddedilir:
 * argüman enjeksiyonu savunması); JSON Schema buradan üretilir.
 */
export function defineTool(meta: ToolDescriptorMeta, input: z.ZodType): ToolDefinition {
  const json = z.toJSONSchema(input, { io: "input" }) as Record<string, unknown>;
  delete json["$schema"];
  if (json["type"] === "object" && json["additionalProperties"] !== false) {
    throw new Error(`araç girdi şeması strictObject olmalı: ${meta.name}`);
  }
  const descriptor = ToolDescriptorSchema.parse({ ...meta, inputSchema: json });
  return { descriptor, input };
}
