import { z } from "zod";
import {
  EnvironmentSchema,
  RiskClassSchema,
  TrustZoneSchema,
} from "./classes.ts";

export const PROFILE_KINDS = ["k8s", "cloud", "db", "pipeline", "scm", "host", "iac"] as const;
export type ProfileKind = (typeof PROFILE_KINDS)[number];
export const ProfileKindSchema = z.enum(PROFILE_KINDS);

export const PROFILE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,62}$/;
export const ProfileIdSchema = z.string().regex(PROFILE_ID_PATTERN, "geçersiz profil kimliği");

/** Hedefin kimliğini sabitleyen, secret olmayan pin. */
export const TargetPinSchema = z.strictObject({
  /** k8s: sunucu URL'si; db: host:port; scm/pipeline: host. */
  endpoint: z.string().min(1).max(512),
  /** Sunucu CA sertifikasının SHA-256 parmak izi (küçük harf hex). */
  caFingerprint: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
  /** SSH host anahtarı parmak izleri (host profilleri). */
  hostKeyPins: z.array(z.string().min(1)).optional(),
});
export type TargetPin = z.infer<typeof TargetPinSchema>;

export const CREDENTIAL_SOURCE_KINDS = ["static", "exec", "sts", "workload-identity", "oidc"] as const;
export type CredentialSourceKind = (typeof CREDENTIAL_SOURCE_KINDS)[number];

export const CredentialSourceSchema = z.strictObject({
  kind: z.enum(CREDENTIAL_SOURCE_KINDS),
  /** `exec` kaynaklarında izinli argv şablonunun kimliği. */
  execTemplateId: z.string().min(1).optional(),
  /** Kasa dışı ortam bağımlılıkları (env adı / dosya yolu; içerik değil). */
  ambientDependencies: z.array(z.string().min(1)).default([]),
});
export type CredentialSource = z.infer<typeof CredentialSourceSchema>;

/**
 * Profil: secret OLMAYAN tanımlayıcı. Kimlik materyali yalnız kasadadır ve bu şemaya hiçbir yoldan girmez.
 */
export const ProfileSchema = z.strictObject({
  id: ProfileIdSchema,
  kind: ProfileKindSchema,
  displayName: z.string().min(1).max(80),
  environment: EnvironmentSchema,
  targetPin: TargetPinSchema,
  /** Bu profil üzerinden izin verilen en yüksek sınıf. */
  classCeiling: RiskClassSchema,
  /** İzinli kapsamlar (ns, şema, repo, bölge...). `*` = hepsi. Boş olamaz: karar açık olmalı. */
  allowedScopes: z.array(z.string().min(1)).min(1),
  credentialSource: CredentialSourceSchema,
  maxLeaseTtlSec: z.number().int().min(1).max(3600).default(120),
  /** Bu profilin çıktısının gidebileceği en uzak model bölgesi. */
  egressClass: TrustZoneSchema,
  /** Tür-özel secret olmayan öznitelikler (ör. db: `role=reader`, `datasource=orders`). */
  attributes: z.record(z.string(), z.string()).default({}),
  /** Yalnız testkit tarafından, çalıştırmaya özgü anahtarla üretilen imza. */
  testFixtureSig: z.string().optional(),
});
export type Profile = z.infer<typeof ProfileSchema>;
export type ProfileInput = z.input<typeof ProfileSchema>;

/**
 * Kapsam listesi bir değeri kapsıyor mu? `*` her şeyi kapsar; `sahip/*` biçimi (yalnız sonda `/*`)
 * `sahip/depo` gibi TEK düzey altı kapsamları kapsar (iç içe `sahip/a/b` kapsanmaz).
 */
export function scopeAllows(allowed: readonly string[], scope: string): boolean {
  if (allowed.includes("*") || allowed.includes(scope)) return true;
  for (const a of allowed) {
    if (a.length > 2 && a.endsWith("/*") && !a.slice(0, -2).includes("*")) {
      const prefix = a.slice(0, -1); // "sahip/"
      if (scope.startsWith(prefix) && scope.length > prefix.length && !scope.slice(prefix.length).includes("/")) return true;
    }
  }
  return false;
}

export const TargetSchema = z.strictObject({
  profileId: ProfileIdSchema,
  kind: ProfileKindSchema,
  /** Adapter'ın çözdüğü gerçek uç nokta; profilin pini ile karşılaştırılır. */
  endpoint: z.string().min(1),
  /** Dokunulan kapsamlar (ns, şema, repo...). */
  scopes: z.array(z.string()),
  /** Kaynak başvuruları (ör. `Deployment/payments/api`); kanıt `subject` eşleşmesi için. */
  refs: z.array(z.string()),
});
export type Target = z.infer<typeof TargetSchema>;
