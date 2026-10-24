import { z } from "zod";
import type { RiskClass, Sensitivity } from "./classes.ts";
import { CREDENTIAL_SOURCE_KINDS, ProfileKindSchema } from "./profile.ts";
import type { Profile, Target } from "./profile.ts";
import { ToolDescriptorSchema } from "./tool.ts";
import type { ToolLimits } from "./tool.ts";

export const ADAPTER_CONTRACT = "ops-adapter/1" as const;

export const ADAPTER_KINDS = [
  "kubernetes",
  "cloud",
  "pipeline",
  "scm",
  "gitops",
  "registry",
  "observability",
  "database",
  "scanner",
  "policy-source",
  "iac",
  "cli",
] as const;
export type AdapterKind = (typeof ADAPTER_KINDS)[number];

export const AdapterManifestSchema = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9-]*$/),
  version: z.string().regex(/^\d+\.\d+\.\d+(-[a-z0-9.]+)?$/),
  contract: z.literal(ADAPTER_CONTRACT),
  kind: z.enum(ADAPTER_KINDS),
  profileKinds: z.array(ProfileKindSchema),
  credentialKinds: z.array(z.enum(CREDENTIAL_SOURCE_KINDS)),
  capabilities: z.array(z.string()),
  tools: z.array(ToolDescriptorSchema).min(1),
});
export type AdapterManifest = z.infer<typeof AdapterManifestSchema>;

/**
 * Broker'ın verdiği opak kimlik tutamacı. Adapter ham materyali yorumlamaz; yalnız broker'ın
 * sağladığı istemci üreticilerine geçirir. (Gerçek gövde `@ops/broker` içinde, dışarıya kapalıdır.)
 */
export interface CredentialHandle {
  readonly kind: "credential-handle";
  readonly profileId: string;
  readonly leaseId: string;
}

export interface AdapterCall {
  readonly tool: string;
  readonly args: unknown;
  readonly profile: Profile;
  /** Kimlik gerektirmeyen yerel araçlarda `null`. */
  readonly handle: CredentialHandle | null;
  readonly callId: string;
  readonly signal: AbortSignal;
  readonly limits: ToolLimits;
}

/** Adapter'ın ham çıktısı; redaksiyon/kompaktlaştırma PEP çıktı hattında yapılır. */
export interface RawToolOutput {
  data: unknown;
  /** Adapter'ın kısa özeti (redaksiyondan geçer). */
  summary?: string;
  truncated?: boolean;
  /** Kanıt `subject` başvuruları. */
  subjects?: string[];
  /** Adapter çıktıya özgü hassasiyeti yükseltebilir (düşüremez). */
  sensitivity?: Sensitivity;
}

export interface Adapter {
  readonly manifest: AdapterManifest;
  /** Sorun listesi; boş = geçerli. */
  validateProfile(profile: Profile): string[];
  /** Somut hedefi çözer; pin ve kapsam denetimi PEP'te yapılır. */
  resolveTarget(tool: string, args: unknown, profile: Profile): Target;
  /** Sınıfı yalnız YÜKSELTEBİLİR (PEP `max` alır). */
  classify?(tool: string, args: unknown): RiskClass | undefined;
  connectCheck?(
    handle: CredentialHandle,
    profile: Profile,
  ): Promise<{ identity: string; targetFingerprint: string }>;
  invoke(call: AdapterCall): Promise<RawToolOutput>;
  dispose?(): Promise<void>;
}
