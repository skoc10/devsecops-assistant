import type { RiskClass } from "./classes.ts";
import type { Target } from "./profile.ts";

/**
 * Onay ekranında PEP'in kendisinin render ettiği kanonik eylem özeti. Modelin düz metni buraya
 * girmez; `argsRedacted` M2/M3'ten geçmiş argümanlardır.
 */
export interface CanonicalActionSummary {
  readonly tool: string;
  readonly class: RiskClass;
  readonly profile: { readonly id: string; readonly environment: string; readonly displayName: string };
  readonly target: Target | null;
  readonly argsRedacted: unknown;
  readonly citedEvidence: readonly { readonly id: string; readonly summary: string }[];
  readonly taintedContext: boolean;
  /** Neden soruluyor: `class`, `taint_escalation`, `policy_ask`, ... */
  readonly why: string;
  /** Onayın kapsamı hakkında PEP'in kendi notu (ör. oturum boyunca çalışma alanı yazımları). */
  readonly note?: string;
}

export interface ApprovalRequest {
  /** Eylem hash'i: onay bu hash'e bağlıdır, çalıştırma anında yeniden doğrulanır. */
  readonly actionHash: string;
  readonly summary: CanonicalActionSummary;
  readonly expiresInSec: number;
}

export type ApprovalOutcome =
  | { readonly approved: true; readonly approvalId: string; readonly actionHash: string }
  | { readonly approved: false; readonly reason: string };

/** Onay kapısı: yanıt yalnız UI sürecinin kontrol terminalinden (TTY) okunur; araç soketinde yoktur. */
export interface ApprovalGate {
  request(req: ApprovalRequest): Promise<ApprovalOutcome>;
}
