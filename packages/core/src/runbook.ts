import type { RiskClass } from "@ops/contracts";

/**
 * Runbook planı (tasarım §4.4): kullanıcının markdown runbook'u deterministik olarak bir PLANA çevrilir. Plan
 * kullanıcıya gösterilir; her araç adımı yine PEP'ten geçer. Şemalar `@ops/skills` (üretici) ile bu paket
 * (gösterim) arasında ortaktır.
 */
export type RunbookStepStatus = "ok" | "manual" | "unknown_tool" | "invalid_args" | "toolset_inactive" | "missing_param" | "profile_unbound" | "not_allowed";

export interface RunbookPlanStep {
  readonly n: number;
  readonly text: string;
  readonly tool?: string;
  readonly args?: Record<string, unknown>;
  readonly class?: RiskClass;
  readonly status: RunbookStepStatus;
  readonly problems?: readonly string[];
}

export interface RunbookPlan {
  readonly name: string;
  readonly title: string;
  readonly params: Readonly<Record<string, string>>;
  readonly steps: readonly RunbookPlanStep[];
}

const STATUS_NOTE: Readonly<Record<RunbookStepStatus, string>> = {
  ok: "",
  manual: "elle/model",
  unknown_tool: "BİLİNMEYEN ARAÇ",
  invalid_args: "GEÇERSİZ ARGÜMAN",
  toolset_inactive: "araç seti kapalı (önce ilgili skill'i yükle)",
  missing_param: "EKSİK PARAMETRE",
  profile_unbound: "profil bağlı değil (/use)",
  not_allowed: "ÇALIŞTIRILAMAZ",
};

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** Kullanıcıya gösterilen plan metni. Okuma adımları `runbook.run` ile otomatik koşar; diğerleri ayrıca onaylanır. */
export function renderRunbookPlan(p: RunbookPlan): string {
  const params = Object.entries(p.params);
  const lines = [`Runbook planı: ${p.title} (${p.name})${params.length ? ` — ${params.map(([k, v]) => `${k}=${clip(v, 40)}`).join(", ")}` : ""}`];
  for (const s of p.steps) {
    const tag = s.tool ? `${s.tool}${s.class ? ` [${s.class}]` : ""}` : "elle";
    const note = STATUS_NOTE[s.status];
    const auto = s.status === "ok" && s.class === "read" ? "otomatik" : s.status === "ok" ? "ayrıca onay/çağrı" : note;
    lines.push(`  ${s.n}. ${tag} — ${clip(s.text, 100)}${auto ? `  (${auto})` : ""}`);
    for (const pr of s.problems ?? []) lines.push(`       ! ${clip(pr, 120)}`);
  }
  lines.push("  (Her araç adımı PEP'ten geçer: okuma dışı adımlar runbook.run ile ÇALIŞMAZ, normal onay akışıyla ayrıca çağrılır.)");
  return lines.join("\n");
}
