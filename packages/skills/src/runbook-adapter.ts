import { z } from "zod";
import { ADAPTER_CONTRACT, AdapterManifestSchema, defineTool, OpsError } from "@ops/contracts";
import type { Adapter, AdapterCall, Profile, RawToolOutput, Target, ToolDefinition } from "@ops/contracts";
import type { RunbookPlan, RunbookPlanStep, Session, ToolRegistry } from "@ops/core";
import { SKILL_NAME } from "./parse.ts";
import { substituteArgs } from "./runbook.ts";
import type { Runbook, RunbookRegistry } from "./runbook.ts";

const base = {
  class: "read",
  scope: "local",
  profileKind: null,
  sensitivity: "none",
  idempotent: true,
  untrustedOutput: false,
  toolset: "core",
} as const;

const paramsSchema = z
  .record(z.string().regex(/^[a-z_][a-z0-9_]{0,40}$/), z.string().max(200))
  .refine((r) => Object.keys(r).length <= 10, "en çok 10 parametre")
  .optional();

const listTool = defineTool(
  { ...base, name: "runbook.list", description: "Kullanıcının runbook'larını listeler (ad, başlık, ne zaman kullanılır).", limits: { timeoutMs: 2_000, maxBytes: 20_000, maxItems: 50, maxOutputTokens: 600 }, typicalOutputTokens: 150 },
  z.strictObject({}),
);
const planTool = defineTool(
  {
    ...base,
    name: "runbook.plan",
    description: "Runbook'u plana çevirir (adım, araç, sınıf, doğrulama durumu). Plan kullanıcıya gösterilir; hiçbir adım çalışmaz.",
    limits: { timeoutMs: 2_000, maxBytes: 60_000, maxItems: 40, maxOutputTokens: 1_200 },
    typicalOutputTokens: 500,
  },
  z.strictObject({ name: z.string().regex(SKILL_NAME).max(64), params: paramsSchema }),
);
export const MAX_RUN_STEPS = 12;
const runTool = defineTool(
  {
    ...base,
    name: "runbook.run",
    description: "Runbook'un OKUMA adımlarını sırayla koşturur (her adım tam PEP'ten geçer); okuma dışı adımlar çalışmaz. Sonuç: adım başına durum + kanıt kimliği.",
    composite: true,
    limits: { timeoutMs: 150_000, maxBytes: 200_000, maxItems: 40, maxOutputTokens: 2_500 },
    typicalOutputTokens: 1_200,
  },
  z.strictObject({ name: z.string().regex(SKILL_NAME).max(64), params: paramsSchema, steps: z.array(z.number().int().min(1).max(30)).max(30).optional() }),
);

/** Bu ret sebeplerinde koşu DURUR: kullanıcı/politika/denetim "hayır" dedi, devam etmek anlamsız veya güvensiz. */
const STOP_CODES: ReadonlySet<string> = new Set([
  "approval_denied",
  "approval_unavailable",
  "audit_unavailable",
  "local_only",
  "no_eligible_provider",
  "token_budget_exceeded",
  "call_budget_exceeded",
]);

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function buildPlan(rb: Runbook, overrides: Readonly<Record<string, string>>, session: Session, registry: ToolRegistry): RunbookPlan {
  const params: Record<string, string> = { ...rb.params, ...overrides };
  const steps: RunbookPlanStep[] = rb.steps.map((st): RunbookPlanStep => {
    if (!st.tool) return { n: st.n, text: st.text, status: "manual" };
    const reg = registry.get(st.tool);
    if (st.tool.startsWith("runbook.") || reg?.def.descriptor.composite) {
      return { n: st.n, text: st.text, tool: st.tool, status: "not_allowed", problems: ["bir runbook adımı runbook/bileşik araç çağıramaz"] };
    }
    if (!reg) return { n: st.n, text: st.text, tool: st.tool, status: "unknown_tool", problems: [`araç kayıtlı değil: ${st.tool}`] };
    const d = reg.def.descriptor;
    const { args, missing } = substituteArgs(st.args ?? {}, params);
    const common = { n: st.n, text: st.text, tool: st.tool, args, class: d.class } as const;
    if (missing.length) return { ...common, status: "missing_param", problems: missing.map((m) => `parametre eksik: ${m} (runbook.plan params ile verin)`) };
    const parsed = reg.def.input.safeParse(args);
    if (!parsed.success) {
      return { ...common, status: "invalid_args", problems: parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".") || "(kök)"}: ${i.message}`) };
    }
    if (!session.activeToolsets.has(d.toolset)) return { ...common, status: "toolset_inactive", problems: [`araç seti '${d.toolset}' kapalı: önce ilgili skill'i skill.load ile yükleyin`] };
    if (d.profileKind !== null && !session.boundByKind(d.profileKind)) return { ...common, status: "profile_unbound", problems: [`'${d.profileKind}' profili bağlı değil`] };
    return { ...common, status: "ok" };
  });
  return { name: rb.name, title: rb.title, params, steps };
}

/**
 * `runbook.list|plan|run` (çekirdek araçlar; YALNIZ kullanıcının runbook'u varsa kaydedilir). Runbook YETKİ VERMEZ:
 * plan yalnız gösterilir; `runbook.run` yalnız `read` sınıfı araç adımlarını, `composite` iç çağrılarla ve HER adımı
 * tam PEP'ten geçirerek koşturur (politika, taint, denetim, çıktı hattı). Okuma dışı adımlar ASLA otomatik çalışmaz.
 */
export function createRunbookAdapter(
  runbooks: RunbookRegistry,
  session: Session,
  toolRegistry: () => ToolRegistry,
): { adapter: Adapter; definitions: ToolDefinition[] } {
  const definitions = [listTool, planTool, runTool];
  const manifest = AdapterManifestSchema.parse({
    id: "runbooks",
    version: "0.0.0",
    contract: ADAPTER_CONTRACT,
    kind: "cli",
    profileKinds: [],
    credentialKinds: [],
    capabilities: [],
    tools: definitions.map((d) => d.descriptor),
  });

  const need = (name: string): Runbook => {
    const rb = runbooks.get(name);
    if (!rb) throw new OpsError("runbook_not_found", `runbook bulunamadı: '${name.slice(0, 64)}'. Mevcut: ${runbooks.all().map((r) => r.name).join(", ") || "(yok)"}`);
    return rb;
  };

  const adapter: Adapter = {
    manifest,
    validateProfile: () => ["yerel adapter profil kullanmaz"],
    resolveTarget: (_t: string, _a: unknown, p: Profile): Target => ({ profileId: p.id, kind: p.kind, endpoint: p.targetPin.endpoint, scopes: [], refs: [] }),
    async invoke(call: AdapterCall): Promise<RawToolOutput> {
      if (call.tool === "runbook.list") {
        const all = runbooks.all();
        return {
          data: { runbooks: all.map((r) => ({ name: r.name, title: r.title, description: clip(r.description, 200), steps: r.steps.length, toolSteps: r.steps.filter((s) => s.tool).length })) },
          summary: `${all.length} runbook`,
        };
      }
      if (call.tool === "runbook.plan") {
        const a = call.args as { name: string; params?: Record<string, string> };
        const plan = buildPlan(need(a.name), a.params ?? {}, session, toolRegistry());
        const bad = plan.steps.filter((s) => s.status !== "ok" && s.status !== "manual").length;
        return { data: plan, summary: `plan '${plan.name}': ${plan.steps.length} adım${bad ? `, ${bad} sorunlu` : ""}` };
      }
      if (call.tool === "runbook.run") {
        const a = call.args as { name: string; params?: Record<string, string>; steps?: number[] };
        const nested = call.nested;
        if (!nested) throw new OpsError("nested_unavailable", "iç çağrı yeteneği yok (bileşik araç yalnız PEP üzerinden çalışır)");
        const plan = buildPlan(need(a.name), a.params ?? {}, session, toolRegistry());
        const selected = a.steps ? new Set(a.steps) : null;
        const rows: Record<string, unknown>[] = [];
        const manual: { n: number; text: string }[] = [];
        let executed = 0;
        let stoppedAt: number | undefined;
        for (const s of plan.steps) {
          if (selected && !selected.has(s.n)) continue;
          if (call.signal.aborted) {
            stoppedAt = s.n;
            break;
          }
          if (!s.tool) {
            manual.push({ n: s.n, text: clip(s.text, 160) });
            continue;
          }
          if (s.status !== "ok") {
            rows.push({ n: s.n, tool: s.tool, status: "skipped", reason: s.status });
            continue;
          }
          if (s.class !== "read") {
            rows.push({ n: s.n, tool: s.tool, status: "skipped", reason: "not_read", hint: "okuma dışı adım: normal onay akışıyla ayrıca çağrılmalı" });
            continue;
          }
          if (executed >= MAX_RUN_STEPS) {
            rows.push({ n: s.n, tool: s.tool, status: "skipped", reason: "step_limit" });
            continue;
          }
          executed += 1;
          const r = await nested({ tool: s.tool, args: s.args ?? {} });
          rows.push({
            n: s.n,
            tool: s.tool,
            status: r.status,
            ...(r.reasonCode ? { reason: r.reasonCode } : {}),
            ...(r.evidenceId ? { evidenceId: r.evidenceId } : {}),
            summary: clip(r.summary, 160),
            tokens: r.tokens.estimate,
            ...(r.byReference ? { byReference: true } : {}),
            // küçük VE güvenilir sonuçlar satır içi; diğerleri evidence.get ile dilimlenir (token ekonomisi + enjeksiyon yüzeyi)
            ...(r.status === "ok" && r.taint === "trusted" && !r.byReference && r.view !== undefined && r.tokens.estimate <= 250 ? { view: r.view } : {}),
          });
          if (r.status !== "ok" && r.reasonCode && STOP_CODES.has(r.reasonCode)) {
            stoppedAt = s.n;
            break;
          }
        }
        const ok = rows.filter((r) => r["status"] === "ok").length;
        const fail = rows.filter((r) => r["status"] === "denied" || r["status"] === "error").length;
        const skipped = rows.filter((r) => r["status"] === "skipped").length;
        return {
          data: { runbook: plan.name, executed, steps: rows, ...(manual.length ? { manual } : {}), ...(stoppedAt !== undefined ? { stoppedAt } : {}) },
          summary: `runbook '${plan.name}': ${executed} adım koştu (${ok} ok${fail ? `, ${fail} hata/ret` : ""})${skipped ? `, ${skipped} atlandı` : ""}${manual.length ? `, ${manual.length} elle` : ""}${stoppedAt !== undefined ? ` — ${stoppedAt}. adımda durdu` : ""}`,
        };
      }
      throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
    },
  };
  return { adapter, definitions };
}
