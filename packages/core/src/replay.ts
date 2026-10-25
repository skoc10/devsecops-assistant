import { riskAtLeast } from "@ops/contracts";
import type { AuditRecord, PolicyDecision, Profile, RiskClass, ToolDescriptor } from "@ops/contracts";
import type { PolicyInput } from "@ops/policy";
import { stripControlChars } from "@ops/redaction";

/**
 * Olay sonrası inceleme ve politika regresyonu (tasarım §3.8 "replay"): denetim kaydından oturumu yeniden kurar.
 * ARAÇLAR YENİDEN ÇAĞRILMAZ, model çağrılmaz, kimlik bağlanmaz: yalnız KAYITLI olaylar okunur.
 *
 * Sınır (dürüst): denetim modelin metnini ve kullanıcı iletilerini SAKLAMAZ; bu yüzden konuşma değil, eylem
 * zaman çizelgesi yeniden kurulur. `--policy` modu her kayıtlı politika kararını aday politikayla yeniden
 * değerlendirir (hangi kararlar gevşer/sıkılaşır); araç sonuçlarını yeniden üretmez.
 */

export type ReplayKind = "session" | "model" | "intent" | "approval" | "result" | "lease" | "alarm" | "break_glass" | "policy_change" | "evidence_release";

export interface ReplayEvent {
  readonly seq: number;
  readonly ts: string;
  readonly kind: ReplayKind;
  readonly callId?: string;
  readonly line: string;
  /** Ayrıntılı kipte gösterilen gürültülü kayıtlar (lease, model isteği). */
  readonly noisy?: boolean;
}

export interface ReplayAnomaly {
  readonly code: "result_without_intent" | "intent_without_result" | "ask_ran_without_approval" | "non_read_in_local_only" | "prod_allow_without_approval";
  readonly severity: "high" | "info";
  readonly seq: number;
  readonly message: string;
}

export interface WhatIfChange {
  readonly seq: number;
  readonly tool: string;
  readonly profile?: string;
  readonly environment?: string;
  readonly recorded: { readonly effect: string; readonly reasonCode?: string };
  readonly candidate: { readonly effect: PolicyDecision["effect"]; readonly reasonCode: string };
  /** `looser`: aday politika kaydedilenden daha az kısıtlayıcı (riskli yön). */
  readonly direction: "looser" | "stricter" | "reason_only";
}

export interface WhatIfDeps {
  readonly policyHash: string;
  decide(input: PolicyInput, at: Date): PolicyDecision;
  tool(name: string): ToolDescriptor | undefined;
  profile(id: string): Profile | undefined;
}

export interface ReplayStats {
  readonly calls: number;
  readonly byDecision: Readonly<Record<string, number>>;
  readonly deniedByReason: Readonly<Record<string, number>>;
  readonly approvals: { readonly allow: number; readonly deny: number };
  readonly modelCalls: number;
  readonly tokens: { readonly input: number; readonly output: number; readonly cacheRead: number };
  readonly tools: readonly { readonly tool: string; readonly count: number }[];
  readonly breakGlass: number;
}

export interface ReplayReport {
  readonly sessionId: string;
  readonly records: number;
  readonly start?: string;
  readonly end?: string;
  readonly header: { readonly start?: string };
  readonly timeline: readonly ReplayEvent[];
  readonly stats: ReplayStats;
  readonly anomalies: readonly ReplayAnomaly[];
  readonly whatIf?: {
    readonly policyHash: string;
    readonly compared: number;
    readonly changed: readonly WhatIfChange[];
    readonly skipped: readonly { readonly seq: number; readonly why: string }[];
  };
}

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const argsLine = (a: unknown): string => {
  if (a === undefined) return "";
  try {
    return clip(JSON.stringify(a), 120);
  } catch {
    return "";
  }
};
const inc = (m: Record<string, number>, k: string): void => {
  m[k] = (m[k] ?? 0) + 1;
};

// Yalnız EYLEM kayıtları "etkinlik" sayılır: `ops policy allow` gibi yönetim komutlarının tek-kayıtlık oturumları hedef seçilmez
const ACTIVITY: ReadonlySet<string> = new Set(["intent", "result", "model_call", "approval"]);

/**
 * Son oturumun kimliği (kayıtlar `seq` sırasıyla). `activeOnly`: yalnız yaşam döngüsü kaydı olan oturumlar
 * (ör. `ops replay` / `ops audit verify` çalıştırmalarının kendi oturumları) atlanır.
 */
export function lastSessionId(records: readonly AuditRecord[], activeOnly = false): string | undefined {
  for (let i = records.length - 1; i >= 0; i--) {
    const r = records[i] as AuditRecord;
    if (!activeOnly || ACTIVITY.has(r.event)) return r.sessionId;
  }
  return undefined;
}

export function buildReplay(all: readonly AuditRecord[], opts: { sessionId?: string; whatIf?: WhatIfDeps } = {}): ReplayReport {
  const sessionId = opts.sessionId ?? lastSessionId(all, true) ?? "";
  const recs = all.filter((r) => r.sessionId === sessionId).sort((a, b) => a.seq - b.seq);

  const timeline: ReplayEvent[] = [];
  const byDecision: Record<string, number> = {};
  const deniedByReason: Record<string, number> = {};
  const toolCount = new Map<string, number>();
  const approvals = { allow: 0, deny: 0 };
  const tokens = { input: 0, output: 0, cacheRead: 0 };
  let modelCalls = 0;
  let breakGlass = 0;
  let calls = 0;
  let localOnly = false;
  const counted = new Set<string>();

  const push = (r: AuditRecord, kind: ReplayKind, line: string, noisy = false): void => {
    // denetim alanları (ör. model seçimi bilinmeyen araç adı) kontrol/ANSI karakteri taşıyabilir: çizelge satırı terminale güvenle basılır
    timeline.push({ seq: r.seq, ts: r.ts, kind, ...(r.callId ? { callId: r.callId } : {}), line: stripControlChars(line), ...(noisy ? { noisy: true } : {}) });
  };

  for (const r of recs) {
    switch (r.event) {
      case "session_start":
        localOnly = (r.message ?? "").includes("egress=local-only");
        push(r, "session", `oturum başladı — ${clip(r.message ?? "", 220)}`);
        break;
      case "session_end":
        push(r, "session", `oturum bitti — ${clip(r.message ?? "", 120)}`);
        break;
      case "model_call": {
        const who = `${r.provider ?? "?"}/${r.model ?? "?"}${r.trustZone ? ` [${r.trustZone}]` : ""}`;
        const quarantine = (r.message ?? "").startsWith("quarantine");
        if (r.decision === "deny") {
          push(r, "model", `model çağrısı REDDEDİLDİ [${r.reasonCode ?? "?"}] ${who}`);
        } else if (r.tokens) {
          modelCalls += 1;
          tokens.input += r.tokens.input;
          tokens.output += r.tokens.output;
          tokens.cacheRead += r.tokens.cacheRead;
          push(r, "model", `${quarantine ? "karantina özetleyici" : "model"} ${who}: ${r.tokens.input}→${r.tokens.output} tok${r.tokens.cacheRead ? ` (önbellek ${r.tokens.cacheRead})` : ""}`);
        } else {
          push(r, "model", `${quarantine ? "karantina özetleyici" : "model"} isteği ${who}: ${clip(r.message ?? "", 100)}`, true);
        }
        break;
      }
      case "intent": {
        // aynı çağrının hem intent'i hem (onaydan sonra) reddedilen sonucu olabilir (ör. target_changed): çağrı BİR kez sayılır
        if (!(r.callId && counted.has(r.callId))) {
          calls += 1;
          if (r.tool) toolCount.set(r.tool, (toolCount.get(r.tool) ?? 0) + 1);
          inc(byDecision, r.decision ?? "?");
          if (r.callId) counted.add(r.callId);
        }
        push(
          r,
          "intent",
          `→ ${r.tool ?? "?"} [${r.class ?? "?"}]${r.profile ? ` ${r.profile}/${r.environment ?? "?"}` : ""} karar=${r.decision ?? "?"}(${r.reasonCode ?? "?"})${r.breakGlass ? " [break-glass]" : ""} ${argsLine(r.argsRedacted)}`,
        );
        break;
      }
      case "approval":
        if (r.decision === "allow") approvals.allow += 1;
        else approvals.deny += 1;
        push(r, "approval", `onay ${r.decision === "allow" ? "VERİLDİ" : "REDDEDİLDİ"} (${r.tool ?? "?"}): ${clip(r.message ?? "", 120)}`);
        break;
      case "result": {
        if (r.exitStatus === "denied") {
          if (!(r.callId && counted.has(r.callId))) {
            calls += 1;
            if (r.tool) toolCount.set(r.tool, (toolCount.get(r.tool) ?? 0) + 1);
            inc(byDecision, "deny");
            if (r.callId) counted.add(r.callId);
          } else {
            // intent'i sayılmış çağrı sonradan reddedildi: karar dağılımında intent kararı yerine 'deny' say
            const prev = recs.find((x) => x.event === "intent" && x.callId === r.callId)?.decision;
            if (prev && (byDecision[prev] ?? 0) > 0) byDecision[prev] = (byDecision[prev] as number) - 1;
            inc(byDecision, "deny");
          }
          inc(deniedByReason, r.reasonCode ?? "?");
          push(r, "result", `✗ ${r.tool ?? "?"} REDDEDİLDİ [${r.reasonCode ?? "?"}] ${clip(r.message ?? "", 140)}`);
        } else if (r.exitStatus === "error") {
          push(r, "result", `✗ ${r.tool ?? "?"} HATA [${r.reasonCode ?? "?"}] ${clip(r.message ?? "", 140)}`);
        } else {
          const red = Object.values(r.redactionCounts ?? {}).reduce((a, b) => a + b, 0);
          push(r, "result", `  ✓ ${r.tool ?? "?"} modele ${r.outputBytesToModel ?? 0} bayt${red ? `, ${red} redaksiyon` : ""}${r.message ? ` (${clip(r.message, 60)})` : ""}`);
        }
        break;
      }
      case "lease":
        push(r, "lease", `kimlik: ${clip(r.message ?? "", 100)}${r.profile ? ` (${r.profile})` : ""}`, true);
        break;
      case "alarm":
        push(r, "alarm", `ALARM: ${clip(r.message ?? "", 160)}`);
        break;
      case "break_glass":
        breakGlass += 1;
        push(r, "break_glass", `BREAK-GLASS: ${clip(r.message ?? "", 160)}${r.profile ? ` (${r.profile})` : ""}`);
        break;
      case "policy_change":
        push(r, "policy_change", `politika değişti: ${clip(r.message ?? "", 140)}`);
        break;
      case "evidence_release":
        push(r, "evidence_release", `karantina açıldı: ${clip(r.message ?? "", 140)}`);
        break;
    }
  }

  // ---- tutarlılık denetimleri (deterministik) ----
  const anomalies: ReplayAnomaly[] = [];
  const byCall = new Map<string, AuditRecord[]>();
  for (const r of recs) if (r.callId) byCall.set(r.callId, [...(byCall.get(r.callId) ?? []), r]);
  for (const rs of byCall.values()) {
    const intent = rs.find((x) => x.event === "intent");
    const result = rs.find((x) => x.event === "result" && x.exitStatus !== "denied" && x.exitStatus !== "error") ?? rs.find((x) => x.event === "result");
    const ran = result?.exitStatus === "ok";
    const approved = rs.some((x) => x.event === "approval" && x.decision === "allow");
    if (ran && !intent && result) {
      anomalies.push({ code: "result_without_intent", severity: "high", seq: result.seq, message: `${result.tool ?? "?"}: sonuç var ama write-ahead intent kaydı yok` });
    }
    if (intent && !result) {
      anomalies.push({ code: "intent_without_result", severity: "info", seq: intent.seq, message: `${intent.tool ?? "?"}: intent var, sonuç kaydı yok (süreç yarıda kesildi veya çağrı çalışmadı)` });
    }
    if (intent && ran && intent.decision === "ask" && !approved) {
      anomalies.push({ code: "ask_ran_without_approval", severity: "high", seq: intent.seq, message: `${intent.tool ?? "?"}: karar 'ask' idi ama onay kaydı olmadan çalıştı` });
    }
    if (intent && localOnly && intent.class && intent.class !== "read") {
      anomalies.push({ code: "non_read_in_local_only", severity: "high", seq: intent.seq, message: `${intent.tool ?? "?"} [${intent.class}]: local-only kipinde okuma dışı sınıf` });
    }
    if (intent && ran && intent.environment === "prod" && intent.class && riskAtLeast(intent.class, "mutate") && intent.decision === "allow") {
      anomalies.push({ code: "prod_allow_without_approval", severity: "high", seq: intent.seq, message: `${intent.tool ?? "?"} [${intent.class}] prod'da onaysız izin verilmiş` });
    }
  }
  anomalies.sort((a, b) => a.seq - b.seq);

  // ---- politika what-if ----
  let whatIf: ReplayReport["whatIf"];
  if (opts.whatIf) {
    const w = opts.whatIf;
    const changed: WhatIfChange[] = [];
    const skipped: { seq: number; why: string }[] = [];
    let compared = 0;
    for (const r of recs) {
      const dc = r.decisionContext;
      const decidedHere = r.event === "intent" || (r.event === "result" && r.decision === "deny");
      if (!dc || !decidedHere || !r.tool) continue;
      const tool = w.tool(r.tool);
      if (!tool) {
        skipped.push({ seq: r.seq, why: `araç artık kayıtlı değil: ${r.tool}` });
        continue;
      }
      let profile: Profile | null = null;
      if (r.profile) {
        const p = w.profile(r.profile);
        if (!p) {
          skipped.push({ seq: r.seq, why: `profil artık kayıtlı değil: ${r.profile}` });
          continue;
        }
        profile = { ...p, ...(dc.ceiling ? { classCeiling: dc.ceiling } : {}), ...(r.environment ? { environment: r.environment } : {}) };
      }
      const cls: RiskClass = r.class ?? "read";
      const decision = w.decide(
        {
          tool,
          effectiveClass: cls,
          unclassified: dc.unclassified,
          profile,
          target: profile ? { profileId: profile.id, kind: profile.kind, endpoint: "-", scopes: [...dc.scopes], refs: [] } : null,
          context: { tainted: dc.tainted, profilesTouched: [...dc.profilesTouched], maxSensitivity: dc.maxSensitivity, zoneCap: "third-party-cloud" },
          effectiveSensitivity: dc.sensitivity,
        },
        new Date(r.ts),
      );
      compared += 1;
      const recordedEffect = r.event === "intent" ? (r.decision ?? "?") : "deny";
      const rank: Record<string, number> = { allow: 0, ask: 1, deny: 2 };
      const sameEffect = recordedEffect === decision.effect;
      if (sameEffect && (r.reasonCode ?? "") === decision.reasonCode) continue;
      changed.push({
        seq: r.seq,
        tool: r.tool,
        ...(r.profile ? { profile: r.profile } : {}),
        ...(r.environment ? { environment: r.environment } : {}),
        recorded: { effect: recordedEffect, ...(r.reasonCode ? { reasonCode: r.reasonCode } : {}) },
        candidate: { effect: decision.effect, reasonCode: decision.reasonCode },
        direction: sameEffect ? "reason_only" : (rank[decision.effect] ?? 0) < (rank[recordedEffect] ?? 0) ? "looser" : "stricter",
      });
    }
    whatIf = { policyHash: w.policyHash, compared, changed, skipped };
  }

  const stats: ReplayStats = {
    calls,
    byDecision,
    deniedByReason,
    approvals,
    modelCalls,
    tokens,
    tools: [...toolCount].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 10).map(([tool, count]) => ({ tool, count })),
    breakGlass,
  };
  return {
    sessionId,
    records: recs.length,
    ...(recs[0] ? { start: recs[0].ts } : {}),
    ...(recs.length ? { end: recs[recs.length - 1]?.ts as string } : {}),
    header: { ...(recs[0] ? { start: recs[0].ts } : {}) },
    timeline,
    stats,
    anomalies,
    ...(whatIf ? { whatIf } : {}),
  };
}

export function renderReplay(rep: ReplayReport, opts: { verbose?: boolean; chain?: string } = {}): string {
  const out: string[] = [];
  out.push(`Oturum ${rep.sessionId || "(yok)"} — ${rep.records} kayıt${rep.start ? `, ${rep.start} → ${rep.end ?? "?"}` : ""}`);
  if (opts.chain) out.push(`Denetim zinciri: ${opts.chain}`);
  out.push("(Araçlar yeniden ÇAĞRILMADI, model çağrılmadı: yalnız kayıtlı olaylar okundu; modelin metni denetimde tutulmaz.)");
  out.push("", "── Zaman çizelgesi ──");
  for (const e of rep.timeline) if (opts.verbose || !e.noisy) out.push(`${e.seq.toString().padStart(4)} ${e.ts.slice(11, 19)} ${e.line}`);
  const s = rep.stats;
  out.push("", "── Özet ──");
  out.push(`çağrı ${s.calls} (${Object.entries(s.byDecision).map(([k, v]) => `${k}:${v}`).join(" ") || "-"}); onay ${s.approvals.allow} verildi/${s.approvals.deny} reddedildi; model turu ${s.modelCalls} (${s.tokens.input}→${s.tokens.output} tok, önbellek ${s.tokens.cacheRead}); break-glass ${s.breakGlass}`);
  if (Object.keys(s.deniedByReason).length) out.push(`ret sebepleri: ${Object.entries(s.deniedByReason).map(([k, v]) => `${k}:${v}`).join(" ")}`);
  if (s.tools.length) out.push(`araçlar: ${s.tools.map((t) => `${t.tool}×${t.count}`).join(", ")}`);
  out.push("", "── Tutarlılık denetimleri ──");
  if (rep.anomalies.length === 0) out.push("sorun yok");
  for (const a of rep.anomalies) out.push(`${a.severity === "high" ? "‼" : "i"} [${a.code}] seq ${a.seq}: ${a.message}`);
  if (rep.whatIf) {
    const w = rep.whatIf;
    out.push("", `── Politika what-if (aday politika ${w.policyHash.slice(0, 12)}) ──`);
    out.push(`${w.compared} karar yeniden değerlendirildi; ${w.changed.length} değişti${w.skipped.length ? `, ${w.skipped.length} atlandı` : ""}`);
    for (const c of w.changed) {
      const mark = c.direction === "looser" ? "⚠ GEVŞER" : c.direction === "stricter" ? "▲ sıkılaşır" : "≈ gerekçe";
      out.push(`${mark} seq ${c.seq} ${c.tool}${c.profile ? ` ${c.profile}/${c.environment ?? "?"}` : ""}: ${c.recorded.effect}(${c.recorded.reasonCode ?? "?"}) → ${c.candidate.effect}(${c.candidate.reasonCode})`);
    }
    for (const k of w.skipped.slice(0, 10)) out.push(`  atlandı seq ${k.seq}: ${k.why}`);
  }
  // tüm çıktı (araç adları, kimlikler dahil) terminale basılmadan önce kontrol/ANSI karakterlerinden arındırılır (satır sonları korunur)
  return out.map((l) => stripControlChars(l)).join("\n");
}
