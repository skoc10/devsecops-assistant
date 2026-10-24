import { estimateTokens, runtimeIsSafe, zoneAllows } from "@ops/contracts";
import type { AgentRuntime, AuditSink, ToolBridge, ToolBridgeResult } from "@ops/contracts";
import type { PolicyEngine } from "@ops/policy";
import { scrubText } from "@ops/redaction";
import type { KnownSecrets } from "@ops/redaction";
import { verifyCitations } from "./citations.ts";
import type { EvidenceStore } from "./evidence.ts";
import { ToolExecutor } from "./executor.ts";
import { formatForModel } from "./format.ts";
import type { ToolGateway } from "./gateway.ts";
import { Ledger } from "./ledger.ts";
import type { OrchestratorEvent } from "./orchestrator.ts";
import { buildSystem } from "./prompt.ts";
import type { SkillCatalog } from "./prompt.ts";
import type { ToolRegistry } from "./registry.ts";
import type { ActiveSkill, Session } from "./session.ts";
import { UsageMeter } from "./usage.ts";

export interface RuntimeOrchestratorDeps {
  readonly runtime: AgentRuntime;
  readonly gateway: ToolGateway;
  readonly registry: ToolRegistry;
  readonly session: Session;
  readonly evidence: EvidenceStore;
  readonly policy: PolicyEngine;
  readonly audit: AuditSink;
  readonly known: KnownSecrets;
  readonly skills?: SkillCatalog;
  /**
   * Sağlayıcı döngülü çalışma zamanında araç listesi görev başında SABİTLENİR (SDK `Agent.create`).
   * Bu yüzden ilgili skill'ler görevden ÖNCE etkinleştirilir.
   */
  /** Görev başında (her `send`) etkinleştirilecek skill'ler; işlev verilirse o anki bağlı profillere göre hesaplanır. */
  readonly preloadSkills?: readonly ActiveSkill[] | (() => readonly ActiveSkill[]);
  readonly options?: { readonly maxCitationRetries?: number };
}

const ADVISORY_NOTE =
  "\n\nTAVSİYE KİPİ: bu oturumda araç çağıramazsın. Yalnız kullanıcıya verilen özetlerle (kanıt kimlikleri) yanıtla; araç çağırmayı deneme.";

/**
 * Orkestratör (`loopOwner: provider`): döngüyü Cursor gibi bir ajan çalışma zamanı yürütür; biz
 * ona yalnız PEP'e giden araç KÖPRÜSÜNÜ veririz. Çalışma zamanı güvenli doğrulanmadıysa
 * (`runtimeIsSafe` false) TAVSİYE KİPİ: araç yok, yalnız redakte defter özeti. Kural ve denetimler
 * host döngüsüyle aynıdır: egress, write-ahead model_call, bütçe, atıf doğrulaması, alarm.
 */
export class RuntimeOrchestrator {
  readonly meter = new UsageMeter();
  readonly ledger = new Ledger();
  private readonly d: RuntimeOrchestratorDeps;
  private disabled: string | undefined;

  constructor(deps: RuntimeOrchestratorDeps) {
    this.d = deps;
  }

  get mode(): "tools" | "advisory" {
    return runtimeIsSafe(this.d.runtime.capabilities) ? "tools" : "advisory";
  }

  async *send(userText: string, signal?: AbortSignal): AsyncGenerator<OrchestratorEvent> {
    const { runtime, session, policy, audit, evidence, known, registry } = this.d;
    const zone = runtime.capabilities.trustZone;
    const maxCite = this.d.options?.maxCitationRetries ?? 1;
    if (this.disabled) {
      yield { type: "error", code: "runtime_disabled", message: `bu oturumda sağlayıcı devre dışı: ${this.disabled}` };
      return;
    }

    const text = scrubText(userText, known);
    if (text !== userText) {
      yield { type: "warning", code: "user_input_redacted", message: "Mesajınızda secret benzeri bir değer vardı; maskelenerek gönderildi. Secret'ları sohbete yapıştırmayın." };
    }
    this.ledger.noteGoal(text);
    if (this.mode === "advisory") {
      yield { type: "warning", code: "advisory_mode", message: "Çalışma zamanı güvenli doğrulanmadı (ADR-0004): TAVSİYE KİPİ — araç çağrısı yok, yalnız redakte özetler paylaşılır" };
    } else {
      const pre = typeof this.d.preloadSkills === "function" ? this.d.preloadSkills() : (this.d.preloadSkills ?? []);
      for (const s of pre) if (!session.activeSkills.has(s.name)) session.activateSkill(s);
    }

    const executor = new ToolExecutor({
      gateway: this.d.gateway,
      registry,
      session,
      audit,
      provider: { id: runtime.id, model: runtime.model },
      zone,
    });

    let prompt = text;
    let toolCallsThisSend = 0;
    for (let attempt = 0; ; attempt++) {
      const budget = policy.checkBudget({ toolCalls: session.usage.toolCalls, sessionTokens: session.usage.sessionTokens });
      if (!budget.ok) {
        yield { type: "error", code: budget.reason, message: "oturum bütçesi aşıldı; yeni oturum başlatın" };
        return;
      }
      if (!zoneAllows(zone, session.context.zoneCap)) {
        await audit.append({ event: "model_call", sessionId: session.id, provider: runtime.id, model: runtime.model, trustZone: zone, decision: "deny", reasonCode: "no_eligible_provider", message: "egress reddedildi" }).catch(() => undefined);
        yield { type: "error", code: "no_eligible_provider", message: `bağlam hassas veri içeriyor: sağlayıcı bölgesi '${zone}', verinin gidebileceği en uzak bölge '${session.context.zoneCap}'` };
        return;
      }

      const advisory = this.mode === "advisory";
      const system = buildSystem({ skills: this.d.skills?.metadata() ?? [], profiles: session.boundProfiles(), active: [...session.activeSkills.values()] }) + (advisory ? ADVISORY_NOTE : "");
      const ledgerSummary = this.ledger.all().length > 0 ? this.ledger.summarize(1_200) : undefined;
      const pending: OrchestratorEvent[] = [];
      let n = 0;
      const bridge: ToolBridge = {
        specs: () => (advisory ? [] : registry.specsFor(session.activeToolsets)),
        invoke: async (name, args): Promise<ToolBridgeResult> => {
          if (advisory) return { text: "REDDEDİLDİ [unknown_tool]: tavsiye kipinde araç yok", isError: true };
          const id = `rt-${++n}`;
          pending.push({ type: "tool_call", id, name, args });
          const r = await executor.execute({ id, name, args }, signal);
          toolCallsThisSend += 1;
          this.meter.addTool(name, r.byReference ? 0 : r.tokens.estimate, r.evidenceId);
          if (r.evidenceId) {
            const e = evidence.get(r.evidenceId);
            if (e) this.ledger.noteEvidence({ id: e.id, tool: e.tool, summary: e.summary, subjects: e.subjects });
          }
          pending.push({
            type: "tool_result", id, name, status: r.status, summary: r.summary, ...(r.evidenceId ? { evidenceId: r.evidenceId } : {}),
            tokens: r.tokens.estimate, byReference: r.byReference, ...(r.reasonCode ? { reasonCode: r.reasonCode } : {}),
          });
          return { text: formatForModel(r), isError: r.status !== "ok" };
        },
      };

      try {
        await audit.append({ event: "model_call", sessionId: session.id, provider: runtime.id, model: runtime.model, trustZone: zone, message: `request mode=${advisory ? "advisory" : "tools"} tools=${bridge.specs().length} systemTokens=${estimateTokens(system)}` });
      } catch {
        yield { type: "error", code: "audit_unavailable", message: "denetim kaydı yazılamadı; çalışma zamanı çağrılmadı" };
        return;
      }

      let answer = "";
      let alarm: { code: string; detail: string } | undefined;
      try {
        for await (const ev of runtime.runTask({ system, prompt, ...(ledgerSummary ? { ledgerSummary } : {}) }, bridge, signal)) {
          for (const p of pending.splice(0)) yield p;
          if (ev.type === "text") answer += ev.text;
          else if (ev.type === "usage") {
            this.meter.addModel(ev.usage);
            session.addModelUsage(ev.usage);
            await audit.append({ event: "model_call", sessionId: session.id, provider: runtime.id, model: runtime.model, trustZone: zone, tokens: { input: ev.usage.inputTokens, output: ev.usage.outputTokens, cacheRead: ev.usage.cacheReadTokens }, message: "response" }).catch(() => undefined);
            yield { type: "usage", inputTokens: ev.usage.inputTokens, outputTokens: ev.usage.outputTokens, cacheReadTokens: ev.usage.cacheReadTokens, sessionTokens: session.usage.sessionTokens };
          } else if (ev.type === "alarm") {
            alarm = { code: ev.code, detail: ev.detail };
            this.disabled = ev.code;
            session.noteResult({ sensitivity: "none", tainted: true });
            await audit.append({ event: "alarm", sessionId: session.id, provider: runtime.id, model: runtime.model, message: `${ev.code}: ${ev.detail}`.slice(0, 400) }).catch(() => undefined);
            yield { type: "warning", code: `alarm:${ev.code}`, message: `sağlayıcı alarmı: ${ev.code} — oturum 'tainted', sağlayıcı bu oturumda devre dışı` };
          }
        }
        for (const p of pending.splice(0)) yield p;
      } catch (e) {
        yield { type: "error", code: "provider_error", message: scrubText(e instanceof Error ? e.message : String(e), known) };
        return;
      }
      if (alarm) {
        yield { type: "error", code: "runtime_alarm", message: `${alarm.code}: çalışma zamanı durduruldu` };
        return;
      }

      const check = verifyCitations(answer, evidence);
      if (check.invalid.length > 0 && attempt < maxCite) {
        const valid = evidence.all().map((e) => e.id).join(", ") || "(yok)";
        prompt = `Önceki cevabında bulunmayan kanıt kimlikleri vardı: ${check.invalid.join(", ")}. Yalnız şu kimlikleri kullan: ${valid}. Cevabı düzelt. Asıl soru: ${text}`;
        yield { type: "warning", code: "citation_invalid", message: `geçersiz kanıt kimliği: ${check.invalid.join(", ")} — çalışma zamanı düzeltmeye yönlendirildi` };
        continue;
      }
      let finalText = answer;
      if (check.invalid.length > 0) finalText += `\n\n⚠ Doğrulanamayan kanıt kimlikleri: ${check.invalid.join(", ")}`;
      else if (check.cited.length === 0 && toolCallsThisSend > 0) finalText += "\n\n⚠ Bu cevap kanıt kimliği içermiyor.";
      this.ledger.noteConclusion(answer);
      yield { type: "final", text: finalText, citations: check, toolCalls: toolCallsThisSend };
      return;
    }
  }
}
