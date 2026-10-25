import { estimateTokens, zoneAllows } from "@ops/contracts";
import type { AuditSink, Message, ModelProvider, ToolCall, ToolResult, TrustZone } from "@ops/contracts";
import type { PolicyEngine } from "@ops/policy";
import { scrubText } from "@ops/redaction";
import type { KnownSecrets } from "@ops/redaction";
import { verifyCitations } from "./citations.ts";
import { ToolExecutor } from "./executor.ts";
import type { CitationCheck } from "./citations.ts";
import type { EvidenceStore } from "./evidence.ts";
import { formatForModel } from "./format.ts";
import type { ToolGateway } from "./gateway.ts";
import { DEFAULT_COMPACT, Ledger, compactMessages } from "./ledger.ts";
import type { CompactOptions } from "./ledger.ts";
import { buildSystem } from "./prompt.ts";
import type { SkillCatalog } from "./prompt.ts";
import type { ToolRegistry } from "./registry.ts";
import type { Session } from "./session.ts";
import { UsageMeter } from "./usage.ts";

export type OrchestratorEvent =
  | { readonly type: "tool_call"; readonly id: string; readonly name: string; readonly args: unknown }
  | {
      readonly type: "tool_result";
      readonly id: string;
      readonly name: string;
      readonly status: ToolResult["status"];
      readonly summary: string;
      readonly evidenceId?: string;
      readonly tokens: number;
      readonly byReference: boolean;
      readonly reasonCode?: string;
    }
  | { readonly type: "usage"; readonly inputTokens: number; readonly outputTokens: number; readonly cacheReadTokens: number; readonly sessionTokens: number }
  | { readonly type: "warning"; readonly code: string; readonly message: string }
  | { readonly type: "text"; readonly text: string }
  | { readonly type: "final"; readonly text: string; readonly citations: CitationCheck; readonly toolCalls: number }
  | { readonly type: "error"; readonly code: string; readonly message: string };

export interface OrchestratorDeps {
  readonly provider: ModelProvider;
  readonly gateway: ToolGateway;
  readonly registry: ToolRegistry;
  readonly session: Session;
  readonly evidence: EvidenceStore;
  readonly policy: PolicyEngine;
  readonly audit: AuditSink;
  readonly known: KnownSecrets;
  readonly skills?: SkillCatalog;
  readonly options?: {
    /** Bir kullanıcı mesajı başına en çok model turu. */
    readonly maxIterations?: number;
    /** Geçersiz kanıt kimliği için düzeltme isteği sayısı. */
    readonly maxCitationRetries?: number;
    readonly compact?: Partial<CompactOptions>;
  };
}

/**
 * Orkestratör (`loopOwner: host`): modelden yalnız ARAÇ ÇAĞRISI ÖNERİSİ alır, çalıştırmaz; her
 * çağrı PEP'ten (ToolGateway) geçer. Sorumlulukları: sistem istemi/araç seti kurulumu (tembel
 * skill + deterministik sıra), kullanıcı girdisi redaksiyonu, egress denetimi, model çağrısı
 * denetimi (write-ahead), paralel okuma, defterle sıkıştırma, kanıt atıf doğrulaması, bütçeler.
 */
export class Orchestrator {
  readonly meter = new UsageMeter();
  readonly ledger = new Ledger();
  private messages: Message[] = [];
  private readonly d: OrchestratorDeps;

  constructor(deps: OrchestratorDeps) {
    this.d = deps;
  }

  private executor(zone: TrustZone): ToolExecutor {
    return new ToolExecutor({
      gateway: this.d.gateway,
      registry: this.d.registry,
      session: this.d.session,
      audit: this.d.audit,
      provider: { id: this.d.provider.id, model: this.d.provider.model },
      zone,
    });
  }

  get history(): readonly Message[] {
    return this.messages;
  }

  async *send(userText: string, signal?: AbortSignal): AsyncGenerator<OrchestratorEvent> {
    const { provider, session, policy, audit, evidence, known, registry } = this.d;
    const opts = this.d.options ?? {};
    const maxIter = opts.maxIterations ?? 12;
    const maxCite = opts.maxCitationRetries ?? 1;
    const zone: TrustZone = provider.capabilities.trustZone;

    // Kullanıcı girdisi de M2/M3'ten geçer: yapıştırılan token modele/denetime gitmez.
    const text = scrubText(userText, known);
    if (text !== userText) {
      yield { type: "warning", code: "user_input_redacted", message: "Mesajınızda secret benzeri bir değer vardı; maskelenerek gönderildi. Secret'ları sohbete yapıştırmayın." };
    }
    this.ledger.noteGoal(text);
    this.messages.push({ role: "user", content: text });

    let citationRetries = 0;
    let iterations = 0;
    let toolCallsThisSend = 0;
    let softWarned = false;

    while (true) {
      if (signal?.aborted) {
        yield { type: "error", code: "aborted", message: "iptal edildi" };
        return;
      }
      if (iterations++ >= maxIter) {
        yield { type: "error", code: "iteration_limit", message: `bir mesaj için en çok ${maxIter} model turu` };
        return;
      }
      const budget = policy.checkBudget({ toolCalls: session.usage.toolCalls, sessionTokens: session.usage.sessionTokens });
      if (!budget.ok) {
        yield { type: "error", code: budget.reason, message: "oturum bütçesi aşıldı; yeni oturum başlatın" };
        return;
      }
      if (budget.soft && !softWarned) {
        softWarned = true;
        yield { type: "warning", code: "budget_soft", message: "oturum token bütçesinin yumuşak eşiğine ulaşıldı" };
      }

      // Egress: bağlam bu sağlayıcıya gidemiyorsa model çağrılmaz (fail-closed).
      if (!zoneAllows(zone, session.context.zoneCap)) {
        const msg = `bağlam hassas veri içeriyor: sağlayıcı bölgesi '${zone}', verinin gidebileceği en uzak bölge '${session.context.zoneCap}'. Yerel sağlayıcı kullanın veya temiz bir oturum başlatın`;
        await audit.append({ event: "model_call", sessionId: session.id, provider: provider.id, model: provider.model, trustZone: zone, decision: "deny", reasonCode: "no_eligible_provider", message: "egress reddedildi" }).catch(() => undefined);
        yield { type: "error", code: "no_eligible_provider", message: msg };
        return;
      }

      const comp = compactMessages(this.messages, this.ledger, { ...DEFAULT_COMPACT, ...(opts.compact ?? {}) });
      if (comp.compacted) {
        this.messages = comp.messages;
        yield { type: "warning", code: "context_compacted", message: "eski turlar defter özetiyle değiştirildi" };
      }
      const system = buildSystem({
        skills: this.d.skills?.metadata() ?? [],
        profiles: session.boundProfiles(),
        active: [...session.activeSkills.values()],
      });
      const tools = registry.specsFor(session.activeToolsets);

      try {
        await audit.append({
          event: "model_call",
          sessionId: session.id,
          provider: provider.id,
          model: provider.model,
          trustZone: zone,
          message: `request messages=${this.messages.length} tools=${tools.length} systemTokens=${estimateTokens(system)}`,
        });
      } catch {
        yield { type: "error", code: "audit_unavailable", message: "denetim kaydı yazılamadı; model çağrılmadı" };
        return;
      }

      let res;
      try {
        res = await provider.generate({ system, messages: [...this.messages], tools, ...(signal ? { signal } : {}) });
      } catch (e) {
        yield { type: "error", code: "provider_error", message: scrubText(e instanceof Error ? e.message : String(e), known) };
        return;
      }
      this.meter.addModel(res.usage);
      session.addModelUsage(res.usage);
      try {
        await audit.append({
          event: "model_call",
          sessionId: session.id,
          provider: provider.id,
          model: provider.model,
          trustZone: zone,
          tokens: { input: res.usage.inputTokens, output: res.usage.outputTokens, cacheRead: res.usage.cacheReadTokens },
          message: `response stop=${res.stopReason} toolCalls=${res.message.toolCalls.length}`,
        });
      } catch {
        yield { type: "error", code: "audit_unavailable", message: "denetim kaydı yazılamadı" };
        return;
      }
      yield {
        type: "usage",
        inputTokens: res.usage.inputTokens,
        outputTokens: res.usage.outputTokens,
        cacheReadTokens: res.usage.cacheReadTokens,
        sessionTokens: session.usage.sessionTokens,
      };
      if (res.stopReason === "error") {
        yield { type: "error", code: "provider_error", message: "sağlayıcı hata ile döndü" };
        return;
      }

      const { content, toolCalls } = res.message;
      this.messages.push({ role: "assistant", content, toolCalls, ...(res.message.providerData !== undefined ? { providerData: res.message.providerData } : {}) });

      if (toolCalls.length === 0) {
        // "Kanıt yoksa iddia yok": atıf doğrulaması
        const check = verifyCitations(content, evidence);
        if (check.invalid.length > 0 && citationRetries < maxCite) {
          citationRetries += 1;
          const valid = evidence.all().map((e) => e.id).join(", ") || "(yok)";
          this.messages.push({ role: "user", content: `Cevabında bulunmayan kanıt kimlikleri var: ${check.invalid.join(", ")}. Yalnız şu kimlikleri kullan: ${valid}. Cevabı düzelt.` });
          yield { type: "warning", code: "citation_invalid", message: `geçersiz kanıt kimliği: ${check.invalid.join(", ")} — model düzeltmeye yönlendirildi` };
          continue;
        }
        let finalText = content;
        if (check.invalid.length > 0) finalText += `\n\n⚠ Doğrulanamayan kanıt kimlikleri: ${check.invalid.join(", ")}`;
        else if (check.cited.length === 0 && toolCallsThisSend > 0) finalText += "\n\n⚠ Bu cevap kanıt kimliği içermiyor.";
        this.ledger.noteConclusion(content);
        yield { type: "final", text: finalText, citations: check, toolCalls: toolCallsThisSend };
        return;
      }
      if (content) yield { type: "text", text: content };

      // Araç çağrıları: hepsi okuma ise paralel (tek birleşik kanıt görünümü), değilse sırayla.
      for (const c of toolCalls) yield { type: "tool_call", id: c.id, name: c.name, args: c.args };
      const allRead = toolCalls.every((c) => registry.get(c.name)?.def.descriptor.class === "read");
      let results: ToolResult[];
      if (allRead) {
        results = await Promise.all(toolCalls.map((c) => this.executor(zone).execute(c, signal)));
      } else {
        results = [];
        for (const c of toolCalls) results.push(await this.executor(zone).execute(c, signal));
      }
      for (let i = 0; i < toolCalls.length; i++) {
        const c = toolCalls[i] as ToolCall;
        const r = results[i] as ToolResult;
        toolCallsThisSend += 1;
        this.messages.push({ role: "tool", toolCallId: c.id, name: c.name, content: formatForModel(r) });
        this.meter.addTool(c.name, r.byReference ? 0 : r.tokens.estimate, r.evidenceId);
        if (r.evidenceId) {
          const e = evidence.get(r.evidenceId);
          if (e) this.ledger.noteEvidence({ id: e.id, tool: e.tool, summary: e.summary, subjects: e.subjects });
        }
        yield {
          type: "tool_result",
          id: c.id,
          name: c.name,
          status: r.status,
          summary: r.summary,
          ...(r.evidenceId ? { evidenceId: r.evidenceId } : {}),
          tokens: r.tokens.estimate,
          byReference: r.byReference,
          ...(r.reasonCode ? { reasonCode: r.reasonCode } : {}),
        };
      }
    }
  }
}
