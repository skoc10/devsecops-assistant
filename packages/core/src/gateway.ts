import { createHash, randomUUID } from "node:crypto";
import {
  estimateTokens,
  maxRisk,
  maxSensitivity,
  OpsError,
  scopeAllows,
  SENSITIVITY_ZONE_CAP,
  stricterZone,
  zoneAllows,
} from "@ops/contracts";
import type {
  ActionPreview,
  Adapter,
  ApprovalGate,
  AuditSink,
  CanonicalActionSummary,
  CredentialBroker,
  DecisionContext,
  Lease,
  Profile,
  RawToolOutput,
  ReasonCode,
  RiskClass,
  Sensitivity,
  Target,
  ToolDescriptor,
  ToolResult,
  TrustZone,
} from "@ops/contracts";
import type { PolicyEngine } from "@ops/policy";
import { Counter, mapStrings, processOutput, scrubText } from "@ops/redaction";
import type { KnownSecrets, MaskingRules } from "@ops/redaction";
import type { EvidenceStore } from "./evidence.ts";
import type { Quarantine, QuarantineResult } from "./quarantine.ts";
import type { ToolRegistry } from "./registry.ts";
import type { Session } from "./session.ts";
import { normalizeEndpoint } from "./url.ts";

/** Kabuk/SQL gibi komut sınıflayıcıları: `"unclassified"` = sınıflanamadı → `destroy` muamelesi. */
export type CommandClassifier = (tool: string, args: unknown) => RiskClass | "unclassified" | undefined;

export interface GatewayDeps {
  readonly registry: ToolRegistry;
  readonly session: Session;
  readonly policy: PolicyEngine;
  readonly audit: AuditSink;
  readonly broker: CredentialBroker;
  readonly evidence: EvidenceStore;
  readonly known: KnownSecrets;
  /** Faz 0'da yok: `ask` kararı `approval_unavailable` ile reddedilir. */
  readonly approval?: ApprovalGate;
  readonly classifiers?: readonly CommandClassifier[];
  /** Araç/profile göre M4 kuralları (DB adapter'ı). */
  readonly maskingFor?: (tool: ToolDescriptor, profile: Profile | null) => MaskingRules | null;
  readonly now?: () => Date;
  readonly newId?: () => string;
  /** Mutasyon atfı için kanıt tazelik penceresi. */
  readonly citationMaxAgeMs?: number;
  /**
   * `egress: local-only` kipi (tasarım §2): yalnız YEREL sağlayıcı bölgesi ve yalnız okuma sınıfı. Sağlayıcı
   * seçiminden bağımsız, PEP'te fail-closed zorlanır.
   */
  readonly localOnly?: boolean;
  /**
   * Karantina (tasarım §4.2): ham serbest metin (log/olay) ana bağlama girmez; modele tipli özet gider, ham içerik
   * kanıt deposunda karantinada kalır. Yoksa untrusted sonuçlar eskisi gibi taint'li akar.
   */
  readonly quarantine?: Quarantine;
}

export interface InvokeRequest {
  readonly tool: string;
  /** Profil takma adı (kimliği). Yerel araçlarda gerekmez. */
  readonly profile?: string;
  readonly args: unknown;
  /** Mutasyon önerisinin dayandığı kanıt kimlikleri. */
  readonly citedEvidence?: readonly string[];
  /** Sonucun gideceği model sağlayıcısının güven bölgesi (egress kontrolü). */
  readonly providerZone: TrustZone;
  readonly provider?: { readonly id: string; readonly model: string };
  readonly signal?: AbortSignal;
}

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

function canonicalJson(v: unknown): string {
  const sort = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(sort);
    if (x !== null && typeof x === "object") {
      return Object.fromEntries(Object.entries(x as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, val]) => [k, sort(val)]));
    }
    return x;
  };
  return JSON.stringify(sort(v));
}

interface CallState {
  readonly callId: string;
  readonly req: InvokeRequest;
  desc?: ToolDescriptor;
  profile?: Profile;
  target?: Target;
  cls?: RiskClass;
  breakGlass?: string;
  /** Politika kararının girdisi (denetime yazılır; `ops replay --policy` yeniden değerlendirir). */
  dctx?: DecisionContext;
}

/**
 * Tool Gateway (PEP). Her araç çağrısı, istisnasız, şu tek boru hattından geçer:
 * şema → profil → hedef pini/kapsam → sınıflama → politika → (atıf) → (onay) → denetim(intent)
 * → lease → adapter → lease bırak → çıktı boru hattı → denetim(result) → egress kontrolü.
 * Denetim yazılamazsa çağrı ÇALIŞMAZ (fail-closed).
 */
export class ToolGateway {
  private readonly d: GatewayDeps;
  private readonly primed = new Set<string>();
  private readonly now: () => Date;
  private readonly newId: () => string;

  /** Uçuştaki çağrı → break-glass hibe kimliği: o çağrının TÜM denetim kayıtları etiketlenir. */
  private readonly bg = new Map<string, string>();

  constructor(deps: GatewayDeps) {
    this.now = deps.now ?? (() => new Date());
    this.newId = deps.newId ?? (() => randomUUID());
    const base = deps.audit;
    const tagged: AuditSink = {
      append: (e) => {
        const id = e.callId ? this.bg.get(e.callId) : undefined;
        return base.append(id && !e.breakGlass ? { ...e, breakGlass: id } : e);
      },
    };
    this.d = { ...deps, audit: tagged };
  }

  async invoke(req: InvokeRequest): Promise<ToolResult> {
    const st: CallState = { callId: this.newId(), req };
    try {
      return await this.invokeInner(req, st);
    } finally {
      this.bg.delete(st.callId);
    }
  }

  private async invokeInner(req: InvokeRequest, st: CallState): Promise<ToolResult> {
    const { registry, session, policy, audit, evidence, known } = this.d;

    const reg = registry.get(req.tool);
    if (!reg) return this.deny(st, "unknown_tool", `bilinmeyen araç: ${req.tool}`);
    const desc = reg.def.descriptor;
    st.desc = desc;

    if (this.d.localOnly && req.providerZone !== "local") {
      return this.deny(st, "local_only", `egress: local-only kipinde yalnız yerel sağlayıcı kullanılır (sağlayıcı bölgesi '${req.providerZone}')`);
    }

    // Oturum bütçesi
    const budget = policy.checkBudget({ toolCalls: session.usage.toolCalls, sessionTokens: session.usage.sessionTokens });
    if (!budget.ok) return this.deny(st, budget.reason, "oturum bütçesi aşıldı");

    // 1. Şema doğrulama (strictObject: fazladan alan reddedilir)
    const parsed = reg.def.input.safeParse(req.args);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => `${i.path.join(".") || "(kök)"}: ${i.message}`).join("; ");
      return this.deny(st, "schema_invalid", issues);
    }
    const args: unknown = parsed.data;

    // 2. Profil çözümleme: yalnız oturuma bağlı profiller; ortamda "current context" yok
    let profile: Profile | null = null;
    if (desc.profileKind !== null) {
      if (!req.profile) return this.deny(st, "profile_unknown", "profil belirtilmedi");
      let p = session.getBound(req.profile);
      if (!p) return this.deny(st, "profile_not_bound", `profil oturuma bağlı değil: ${req.profile}`);
      // Break-glass: süresi dolduysa tavan ÖNCE düşürülür (fail-safe), sonra denetlenir; etkinse çağrı etiketlenir.
      const grant = session.breakGlass.get(p.id);
      if (grant) {
        if (this.now().getTime() >= Date.parse(grant.expiresAt)) {
          session.endBreakGlass(p.id);
          try {
            await audit.append({ event: "break_glass", sessionId: session.id, profile: p.id, environment: grant.original.environment, breakGlass: grant.id, decision: "deny", message: "bitir neden=expired" });
          } catch {
            return this.deny(st, "audit_unavailable", "break-glass bitiş kaydı yazılamadı; çağrı çalıştırılmadı", { skipAudit: true });
          }
          p = session.getBound(req.profile) ?? p;
        } else {
          this.bg.set(st.callId, grant.id);
          st.breakGlass = grant.id;
        }
      }
      if (p.kind !== desc.profileKind) {
        return this.deny(st, "kind_mismatch", `araç '${desc.profileKind}' profili ister, '${p.id}' '${p.kind}'`);
      }
      profile = p;
      st.profile = p;
    }

    // M3: profilin secret'ları, argümanlar/onay özeti/denetim yazılmadan ÖNCE kayıtlı olmalı.
    if (profile && !this.primed.has(profile.id) && this.d.broker.prime) {
      try {
        await this.d.broker.prime(profile, known);
        this.primed.add(profile.id);
      } catch {
        return this.finishError(st, "adapter_error", "kimlik hazırlanamadı (kasa kilitli olabilir)");
      }
    }

    // 3. Hedef çözümleme, pin ve kapsam
    let target: Target | null = null;
    if (profile) {
      try {
        target = reg.adapter.resolveTarget(desc.name, args, profile);
      } catch (e) {
        return this.deny(st, "target_unresolved", scrubText(e instanceof Error ? e.message : String(e), known));
      }
      st.target = target;
      if (target.profileId !== profile.id || normalizeEndpoint(target.endpoint) !== normalizeEndpoint(profile.targetPin.endpoint)) {
        return this.deny(st, "target_pin_mismatch", "çözülen hedef profilin pinli uç noktasıyla eşleşmiyor");
      }
      const wildcardOk = profile.allowedScopes.includes("*");
      if (!wildcardOk && target.scopes.length === 0) {
        return this.deny(st, "scope_violation", "hedef kapsamı belirtilmedi ve profil '*' izinli değil");
      }
      for (const s of target.scopes) {
        if (!scopeAllows(profile.allowedScopes, s)) return this.deny(st, "scope_violation", `kapsam profilin izinli kapsamlarında değil: ${s}`);
      }
    }

    // 4. Sınıflama: manifest ⊔ adapter ⊔ komut/SQL sınıflayıcıları (yalnız YÜKSELTİR)
    let cls: RiskClass = desc.class;
    let unclassified = false;
    const fromAdapter = reg.adapter.classify?.(desc.name, args);
    if (fromAdapter) cls = maxRisk(cls, fromAdapter);
    for (const c of this.d.classifiers ?? []) {
      const r = c(desc.name, args);
      if (r === "unclassified") unclassified = true;
      else if (r) cls = maxRisk(cls, r);
    }
    st.cls = unclassified ? "destroy" : cls;
    if (this.d.localOnly && st.cls !== "read") {
      return this.deny(st, "local_only", `egress: local-only kipi yalnız okuma sınıfına izin verir (araç sınıfı '${st.cls}')`);
    }
    if (this.d.localOnly && desc.network === "open") {
      return this.deny(st, "local_only", "egress: local-only kipinde açık ağ çıkışlı araç çalışmaz");
    }

    // 5-6. Politika (bağlam etiketi/taint dahil)
    const effSens: Sensitivity = maxSensitivity(desc.sensitivity, reg.adapter.sensitivityOf?.(desc.name, args) ?? "none");
    const decision = policy.decide({ tool: desc, effectiveClass: cls, unclassified, profile, target, context: session.context, effectiveSensitivity: effSens });
    st.dctx = {
      unclassified,
      sensitivity: effSens,
      tainted: session.context.tainted,
      maxSensitivity: session.context.maxSensitivity,
      profilesTouched: session.context.profilesTouched.slice(0, 16),
      scopes: (target?.scopes ?? []).slice(0, 16),
      ...(profile ? { ceiling: profile.classCeiling } : {}),
    };
    if (decision.effect === "deny") return this.deny(st, decision.reasonCode, decision.detail, { policyDecision: true });

    // Egress ön denetimi: veri o sağlayıcıya gidemeyecekse çağrıyı hiç çalıştırma
    const futureCap = this.zoneCapFor(effSens, profile);
    if (!zoneAllows(req.providerZone, futureCap)) {
      return this.deny(st, "no_eligible_provider", `sağlayıcı bölgesi '${req.providerZone}', verinin gidebileceği en uzak bölge '${futureCap}'`);
    }

    // Mutasyon atfı (sözdizimsel): hedef kaynak, atıf yapılan taze kanıtın subject'inde olmalı
    if (st.cls !== "read" && profile && target) {
      const ok = evidence.supports({
        ids: req.citedEvidence ?? [],
        targetRefs: target.refs,
        profileId: profile.id,
        epoch: session.epoch,
        maxAgeMs: this.d.citationMaxAgeMs ?? 30 * 60_000,
        now: this.now(),
      });
      if (!ok.ok) return this.deny(st, "citation_missing", ok.why);
    }

    // 6.5 Önizleme (yalnız mutasyon+ ve adapter destekliyorsa): neyi onayladığınızı gösterir + TOCTOU sürümü
    let preview: ActionPreview | undefined;
    if (st.cls !== "read" && profile && reg.adapter.preview) {
      const pv = await this.runPreview(st, reg.adapter, desc, args, profile, "onizleme");
      if (pv.denied) return pv.denied;
      preview = pv.preview;
    }
    const previewDigest = preview ? sha256(canonicalJson({ v: preview.targetVersion ?? null, d: preview.diff ?? null })) : null;

    // 7. Onay: eylem hash'i, gösterilen önizlemenin özetini de kapsar (onay = bu diff + bu sürüm)
    const actionHash = sha256(
      canonicalJson({ tool: desc.name, args, profile: profile?.id ?? null, target, class: st.cls, policy: policy.versionHash, preview: previewDigest }),
    );
    let approvalId: string | undefined;
    const isLocalWrite = desc.scope === "local" && desc.localWrite;
    const grantedBySession =
      decision.effect === "ask" &&
      decision.reasonCode === "approval_required" &&
      isLocalWrite &&
      st.cls === "read" &&
      !session.context.tainted &&
      session.writeGrants.has(desc.name);
    if (grantedBySession) {
      try {
        await audit.append({
          event: "approval",
          sessionId: session.id,
          callId: st.callId,
          tool: desc.name,
          actionHash,
          decision: "allow",
          message: "oturum yazma izni (aynı araç için ilk onaydan; bağlam taint'siz)",
        });
      } catch {
        return this.deny(st, "audit_unavailable", "onay kaydı yazılamadı; çağrı çalıştırılmadı", { skipAudit: true });
      }
    } else if (decision.effect === "ask") {
      const gate = this.d.approval;
      if (!gate) return this.deny(st, "approval_unavailable", `onay gerekli (${decision.reasonCode}) ama onay kapısı yok`);
      const summary: CanonicalActionSummary = {
        tool: desc.name,
        class: st.cls,
        profile: profile
          ? { id: profile.id, environment: profile.environment, displayName: profile.displayName }
          : { id: "-", environment: "-", displayName: "-" },
        target,
        argsRedacted: mapStrings(args, (s) => scrubText(s, known)),
        citedEvidence: (req.citedEvidence ?? []).flatMap((id) => {
          const e = evidence.get(id);
          return e ? [{ id, summary: e.summary }] : [];
        }),
        taintedContext: session.context.tainted,
        why: decision.reasonCode,
        ...(profile && session.breakGlass.get(profile.id)
          ? (() => {
              const g = session.breakGlass.get(profile.id) as NonNullable<ReturnType<typeof session.breakGlass.get>>;
              return { breakGlass: { id: g.id, reason: scrubText(g.reason, known), expiresAt: g.expiresAt, originalCeiling: g.original.classCeiling } };
            })()
          : {}),
        ...(preview
          ? {
              preview: {
                ...(preview.targetVersion !== undefined ? { targetVersion: scrubText(preview.targetVersion, known) } : {}),
                ...(preview.diff !== undefined ? { diff: scrubText(preview.diff, known) } : {}),
                ...(preview.impact ? { impact: preview.impact.map((x) => scrubText(x, known)) } : {}),
                ...(preview.rollback !== undefined ? { rollback: scrubText(preview.rollback, known) } : {}),
              },
            }
          : {}),
        ...(isLocalWrite && decision.reasonCode === "approval_required" && st.cls === "read"
          ? { note: "Bu onay, bu oturumda AYNI aracın çalışma alanı (anlık kopya) yazımlarını kapsar; bağlamda untrusted içerik belirirse yeniden sorulur." }
          : {}),
      };
      const outcome = await gate.request({ actionHash, summary, expiresInSec: 300 });
      const hashOk = outcome.approved && outcome.actionHash === actionHash;
      // onay kararı (verildi/reddedildi) denetime ayrıca yazılır; yazılamazsa çağrı çalışmaz
      try {
        await audit.append({
          event: "approval",
          sessionId: session.id,
          callId: st.callId,
          tool: desc.name,
          ...(profile ? { profile: profile.id, environment: profile.environment } : {}),
          actionHash,
          decision: hashOk ? "allow" : "deny",
          ...(outcome.approved ? { approvalId: outcome.approvalId } : {}),
          message: outcome.approved ? (hashOk ? "onaylandı" : "onay başka bir eyleme ait") : scrubText(outcome.reason, known),
        });
      } catch {
        return this.deny(st, "audit_unavailable", "onay kaydı yazılamadı; çağrı çalıştırılmadı", { skipAudit: true });
      }
      if (!outcome.approved) return this.deny(st, "approval_denied", outcome.reason);
      if (!hashOk) return this.deny(st, "approval_denied", "onay başka bir eyleme ait (eylem hash'i uyuşmuyor)");
      approvalId = outcome.approvalId;
      if (isLocalWrite && decision.reasonCode === "approval_required" && st.cls === "read" && !session.context.tainted) session.writeGrants.add(desc.name);
    }

    // Break-glass onay beklerken bitmiş/süresi dolmuş olabilir: yükseltilmiş tavanla verilen karar GEÇERSİZ.
    if (st.breakGlass && profile) {
      const live = session.breakGlass.get(profile.id);
      if (!live || live.id !== st.breakGlass || this.now().getTime() >= Date.parse(live.expiresAt)) {
        return this.deny(st, "ceiling_exceeded", "break-glass süresi/izni bu çağrı beklerken sona erdi; çağrı çalıştırılmadı");
      }
    }

    // 8. Denetim: intent (write-ahead). Yazılamazsa ÇALIŞTIRMA.
    const argsRedacted = mapStrings(args, (s) => scrubText(s, known));
    try {
      await audit.append({
        event: "intent",
        sessionId: session.id,
        callId: st.callId,
        tool: desc.name,
        class: st.cls,
        ...(profile ? { profile: profile.id, environment: profile.environment } : {}),
        ...(target ? { target: `${target.endpoint} [${target.scopes.join(",")}]` } : {}),
        decision: decision.effect,
        reasonCode: decision.reasonCode,
        ...(st.dctx ? { decisionContext: st.dctx } : {}),
        ...(approvalId ? { approvalId } : {}),
        ...(req.citedEvidence?.length ? { message: `atıf: ${req.citedEvidence.slice(0, 10).join(",")}` } : {}),
        actionHash,
        argsRedacted,
        policyVersionHash: policy.versionHash,
        trustZone: req.providerZone,
        ...(req.provider ? { provider: req.provider.id, model: req.provider.model } : {}),
      });
    } catch {
      return this.deny(st, "audit_unavailable", "denetim kaydı yazılamadı; çağrı çalıştırılmadı", { skipAudit: true });
    }

    // 9. Lease
    let lease: Lease | null = null;
    if (profile) {
      try {
        const ttl = Math.min(profile.maxLeaseTtlSec, Math.ceil(desc.limits.timeoutMs / 1000) + 30);
        lease = await this.d.broker.acquire({ profile, purpose: desc.name, callId: st.callId, ttlSec: ttl }, known);
      } catch (e) {
        return this.finishError(st, "adapter_error", `kimlik bağlanamadı: ${scrubText(e instanceof Error ? e.message : String(e), known)}`);
      }
      try {
        await audit.append({ event: "lease", sessionId: session.id, callId: st.callId, profile: profile.id, message: "acquired" });
      } catch {
        await lease.release().catch(() => undefined);
        return this.deny(st, "audit_unavailable", "lease denetimi yazılamadı; çağrı çalıştırılmadı", { skipAudit: true });
      }
    }

    // 9.5 TOCTOU: onaydan sonra hedef değişti mi? (önizleme yeniden hesaplanır; sürüm/diff özeti eşleşmezse ÇALIŞMAZ)
    if (preview && profile && lease) {
      const again = await this.previewOnce(st, reg.adapter, desc, args, profile, lease, req.signal);
      const digest2 = again.preview ? sha256(canonicalJson({ v: again.preview.targetVersion ?? null, d: again.preview.diff ?? null })) : null;
      if (again.error !== undefined || digest2 !== previewDigest) {
        await this.releaseLease(st, lease);
        return again.error !== undefined
          ? this.deny(st, "preview_failed", `çalıştırma öncesi yeniden doğrulama başarısız: ${scrubText(again.error, known)}`)
          : this.deny(st, "target_changed", "onaydan sonra hedefin sürümü/içeriği değişti; hiçbir şey uygulanmadı");
      }
    }

    // 10. Adapter (zaman aşımı + iptal)
    let raw: RawToolOutput;
    const ac = new AbortController();
    const onAbort = (): void => ac.abort();
    req.signal?.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => ac.abort(), desc.limits.timeoutMs);
    try {
      raw = await Promise.race([
        reg.adapter.invoke({ tool: desc.name, args, profile: profile ?? (undefined as never), handle: lease?.handle ?? null, callId: st.callId, signal: ac.signal, limits: desc.limits, ...(preview?.targetVersion !== undefined ? { approvedVersion: preview.targetVersion } : {}) }),
        new Promise<never>((_, reject) => {
          ac.signal.addEventListener("abort", () => reject(new OpsError("timeout", "araç zaman aşımına uğradı veya iptal edildi")), { once: true });
        }),
      ]);
    } catch (e) {
      clearTimeout(timer);
      req.signal?.removeEventListener("abort", onAbort);
      await this.releaseLease(st, lease);
      const code: ReasonCode = e instanceof OpsError && e.code === "timeout" ? "timeout" : e instanceof OpsError && e.code === "quarantined" ? "quarantined" : "adapter_error";
      return this.finishError(st, code, scrubText(e instanceof Error ? e.message : String(e), known));
    }
    clearTimeout(timer);
    req.signal?.removeEventListener("abort", onAbort);

    // 11. Lease bırak
    await this.releaseLease(st, lease);

    // 12. Çıktı boru hattı (adapter DIŞINDA, atlanamaz)
    const args0 = (args ?? {}) as Record<string, unknown>;
    const select = Array.isArray(args0["select"]) && (args0["select"] as unknown[]).every((s) => typeof s === "string") ? (args0["select"] as string[]) : undefined;
    const masking = this.d.maskingFor?.(desc, profile) ?? null;
    const processed = processOutput(raw.data, raw.summary, {
      structuralProfile: desc.redactionProfile,
      maxBytes: desc.limits.maxBytes,
      maxItems: desc.limits.maxItems,
      maxOutputTokens: policy.resultTokenCap(desc),
      ...(desc.projection ? { projection: desc.projection } : {}),
      ...(select && desc.projection?.selectable ? { select } : {}),
      masking,
      known,
    });
    // `taint`: KANIT içeriğinin güvenilirliği. Karantinada modele giden görünümün taint'i ayrıdır (`viewTaint`).
    const taint = desc.untrustedOutput || raw.taint === "untrusted" ? "untrusted" : "trusted";
    const sensitivity: Sensitivity = maxSensitivity(desc.sensitivity, raw.sensitivity ?? "none");
    const subjects = [...new Set([...(raw.subjects ?? []), ...(target?.refs ?? [])])];
    const observedAt = this.now().toISOString();
    let quarantined: QuarantineResult | null = null;
    if (this.d.quarantine && taint === "untrusted") {
      // Tipli özet çıkarılamazsa sonuç eskisi gibi (taint'li) akar: karantina yalnız DARALTIR, hiçbir şeyi genişletmez.
      quarantined = await this.d.quarantine
        .apply({
          tool: desc.name,
          evidence: processed.evidence,
          sensitivity,
          zoneCapAfter: session.zoneCapAfter({ ...(profile ? { profile } : {}), sensitivity }),
          ...(req.signal ? { signal: req.signal } : {}),
        })
        .catch(() => null);
    }
    const viewTaint = quarantined ? quarantined.taint : taint;
    const quarantineViewText = quarantined ? JSON.stringify(quarantined.view) : undefined;
    const viewTokens = quarantineViewText !== undefined ? estimateTokens(quarantineViewText) : processed.byReference ? 0 : processed.tokens;
    const entry = evidence.put({
      callId: st.callId,
      tool: desc.name,
      profileId: profile?.id,
      epoch: session.epoch,
      observedAt,
      subjects,
      sensitivity,
      taint,
      summary: processed.summary || desc.name,
      text: processed.evidenceText,
      ...(quarantined ? { quarantined: true } : {}),
    });

    session.usage.toolCalls += 1;
    session.usage.resultTokens += viewTokens;
    session.noteResult({ ...(profile ? { profile } : {}), sensitivity, tainted: viewTaint === "untrusted" });

    const redactionCounts = Object.fromEntries(processed.redactions.map((r) => [r.rule, r.count]));
    const viewBytes = Buffer.byteLength(quarantineViewText ?? processed.viewText, "utf8");

    // 13. Denetim: result. Yazılamazsa sonuç modele VERİLMEZ (kanıt yerelde kalır).
    try {
      await audit.append({
        event: "result",
        sessionId: session.id,
        callId: st.callId,
        tool: desc.name,
        class: st.cls,
        ...(profile ? { profile: profile.id, environment: profile.environment } : {}),
        exitStatus: "ok",
        outputRedacted: processed.evidenceText,
        outputHash: sha256(processed.evidenceText),
        outputBytesToModel: viewBytes,
        redactionCounts,
        resultTokensEstimate: processed.tokens,
        ...(quarantined && this.d.quarantine ? { message: `quarantine mode=${this.d.quarantine.mode} model=${quarantined.modelSummary}` } : {}),
        policyVersionHash: policy.versionHash,
        trustZone: req.providerZone,
        ...(req.provider ? { provider: req.provider.id, model: req.provider.model } : {}),
      });
    } catch {
      return this.denied(st, "audit_unavailable", "denetim kaydı yazılamadı; sonuç modele verilmedi (kanıt yerelde)", entry.id);
    }

    // 14. Egress son denetimi: adapter hassasiyeti yükselttiyse
    const finalCap = session.context.zoneCap;
    if (!zoneAllows(req.providerZone, finalCap)) {
      return this.denied(st, "no_eligible_provider", `sonuç hassasiyeti '${sensitivity}' bu sağlayıcıya gidemez; kanıt yerelde (${entry.id})`, entry.id);
    }

    return {
      callId: st.callId,
      tool: desc.name,
      status: "ok",
      evidenceId: entry.id,
      summary: processed.summary,
      ...(quarantined ? { view: quarantined.view } : processed.byReference ? {} : { view: processed.view }),
      byReference: quarantined ? false : processed.byReference,
      truncated: processed.truncated || raw.truncated === true,
      redactions: processed.redactions,
      provenance: {
        source: desc.name,
        ...(profile ? { profileId: profile.id, targetFingerprint: sha256(normalizeEndpoint(profile.targetPin.endpoint)).slice(0, 16) } : {}),
        observedAt,
        query: JSON.stringify(argsRedacted).slice(0, 200),
      },
      sensitivity,
      taint: viewTaint,
      subjects,
      tokens: { estimate: quarantined ? viewTokens : processed.byReference ? processed.fullTokens : processed.tokens },
    };
  }

  /** Tek önizleme çağrısı (zaman aşımı + iptal). Hata mesajı döner, atmaz. */
  private async previewOnce(
    st: CallState,
    adapter: Adapter,
    desc: ToolDescriptor,
    args: unknown,
    profile: Profile,
    lease: Lease,
    signal?: AbortSignal,
  ): Promise<{ preview?: ActionPreview; error?: string }> {
    const ac = new AbortController();
    const onAbort = (): void => ac.abort();
    signal?.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => ac.abort(), Math.min(desc.limits.timeoutMs, 30_000));
    try {
      const preview = await Promise.race([
        adapter.preview!({ tool: desc.name, args, profile, handle: lease.handle, callId: st.callId, signal: ac.signal, limits: desc.limits }),
        new Promise<never>((_, reject) => ac.signal.addEventListener("abort", () => reject(new OpsError("timeout", "önizleme zaman aşımına uğradı")), { once: true })),
      ]);
      return { preview };
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }

  /** Onay öncesi önizleme: kendi (kısa) lease'iyle, salt okuma. Başarısızlık = ret (fail-closed). */
  private async runPreview(
    st: CallState,
    adapter: Adapter,
    desc: ToolDescriptor,
    args: unknown,
    profile: Profile,
    _label: string,
  ): Promise<{ preview: ActionPreview; denied?: undefined } | { denied: ToolResult; preview?: undefined }> {
    const { audit, session, known } = this.d;
    let lease: Lease;
    try {
      lease = await this.d.broker.acquire({ profile, purpose: `${desc.name}:preview`, callId: st.callId, ttlSec: Math.min(profile.maxLeaseTtlSec, 60) }, known);
    } catch (e) {
      return { denied: await this.deny(st, "preview_failed", `önizleme için kimlik bağlanamadı: ${scrubText(e instanceof Error ? e.message : String(e), known)}`) };
    }
    try {
      await audit.append({ event: "lease", sessionId: session.id, callId: st.callId, profile: profile.id, message: "acquired (önizleme)" });
    } catch {
      await lease.release().catch(() => undefined);
      return { denied: await this.deny(st, "audit_unavailable", "lease denetimi yazılamadı; çağrı çalıştırılmadı", { skipAudit: true }) };
    }
    const r = await this.previewOnce(st, adapter, desc, args, profile, lease, st.req.signal);
    await this.releaseLease(st, lease);
    if (r.error !== undefined || !r.preview) return { denied: await this.deny(st, "preview_failed", `önizleme üretilemedi: ${scrubText(r.error ?? "?", known)}`) };
    return { preview: r.preview };
  }

  private zoneCapFor(sensitivity: Sensitivity, profile: Profile | null): TrustZone {
    let cap = stricterZone(this.d.session.context.zoneCap, SENSITIVITY_ZONE_CAP[sensitivity]);
    if (profile) cap = stricterZone(cap, profile.egressClass);
    return cap;
  }

  private async releaseLease(st: CallState, lease: Lease | null): Promise<void> {
    if (!lease) return;
    try {
      await lease.release();
    } finally {
      // Denetim bozulduysa sonraki çağrılar zaten fail-closed reddedilir.
      await this.d.audit
        .append({ event: "lease", sessionId: this.d.session.id, callId: st.callId, ...(st.profile ? { profile: st.profile.id } : {}), message: "released" })
        .catch(() => undefined);
    }
  }

  private async finishError(st: CallState, code: ReasonCode, message: string): Promise<ToolResult> {
    const { audit, session, policy } = this.d;
    try {
      await audit.append({
        event: "result",
        sessionId: session.id,
        callId: st.callId,
        ...(st.desc ? { tool: st.desc.name } : {}),
        ...(st.cls ? { class: st.cls } : {}),
        ...(st.profile ? { profile: st.profile.id, environment: st.profile.environment } : {}),
        exitStatus: "error",
        reasonCode: code,
        message,
        policyVersionHash: policy.versionHash,
      });
    } catch {
      // günlük bozuk: sonraki çağrılar reddedilecek
    }
    return this.resultShell(st, "error", code, message);
  }

  private async deny(st: CallState, code: ReasonCode, detail?: string, opts: { skipAudit?: boolean; policyDecision?: boolean } = {}): Promise<ToolResult> {
    const { audit, session, policy } = this.d;
    const message = detail ? scrubText(detail, this.d.known) : code;
    if (!opts.skipAudit) {
      try {
        await audit.append({
          event: "result",
          sessionId: session.id,
          callId: st.callId,
          tool: st.desc?.name ?? st.req.tool,
          ...(st.cls ? { class: st.cls } : {}),
          ...(st.profile ? { profile: st.profile.id, environment: st.profile.environment } : {}),
          decision: "deny",
          reasonCode: code,
          exitStatus: "denied",
          message,
          // yalnız POLİTİKA motorunun reddi karar girdisini taşır (sonraki reddler — egress, atıf, onay — politika dışıdır)
          ...(st.dctx && opts.policyDecision ? { decisionContext: st.dctx } : {}),
          policyVersionHash: policy.versionHash,
          trustZone: st.req.providerZone,
        });
      } catch {
        // denetim yazılamasa da çağrı zaten reddedildi
      }
    }
    return this.resultShell(st, "denied", code, message);
  }

  /** Sonuç oluştu ama modele verilemez (egress/denetim): kanıt yerelde, model yalnız sebep görür. */
  private denied(st: CallState, code: ReasonCode, message: string, evidenceId: string): ToolResult {
    return { ...this.resultShell(st, "denied", code, message), evidenceId };
  }

  private resultShell(st: CallState, status: "denied" | "error", code: ReasonCode, message: string): ToolResult {
    return {
      callId: st.callId,
      tool: st.desc?.name ?? st.req.tool,
      status,
      summary: message,
      byReference: false,
      truncated: false,
      redactions: new Counter().toSummary(),
      provenance: { source: st.desc?.name ?? st.req.tool, observedAt: this.now().toISOString() },
      sensitivity: "none",
      taint: "trusted",
      subjects: [],
      tokens: { estimate: 0 },
      reasonCode: code,
    };
  }
}
