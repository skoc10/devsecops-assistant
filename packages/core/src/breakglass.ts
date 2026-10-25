import { randomBytes } from "node:crypto";
import { OpsError, riskRank } from "@ops/contracts";
import type { AuditRecord, AuditSink, DoctorReport, Profile, RiskClass } from "@ops/contracts";
import { stripControlChars } from "@ops/redaction";
import type { BreakGlassGrant, Session } from "./session.ts";

/** Üst süre: tasarım §8.6 (≤ 30 dk, tek profil). */
export const BREAK_GLASS_MAX_TTL_SEC = 30 * 60;
export const BREAK_GLASS_MIN_TTL_SEC = 60;
export const BREAK_GLASS_MIN_REASON = 12;
export const BREAK_GLASS_MAX_REASON = 300;
/** Yeniden kimlik doğrulama kanıtının en çok bu kadar eski olmasına izin verilir. */
export const BREAK_GLASS_REAUTH_FRESH_MS = 60_000;

export interface ReauthProof {
  /** Ör. `vault-passphrase`. */
  readonly method: string;
  readonly verifiedAt: Date;
}

export interface BreakGlassDeps {
  readonly session: Session;
  readonly audit: AuditSink;
  /** Yükseltilmiş kopyayı FİİLİ yetkiye karşı sınar (doktor); bağlanamazsa break-glass başlamaz. */
  readonly doctor: (raised: Profile) => Promise<DoctorReport>;
  readonly now?: () => Date;
  readonly newId?: () => string;
  /** Doluysa break-glass başlatılamaz (ör. `egress: local-only` kipi: yalnız okuma). */
  readonly disabledReason?: string;
}

export interface BreakGlassRequest {
  readonly profileId: string;
  readonly ceiling: RiskClass;
  readonly reason: string;
  readonly ttlSec: number;
  readonly reauth: ReauthProof;
}

export interface BreakGlassStatus {
  readonly id: string;
  readonly profileId: string;
  readonly environment: string;
  readonly from: RiskClass;
  readonly to: RiskClass;
  readonly reason: string;
  readonly expiresAt: string;
  readonly remainingSec: number;
}

const clipOne = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/**
 * Break-glass (tasarım §8.6, T8): bağlı BİR profilin sınıf tavanını geçici yükseltir. Denetim, redaksiyon ve
 * çıktı boru hattını KAPATMAZ; onay/taint/atıf/ön izleme kuralları aynen sürer (yalnız tavan değişir).
 * Fail-closed: denetim yazılamıyorsa, yeniden kimlik doğrulama eski/yoksa, gerekçe/süre geçersizse veya
 * doktor yükseltilmiş tavanı fiili yetkiyle bağdaştıramıyorsa HİÇBİR ŞEY DEĞİŞMEZ.
 */
export class BreakGlassController {
  private readonly d: BreakGlassDeps;
  private readonly now: () => Date;
  private readonly newId: () => string;

  constructor(deps: BreakGlassDeps) {
    this.d = deps;
    this.now = deps.now ?? (() => new Date());
    this.newId = deps.newId ?? (() => `bg-${randomBytes(4).toString("hex")}`);
  }

  async start(req: BreakGlassRequest): Promise<BreakGlassGrant> {
    const { session, audit } = this.d;
    if (this.d.disabledReason) throw new OpsError("break_glass_disabled", `break-glass kapalı: ${this.d.disabledReason}`);
    const reason = req.reason.trim();
    if (reason.length < BREAK_GLASS_MIN_REASON) throw new OpsError("break_glass_reason", `gerekçe en az ${BREAK_GLASS_MIN_REASON} karakter olmalı (ne için, hangi olay/bilet)`);
    if (reason.length > BREAK_GLASS_MAX_REASON) throw new OpsError("break_glass_reason", `gerekçe en çok ${BREAK_GLASS_MAX_REASON} karakter olabilir`);
    if (stripControlChars(reason) !== reason) throw new OpsError("break_glass_reason", "gerekçe kontrol karakteri içeremez");
    if (!Number.isInteger(req.ttlSec) || req.ttlSec < BREAK_GLASS_MIN_TTL_SEC || req.ttlSec > BREAK_GLASS_MAX_TTL_SEC) {
      throw new OpsError("break_glass_ttl", `süre ${BREAK_GLASS_MIN_TTL_SEC / 60} dk ile ${BREAK_GLASS_MAX_TTL_SEC / 60} dk arasında olmalı (zorunlu; süresiz yok)`);
    }
    const now = this.now();
    const age = now.getTime() - req.reauth.verifiedAt.getTime();
    if (!req.reauth.method || age < 0 || age > BREAK_GLASS_REAUTH_FRESH_MS) {
      throw new OpsError("break_glass_reauth", "yeniden kimlik doğrulama gerekli (taze kanıt yok)");
    }
    const profile = session.getBound(req.profileId);
    if (!profile) throw new OpsError("profile_not_bound", `profil oturuma bağlı değil: ${req.profileId} (önce /use ile bağlayın)`);
    if (session.breakGlass.has(profile.id)) throw new OpsError("break_glass_active", `'${profile.id}' için break-glass zaten etkin; önce bitirin`);
    if (riskRank(req.ceiling) <= riskRank(profile.classCeiling)) {
      throw new OpsError("break_glass_ceiling", `istenen tavan '${req.ceiling}' mevcut tavanı ('${profile.classCeiling}') yükseltmiyor`);
    }
    const raised: Profile = { ...profile, classCeiling: req.ceiling };
    const report = await this.d.doctor(raised);
    if (!report.bindable) {
      const codes = report.findings.filter((f) => f.severity === "error").map((f) => f.code).slice(0, 5).join(",");
      throw new OpsError("break_glass_doctor", `fiili yetki yükseltilmiş tavanla bağdaşmıyor veya bağlanılamadı (${codes || "bilinmiyor"})`);
    }
    const grant: BreakGlassGrant = {
      id: this.newId(),
      profileId: profile.id,
      kind: profile.kind,
      original: profile,
      raised,
      reason,
      startedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + req.ttlSec * 1000).toISOString(),
      reauth: req.reauth.method,
    };
    // Denetim ÖNCE: yazılamıyorsa break-glass başlamaz (fail-closed).
    try {
      await audit.append({
        event: "break_glass",
        sessionId: session.id,
        profile: profile.id,
        environment: profile.environment,
        breakGlass: grant.id,
        decision: "allow",
        message: `başlat tavan ${profile.classCeiling}→${req.ceiling} süre ${req.ttlSec}sn yeniden-doğrulama=${grant.reauth} bitiş=${grant.expiresAt} gerekçe=${reason}`,
      });
    } catch {
      throw new OpsError("audit_unavailable", "denetim kaydı yazılamadı: break-glass başlatılmadı");
    }
    session.startBreakGlass(grant);
    return grant;
  }

  /** Elle/oturum sonu bitirme. Önce tavan düşürülür (fail-safe), sonra denetlenir. */
  async end(profileId: string, why: "user" | "expired" | "rebind" | "session_end" = "user"): Promise<BreakGlassGrant | undefined> {
    const g = this.d.session.endBreakGlass(profileId);
    if (!g) return undefined;
    await this.d.audit
      .append({ event: "break_glass", sessionId: this.d.session.id, profile: g.profileId, environment: g.original.environment, breakGlass: g.id, decision: "deny", message: `bitir neden=${why}` })
      .catch(() => undefined);
    return g;
  }

  /** Süresi dolan hibeleri bitirir (zamanlayıcı ve oturum sonu için). */
  async sweep(): Promise<BreakGlassGrant[]> {
    const t = this.now().getTime();
    const out: BreakGlassGrant[] = [];
    for (const g of [...this.d.session.breakGlass.values()]) {
      if (Date.parse(g.expiresAt) <= t) {
        const e = await this.end(g.profileId, "expired");
        if (e) out.push(e);
      }
    }
    return out;
  }

  async endAll(why: "session_end" | "user" = "session_end"): Promise<BreakGlassGrant[]> {
    const out: BreakGlassGrant[] = [];
    for (const g of [...this.d.session.breakGlass.values()]) {
      const e = await this.end(g.profileId, why);
      if (e) out.push(e);
    }
    return out;
  }

  status(): BreakGlassStatus[] {
    const t = this.now().getTime();
    return [...this.d.session.breakGlass.values()].map((g) => ({
      id: g.id,
      profileId: g.profileId,
      environment: g.original.environment,
      from: g.original.classCeiling,
      to: g.raised.classCeiling,
      reason: g.reason,
      expiresAt: g.expiresAt,
      remainingSec: Math.max(0, Math.floor((Date.parse(g.expiresAt) - t) / 1000)),
    }));
  }
}

/** Kalıcı banner satırı (REPL ve onay ekranı): her etkin hibe için bir satır. */
export function breakGlassBanner(s: BreakGlassStatus): string {
  const m = Math.floor(s.remainingSec / 60);
  const sec = String(s.remainingSec % 60).padStart(2, "0");
  return `⚠ BREAK-GLASS ETKİN: ${s.profileId} [${s.environment}] tavan ${s.from} → ${s.to}, kalan ${m}:${sec} — gerekçe: ${clipOne(s.reason, 120)}`;
}

/**
 * Oturum sonu inceleme dosyası (`breakglass-review`): DENETİM KAYITLARINDAN üretilir (bellekten değil), böylece
 * hash zinciriyle korunan kayıtlarla birebir örtüşür. Break-glass süresince yazılan her kayıt `breakGlass`
 * alanıyla etiketlidir.
 */
export function renderBreakGlassReview(records: readonly AuditRecord[], sessionId: string): string | null {
  const mine = records.filter((r) => r.sessionId === sessionId);
  const events = mine.filter((r) => r.event === "break_glass");
  if (events.length === 0) return null;
  const ids = [...new Set(events.flatMap((r) => (r.breakGlass ? [r.breakGlass] : [])))];
  const lines = [`# Break-glass inceleme — oturum ${sessionId}`, "", `Üretildi: ${new Date().toISOString()} (denetim kayıtlarından; \`ops audit verify\` ile zincir doğrulanır)`, ""];
  for (const id of ids) {
    const ev = events.filter((r) => r.breakGlass === id);
    const start = ev.find((r) => r.decision === "allow");
    const end = ev.find((r) => r.decision === "deny");
    lines.push(`## ${id} — profil ${start?.profile ?? "?"} [${start?.environment ?? "?"}]`, "");
    lines.push(`- Başlangıç: ${start?.ts ?? "?"}`);
    lines.push(`- Bitiş: ${end?.ts ?? "(kayıt yok — oturum çökmüş olabilir)"}  ${end?.message ?? ""}`);
    lines.push(`- Ayrıntı: ${start?.message ?? "?"}`, "");
    const calls = mine.filter((r) => r.breakGlass === id && r.event !== "break_glass");
    const intents = calls.filter((r) => r.event === "intent");
    const results = calls.filter((r) => r.event === "result");
    lines.push(`### Bu süre içindeki çağrılar (${intents.length} niyet, ${results.length} sonuç)`, "");
    lines.push("| Zaman | Araç | Sınıf | Karar | Gerekçe kodu | Sonuç |", "|---|---|---|---|---|---|");
    const resultOf = new Map(results.map((r) => [r.callId, r]));
    for (const i of intents) {
      const res = i.callId ? resultOf.get(i.callId) : undefined;
      lines.push(`| ${i.ts} | ${i.tool ?? "-"} | ${i.class ?? "-"} | ${i.decision ?? "-"} | ${i.reasonCode ?? "-"} | ${res?.exitStatus ?? "(yok)"} |`);
    }
    const denied = results.filter((r) => r.exitStatus === "denied");
    for (const d of denied) lines.push(`| ${d.ts} | ${d.tool ?? "-"} | ${d.class ?? "-"} | deny | ${d.reasonCode ?? "-"} | denied |`);
    lines.push("");
  }
  lines.push("## İnceleme listesi", "", "- [ ] Gerekçe ve bilet/olay kaydı doğru mu?", "- [ ] Yukarıdaki çağrıların her biri beklenen müdahaleyle örtüşüyor mu?", "- [ ] Hedefte (kümede/veritabanında) kalıcı değişiklik doğrulandı mı?", "- [ ] Tavan geri döndü (bitiş kaydı var)?", "");
  return lines.join("\n");
}
