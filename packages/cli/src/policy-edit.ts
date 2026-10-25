import { createHash } from "node:crypto";
import { parseDocument } from "yaml";
import { OpsError } from "@ops/contracts";
import { diffFile } from "@ops/diff";
import { PolicyEngine, parsePolicy } from "@ops/policy";
import type { PolicyDocument, PolicyRule } from "@ops/policy";

/** "Hep izin" kuralının en uzun ömrü (T7: dar ve süreli). */
export const MAX_ALLOW_TTL_SEC = 30 * 24 * 3600;
export const DEFAULT_ALLOW_TTL_SEC = 8 * 3600;

const TOOL = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$/;

/** `8h`, `7d`, `30m` → saniye. */
export function parseTtlSec(text: string): number {
  const m = /^(\d{1,6})\s*([smhd])$/i.exec(text.trim());
  if (!m) throw new OpsError("usage", `süre geçersiz: '${text.slice(0, 20)}' (örnek: 30m, 8h, 7d)`);
  const mult = { s: 1, m: 60, h: 3600, d: 86400 }[(m[2] as string).toLowerCase() as "s" | "m" | "h" | "d"];
  return Number(m[1]) * mult;
}

export interface AllowRuleInput {
  readonly tool: string;
  readonly profile: string;
  readonly scope?: readonly string[];
  readonly ttlSec: number;
  readonly description?: string;
  readonly id?: string;
  readonly now: Date;
  /** Kayıtlı profil (kimlik/ortam/tavan doğrulaması için). */
  readonly registered: { readonly environment: string; readonly classCeiling: string } | undefined;
}

/** Dar "hep izin" kuralı kurar; kapsam dışı/geniş istekleri nedeniyle reddeder. */
export function buildAllowRule(i: AllowRuleInput): PolicyRule {
  if (!TOOL.test(i.tool)) throw new OpsError("policy_edit", `araç adı TAM ve geçerli olmalı (joker yok): ${i.tool.slice(0, 60)}`);
  if (!/^[a-z0-9][a-z0-9._-]{0,62}$/.test(i.profile)) throw new OpsError("policy_edit", `profil kimliği TAM ve geçerli olmalı (joker yok): ${i.profile.slice(0, 60)}`);
  if (!i.registered) throw new OpsError("policy_edit", `profil kayıtlı değil: ${i.profile} (yazım hatası mı?)`);
  if (i.registered.environment === "prod") throw new OpsError("policy_edit", "prod profili için 'hep izin' yazılamaz: prod mutasyonu her zaman sorar");
  if (i.registered.classCeiling === "read") throw new OpsError("policy_edit", `profilin tavanı 'read': mutasyon zaten reddedilir, izin kuralı anlamsız`);
  if (!Number.isInteger(i.ttlSec) || i.ttlSec < 60 || i.ttlSec > MAX_ALLOW_TTL_SEC) throw new OpsError("policy_edit", `süre 1 dakika ile ${MAX_ALLOW_TTL_SEC / 86400} gün arasında olmalı (süresiz izin yok)`);
  const scope = (i.scope ?? []).map((s) => s.trim()).filter(Boolean);
  for (const s of scope) if (!/^[A-Za-z0-9_.:\-/]{1,100}$/.test(s)) throw new OpsError("policy_edit", `kapsam geçersiz: ${s.slice(0, 40)}`);
  const stamp = i.now.toISOString().slice(0, 10).replace(/-/g, "");
  const id = i.id ?? `izin-${i.tool.replace(/\./g, "-")}-${i.profile}-${stamp}-${createHash("sha256").update(`${i.tool}|${i.profile}|${i.now.toISOString()}`).digest("hex").slice(0, 4)}`.toLowerCase();
  return {
    id,
    description: i.description ?? `${i.tool} için ${i.profile} profilinde süreli izin (${scope.length ? `kapsam ${scope.join(",")}` : "tüm izinli kapsamlar"})`,
    when: { tool: i.tool, profile: i.profile, class: ["mutate"], ...(scope.length ? { scope } : {}) },
    effect: "allow",
    expires: new Date(i.now.getTime() + i.ttlSec * 1000).toISOString(),
  };
}

/** Yorumları koruyarak kuralı ekler; sonucu şemadan geçirir (geçersizse atar). */
export function addRuleToText(text: string, rule: PolicyRule): string {
  const doc = parseDocument(text);
  if (doc.errors.length) throw new OpsError("policy_invalid", "policy.yaml ayrıştırılamadı");
  const rules = doc.get("rules");
  const current = rules && typeof (rules as { toJSON?: () => unknown }).toJSON === "function" ? ((rules as { toJSON(): unknown[] }).toJSON() as { id?: string }[]) : [];
  if (current.some((r) => r.id === rule.id)) throw new OpsError("policy_edit", `kural kimliği zaten var: ${rule.id}`);
  const node = doc.createNode(rule);
  if (rules && "items" in (rules as object)) {
    const seq = rules as { items: unknown[]; flow?: boolean };
    seq.flow = false; // `rules: []` akış biçimini blok biçime çevir
    seq.items.push(node);
  } else doc.set("rules", doc.createNode([rule]));
  const out = doc.toString({ lineWidth: 0 });
  parsePolicy(out); // şema + allow daraltma kuralları burada zorlanır
  return out;
}

export function removeRuleFromText(text: string, id: string): string {
  const doc = parseDocument(text);
  if (doc.errors.length) throw new OpsError("policy_invalid", "policy.yaml ayrıştırılamadı");
  const rules = doc.get("rules") as { items?: { toJSON(): { id?: string } }[] } | undefined;
  const idx = rules?.items?.findIndex((n) => n.toJSON().id === id) ?? -1;
  if (!rules?.items || idx < 0) throw new OpsError("policy_edit", `kural bulunamadı: ${id}`);
  rules.items.splice(idx, 1);
  const out = doc.toString({ lineWidth: 0 });
  parsePolicy(out);
  return out;
}

export const policyHash = (doc: PolicyDocument): string => new PolicyEngine(doc).versionHash;

/** Unified diff (yorum ve biçim değişiklikleri dahil); değişiklik yoksa boş. */
export function renderPolicyDiff(before: string, after: string): string {
  return diffFile("policy.yaml", before, after).patch;
}

export function renderRuleList(doc: PolicyDocument, now: Date): string {
  const lines = [`policy sürümü ${policyHash(doc).slice(0, 12)} — bütçeler: araç ${doc.budgets.maxToolCalls}, sonuç ${doc.budgets.maxResultTokens} tok, oturum yumuşak ${doc.budgets.softSessionTokens}/sert ${doc.budgets.hardSessionTokens}`];
  if (doc.rules.length === 0) lines.push("(kural yok: yalnız sabit taban davranış geçerli)");
  for (const r of doc.rules) {
    const expired = r.expires !== undefined && Date.parse(r.expires) < now.getTime();
    const w = Object.entries(r.when).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : String(v)}`).join(" ");
    lines.push(`${expired ? "✗ SÜRESİ DOLMUŞ" : "✓"} ${r.id}  ${r.effect.toUpperCase()}  ${w}${r.expires ? `  bitiş ${r.expires}` : ""}${r.description ? `\n    ${r.description}` : ""}`);
  }
  return lines.join("\n");
}
