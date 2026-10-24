import { OpsError, riskRank } from "@ops/contracts";
import type { DoctorFinding, DoctorReport, Profile } from "@ops/contracts";
import { CLUSTER_SCOPE } from "./kinds.ts";
import { analyzeRules } from "./rbac.ts";
import type { RbacRule } from "./rbac.ts";

export interface DoctorDeps {
  connect(): Promise<{ identity: string; targetFingerprint: string }>;
  rulesFor(namespace: string): Promise<{ rules: RbacRule[]; incomplete: boolean; evaluationError?: string }>;
  now?: () => Date;
}

const MAX_SCOPES = 5;

/**
 * Profil doktoru (k8s): bağlan → kimlik yankısı → pin → fiili RBAC ↔ beyan edilen tavan.
 * Beyan ≠ gerçek yetki; gerçek yetkiyi uzak RBAC belirler. `bindable=false` ise profil oturuma
 * bağlanmaz. Mesajlar secret içermez (yalnız kod/ad).
 */
export async function diagnose(profile: Profile, deps: DoctorDeps): Promise<DoctorReport> {
  const findings: DoctorFinding[] = [];
  const add = (severity: DoctorFinding["severity"], code: string, message: string): void => {
    findings.push({ severity, code, message });
  };
  const report = (over: Partial<DoctorReport>): DoctorReport => {
    const bindable = over.bindable ?? false;
    return {
      profileId: profile.id,
      checkedAt: (deps.now ?? (() => new Date()))().toISOString(),
      connected: false,
      pinOk: true,
      declaredCeiling: profile.classCeiling,
      scopesChecked: [],
      findings,
      ...over,
      bindable,
    };
  };

  let identity: string;
  try {
    ({ identity } = await deps.connect());
  } catch (e) {
    if (e instanceof OpsError && e.code === "target_pin_mismatch") {
      add("error", "pin_mismatch", e.message);
      return report({ pinOk: false });
    }
    add("error", "connect_failed", e instanceof Error ? e.message.slice(0, 200) : "bağlantı kurulamadı");
    return report({});
  }
  if (/^system:anonymous$/.test(identity)) add("error", "anonymous_identity", "kimlik anonim (system:anonymous): kimlik bilgisi sunucuca tanınmıyor");
  else if (identity === "bilinmiyor") add("warn", "identity_unknown", "sunucu kimlik yankısı vermedi (SelfSubjectReview yok); kimlik doğrulandı ama adı bilinmiyor");

  // Hangi namespace'ler denetlenecek?
  const declared = profile.allowedScopes.filter((s) => s !== CLUSTER_SCOPE && s !== "*");
  let scopes = declared.slice(0, MAX_SCOPES);
  if (scopes.length === 0) {
    scopes = ["default"];
    add("info", "scope_sampled", "izinli kapsam '*'/'cluster': yetki 'default' namespace'i üzerinden örneklendi");
  } else if (declared.length > MAX_SCOPES) {
    add("info", "scope_truncated", `yalnız ilk ${MAX_SCOPES} namespace denetlendi (${declared.length} var)`);
  }

  const union: RbacRule[] = [];
  const checked: string[] = [];
  for (const ns of scopes) {
    try {
      const r = await deps.rulesFor(ns);
      checked.push(ns);
      union.push(...r.rules);
      if (r.incomplete) add("warn", "rules_incomplete", `'${ns}' için kural listesi eksik olabilir (yetkilendirici tam liste vermedi)`);
      if (r.evaluationError) add("warn", "rules_evaluation_error", `'${ns}' için kural değerlendirme hatası bildirildi`);
    } catch (e) {
      add("warn", "rules_unavailable", `'${ns}' için yetki kuralları okunamadı: ${e instanceof Error ? e.message.slice(0, 160) : "hata"}`);
    }
  }
  if (checked.length === 0) {
    add("error", "rbac_unverified", "fiili yetki doğrulanamadı: profil güvenli sayılamaz");
    return report({ connected: true, identity });
  }

  const analysis = analyzeRules(union);
  for (const f of analysis.findings) {
    // Beyan edilen tavan yazmaya izin veriyorsa yazma bulguları uyarıdır; read için hatadır.
    if (f.code === "secrets_readable") {
      add(profile.classCeiling === "read" ? "error" : "warn", f.code, f.message);
    } else {
      add(riskRank(profile.classCeiling) >= riskRank(analysis.effective) ? "warn" : "error", f.code, f.message);
    }
  }
  if (riskRank(analysis.effective) > riskRank(profile.classCeiling)) {
    add("error", "ceiling_exceeded_by_rbac", `beyan edilen tavan '${profile.classCeiling}', fiili yetki '${analysis.effective}'; profil oturuma bağlanmaz`);
  }
  const bindable = !findings.some((f) => f.severity === "error");
  return report({ connected: true, identity, effectiveClass: analysis.effective, scopesChecked: checked, bindable });
}
