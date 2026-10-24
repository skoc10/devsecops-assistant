import { OpsError, riskRank } from "@ops/contracts";
import type { DoctorFinding, DoctorReport, Profile, RiskClass } from "@ops/contracts";
import type { PrivilegeFacts } from "./facts.ts";

export interface DoctorDeps {
  /** Bağlanır, korumaları uygular ve yetkileri okur. Pin uyuşmazlığı `target_pin_mismatch` OpsError'ı olarak atılır. */
  inspect(): Promise<{ identity: string; facts: PrivilegeFacts; loopback: boolean }>;
  now?: () => Date;
}

/**
 * Profil doktoru (PostgreSQL reader): bağlan → kimlik → pin → FİİLİ rol yetkileri ↔ beyan edilen tavan.
 * Beyan ≠ gerçek yetki; reader olarak etiketli bir rolün INSERT/CREATE/üstün yetkisi varsa profil
 * oturuma BAĞLANMAZ. Mesajlar secret içermez (yalnız kod/ad).
 */
export async function diagnose(profile: Profile, deps: DoctorDeps): Promise<DoctorReport> {
  const findings: DoctorFinding[] = [];
  const add = (severity: DoctorFinding["severity"], code: string, message: string): void => {
    findings.push({ severity, code, message });
  };
  const report = (over: Partial<DoctorReport>): DoctorReport => ({
    profileId: profile.id,
    checkedAt: (deps.now ?? (() => new Date()))().toISOString(),
    connected: false,
    pinOk: true,
    declaredCeiling: profile.classCeiling,
    scopesChecked: [],
    findings,
    ...over,
    bindable: over.bindable ?? false,
  });

  let got: Awaited<ReturnType<DoctorDeps["inspect"]>>;
  try {
    got = await deps.inspect();
  } catch (e) {
    if (e instanceof OpsError && e.code === "target_pin_mismatch") {
      add("error", "pin_mismatch", e.message);
      return report({ pinOk: false });
    }
    add("error", "connect_failed", e instanceof Error ? e.message.slice(0, 200) : "bağlantı kurulamadı");
    return report({});
  }
  const f = got.facts;

  if (f.role.superuser) add("error", "superuser", "rol SÜPER KULLANICI: reader olarak kullanılamaz");
  if (f.role.createRole) add("error", "createrole", "rol CREATEROLE yetkisine sahip");
  if (f.role.createDb) add("error", "createdb", "rol CREATEDB yetkisine sahip");
  if (f.role.replication) add("error", "replication", "rol REPLICATION yetkisine sahip");
  if (f.role.bypassRls) add("error", "bypassrls", "rol satır güvenliğini (RLS) atlıyor");
  for (const r of f.dangerousRoles) add("error", "dangerous_role", `rol '${r}' üyeliğine sahip (dosya/program/sinyal/yazma yetkisi)`);
  for (const r of f.broadReadRoles) add("warn", "reads_all_data", `rol '${r}' üyesi: tüm şemaları okuyabilir (izinli şema kapsamı yalnız istemci tarafında zorlanır)`);
  if (f.databaseCreate) add("error", "database_create", "rolün veritabanında CREATE yetkisi var");
  if (f.schemaCreate.length > 0) add("error", "schema_create", `şemalarda CREATE yetkisi var: ${f.schemaCreate.slice(0, 5).join(", ")}`);
  if (f.databaseTemp) add("warn", "temp_privilege", "TEMPORARY yetkisi var (PUBLIC varsayılanı; READ ONLY işlem geçici tablo oluşturmayı da engeller)");
  if (f.writableRelationCount > 0) {
    add("error", "write_privilege", `${f.writableRelationCount} ilişkide yazma yetkisi var (INSERT/UPDATE/DELETE/TRUNCATE): ${f.writableRelations.slice(0, 5).join(", ")}${f.writableRelationCount > 5 ? "…" : ""}`);
  }
  if (f.writableSequences.length > 0) add("warn", "sequence_privilege", `sekanslarda USAGE/UPDATE yetkisi var: ${f.writableSequences.slice(0, 3).join(", ")}`);
  for (const fn of f.dangerousFunctions) add("error", "dangerous_function", `tehlikeli fonksiyon çalıştırma yetkisi: ${fn.slice(0, 80)}`);
  for (const o of f.readableOutsideScopes) add("warn", "readable_outside_scopes", `izinli şemalar dışında okunabilen şema: ${o.schema} (${o.tables} tablo/view)`);
  for (const m of f.missingScopes) add("warn", "scope_missing", `izinli şema veritabanında yok: ${m}`);
  if (!f.transactionReadOnly) add("error", "read_only_guard_failed", "oturum salt-okunur kipe alınamadı");
  if (!f.tls && !got.loopback) add("error", "no_tls", "bağlantı TLS ile şifrelenmemiş");
  else if (!f.tls) add("info", "no_tls_loopback", "TLS yok (loopback)");

  let effective: RiskClass = "read";
  const raise = (c: RiskClass): void => {
    if (riskRank(c) > riskRank(effective)) effective = c;
  };
  if (f.writableRelationCount > 0 || f.dangerousRoles.length > 0) raise("mutate");
  if (f.databaseCreate || f.schemaCreate.length > 0 || f.role.createRole || f.role.createDb) raise("deploy");
  if (f.role.superuser || f.role.replication || f.role.bypassRls || f.dangerousFunctions.length > 0) raise("destroy");
  if (riskRank(effective) > riskRank(profile.classCeiling)) {
    add("error", "ceiling_exceeded_by_grants", `beyan edilen tavan '${profile.classCeiling}', fiili yetki '${effective}'; profil oturuma bağlanmaz`);
  }
  add("info", "server", `PostgreSQL ${f.serverVersion}`);

  const scopes = profile.allowedScopes.filter((s) => s !== "*");
  const bindable = !findings.some((x) => x.severity === "error");
  return report({ connected: true, identity: got.identity, effectiveClass: effective, scopesChecked: scopes.length ? scopes : ["*"], bindable });
}
