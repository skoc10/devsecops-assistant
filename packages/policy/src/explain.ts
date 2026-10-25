import { REASON_CODES } from "@ops/contracts";
import type { ReasonCode } from "@ops/contracts";

/** `ops explain-policy`: her makine-okur sebep kodunun insan-okur açıklaması ve çözüm yolu. */
export const REASON_EXPLANATIONS: Readonly<Record<ReasonCode, string>> = {
  allowed: "İzin verildi: sınıf profil tavanı içinde ve onay gerektiren bir koşul yok.",
  schema_invalid: "Argümanlar aracın katı şemasına uymuyor (fazladan/eksik alan). Argüman enjeksiyonuna karşı ek alanlar reddedilir.",
  unknown_tool: "Araç kayıtlı değil veya ilgili araç seti etkin değil. Önce ilgili skill'i skill.load ile yükleyin.",
  profile_not_bound: "Bu tür için oturuma bağlı profil yok. Kullanıcı /use <profil> ile bağlamalı (doktor geçmeli).",
  profile_unknown: "Çağrıda profil belirtilmedi; ortamda 'current context' yoktur.",
  kind_mismatch: "Araç türü ile profil türü uyuşmuyor (ör. veritabanı aracı + k8s profili).",
  target_unresolved: "Hedef çözümlenemedi (eksik/geçersiz namespace, tür veya zaman penceresi).",
  target_pin_mismatch: "Çözülen hedef profilin pinli uç noktasıyla (URL/CA parmak izi) eşleşmiyor; kimlik gönderilmedi.",
  scope_violation: "Hedef kapsam (namespace/şema/repo) profilin izinli kapsamlarında değil. Profilin allowedScopes listesini gözden geçirin.",
  ceiling_exceeded: "İşlem sınıfı profilin sınıf tavanını (class_ceiling) aşıyor. Faz 0–1'de tavan 'read'tir; yükseltme bilinçli bir profil kararıdır.",
  ceiling_requirement: "Araç, profilden daha yüksek bir tavan ister (ör. sunucu tarafı dry-run).",
  unclassified: "Komut/ifade sınıflanamadı; güvenlik için 'destroy' muamelesi görür. Çözüm: komut kataloğuna ekleyip sınıflayın.",
  policy_deny: "policy.yaml'daki bir 'deny' kuralı eşleşti (kural kimliği ayrıntıda).",
  taint_escalation: "Bağlamda UNTRUSTED içerik (log, olay, dosya) var ve işlem mutasyon, başka profile okuma, daha hassas veriye okuma veya dış ağ çıkışı: en az onay gerekir.",
  approval_required: "İşlem sınıfı (mutate+) veya yerel yazma nedeniyle onay gerekir.",
  policy_ask: "policy.yaml'daki bir 'ask' kuralı eşleşti (kural kimliği ayrıntıda).",
  approval_unavailable: "Onay gerekti ama onay kapısı yok (ör. TTY'siz daemon). Çağrı güvenli tarafta reddedildi.",
  approval_denied: "Kullanıcı reddetti, zaman aşıldı veya doğrulama metni eşleşmedi.",
  citation_missing: "Mutasyon, hedefi içeren taze bir kanıta atıf yapmadı (aynı profil/çağ, ≤ 30 dk).",
  audit_unavailable: "Denetim kaydı yazılamadı; denetimsiz çalışmamak için çağrı çalıştırılmadı (fail-closed).",
  no_eligible_provider: "Bağlam, model sağlayıcısının bölgesine gidemeyecek kadar hassas (egress). Yerel sağlayıcı kullanın veya temiz bir oturum başlatın.",
  token_budget_exceeded: "Oturum token bütçesi (sert eşik) aşıldı. Yeni oturum başlatın veya policy.yaml budgets'ı gözden geçirin.",
  call_budget_exceeded: "Oturumdaki en çok araç çağrısı sayısı aşıldı.",
  adapter_error: "Adapter işlemi başarısız oldu (ör. API hatası, kimlik bağlanamadı). Ayrıntı mesajdadır.",
  timeout: "Araç zaman aşımına uğradı veya iptal edildi.",
  local_only: "`egress: local-only` kipi: yalnız YEREL (local) model sağlayıcısı ve yalnız okuma sınıfı çalışır. Yerel bir sağlayıcı yapılandırın veya kipi kapatın (OPS_EGRESS / --local-only).",
  quarantined: "Bu kanıtın ham içeriği KARANTİNADA: serbest metin (log/olay/diff) ana modele verilmez, yalnız tipli özeti verilir. Ham içeriği görmek için `/show <id>` (yalnız ekranınıza), modele açmak için `/raw <id>` (bağlam güvenilmez içerik alır).",
  target_changed: "Onaydan sonra hedefin sürümü/içeriği DEĞİŞTİ (TOCTOU): onaylanan eylem artık geçerli değil, hiçbir şey uygulanmadı. İncelemeyi yenileyip yeniden onay verin.",
  preview_failed: "Mutasyon önizlemesi (diff/etki/sürüm) üretilemedi; neyi onaylayacağınız gösterilemediği için çağrı reddedildi (fail-closed).",
};

export function explainReason(code: string): string {
  return (REASON_EXPLANATIONS as Record<string, string>)[code] ?? `Bilinmeyen sebep kodu: ${code}`;
}

/** Eksik açıklama kalmasın diye testte kullanılır. */
export const ALL_REASON_CODES: readonly ReasonCode[] = REASON_CODES;
