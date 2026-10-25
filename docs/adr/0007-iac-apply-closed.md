# ADR-0007 — `iac.apply` / `ansible.run` bu sürümde KAPALI; açılırsa plan-hash'e bağlıdır

Durum: kabul (Faz 2e). Tarih: 2026-10.

## Bağlam
Tasarım (§7.5) `iac.apply` (deploy) ve `ansible.run` (deploy) araçlarını "varsayılan kapalı, açılırsa onaylanan plan = uygulanan plan" olarak öngörür. Faz 2e'de `iac.plan` (ağsız, kimliksiz, boş state'e karşı) ve `ansible.check` (yerel bağlantı) gerçek `tofu`/`terraform`/`ansible` ile gerçekleşti.

## Karar
`iac.apply` ve `ansible.run` **uygulanmadı ve kayıtlı değildir**. Nedenleri:

1. IaC araçları OS sandbox'ta **ağsız** koşar (sandbox ağ allowlist'i *Planned*). Uzak altyapıya (bulut API'leri, SSH) ulaşamayan bir `apply`, yalnız atılacak anlık kopyada/sandbox'ta etki eder; modele ve kullanıcıya "uygulandı" izlenimi verir (yanıltıcı).
2. Gerçek etki kimlik gerektirir: `cloud`/`host` profil türleri (lease, hedef pini, `inventory_scope`, `host_key_pins`) Faz 3'tür. Kimliksiz `apply` ya anlamsız ya da çevre kimliğine yaslanır (T15).
3. Tasarımın önerdiği yol zaten hedefin kendi pipeline'ıdır (PR → Atlantis/CI): ürün PR üretir (`scm.pr.create`), plan/apply'ı pipeline yapar.

## Açılması için gerekenler (kabul ölçütü)
- Sandbox ağ allowlist'i (kayıt defteri + hedef API uçları) ve profil pinli çıkış.
- `cloud`/`host` profili + lease (kimlik yalnız çağrı süresince, M3'e kayıtlı).
- Çalışma alanı kaydında açık `allowApply` (varsayılan `false`), araçlar yalnız o zaman ilan edilir.
- **Plan-hash bağlama**: `iac.plan` planı kaydeder (`planId`, plan dosyası sha256, yapılandırma özeti, state özeti); `iac.apply {planId}` yalnız o plan dosyasını uygular (`apply <planfile>`); eylem hash'i plan dosyası özetini ve yapılandırma/state özetini içerir; onaydan sonra herhangi biri değişirse `target_changed` (gateway TOCTOU yeniden önizlemesi — profilsiz yerel araçlar için de çalışacak şekilde genişletilmeli). Sınıf, planın içeriğinden türer: herhangi bir silme/yeniden yaratma → `destroy`, aksi `deploy`.
- `ansible.run`: önce aynı playbook+limit için başarılı `ansible.check`, `--limit` zorunlu ve `allowedScopes` içinde, `-vvv` yasak, SSH `StrictHostKeyChecking=yes` + pinli `known_hosts`, vault/become parolası fd ile.

## Sonuçlar
- Faz 2 bitiş senaryosundaki "`iac.apply`/`ansible.run` kapalıdır" maddesi doğrudan sağlanır.
- STATUS'ta bu araçlar **Planned (kapalı)** olarak görünür; "Faz 2 tamam" iddiası bunları kapsamaz.
