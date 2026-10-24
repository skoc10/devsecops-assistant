# Ürün sınırı ve kurulum modeli

## 1. Ürünün sınırı

**Kullanıcı:** platform / DevOps / SRE / güvenlik mühendisi; kendi makinesinde, kendi kimlikleriyle çalışır. Ürün bir şirkete ait değildir; bir kuruma özgü isim, URL, repo, runbook ya da politika gömülü gelmez.

**Yapar**
- Sohbetle soru cevaplar; cevabı **kanıt kimlikleriyle** (`evidence_id`) destekler.
- Bağlı kaynaklardan salt okunur kanıt toplar: küme, pipeline, git, kayıt deposu, gözlemlenebilirlik, veritabanı, tarayıcı sonuçları, hedef sistemin politikası.
- Birden çok kaynaktan gelen kanıtı deterministik anahtarlarla (image digest, commit SHA, workload kimliği, zaman penceresi) tek zaman çizelgesinde birleştirir.
- Değişikliği **önce gösterir**: diff, server-side dry-run, etki alanı, geri alma planı. Öneriyi `ChangeSet` dosyası veya hedef sistemin kendi onay mekanizması üzerinden (PR) çıkarır.
- Politikanın izin verdiği sınıfta, kullanıcı onayıyla dar kapsamlı işlem yapar (Faz 2+).
- **Altyapı kodu yazar:** Terraform/OpenTofu modülleri ve Ansible playbook/rol'leri; `fmt/validate/lint/scan` döngüsüyle doğrular, `plan`/`--check` sonucunu özetler ve PR olarak önerir (§7.5). Kullanıcının kendi kod stilini skill/proje yönergesi olarak getirir; ürüne gömülü kurum standardı yoktur.
- Kullanıcının runbook'unu çalıştırır; yoksa genel teşhis akışını kullandığını **açıkça söyler**.

**Yapmaz**
- Kendi tarayıcısını (SAST/SCA/imaj tarayıcı) yazmaz; mevcut araca bağlanır ve sonucunu okur.
- Kendi politikasını *hedef sistem için* uydurmaz; OPA/Kyverno/bulut politikasını bağlı kaynaktan okur. (Ürünün kendi **erişim politikası** ayrı bir şeydir, bkz. §3.4.)
- Kimlik deposu değildir; sohbet, repo ve model bağlamı kasa değildir.
- Hedef sistemin onay mekanizmasını (branch koruması, admission, change board) atlamaz.
- Gözlemlenebilirlik verisi depolamaz, ticket/incident yönetmez, kubectl'in yerine geçmez.
- Ekip sunucusu, çok kullanıcılı veya çok kiracılı SaaS değildir; tek kullanıcının kendi makinesinde çalışır.
- IaC'yi (Terraform `apply`, `ansible-playbook` gerçek koşu) varsayılan olarak kendi başına uygulamaz; kod ve plan üretir, uygulamayı hedefin pipeline'ına bırakır. Doğrudan uygulama Faz 2'de politika + onayla açılabilir.
- Serbest kabuk vermez: kabuk bir araçtır, sınıflanır, denetlenir.

## 2. Kurulum modeli

| Seçenek | Artı | Eksi | Karar |
|---|---|---|---|
| A. Tek kullanıcılı yerel uygulama | Kimlik makineden çıkmaz; OS anahtar zinciri; ağ erişimi (VPN, bastion) zaten kullanıcıda; hava boşluğu doğal; saldırı yüzeyi küçük | Ekip paylaşımı, ortak denetim yok | **v1** |
| B. Ekip sunucusu | Merkezi kasa, merkezi denetim, ortak skill/politika | Çok kullanıcılı yetkilendirme, kimlik ödünç verme (confused deputy), sunucu ele geçirme = tüm kimlikler, OIDC/RBAC işi | **Planda yok** (kullanıcı kararı); ileride istenirse ayrı bir tasarım turu |

**Kapsam:** yalnız tek kullanıcı. Tüm durum kullanıcının `OPS_HOME` dizini altındadır; `SecretStore` (anahtar zinciri / şifreli dosya) ve `AuditSink` arayüzleri **test edilebilirlik ve platform farkları** için vardır, çok kullanıcılı genişleme için değil. Denetim kaydındaki `principal` alanı sabittir (`local-user`). UI ile çekirdek arasında yerel API (Unix domain socket, 0600): UI çekirdeğin içinde değil, istemcisidir. Ekip sunucusuna hazırlık amaçlı hiçbir soyutlama eklenmez (D12).

**Arayüz v1:** `ops` CLI + TUI (sohbet, onay istemi, denetim görüntüleme). Yerel web arayüzü ve masaüstü paketi (Tauri/Electron) Faz 3+. Gerekçe: onay istemini model metninden bağımsız, **PEP'in render ettiği kanonik eylem özeti** olarak göstermek için TUI yeterli ve en küçük yüzeydir.

**Çevrimdışı/hava boşluklu mod:** `egress: local-only` çalışma kipi — yerel model + yalnız profilde pinli hedeflere erişim + telemetri kapalı + yalnız `read`. Basit kip Faz 1; tam paket (çevrimdışı kurulum, imzalı skill paketi, yerel sağlayıcı/ayna) Faz 3.


[← Belge dizini](00-overview.md#belge-dizini)
