# Kimlik ve oturum ömrü

## 8. Kimlik ve oturum ömrü

### 8.1 Profil
**Secret olmayan tanımlayıcı** (`profiles.yaml`): `id`, `kind`, `display_name`, `environment` (`dev|stage|prod|sandbox`), `target_pin` (sunucu URL'si + CA parmak izi veya host:port), `class_ceiling` (`read|mutate|deploy|destroy`), `allowed_scopes` (ns / şema / repo / bölge), `credential_source` türü, `max_lease_ttl`, `egress_class` (bu profilin çıktısı hangi `trust_zone`'a gidebilir; prod DB varsayılanı `local`).
**Secret gövde** yalnız kasada: işletim sistemi anahtar zinciri veya şifreli yerel dosya (XChaCha20-Poly1305 / AEAD; anahtar passphrase + KDF'den, mümkünse anahtar zincirinde sarılı) **[doğrulanacak: `@napi-rs/keyring` ve libsodium bağlamaları]**. Sohbet, repo, model bağlamı, log ve denetim kaydı kasa değildir.

### 8.2 Kubeconfig içe aktarma (`ops profile add k8s`)
1. Dosya yalnız yerel okunur; **tek bağlam** (cluster+user+varsayılan ns) çıkarılır, diğerleri atılır.
2. Normalize: `server` ve CA pinlenir; `insecure-skip-tls-verify`, `proxy-url`, bilinmeyen alanlar uyarı/ret.
3. `exec` kimlik eklentisi varsa ikili yol+hash **ve argv şablonu** allowlist'e karşı kontrol edilir; şablon dışı komut/argüman → ret (§3.5). Eklenti yalnız broker tarafından, OS sandbox içinde çalıştırılır **[doğrulanacak: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins]**.
4. Secret gövde kasaya yazılır. **Özgün dosya ve ortam kimlikleri ürünün denetimi dışında kalır:** doktor, bilinen konumlardaki *ortam kimliklerini* (`~/.kube/config`, bulut CLI depoları; yalnız varlık ve izin bitleri, içerik okunmaz) listeler ve "bu makinede ürünün kontrol edemediği kimlikler var" uyarısı verir; özgün dosyanın güvenli taşınması/silinmesi önerilir. Ürün terminali ve dış ajan süreçleri bu yolları görmez (§3.6); kullanıcının kendi kabuğu ve diğer süreçleri görür.
5. **Doktor (`ops profile doctor`):** bağlan → `whoami`/kimlik yankısı → pinli sunucu/CA ile eşleşme → `can-i --list` ile **fiili** yetkiyi çıkar → beyan edilen `class_ceiling` ile karşılaştır. `read` beyan edilmiş ama `create/delete/patch/exec` veya `secrets get/list` var → **uyarı + profili `read` olarak işaretlemeyi reddet**. Beyan ≠ gerçek yetki; gerçek yetkiyi uzak RBAC belirler. Doktor yalnız import'ta değil, **her oturum başında bağlanacak profiller için** de çalışır (yetki kayması izlenir); fiili yetki beyan edilen tavanı aşıyorsa profil oturuma **bağlanmaz**.
6. Onboarding yardımcısı: "salt okunur kimlik yarat" için ClusterRole+Binding **manifest dosyası üretir** (uygulamaz); kullanıcı kendi süreciyle uygular.

### 8.3 Profil bağlama (kapsam)
- Oturumda profiller kullanıcı tarafından **açıkça** bağlanır (`/use k8s:<ad>`); varsayılan: **tür başına en fazla 1** bağlı profil. Aynı anda "açık bağlam" olarak iki küme yoktur. Karşılaştırma gerekirse yalnız **kullanıcının başlattığı** açık `compare` kipi (modele bırakılmaz): iki profil de `read` tavanlı olmalı; mutasyon araçları o kipte kapalı; her sonuç profil etiketli; mutasyon önerisinde karşılaştırma kanıtlarına atıf yapılamaz. Bu, "aynı anda tek açık bağlam" kuralının bilinçli ve sınırlı tek istisnasıdır.
- Her araç çağrısı `profile` taşır; model yalnız bağlı takma adlara başvurabilir.
- Ortam katmanı rozetleri istem satırında ve onay ekranında görünür; `prod` profillerinde mutasyon onayı **ortam adını yazdırarak** alınır.

### 8.4 Veritabanı: iki kimlik
| | reader | writer |
|---|---|---|
| Kasa girdisi | `db/<ds>#reader` | `db/<ds>#writer` (ayrı DB kullanıcısı, ayrı parola) |
| Varsayılan | **evet** | hayır; ancak onaylı işlemle |
| DB tarafı | yalnız izinli şemada `SELECT` (mümkünse yalnız **maskeli view'lara**); `TEMP`/`CREATE` yetkisi yok; `default_transaction_read_only=on`; `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` | gereken minimum DML/DDL |
| İstemci tarafı | AST **allowlist** sınıflayıcı: tek ifade; yalnız `SELECT`/`EXPLAIN` düğümleri; **izinli fonksiyon listesi** (denylist değil — fail-open olur); `SET`/`DO`/`CALL`/`COPY` yok; satır/süre/bayt limiti; sunucu tarafı imleç ile `FETCH` | onaylı ifade seti hash'i dışında hiçbir şey çalışmaz; tek transaction; etkilenen satır > onaylanan → ROLLBACK |
| Ömür | oturum boyunca havuzlanabilir (kısa idle) | tek işlem; çağrı sonunda bağlantı kapanır, lease düşer |
| Doktor | `has_*_privilege` ile yazma yetkisi olmadığını doğrular; varsa **reddeder** | yalnız Faz 2'de etkin |
Not: PostgreSQL `READ ONLY` işlem modu "disk yazımını tümüyle engellemez" ve komut listesiyle sınırlıdır **[doğrulandı: https://www.postgresql.org/docs/current/sql-set-transaction.html]**; bu yüzden tek başına güvenlik sınırı sayılmaz. **Katman bağımsızlığı (dürüst beyan):** araç yüzü (tavan), AST allowlist ve rol yetkisi birbirinden bağımsızdır; oturum `READ ONLY` ayarı kullanıcı düzeyinde `SET` ile geri alınabildiğinden AST allowlist'e *bağımlı* savunma derinliğidir, bağımsız katman sayılmaz. Doktor (oturum başı) rol yetkisini ve `TEMP` gibi yan yetkileri sınar.

### 8.5 Lease ve oturum yaşam döngüsü
| Nesne | Ömür | Sona erme |
|---|---|---|
| Lease (kimlik materyali) | Tek çağrı (+ az sayıda adım) | finally'de silinir (en iyi çaba, §3.5 sınırı); denetim "lease released" |
| Reader havuzu | Oturum boyunca, idle ≤ 5 dk | oturum kapanır / idle |
| Writer bağlantısı | Tek onaylı işlem | işlem biter/hata |
| Onay (approval) | Tek eylem hash'i; varsayılan 5 dk; tavan 15 dk | süre dolar → yeniden onay |
| Oturum politikası | Başlangıçta anlık görüntü; hash denetimde | politika değişirse yeni oturum |
| Oturum | Boşta ≤ 30 dk | onaylar ve lease'ler düşer |
| Break-glass | ≤ 30 dk, tek profil | otomatik geri dönüş |

**Kısa ömürlü kimlik:** statik kubeconfig varken de (lease olarak materyalize), bulut STS / workload identity / OIDC varken de (`CredentialSource` türü) aynı yoldan çalışır. Bulut tarafındaki somut akışlar (AWS AssumeRole, Azure workload identity, GCP impersonation) Faz 3'te ilgili adapter ile; sözleşme Faz 0'da hazır **[doğrulanacak: bulut sağlayıcı belgeleri]**.

### 8.6 Break-glass (Faz 2'de eklenir; Faz 0–1'de özellik yoktur)
`ops break-glass --profile <ad> --reason "<metin>" --ttl 30m`: gerekçe zorunlu; yeniden kimlik doğrulama (kasa parolası / OS biyometri); yalnız o profilin `class_ceiling`'ini geçici yükseltir; **denetim, redaksiyon ve çıktı boru hattını kapatmaz**; her çağrı "break-glass" etiketli; TUI'de kalıcı banner; süre bitince otomatik düşer; oturum sonunda `breakglass-review.md` üretilir. Denetim yazılamıyorsa break-glass da çalışmaz (fail-closed).


[← Belge dizini](00-overview.md#belge-dizini)
