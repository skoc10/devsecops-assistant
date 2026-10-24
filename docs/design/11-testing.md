# Test

## 12. Test

**İlkeler:** hiçbir test gerçek üretim sistemine yazmaz; secret/kubeconfig fixture'ı **depoda yok** — sahte profil ve canary değerleri çalışma anında rastgele üretilir (geçici dizin, 0600); sahte küme kendi CA'sını üretir.

### 12.1 Üretime yazmayı yapısal olarak engelleyen kurallar
1. Testler **izole `OPS_HOME`** (geçici dizin; gerçek kasa ve profiller erişilemez) ile koşar; yüklenebilen tek profil, testkit'in çalışma anında ürettiği ve koşucuya özgü anahtarla imzaladığı sahte profillerdir (`test_fixture` etiketi bir *beyan* değil, **imza**). `environment: prod` etiketli profil testkit'te reddedilir.
2. CI ağı: yalnız loopback + paket deposu; hedef sistem adresleri allowlist dışı. (Asıl koruma CI ağ ilkesidir; yerel koşuda koruma izole `OPS_HOME` + sahte profil imzasıdır.)
3. Writer kimlikleri CI'da **yoktur**; Faz 2 yazma testleri yalnız efemer `kind` kümesi ve efemer PostgreSQL konteynerinde.
4. Gerçek Cursor API testleri varsayılan kapalı; açılırsa yalnız `tools: []` (araçsız) ve redakte bağlam.

### 12.2 Test kataloğu
| ID | Test | Ne gösterir | Faz |
|---|---|---|---|
| S-01 | **Kabuk sınıflayıcı atlatma külliyatı**: `;`, `&&`, `\|`, `$()`, backtick, heredoc, `--server=`, env öneki, `xargs`, `find -exec`, `kubectl get secret -o yaml`, unicode/boşluk hileleri (fuzz+property) | Sınıflanamayan/atlatma = `destroy` muamelesi/ret; sınıf doğru | 1 |
| S-02 | **SQL sınıflayıcı külliyatı**: çoklu ifade, CTE içinde DML, `SELECT … FOR UPDATE`, `SELECT INTO`, `COPY … TO PROGRAM`, `pg_terminate_backend`, `lo_import`, `dblink`, `SET ROLE`, `SET default_transaction_read_only=off`, `DO`, `EXPLAIN ANALYZE <DML>`, dolar-quote/yorum hileleri | Yalnız izinli düğümler geçer | 1 |
| S-03 | **Reader ile yazma reddi:** *bağımsız* katmanlar (araç yüzü/tavan, AST allowlist, rol yetkisi) tek tek devre dışı bırakılır; kalanlar yine durdurur. Oturum `READ ONLY` ayarı ayrıca *bağımlı* katman olarak sınanır: AST allowlist kapatılınca `SET` ile geri alınabildiği gösterilir (bu yüzden bağımsız sayılmaz). k8s: reader profil için yazma aracı yok + RBAC 403 | Tek hata noktası yok | 0 (k8s) / 1 (DB) |
| S-04 | **Yanlış hedef reddi:** pin uyuşmazlığı (farklı sunucu/CA), kapsam dışı ns/şema, tür uyuşmazlığı (db aracı + k8s profili), bağlı olmayan profil, takma ad çakışması | PEP adım 2–3 (WP3); profil düzeyinde pin kontrolü `connectCheck` (WP4) | 0 |
| S-05 | **Yanlış profil/atıf:** staging kanıtına atıfla prod mutasyonu önerisi → ret | Kanıt-hedef eşleşmesi | 2 |
| S-06 | **Canary sızıntı:** kasada, sahte kümede (Secret, env, log, event), DB hücresinde, CI logunda, kullanıcı girdisinde rastgele canary; **ham/base64/URL-encoded/bölünmüş** varyantlar. Altı kanal: sağlayıcıya giden her bayt (yakalayıcı), denetim, UI akışı, stdout/stderr, hata-çökme çıktıları, geçici dosyalar. **Dış ajan ayağı:** SDK içinden çıkan baytlar gözlenemediğinden, `cursor-host`'a verdiğimiz her bayt (görev metni + IPC ile dönen araç sonuçları) yakalanır ve canary içermediği doğrulanır; SDK'nın kendi diskten okuması ise araç allowlist'i + OS sarmalayıcı ile engellenir (S-10) | **Sıfır eşleşme** | 0 → |
| S-07 | **Enjeksiyon senaryosu:** scripted modelle "log içindeki talimat → `delete`" tepkisi simüle edilir → tavan (Faz 0), taint etiketlerinin hesabı (Faz 0, birim), taint tabanlı `ask` (Faz 1: staging logu + prod DB okuma denemesi), mutasyon yolu (Faz 2); (CI dışı) gerçek modellerle kırmızı takım eval seti | Politika, modelin iyi niyetine bağlı değil | 0 / 1 / 2 |
| S-08 | **Denetim:** yazma hatası simülasyonunda çağrı **çalışmaz**; bayt değişimi/silme/sıra değişimi `verify` ile yakalanır | Fail-closed + tamper tespiti | 0 |
| S-09 | **Onay:** TOCTOU (hedef sürümü değişti → ret), eylem hash uyuşmazlığı, süre aşımı, onay bütçesi/soğuma, "hep izin" kapsam daralması | Onay yorgunluğu kontrolleri | 2 |
| S-10 | **Dış ajan atlatma (sahte Cursor SDK):** (a) kabuk açık yapılandırma → sağlayıcı reddi, (b) çalışma zamanında izinsiz `tool_call` adı → iptal+alarm, (c) resume'da seçenek eksik → **araçsız**, (d) ajan süreci env'inde canary yok, (e) hook deny-all, (f) OS sarmalayıcıda kimlik yolları / D-Bus / ağ erişilemez | Serbest kabuk yolu yok | 0 (WP8) |
| S-11 | **Break-glass:** gerekçesiz/TTL'siz ret; denetim kapatılamaz; TTL sonunda düşme; inceleme dosyası | Denetimsiz break-glass yok | 2 |
| S-12 | **Argüman enjeksiyonu / yerel API:** yasak bayraklar, `additionalProperties`, UDS izinleri ve belirteç, `ps`'te secret yok | CVE-2026-47250 sınıfı | 0 |
| S-13 | **Model değişimi değişmezliği:** aynı scripted çağrı dizisi farklı sağlayıcı kipleriyle aynı politika kararı ve denetim alanlarını üretir | "Model değişince yetki değişmez" | 0 |
| S-14 | **Doktor kayması:** oturum başı yeniden doğrulama; RBAC / rol sonradan genişletilince profil oturuma bağlanmaz | Beyan ≠ fiili yetki | 0 (k8s) / 1 (DB) |
| S-15 | **Terminal sandbox / ortam kimliği:** `shell.run` içinden `~/.kube/config`, `~/.aws`, `~/.ssh`, D-Bus, `KUBECONFIG` env'i erişilemez; HOME izole; ağ kapalı; `report.write` → `.git/config` → `git status` zinciri engellenir; exec eklentisi şablon dışı argümanla çalıştırılamaz | Ortam kimliği yolu yok | 0 (eklenti şablonu) / 1 (terminal) |
| S-16 | **Onay kanalı:** alt süreç (sahte cursor-host / skill betiği) araç soketinden onay veremez; `/dev/tty` dışı onay reddedilir | Onay kimlik doğrulaması | 1 (v0) / 2 |
| S-17 | **HCL ön-taraması + sandbox:** `data "external"`, provisioner, uzak modül, registry dışı sağlayıcı, gömülü kimlik içeren fixture'lar → deny/`ask`; sandbox'ta `init/validate` yalnız allowlist'li kayıt defterine/aynaya bağlanır; lock hash farkı `ask` | T18: IaC kod yürütme yüzeyi | 1b |
| S-18 | **Ansible sınıflama + ön-tarama:** modül sınıf kataloğu, `check_mode: false`, `lookup('pipe')`, `local_action`, özel plugin dizini, repodaki `ansible.cfg` → doğru sınıf/`ask`; `StrictHostKeyChecking=yes` zorunlu; `-vvv` reddi | T19 | 1b / 2 |
| S-19 | **IaC gizli dosya canary:** worktree'ye rastgele canary içeren `*.tfstate`, `*.tfvars`, vault dosyası, envanter parolası ve plan JSON'da `sensitive` bayraklı değer; `fs.read`/`iac.*`/`evidence.get` yollarında model yüküne ve denetime sızmaz; gömülü secret yazımı reddedilir | T20 | 1b (plan JSON: 2) |
| S-20 | **Worktree izolasyonu ve CI tanımı yasağı:** kullanıcının çalışma kopyasına yazılamaz; `write_paths` dışına, `.git/`'e ve `.github/**`'e yazım reddedilir; symlink ve `..` kaçışı | T16, T21 | 1b |
| B-01 | **Başlangıç öneki boyutu:** sistem + çekirdek araçlar + skill metaverisi token tahmini ≤ eşik; yeni skill/araç eklenince fark raporlanır | Önek şişmesi regresyonu | 0 (WP7) |
| B-02 | **Skill linter:** `skills-ref validate` + gövde ≤500 satır / ≤5000 token tahmini, `description` ≤1024, yetki talebi şeması, `scripts/` hash'i | Skill kalitesi ve maliyeti | 1 |
| B-03 | **Referansla taşıma:** tavanı aşan araç sonucu modele ham gitmez; `evidence_id` + kompakt görünüm; `evidence.get` dilimi doğru ve redakte; kompaktlaştırma redaksiyondan **sonra** (canary kompakt görünümde de yok) | Token tavanı + sızıntı | 0 (WP2/WP5) |
| B-04 | **Token bütçesi regresyonu:** E-xx senaryolarında toplam token (girdi/çıktı/araç sonucu) baz çizgi +%10'u aşarsa CI kırmızı; `ops usage` kırılımı doğru | Maliyet regresyonu | 0 (WP7) / 1 |
| B-05 | **Önek kararlılığı:** aynı oturumda önek bayt-bayt aynı; araç sırası deterministik; skill etkinleşince yalnız eklenen blok değişir | İstem önbelleği isabeti | 1 |
| C-xx | **Adapter conformance paketi:** sınıf beyanı, limit, redaksiyon kancası, secret sızıntısı yok, hedef beyanı, yanlış hedef reddi, hata mesajı redaksiyonu | Her yeni adapter aynı testten geçer | 0 → |
| I-01 | `kind` entegrasyonu (k8s okuma) | Gerçek API davranışı | 0 |
| I-02 | Efemer PostgreSQL: reader/writer rolleri, doktor | Katman 4 gerçek | 1 / 2 |
| I-03 | GitHub Actions kayıt/yeniden oynatma fixture'ları (sanitize) | Ağsız deterministik | 1 |
| E-xx | **Faz bitiş senaryoları** scripted model ile uçtan uca | Faz kabul ölçütü | 0 → |
| R-01 | Skill/sağlayıcı **eval seti**: kasıtlı bozuk dağıtımlar; kök neden bulundu mu (CI dışı, maliyetli) | Kalite takibi | 1 |


[← Belge dizini](00-overview.md#belge-dizini)
