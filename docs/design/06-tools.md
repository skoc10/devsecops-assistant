# Araç listesi

## 7. v1 araç listesi

**Sınıf tanımları** (hedef sisteme etkisi). İki ek eksen: **`scope`** = `target | local` (yerel dosya yazımı `local-write`: yalnız `workspace/out/`, noktalı dosya / `.git/` / çalıştırılabilir bit yasak; yukarıdaki sıralamanın dışındadır) ve **`network`** = `none | allowlisted | open` (`read` sınıfı `open` ağ çıkışlı komutu kabul etmez). Sınıflanamayan her şey `destroy` muamelesi görür.
- `read` — hedefte yan etki yok. Sorgu maliyeti bile sınırlıdır (limit/zaman aşımı).
- `mutate` — canlı durumu veya veriyi geri alınabilir biçimde değiştirir (scale, annotate, SQL DML, PR açma).
- `deploy` — yeni sürüm/artefakt devreye alır veya yayılımı tetikler (apply, rollout, sync, pipeline tetikleme).
- `destroy` — geri alınamaz silme/bırakma (delete, DROP, TRUNCATE, `terraform destroy`). Varsayılan: kapalı.

**Maskeleme teknikleri** (çıktı boru hattında, adapter'ın **dışında** ve atlanamaz)
| Kod | Teknik | Not |
|---|---|---|
| M1 | Yapısal reddet listesi | Alan/tür at: `Secret.data`, kubeconfig benzeri yapılar, `managedFields`, `Authorization` başlıkları |
| M2 | Desen + entropi | Bulut anahtarı, JWT, PEM bloğu, parolalı bağlantı dizesi, token önekleri; kural seti gitleaks tarzı bakımlı bir listeden **[doğrulanacak: https://github.com/gitleaks/gitleaks — config/gitleaks.toml]** |
| M3 | Bilinen-secret taraması | Broker'ın o oturumda verdiği her değer ve base64/URL-encoded varyantları |
| M4 | Alan/kolon maskesi | `masking.yaml` (email, telefon, kart, kimlik no, token, parola → hash/kısalt/at). **Üç parça:** (a) *AST kuralı* — maskeli sütunlar yalnız doğrudan seçim öğesi olarak kullanılabilir; ifade/fonksiyon içinde (`lower(email)`), `to_jsonb(t)`/`row_to_json`, tam-satır referansı veya maskeli tabloda `SELECT *` → **ret/yeniden yazım**; (b) *köken* — sürücü sütun kökenini veriyorsa (`columnOrigin`) o sütuna kural uygulanır; (c) *değer dedektörleri* — kökeni bilinmeyen sütunlarda tüm hücrelere PII dedektörleri (email, telefon, Luhn'lu kart, kimlik no kalıpları). **En güçlüsü DB tarafıdır:** reader rolü yalnız **maskeli view'lara** yetkilidir (ürün view betiğini dosya olarak üretir, uygulamaz). M4 tek başına garanti değil, ikinci hat (`Best-effort`) |
| M5 | Boyut/satır limiti | Açık "kesildi" işareti ve toplam sayı |
| M6 | Taint zarfı | Serbest metin `untrusted` zarfında; zarf tek başına güvenlik sınırı **değildir** (bkz. §9-T2) |

### 7.1 Faz 0 — Kubernetes (profil türü: `k8s`)
| Ad | Sınıf | Çıktı / maskeleme |
|---|---|---|
| `k8s.profile.describe` | read | Yalnız secret olmayan tanımlayıcı: ad, ortam, sunucu host'u, izinli ns'ler, sınıf tavanı. Kimlik içeriği yok (M1) |
| `k8s.resources.list` | read | M1: `Secret` türü varsayılan reddedilir (yalnız ad/tür/anahtar adları); `managedFields` atılır; pod env'de `secretKeyRef` yalnız referans; M2; M5 (≤200 öğe) |
| `k8s.resources.get` | read | Aynı kurallar, tek nesne; ConfigMap değerleri anahtar adı desenine göre (`*token*`, `*password*`, `*key*`) maskeli |
| `k8s.resources.describe` | read | Birleşik görünüm (spec+status+olaylar); aynı kurallar |
| `k8s.events.list` | read | Zaman penceresi zorunlu; mesaj M2; `untrusted_output` |
| `k8s.pods.logs` | read | `since` zorunlu, satır ve bayt sınırı, önceki container opsiyonel; M2+M3; `untrusted_output` (enjeksiyon yüzeyi #1) |
| `k8s.auth.can_i` | read | Yalnız profilin kendi kimliği için `SelfSubjectAccessReview/RulesReview`; çıktı kural listesi |
| `k8s.workload.health` | read | Deterministik türetilmiş yapı: rollout durumu, replika, restart, OOMKilled, probe, HPA, PDB, düğüm baskısı; serbest metin yok |

### 7.2 Faz 1 — Pipeline, SCM, PostgreSQL reader, korelasyon
| Ad | Sınıf | Profil | Çıktı / maskeleme |
|---|---|---|---|
| `pipeline.runs.list` / `pipeline.run.get` / `pipeline.jobs.list` | read | `pipeline` | Meta; zaman penceresi ve limit zorunlu |
| `pipeline.job.logs` | read | `pipeline` | Platformun kendi maskesine **ek olarak** M2+M3; bayt sınırı; `untrusted_output` |
| `pipeline.workflow.definition` | read | `pipeline`/`scm` | Dosya içeriği M2; deterministik kural kontrolleri (pinsiz action, geniş izin, tetikleyici riskleri) ürün kuralı değil **skill + kural dosyası** |
| `pipeline.artifacts.list` | read | `pipeline` | Yalnız meta ve digest |
| `scm.file.read` | read | `scm` | Secret-dosya desen denylist (`.env`, `*.pem`, özel anahtar adları) → reddet; M2 |
| `scm.diff.get` / `scm.pr.list` / `scm.commit.list` | read | `scm` | Meta ve diff; M2; diff `untrusted_output` |
| `db.datasource.describe` | read | `db#reader` | Ad, tür, ortam, rol=reader, limitler; bağlantı bilgisi yok |
| `db.schema.describe` | read | `db#reader` | Yalnız katalog; veri yok; kolon etiketleri maske politikasıyla birlikte |
| `db.query.read` | read | `db#reader` | Sınıflayıcı + reader + limit (varsayılan ≤500 satır, ≤10 sn, ≤256 KiB); M4 kolon maskesi; hücre değerlerine M2/M3; model "kesildi mi + toplam sayı" meta'sını görür |
| `db.query.explain` | read | `db#reader` | Yalnız `EXPLAIN` (`ANALYZE` yok); plan metni |
| `db.stats.summary` | read | `db#reader` | Bağlantı/kilit/uzun sorgu/boyut/replikasyon gecikmesi; sorgu metnindeki literaller maskelenir |
| `timeline.build` | read (yerel) | — | Yalnız kanıt deposundan; deterministik anahtarlar (§3.9) |
| `k8s.policy.reports` | read | `k8s` | Kyverno PolicyReport / Gatekeeper durumu (CRD varsa) |

### 7.3 Terminal ve çekirdek araçlar
| Ad | Sınıf | Profil | Not |
|---|---|---|---|
| `shell.run` | hesaplanır | yok | Kimliksiz; OS sandbox, izole HOME, ağ kapalı (§3.6); **Faz 1'den itibaren**; Faz 1'de yalnız kataloğun `read` kısmı |
| `shell.run_profiled` | hesaplanır | ilgili tür | Yalnız katalogdaki ikili+alt komut+bayrak; kimlik broker'dan; yasak bayraklar: `--server`, `--token`, `--kubeconfig`, `--insecure-skip-tls-verify`, `--as` |
| `skill.list` / `skill.load` | read (yerel) | — | Skill gövdesi bağlama alınır; `trust_tier` etiketlenir |
| `evidence.get` / `evidence.search` | read (yerel) | — | Yalnız redakte kanıt; `select` (alan/JSONPath), `limit`, `offset`; büyük sonuçlar bağlama **yalnız bu araçla, dilimlenerek** girer (§4.5-5) |
| `change.propose` / `report.write` | local-write | — | Yalnız `workspace/out/`; noktalı dosya, `.git/`, çalıştırılabilir bit yasak; `shell.run` çalışma dizini `out/` dışında; ilk kullanımda sorar |

### 7.4 Faz 2 — onaylı değişiklik araçları
| Ad | Sınıf | Not |
|---|---|---|
| `k8s.apply.diff` | read (etki) | İki kip: `client` (canlı nesneyi `get` ile al + yerel diff; **yalnız okuma RBAC'ı**) ve `server-dry-run` (sunucu tarafı dry-run; hedefte **yazma RBAC'ı** ister → yalnız `class_ceiling ≥ mutate` profillerinde, read-tavanlı profilde yok; doktorla çelişmez). **Her apply'dan önce zorunlu** |
| `k8s.apply` / `k8s.rollout.undo` | deploy | Onay eylem hash'ine bağlı; hedef `resourceVersion`/digest yeniden doğrulanır |
| `k8s.scale` / `k8s.rollout.restart` | mutate | Dar kapsam: tek workload |
| `k8s.exec` | mutate | Her zaman `ask`; varsayılan `deny` |
| `k8s.resources.delete` | destroy | Varsayılan kapalı; yalnız break-glass veya açık politika |
| `scm.pr.create` | mutate | **Yalnız PR**; korumalı dala doğrudan yazma yok; hedefin kendi onayı geçerli |
| `pipeline.run.rerun` / `pipeline.run.cancel` | deploy / mutate | |
| `db.change.propose` | read | SQL dosyası + sınıf + etki tahmini; çalıştırmaz |
| `db.change.apply` | mutate / destroy | Writer lease; onaylı ifade seti hash'i; tek transaction; satır sayısı sınırı aşılırsa ROLLBACK |

Faz 3 araç aileleri: `cloud.*`, `registry.*`, `obs.*`, `gitops.*`, `scanner.*`, `policy.*` (§5.4 tablosuyla aynı şekil).

### 7.5 Altyapı kodu: Terraform/OpenTofu ve Ansible (D16)
**Çalışma alanı modeli.** `ops workspace add <yol>` ile kaydedilen secret olmayan tanımlayıcı: `{path, vcs, engine: terraform|opentofu|ansible, write_paths (glob), deny_paths}`. Ajan kullanıcının çalışma kopyasına **yazmaz**: her oturum için `git worktree` açılır (`$OPS_HOME/worktrees/<oturum>`); değişiklik **dal + diff** olarak çıkar, kullanıcı birleştirir veya §7.4'teki `scm.pr.create` ile PR olur. Varsayılan `deny_paths` (okuma ve yazma): `.git/`, `*.tfstate*`, `.terraform/`, `*.pem`, `*.key`, `id_*`, `.env*`; `*.tfvars`/`*.auto.tfvars` okuma ve yazma `ask`; `$ANSIBLE_VAULT;` başlıklı dosyalar (yalnız meta), `group_vars/*vault*`. **CI tanımlarına yazma yasak:** `.github/**`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines*.yml` (T21).

**Döngü.** yaz (`fs.write`) → `iac.fmt` → `iac.validate` → `iac.lint` → `iac.scan` → hata özetine göre düzelt → diff göster. Faz 2: `iac.plan` / `ansible.check` → PR gövdesine plan özeti. Hata çıktıları kompakt görünümle (`{severity, summary, dosya:satır}`) döner (§4.5).

| Ad | Sınıf | Profil | Not | Faz |
|---|---|---|---|---|
| `iac.project.inspect` | read (yerel) | — | Proje yapısı: motor ve sürüm, sağlayıcılar, modüller, backend **türü** (değer yok), değişken/çıktı adları, rol/playbook listesi. State, tfvars, vault içeriği okunmaz (M1) | 1b |
| `fs.read` / `fs.write` | read / local-write | — | Yalnız worktree + `write_paths`; `deny_paths` uygulanır; yazılacak içerik M2'den geçer (**sabit kodlanmış secret yazımı reddedilir**); çalıştırılabilir bit yok; ilk yazımda diff gösterilir | 1b |
| `iac.fmt` | local-write (worktree) | — | `terraform fmt` / `tofu fmt` | 1b |
| `iac.validate` | read (yerel, sandbox) | — | `init -backend=false` + `validate -json`. Ağ: yalnız sağlayıcı kayıt defteri allowlist'i veya yerel ayna. **HCL ön-taraması** (aşağıda). Çıktı kompakt | 1b |
| `iac.lint` | read (yerel) | — | `tflint`, `ansible-lint`, `ansible-playbook --syntax-check` (bağlantı yok) | 1b |
| `iac.scan` | read (yerel) | — | Kurulu tarayıcıyı (checkov/trivy config vb.) çalıştırır veya SARIF/JSON sonucunu okur; **ürün kendi tarayıcısını yazmaz** (§1) | 1b |
| `iac.docs.lookup` | read | — | Kaynak/modül şeması: yerel `terraform providers schema -json` çıktısından **yalnız istenen kaynak türünün** kompakt görünümü; ya da MCP istemci köprüsüyle HashiCorp Terraform MCP sunucusunun doküman araçları (yalnız read) **[doğrulanacak]**. Modelin eğitim bilgisi yerine güncel şema: hata ve tur sayısı düşer | 1b |
| `ansible.inventory.list` | read (yerel) | — | Statik envanter: host/grup adları ve güvenli değişkenler; `ansible_*password*`, `ansible_ssh_private_key_file`, `ansible_become_pass` M1. Dinamik envanter betiği/eklentisi **kod çalıştırır** → `ask` | 1b |
| `iac.plan` | read (kimlikli; kilit yan etkisi) | `cloud` (reader) veya `iac` | Sandbox; kimlik lease ile; `-lock=false` varsayılan (reader kilit yazamaz) **[doğrulanacak]**; HCL ön-tarama uyarısı varsa `ask`. Çıktı: plan JSON'da `*_sensitive` bayraklı değerler **atılır** (M1-iac); özet = add/change/destroy sayıları + adres listesi + kural tabanlı risk etiketleri (silme, IAM, ağ kuralı); tam plan Evidence Store'da | 2 |
| `iac.apply` | deploy | `cloud`/`iac` | **Varsayılan kapalı**; hedefin pipeline'ı tercih edilir. Açılırsa yalnız `apply <planfile>`: onaylanan plan = uygulanan plan, plan dosyası hash'i eylem hash'ine dahil | 2 |
| `iac.destroy` | destroy | `cloud`/`iac` | Varsayılan kapalı; break-glass veya açık politika | 2 |
| `ansible.check` | ön-taramaya göre `read` ya da `mutate` | `host` | `--check --diff`. Check modu yan etkisiz **garanti etmez** (`check_mode: false` görevleri gerçekten çalışır) **[doğrulanacak: docs.ansible.com playbooks_checkmode]** → statik ön-tarama temizse read, değilse `mutate` + `ask` | 2 |
| `ansible.run` | deploy | `host` | **Varsayılan kapalı**; açılırsa `--limit` zorunlu ve `allowed_scopes` içinde, önce `ansible.check`, onay, sabit ayrıntı düzeyi (`-vvv` yasak: kimlik sızar) | 2 |

**HCL ön-taraması (kod çalıştıran yapılar).** `terraform validate`/`plan` ve modül/sağlayıcı yükleme **yürütülebilir koddur**; model yazsa da üçüncü taraf modülden gelse de aynı kural: `data "external"`, `provisioner "local-exec" | "remote-exec" | "file"`, uzak `module source` (git/ssh/http/s3/gcs), registry dışı `required_providers` kaynağı, `provider` bloğunda gömülü kimlik alanları (`access_key`, `token`, `password`) → varsayılan **deny**, politika izin verirse `ask`. `.terraform.lock.hcl` zorunlu; sağlayıcı hash değişimi `ask`. `init` ağı yalnız kayıt defteri allowlist'i veya yerel dosya aynası (hava boşluğu: `provider_installation` aynası **[doğrulanacak: https://developer.hashicorp.com/terraform/cli/config/config-file]**).
**Ansible sınıf kataloğu (modül başına).** `setup/stat/find/debug/assert/ping` read; `copy/template/lineinfile/package/service` mutate–deploy; `file state=absent`, `user state=absent` destroy; `command/shell/raw/script` ≥ deploy; sınıflanamayan modül = destroy muamelesi. Ön-tarama işaretleri: `check_mode: false`, `lookup('pipe', …)`, `local_action`/`delegate_to: localhost`, `become`, yol değişkenli `include_tasks`, repodaki özel plugin dizinleri (`library/`, `action_plugins/`, `callback_plugins/`) ve `ansible.cfg` (**güvenilmez**: ürün kendi `ansible.cfg`'sini sandbox'a koyar).
**SSH ve vault.** `host` profili: `{inventory_scope (grup/host glob), host_key_pins, become_policy}`; kimlik yalnız lease ile (ssh-agent soketi veya sandbox içinde 0600 geçici anahtar); `StrictHostKeyChecking=yes` ve ürünün ürettiği pinli `known_hosts`; Ansible Vault parolası ve `become` parolası kasada, fd ile verilir, bağlama girmez.
**Skill'ler.** `terraform` (modül yapısı, sürüm pinleme, değişken/çıktı kuralları, `sensitive`, backend'i koda gömmeme, etiketleme, `moved`/`import` blokları, gözden geçirme listesi) ve `ansible` (idempotans, rol yapısı, `no_log`, handler, vault kullanımı, `--check` uyumu). **Kurum standardı gömülü değildir**; kullanıcı kendi yönergesini user skill veya çalışma alanındaki `.ops/conventions.md` ile getirir. İkisi ayrı ve ≤5k token; ayrıntı `references/` altında talep halinde (§4.5).
**Teslim.** Varsayılan çıktı: dal + diff, Faz 2'de PR (gövdede doğrulama çıktıları ve plan özeti). Plan/apply'ı hedefin kendi pipeline'ı (Atlantis, CI, Terraform Cloud vb.) yapar; ürün onun onay mekanizmasını atlamaz.


[← Belge dizini](00-overview.md#belge-dizini)
