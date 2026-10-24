# Durum: gerçekleşen ve planlanan kontroller

Etiketler (tasarım kararı D14): **Enforced** = kodda uygulanıyor ve testle doğrulanıyor · **Best-effort** = uygulanıyor ama garanti değil (sınırı yazılı) · **Planned** = henüz yok · **Library-only** = kütüphane var, çalışma zamanı yoluna bağlı değil.

Son güncelleme: WP7 tamamlandı (bileşim kökü, opsd, CLI, E-01, B-04).

## Faz 0

| Kontrol | Etiket | Paket | Test |
|---|---|---|---|
| Sözleşmeler (Profile, Target, ToolDescriptor, ToolResult, PolicyDecision, AuditRecord, ModelProvider, AgentRuntime, DatabaseDriver, SecretStore) | **Enforced** (zod şemaları; strict, secret alanı yok) | `packages/contracts` | `contracts/test/*` |
| Testkit çekirdeği: canary (ham/base64/url/hex/json/bölünmüş), CaptureSink, imzalı sahte profil, izole `OPS_HOME`, ScriptedProvider, FakeAdapter, adapter yapı denetimi | **Enforced** | `packages/testkit` | `testkit/test/*` |
| Denetim: HMAC'li hash zinciri, write-ahead fail-closed yazıcı (depolama/çapa hatasında günlük kilitlenir), `verify` (düzenleme/silme/sıra değişimi/yanlış anahtar) | **Enforced** | `packages/audit` | S-08 (`audit/test`) |
| Denetim: kuyruk kesme tespiti (başlık çapası) | **Best-effort** — çapa aynı kullanıcı hesabında; tamper-tespit, önleme değil; çapasız kesme fark edilmez | `packages/audit` | S-08 |
| Redaksiyon M1 yapısal reddet listesi (kayıtlı profil varsayılan maskeleri kaybedemez) | **Enforced** | `packages/redaction` | S-06 |
| Redaksiyon M2 desen/entropi (gitleaks tarzı dar kural seti) | **Best-effort** — bilinmeyen biçim kaçabilir | `packages/redaction` | S-06 |
| Redaksiyon M3 bilinen-secret taraması (ham/base64 hizalamaları/url/hex/json/satır) | **Enforced** kayıtlı değerler için; bölünmüş/birleştirilmiş sızıntı **Best-effort** (tespit edilemez) | `packages/redaction` | S-06 |
| M4 değer dedektörleri + sütun maskesi (AST kuralı Faz 1'de DB adapter'ında) | **Best-effort** | `packages/redaction` | S-06 |
| M5 limit, M6 kontrol karakteri/bidi temizliği | **Enforced**; M6 taint zarfı tek başına güvenlik sınırı değildir | `packages/redaction` | S-06 |
| Kompaktlaştırma (projeksiyon, boş atma, tablo, liste/log kümeleme, token tavanı, `byReference`), redaksiyondan sonra | **Enforced** | `packages/redaction` | B-03 |
| PEP (Tool Gateway) 14 adımlı boru hattı: şema(strict) → profil → hedef pini/kapsam → sınıflama → politika → atıf → onay → denetim(intent, write-ahead) → lease → adapter → lease bırak → çıktı hattı → denetim(result) → egress | **Enforced** | `packages/core` | S-03, S-04, S-06, S-08, S-12, S-13 (`core/test/gateway.test.ts`) |
| Politika motoru: sınıf tavanı sert, sınıflanamayan=destroy, deny>ask>allow, allow yalnız süreli+dar+mutate, kurallar tavan/taint'i gevşetemez | **Enforced** | `packages/policy` | `policy/test` |
| Bağlam etiketi + taint yükseltme (mutasyon, başka profile okuma, daha hassas veri, dış ağ → en az ask) | **Enforced** | `packages/policy`, `packages/core` | T2 testleri |
| Onay kapısı | **Planned** — kapı yoksa `ask` kararı `approval_unavailable` ile reddedilir (Faz 0 davranışı); v0 Faz 1 | `packages/core` | S-09, S-16 |
| Mutasyon atfı: hedef kaynak, aynı profil/çağdan taze kanıtın `subject`'inde olmalı (sözdizimsel; anlamsal ilgiyi insan onayı doğrular) | **Enforced** (sözdizimsel kısım) | `packages/core` | S-05 çekirdeği |
| Egress: bağlam `zoneCap` ↔ sağlayıcı bölgesi (ön ve son denetim); uygun sağlayıcı yoksa fail-closed | **Enforced** (gateway tarafı); sağlayıcı yönlendirmesi orkestratörde **Planned** | `packages/core` | T14 testleri |
| Bütçeler: oturum çağrı sayısı, sonuç token tavanı, oturum token eşikleri (`policy.yaml` `budgets`) | **Enforced** (sayaçlar); model `usage` beslemesi orkestratörde **Planned** | `packages/policy`, `packages/core` | bütçe testleri |
| Broker `prime`: profil secret'ları ilk çağrıdan ÖNCE M3'e kaydedilir | **Enforced** (gateway tarafı; gerçek broker WP4) | `packages/core` | S-06 |
| Kasa: `EncryptedFileStore` (AES-256-GCM, scrypt, girdi adı AAD'ye bağlı, 0600/0700, `close()` sıfırlar) | **Enforced** — KDF scrypt'tir (Argon2id Node çekirdeğinde yok); parola tamponu sıfırlanır, JS string kopyaları için en iyi çaba | `packages/broker` | `broker/test/vault.test.ts` |
| Kasa: OS anahtar zinciri (Linux `secret-tool` stdin ile, macOS `security`) | **Library-only** — komut kurucusu sahte `Exec` ile test edilir; gerçek anahtar zincirine karşı denenmedi. macOS `security add-generic-password` değeri argv'de taşır (belgelenmiş sınır; `ps` ile görünür) | `packages/broker` | `broker/test/vault.test.ts` |
| Kubeconfig içe aktarma: tek bağlam, dosya başvuruları satır içi, CA parmak izi pini; `insecure-skip-tls-verify`, `proxy-url`, `exec`, `auth-provider`, basic auth, düz http **reddedilir**; hata/uyarı metinleri secret içermez | **Enforced** | `packages/broker` | `broker/test/kubeconfig.test.ts` |
| Profil kayıt defteri (secret taşımayan, strict şema, 0600); test kipi `admit` (imzalı sahte profil) ister ve prod'u reddeder | **Enforced** | `packages/broker` | `broker/test/registry.test.ts` |
| `LocalBroker`: çağrı başına lease, TTL, eşzamanlı sınır, opak tutamaç, `prime`/`acquire` M3'e kaydeder; `CredentialResolver` yalnız lease etkinken malzeme verir | **Enforced**; birinci taraf adapter aynı heap'te çalışır, silme **Best-effort** (§3.5 sınırı) | `packages/broker` | `broker/test/broker.test.ts` |
| `ProfileService` (`add`/`list`/`rm`): kimlik yalnız kasaya, hata olursa geri alma | **Enforced** (CLI bağlantısı WP7) | `packages/broker` | `broker/test/service.test.ts` |
| Ortam kimliği taraması (yalnız varlık + izin bitleri; içerik okunmaz) | **Enforced** | `packages/broker` | `broker/test/service.test.ts` |
| Denetim HMAC anahtarı kasada (`audit/hmac-key`) | **Enforced** | `packages/broker` | `broker/test/service.test.ts` |
| OS sandbox: bubblewrap sarmalayıcı (tüm ad alanları ayrı, `--clearenv`, boş kök + salt-okunur `/usr`, `/home`/`/root`/`/run` yok, ağ varsayılan kapalı, zaman aşımı + çıktı sınırı + süreç grubu öldürme) | **Enforced** (Linux, bubblewrap ile — gerçek süreçlerle testli); bwrap yoksa/çalışmıyorsa `detectSandbox` `null` döner ve çağıranlar fail-closed davranır | `packages/sandbox` | S-15 (`sandbox/test`) |
| OS sandbox: macOS seatbelt (`sandbox-exec`) | **Library-only** — yalnız profil/komut kurucusu birim testli; macOS'ta ELLE doğrulanmadı (`sandbox-exec` Apple'ca deprecated, doğrulanacak) | `packages/sandbox` | `sandbox.test.ts` |
| `UnsafeDirectRunner` (izolasyonsuz; yalnız test ve açık kullanıcı onayı) | Bilinçli zayıf — ürün yolunda varsayılan DEĞİL | `packages/sandbox` | — |
| Sandbox ağ allowlist'i (yalnız sağlayıcı uçları) | **Planned** — şu an ağ ya tamamen kapalı ya da host ağı; bulut CLI eklentileri host ağı kullanır (belgelenmiş sınır) | `packages/sandbox` | — |
| Exec kimlik eklentisi: kapalı şablon kataloğu (aws eks, aws-iam-authenticator, gke-gcloud-auth-plugin, kubelogin; bayrak ve değer desenleri, yinelenen/bilinmeyen bayrak, env allowlist), ikili yol + SHA-256 pini, her çalıştırmada yeniden doğrulama, yalnız sandbox içinde, stderr taşınmaz, ambient bağımlılık beyanı (kimlikli env yalnız açık onayla), bitişe göre bellek önbelleği | **Enforced** (şablonlar **doğrulanacak**: bayrak adları sürüme bağlı; gerçek bulut CLI'larına karşı denenmedi) | `packages/broker` | S-15, T17 (`broker/test/exec.test.ts`) |
| Exec profillerinde `prime` M3'e kayıt yapamaz (token lease anında doğar); intent denetim kaydı token içeremez, çıktı/result yolu M3 ile korunur | **Enforced** (belgelenmiş sınır) | `packages/broker`, `packages/core` | exec.test.ts |
| `connectCheck`, profil doktoru | **Enforced** (WP6a) | `packages/adapters/kubernetes` | S-14 |
| Kubernetes okuma adapter'ı: `k8s.profile.describe`, `resources.list/get/describe`, `events.list`, `pods.logs`; yalnız GET; kompakt projeksiyon + `select`; kapalı tür tablosu; namespace/ad DNS regex'i | **Enforced** (testli, sahte API'ye karşı gerçek TLS) — gerçek kümeye karşı (`kind`) denenmedi, I-01 WP6'da | `packages/adapters/kubernetes` | `adapters/kubernetes/test/adapter.test.ts` |
| Kimlik pini: sunucu URL'si ve CA parmak izi kimlik gönderilmeden ÖNCE doğrulanır; yönlendirme izlenmez; yanıt boyutu sınırlı | **Enforced** | `packages/adapters/kubernetes` | S-04, S-12 |
| `Secret` türü `as=Table` ile okunur: değerler sunucudan hiç çekilmez; ek olarak ConfigMap secret-benzeri anahtarları, `managedFields`, `last-applied-configuration` atılır; M1 `k8s` profili son hat | **Enforced** | `packages/adapters/kubernetes` | S-06 (adapter ayağı) |
| `k8s.workload.health`: türetilmiş sağlık (rollout, sorunlu kapsayıcı, imaj digest, HPA/PDB, düğüm baskısı, bulgu kodları); serbest metin ve kubelet mesajları çıktıya girmez, bilinmeyen neden kodları `Other` olur | **Enforced** | `packages/adapters/kubernetes` | `health.test.ts` |
| `k8s.auth.can_i`: SelfSubjectRulesReview + yerel eşleme | **Enforced** | `packages/adapters/kubernetes` | `health.test.ts` |
| Profil doktoru (k8s): bağlan → kimlik yankısı → pin → fiili RBAC ↔ beyan edilen tavan; Secret okuma, yazma, exec, silme, joker, impersonate, proxy, token üretme → `read` profili bağlanamaz; yetki kayması oturum başında yakalanır | **Enforced** (`adapter.doctor`; oturum başı çağrı WP7 orkestratöründe) | `packages/adapters/kubernetes` | S-14 (`doctor.test.ts`) |
| Salt okunur RBAC manifest üreticisi (uygulamaz; Secret/exec/proxy/yazma yok; üretilen kurallar analizörden `read` geçer) | **Enforced** | `packages/adapters/kubernetes` | `rbac.test.ts` |
| Conformance paketi v0 (yapı + davranış: sızıntı, kapsam reddi, pin, çıktı tavanı/projeksiyon) | **Enforced** (kubernetes için); genel davranış paketi diğer adapter'larla genişler | `packages/testkit`, `packages/adapters/kubernetes` | C-xx |
| Sandbox sarmalayıcı, exec eklentisi şablonu, doktor | Planned | `packages/sandbox`, `packages/broker` | S-14, S-15 |
| Orkestratör (`loopOwner=host`): PEP üzerinden araç çağrısı, kullanıcı girdisi M2/M3, egress denetimi (bağlam ↔ sağlayıcı bölgesi, fail-closed), write-ahead `model_call` denetimi, paralel okuma, model turu/bütçe sınırları, profil enjeksiyonu (tür başına tek bağlı profil) | **Enforced** | `packages/core` | `core/test/orchestrator.test.ts` |
| Kanıt atıf doğrulayıcı: `[ev-N]` kimlikleri Evidence Store'da olmalı; geçersizse bir kez düzeltme isteği, sonra cevap işaretlenir. Yalnız SÖZDİZİMSEL; anlamsal ilgiyi insan değerlendirir | **Enforced** (sözdizimsel kısım) | `packages/core` | `orchestrator.test.ts`, `ledger.test.ts` |
| Bağlam defteri: eşikte eski turlar deterministik özetle (hedef + kanıt satırları) değişir, eski araç gövdeleri referansa döner | **Enforced** | `packages/core` | `ledger.test.ts` |
| Önek kararlılığı (B-05): sistem istemi sabit önek + değişken son ek; araç listesi etkinleşme sırasıyla yalnız sona büyür | **Enforced**; sağlayıcı istem önbelleği (cache_control) kullanımı WP8/Faz 1 | `packages/core` | B-05 |
| Token ölçümü: model çağrısı başına `tokens`, araç sonucu tahmini; `usageFromAudit`/`formatUsage` (denetimden `ops usage`) | **Enforced** (CLI komutu WP7b) | `packages/core` | `ledger.test.ts` |
| Tembel skill yükleyici: `SKILL.md` + `ops.skill.yaml` (katı), güven katmanı dizinden, linter (ad, açıklama, 500 satır / 5000 token), gerektirdiği adapter yoksa gizlenir, en çok 2 etkin gövde, `scripts/` ASLA çalışmaz, imported skill çıktısı untrusted | **Enforced** (B-02 çekirdeği; tam linter Faz 1) | `packages/skills` | `skills/test` |
| Yerleşik skill'ler: `kubernetes`, `generic-diagnosis` (meta blok ≤ 250 token, sabit önek ≤ 3k token — B-01) | **Enforced** | `skills/` | B-01 |
| Bileşim kökü `createRuntime`: kasa → denetim anahtarı (kasada) → HMAC'li günlük + çapa → broker (+sandbox'lı exec) → araç kaydı → politika → PEP; profil `diagnose`/`bindProfile` (doktor `bindable=false` ise bağlamaz) | **Enforced** | `packages/cli` | `cli/test/e2e.test.ts` |
| `opsd`: UDS 0600 (dizin 0700), NDJSON, yalnız `ping/profile.list/profile.bind/chat.send/usage.get/shutdown`; araç çağırma ve onay yöntemleri bu soketten SUNULMAZ; tek eşzamanlı sohbet; geçersiz istekte kimlik yansıtılır. Peer-uid doğrulaması YOK (Node'da SO_PEERCRED yok): koruma dosya izinleridir | **Enforced** (izin tabanlı); aynı UID'li saldırgan kapsam dışı | `packages/cli` | `opsd.test.ts` |
| `ops` CLI: `init`, `profile add/list/rm/doctor/rbac`, `doctor`, `audit verify`, `usage`, `daemon`, `chat [--embedded]`; parola yalnız 0600 dosyadan veya yankısız TTY isteminden (ortam değişkeninden DEĞİL) | **Enforced** | `packages/cli` | `cli.test.ts` |
| Sohbet arayüzü: model/araç kaynaklı tüm metin ANSI/OSC/bidi/kontrol karakterlerinden arındırılarak basılır | **Enforced** | `packages/cli` | `e2e.test.ts` |
| E-01 (Faz 0 kabul, scripted model + sahte küme): doktor → skill.load → health → events+logs (paralel) → atıflı kök neden; silme/ölçekleme reddi (S-07); canary 4 kanalda temiz (S-06); `audit verify` + bozulma tespiti (S-08); sağlayıcı bölgesi değişimi (S-13) | **Enforced** (scripted modelle). Gerçek sağlayıcıyla ELLE kabul WP8 sonrası | `packages/cli` | E-01 |
| B-01 (sabit önek ≤ 3k), B-03 (sonuç ≤ 1,5k veya referans), B-04 (`test/e2e/baseline.json`; +%10 eşiği; sonuç toplamı ≤ 8k) | **Enforced** | `packages/cli`, `test/e2e` | B-01/03/04 |
| Model sağlayıcıları (`OPS_PROVIDER` kaydı hazır, sağlayıcı yok) | Planned (WP8) | `packages/providers` | S-13 |
| Sağlayıcılar (OpenAI-uyumlu, Cursor runtime) | Planned | `packages/providers`, `packages/runtimes` | S-10, S-13 |

## Faz 1 / 1b / 2 / 3

Tümü **Planned**. Ayrıntı: [design/10-phases.md](design/10-phases.md).

## Bilinen eksikler ve belgelenmiş sınırlar

- Gerçek Cursor SDK spike'ı (§6.4-11) geçerli bir Cursor API anahtarı ve hedef işletim sistemi gerektirir; otomatik testler sahte (mock) SDK ile koşar.
- OS sandbox: Linux'ta bubblewrap ile GERÇEK izolasyon testleri koşar (bwrap yoksa testler uyarıyla atlanır; CI'da kurulur). macOS seatbelt bu ortamda çalıştırılamadı: profil kurucusu birim testli, gerçek davranış macOS'ta elle doğrulanmalıdır. Windows desteklenmez (Faz 3).
- Lisans henüz seçilmedi (`UNLICENSED`); depo sahibi karar verecek.
