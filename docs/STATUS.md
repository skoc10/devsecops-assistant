# Durum: gerçekleşen ve planlanan kontroller

Etiketler (tasarım kararı D14): **Enforced** = kodda uygulanıyor ve testle doğrulanıyor · **Best-effort** = uygulanıyor ama garanti değil (sınırı yazılı) · **Planned** = henüz yok · **Library-only** = kütüphane var, çalışma zamanı yoluna bağlı değil.

Son güncelleme: WP4 tamamlandı (kasa + broker + kubeconfig içe aktarma).

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
| Exec kimlik eklentisi (argv şablonu + sandbox), `connectCheck`, profil doktoru | Planned (WP6) | `packages/broker`, `packages/sandbox` | S-14, S-15 |
| Kubernetes okuma adapter'ı | Planned | `packages/adapters/kubernetes` | C-xx |
| Sandbox sarmalayıcı, exec eklentisi şablonu, doktor | Planned | `packages/sandbox`, `packages/broker` | S-14, S-15 |
| Orkestratör, `opsd`, `ops chat`, tembel skill, token ölçümü | Planned | `packages/core`, `packages/cli`, `packages/skills` | E-01, B-01, B-04 |
| Sağlayıcılar (OpenAI-uyumlu, Cursor runtime) | Planned | `packages/providers`, `packages/runtimes` | S-10, S-13 |

## Faz 1 / 1b / 2 / 3

Tümü **Planned**. Ayrıntı: [design/10-phases.md](design/10-phases.md).

## Bilinen eksikler ve belgelenmiş sınırlar

- Gerçek Cursor SDK spike'ı (§6.4-11) geçerli bir Cursor API anahtarı ve hedef işletim sistemi gerektirir; otomatik testler sahte (mock) SDK ile koşar.
- OS sandbox (bubblewrap/seatbelt) bu geliştirme ortamında kurulu değildir; sandbox sarmalayıcı komut kurucusu ve tespit mantığı test edilir, gerçek izolasyon testi sandbox'lı ortamda elle yapılmalıdır.
- Lisans henüz seçilmedi (`UNLICENSED`); depo sahibi karar verecek.
