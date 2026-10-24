# Durum: gerçekleşen ve planlanan kontroller

Etiketler (tasarım kararı D14): **Enforced** = kodda uygulanıyor ve testle doğrulanıyor · **Best-effort** = uygulanıyor ama garanti değil (sınırı yazılı) · **Planned** = henüz yok · **Library-only** = kütüphane var, çalışma zamanı yoluna bağlı değil.

Son güncelleme: WP2 tamamlandı (denetim + redaksiyon + kompaktlaştırma).

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
| Politika v0 + PEP boru hattı | Planned | `packages/policy`, `packages/core` | S-03, S-04, S-12, S-13 |
| Kasa + broker + kubeconfig içe aktarma | Planned | `packages/broker` | S-06, S-04 |
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
