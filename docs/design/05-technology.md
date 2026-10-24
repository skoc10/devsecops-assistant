# Teknoloji

## 6. Teknoloji

### 6.1 Dil ve çalışma zamanı: TypeScript / Node.js
| Aday | Artı | Eksi | Karar |
|---|---|---|---|
| **TypeScript (Node ≥ 22.13)** | Cursor SDK ve MCP SDK birinci sınıf TS; TUI, daemon, adapter, plugin tek dil; JSON Schema (zod) ile sözleşme; Python SDK'nın kendisi de bir köprü üzerinden TS SDK'yı gömüyor **[doğrulanacak: https://cursor.com/docs/sdk/bridge]**, yani Node zaten gerekecek | npm tedarik zinciri riski; tek ikili dağıtım ek iş | **Seçildi** |
| Go | Tek statik ikili, `client-go` ekosistemi (kubectl-ai, k8sgpt, cynative, kagent Go) | Cursor SDK TS/Python; shell AST için olgun Go kütüphanesi var ama UI/plugin için ikinci dil gerekir | Sonraki adapter'lar MCP/stdio ile Go yazılabilir |
| Python | HolmesGPT ekosistemi, güvenlik araçları | Dağıtım/sanal ortam yükü; Cursor için yine Node köprüsü | Adapter/skill scriptleri için MCP/stdio |

Gerekenler: Node ≥ 22.13 ve `node:sqlite` (Cursor SDK gereksinimi; yoksa `ConfigurationError`) **[doğrulanacak: https://cursor.com/docs/sdk/typescript]**. pnpm workspaces; zod → JSON Schema; vitest; ESLint. Tedarik zinciri: lockfile + sürüm pini, **yaşam-döngüsü scriptleri kapalı** (`pnpm` onlyBuiltDependencies / `ignore-scripts`), kendi SBOM'u (CycloneDX), imzalı sürüm **[doğrulanacak: Sigstore/cosign]**. Tek ikili dağıtım (Node SEA veya eşdeğeri) **[doğrulanacak: https://nodejs.org/api/single-executable-applications.html]** Faz 3.

### 6.2 Kasa
`SecretStore` arayüzü; v1: (1) işletim sistemi anahtar zinciri (macOS Keychain, Linux Secret Service/libsecret) — Node bağlaması **[doğrulanacak: `@napi-rs/keyring`; `keytar` arşivlenmiş görünüyor]**; (2) şifreli yerel dosya (AEAD; anahtar passphrase+Argon2id'den; Secret Service yoksa varsayılan). v1 hedef platform: **Linux + macOS** (Windows Faz 3: named pipe + Credential Manager). Dışarıdan: Vault/OpenBao, bulut secret manager, 1Password CLI — Faz 3 `ExternalProviderStore`.

### 6.3 Arayüz ve çekirdek süreç
`opsd` (arka plan servisi, UDS) + `ops` CLI/TUI (Ink veya eşdeğeri **[doğrulanacak]**). Çekirdek kütüphane olarak da gömülebilir (test ve masaüstü kabuğu için). Telemetri varsayılan kapalı; OTLP dışa aktarım Faz 3, **prompt/araç içeriği asla** varsayılan eklenmez (HolmesGPT/kagent trace örneğinin tersi).

### 6.4 Cursor SDK'nın durduğu katman
**Doğrulanan gerçekler** (kaynak: https://cursor.com/docs/sdk/typescript , https://cursor.com/docs/sdk/python , https://cursor.com/docs/release-notes/sdk ; sayfayı özetleyen bir model üzerinden okundu, kritik alıntıları geliştirme öncesi **gözle doğrulayın**):
- Paketler: `@cursor/sdk` (npm), `cursor-sdk` (PyPI/pip; import `cursor_sdk`, Python ≥3.10).
- Kimlik: kullanıcı API anahtarı ve service account anahtarı; `Cursor.auth.login()` tarayıcı girişiyle anahtar üretir ve `~/.cursor/sdk/auth.json`'a yazar (varsayılan 90 gün). Çözümleme sırası: açık `apiKey` → `CURSOR_API_KEY` → saklı giriş. **Team Admin anahtarı "henüz" desteklenmiyor** (sürüme bağlı ifade). `auth.json` dosya izinleri sayfada yok.
- "Local", **döngünün ve dosya erişiminin** nerede çalıştığını söyler, **modelin değil**; tüm çıkarım Cursor'un barındırdığı modellerle yapılır.
- Headless yerel ajan araç çağrılarını (shell, edit, write…) **insan onayı olmadan** çalıştırır; `local.sandboxOptions.enabled` varsayılan **false**. Auto-review varsayılan kapalı ve "best-effort convenience, not a security boundary".
- Allowlist: `tools` (yerleşik araç allowlist'i; `tools: []` = yalnız metin), `disallowedTools` ("deny wins"); `"shell"` ve `"mcp"` grupları var. **İkisi de `Agent.resume()`'da geri gelmez**, `systemPrompt` ve satır-içi `mcpServers` de gelmez ("secret taşıdıkları için"). Tam `ToolName` listesi sayfada yok.
- Özel araç: `local.customTools` → SDK bunları `custom-user-tools` adlı MCP sunucusu olarak kaydeder; `execute` geri çağrısı **SDK'yı barındıran süreçte** koşar; özel araçlar etkileşimli onayı atlar. Cloud'da `customTools` yok sayılır.
- Yerel ajan süreci **kullanıcının tüm ortamını miras alır** ("inherits your own environment").
- Sandbox açılırsa: yazma `cwd`+temp+izinli yollar; **okuma çalışma alanıyla sınırlı değildir**; dış ağ varsayılan kapalı; platform desteklemezse `ConfigurationError`.
- Kapılama için sayfa şunu önerir: dosya tabanlı hook'lar (`beforeShellExecution`, `preToolUse`) veya sandbox; hook'ta programatik geri çağrı yok. `PreToolUse` deny'ın yerel ajanlarda bloklaması 1.0.40'tan beri.
- Olay modeli: `Agent` → `Run`; `SDKMessage` birleşimi `system | user | assistant | thinking | tool_call | status | task | request | usage` (hepsinde `agent_id`, `run_id`); `tool_call.status ∈ running|completed|error`. **`request` olayı ("awaiting user input or approval") nasıl yanıtlanır: sayfada yok.** "Tool call schema is not stable."
- Sayfada geçen çekirdek metotlar (yalnız bunlar kullanılacak): `Agent.create`, `Agent.resume`, `Agent.prompt`, `agent.send`, `agent.close`, `run.stream`, `run.wait`, `run.cancel`, `Cursor.auth.login/status/logout`, `Cursor.models.list`.
- SDK için BYOK / yerel model / özel endpoint **bulunamadı** → Cursor ile "yerel model" mümkün değil; hava boşluğu kipinde Cursor kullanılamaz.

**Tasarım sonuçları (Cursor sürüm 1 sözleşmesi)**
1. **Yer:** `packages/runtimes/cursor` (`AgentRuntime`) ve aynı çalışma zamanını `loopOwner=provider` olarak sunan `packages/providers/cursor`. SDK **yalnız** bu paketlerde import edilir; çekirdek SDK'yı bilmez.
2. **Ayrı süreç (`cursor-host`):** SDK, **OS sandbox'ı içinde** (bubblewrap/seatbelt) ayrı bir OS sürecinde koşar: izole `HOME`, boş/geçici çalışma dizini, **env temizlenmiş**, kullanıcının dosya sistemi (özellikle `~/.kube`, `~/.aws`, `~/.ssh`) bağlanmamış, D-Bus/Secret Service soketi yok, ağ yalnız sağlayıcı uçları + loopback araç köprüsü (mekanizma: sandbox ağ ilkesi veya allowlist'li yerel proxy **[doğrulanacak]**). Bu OS sarmalayıcı olmadan "vault'a erişimi yok" bir *varsayım*dır, kontrol değil; sarmalayıcı kurulamazsa Cursor yalnız tavsiye kipinde çalışır. Tek taşıdığı sır Cursor API anahtarıdır (kasada `provider/cursor`; spawn anında env ile). Böylece "ajan süreci kullanıcının tüm ortamını miras alır" bulgusu etkisiz kalır.
3. **SDK sandbox'ı ek katmandır:** `sandboxOptions.enabled: true`; okuma çalışma alanıyla sınırlı olmadığından asıl sınır yukarıdaki OS sarmalayıcıdır. Platform ikisini de desteklemezse sağlayıcı başlamaz → tavsiye kipine düşer.
4. **Araç yüzü tek kapı:** **asıl kontrol `tools` allowlist'idir** (yalnız özel/MCP grubu; SDK yeni bir yerleşik araç eklerse varsayılan açık kalmasın diye allowlist esastır); `disallowedTools` shell, edit, read, web arama ve gerisini kapatan ikincil kemerdir. Özel araçların `execute`'u yalnızca **IPC yönlendiricisidir** → opsd'deki PEP'e (süreli, oturuma özel taşıyıcı belirteçle). Araç tanımları **secret taşımaz**.
5. **Resume'a güvenme:** `tools`/`disallowedTools`/`systemPrompt`/`mcpServers` resume'da geri gelmediği için, bunlardan biri unutulursa varsayılan (**kabuk açık, onaysız**) devreye girer. Bu yüzden: (a) varsayılan **stateless** — her orkestratör turu yeni `Agent.create`, konuşma durumu bizde (tura **bağlam defteri özeti** gönderilir, ham transkript değil: §4.5-6); (b) resume gerekirse **tek bir fonksiyondan** (`buildCursorLaunchOptions`) geçer, birim testi seçenek kümesini kilitler; (c) eksik seçenek = **araçsız** (fail-closed), kabuk değil.
6. **Çalışma zamanı bekçisi (tespit edici, önleyici değil):** `tool_call` olaylarında izinli özel araç adları dışında bir ad görülürse `run.cancel()`, oturum "tainted", denetime `provider-shell-bypass` alarmı, sağlayıcı bu oturumda devre dışı. Olay geldiğinde komut çoktan çalışmış olabilir; birincil kontrol madde 2–4'tür, bekçi alarm ve oturum kapatma içindir.
7. **Ayar kaynakları kapalı:** `settingSources` verilmez (yalnız satır-içi sunucular yüklenir); proje/kullanıcı `.cursor/mcp.json` ve hook'ları devreye girmez. Ek kemer: `beforeShellExecution`/`preToolUse` **deny-all** hook dosyası **[doğrulanacak: https://cursor.com/docs/hooks.md]**. Hook dosyalarının `settingSources` olmadan yüklenip yüklenmediği belirsiz (§15); yüklenmiyorsa hook'lar yalnız bu iş için ayrılmış temiz geçici dizine (`settingSources: ["project"]`, kullanıcı düzeyi yapılandırma yok) konur — spike (madde 11) bunu sınar.
8. **Veri çıkışı:** Cursor'a giren her şey üçüncü taraf barındırmalı modele gider → `trust_zone: third-party-cloud`. `egress_class=local` olan çıktı (ör. prod DB) bu sağlayıcıya **gitmez**; yönlendirme yerel `ModelProvider`'a olur. Gizlilik/ZDR kuralları SDK için IDE ile aynı denir; ayrıntı **[doğrulanacak: https://cursor.com/docs/cloud-agent/security.md]**.
9. **Kimlik girişi:** Cursor API anahtarı kasadan; `Cursor.auth.login()` v1'de önerilmez (anahtarı kasa dışında `auth.json`'a yazar). Kullanılırsa doktor dosya izinlerini kontrol eder.
10. **Sürüm pini + sözleşme testleri:** `@cursor/sdk` tam sürüme pinli; `tool_call` şeması "stabil değil" olduğu için olay ayrıştırıcı toleranslı ve sözleşme testli; yükseltme ayrı PR.
11. **Karar kapısı (WP8 spike, ≈½ gün):** (i) `tools` ile yalnız özel araçlar bırakılabiliyor mu, (ii) SDK sandbox'ı ve OS sarmalayıcı hedef işletim sistemlerinde açılıyor mu, (iii) `request` olayı nasıl yanıtlanır, (iv) hook deny-all çalışıyor mu, (v) `tools: []` metin modunda bağlam sızıntısı yok mu, (vi) hook'lar `settingSources` ile/olmadan yükleniyor mu, (vii) OS sarmalayıcı altında SDK sağlayıcı uçlarına bağlanabiliyor mu (ağ ilkesi mekanizması). Herhangi biri başarısızsa Cursor **yalnız tavsiye kipi**; Faz 0 kapanışı OpenAI-uyumlu `loopOwner=host` sağlayıcıyla yapılır.

### 6.5 Model sağlayıcıları
| Sağlayıcı | Arayüz | `trust_zone` | Not |
|---|---|---|---|
| Cursor | `AgentRuntime` / `ModelProvider(loopOwner=provider)` | third-party-cloud | İlk uygulama (varsayılan karar); §6.4 |
| OpenAI-uyumlu uç | `ModelProvider(loopOwner=host)` | yapılandırmaya göre | Yerel sunucular (Ollama, vLLM, llama.cpp) çoğunlukla bu uyumlulukla sunulur **[doğrulanacak]** → "yerel model" yolu |
| Anthropic | `ModelProvider(host)` | third-party-cloud | Resmi SDK |
| Azure OpenAI | `ModelProvider(host)` | tenant-cloud (kullanıcı tanımlar) | |
| Yerel | `ModelProvider(host)` | `local` | Hassas çıktı için seçilir; HolmesGPT notuna göre yerel modellerde araç çağrısı sınırlı olabilir → isteğe bağlı **tool-use shim** (kubectl-ai fikri) |
| Scripted/fake | `ModelProvider(host)` | local | Yalnız test: adversarial araç çağrıları üretir |
Sağlayıcı değişince araç sözleşmesi, sınıflar ve politika aynı; denetim her çağrıda `provider+model+trust_zone` yazar.

### 6.6 İlk bağdaştırıcılar için bağımlılık adayları (hepsi **[doğrulanacak]**)
Kubernetes: `@kubernetes/client-node` (kubectl çağırmadan doğrudan API). Pipeline: GitHub Actions REST (Octokit). PostgreSQL: `pg` + PostgreSQL ayrıştırıcısı (`libpg_query` bağlaması). Kabuk ayrıştırma: tree-sitter-bash (WASM) veya eşdeğeri; ayrıştırılamayan her yapı = ret. Redaksiyon kural seti: gitleaks tarzı bakımlı liste. **IaC (Faz 1b):** `terraform` veya `tofu`, `tflint`, `ansible`, `ansible-lint` ve (kuruluysa) `checkov`/`trivy config`/benzeri tarayıcılar **ürünle gelmez**; kullanıcı kurar, `ops doctor` bulur ve sürümünü bildirir; hepsi OS sandbox'ta, komut kataloğu üzerinden çalışır. MCP istemci köprüsü için resmî MCP TypeScript SDK'sı **[doğrulanacak: https://github.com/modelcontextprotocol/typescript-sdk]**.


[← Belge dizini](00-overview.md#belge-dizini)
