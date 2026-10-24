# Öneriler, doğrulanacaklar, kararlar

## 14. Ek öneriler (listede olmayan, eklenmesini önerdiklerim)
| # | Öneri | Gerekçe | Faz |
|---|---|---|---|
| 1 | **Profil doktoru** (beyan edilen tavan ↔ fiili RBAC/DB yetkisi) | "Reader" etiketi yalan olabilir; ilk savunma hattı | 0 |
| 2 | **Kanıt kimliği + atıf doğrulayıcı** ("kanıt yoksa iddia yok") | Halüsinasyonu deterministik azaltır; mutasyon-kanıt eşlemesinin temeli | 0 |
| 3 | **Taint-bilinçli politika** (bağlam etiketi: untrusted varken mutasyon, başka profile/daha hassas veriye okuma ve dış kanal onaya düşer) | Enjeksiyona karşı gerçek kontrol (filtre değil) | 0 etiket / 1 okuma `ask` / 2 mutasyon |
| 4 | **Replay + eval harness** (denetim kaydından oturum yeniden oynatma; bozuk-dağıtım eval seti) | Regresyon ve sağlayıcı karşılaştırması; olay sonrası inceleme | 1 |
| 5 | **Kontrol olgunluk etiketleri** README'de (Enforced / Planned / Library-only) | kars'tan; "uygulanmayan kontrol" tuzağını önler | 0 |
| 6 | **`ops explain-policy`** ("bu çağrı neden reddedildi/soruldu") | Onay yorgunluğu ve güveni azaltır | 1 |
| 7 | **Bütçeler** (tur/araç/token/maliyet): ölçüm Faz 0'dan, politika Faz 1 | DoS ve maliyet kontrolü; token ekonomisi (§4.5) | 0 / 1 |
| 8 | **Kanıtı MCP `resource` olarak sunmak** (`evidence://<id>`; araç sonucu `resource_link` döner, ayrıntı talep halinde çekilir) | Büyük çıktı bağlama girmeden referansla taşınır; MCP spesifikasyonu `resource_link`/`structuredContent` destekler | 0 (iç) / 3 (genel MCP yüzü) |
| 9 | **Tersinir tokenizasyon (M7)** (k8sgpt anonymize fikri: değerleri `‹ip-1›` yap, cevapta geri çöz) | Hassas veri üçüncü taraf modele gitmek zorundaysa | 3 |
| 10 | **MCP iki yönlü, dar kullanım:** tüket (istemci köprüsü v0, yalnız read ve etkin araç seti) · sun (PEP'li araçlar MCP sunucusu) | Dış ajanı kendi kabuğundan ayırmanın standart yolu; körlemesine araç bağlamak token ve güvenlik maliyeti | 0 (IPC) / 1b (istemci v0) / 3 (sunucu yüzü) |
| 11 | **Skill linter** (`skills-ref validate` + ürün kuralları: yetki talebi, script hash'i) | Kullanıcı skill'i ve ithal skill güvenliği | 1 |
| 12 | **Default-deny egress kipi** (ağ yalnız profil pinli hedefler + sağlayıcı) | kars `Learn` kipinin tersi; hava boşluğuna doğal geçiş | 1 |
| 13 | **Kod-yürütme kipi** (cynative: model betik yazar, sandbox'ta yalnız izinli araçları çağırır) | Tur/token azaltır; ama sandbox ister | 3+ araştırma, v1 hayır |
| 14 | **Windows desteği** | v1 Linux+macOS | 3 |
| 15 | **Kendi tedarik zinciri güvencesi** (SBOM, imzalı sürüm, scriptsiz bağımlılık kurulumu) | Güvenlik aracı olarak kendi riski | 0 / 3 |
| 16 | **IaC için yerel şema görünümü** (`terraform providers schema -json` → yalnız istenen kaynak türü, kompakt) | Modelin eğitim bilgisi yerine güncel şema; hata/tur/token azalır | 1b |
| 17 | **Proje yönergesi dosyası** (`.ops/conventions.md`: kullanıcının IaC/Ansible/pipeline kuralları; skill gibi tembel yüklenir) | Kurum standardını ürüne gömmeden uygulatmak | 1b |
| 18 | **Token raporu panosu** (`ops usage`: oturum/skill/araç kırılımı, en pahalı 5 sonuç) | Optimizasyonun neresine bakılacağını gösterir | 0 |

## 15. Doğrulanacaklar listesi
| Konu | Neden belirsiz | Bakılacak adres |
|---|---|---|
| Cursor `request` olayı nasıl yanıtlanır | Sayfada yok | https://cursor.com/docs/sdk/typescript ; https://cursor.com/docs/cloud-agent/api/endpoints.md |
| `ToolName` tam listesi; `tools` ile yalnız özel araç bırakma | Sayfada tam liste yok | aynı sayfa (spike) |
| Resume: `customTools`, `settingSources`, `apiKey`, cloud `envVars` | Yalnız inline MCP, `tools`, `disallowedTools`, `systemPrompt`, `model` için "geri gelmez" yazıyor | aynı sayfa; https://cursor.com/docs/release-notes/sdk |
| Hook'lar (`beforeShellExecution`, `preToolUse`) ve deny-all | Yalnız dosya tabanlı; ayrıntı ayrı sayfada | https://cursor.com/docs/hooks.md |
| Python SDK sandbox/onay varsayılanları, bridge | Sayfada yok | https://cursor.com/docs/sdk/bridge ; https://github.com/cursor/sdk-bridge |
| Team Admin anahtarı "henüz" desteklenmiyor | Sürüme bağlı | https://cursor.com/docs/release-notes/sdk |
| Cursor gizlilik / ZDR / `auth.json` izinleri | Sayfada yok; SDK için "IDE ile aynı Privacy Mode" deniyor | https://cursor.com/docs/cloud-agent/security.md ; https://cursor.com/docs/cloud-agent/identity.md |
| SDK için BYOK / yerel model | Bulunamadı | https://cursor.com/help/models-and-usage/api-keys |
| Node SEA ile tek ikili | Sürüm bağımlı | https://nodejs.org/api/single-executable-applications.html |
| Kubeconfig exec credential plugin sözleşmesi | | https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins |
| Kyverno PolicyReport / Gatekeeper constraint durumu | | https://kyverno.io/docs/ ; https://open-policy-agent.github.io/gatekeeper/ |
| PG ayrıştırıcı bağlaması (`libpg_query`) | | https://github.com/pganalyze/libpg_query |
| Kabuk AST (tree-sitter-bash) | | https://github.com/tree-sitter/tree-sitter-bash |
| OS anahtar zinciri bağlaması | `keytar` arşivlenmiş görünüyor | https://github.com/Brooooooklyn/keyring-node |
| Redaksiyon kural seti | | https://github.com/gitleaks/gitleaks |
| GitHub Actions log/run API ve gerekli izinler | | https://docs.github.com/en/rest/actions |
| Cedar / OPA'nın yerleşik değerlendirici yerine geçmesi | ADR konusu | https://docs.cedarpolicy.com ; https://www.openpolicyagent.org/docs |
| MCP `Tasks` ve `Skills over MCP` uzantıları | Yeni | https://modelcontextprotocol.io/specification/latest |
| Yerel sunucuların (Ollama/vLLM/llama.cpp) OpenAI uyumluluğu ve araç çağrısı kalitesi | Sürüm bağımlı | ilgili projelerin dokümanı |
| kubectl-ai `readOnlyOps/writeOps` listeleri | Ajan okumadı | https://github.com/GoogleCloudPlatform/kubectl-ai (pkg/tools/kubectl_filter.go) |
| ocm-mcp-server ayrıntıları | Yalnız PyPI sayfasından okundu | https://pypi.org/project/ocm-mcp-server/ |
| CVE-2026-47250 ayrıntısı | İkincil kaynaklardan | https://nvd.nist.gov/vuln/detail/CVE-2026-47250 |
| self-orchestrating-devsecops | 404; kullanıcı kararı: listeden çıkar, "okunamadı" notu kalsın | — |
| bubblewrap / seatbelt ile sandbox, D-Bus/Secret Service soketinin kapatılması, sandbox altında ağ ilkesi | Üç platformda davranış doğrulanmadı | https://github.com/containers/bubblewrap ; macOS `sandbox-exec`/Seatbelt belgeleri (resmî olarak "deprecated" notu olabilir) |
| PostgreSQL sütun kökeni (`RowDescription` tablo/sütun kimliği) ve MySQL/SQL Server karşılıkları | Köken yalnız doğrudan sütun başvurularında var | https://www.postgresql.org/docs/current/protocol-message-formats.html |
| Terraform plan/state JSON'da `*_sensitive` bayrakları ve değerlerin JSON'da bulunup bulunmadığı | Sayfa bayrakları anlatıyor, değerlerin maskelenip maskelenmediğini açıkça söylemiyor | https://developer.hashicorp.com/terraform/internals/json-format |
| `terraform plan -lock=false` ve reader kimliğiyle plan; OpenTofu uyumu; `terraform providers schema -json`; `provider_installation` yerel aynası | Sürüm/backend bağımlı | https://developer.hashicorp.com/terraform/cli ; https://opentofu.org/docs |
| HashiCorp Terraform MCP Server güncel araç listesi ve yazma yetenekleri | Araç adları sürümler arasında değişiyor | https://developer.hashicorp.com/terraform/docs/tools/mcp-server ; https://github.com/hashicorp/terraform-mcp-server |
| Red Hat Ansible geliştirme araçları MCP sunucusu ve `ansible.mcp` koleksiyonu | Yalnız girişi okundu | https://developers.redhat.com/articles/2026/08/19/red-hat-ansible-development-tools-mcp-server ; https://catalog.redhat.com/software/collection/ansible/mcp |
| Ansible check modunun garantileri (`check_mode: false`, desteklemeyen modüller, `command/shell`), `ansible.cfg` yükleme önceliği ve plugin yolları | Sayfa 429 verdi, okunamadı | https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_checkmode.html ; https://docs.ansible.com/ansible/latest/reference_appendices/config.html |
| Anthropic istem önbelleği (`cache_control`, TTL, min boyut, fiyat) ve "tool search" benzeri tembel araç yükleme özelliği | Resmî sayfa yalnız önbellek için bulundu; tool search doğrulanamadı | https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching |
| MCP `subscriptions/listen`, `listChanged` ve araç listesi önbellekleme (`ttlMs`, `cacheScope`) ayrıntıları | Spesifikasyon 2026-07-28 yeni; uygulama notları | https://modelcontextprotocol.io/specification/latest/server/tools |

## 16. Kararlar (kullanıcı yanıtları) ve kalan açık sorular
**Kesinleşen kararlar**
- **Teslimat:** tasarım `docs/design/` altında markdown olarak repoya yazılacak; tam taslak bu turda, sonra tur tur revize.
- **Q1 — Eksik repo:** `suhail39ahmed/self-orchestrating-devsecops` listeden çıkarıldı; belgede "okunamadı" notu kalır (§10). Doğru URL gelirse eklenir.
- **Q2 — Platform:** v1 = **Linux + macOS**; Windows Faz 3.
- **Q3 — Cursor sırası:** Cursor ilk sağlayıcı; **Faz 0 kapanışı WP8 spike sonucuna bağlı** (geçmezse OpenAI-uyumlu `loopOwner=host` ile kapanır, Cursor tavsiye kipinde kalır).
- **Q5 — Politika motoru:** küçük yerleşik değerlendirici; arayüz Cedar/OPA'ya açık (ADR-0005).

**Varsayılan olarak kabul edilen (itiraz edilebilir)**
- **Q4.** İlk pipeline = GitHub Actions (sözleşme tarafsız; ikinci uygulama Faz 3; Faz 1'de ikinci sistemin `runs.list/run.get` kısmı fixture ile sözleşme testinde).

**Kalan açık sorular**
- Yerel sandbox'ın (bubblewrap/seatbelt) kullanıcının dağıtımında kurulu olmaması durumunda ürün davranışı (öneri: Terminal'i dar yerleşik kümeye düşür, Cursor'u tavsiye kipine al, kullanıcıyı bilgilendir) onay ister mi?
- Kullanıcıların kendi kataloğa komut eklerken sınıf beyanını ne kadar kolay yapabileceği (UX): `ops catalog add` sihirbazı mı, YAML mı? (Faz 1 ADR.)


[← Belge dizini](00-overview.md#belge-dizini)
