# ops-assistant — Genel Amaçlı DevSecOps Asistanı: Tasarım Taslağı (r2)

> Durum: tasarım r2. Uygulama sürüyor; gerçekleşen durum için [../STATUS.md](../STATUS.md) dosyasına bakın. Bu belgedeki "kod yok" ibaresi tasarım turu içindi; kod `packages/` altındadır.
> Sözleşme: modül, API, dosya ve protokol adları İngilizce. Güncel olmadığı düşünülen her bilgi **[doğrulanacak: adres]** ile işaretli. Hiçbir yerde secret değeri, kubeconfig veya connection string yoktur; testlerdeki canary değerleri çalışma anında rastgele üretilir ve commit edilmez.

## Context

Boş bir depo (`skoc10/devsecops-assistant`, commit yok) üzerinde, **belirli bir şirkete, kümeye, pipeline'a veya runbook'a bağlı olmayan** bir DevSecOps asistanı tasarlanıyor. Kullanıcı kendi ortamını tanır; ürün kaynaklara bağdaştırıcılarla konuşur. Asistan: sohbet eder, kendi terminalini politika altında kullanır, bağlı sistemlerden kanıt toplar, değişiklik önermeden önce ne yapacağını gösterir ve yalnız izin verilen sınıfta işlem yapar.

Tasarımın dayandığı temel gözlem: piyasadaki araçların çoğu ya **salt okunur araştırmacı** (teşhis), ya **deterministik tarayıcı/analizci**, ya da **onaylı değişiklik** örüntüsünü uyguluyor; kimlik yönetimi ise çoğunlukla "ajan kubeconfig'i görür" modeline dayanıyor ve araç-çıktısı enjeksiyonu / argüman enjeksiyonu açıkları gerçek (bkz. §10, CVE-2026-47250 örneği). Bu ürünün farkı: **kimlik asla ajana verilmez, her araç çağrısı tek bir politika boru hattından geçer, değişiklik öneri olarak çıkar.**

Araştırma: 9 listelenen ürün + ek rakipler, 3 paralel araştırma ajanı ve web ile okundu (sonuçlar §10). Ürün ve API bilgisi **sayfa esas alınarak** yazıldı; sayfada bulunamayan her şey "doğrulanacak".

---

## 0. Karar özeti (tek bakışta)

| # | Karar | Seçim | Tek cümle gerekçe |
|---|---|---|---|
| D1 | Kurulum | **Yalnız tek kullanıcılı yerel daemon (`opsd`) + CLI/TUI.** Ekip sunucusu / çok kullanıcılı mod planda **yoktur** (Faz 4 kaldırıldı) | Kimlik zaten kullanıcının makinesinde; çok kullanıcılı yetkilendirme ve ortak kasa hiç gerekmez, saldırı yüzeyi küçük kalır |
| D2 | Ajan modeli | **Tek orkestratör + yüklenebilir skill**; ağır/riskli veri işleme için *kimliksiz, araçsız* izole alt-çalışan | Tek PEP, tek denetim izi, çapraz-alan korelasyonu tek bağlamda; alan başına ajan kimlik çoğaltır |
| D3 | Güvenlik omurgası | **Tool Gateway (PEP)**: her çağrı tek boru hattı; model/ajan/skill hiçbiri yetki taşımaz | Model değişince yetki değişmesin |
| D4 | Kimlik | Kasa + **çağrı başına lease**. Model, skill, dış ajan süreci ve eklenti adapter'ları kimlik materyalini görmez; birinci taraf adapter yalnız opak `CredentialHandle` alır (aynı süreç/heap: bkz. §3.5 sınırı) | Gereksinim: kimlik çağrı anında bağlanır, bitince düşer |
| D5 | Yetki sınıfları | `read < mutate < deploy < destroy`; **sınıflanamayan = `destroy` muamelesi** (tavan izin vermiyorsa ret; çözüm: kataloğa ekleyip sınıflamak). `local-write` ve `network` ayrı eksenler (§7) | Fail-closed |
| D6 | Dil/çalışma zamanı | TypeScript / Node.js; başka dildeki adapter'lar MCP/stdio ile | Cursor SDK ve MCP SDK TS'te birinci sınıf; TUI/daemon/adapter tek dil |
| D7 | Skill biçimi | Agent Skills açık standardı (`SKILL.md`) + ürüne özel `ops.skill.yaml` sidecar | Ekosistem uyumu; `metadata` alanı yalnız string→string |
| D8 | Model katmanı | İki arayüz: `ModelProvider` (döngüyü biz yürütürüz) ve `AgentRuntime` (döngüyü sağlayıcı yürütür). Cursor iki arayüzde de var, kabuğu kapalı | Cursor SDK ajan-biçimli; düz chat-completion değil |
| D9 | Örüntü birleşimi | **Investigate → Propose → Approve → Apply**: HolmesGPT-tarzı salt okunur araştırma + k8sgpt/Trivy-tarzı deterministik analizci girişi + ocm-mcp-server-tarzı öner/onayla/uygula | Varsayılan %90 okuma; değişiklik artefakt olarak çıkar |
| D10 | Denetim | Hash zincirli JSONL, **write-ahead, fail-closed** (denetim yazılamazsa çağrı çalışmaz) | Denetimsiz break-glass olmasın |
| D11 | Yetki tavanı | Faz 0–1: yalnız `read`. Faz 2: onaylı `mutate`/`deploy`. `destroy` varsayılan kapalı | "Önce kanıt, sonra öneri, sonra onay" |
| D12 | Kapsam disiplini (bilerek **v1 dışı**) | Ekip sunucusu / OIDC / merkezi kasa-denetim, Cedar/OPA entegrasyonu, imzalı onay belirteci, MCP **sunucu** yüzü (dış istemcilere), kod-yürütme kipi, tersinir tokenizasyon, harici denetim sink'i, web UI, Windows. (Bulut adapter'ları Faz 3.) | v1'i dar tutmak; arayüzler bu genişlemelere kapalı kalmaz |
| D13 | "v1" tanımı | v1 = Faz 0–2. Her kontrolün **hangi fazda devreye girdiği** belirtilir; hiçbir kontrol, ait olduğu fazdan önce "var" sayılmaz | Dürüst kapsam |
| D14 | Güvenlik beyanı | Her kontrol `Enforced` / `Best-effort` / `Planned` etiketiyle yazılır; "garanti" yalnız bağımsız katmanlar için | Fazla güven veren iddia yok (inceleme bulgusu) |
| D15 | **Token ekonomisi** (birinci sınıf hedef) | LLM yalnız yorumlar; toplama/süzme/korelasyon/sınıflama/maskeleme koddur. **Skill'ler ve araç setleri tembel yüklenir**; sonuçlar **referansla** (`evidence_id`) taşınır; MCP yalnız **dar, etkin araç setiyle** ve kanıtı kaynak olarak sunmak için kullanılır; bağlam defteri + model kademeleri + önek kararlılığı; token ölçümü Faz 0'dan (§4.5) | Maliyet ve gecikme; ayrıca küçük bağlam = küçük enjeksiyon yüzeyi |
| D16 | **Altyapı kodu (Terraform/OpenTofu, Ansible)** | Ajan IaC **yazar → doğrular → PR/değişiklik dosyası olarak çıkarır**; uygulama (`apply`/`ansible-playbook`) varsayılan olarak hedefin kendi pipeline'ına bırakılır. Yazım yalnız **git worktree**'de, gizli dosya/CI tanımı denylist'iyle; kod çalıştıran yapılar (external data, provisioner, `lookup('pipe')`…) ön-taranır (§7.5) | "Hedefin onay mekanizmasını atlama" ilkesi; IaC aynı zamanda yürütülebilir koddur |


---

## Belge dizini

> Belgelerdeki `§` numaraları tüm dosyalarda ortak numaralamadır (ör. §4.5 = `03-agent-model.md`).

- [Genel bakış ve karar özeti](00-overview.md)
- [Ürün sınırı ve kurulum modeli](01-scope-and-install.md)
- [Mimari](02-architecture.md)
- [Ajan modeli ve token ekonomisi](03-agent-model.md)
- [Bağdaştırıcı sözleşmesi](04-adapter-contract.md)
- [Teknoloji](05-technology.md)
- [Araç listesi](06-tools.md)
- [Kimlik ve oturum ömrü](07-identity.md)
- [Tehdit modeli](08-threat-model.md)
- [Piyasa analizi](09-market.md)
- [Fazlar](10-phases.md)
- [Test](11-testing.md)
- [Dosya ağacı ve iş paketleri](12-tree-and-work-packages.md)
- [Öneriler, doğrulanacaklar, kararlar](13-recommendations-and-open-questions.md)
- [İzlenebilirlik, karşıt inceleme ve revizyonlar](14-adversarial-review-and-revisions.md)
