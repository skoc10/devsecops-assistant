# Ajan modeli ve token ekonomisi

## 4. Ajan modeli

### 4.1 Karşılaştırma

| Ölçüt | A. Alan başına ajan | B. Tek orkestratör + skill |
|---|---|---|
| En az yetki | Güçlü (araç yüzeyi alan başına) | Orta; PEP profil bazlı sınırlar, skill yetki vermez |
| Kimlik | Her ajan kimlik ister → çoğalma riski (**gereksinim: reddedilir**) ya da ortak broker şart | Tek broker, tek yol |
| Çapraz-alan korelasyonu | Ajanlar arası mesajlaşma, bağlam kaybı | Tek bağlam, kanıt deposu ortak |
| Denetim | Dağınık, birleştirme gerekir | Tek iz |
| Maliyet/gecikme | Çok ajan, çok tur | Tek döngü |
| Kullanıcı genişletmesi | Yeni ajan = kod | Yeni skill = markdown |
| Araç sayısı büyüyünce | İyi | Seçim doğruluğu düşer (skill başına araç seti açılarak azaltılır) |
| Enjeksiyon etki alanı | Ajan sınırı içinde | Bağlamdaki tüm açık araçlar (taint politikası ile azaltılır) |
| Model yönlendirme | Alan başına model | Skill başına model yönlendirme ile eşdeğer |
| **Token tüketimi** | Her ajanın kendi sistem istemi + araç şemaları + ajanlar arası mesajlaşma; bağlam çoğalır | Tek kararlı önek (önbelleklenebilir), skill/araç seti tembel, tek kanıt defteri, referansla taşıma (§4.5) |

### 4.2 Öneri: B, ve izole alt-çalışan
- **Tek orkestratör + skill.** Skill = alana ait oyun kitabı (talimat + kontrol listesi + sorgu kalıpları). Skill **yetki taşımaz**; `allowed-tools` yalnız talep, karar PEP'te.
- **İzole alt-çalışan (aynı çalışma zamanı, daha dar hibe):** (a) *Karantina özetleyici* — ham log/çıktıyı okur, **araçsız** ve kimliksiz, yapılandırılmış özet döner (dual-LLM / quarantine kalıbı). Ham serbest metin (log, event mesajı, diff, DB hücresi) **varsayılan olarak ana bağlama girmez**: karantina özetleyiciye gider; ana modele yalnız **şema-tipli** alanlar (enum, sayı, bool, zaman damgası, kalıp-doğrulamalı kısa tanımlayıcı) döner ve bunlar taint'siz sayılır; özetin serbest metin alanları taint'li kalır. Ham alıntı UI'da kullanıcıya gösterilir, ana modele değil; kullanıcı "ham logu modele ver" derse bağlam tainted olur. (b) *Paralel araştırmacı* — yalnız `read` araçları, ayrı bağlam. Bunlar alan ajanı değildir; kimlik tutmaz, aynı PEP'ten geçer.
- Skill'ler (v1 yerleşik, şirket bilgisi yok): `kubernetes, cloud, pipelines, gitops, containers, secrets, vulnerability, compliance, observability, database, incident-response, terraform, ansible` + `generic-diagnosis` (runbook yokken). `terraform` skill'i OpenTofu ile uyumlu yazılır **[doğrulanacak]**; `terraform` ve `ansible` **ayrı skill**'lerdir (yalnız gereken yüklensin: §4.5). Faz sırası §11.

### 4.3 A'ya geçiş koşulları (herhangi biri sağlanırsa değerlendir)
1. Aynı oturumda etkin araç sayısı sürekli ~40'ı aşıyor ve skill-bazlı açma yetmiyor (ölç: araç seçim doğruluğu, eval seti).
2. Bir alan farklı **güven bölgesi** gerektiriyor ve skill-bazlı model yönlendirme yetmiyor (ör. veritabanı yalnız yerel modelle).
3. Uzun süreli paralel soruşturmalar (saatlerce) tek bağlamı bloke ediyor.
Her durumda **kimlik kasada kalır**, ajanlar yalnız PEP üzerinden çağırır.

### 4.4 Skill sözleşmesi
- Dizin: `skills/<name>/{SKILL.md, ops.skill.yaml, references/, assets/}`; `name` küçük harf-rakam-tire, ≤64, dizin adıyla aynı; `description` ≤1024 ve "ne yapar + ne zaman kullanılır" **[doğrulandı: https://agentskills.io/specification]**.
- Sidecar `ops.skill.yaml`: `requires.adapters`, `requests.toolsets` (araç SETİ adları; uygulamada `requests.tools` yerine bu ad kullanıldı), `model_hint`, `runbook` adımları. `trust_tier` (`builtin | user | imported`) dosyada BEYAN EDİLEMEZ: skill'in yüklendiği dizinden gelir (katı şema bilinmeyen anahtarı reddeder). (Ürün alanları `metadata`'ya konmaz: `metadata` string→string.)
- Progressive disclosure: başlangıçta yalnız `name+description`; etkinleşince gövde; `references/` talep halinde.
- `scripts/` **varsayılan çalışmaz**; yalnız manifestte hash'li ve terminal PEP'inden geçerek.
- Kullanıcı kendi skill'ini `~/.ops-assistant/skills/` altına ekler (`trust_tier: user`); ithal edilenlerde hash gösterilir ve pinlenir. Skill talimatı = potansiyel enjeksiyon yüzeyi, bu yüzden yetki veremez.
- **Runbook:** kullanıcı getirir (markdown). Orkestratör onu bir **plana** çevirir, plan kullanıcıya gösterilir, her adım yine PEP'ten geçer. Runbook bulunamazsa asistan şunu söyler: "Bu soru için runbook bulunamadı; genel teşhis akışını (`generic-diagnosis`) kullanıyorum."

### 4.5 Token ekonomisi (D15)
**İlke:** LLM yalnız *yorumlar*; toplamayı, süzmeyi, korele etmeyi, sınıflamayı ve maskelemeyi kod yapar. Token bir bütçedir ve tasarımın girdisidir; sonradan optimizasyon değildir. Sebep yalnız maliyet değil: bağlam küçüldükçe enjeksiyon yüzeyi ve araç-seçim hatası da küçülür.

| # | Mekanizma | Nasıl çalışır | Faz |
|---|---|---|---|
| 1 | **Deterministik önişleme (kompozit okuma araçları)** | `k8s.workload.health`, `timeline.build`, `db.stats.summary`, tarayıcı/analizci çıktısı okuma: ham nesne yerine **türetilmiş yapı** döner (k8sgpt analizör fikri). Model ham YAML/JSON'u görmez. Araç tasarım kuralı: §5.3-8 | 0 |
| 2 | **Skill'ler tembel yüklenir** | Başlangıçta yalnız `name+description` (≈100 token/skill), etkinleşince gövde (önerilen <5000 token, <500 satır), `references/` talep halinde **[doğrulandı: agentskills.io/specification]**. Ürün kuralları: aynı anda en çok 2 skill gövdesi etkin; `description` yönlendirme için yazılır ("ne yapar + ne zaman"); skill linter gövde boyutunu denetler | 0 |
| 3 | **Araç setleri (toolset) skill'e bağlı ve tembel** | Açılışta yalnız **çekirdek araçlar** (≈8: `skill.list/load`, `evidence.get/search`, `timeline.build`, `*.profile.describe`…); skill etkinleşince `ops.skill.yaml → requests.toolsets` ile yalnız ilgili araç seti bağlama eklenir. Toolset fikri containers/kubernetes-mcp-server'dan: daha az bağlam, daha doğru araç seçimi **[doğrulandı: sayfa]**. Araç `description` ≤ 2 cümle; şema alan açıklamaları asgari. **Araç sırası deterministik ve sabit** (önbellek isabeti; MCP spesifikasyonu da deterministik sıralamayı bu sebeple öneriyor **[doğrulandı: MCP 2026-07-28, server/tools]**) | 0 / 1 |
| 4 | **MCP — iki dar rol** | (a) **Araç köprüsü**: Cursor/ikinci ajan ve MCP istemci köprüsü (dış MCP sunucuları, örn. sağlayıcı dokümanı arama). (b) **Kanıtı kaynak olarak sunmak**: büyük sonuç bağlama girmez; araç `resource_link` + `structuredContent` döner (`evidence://<id>`), model `evidence.get(id, select, limit)` ile yalnız gereken dilimi çeker **[doğrulandı: MCP araç sonucu `resource_link`, `outputSchema`, `structuredContent` destekler]**. Köprü yalnız **etkin araç setini** listeler: `tools/list` yetkilendirmeye göre değişebilir, `listChanged` ile güncellenebilir, ama bağlantıya göre değişmemelidir **[doğrulandı]** → etkin set oturum belirtecinin kapsamından türetilir. **Bir MCP sunucusunun bütün araçlarını körlemesine bağlamak yasak** (maliyet + T9). `Skills over MCP` ve `Tasks` uzantıları izlenir **[doğrulanacak]** | 0 (iç) / 1 (istemci v0) / 3 (sunucu yüzü) |
| 5 | **Sonuç referansla taşınır** | PEP çıktı hattı (§3.2-12) tam redakte sonucu Evidence Store'a yazar; modele **kompakt görünüm + `evidence_id`**. Kompakt görünüm: alan projeksiyonu (`select`), varsayılan/boş alan ve `managedFields` atma, sütunlu tablo biçimi, top-N + toplam sayı, zaman penceresi, sayfalama; **log:** normalize edilmiş satırları kümele (sayaç + ilk/son zaman), hata/uyarı öncelikli, baş+kuyruk; **delta:** "son gözlemden beri değişen" | 0 |
| 6 | **Bağlam defteri (ledger) + sıkıştırma** | Ham sonuç mesajları döngüde tutulmaz. Konuşma durumu = `{hedef, hipotezler, kanıt defteri (id + tek satır özet + subject), açık sorular}`. Eşikte eski turlar defterden üretilen özetle değiştirilir. **Cursor kipinde** (stateless-per-tur, §6.4-5) her tura ham transkript değil **defter özeti** gönderilir: resume'a güvenmemek token maliyetini artırmaz | 0 |
| 7 | **Model kademeleri** | Karantina özetleyici, sınıflama/etiketleme, log kümeleme gibi dar işler **küçük/ucuz** modele; çok adımlı akıl yürütme büyük modele; hassas veri yerel modele. `ModelProvider` yetenek bildirimine `tier` ve `cost_class`; skill'in `model_hint`'i yönlendirir (DojOps `ModelRouter` ve Open Horizons `model-routing` örnekleri, bkz. §10) | 1 |
| 8 | **Önek kararlılığı ve istem önbelleği** | Sistem istemi + çekirdek araçlar + skill metaverisi **sabit sırada, kararlı önekte**; değişken içerik (defter, son sonuçlar) sona. Host-owned sağlayıcılarda sağlayıcı istem önbelleği (Anthropic `cache_control`; okuma yazmadan çok daha ucuz, TTL ve min boyut sağlayıcıya bağlı) **[doğrulanacak: https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching]**. Cursor SDK'da önbellek kontrolü belgelenmemiş → yalnız ölçülür | 1 |
| 9 | **Plan-sonra-yürüt ve paralel okuma** | Model bir **okuma planı** (bağımsız birden çok araç çağrısı) önerir; PEP paralel yürütür ve **tek birleşik kanıt görünümü** döner → LLM tur sayısı düşer. Runbook adımları deterministik yürütücüyle koşar; model yalnız plan ve sonuç yorumunda | 1 |
| 10 | **Ölçüm ve bütçe (Faz 0'dan)** | Her model çağrısı için `tokens_in/out/cache_read` (sağlayıcı `usage`; Cursor SDK `usage` olayı ve `RunResult.usage` **[doğrulandı]**), her araç sonucu için `result_tokens_est`; denetim kaydına yazılır; `ops usage` raporu (oturum/skill/araç kırılımı). Politika: oturum yumuşak/sert eşik, tur başına en çok araç çağrısı, **sonuç başına tavan** (aşan otomatik referansla) | 0 ölçüm / 1 politika |
| 11 | **Ham serbest metin ana bağlama girmez** | §4.2 karantina özetleyici; aynı zamanda token tasarrufudur | 1 |

**Başlangıç hedefleri** (ölçülüp WP7'de ayarlanacak; söz değil, regresyon eşiği): başlangıç öneki (sistem + çekirdek araçlar + skill metaverisi) ≈ ≤3k token; etkin skill gövdesi ≤5k; tek araç sonucu ≈ ≤1,5k token; Faz 0 bitiş senaryosunda ana bağlama giren toplam araç sonucu ≈ ≤8k token.
**Testler:** B-01 başlangıç öneki boyutu, B-02 skill linter, B-03 referansla taşıma, B-04 token bütçesi regresyonu, B-05 önek kararlılığı (§12).


[← Belge dizini](00-overview.md#belge-dizini)
