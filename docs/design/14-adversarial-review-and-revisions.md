# İzlenebilirlik, karşıt inceleme ve revizyonlar

## 17. Gereksinim izlenebilirliği
| İstek | Bölüm |
|---|---|
| İç terminal: sınıflama, denetim, onay, kimlik çağrı anında | §3.2, §3.6, §3.5, §7.3 |
| Terminal ajanları, Cursor SDK, ikinci ajan, tehdit modeline "local ≠ yerel model" | §3.7, §5.5, §6.4, §9-T6 |
| Küme kimliği: profil, tek bağlam değil, okuma ağırlıklı | §8.1–8.3, §7.1 |
| Veritabanı: reader/writer, SQL sınıflama, maskeleme, PostgreSQL ilk | §8.4, §7.2, §12 (S-02/S-03) |
| Uzmanlık: iki model karşılaştırması, skill, kullanıcı skill'i, kimlik kasada | §4 |
| Modeller: değiştirilebilir, yerel, denetimde sağlayıcı, yetki sağlayıcıdan bağımsız | §3.7, §6.5, §3.8 |
| Ekstra ihtiyaçlar v1/sonra kararı | §11.1 |
| Tehdit modeli (8 madde + ek) | §9 |
| Piyasa incelemesi, örüntü seçimi | §10 |
| 12 başlık, dosya ağacı, ilk beş iş paketi | §1–§13 |
| Bağımsız karşıt inceleme bulguları ve karşılıkları | §18 |
| **r2:** Tek kullanıcı kapsamı (ekip sunucusu yok) | §2, D1, D12, §11.2 |
| **r2:** Token ekonomisi — skill ve MCP kullanımı | D15, §4.5, §3.2-12, §5.3-8/9, §7.3, §12 (B-xx) |
| **r2:** Terraform/Ansible yazabilme | D16, §1, §4.2, §5.4, §7.5, §9 (T18–T21), §12 (S-17..S-20), §11.2 (Faz 1b, 2) |

## 18. Bağımsız karşıt inceleme: bulgular ve karşılıkları (r0 → r1)
Bu belge r0 halinde, taslağın sonucunu bilmeyen ayrı bir mimari ajanına "atlatma yolları, çelişkiler, eksik gereksinimler, aşırı mühendislik, fazla güven veren iddialar" odağıyla okutuldu. Bulgular ve işleniş biçimi:

| Bulgu | Karşılık |
|---|---|
| Kasa dışı ortam kimlikleri (`~/.kube/config`, bulut CLI depoları); `shell.run` jail'i yol/HOME izolasyonu içermiyor; cursor-host aynı UID | §3.6 OS sandbox + izole HOME + kimlik yolları bağlanmaz; §8.2-4 ortam kimliği uyarısı; §6.4-2 OS sarmalayıcı; T15 |
| Exec eklentisi allowlist'i yalnız ikili+hash; import/doktor PEP dışında çalışıyor; "env temiz" ile çelişki | §3.5 argv şablonu + sandbox'lı broker yolu + `ambient_dependencies` ve dürüst beyan; T17 |
| Cursor bekçisi tespit edicidir; `disallowedTools` açık-varsayılan; hook/`settingSources` çelişkisi; egress mekanizması yok | §6.4 madde 2–7, 11: allowlist birincil, OS sarmalayıcı, bekçi "tespit edici", hook yerleşimi spike'ta, ağ ilkesi mekanizması |
| Taint yalnız `mutate+`; karantina özetleyici çıktısı taint'i taşır | §3.2-6 bağlam etiketi (başka profile/daha hassas okuma, dış kanal), §4.2 şema-tipli alanlar |
| `report.write` → `git` yürütme zinciri; ağlı "read"; `scripts/` hash'i güvenlik değil bütünlük | §7 `scope`/`network` eksenleri, §3.6 git sertleştirme, T16 |
| Onay kanalı kimlik doğrulaması; belirteç kapsamı; yanlış çapraz referans | §3.2-7 `/dev/tty`, ayrı araç soketi; T11; S-16 |
| Hassasiyet sonuç başına izleniyor; yerel model yokken davranış belirsiz | §3.2-14 bağlam düzeyi egress, `no_eligible_provider`; T14 |
| Ham kanıt kasası aşaması belirsiz; replay araç çağırıyor mu | §3.8: M1–M5 sonrası; replay kayıtlı sonuç oynatır |
| `k8s.apply.diff` "read" ↔ doktor çelişkisi | §7.4 iki kip (`client` / `server-dry-run`) |
| `compare` kipi tek bağlam kuralını deliyor | §8.3 yalnız kullanıcı başlatır, read-only, atıf yasağı, bilinçli istisna |
| Onay gruplaması ↔ eylem hash'i; MCP köprüsü ↔ Faz 0 IPC; "bilinmeyen" sınıfı belirsiz; `local-write` sıralama dışı | T7; §3.7 "araç köprüsü"; D5 `destroy` muamelesi; §7 `scope` ekseni |
| Faz bağımlılıkları: T6/T8 hangi fazda; WP2↔S-04; Faz 0 kabulü gerçek sağlayıcı ister | D13 ve §9 Faz notları; WP yeniden kesimi; kabul #2/#5 elle kabul (WP8) |
| Eksik gereksinimler: MySQL/SQL Server sözleşmesi, denetimde redakte çıktı, AgentRuntime genel yükümlülükleri, `opsd`/UDS/TUI hiçbir WP'de, S-06 Cursor ayağı | §5.4 `DatabaseDriver`; §3.8 `outputRedacted`; §3.7 yükümlülükler; WP7; S-06 |
| WP3/WP2/WP4/WP5a sığmaz; kabuk sınıflayıcı Faz 0'da gereksiz; sahte API atanmamış | §13.2: WP yeniden kesildi, Faz 0 = WP1–WP8, kabuk Faz 1'e, fake API WP5'e |
| Fazla güven veren iddialar: zeroize, "adapter hiç görmez", "4 bağımsız katman", M4, hash zinciri, kanıt-hedef eşleşmesi, `test_fixture` etiketi, doktor yalnız import'ta | §3.5 sınır; D4; §8.4/T3 bağımlı-bağımsız ayrımı; §7 M4; §3.8; §3.3 `subject`; §12.1 imza + izole `OPS_HOME`; §8.2-5 oturum başı doktor; D14 etiketleri |
| Aşırı mühendislik: ekip sunucusuna hazırlık soyutlamaları (r2'de ekip sunucusu tamamen kapsam dışı), Cedar/OPA arayüzü, iki `loopOwner` kipi | D12: imzalı onay, harici sink vb. v1 dışı; politika arayüzü minimal; **iki `loopOwner` kipi korundu** (ikinci sağlayıcı gereksinimi ve arayüzün Cursor biçimli kalmaması için) |

**Bilinçli olarak kabul edilmeyen veya kısmen alınan:** iki `loopOwner` kipi tamamen sadeleştirilmedi (yukarıda gerekçe); kabuk sınıflayıcının Faz 1'e kayması "iç terminal zorunlu yetenek" gereksinimini bozmaz çünkü Faz 0 kabulü kabuğa bağlı değildir ve sözleşme/PEP yolu Faz 0'da hazırdır.

## 19. r2 revizyonu: kullanıcı geri bildirimi
| İstek | Ne değişti | Yan etki / maliyet |
|---|---|---|
| **Tek kullanıcı yeterli; ekip sunucusu Faz 4'e gerek yok** | Ekip sunucusu, OIDC, merkezi kasa/denetim, imzalı onay belirteci ve "B'ye hazırlık" soyutlamaları **tamamen kaldırıldı** (D1, D12, §2, §4.3, §11); Faz 4 silindi, çevrimdışı paket Faz 3'e taşındı | Güvenlik yüzeyi küçüldü; `principal` sabit `local-user`; harici denetim sink'i yalnız isteğe bağlı Faz 3 |
| **Token tüketimi asgari; skill ve MCP önemli** | Yeni **D15** ve **§4.5** (11 mekanizma): deterministik önişleme, tembel skill, tembel araç seti, MCP'nin iki dar rolü (araç köprüsü + kanıtı kaynak olarak sunma), referansla taşıma, bağlam defteri, model kademeleri, önek kararlılığı/önbellek, paralel okuma planı, ölçüm; PEP çıktı hattına kompaktlaştırma (§3.2-12); araç tanımına `toolset/projection/typical_output_tokens` (§5.1); `evidence.get` dilimleme (§7.3); WP2/WP3/WP5/WP7 teslimleri; Faz 0 kabul #7; B-01..B-05; MCP istemci köprüsü v0 Faz 3'ten **Faz 1b'ye çekildi** (yalnız read) | Başlangıç hedefleri (≈3k önek, ≤1,5k/sonuç) **ölçülüp ayarlanacak**; Cursor SDK'da önbellek kontrolü belgelenmemiş (yalnız ölçülür) |
| **Terraform ve Ansible yazabilmeli (planda yoktu)** | r1'de IaC yalnız tarama hedefi ve `terraform validate` kataloğu olarak geçiyordu. Şimdi **D16**, §1 (Yapar/Yapmaz), skill'ler `terraform` + `ansible` (§4.2), adapter türü `iac` (§5.4), **§7.5** (worktree, `fs.write`, `iac.*`, `ansible.*`, HCL/playbook ön-taraması, SSH/vault, CI tanımı yasağı), T18–T21, S-17..S-20, **Faz 1b** (yerel yazma+doğrulama) ve Faz 2 (plan/check/PR; `apply` ve `ansible.run` varsayılan kapalı), HashiCorp Terraform MCP sunucusu ve Red Hat Ansible MCP örnekleri (§10) | **Faz 1 büyüdü** (1a + 1b); IaC kod çalıştıran bir yüzeydir → ön-tarama `Best-effort`, dinamik ifadelerde sandbox ikinci hat; Terraform/Ansible ikilileri ürünle gelmez (kullanıcı kurar, `ops doctor` bulur) |

**Alınan karar (itiraz edilebilir):** IaC için varsayılan çıktı **dal + diff / PR**'dır; `terraform apply` ve `ansible-playbook` gerçek koşusu hedefin kendi pipeline'ına bırakılır, ürün içinde yalnız Faz 2'de ve politika+onayla açılabilir.


[← Belge dizini](00-overview.md#belge-dizini)
