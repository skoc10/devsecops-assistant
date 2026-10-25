# Güvenlik

## Bildirim

Güvenlik açıklarını **herkese açık issue olarak açmayın.** GitHub'ın özel güvenlik bildirimi (Private vulnerability reporting / Security Advisories) üzerinden depo sahibine bildirin. Bildirimde sürüm, yeniden üretim adımları ve etkisini belirtin; gerçek secret, kubeconfig veya bağlantı dizesi eklemeyin.

## Tehdit modeli özeti

Ayrıntı: [docs/design/08-threat-model.md](docs/design/08-threat-model.md). Her kontrolün güncel durumu: [docs/STATUS.md](docs/STATUS.md).

| Tehdit | Ana kontrol |
|---|---|
| Model hatalı/enjekte komut üretir | Şema doğrulama, deterministik sınıflayıcı (sınıflanamayan = `destroy` muamelesi), profil sınıf tavanı |
| Araç çıktısı sonraki tura talimat olur | Bağlam etiketi + taint, taint altında `ask`; opsiyonel karantina: log/olay yerine şema-tipli özet ([ADR-0008](docs/adr/0008-quarantine-typed-digest.md)) |
| Reader kimliğiyle yazma | Bağımsız katmanlar: araç yüzü, AST allowlist, rol yetkisi; doktor |
| Yanlış profil / hedef | Her çağrıda açık profil, hedef pini, kapsam, kanıt `subject` eşleşmesi |
| Secret log/modele gider | Kasa + lease, M1–M4 redaksiyon, bilinen-secret taraması (M3), egress kontrolü |
| Dış ajanın serbest kabuğu | Araç allowlist'i + OS sandbox + araç köprüsü; bekçi yalnız tespit edicidir |
| Onay yorgunluğu | Okuma sormaz, dar kurallar, onay bütçesi, artan sürtünme |
| Denetimsiz break-glass | Denetim kapatılamaz (fail-closed), gerekçe + TTL + banner |
| Bulut modele hassas bağlam | `egress` bölge sınırı (bağlam etiketi ↔ sağlayıcı bölgesi), `--local-only` kipi (PEP'te fail-closed) |
| Zararlı / ithal skill veya runbook | Skill linter (görünmez Unicode hata; enjeksiyon/`curl \| sh`/dış URL uyarı), skill yetki veremez, `scripts/` çalışmaz; runbook adımları tam PEP'ten geçer ([ADR-0009](docs/adr/0009-composite-tools-runbooks.md)) |
| Olay sonrası inceleme | `ops replay`: zincir doğrulama + tutarlılık denetimleri + politika what-if ([ADR-0010](docs/adr/0010-replay-decision-context.md)) |

## Bilinen sınırlar (özet)

- Aynı kullanıcı hesabında ptrace/bellek okuyabilen zararlı süreç **kapsam dışıdır**.
- Kullanıcının kendi kabuğunda / ortamında duran kimlikler (ör. `~/.kube/config`) ürünün denetimi dışındadır; yalnız uyarılır.
- Denetim zinciri **tamper-tespit** sağlar, tamper-önleme değil. Baş çapası zincir anahtarıyla MAC'lidir (silinen/sahte çapa kesmeyi aklamaz); eski geçerli çapanın geri yüklenmesi ve günlük + çapanın birlikte silinmesi dış çapa olmadan tespit edilemez. Aynı günlüğe yazan süreçler (opsd + tek seferlik komutlar) dosya kilidiyle sıralanır.
- JS bellekte secret silme **en iyi çabadır**.
- Sütun maskeleme (M4) `Best-effort`tur; en güçlü savunma veritabanında maskeli view'dır.
- Karantina varsayılan **kapalıdır** ve yalnız log/olay araçlarını kapsar; diğer untrusted araçlar taint ile korunur.
- macOS'ta seatbelt profili güncel sürümde (macOS 27) süreç başlatamıyor; sandbox gerektiren araçlar macOS'ta yalnız `ops vm up` ile açılan **Linux VM'inde bubblewrap** altında çalışır ([ADR-0011](docs/adr/0011-macos-vm-sandbox.md)). VM kapalıysa araçlar **kapalıdır** (fail-closed). VM'e yalnız `OPS_HOME/worktrees` (rw) ve kayıtlı çalışma alanı depoları (ro) girer; `$HOME`, kasa, denetim girmez. Sınırlar: VM kaçışı ve hipervizör/hgfs güvenliği kapsam dışı; sandbox içindeki `network: host` KONUĞUN ağıdır; Cursor çalışma zamanı ve exec kimlik eklentileri VM kipinde desteklenmez; VM yolu CI'da koşmaz (yerel `pnpm test:vm`). Linux/bubblewrap etkilenmez.
- `trust_zone: local` yalnız loopback uca verilebilir; loopback'te dinleyen ve buluta aktaran bir vekil/tünel ürün tarafından görülemez (local-only kullanıcı beyanına dayanır).
- Skill/runbook sezgisel taramaları (`injection_phrase`, `external_url`, …) `Best-effort`tir: temiz çıkış güven değildir.
- Anthropic/OpenAI-uyumlu/Cursor sağlayıcıları ve model kademesi yerel sahte uçlara karşı test edildi; **gerçek servislere karşı doğrulanmadı**.
- `ops replay` modelin metnini göstermez (denetim bunu saklamaz); yalnız eylem çizelgesini kurar.
