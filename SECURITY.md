# Güvenlik

## Bildirim

Güvenlik açıklarını **herkese açık issue olarak açmayın.** GitHub'ın özel güvenlik bildirimi (Private vulnerability reporting / Security Advisories) üzerinden depo sahibine bildirin. Bildirimde sürüm, yeniden üretim adımları ve etkisini belirtin; gerçek secret, kubeconfig veya bağlantı dizesi eklemeyin.

## Tehdit modeli özeti

Ayrıntı: [docs/design/08-threat-model.md](docs/design/08-threat-model.md). Her kontrolün güncel durumu: [docs/STATUS.md](docs/STATUS.md).

| Tehdit | Ana kontrol |
|---|---|
| Model hatalı/enjekte komut üretir | Şema doğrulama, deterministik sınıflayıcı (sınıflanamayan = `destroy` muamelesi), profil sınıf tavanı |
| Araç çıktısı sonraki tura talimat olur | Bağlam etiketi + taint, karantina özetleyici, taint altında `ask` |
| Reader kimliğiyle yazma | Bağımsız katmanlar: araç yüzü, AST allowlist, rol yetkisi; doktor |
| Yanlış profil / hedef | Her çağrıda açık profil, hedef pini, kapsam, kanıt `subject` eşleşmesi |
| Secret log/modele gider | Kasa + lease, M1–M4 redaksiyon, bilinen-secret taraması (M3), egress kontrolü |
| Dış ajanın serbest kabuğu | Araç allowlist'i + OS sandbox + araç köprüsü; bekçi yalnız tespit edicidir |
| Onay yorgunluğu | Okuma sormaz, dar kurallar, onay bütçesi, artan sürtünme |
| Denetimsiz break-glass | Denetim kapatılamaz (fail-closed), gerekçe + TTL + banner |

## Bilinen sınırlar (özet)

- Aynı kullanıcı hesabında ptrace/bellek okuyabilen zararlı süreç **kapsam dışıdır**.
- Kullanıcının kendi kabuğunda / ortamında duran kimlikler (ör. `~/.kube/config`) ürünün denetimi dışındadır; yalnız uyarılır.
- Denetim zinciri **tamper-tespit** sağlar, tamper-önleme değil; kuyruk kesme dış çapa olmadan tespit edilemez.
- JS bellekte secret silme **en iyi çabadır**.
- Sütun maskeleme (M4) `Best-effort`tur; en güçlü savunma veritabanında maskeli view'dır.
