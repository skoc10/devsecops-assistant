# ADR-0010 — `ops replay`: eylem çizelgesi ve politika what-if; karar girdisi denetime yazılır

Durum: kabul (Faz 1 artıkları). Tarih: 2026-10.

## Bağlam
Tasarım §3.8: "Replay: denetim kaydı + kanıt kasasıyla oturum yeniden oynatılabilir; araçlar yeniden çağrılmaz." Denetim kaydı bilerek **modelin metnini ve kullanıcı iletilerini saklamaz** (gizlilik; ham çıktı hiçbir yerde tutulmaz).

## Karar
- `ops replay` konuşmayı değil **eylem çizelgesini** yeniden kurar: model turları, intent'ler (karar + gerekçe), onaylar, sonuç boyutları/redaksiyon sayıları, break-glass, karantina açma. Zincir doğrulanır; bozuksa çizelgeye güvenilmez (çıkış 1).
- Deterministik tutarlılık denetimleri: intent'siz sonuç, onaysız çalışan `ask`, local-only'de okuma dışı sınıf, prod'da onaysız izin, yarım kalan intent.
- **Politika what-if** (`--policy DOSYA|current`): her kayıtlı politika kararı aday politikayla yeniden değerlendirilir. Bunun için intent ve politika-ret kayıtlarına **karar girdisi** (`decisionContext`: bayraklar, hassasiyet sınıfları, profil kimlikleri, kapsam adları, o anki sınıf tavanı) eklendi; secret/içerik içermez. Gevşeyen kararlar (`⚠ GEVŞER`) ayrıca vurgulanır.
- Araç çağrılmaz, model çağrılmaz, kimlik bağlanmaz.

## Sınırlar (dürüst)
- "Scripted model altında yeniden oynatma" ve araç sonucu yeniden üretimi YOK (metin saklanmadığı için yapılamaz; saklamak gizlilik ilkesine aykırı olurdu).
- What-if, aracı/profili kaydın o anki değil ŞİMDİKİ tanımıyla değerlendirir (tavan ve ortam kayıttan alınır); bu sürümden önceki kayıtlarda `decisionContext` yoktur (atlanır).
- Aynı politika kararları birebir yeniden üretir (testle): karar girdisi eksiksizdir.
