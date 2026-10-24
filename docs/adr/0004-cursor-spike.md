# ADR-0004: Cursor SDK doğrulama spike'ı

Durum: **beklemede** — geçerli Cursor API anahtarı ve sandbox'lı hedef işletim sistemi gerektirir; otomatik geliştirme ortamında yapılamadı.

## Yapılacak denetimler (docs/design/05-technology.md §6.4-11)
1. `tools` ile yalnız özel araçlar bırakılabiliyor mu?
2. SDK sandbox'ı ve OS sarmalayıcı hedef işletim sistemlerinde açılıyor mu?
3. `request` olayı nasıl yanıtlanır?
4. Hook deny-all çalışıyor mu?
5. `tools: []` metin modunda bağlam sızıntısı yok mu?
6. Hook'lar `settingSources` ile/olmadan yükleniyor mu?
7. OS sarmalayıcı altında SDK sağlayıcı uçlarına bağlanabiliyor mu?

Sonuç bu dosyaya işlenir; herhangi biri başarısızsa Cursor yalnız tavsiye kipinde kalır.
