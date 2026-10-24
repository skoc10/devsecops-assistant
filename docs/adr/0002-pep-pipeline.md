# ADR-0002: Tek boru hattı (Tool Gateway / PEP)

Durum: kabul edildi (tasarım r2)

## Karar
Model, ajan, skill veya dış süreç yetki taşımaz. Her araç çağrısı 14 adımlık tek boru hattından geçer: şema → profil → hedef pini → sınıflama → politika → bağlam etiketi/taint → onay → denetim (intent, write-ahead) → lease → adapter → lease bırak → redaksiyon + kompaktlaştırma → denetim (result) → egress kontrolü (docs/design/02-architecture.md §3.2).

## Sonuçlar
- Denetim yazılamazsa çağrı çalışmaz (fail-closed).
- Adapter yalnız opak `CredentialHandle` görür; çıktı boru hattı adapter dışındadır ve atlanamaz.
- Kompaktlaştırma redaksiyondan **sonra** çalışır.
- Faz 0'da `ask` kararı `deny` olarak uygulanır (onay kapısı v0 Faz 1'de gelir).
