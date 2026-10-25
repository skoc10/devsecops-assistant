# ADR-0009 — Bileşik araçlar (`composite`) ve runbook → plan

Durum: kabul (Faz 1 artıkları). Tarih: 2026-10.

## Bağlam
Tasarım §4.4/D15 #9: runbook adımları deterministik yürütücüyle koşmalı, model yalnız plan ve sonuç yorumunda olmalı (tur ve token tasarrufu). Ancak "yürütücü" bir **ikinci yetki yolu** olmamalı: her adım yine PEP'ten geçmeli.

## Karar
1. **Runbook** = kullanıcının markdown dosyası (`OPS_HOME/runbooks/<ad>.md`); numaralı adımlar, adımda en çok bir `` `araç {json}` `` çağrısı, `{{param}}` yalnız JSON **string değerlerinde** yerine konur (yapı enjekte edilemez). Runbook yetki taşımaz.
2. `runbook.plan`: deterministik plan; her adım araç şemasıyla doğrulanır (bilinmeyen araç, geçersiz argüman, eksik parametre, kapalı araç seti, bağlı olmayan profil). Plan **kullanıcıya gösterilir** (`plan` olayı).
3. `runbook.run`: yalnız `read` sınıfı adımları sırayla koşar. Bunun için araç tanımına `composite: true` ve `AdapterCall.nested` eklendi: gateway, bileşik araca bir iç-çağrı işlevi verir; her iç çağrı `ToolExecutor` üzerinden **tam PEP**'e girer (etkin araç seti, tür başına profil enjeksiyonu, politika, taint, onay, denetim, çıktı hattı) — aynı oturum, aynı sağlayıcı bölgesi/etiketi. Denetimde iç intent'in `message` alanı `iç çağrı (üst: <callId>)` taşır.
4. Güvenlik kuralları: iç içe bileşik araç `policy_deny`; okuma dışı adım ASLA otomatik koşmaz (araç seti açık olsa bile `not_read`); onay reddi/denetim/bütçe/local-only hatasında koşu durur; adım başına küçük (≤250 token) VE güvenilir sonuç satır içi döner, diğerleri kanıt kimliğiyle (token ekonomisi + enjeksiyon yüzeyi).
5. `runbook.*` araçları yalnız kullanıcının runbook'u varsa kaydedilir; sistem istemine tek satırlık ipucu da yalnız o zaman eklenir (runbook'u olmayan kullanıcıda sabit önek DEĞİŞMEZ).

## Sonuçlar
- (+) Bileşik araç yeni bir yetki kazandırmaz: tüm kontroller iç çağrı başına yeniden işler (testle: kapsam dışı hedef, kapalı araç seti, mutasyon onay kapısı).
- (−) Runbook'un kendisi kullanıcı içeriğidir; "kullanıcı skill'i" gibi güvenilir sayılır. Dışarıdan alınmış runbook'u kullanıcı gözden geçirmelidir (`ops runbook list`).
- (−) `runbook.run` yalnız okuma adımlarını koşar; mutasyon adımları normal onay akışıyla ayrıca çağrılmalıdır (bilinçli).
