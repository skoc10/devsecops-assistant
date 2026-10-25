# ADR-0008 — Karantina: ham log/olay ana modele girmez, tipli özet girer

Durum: kabul (Faz 1 artıkları). Tarih: 2026-10.

## Bağlam
Tasarım §4.2: ham serbest metin (log, olay mesajı, diff, DB hücresi) enjeksiyonun ana kanalıdır. Mevcut savunma "taint": untrusted içerik bağlama girdiğinde mutasyon/başka profile okuma/dış ağ `ask` olur. Bu doğru ama **onay yorgunluğu** (T7) üretir ve içeriği yine de modele taşır.

## Karar
- `k8s.pods.logs`, `pipeline.job.logs`, `k8s.events.list` için PEP çıktı hattından SONRA (redakte kanıt üzerinde) **şema-tipli özet** üretilir: sayılar, sabit sinyal numaralandırması (`oom_killed`, `connection_refused`, …), ISO zaman damgaları; olay nedenleri **kapalı listeden** (bilinmeyen = `other`). Özette serbest metin taşıyabilecek hiçbir alan yoktur (zod `strictObject`; en uzun serbest değer bir `enum` üyesidir) → özet **taint'siz** sayılır, bağlam kirlenmez.
- Ham kanıt Evidence Store'da **karantinada**: `evidence.get` `quarantined` ile reddedilir, `evidence.search` içerik taramaz (eşleşme sayısı bile sızdırır), `timeline.build` karantinadaki olay nedenlerini kapalı listeden alır.
- Kullanıcı: `/show ID` ham (redakte) içeriği yalnız ekrana basar; `/raw ID` write-ahead denetimle (`evidence_release`) modele açar — içerik alındığında bağlam tainted olur ve politika normal işler.
- `model` kipi (opsiyonel): araçsız, katı şemalı bir model sınıflaması; yanıt şemaya uymaz veya araç çağrısı isterse yok sayılır; serbest `notes` varsa sonuç taint'li; özetleyici sağlayıcının bölgesi bağlamın sınırını aşıyorsa veya denetim yazılamıyorsa model **çağrılmaz**.

## Neden "temizleme" değil "kanal kapatma"
Enjeksiyon metnini süzmek (regex, LLM ile) yarışı kaybeder. Burada savunma, talimat taşıyabilecek kanalı yapısal olarak kapatmaktır; tipli bir alan "önceki talimatları unut" diyemez. Property testi: rastgele (düşmanca) girdiden üretilen özet, girdiden uzun alt dizi kopyalamaz ve şemaya uyar.

## Sonuçlar
- (+) Okuma→mutasyon zincirinde onay sayısı düşer; ham log token harcamaz (özet ≈ 100–250 token).
- (−) Tanı kalitesi: tipli özet "hangi sınıf hata" der, "hangi mesaj" demez. Gerçek modellerle kalite **ölçülmedi** → **varsayılan KAPALI** (`OPS_QUARANTINE=digest|model` / `--quarantine`). Tasarımın varsayılanı "açık"tır; sapma bilinçli ve STATUS'ta yazılıdır.
- (−) Kapsam yalnız log/olay araçları. Diff, DB hücresi, terminal, MCP, `describe` için tipli özet yok → eskisi gibi taint'li akar.
