# ADR-0003: Cursor SDK başlatma profili

Durum: kabul edildi; gerçek SDK doğrulaması (ADR-0004) bekliyor

## Bağlam
Cursor SDK bir ajan SDK'sıdır (düz model API'si değil). Headless yerel ajan araçları onaysız çalıştırır, sandbox varsayılan kapalıdır, `tools`/`disallowedTools`/`systemPrompt`/satır-içi `mcpServers` `resume`'da geri gelmez, süreç kullanıcının tüm ortamını miras alır (docs/design/05-technology.md §6.4).

## Karar
- SDK yalnız `packages/runtimes/cursor` içinde import edilir; ayrı OS sürecinde (`cursor-host`), OS sandbox'ta, temiz env ile koşar.
- Birincil kontrol `tools` allowlist'idir (yalnız özel araçlar); `disallowedTools` ikincil kemerdir.
- Özel araçların `execute`'u yalnız IPC yönlendiricisidir; secret taşımaz.
- Varsayılan **stateless**: her tur yeni ajan, tek fonksiyondan (`buildCursorLaunchOptions`) kurulur, bağlama defter özeti gider.
- Çalışma zamanı bekçisi yalnız **tespit edicidir**; izinsiz `tool_call` adı görülürse iptal + alarm.
- Sandbox kurulamıyorsa Cursor yalnız tavsiye kipinde (`tools: []`) çalışır.
