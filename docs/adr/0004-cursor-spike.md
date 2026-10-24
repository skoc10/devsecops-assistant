# ADR-0004: Cursor SDK doğrulama spike'ı

Durum: **beklemede (elle yapılacak)** — geçerli Cursor API anahtarı, gerçek `@cursor/sdk` ve hedef işletim sistemi gerektirir; otomatik geliştirme ortamında yapılamadı. Bu yüzden `CursorRuntime` varsayılan olarak **TAVSİYE KİPİ**'ndedir (`builtinToolsDisableable: false` → `runtimeIsSafe` false): araç çağrısı yok, yalnız redakte defter özeti paylaşılır.

## Ne var, ne yok
- **Var ve testli (sahte SDK + gerçek bubblewrap):** `buildCursorLaunchOptions` (tek başlatma fonksiyonu, seçenek kümesi kilitli, gevşek seçenek fırlatır), `cursor-host` ayrı süreç + OS sandbox (temiz env, boş kök, ev dizini/kimlik yolları yok, API anahtarı yalnız stdin ile), NDJSON köprü protokolü (her araç çağrısı PEP'e gider), tespit edici bekçi (izinli olmayan `tool_call` adı → iptal + alarm + oturum `tainted` + sağlayıcı devre dışı), stateless tur (her görev yeni `Agent.create`), tavsiye kipi, egress denetimi.
- **Yok / doğrulanmadı:** `@cursor/sdk` bu depoya bağımlılık olarak eklenmedi; `src/sdk.ts` ve `src/map.ts` içindeki şekiller dokümantasyondan türetilmiş **varsayımlardır**: `Agent.create({ tools, disallowedTools, local: { cwd, sandboxOptions, customTools } })`, `agent.send()`, `run.stream()`, `run.cancel()`, `SDKMessage` tipleri. Yerleşik araç adları (`BUILTIN_DENY`) **tahmindir** ("Tam ToolName listesi sayfada yok").

## Spike adımları (insan, gerçek anahtarla)
Ön koşul: `pnpm add -w @cursor/sdk` (sürümü tam pinleyin), Linux'ta bubblewrap veya macOS. Cursor anahtarını `ops provider set-key cursor` ile kasaya yazın (`OPS_PROVIDER_KEY_FILE`).

1. **Araç allowlist'i:** `tools: []` + `customTools` ile ajan yalnız özel araçları görüyor mu? Ajana "kabuk ile `id` çalıştır" dedirtin; `tool_call` olayında kabuk adı görünmemeli. Görünürse `BUILTIN_DENY` listesini gerçek `ToolName`'lere göre düzeltin; düzeltmeyle de kapanmıyorsa Cursor tavsiye kipinde kalır.
2. **Sandbox:** `sandboxOptions.enabled: true` hedef işletim sisteminde açılıyor mu (`ConfigurationError` yok mu)? OS sarmalayıcı (bwrap/seatbelt) altında SDK çalışıyor mu (Node ≥ 22.13, `node:sqlite`)?
3. **`request` olayı:** onay isteyen olay nasıl yanıtlanır? Köprü araçlarında onay gerekmemeli; gerekiyorsa hiçbir koşulda otomatik onaylanmamalı (varsayılan: iptal).
4. **Hook deny-all:** `beforeShellExecution`/`preToolUse` hook'larıyla ikinci kemer çalışıyor mu? Hook dosyaları `settingSources` olmadan yükleniyor mu (yüklenmiyorsa yalnız bu iş için ayrılmış temiz dizinde)?
5. **Metin modu:** `tools: []` ve `customTools: []` ile bağlam sızıntısı yok mu (ajan diskten/ortamdan okumuyor mu)? `HOME` boşken `auth.json` aranmıyor/yazılmıyor mu?
6. **Ağ:** sandbox altında SDK yalnız sağlayıcı uçlarına bağlanabiliyor mu? Şu an ağ `host` (allowlist YOK): sandbox ağ ilkesi veya allowlist'li yerel proxy gerekir (Planned).
7. **Olay şemaları:** `tool_call` / `assistant` / `usage` alanlarını `map.ts` ile karşılaştırın; "tool call schema is not stable" olduğundan sürüm pinleyin ve sözleşme testlerini gerçek çıktı örnekleriyle (secret'sız) genişletin.

## Kabul
Yedi maddenin hepsi geçerse `OPS_CURSOR_SPIKE_PASSED=1` ile araç modu açılır ve bu dosya "kabul edildi, tarih, SDK sürümü" ile güncellenir. Herhangi biri başarısızsa Cursor yalnız tavsiye kipinde kalır; Faz 0 kapanışı OpenAI-uyumlu `loopOwner=host` sağlayıcıyla yapılır (E-01 bu yolla zaten testlidir).
