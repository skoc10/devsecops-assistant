# Dosya ağacı ve iş paketleri

## 13. v1 dosya ağacı ve ilk beş iş paketi

### 13.1 Dosya ağacı (depo kökü = ürün)
```
devsecops-assistant/
├─ README.md                    # ürün özeti + kontrol olgunluk etiketleri (Enforced/Planned)
├─ SECURITY.md                  # tehdit modeli özeti, bildirim süreci, bilinen sınırlar
├─ LICENSE
├─ package.json  pnpm-workspace.yaml  tsconfig.base.json  .nvmrc
├─ docs/
│  ├─ design/                   # bu belgenin bölümlere ayrılmış hâli
│  ├─ adr/                      # 0001-agent-model, 0002-pep-pipeline, 0003-cursor-launch-profile, 0004-cursor-spike …
│  └─ threat-model.md
├─ packages/
│  ├─ contracts/                # ops-adapter/1, Profile, Target, ToolDescriptor, ToolResult, PolicyDecision,
│  │                            #   AuditRecord, ModelProvider, AgentRuntime (zod → JSON Schema)
│  ├─ core/                     # session, orchestrator, evidence store, tool gateway (PEP 14 adım)
│  ├─ policy/                   # PolicyEngine arayüzü + yerleşik değerlendirici, policy.yaml şeması
│  ├─ classifiers/              # Faz 1: shell/ (AST→argv→katalog), sql/ (AST allowlist)
│  ├─ broker/                   # lease, SecretStore (keychain, encrypted-file), profile import (kubeconfig), doctor
│  ├─ redaction/                # M1–M6 boru hattı + kural setleri + kompaktlaştırma (projeksiyon, tekrar kümeleme, top-N, token tahmini)
│  ├─ audit/                    # hash zinciri, verify, AuditSink arayüzü
│  ├─ sandbox/                  # OS sandbox sarmalayıcı (bubblewrap/seatbelt): exec eklentisi (WP6), cursor-host (WP8), terminal (Faz 1)
│  ├─ terminal/                 # Faz 1: exec servisi, izole HOME / env temizleme, dizin jail'i, komut kataloğu yükleyici
│  ├─ workspace/                # Faz 1b: çalışma alanı kaydı, git worktree yönetimi, yazma yolu politikası, gizli dosya denylist'i
│  ├─ skills/                   # Agent Skills yükleyici, kayıt defteri, runbook→plan
│  ├─ providers/                # openai-compatible/, anthropic/, azure-openai/, cursor/ (loopOwner=provider yüzü)
│  ├─ runtimes/
│  │  └─ cursor/                # cursor-host süreci + IPC köprüsü + buildCursorLaunchOptions
│  ├─ adapters/
│  │  ├─ kubernetes/            # Faz 0: okuma; Faz 2: yazma araçları (ayrı tools[] girdileri)
│  │  ├─ pipeline-github-actions/   # Faz 1
│  │  ├─ scm-github/            # Faz 1 (okuma) / Faz 2 (pr.create)
│  │  ├─ database-postgres/     # Faz 1 (reader) / Faz 2 (writer)
│  │  ├─ iac-terraform/         # Faz 1b: inspect/fmt/validate/lint/scan/docs; Faz 2: plan (apply varsayılan kapalı)
│  │  └─ iac-ansible/           # Faz 1b: lint/syntax-check/envanter; Faz 2: check (run varsayılan kapalı)
│  ├─ mcp-bridge/               # Faz 1b: MCP istemci köprüsü v0 (manifestli read araçları, sandbox'lı stdio); Faz 3: PEP'li MCP sunucu yüzü + imzalı eklenti
│  ├─ testkit/                  # scripted provider, fake k8s API, canary üretici, conformance suite
│  └─ cli/                      # `ops` CLI + TUI, `opsd` servisi
├─ skills/                      # yerleşik SKILL.md + ops.skill.yaml setleri (şirket bilgisi yok)
│  ├─ generic-diagnosis/  kubernetes/                       # Faz 0
│  ├─ pipelines/  database/  incident-response/  terraform/  ansible/             # Faz 1
│  └─ cloud/ gitops/ containers/ secrets/ vulnerability/ compliance/ observability/   # Faz 3
├─ policies/                    # varsayılan policy.yaml (bütçeler `budgets` bölümünde), masking.yaml, command-catalog/*.yaml (iac.yaml dahil)
├─ test/
│  ├─ e2e/                      # faz bitiş senaryoları (scripted model)
│  └─ fixtures/                 # kind manifestleri, postgres init; secret/kubeconfig YOK (çalışma anında üretilir)
└─ .github/workflows/           # lint, unit, conformance, e2e(kind), SBOM, secret-scan
```

### 13.2 İlk beş iş paketi (her biri bir geliştirme oturumunda bitirilebilir)
> Boyutlandırma notu: bağımsız inceleme ilk taslaktaki WP2–WP5'in tek oturuma sığmayacağını gösterdi (denetim+redaksiyon+politika+PEP+kabuk sınıflayıcı tek pakette, kasa+doktor+exec eklentisi tek pakette, sahte API sunucusu hiçbir pakete atanmamış). Paketler **güvenlik omurgası önce, saf-mantık önce, entegrasyon sonra** olacak biçimde yeniden kesildi. **Faz 0 sekiz iş paketidir (WP1–WP8)**; ilk beşi ayrıntılı, WP6–WP8 aşağıda kısa.

| WP | Hedef | Teslimler | Bitti kriteri (testle) | Bağımlılık |
|---|---|---|---|---|
| **WP1** Sözleşmeler + iskelet + testkit çekirdeği | Her şeyin dayandığı tipler | pnpm monorepo, CI (lint+unit), `contracts` (Profile, Target, ToolDescriptor, ToolResult, PolicyDecision, AuditRecord, ModelProvider, AgentRuntime, **DatabaseDriver**), `testkit`: canary üretici, scripted provider, fake adapter; ADR-0001/0002 | `pnpm test` yeşil; eksik/fazla alanlı araç tanımı reddedilir; JSON Schema üretilir; fake adapter conformance'ı geçer | — |
| **WP2** Denetim + redaksiyon çekirdeği | Saf mantık; sızıntı ve tamper testlerinin zemini | hash zincirli `audit` (`verify`, fail-closed yazıcı, `headHash` ikinci konuma), `redaction` (M1, M2, M3, M5, M6; kural seti) + **kompaktlaştırma** (alan projeksiyonu, log tekrar kümeleme, top-N, token tahmini), canary sızıntı harness'ı (model-yükü / UI / stdout yakalayıcılar) | S-08 (zincir + yazma hatası), S-06 çekirdek (ham/base64/URL-encoded/bölünmüş varyant — adapter'sız fonksiyon testleri), B-03 çekirdek (kompaktlaştırma redaksiyondan sonra; canary kompakt görünümde yok), property testleri | WP1 |
| **WP3** Politika v0 + PEP (kuru boru hattı; fake adapter/fake broker) | 14 adımlık boru hattı | `policy.yaml` şeması + değerlendirici (sınıf × tavan × ortam × bağlam etiketi → allow/ask/deny; sınıflanamayan = `destroy` muamelesi; Faz 0'da `ask` = `deny` + gerekçe kodu), profil çözümleme + hedef pin/scope kontrolü, bağlam etiketi / taint hesabı, egress kontrolü (`trust_zone`, `no_eligible_provider`), token/tur bütçesi eşikleri (yumuşak/sert; `policy.yaml` `budgets`), PEP adımları 1–14 | S-03 (araç yüzü/tavan), S-04 (PEP adım 2–3), S-08 (denetim yazılamazsa çağrı çalışmaz), S-12 (şema/ek alan reddi), S-13 (politika kararı sağlayıcıdan bağımsız) | WP1, WP2 |
| **WP4** Kasa + broker + statik kubeconfig içe aktarma | Kimlik ajana hiç görünmeden bağlansın | `SecretStore` (anahtar zinciri + şifreli dosya), `lease` API (opak `CredentialHandle`, finally'de silme), kubeconfig normalleştirme + pin (statik token/sertifika; `insecure-skip-tls-verify` ret), `ops profile add/list/rm`, ortam kimliği uyarısı | S-06 (kasa/CLI kanalları), pin uyuşmazlığı (`connectCheck`), lease dosyası silinir, kasa dosya izinleri | WP1–WP3 |
| **WP5** Fake k8s API + Kubernetes okuma adapter'ı (çekirdek) | İlk gerçek hedef | testkit **fake k8s API** (kendi CA'sı; list/get/events/logs/`SelfSubjectRulesReview`), adapter: `k8s.profile.describe`, `resources.list/get/describe`, `events.list`, `pods.logs` — hepsi **kompakt projeksiyonlu** (varsayılan alan kümesi, `select`, log tekrar kümeleme); conformance paketi v0 (çıktı tavanı ve projeksiyon dahil) | C-xx yeşil; `Secret.data` hiçbir yoldan çıkmaz; log/event içi canary maskelenir (S-06); kapsam dışı ns reddi (S-04) | WP1–WP4 |

**Faz 0'ı kapatan sonraki paketler (kısa):**
- **WP6** — `packages/sandbox` ilk sürüm (bubblewrap/seatbelt sarmalayıcı), kubeconfig **exec eklentisi** (argv şablon allowlist'i, sandbox'lı çalıştırma), **profil doktoru** (fiili yetki, oturum başı yeniden kontrol; S-14), `k8s.auth.can_i`, `k8s.workload.health`, `kind` entegrasyonu (I-01), salt okunur RBAC manifest üreticisi, S-15 (eklenti şablonu kısmı).
- **WP7** — Orkestratör (`loopOwner=host`) + `opsd` (UDS) + `ops chat` CLI + **tembel skill yükleyici** (`generic-diagnosis`, `kubernetes`; yalnız metaveri + istek üzerine gövde) + **bağlam defteri** + **token ölçümü / `ops usage`** + kararlı önek montajı (B-01) + kanıt kimliği / atıf doğrulayıcı + scripted provider ile **E-01** ve token baz çizgisi (B-04). *Bir oturuma sığmazsa WP7a (orkestratör+`opsd`+CLI+E-01) ve WP7b (skill/defter/token ölçümü) olarak bölünür.*
- **WP8** — Sağlayıcılar: minimal OpenAI-uyumlu `loopOwner=host` (WP8a) · **Cursor spike (§6.4-11) + ADR-0004** ve geçerse `runtimes/cursor` (OS sarmalayıcı, `buildCursorLaunchOptions`, bekçi) + S-10 (WP8b) · Faz 0 kabul #5 ve #2'nin gerçek sağlayıcıyla **elle kabulü**. Cursor kapısı geçmezse WP8b yalnız tavsiye kipi teslim eder; Faz 0 OpenAI-uyumlu sağlayıcıyla kapanır.


[← Belge dizini](00-overview.md#belge-dizini)
