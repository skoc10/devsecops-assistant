# Bağdaştırıcı sözleşmesi

## 5. Bağdaştırıcı sözleşmesi

### 5.1 Adapter manifesti (`ops-adapter/1`)
| Alan | Anlam |
|---|---|
| `id`, `version`, `contract` | `ops-adapter/1`; sürümler uyum kuralıyla |
| `kind` | `kubernetes, cloud, pipeline, scm, gitops, registry, observability, database, scanner, policy-source, iac, cli` (profil türleri: `k8s, cloud, db, pipeline, scm, host, iac`) |
| `profile_schema` | Profilin **secret olmayan** tanımlayıcısının JSON Schema'sı |
| `credential_kinds[]` | Desteklenen `CredentialSource` türleri |
| `capabilities[]` | `dry_run`, `diff`, `watch`, `pagination` … |
| `tools[]` | Aşağıdaki araç tanımı |

**Araç tanımı:** `name` (`<önek>.<noun>.<verb>`; önek adapter'ın kısa kimliği: `k8s`, `pipeline`, `scm`, `db`, `cloud`, `obs`…), `description`, `input_schema`, `output_schema`, `class` (varsayılan sınıf), `scope_extractor` (argümandan hedef), `sensitivity` (`none|internal|pii|secret-adjacent`), `idempotent`, `dry_run`, `limits{timeoutMs,maxBytes,maxItems}`, `redaction_profile`, `untrusted_output` (bool; log/serbest metin = true), `toolset` (skill ile bağlanan araç grubu), `projection` (varsayılan kompakt alan kümesi; `select` desteği), `typical_output_tokens` (bütçe planlaması için).

### 5.2 Çalışma zamanı yüzü (yaşam döngüsü)
`describe()` · `validateProfile(descriptor)` · `connectCheck(handle) → {identity, targetFingerprint}` · `resolveTarget(tool,args)` · `classify(tool,args)` (yalnız yükseltir) · `dryRun(tool,args,handle)` · `invoke(tool,args,handle,ctx) → ToolResult` · `dispose(handle)`. (`handle` = broker'ın verdiği opak `CredentialHandle`; adapter ham materyali yorumlamaz.)

**`ToolResult` zarfı:** `{status, data, summary, truncated, redactions[], provenance{source,query,observedAt,profileId,targetFingerprint}, sensitivity, taint}`.

### 5.3 Ortak kurallar (tüm türler)
1. **Hedef beyanı zorunlu:** her araç hedefi çözebilir; çözemeyen araç yüklenmez.
2. **Sayfalama ve limit:** sınırsız liste yok; `limit` zorunlu, üst sınır manifestte.
3. **Zaman aralığı** zorunlu (log, metrik, olay).
4. **Serbest metin dönen araçlar** `untrusted_output=true`; zarflanır.
5. **Secret'a yan etki yok:** adapter kimlik materyalini loga, hata mesajına, `ToolResult`'a koymaz; hata metni redakte edilir.
6. **Yazma araçları ayrı yetki sınıfı:** `read` adapter'ı `mutate` aracı barındırıyorsa manifestte ayrı `tools[]` girdisi, ayrı `class`; profil tavanı bunu keser.
7. **Conformance paketi** (testkit): her adapter aynı testlerden geçer — sınıf beyanı, limit, redaksiyon kancası, secret sızıntısı yok, hedef beyanı, yanlış hedef reddi, **çıktı tavanı ve `select`/projeksiyon** (bkz. §12).
8. **Token disiplini (§4.5):** araç ham nesne yerine **kompakt, türetilmiş** çıktı döner; varsayılan alan kümesi küçüktür, `select` ile genişletilir; sınırsız sayfa yok; çıktı `structuredContent` + kısa özet; tavanı aşan sonuç yalnız referansla (`evidence_id`) döner.
9. **Araç seti bağlama:** her araç tek bir `toolset`'e aittir; adapter'ın tüm araçları bağlama körlemesine eklenmez.

### 5.4 Türlere göre ortak şekil
| Tür | Hedef birimi | Okuma fiilleri (v1) | Yazma fiilleri (Faz 2+) | İlk uygulama |
|---|---|---|---|---|
| kubernetes | küme+ns | list, get, describe, events, logs, can-i, workload.health, policy.reports | apply(diff/dry-run önce), scale, rollout restart/undo, delete, exec | `@kubernetes/client-node` ile doğrudan API |
| pipeline | repo/proje+run | runs.list, run.get, jobs.list, job.logs, workflow.definition, artifacts.list | rerun, cancel | GitHub Actions; GitLab CI, Jenkins, Azure DevOps sonraki |
| scm | repo | file.read, diff, pr.list, commit.list | pr.create (yalnız PR, korumalı dala doğrudan yazma yok) | GitHub (REST/GraphQL) **[doğrulanacak]** |
| cloud | hesap/abonelik/proje+bölge | identity.whoami, resources.list/get, cost.summary, quota.get, policy.compliance | — (Faz 3+ ayrı değerlendirme) | Azure, AWS, GCP aynı sözleşme; hiçbiri varsayılan değil |
| gitops | uygulama | app.list/get/diff/status | sync (deploy) | Argo CD / Flux (Faz 3) |
| registry | repo/digest | image.inspect, sbom.get, signature.verify | — | OCI dağıtım API (Faz 3) |
| observability | veri kaynağı+zaman aralığı | metrics.query, logs.query, alerts.list, traces.get | — | Prometheus-uyumlu, Loki-uyumlu (Faz 3) |
| database | datasource+şema | schema.describe, query.read, query.explain, stats.summary | change.apply (writer lease) | PostgreSQL; MySQL, SQL Server `DatabaseDriver` sözleşmesiyle (aşağıda) |
| scanner | hedef (imaj/repo/IaC) | findings.import (SARIF, CycloneDX, SPDX, tarayıcı JSON), findings.list/get | — | Mevcut araç çıktısını oku; gömülü tarayıcı yok |
| policy-source | küme/hesap | policy.list, policy.report, policy.evaluate (salt okunur) | — | Kyverno, OPA, bulut politikası |
| cli | ikili+alt komut | katalogdaki okuma komutları | katalogdaki diğer sınıflar | Kapalı araçlar için kullanıcı kataloğu |
| iac | workspace (git worktree) + hedef (plan için bulut hesabı / inventory grubu) | project.inspect, fmt, validate, lint, scan, docs.lookup; (Faz 2) plan, ansible check | (Faz 2) PR ile değişiklik; apply/destroy/`ansible.run` varsayılan kapalı | Terraform/OpenTofu ve Ansible; ikili'ler kullanıcının makinesinde, sandbox'ta (§7.5) |

**`DatabaseDriver` alt sözleşmesi** (database adapter'ının sürücü yüzü; WP1'de `contracts` içinde): `dialect` (`postgresql | mysql | sqlserver`) · `connect(handle, role: reader|writer)` · `applyReaderGuards(session)` (salt-okunur oturum, süre/kilit/boşta zaman aşımları) · `classify(sql) → {statementKinds, relations, columnRefs, functions, wholeRowRefs}` (diyalekte özgü AST; **allowlist** değerlendirmesi PEP/politikada) · `executeRead(sql, limits) → satır akışı + sütun kökeni (varsa)` · `describeSchema()` · `explain(sql)` (çalıştırmadan) · `capabilities{readOnlyTx, statementTimeout, columnOrigin}`. Diyalekt eşlemesi **[doğrulanacak]**: PostgreSQL → `default_transaction_read_only`, `statement_timeout`, `libpg_query` AST; MySQL → `SET SESSION TRANSACTION READ ONLY`, `max_execution_time`, MySQL ayrıştırıcısı; SQL Server → salt okunur rol / `ApplicationIntent=ReadOnly`, `SET LOCK_TIMEOUT`, T-SQL ayrıştırıcısı. Bir diyalekte eksik koruma `capabilities` ile bildirilir; eksik koruma = ek katman zorunlu (rol yetkisi).

### 5.5 Eklenti bağdaştırıcılar (MCP istemci köprüsü v0: Faz 1 — yalnız `read` sınıfı manifestli araçlar, sandbox'lı stdio; tam eklenti sistemi: Faz 3)
- **Yol 1 — in-process paket** (birinci taraf): yukarıdaki arayüzü doğrudan uygular.
- **Yol 2 — MCP köprüsü:** dış MCP sunucusu (stdio) **manifest ile sarılır**. MCP araç açıklamaları/annotation'ları spesifikasyona göre **güvenilmez** kabul edilir **[doğrulandı: https://modelcontextprotocol.io/specification/latest — "descriptions of tool behavior such as annotations should be considered untrusted"]**; bu yüzden sınıf, hedef çıkarıcı ve limitler **kullanıcı/ürün manifestinde** tanımlanır, MCP'den alınmaz. Dış sunucu kimlik gerektiriyorsa broker onu *profil başına başlatılan süreç* olarak, lease ile besler; imzalı/hash'li yükleme zorunlu.
- Tersi yön: ürünün PEP'li araçları **MCP sunucusu** olarak da sunulur (yerel, kısa ömürlü oturum belirteciyle). Dış terminal ajanı (Cursor vb.) böylece kendi kabuğu yerine bunları kullanır.


[← Belge dizini](00-overview.md#belge-dizini)
