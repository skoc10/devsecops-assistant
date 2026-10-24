# Fazlar

## 11. Fazlar

### 11.1 Kapsam matrisi ("ürünün ayrıca yapması gerekenler")
| İhtiyaç | Karar | Faz |
|---|---|---|
| Secret'ın araç çıktısından modele sızmasını engelleme | **v1 çekirdek** | 0 |
| Denetim kaydı, ortam ayrımı (profil `environment`) | **v1 çekirdek** | 0 |
| Kısa ömürlü kimlik (statik + exec plugin) | v1; STS/workload identity bulut adapter'ıyla | 0 / 3 |
| Runbook çalıştırma + "runbook yok, genel teşhis" bildirimi | v1 | 1 |
| İç terminal (sınıflı kabuk, OS sandbox'lı) + komut kataloğu | v1 (zorunlu yetenek); Faz 0 kabulü kabuğu kullanmaz | 1 |
| Dış terminal ajanı (Cursor) | Faz 0'da spike + çalışma zamanı (kapıya bağlı) | 0 |
| Birden çok kaynakta olay birleştirme | küme↔pipeline v1; +registry/metrik sonra | 1 / 3 |
| Çevrimdışı / hava boşluklu (yerel model, salt okunur) | basit kip v1; tam paket sonra | 1 / 3 |
| Onay kapısı | **v0** (TTY, eylem hash'i; taint tabanlı `ask` ve sınıflanamayan komut için); tam sürüm (diff, bütçe, ortam adı yazdırma) | 1 / 2 |
| Dry-run / diff | v1.5 | 2 |
| Öneriyi PR / değişiklik dosyası olarak çıkarma | v1.5 | 2 |
| Policy-as-code değerlendirmesi (hedeften okuma) | Kyverno PolicyReport okuma 1; tam 3 | 1 / 3 |
| İmaj/bağımlılık/IaC/secret tarama sonuçlarını okuma | sonra | 3 |
| SBOM + zafiyet bulgusunu workload/pipeline ile eşleme | sonra (digest/SHA anahtarları Faz 1'de hazır) | 3 |
| Maliyet, kapasite, sertifika süresi sinyalleri | sertifika (cert-manager CRD) 1–3; maliyet/kapasite 3 | 3 |
| MCP istemci köprüsü v0 (yalnız read araçları, sandbox'lı stdio) · tam eklenti sistemi (imzalı paket, HTTP, MCP sunucu yüzü) | v0 v1; tam sonra | 1 / 3 |
| **Token ekonomisi:** ölçüm, kompakt çıktı, referansla taşıma, tembel skill/araç seti, bağlam defteri | v1 çekirdek; politika, model kademeleri, önbellek sonra | 0 / 1 |
| **Terraform/OpenTofu ve Ansible:** yazma + yerel doğrulama (worktree, fmt/validate/lint/scan, HCL ön-tarama) | v1 | 1b |
| IaC `plan` / `ansible --check` / PR; `apply` ve `ansible.run` varsayılan kapalı | v1.5 | 2 |

### 11.2 Fazlar ve bitiş senaryoları
**Faz 0 — "Herhangi bir kubeconfig ile salt okunur küme sorusu"** (WP1–WP8; ilk beşi §13.2'de ayrıntılı)
Kapsam: sözleşmeler, denetim, redaksiyon, politika+PEP, kasa+broker, k8s okuma adapter'ı (+exec eklentisi, doktor), orkestratör, `opsd`, sohbet CLI, scripted + OpenAI-uyumlu sağlayıcı + (kapı geçerse) Cursor. **Terminal Service bu fazda yok** (Faz 1).
**Bitiş senaryosu (kabul):**
1. Kullanıcı bir kubeconfig'i `ops profile add k8s` ile içe aktarır (kind/k3d/EKS/AKS/GKE tipi; exec eklentili olanlar allowlist akışıyla). Doktor, kimlik yankısı ve fiili yetkiyi gösterir; içerik ne stdout'ta ne log'da ne denetimde görünür.
2. Test kümesinde bilerek bozulmuş bir dağıtım için `ops chat` (otomatik kabul E-01, scripted modelle; gerçek sağlayıcıyla **elle kabul**, WP8): "payments ns'inde pod neden CrashLoopBackOff?" Asistan `k8s.workload.health → k8s.events.list → k8s.pods.logs` çağırır; cevap kök neden + `evidence_id` atıfları + **önerilen** komut/diff (çalıştırmaz).
3. "Şu deployment'ı sil" → PEP `deny` (sınıf tavanı); denetimde kayıtlı; kullanıcıya gerekçe kodu gösterilir.
4. Kümedeki canary secret model yükünde, UI akışında, denetimde, hata çıktısında **yok** (S-06).
5. Sağlayıcı scripted ↔ (OpenAI-uyumlu | Cursor) değişince politika kararları ve denetim alanları aynı (S-13).
6. `ops audit verify` geçer; dosyada bir bayt değişince kırılır (S-08).
7. **Token raporu:** `ops usage` oturum için çağrı başına token ve araç sonucu tahmini gösterir; tavanı aşan bir sonuç modele ham gitmez, `evidence_id` ile referanslanır ve `evidence.get` ile dilimlenir; yumuşak bütçe aşımı uyarısı tetiklenir (B-03, B-04).

**Faz 1 — "Pipeline okuma + reader SQL + korelasyon + skill"** (≈ 10–12 iş paketi; iki dilim: **1a** bu paragraf ve **1b** aşağıda)
Kapsam: **Terminal Service + kabuk sınıflayıcı + OS sandbox'lı `shell.run`/`shell.run_profiled` + komut kataloğu**, **onay kapısı v0**, GitHub Actions okuma, SCM okuma, PostgreSQL reader (+doktor; SQL AST allowlist sınıflayıcı), `timeline.build` (küme↔pipeline, digest/SHA), skill kayıt defteri + kullanıcı skill'i + runbook→plan + `generic-diagnosis` bildirimi, ek sağlayıcılar (Anthropic, Azure OpenAI; yerel model ile `local-only` doğrulaması — OpenAI-uyumlu uç Faz 0'da WP8'de gelir), `egress: local-only` kipi, bütçeler, kanıt atıf doğrulayıcı, `ops explain-policy`, replay.
**Bitiş senaryosu:** "Prod'da dünden beri 5xx arttı": asistan workload sağlığı + son rollout + ilgili pipeline run'ı (image digest/commit SHA ile eşleşmiş) + `orders` tablosunda uzun sorgu/kilit (reader) → **tek zaman çizelgesi** ve atıflı cevap; reader oturumunda `UPDATE`/`COPY … TO PROGRAM` denemesi bağımsız katmanların her birinde ayrı ayrı reddedilir (S-03); aynı senaryo yerel modelle `local-only` kipinde çalışır; kullanıcı kendi skill'ini ekler ve ilgili runbook yokken asistan "runbook bulunamadı, genel teşhis akışını kullanıyorum" der. **Taint senaryosu:** ham pod logu karantina özetleyiciden geçtiği için ardından gelen DB okuması sormaz; kullanıcı "ham logu modele ver" derse bağlam tainted olur ve DB okuması `ask`'a düşer (onay kapısı v0).

**Faz 1b — "IaC yazımı, MCP istemci köprüsü v0, token politikaları"** (≈ 4–5 iş paketi)
Kapsam: `ops workspace` + git worktree + `fs.read/write` (denylist, CI tanımı yasağı, gömülü secret reddi); `terraform`/`tofu` ve `ansible` için `iac.project.inspect/fmt/validate/lint/scan`, **HCL ve playbook ön-taraması**, komut kataloğu girdileri (`policies/command-catalog/iac.yaml`); `terraform` ve `ansible` skill'leri; `iac.docs.lookup` (yerel şema + MCP istemci köprüsü v0 ile Terraform doküman araçları); token politikaları (sonuç tavanı, oturum bütçesi, model kademeleri, istem önbelleği, plan-sonra-yürüt paralel okuma).
**Bitiş senaryosu:** Kullanıcı "şu servis için küçük bir VPC modülü ve onu çağıran kök modül yaz" der → asistan `terraform` skill'ini yükler (yalnız o skill ve araç seti bağlama girer), sağlayıcı şemasını **yalnız gereken kaynak türleri için** çeker, worktree'de `main.tf/variables.tf/outputs.tf` yazar, `fmt → validate → lint → scan` döngüsünü çalıştırıp hataları düzeltir, diff'i gösterir; state/tfvars'a dokunmaz, gömülü secret yazamaz, kod çalıştıran yapı içermez (aksi halde ön-tarama durdurur). Aynı akış bir Ansible rolü için çalışır (`ansible-lint` + `--syntax-check`, sınıf kataloğu uyarıları). Oturum token raporu başlangıç hedeflerinin (§4.5) içindedir (B-04).

**Faz 2 — "Onaylı değişiklik"** (≈ 5–6 iş paketi)
Kapsam: `ChangeSet`, `k8s.apply.diff` (client kip; `server-dry-run` yalnız ≥mutate profilde) → PR (`scm.pr.create`) veya onaylı `k8s.apply/scale/rollout`, `db.change.propose/apply` (writer lease), tam onay kapısı (diff, TOCTOU, bütçe, ortam adı yazdırma), break-glass, `policy.yaml` düzenleme akışı.
**Bitiş senaryosu:** Hatalı replika/imaj ayarı için asistan diff + etki + geri alma planını gösterir ve varsayılan olarak **PR** açar; kullanıcı "stage'e şimdi uygula" derse ortam-katmanlı onayla uygulanır; hedefin admission/Kyverno reddi **modele hata olarak döner, atlatılmaz**. DB'de `db.change.propose` → onay → writer lease → tek transaction; etkilenen satır onaylananı aşarsa ROLLBACK; yapıştırılmış prod profili ortam adı yazdırmadan mutasyon yapamaz; onay bütçesi aşılınca soğuma devreye girer; break-glass kayıtlı, TTL'li, denetim açık. **IaC kolu:** 1b'de yazılan Terraform/Ansible değişikliği `scm.pr.create` ile PR olur; PR gövdesinde doğrulama çıktıları ve `iac.plan` (reader kimliğiyle, `*_sensitive` temizlenmiş) özeti bulunur; `ansible.check` statik ön-tarama temizse read, değilse onaylı mutate; `iac.apply`/`ansible.run` kapalıdır (açılırsa onaylanmış plan dosyası hash'ine bağlı); CI tanımını değiştiren değişiklik `ask` ve diff'te vurgulu.

**Faz 3 — Genişleme:** bulut adapter'ları (Azure, AWS, GCP; STS/workload identity), registry+scanner girişi (SARIF, CycloneDX, SPDX, Trivy/Grype JSON) + SBOM eşleme, gözlemlenebilirlik (Prometheus/Loki-uyumlu), GitOps (Argo CD/Flux), policy-source (Kyverno/OPA/bulut politikası), diğer pipeline'lar (GitLab CI, Jenkins, Azure DevOps), tam eklenti SDK (imza, HTTP taşıma) + MCP sunucu yüzü, ikinci dış terminal ajanı, MySQL/SQL Server sürücüleri, tersinir tokenizasyon (M7), OTLP dışa aktarım, yerel web arayüzü, Windows, tam çevrimdışı paket (imzalı skill/adapter paketleri, yerel sağlayıcı ayna ve model).
**Bitiş senaryosu:** Üç farklı bulutta aynı `cloud.*` sözleşmesiyle kimlik+maliyet+politika uyumu sorusu; bir imaj zafiyeti bulgusu → digest → çalışan workload → pipeline run → PR önerisi zinciri; üçüncü taraf bir MCP adapter'ı imzalı manifest ve broker lease'iyle çalışır, sınıfları kendi manifestinden.

*(Faz 4 kaldırıldı: ekip sunucusu / çok kullanıcılı mod bu planda yoktur; çevrimdışı paket Faz 3'e alındı.)*


[← Belge dizini](00-overview.md#belge-dizini)
