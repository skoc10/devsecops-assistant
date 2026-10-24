# Mimari

## 3. Mimari

### 3.1 Bileşenler

```
 Kullanıcı ──► UI (TUI/CLI) ──► opsd (yerel API, UDS)
                                  │
              ┌───────────────────┴────────────────────┐
              │ Orchestrator (tek ajan döngüsü)         │
              │  • Skill Registry (progressive load)    │
              │  • Evidence Store / Correlator          │
              │  • Change Proposer (ChangeSet/PR)       │
              └───────┬─────────────────────┬──────────┘
          ModelProvider / AgentRuntime       │ her araç çağrısı
          (Cursor, Anthropic, OpenAI-uyumlu, │
           Azure OpenAI, yerel)              ▼
                                   ┌──────────────────────┐
                                   │ Tool Gateway (PEP)   │◄── Policy Engine (PDP)
                                   │  tek boru hattı §3.2 │◄── Classifiers (shell, sql)
                                   └─┬─────┬─────┬─────┬──┘
                                     │     │     │     └──► Audit Log (hash zinciri)
                                     │     │     └────────► Output Pipeline (limit/redact/mask/taint)
                                     │     └──────────────► Credential Broker ◄── Vault (keychain/şifreli dosya)
                                     ▼
                         Adapter Host: kubernetes, pipeline, scm, database, …
                         Terminal Service (sınıflı kabuk), MCP Bridge (Faz 3)
```

### 3.2 Tek boru hattı (her araç çağrısı, istisnasız)

1. **Şema doğrulama** — girdi, aracın JSON Schema'sına uymak zorunda; fazladan alan reddedilir (argüman enjeksiyonu savunması).
2. **Profil çözümleme** — çağrı `profile` takma adını **açıkça** taşır; ortamda "current context" yoktur. Profil türü ile adapter türü uyuşmalı; profil oturuma bağlı (`bound`) olmalı.
3. **Hedef çözümleme ve pin kontrolü** — `resolveTarget(args)` somut hedefi üretir (küme+ns, hesap+bölge, db+şema, repo…). Hedef, profilin pinli uç noktası (server URL + CA parmak izi / host:port) ve `allowed_scopes` içinde olmalı. Aksi: **yanlış hedef reddi**.
4. **Sınıflama** — `class = max(manifest sınıfı, adapter.classify(args), shell/sql sınıflayıcısı)`. Adapter sınıfı yalnız **yükseltebilir**. Sınıflanamayan komut/ifade `destroy` muamelesi görür (tavan izin vermiyorsa ret).
5. **Politika kararı** — `allow | ask | deny` + gerekçe kodu. Girdi: sınıf, profil tavanı (`class_ceiling`), ortam katmanı (`dev|stage|prod|sandbox`), oturum politikası, **taint durumu**.
6. **Bağlam etiketi ve taint** — oturum bağlamı `{taint, dokunulan_profiller, max_sensitivity}` etiketi taşır. Bağlamda `untrusted` içerik varsa şu çağrılar, oturum "otomatik izin" dese bile, en az `ask` olur: (a) `mutate+` sınıfı; (b) bağlamda henüz dokunulmamış **başka bir profile** okuma veya bağlamın `max_sensitivity` değerini yükselten okuma (staging logundaki enjeksiyonun prod DB'yi okutması); (c) dış çıkış kanalı olan araç (PR açma, ağ). Onay ekranı hangi kanıtın bağlamda olduğunu gösterir. Taint'in sık tetiklenip onay yorgunluğu yaratmaması için serbest metin ham haliyle ana bağlama girmez (bkz. §4.2). Bkz. §9-T2.
7. **Onay (ask ise)** — PEP *kanonik eylem özetini* (araç, profil, ortam, hedef, diff, sınıf, geri alma) kendisi render eder; modelin düz metni onay ekranına girmez. Onay, **eylem hash'ine** (araç+arg+profil+hedef sürüm/digest) bağlanır; çalıştırma anında yeniden doğrulanır (TOCTOU). **Onay kanalı:** yanıt yalnız UI sürecinin kontrol terminalinden (`/dev/tty`) okunur; araç soketinde onay uç noktası **yoktur**; alt süreçler (cursor-host, dış adapter, skill betiği) yalnız `tool.invoke` kapsamlı belirteç alır ve onay verebilecek kanala erişemez. Aynı UID'de ptrace yetkili bir saldırgan bunu aşabilir (bkz. §9 kapsam dışı).
8. **Denetim — intent kaydı** (write-ahead). Yazılamazsa dur (fail-closed).
9. **Lease al** — broker, `(profil, amaç, callId, ttl)` için kimlik materyalini yalnız adapter'ın çalıştıracağı istemciye/alt sürece bağlar.
10. **Adapter çalıştır** — zaman aşımı, bayt/satır/öğe limiti adapter manifestinden.
11. **Lease bırak** — materyal silinir (en iyi çaba; bkz. §3.5 sınırı), her durumda (finally).
12. **Çıktı boru hattı** — limit → M1 yapısal reddet listesi → M2 desen/entropi → M3 bilinen-secret taraması → M4 alan/kolon maskesi → **kompaktlaştırma** (alan projeksiyonu, tekrar kümeleme, top-N, token tahmini; *redaksiyondan sonra*, redakte veri üzerinde) → tam redakte sonuç Evidence Store'a yazılır, modele **kompakt görünüm + `evidence_id`** gider (token tavanını aşan sonuç yalnız referansla) → M6 taint zarfı (bkz. §4.5, §7).
13. **Denetim — result kaydı** (çıkış kodu, **redakte çıktı** (üst sınırlı) + hash, redaksiyon sayıları, modele giden bayt, sağlayıcı+model).
14. **Egress kontrolü** — **sonuç değil, bağlam** denetlenir: bağlamın `max_sensitivity` etiketi, hedef sağlayıcının `trust_zone`'una (`local | private-net | third-party-cloud`) uymuyorsa sonuç o sağlayıcıya gitmez; sohbet geçmişi de bağlamın parçası olduğundan oturum ortasında buluta geçiş, hassas bağlamla **yapılamaz** (yeni, temiz bağlam + yalnız `sensitivity: none` özet gerekir). Uygun sağlayıcı yoksa (ör. yerel model erişilemez) çağrı **fail-closed** reddedilir: `no_eligible_provider`.

### 3.3 Orchestrator
- Tek ajan döngüsü; modelden yalnız **araç çağrısı önerisi** alır, çalıştırmaz.
- Bağlamı kanıt-merkezli tutar: her `ToolResult` bir `evidence_id` alır (kaynak, sorgu, zaman, profil, hash). Nihai cevaptaki her iddia kanıt kimliğine bağlanır; deterministik bir **atıf doğrulayıcı** olmayan kimliği reddeder ("kanıt yoksa iddia yok").
- **Mutasyon önerisi kanıta bağlı olmak zorunda**; her kanıt bir `subject` (kaynak başvuruları: tür/ad/ns, tablo vb.) taşır. PEP, önerinin hedefinin atıf yapılan **en az bir kanıtın `subject`'inde geçtiğini**, aynı `(profil, çağ)` içinde ve taze (varsayılan ≤ 30 dk) olduğunu denetler → staging'de araştırıp prod'a uygulama hatası ve ilgisiz kanıta (`can_i` gibi) atıf yakalanır. Bu denetim *sözdizimsel*dir; anlamsal ilgiyi insan onayı doğrular (onay ekranı atıf yapılan kanıtların özetini gösterir).
- Profil değişimi bir **kapsam çağı (scope epoch)** başlatır: eski kanıt kalır ama etiketlidir; yeni çağda üretilen mutasyonlarda atıf olarak kullanılamaz.

### 3.4 Policy Engine (PDP) — iki ayrı politika kavramı
- **Assistant policy (ürünün erişim politikası):** "hangi sınıf, hangi profil, hangi ortam, ne zaman, onay gerekir mi, limitler". Yerel `policy.yaml`, deklaratif, ilk-eşleşen-reddet-kazanır. v1'de küçük yerleşik değerlendirici; arayüz Cedar veya OPA/Rego ile değiştirilebilir **[doğrulanacak: Cedar → https://docs.cedarpolicy.com ; OPA → https://www.openpolicyagent.org/docs]**.
- **Target policy (hedef sistemin politikası):** Kyverno `PolicyReport`, Gatekeeper constraint durumu, OPA `eval` sonucu, Azure Policy / AWS Config / GCP politika durumu. Ürün bunları **okur ve gösterir**, üretmez. `policy-source` adapter türü (Faz 3; Kyverno PolicyReport okuma Faz 1'e çekilebilir).

### 3.5 Credential Broker (kimlik aracısı)
- `SecretStore` arayüzü: `OsKeychainStore`, `EncryptedFileStore` (v1); `ExternalProviderStore` (Vault/OpenBao, bulut KMS/Secret Manager, 1Password CLI — Faz 3+).
- `CredentialSource` türleri: `static` (kubeconfig içi token/sertifika, DB kullanıcı/parola), `exec` (kubeconfig exec credential plugin: `aws eks get-token`, `kubelogin`, gke eklentisi), `sts` / `workload-identity` / `oidc` (bulut). Statik de olsa **lease** olarak materyalize edilir (aynı yol, aynı denetim).
- `lease` = `{profileId, purpose, callId, ttl, scope}`; çağrı başına, yeniden kullanılmaz. Kısa ömürlü token yalnız bellekte, `ttl` altında önbellek.
- Materyal şu yollarla taşınır: birinci taraf adapter'ın in-process istemcisine opak `CredentialHandle` (`Buffer`/`Uint8Array`; mümkün olduğunca JS string'ine çevrilmez); alt süreçte 0600 geçici dosya veya env (argv'de **asla** — `ps` ile görünür). Çağrı sonunda silinir. **Sınır (dürüst beyan):** JS string'leri değişmezdir ve GC kopya bırakabilir; birinci taraf adapter'lar asistanla aynı süreç/heap'te çalışır. Bu yüzden silme/zeroize **en iyi çaba**dır ve "adapter kimliği hiç görmez" iddiası yalnız model, skill, dış süreç ve **eklenti adapter'ları** için geçerlidir; eklenti adapter'lar ayrı süreçte, yalnız kendi profilinin lease'iyle koşar.
- **Exec kimlik eklentileri** (`aws eks get-token`, `kubelogin`, gke eklentisi…) allowlist'e **ikili yol+hash + argv şablonu** (ör. `<ikili> <alt komut> --cluster-name <değişken>`) olarak girer; yaygın eklentiler için ürünle gelen şablon kataloğu vardır, kullanıcı şablonları ayrıca gözden geçirilir. Eklenti **yalnız broker tarafından**, OS sandbox içinde (§3.6) ve denetlenerek çalıştırılır — `shell.run` yoluyla değil; `ops profile add/doctor` da bu yolu kullanır. Eklenti bulut CLI'sının kendi kimlik deposuna (AWS profili/SSO önbelleği vb.) ihtiyaç duyarsa bu bağımlılık profilde `ambient_dependencies` olarak beyan edilir ve yalnız adı geçen env/dosya sandbox'a verilir. **Dürüst beyan:** bu kaynaklarda temel bulut kimliği kasada değil, bulut CLI'sının deposundadır; ürün onun modele/adapter'a görünmesini engeller ama o depoyu kullanan başka yerel süreçleri engelleyemez.
- Broker, verdiği tüm değerleri bilir → çıktı boru hattında **M3 (bilinen-secret tarayıcı)** olarak kullanılır (ham, base64, URL-encoded varyantlar).

### 3.6 Terminal Service
- Asistan sürecinin kabuğudur; modele **doğrudan** açık değildir. İki araç yüzü:
  - `shell.run` — kimliksiz; **OS sandbox içinde** (Linux: bubblewrap/seccomp, macOS: seatbelt **[doğrulanacak]**); `HOME`/`XDG_*` oturuma özel boş dizine yönlendirilir; bilinen kimlik yolları (`~/.kube`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.ssh`, `~/.docker`, `~/.config/gh`, `~/.cursor`…) sandbox'ta **bağlanmaz**; env temizlenmiş (`KUBECONFIG`, `AWS_*`, `AZURE_*`, `GOOGLE_*`, `*_TOKEN` yok); ağ varsayılan **kapalı**; non-interaktif (v1'de PTY yok). `git` gibi komutlar sertleştirilmiş sabit önekle çalışır (hook, `core.fsmonitor`, `ext::` protokolü kapalı). OS sandbox kurulamıyorsa `shell.run` yalnız çok dar yerleşik salt-okunur kümeyle çalışır ve kullanıcı bilgilendirilir. Yerel salt okunur komutlar: `git status`, `ls`, `terraform fmt -check`… (`terraform validate`/`init` ağ ve sağlayıcı yüklediği için `shell.run` değil `iac.validate` yolundan, bkz. §7.5)
  - `shell.run_profiled` — **yalnız katalogdaki ikili + alt komut + bayrak kümesi** (`kubectl`, `helm`, `az`, `aws`, `gcloud`, `psql`…). Kimlik broker'dan bu çağrıya bağlanır. `--server`, `--token`, `--kubeconfig`, `--insecure-skip-tls-verify`, `--as`, `-o jsonpath` ile secret yolları gibi bayraklar **katalogda yok** (CWE-88 dersi, bkz. §10).
- Sınıflayıcı: bash AST ayrıştırma (tree-sitter-bash veya eşdeğeri **[doğrulanacak]**) → `argv` → komut kataloğu. Boru, `&&`, `;`, alt kabuk, komut ikamesi, yönlendirme, heredoc → en yüksek sınıf veya ret. Kataloğa girmeyen komut `destroy` muamelesi görür. Yol argümanları jail içinde olmalı; kimlik dosyası desenleri reddedilir.
- "Kapalı aracın API'si yok" durumu: kullanıcı kataloğa **kendi** komut tanımını ekler (ikili, alt komut, bayraklar, sınıf, hedef çıkarıcı, `network: none|allowlisted|open`); politika katmanından geçmeden çalışmaz. `read` sınıfı `network: open` girişi **kabul etmez** (`git ls-remote https://…` read değildir). `scripts/` içeriğinin hash'i yalnız bütünlük sağlar, sınıfı belirlemez; sınıf kataloğa göre.
- **Faz:** Terminal Service ve kabuk sınıflayıcı **Faz 1**'de teslim edilir (Faz 0 kabulü kabuğu kullanmaz); sözleşme ve PEP yolu Faz 0'da hazırdır.

### 3.7 Model katmanı
- `ModelProvider` (**host-owned loop**): `generate(messages, tools) → stream`; yetenek bildirimi `{toolCalling, structuredOutput, trust_zone, contextWindow}`. Anthropic, OpenAI-uyumlu uç, Azure OpenAI, yerel (OpenAI-uyumlu yerel sunucu).
- `AgentRuntime` (**provider-owned loop**): `runTask(task, grantedTools, workspace) → events`. Cursor SDK burada; ikinci dış terminal ajanı da aynı sözleşmeye eklenir. Tek kapı: ajanın araçları yalnız ürünün **araç köprüsü** üzerinden gelir (Faz 0: özel araç → IPC → PEP; genel MCP yüzü Faz 3). **Her `AgentRuntime` (yalnız Cursor değil) şunu sağlamak zorundadır:** ayrı OS süreci; temizlenmiş env ve izole `HOME`; OS sandbox (dosya + ağ); yerleşik kabuk/dosya araçlarının kapatılabildiğinin yetenek bildirimi (`builtinToolsDisableable`); çalışma zamanı bekçisi arayüzü; yalnız `tool.invoke` kapsamlı, süreli taşıyıcı belirteç; resume/devam durumunda eksik kısıt = araçsız (fail-closed). Karşılamayan çalışma zamanı yalnız tavsiye kipinde çalışır.
- **Cursor SDK ajan SDK'sıdır, düz chat-completions/inference API'si değildir** **[doğrulandı: https://cursor.com/docs/sdk/typescript — "not a standalone model-inference or chat-completions API"]**. Bu yüzden Cursor, `ModelProvider` arayüzüne `loopOwner=provider` kipinde oturur: döngü Cursor'da, araçlar bizim köprümüzde (PEP'e giden), yerleşik kabuk/dosya araçları kapalı. Bu doğrulanamazsa Cursor yalnız **tavsiye kipinde** (`tools: []`, araçsız, redakte bağlam) çalışır. Hem `loopOwner=host` (ikinci sağlayıcı, scripted test sağlayıcısı) hem `loopOwner=provider` kipi v1'de **birlikte** desteklenir, böylece arayüz Cursor biçimli kalmaz. Ayrıntı ve doğrulama §6.4.
- Her çağrı denetim kaydına `{provider, model, trust_zone}` yazar. Model değişince araç sözleşmesi ve yetki **değişmez** (politika modelden bağımsız).

### 3.8 Audit Log
- Alanlar: `ts, sessionId, callId, principal, provider, model, tool, class, profile, environment, target, decision, reasonCode, approvalId, actionHash, argsRedacted, exitStatus, outputRedacted (M1–M5 sonrası, üst sınırlı; varsayılan 8 KiB), outputHash, outputBytesToModel, redactionCounts, policyVersionHash, prevHash, hash`.
- Hash zinciri; `ops audit verify` zinciri yeniden hesaplar: **ortadaki** kaydın düzenlenmesi/silinmesi/yeniden sıralanması tespit edilir. **Sınır:** dış çapa yoksa kuyruk kesme ve dosyayı baştan yazma tespit edilmez. v1 hafifletmesi: zincir başı (`headHash`) oturum sonunda OS anahtar zincirinde ayrı bir girdiye ve kullanıcıya gösterilen özet satıra yazılır; zincir HMAC anahtarı kasadadır. Aynı kullanıcı hesabındaki saldırgan bunları da değiştirebilir → bu **tamper-tespit**tir, tamper-önleme değil; harici sink Faz 3. Fikir ocm-mcp-server ve DojOps'tan (bkz. §10).
- Denetim kaydı yalnız redakte değer içerir; **ham çıktı hiçbir yerde saklanmaz**. "Kanıt kasası" (yerel, şifreli, TTL'li) M1–M5 **sonrası** redakte çıktıyı daha uzun tutar.
- Sink'ler: yerel dosya (v1); syslog/OTLP (Faz 3). Replay: denetim kaydı + kanıt kasası ile oturum, scripted model altında yeniden oynatılabilir; **araçlar yeniden çağrılmaz**, kayıtlı sonuçlar oynatılır (regresyon ve olay sonrası inceleme).

### 3.9 Evidence Store / Correlator
- `Evidence{id, source, profile, query, observedAt, hash, sensitivity, taint, summary}`.
- Birleştirme **deterministik**: anahtarlar `image digest` (Pod `imageID` ↔ registry ↔ pipeline artefaktı), `commit SHA` (OCI etiketi `org.opencontainers.image.revision` ↔ pipeline run ↔ PR), `app.kubernetes.io/*` etiketleri, `namespace/workload`, zaman penceresi. LLM birleştirmez, yorumlar.
- Zaman çizelgesi (`timeline.build`): küme olayları + rollout + pipeline run + kayıt deposu push + metrik eşiği. Faz 1: küme↔pipeline; Faz 3: +registry +metrik.


[← Belge dizini](00-overview.md#belge-dizini)
