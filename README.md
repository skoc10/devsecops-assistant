# ops-assistant

Herhangi bir şirketin, herhangi bir ortamında kurulabilen **genel amaçlı DevSecOps asistanı**. Tek kullanıcının kendi makinesinde çalışır; kullanıcı kendi bulut hesabını, Kubernetes kümelerini, CI sistemini, kayıt deposunu, gözlemlenebilirlik araçlarını ve veritabanlarını hazır bağdaştırıcılarla (adapter) bağlar. Ürünün içinde belirli bir şirket, müşteri veya üretim sistemi gömülü değildir.

> **Durum:** geliştirme aşamasında. Gerçekleşen ve planlanan kontrollerin dürüst dökümü için [docs/STATUS.md](docs/STATUS.md) dosyasına bakın. Tasarımın tamamı [docs/design/](docs/design/00-overview.md) altındadır.

## Ne yapar

- Sohbetle soru cevaplar; cevabını **kanıt kimlikleriyle** (`evidence_id`) destekler.
- Bağlı kaynaklardan salt okunur kanıt toplar ve deterministik anahtarlarla (image digest, commit SHA, workload) tek zaman çizelgesinde birleştirir.
- Değişikliği önce gösterir (diff, dry-run); öneriyi PR / değişiklik dosyası olarak çıkarır, hedef sistemin kendi onay mekanizmasını atlamaz.
- Terraform/OpenTofu ve Ansible kodu deponun **anlık kopyasında** yazar ve doğrular (fmt/validate/lint/plan/`--check`), değişikliği `git apply` ile uygulanabilir **yama** olarak (veya `scm.pr.create` ile PR olarak) verir; `iac.apply`/`ansible.run` **bilinçli olarak yoktur** ([ADR-0007](docs/adr/0007-iac-apply-closed.md)) — uygulama hedefin pipeline'ına bırakılır.
- Kullanıcının **runbook**'unu (markdown) plana çevirir, planı gösterir ve okuma adımlarını her biri tam PEP'ten geçerek koşturur ([ADR-0009](docs/adr/0009-composite-tools-runbooks.md)); runbook yoksa genel teşhis akışını kullandığını söyler.
- Denetim kaydından oturumu **inceler** (`ops replay`: eylem çizelgesi, tutarlılık denetimleri, politika what-if).
- Politika izin verdiği sınıfta (`read < mutate < deploy < destroy`), kullanıcı onayıyla dar kapsamlı işlem yapar.

## Temel ilkeler

1. **Kimlik asla ajana verilmez.** Kubeconfig, bağlantı dizesi, token kasadadır (işletim sistemi anahtar zinciri veya şifreli yerel dosya); her araç çağrısında kimlik aracısı (broker) bağlar, çağrı bitince düşer.
2. **Her araç çağrısı tek bir boru hattından geçer** (Tool Gateway / PEP): şema → profil → hedef pini → sınıflama → politika → onay → denetim → lease → çalıştırma → redaksiyon → egress kontrolü.
3. **Denetim fail-closed:** denetim kaydı yazılamazsa çağrı çalışmaz.
4. **Token ekonomisi birinci sınıf hedef:** LLM yalnız yorumlar; toplama, süzme, korelasyon, sınıflama ve maskeleme koddur. Skill'ler ve araç setleri tembel yüklenir, büyük sonuçlar referansla (`evidence_id`) taşınır.
5. **Dürüst güvenlik beyanı:** her kontrol `Enforced` / `Best-effort` / `Planned` etiketiyle yazılır.
6. **Ham serbest metin ana modele girmeyebilir (opsiyonel karantina):** log/olay yerine şema-tipli özet gider; ham içeriği yalnız kullanıcı `/show` (ekrana) veya `/raw` (modele, denetimli) ile açar ([ADR-0008](docs/adr/0008-quarantine-typed-digest.md)).
7. **Çevrimdışı/yerel kip:** `--local-only` / `OPS_EGRESS=local-only` — yalnız yerel model, yalnız okuma sınıfı, MCP köprüsü ve break-glass kapalı (PEP'te fail-closed).

## Depo yapısı

```
docs/design/   tasarım belgeleri (Türkçe)
docs/adr/      mimari karar kayıtları
docs/STATUS.md gerçekleşen / planlanan kontroller
packages/      TypeScript çalışma alanı paketleri (contracts, core, policy, audit, redaction, broker, adapters, ...)
skills/        yerleşik Agent Skills (SKILL.md) setleri
policies/      varsayılan politika, maskeleme ve komut kataloğu dosyaları
test/          uçtan uca senaryolar
```

## Hızlı başlangıç (kaynak ağacından)

```sh
pnpm install
export OPS_PASSPHRASE_FILE=~/.ops-assistant-passphrase   # 0600 izinli dosya; ortam değişkeninde parola tutulmaz
node packages/cli/src/bin.ts init
node packages/cli/src/bin.ts profile add k8s --id dev --kubeconfig ~/kube.yaml --env dev --scope default
node packages/cli/src/bin.ts profile doctor dev        # fiili RBAC ↔ beyan edilen tavan
node packages/cli/src/bin.ts profile rbac --sa-namespace ops --namespace default   # salt okunur RBAC manifesti ÜRETİR (uygulamaz)
# PostgreSQL (salt okunur reader rolü; parola 0600 dosyadan, bağlantı dizesi YOK):
export OPS_DB_PASSWORD_FILE=~/.ops-db-password
node packages/cli/src/bin.ts profile add db --id shop --env stage --host db.example --database shop --user ops_reader --scope public,sales --ca-file ~/db-ca.pem
node packages/cli/src/bin.ts profile doctor shop        # fiili rol yetkileri ↔ beyan (yazma/CREATE/süper yetki varsa BAĞLANMAZ)
# (isteğe bağlı) yazıcı profili: reader'dan AYRI, yalnız gereken tablolarda DML yetkili DB kullanıcısı; her değişiklik önizleme + onay + tek işlem + satır üst sınırı
node packages/cli/src/bin.ts profile add db --id shop-w --env stage --host db.example --database shop --user ops_writer --scope public --ca-file ~/db-ca.pem --ceiling mutate
# IaC (Terraform/OpenTofu/Ansible): ajan deponuza YAZMAZ, HEAD'in anlık kopyasında çalışır (ikililer ürünle gelmez)
export OPS_TOOL_DIRS=/opt/ops-tools/bin:/opt/ops-tools/venv/bin     # tofu/terraform/ansible/ansible-lint dizinleri
node packages/cli/src/bin.ts workspace add --id infra --path ~/src/infra --engine opentofu
node packages/cli/src/bin.ts chat --embedded --workspace infra     # terraform skill'i otomatik ilan edilir
node packages/cli/src/bin.ts workspace diff infra                  # ajanın değişiklikleri
node packages/cli/src/bin.ts workspace export infra --out infra.patch   # git apply ile uygulanabilir yama (depoya yazmaz)
# (isteğe bağlı) dış MCP sunucuları: OPS_HOME/mcp-servers.yaml (ikili sha256 pini, yalnız read); `ops mcp check`
node packages/cli/src/bin.ts doctor                    # sandbox + ortam kimlikleri (içerik okunmaz)
node packages/cli/src/bin.ts audit verify
# politika: "hep izin" yalnız dar + süreli + prod dışı; diff gösterilir, kontrol terminalinde 'evet' ister, denetlenir
node packages/cli/src/bin.ts policy allow --tool k8s.scale --profile dev --scope default --ttl 8h
# acil durum: çalışan opsd/sohbette geçici tavan yükseltme (gerekçe + süre + kasa parolası; denetim/onay AÇIK kalır)
node packages/cli/src/bin.ts break-glass --profile dev --ceiling mutate --ttl 15m --reason "INC-123 payments api ölçekleme"
```

```sh
# inceleme ve denetim araçları
node packages/cli/src/bin.ts replay                       # son oturumun eylem çizelgesi + tutarlılık denetimi (araç/model ÇAĞRILMAZ)
node packages/cli/src/bin.ts replay --policy current      # kayıtlı kararlar şimdiki politikayla yeniden değerlendirilir (gevşeyen kararlar vurgulanır)
node packages/cli/src/bin.ts skill lint --builtin          # skill denetimi (görünmez Unicode, enjeksiyon/curl|sh/dış URL sezgileri, hash)
node packages/cli/src/bin.ts runbook list                  # OPS_HOME/runbooks/<ad>.md
# sohbet seçenekleri
OPS_QUARANTINE=digest node packages/cli/src/bin.ts chat --embedded     # ham log/olay modele girmez; sohbette /show ID, /raw ID
node packages/cli/src/bin.ts chat --embedded --local-only             # yalnız yerel model + yalnız okuma
```

`ops chat` için bir model sağlayıcısı gerekir (`OPS_PROVIDER`: `anthropic`, `openai-compatible` veya `cursor`; anahtar `ops provider set-key AD` ile kasaya yazılır; ayrıntı ve doğrulanmamış kısımlar [docs/STATUS.md](docs/STATUS.md)'da). Hiçbir sağlayıcı bu ortamda **gerçek servise karşı** denenmedi (yerel sahte uçlara/ScriptedProvider'a karşı test edildi). Sohbet döngüsü scripted sağlayıcıyla uçtan uca test edilir (E-01).

## Geliştirme

Gereksinimler: Node ≥ 22.13, pnpm ≥ 10.

```sh
pnpm install
pnpm typecheck
pnpm test
```

Testler **gerçek üretim sistemine hiçbir zaman yazmaz**: sahte profiller ve canary değerleri çalışma anında rastgele üretilir, izole bir `OPS_HOME` dizininde koşar ve depoya commit edilmez.
