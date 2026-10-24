# ops-assistant

Herhangi bir şirketin, herhangi bir ortamında kurulabilen **genel amaçlı DevSecOps asistanı**. Tek kullanıcının kendi makinesinde çalışır; kullanıcı kendi bulut hesabını, Kubernetes kümelerini, CI sistemini, kayıt deposunu, gözlemlenebilirlik araçlarını ve veritabanlarını hazır bağdaştırıcılarla (adapter) bağlar. Ürünün içinde belirli bir şirket, müşteri veya üretim sistemi gömülü değildir.

> **Durum:** geliştirme aşamasında. Gerçekleşen ve planlanan kontrollerin dürüst dökümü için [docs/STATUS.md](docs/STATUS.md) dosyasına bakın. Tasarımın tamamı [docs/design/](docs/design/00-overview.md) altındadır.

## Ne yapar

- Sohbetle soru cevaplar; cevabını **kanıt kimlikleriyle** (`evidence_id`) destekler.
- Bağlı kaynaklardan salt okunur kanıt toplar ve deterministik anahtarlarla (image digest, commit SHA, workload) tek zaman çizelgesinde birleştirir.
- Değişikliği önce gösterir (diff, dry-run); öneriyi PR / değişiklik dosyası olarak çıkarır, hedef sistemin kendi onay mekanizmasını atlamaz.
- Terraform/OpenTofu ve Ansible kodu yazar, doğrular ve PR olarak önerir; `apply` varsayılan olarak hedefin pipeline'ına bırakılır.
- Politika izin verdiği sınıfta (`read < mutate < deploy < destroy`), kullanıcı onayıyla dar kapsamlı işlem yapar.

## Temel ilkeler

1. **Kimlik asla ajana verilmez.** Kubeconfig, bağlantı dizesi, token kasadadır (işletim sistemi anahtar zinciri veya şifreli yerel dosya); her araç çağrısında kimlik aracısı (broker) bağlar, çağrı bitince düşer.
2. **Her araç çağrısı tek bir boru hattından geçer** (Tool Gateway / PEP): şema → profil → hedef pini → sınıflama → politika → onay → denetim → lease → çalıştırma → redaksiyon → egress kontrolü.
3. **Denetim fail-closed:** denetim kaydı yazılamazsa çağrı çalışmaz.
4. **Token ekonomisi birinci sınıf hedef:** LLM yalnız yorumlar; toplama, süzme, korelasyon, sınıflama ve maskeleme koddur. Skill'ler ve araç setleri tembel yüklenir, büyük sonuçlar referansla (`evidence_id`) taşınır.
5. **Dürüst güvenlik beyanı:** her kontrol `Enforced` / `Best-effort` / `Planned` etiketiyle yazılır.

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
node packages/cli/src/bin.ts doctor                    # sandbox + ortam kimlikleri (içerik okunmaz)
node packages/cli/src/bin.ts audit verify
```

`ops chat` için bir model sağlayıcısı gerekir (`OPS_PROVIDER`: `openai-compatible` veya `cursor`; ayrıntı ve doğrulanmamış kısımlar [docs/STATUS.md](docs/STATUS.md)'da). Sohbet döngüsü scripted sağlayıcıyla uçtan uca test edilir (E-01).

## Geliştirme

Gereksinimler: Node ≥ 22.13, pnpm ≥ 10.

```sh
pnpm install
pnpm typecheck
pnpm test
```

Testler **gerçek üretim sistemine hiçbir zaman yazmaz**: sahte profiller ve canary değerleri çalışma anında rastgele üretilir, izole bir `OPS_HOME` dizininde koşar ve depoya commit edilmez.
