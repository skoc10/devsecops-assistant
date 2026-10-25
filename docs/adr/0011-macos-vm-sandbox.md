# ADR-0011 — macOS'ta OS sandbox: Vagrant yönetimli Linux VM içinde bubblewrap

Durum: kabul. Tarih: 2026-10.

## Bağlam

Kod çalıştıran her araç (`shell.run`, çalışma alanı anlık kopyası için git, `iac.*`/`ansible.*`, MCP köprüsü, Cursor
çalışma zamanı) yalnız bir OS sandbox'ı içinde koşar; sandbox yoksa araç **kayıtlı değildir / çalışmaz** (fail-closed).
Linux'ta bu sandbox bubblewrap'tır (`BwrapSandbox`, CI'da gerçek süreçlerle testli). macOS'ta `sandbox-exec`
(seatbelt) profili macOS 27'de her süreci SIGABRT ile düşürür ([STATUS](../STATUS.md)); Apple `sandbox-exec`'i
"deprecated" işaretlemiştir ve profil dili belgesizdir. Seçenekler:

1. Seatbelt profilini yeniden tasarlamak — belgesiz, sürümden sürüme kırılan, pozitif kontrolü zor bir yüzey.
2. Kod çalıştıran araçları macOS'ta kapalı bırakmak — güvenli ama ürün macOS'ta büyük ölçüde işlevsiz.
3. Komutları **Vagrant ile yönetilen bir Linux VM** içinde, orada da **bubblewrap** altında çalıştırmak — Linux'taki
   sandbox'ın birebir aynısı, ek olarak VM sınırı.

Kullanıcı 3'ü seçti. Bu ADR o kararın sınırlarını yazar.

## Karar

### 1. Yaşam döngüsü: VM yalnız açık komutla başlar

- `ops vm up | status | halt | destroy | reload | ssh-config` komutları VM'i yönetir. **Hiçbir araç çağrısı, `createRuntime`
  veya `detectSandbox` VM'i kendiliğinden başlatmaz**: bir model çağrısının hipervizörü tetiklemesi hem gecikme hem
  de beklenmeyen yan etki (ağ arayüzü, paylaşım bağlama) demektir. VM kapalıysa sandbox `null`dır ve araçlar Linux'ta
  bwrap yokken nasıl kapanıyorsa öyle kapanır; `ops doctor` ve denetim kaydı nedenini söyler.
- Vagrant dizini depodaki `vm/`dir (`Vagrantfile` + `provision.sh`); Vagrant'ın makine durumu (`.vagrant/`) ve ürünün
  VM durumu `OPS_HOME/vm/` altındadır (`VAGRANT_DOTFILE_PATH`). Böylece depo kopyası/worktree'leri değişse de tek VM vardır.
- `ops vm up` sırayla: paylaşım listesini hesaplar → `vagrant up --provider …` → `vagrant ssh-config` → sunucu anahtarını
  `ssh-keyscan` ile `OPS_HOME/vm/known_hosts` dosyasına sabitler → kendi `ssh_config`'ini yazar (`StrictHostKeyChecking yes`,
  `IdentitiesOnly yes`, `ControlMaster auto`) → konuk içinde `bwrap`'ın **gerçekten çalıştığını** yoklar → `OPS_HOME/vm/state.json`
  yazar (box, sürüm, sağlayıcı, paylaşımlar, konuk araç dizinleri). Yoklama geçmezse durum dosyası yazılmaz.
- `ops vm destroy` durum dosyasını siler. Durum dosyası yokken VM "yok" sayılır (çalışıyor olsa bile).

### 2. Tespit

- `detectSandbox()` macOS'ta artık seatbelt'i yoklamaz (çalışmadığı bilinen yolu her başlangıçta denemek anlamsız).
  Sıra: `OPS_SANDBOX=vm` → yalnız VM; `OPS_SANDBOX=none` → sandbox yok; verilmediyse `OPS_HOME/vm/state.json` varsa VM
  yoklanır (SSH ile `bwrap … /usr/bin/true`), yoksa/yoklama geçmezse `null`.
- Durum dizini `OPS_HOME/vm`dir; `OPS_VM_DIR` ortam değişkeni bunu geçersiz kılar (ayrı/geçici `OPS_HOME` ile koşan testler
  kullanıcının gerçek VM'ini böyle bulur; `vm/run-vm-tests.sh` ayarlar).
- `OPS_SANDBOX=vm` açıkça istenmiş ama VM erişilemezse `detectSandbox` yine `null` döner (fail-closed); nedenini
  `detectSandboxDetailed()` ve `ops doctor` gösterir ("VM kapalı: `ops vm up`"). Linux'ta `OPS_SANDBOX=vm` de desteklenir
  (VM'i Linux'ta da kullanmak isteyen için) ama varsayılan bwrap'tır.
- Yoklama, ürünün kendi `VmSandbox.run`'ı ile yapılır: SSH bağlantısı, konuk bubblewrap'ı ve kullanıcı ad alanı
  sysctl'i birlikte sınanır; "kurulu" değil "çalışıyor" ölçülür.

### 3. Komut taşıma: tek çoğullanmış SSH bağlantısı

- Her `run`/`spawn`, host'ta `ssh -F OPS_HOME/vm/ssh_config` ile konukta **`exec timeout -s KILL <s> bwrap <argv>`**
  çalıştırır. bubblewrap argümanları host'ta `buildBwrapArgs` ile (Linux'taki **aynı** kurucu) üretilir; farklı olan
  yalnız dizin düzeni (`HostLayout`) — bu, konuktan bir kez okunup örnek ömrünce önbelleklenir (`/bin → usr/bin`
  symlink'leri vb. konuğunkidir, host'unki değil).
- Uzak komut tek bir dizgedir: her argüman POSIX tek tırnakla kaçışlanır; kabuk meta-karakterleri yorumlanmaz
  (`buildRemoteCommand` birim testli). Dizge 100 KiB'ı aşarsa reddedilir (`MAX_ARG_STRLEN`).
- Bağlantı: `ControlMaster auto` + `ControlPath OPS_HOME/vm/cm-%C` + `ControlPersist 600`. İlk çağrı el sıkışmayı öder,
  sonrakiler var olan kanalı kullanır. Ölçüm (bu Mac, VMware Fusion, bento/ubuntu-24.04 arm64): `ssh … true` sıcak
  bağlantıda ~50 ms, `bwrap … /usr/bin/true` dahil ~50 ms (soğuk bağlantı ~220 ms; `ops vm status` sıcak yoklamayı 8–20 ms ölçtü). **Bütçe:** sıcak bağlantıda çağrı başına ek
  gecikme ≤ 250 ms (p50), ≤ 1 s (p95); `vm.vm.test.ts` bunu ölçer ve aşılırsa düşer (ölçülen: p50 24 ms, p95 31 ms,
  `bwrap … /bin/sh -c true` dahil). Soğuk bağlantı (ilk çağrı) bütçe dışıdır.
- Zaman aşımı/çıktı sınırı/süreç grubu öldürme host'ta **aynı** `spawnLimited`/`spawnStreaming` ile uygulanır (öldürülen
  yerel `ssh`tir). Konukta kalıntı kalmaması için iki bağımsız kilit: `timeout -s KILL` ve bwrap `--die-with-parent`
  (SSH oturumu kapanınca bwrap ve PID ad alanındaki her şey ölür). Doğrulandı: yerel ssh SIGKILL ile öldürüldüğünde
  konukta yetim `sleep` kalmadı.
- Çıkış kodu: uzak sürecin kodu ssh'tan aynen döner; uzak süreç sinyalle öldürüldüyse ssh 255 döner (ssh bağlantı
  hatası da 255'tir — ayrım `stderr` ve `timedOut` ile yapılır; çağıranlar zaten `code !== 0`u başarısızlık sayar).
- stdin aynen iletilir; stdout/stderr ayrı kanallardır (ssh karıştırmaz).

### 4. Yol eşlemesi (`roBinds`/`rwBinds`/`cwd`/`home`)

- Paylaşılan her host dizini konukta **aynı mutlak yola** bağlanır (`/Users/u/.ops-assistant/worktrees` ↔ aynı yol).
  Böylece araçların ürettiği yollar (terraform tanıları, `git` çıktıları, kanıt/denetim kayıtları) host ve konukta aynıdır;
  `shell.run` kataloğunun yol jail'i ve iş alanı denetimleri değişmeden çalışır.
- `VmSandbox`, bir spec'teki her yolu (`argv[0]` hariç — o konuk ikilisidir) şu köklerden birinin altında olmaya
  **zorlar**: (a) `state.json`'daki paylaşımlar, (b) konuk araç kökleri (`/opt/ops-tools`), (c) sandbox içinde zaten var
  olan sanal yollar (`/home/ops-*` tmpfs ev dizinleri, `/tmp`). Başka bir yol → `vm_path_not_shared` hatası, komut
  **çalıştırılmaz**. "Konukta öyle bir dizin yok" sessizliği yerine açık ret: kullanıcı `OPS_WORKDIR`'ı paylaşılmayan bir
  dizine verirse terminal aracı başlamaz ve neden söylenir.
- Eşleme tablosu `state.json`'da `shares: [{host, guest, mode}]` biçimindedir; bugün `host === guest`, ama kurucu farklı
  önekleri de çevirebilir (test edilir) — ileride paylaşım kökünü `/ops/...` altına almak isteyen için.

### 5. Ne paylaşılır, ne asla paylaşılmaz

Paylaşılan (VMware **hgfs**, `vmhgfs-fuse`; bkz. §8):
- `OpsPaths.worktreesDir` (`OPS_HOME/worktrees`), **okuma-yazma** — anlık kopyaların `work/` dizinine `terraform fmt`,
  `init` (`.terraform.lock.hcl`), `ansible-lint` yazar.
- `workspaces.json`'da **kayıtlı IaC çalışma alanlarının** depo kökleri, **salt okunur** — anlık kopya git'in
  `ls-tree`/`cat-file`'ını depo üstünde çalıştırır; Linux'ta bu depo bwrap'a `--ro-bind` ile verilir, VM'de aynı şey için
  konukta görünür olması gerekir. Salt okunur paylaşım + bwrap `--ro-bind` = Linux'takiyle aynı görünürlük (yalnız git
  süreci, yalnız okuma). Yeni çalışma alanı kaydı macOS'ta `ops vm reload` ister (paylaşımlar açılışta bağlanır);
  `ops workspace add` bunu söyler.

Asla paylaşılmayan: `$HOME`'un kendisi, `~/.ssh`, `~/.aws`, `~/.kube`, `OPS_HOME`'un kalanı (kasa, denetim, soket,
profiller, politika), depo kaynak ağacı (bu depo), `/tmp`. Vagrant'ın varsayılan `/vagrant` paylaşımı **kapalıdır**.

### 6. Araç ikilileri konukta

Host ikilileri (Mach-O) konukta çalışamaz. `vm/provision.sh` konukta `/opt/ops-tools/` altına kurar: `bin/{tofu,terraform}`
(1.8.5 / 1.9.8, **mimariye göre** sha256 pinli — `linux_arm64` ve `linux_amd64` değerleri yayıncıların SHA256SUMS
dosyalarından), `venv/bin/{ansible-playbook,ansible-lint,…}` (ansible-core 2.21.5, ansible-lint 26.10.1), `node/bin/node`
(22.23.4, SHASUMS256.txt'den sha256), ayrıca `bubblewrap`, `git`, `jq`. CI (`ci.yml`) ile aynı sürümler.
`OPS_TOOL_DIRS`'in konuk karşılığı `state.json.toolDirs`'tir (`/opt/ops-tools/bin:/opt/ops-tools/venv/bin`); kullanıcı
`OPS_TOOL_DIRS` vermediyse VM kipinde bu kullanılır. Kullanıcı ad alanı için `kernel.apparmor_restrict_unprivileged_userns=0`
`/etc/sysctl.d/` ile kalıcıdır; provizyon sonunda `vagrant` kullanıcısıyla gerçek bir `bwrap --unshare-all` koşturulur.

Dosya sistemi sorguları (ikili var mı, venv'in yorumlayıcı zinciri, MCP sunucusunun sha256'sı, `git` yolu) host'ta değil
**konukta** cevaplanmalıdır: `Sandbox` arayüzüne isteğe bağlı `fs` (`executable/exists/realpath/readlink/sha256`) eklendi;
`VmSandbox` bunu SSH ile, `BwrapSandbox`/`UnsafeDirectRunner` yerel dosya sistemiyle sağlar. IaC çözümleyici, terminal
ikili çözümleyici, anlık kopya `git` seçimi ve MCP pin doğrulaması bu arayüzü kullanır.

### 7. Güvenlik sınırı

- Tehdit modeli değişmedi: aynı UID'li saldırgan kapsam dışı (ssh anahtarını, durum dosyasını, Vagrant dizinini
  değiştirebilir). VM'den kaçış (hipervizör açığı) kapsam dışı.
- **Konukta host kimliği yoktur**: ev dizini, kasa, denetim, kubeconfig paylaşılmaz; konuk ortamı bwrap `--clearenv` ile
  zaten boştur. Konuğun tek host erişimi hgfs paylaşımlarıdır (§5).
- SSH: Vagrant'ın ürettiği makineye özel anahtar (`insecure key` değil), sunucu anahtarı `ops vm up`'ta sabitlenir,
  `StrictHostKeyChecking yes`, agent iletimi/port iletimi/X11 kapalı. Bağlantı 127.0.0.1'e NAT iletimidir.
- Konuk ağı: VM'in dış ağı vardır (provizyon ve `vagrant` için); **sandbox içindeki** süreç `--unshare-all` ile ağsızdır,
  `network: "host"` isteyen (MCP `host` sunucusu, Cursor) konuğun ağını görür — Linux'taki "host ağı, allowlist yok"
  sınırının aynısı. Konuk, host'un loopback'ini GÖRMEZ (ağ ad alanı değil, ayrı makine): Linux'taki `network: host`
  davranışından farklı tek nokta budur (test buna göre: host'ta dinleyen sunucu VM'den erişilemez).
- bwrap sertleştirmesi Linux ile **aynı argümanlardır** (`--unshare-all`, `--clearenv`, boş kök, `/usr` salt okunur,
  `/home`/`/root`/`/run` yok). VM yalnız ikinci bir sınırdır; bwrap'ı zayıflatmanın gerekçesi değildir.
- Yol zorlaması (§4) ile model, paylaşılmamış bir host yolunu bağlatamaz; paylaşılan yollar da bwrap içinde yine açıkça
  bağlandığı kadar görünür.
- **Kayıtlı depo paylaşımı kararı (ana oturum onayı, 2026-10-25):** Linux tasarımı anlık kopya için gerçek depoyu bwrap'a
  `--ro-bind` ile zaten veriyor (`snapshot.ts`); VM bunu birebir yansıtır. Kurallar: (1) yalnız `workspaces.json`'daki her
  deponun **gerçek yolu** (realpath), hipervizör düzeyinde salt okunur (hgfs `ro`) **ve** bwrap'ta `--ro-bind`; asla üst
  dizin, asla `$HOME`; kayıtlı yol yoksa ya da paylaşılmayacak bir yerdeyse (ev dizini/atası, `.ssh`/`.aws`/`.kube`/… kimlik
  konumları, `OPS_HOME`, `/tmp`/`/var/folders` gibi çalışma zamanı dizinleri — MCP köprüsünün `roBindProblem` kuralı) veya
  başka bir paylaşımla iç içeyse `ops vm up/reload` sessizce daraltmaz, **reddeder** (`vm_share_refused`). (2) Konuk git aynı
  sertleştirme önekiyle koşar (`core.fsmonitor=false`, `core.hooksPath=/dev/null`, `protocol.ext.allow=never`, `GIT_CONFIG_*`
  boş; `ls-tree`/`cat-file --batch` süzgeç uygulamaz); `snapshot.test.ts`'in zararlı depo testleri VM'e karşı geçti. (3) Depo
  konuğa paylaşılmamışsa anlık kopya **üretilmez**: `workspace_not_shared` (boş kopya yerine açık ret); `ops workspace add/rm`
  `ops vm reload` gerektiğini söyler; `ops doctor` ve `ops vm status` her kayıtlı alanın paylaşım durumunu ✓/✗ listeler.
  Seçenek B (host'ta sandbox'sız git) `sandbox_required` sözünü bozduğu, seçenek C (snapshot/IaC macOS'ta kapalı) VM'i ana
  kullanım için anlamsız kıldığı için reddedildi. **Bugünkü paylaşım listesi:** `OPS_HOME/worktrees` (rw) + kayıtlı depo
  gerçek yolları (ro); `state.json.shares` bunun kaydıdır ve `ops vm status` gösterir.

### 8. Paylaşım türü: hgfs (denenen)

| Tür | Sonuç |
|---|---|
| **hgfs** (`vmhgfs-fuse`, VMware'in Vagrant eklentisinin varsayılanı) | Çift yönlü, anlık; host'un yazdığı 0600/0700 kipleri konukta uid eşlemesiyle `vagrant` kullanıcısına ait görünür; konuğun yazdığı dosya host'ta kullanıcıya ait ve aynı kipte. bwrap `--bind` fuse mount üstünde (aynı uid, `--unshare-all`) çalıştı. **Seçildi.** |
| NFS | macOS'ta `/etc/exports` için `sudo` ister (her `up`'ta parola), host NFS sunucusu LAN'a açılır. Reddedildi. |
| rsync | Tek yönlü ve anlık değil; konuğun yazdığı `.terraform.lock.hcl`/`fmt` çıktısı host'a dönmez. Reddedildi. |
| virtiofs | Vagrant VMware eklentisi desteklemiyor (Parallels/UTM'de var). Sağlayıcı değişirse yeniden değerlendirilir. |

hgfs'in sınırları: dosya kilitleme ve `inotify` güvenilmez; **FIFO/soket gibi özel dosyalar taşınmaz** (host'taki FIFO konukta
düz dosya görünür — terminal testinin FIFO zaman aşımı senaryosu VM kipinde atlanır, zaman aşımı/kill yolu `vm.vm.test.ts`te
ayrıca sınanır). Ürün bunlara dayanmaz (anlık kopyalar oturuma özeldir).

### 9. Sağlayıcı

Bu Mac'te (Apple Silicon) `bento/ubuntu-24.04` kutusunun arm64 sürümü VMware Fusion ile ~60 saniyede açıldı; `OPS_VM_PROVIDER`
ile `parallels`/`virtualbox`/`utm` seçilebilir (kutu aynı sürümde bu sağlayıcılar için de yayımlanmış), ama yalnız
`vmware_desktop` denendi. Kutu sürümü sabittir (`config.vm.box_version`); güncelleme bilinçli bir commit'tir.

## Sınırlar (dürüst)

- **Cursor çalışma zamanı VM kipinde kapalıdır**: `cursor-host` betiği, host Node ikilisi ve `@cursor/sdk` host
  dosyalarıdır; konuğa taşınmaları ayrı iş (ADR-0004 spike'ı da henüz geçilmedi). Açık hata verir.
- **Exec kimlik eklentileri** (`aws eks get-token` vb.) VM kipinde çalışmaz: host ikilisi pini host dosyasına aittir.
  Açık hata verir; statik kimlikler etkilenmez.
- `shell.run` iş alanı (`OPS_WORKDIR`) paylaşılan bir kök altında olmalıdır: pratikte kayıtlı bir çalışma alanı deposu
  (salt okunur paylaşım) veya bir anlık kopya dizini. Herhangi bir host dizini verilemez.
- Konuk araç sürümleri provizyonla sabittir; `ops doctor` konuktaki sürümleri gösterir, uyuşmazlığı düzeltmez
  (`ops vm destroy && ops vm up`).
- Vagrant/hipervizör güncellemeleri, hgfs sürücüsü ve VMware'in NAT'ı ürünün denetimi dışındadır; `ops vm status`
  yalnız raporlar.
- Testler: VM gerektiren testler ayrı yapılandırmadadır (`vitest.vm.config.ts`, `pnpm test:vm`); CI'da koşmaz ve
  "atlanan test yok" kapısını etkilemez. Bu, VM yolunun CI'da **doğrulanmadığı** anlamına gelir — yerelde koşulur ve
  sonuç PR'da raporlanır.
