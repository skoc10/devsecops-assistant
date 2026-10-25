#!/usr/bin/env bash
# ops-assistant sandbox VM provizyonu (ADR-0011 §6). Konukta root olarak çalışır; idempotenttir.
# Araç sürümleri ve sha256 değerleri .github/workflows/ci.yml ile AYNI kaynaklardan (yayıncı SHA256SUMS dosyaları);
# mimariye göre (arm64/amd64) seçilir. İmza doğrulaması (GPG/cosign) yapılmaz — bilinen sınır.
set -euo pipefail

TOOLS=/opt/ops-tools
DL=/var/tmp/ops-tools-dl
TOFU_VERSION=1.8.5
TF_VERSION=1.9.8
NODE_VERSION=22.23.4
ANSIBLE_CORE=2.21.5
ANSIBLE_LINT=26.10.1

case "$(uname -m)" in
  aarch64|arm64)
    ARCH=arm64; NODE_ARCH=arm64
    TOFU_SHA=2535e8d4979806cbf79a1b704dccf1fae45b4d50ccaee3e54c1771044db4a573
    TF_SHA=f85868798834558239f6148834884008f2722548f84034c9b0f62934b2d73ebb
    NODE_SHA=6287aa46b6c375d816e63ae66d024fbbfd70404825aabdfdf898a970871d2f4b ;;
  x86_64)
    ARCH=amd64; NODE_ARCH=x64
    TOFU_SHA=e2951ba6be8ae9427aabbd5c6f243855e8b526cb2ae6bc33a05dae22d7e82632
    TF_SHA=186e0145f5e5f2eb97cbd785bc78f21bae4ef15119349f6ad4fa535b83b10df8
    NODE_SHA=1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce ;;
  *) echo "desteklenmeyen mimari: $(uname -m)" >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# bubblewrap: sandbox; git/jq: shell.run kataloğu ve anlık kopya; python3-venv: ansible; unzip/curl/xz: indirmeler
apt-get install -y -qq --no-install-recommends bubblewrap git jq unzip curl ca-certificates xz-utils python3 python3-venv >/dev/null

# Kullanıcı ad alanları (Ubuntu 24.04 AppArmor kısıtı) — kalıcı.
install -d -m 755 /etc/sysctl.d
echo "kernel.apparmor_restrict_unprivileged_userns = 0" > /etc/sysctl.d/60-ops-userns.conf
sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0

install -d -m 755 "$TOOLS" "$TOOLS/bin" "$DL"

fetch() { # fetch URL DOSYA SHA256
  local url=$1 out=$2 sha=$3
  if [ -f "$out" ] && echo "$sha  $out" | sha256sum -c --quiet - 2>/dev/null; then return 0; fi
  curl -fsSL --retry 3 -o "$out" "$url"
  echo "$sha  $out" | sha256sum -c --quiet -
}

if [ ! -x "$TOOLS/bin/tofu" ] || [ "$("$TOOLS/bin/tofu" version -json 2>/dev/null | jq -r .terraform_version)" != "$TOFU_VERSION" ]; then
  fetch "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_${ARCH}.zip" "$DL/tofu.zip" "$TOFU_SHA"
  unzip -q -o "$DL/tofu.zip" tofu -d "$TOOLS/bin"
fi
if [ ! -x "$TOOLS/bin/terraform" ] || [ "$("$TOOLS/bin/terraform" version -json 2>/dev/null | jq -r .terraform_version)" != "$TF_VERSION" ]; then
  fetch "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_${ARCH}.zip" "$DL/tf.zip" "$TF_SHA"
  unzip -q -o "$DL/tf.zip" terraform -d "$TOOLS/bin"
fi
if [ ! -x "$TOOLS/node/bin/node" ] || [ "$("$TOOLS/node/bin/node" --version)" != "v${NODE_VERSION}" ]; then
  fetch "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" "$DL/node.tar.xz" "$NODE_SHA"
  rm -rf "$TOOLS/node" "$TOOLS/node-tmp"; install -d "$TOOLS/node-tmp"
  tar -xJf "$DL/node.tar.xz" -C "$TOOLS/node-tmp" --strip-components=1
  mv "$TOOLS/node-tmp" "$TOOLS/node"
fi
if [ ! -x "$TOOLS/venv/bin/ansible-lint" ] || ! "$TOOLS/venv/bin/pip" show ansible-core 2>/dev/null | grep -q "^Version: ${ANSIBLE_CORE}$"; then
  rm -rf "$TOOLS/venv"
  python3 -m venv "$TOOLS/venv"
  "$TOOLS/venv/bin/pip" install --quiet --disable-pip-version-check "ansible-core==${ANSIBLE_CORE}" "ansible-lint==${ANSIBLE_LINT}"
fi
chmod -R a+rX "$TOOLS"

# Doğrulama: bwrap vagrant kullanıcısıyla GERÇEKTEN çalışıyor mu (kurulu olması yetmez)?
su -s /bin/sh vagrant -c 'bwrap --die-with-parent --new-session --unshare-all --clearenv --proc /proc --dev /dev --tmpfs /tmp --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib -- /usr/bin/true'
echo "ops-vm: bwrap $(bwrap --version | cut -d' ' -f2) | tofu $TOFU_VERSION | terraform $TF_VERSION | node $NODE_VERSION | ansible-core $ANSIBLE_CORE | ansible-lint $ANSIBLE_LINT | $(uname -m)"
