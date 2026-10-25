#!/usr/bin/env bash
# Sandbox gerektiren takımları AÇIK sandbox VM'ine karşı koşturur (ADR-0011). Önce: `ops vm up`.
#  - OPS_SANDBOX=vm: detectSandbox yalnız VM'i kabul eder (bwrap'a düşmez; VM yoksa testler FAIL eder, atlanmaz)
#  - OPS_TEST_VM=1: VM'e özgü testler (*.vm.test.ts) açılır
#  - TMPDIR paylaşım (OPS_HOME/worktrees) altındadır: testlerin geçici depo/iş alanı dizinleri konukta görünür
#  - OPS_VM_DIR gerçek VM durum dizinidir: testler kendi geçici OPS_HOME'larıyla koşar, VM'i bu yolla bulurlar
#  - OPS_TOOL_DIRS konuk araç dizinleridir
set -euo pipefail
cd "$(dirname "$0")/.."
OPS_HOME="${OPS_HOME:-$HOME/.ops-assistant}"
[ -f "$OPS_HOME/vm/state.json" ] || { echo "VM durum dosyası yok: önce \`ops vm up\`" >&2; exit 1; }
export OPS_SANDBOX=vm OPS_TEST_VM=1 OPS_VM_DIR="$OPS_HOME/vm"
export TMPDIR="$OPS_HOME/worktrees/.vm-test-tmp"
mkdir -p "$TMPDIR"; chmod 700 "$TMPDIR"
export OPS_TOOL_DIRS="${OPS_TOOL_DIRS:-/opt/ops-tools/bin:/opt/ops-tools/venv/bin}"
exec pnpm exec vitest run --config vitest.vm.config.ts "$@"
