#!/usr/bin/env bash
# After VMCloak snapshot: import win10vm_* into qemu.yaml and drop example1.
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
export CUCKOO_CWD="$HOME/.cuckoocwd"
VMS="$HOME/.vmcloak/vms/qemu"
if [[ ! -d "$VMS" ]]; then
  echo "no VMCloak VMs at $VMS" >&2
  exit 2
fi
echo "=== vms ==="
find "$VMS" -maxdepth 2 -type f | head -40
echo "=== import qemu ==="
cuckoo machine import qemu "$VMS"
echo "=== delete example1 ==="
cuckoo machine delete qemu example1 || true
echo "=== qemu.yaml ==="
cat "$HOME/.cuckoocwd/conf/machineries/qemu.yaml"
echo "DONE_IMPORT"
