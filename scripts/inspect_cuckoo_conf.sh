#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
CWD="$HOME/.cuckoocwd"
echo "=== conf listing ==="
ls -la "$CWD/conf" || true
find "$CWD/conf" -type f | sort || true
echo "=== versions ==="
cat "$CWD/.versions" || true
echo "=== createcwd help ==="
cuckoo createcwd --help
echo "=== default conf in src ==="
find "$HOME/cuckoo3" -iname '*qemu*.yaml' -o -iname '*kvm*.yaml' -o -iname '*cuckoo.yaml' | head -50
echo "=== conf examples ==="
find "$HOME/cuckoo3" -path '*conf*' -name '*.yaml' | head -80
echo "=== storage.py createcwd hints ==="
python - <<'PY'
from cuckoo.common import storage
print("storage", storage.__file__)
PY
echo "=== qemu-system ==="
which qemu-system-x86_64
qemu-system-x86_64 --version | head -3
ls -l /dev/kvm
echo nested=$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || echo unknown)
free -h
df -h / /home
echo "=== iso/images ==="
find /home/tuonghk /mnt/c/Users/tuonghk -maxdepth 4 \( -iname '*.iso' -o -iname '*.qcow2' -o -iname '*Win10*' \) 2>/dev/null | head -40
echo "DONE_INSPECT"
