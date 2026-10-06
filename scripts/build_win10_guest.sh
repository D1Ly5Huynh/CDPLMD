#!/usr/bin/env bash
# After ISO is SHA1-ok: mount, vmcloak init, recommended install, 1 snapshot.
set -euo pipefail
source "$HOME/.vmcloak-venv/bin/activate"
ISO="$HOME/win10x64.iso"
EXPECT_SHA1="ce8005a659e8df7fe9b080352cb1c313c3e9adce"
LOG="$HOME/vmcloak_win10.log"

have=$(sha1sum "$ISO" | awk '{print $1}')
if [[ "$have" != "$EXPECT_SHA1" ]]; then
  echo "ISO not ready sha1=$have" >&2
  exit 2
fi

if ! findmnt /mnt/win10x64 >/dev/null 2>&1; then
  echo "ISO must be mounted at /mnt/win10x64 (run guest_mount_root.sh as root)" >&2
  exit 3
fi

echo "=== vmcloak migrate ===" | tee -a "$LOG"
vmcloak migrate || true

echo "=== vmcloak init win10base ===" | tee -a "$LOG"
# 64 GiB sparse qcow2 (CERT-EE default is 128; host C: ~128 GB free).
# 4 GiB RAM / 2 CPU matches CERT-EE quickstart; nested in WSL 12 GiB.
vmcloak --debug init \
  --win10x64 \
  --hddsize 64 \
  --cpus 2 \
  --ramsize 4096 \
  --network 192.168.30.0/24 \
  --vm qemu \
  --vrde --vrde-port 1 \
  --ip 192.168.30.2 \
  --iso-mount /mnt/win10x64 \
  win10base br0 2>&1 | tee -a "$LOG"

# Paper IF-MalEvade §IV: orig-vs-mutate Cuckoo signatures. Guest needs
# agent (from init) + Defender/WU off. Skip IE/.NET/Edge/Adobe/VCRedist.
echo "=== vmcloak install disableservices (paper-min) ===" | tee -a "$LOG"
vmcloak --debug install win10base disableservices 2>&1 | tee -a "$LOG"

echo "=== vmcloak snapshot ===" | tee -a "$LOG"
vmcloak --debug snapshot --count 1 win10base win10vm_ 192.168.30.10 2>&1 | tee -a "$LOG"

echo "DONE_WIN10_GUEST" | tee -a "$LOG"
ls -lh "$HOME/.vmcloak/vms/qemu/" || true
