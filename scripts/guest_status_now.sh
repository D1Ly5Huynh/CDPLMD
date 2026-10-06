#!/usr/bin/env bash
set -u
DEST=/home/tuonghk/win10x64.iso
EXPECT=4334315520
echo "=== iso ==="
if [[ -f "$DEST" ]]; then
  sz=$(stat -c%s "$DEST")
  echo "SIZE=$sz EXPECT=$EXPECT"
  awk -v s="$sz" -v e="$EXPECT" 'BEGIN{printf "pct=%.1f size_mib=%.1f\n", 100.0*s/e, s/1048576.0}'
else
  echo "ISO_MISSING"
fi
echo "=== br0 ==="
ip -br link show br0 2>/dev/null || echo NO_BR0
ip addr show br0 2>/dev/null | head -8
echo "=== kvm tun ==="
ls -l /dev/kvm /dev/net/tun
echo "=== vmcloak ==="
ls -l /home/tuonghk/.vmcloak-venv/bin/vmcloak
echo "=== cuckoo pkgs ==="
/home/tuonghk/.cuckoo-venv/bin/python -c "import sqlalchemy,pefile,psutil,setuptools; print(sqlalchemy.__version__, pefile.__version__, psutil.__version__, setuptools.__version__)"
echo "=== curl ==="
pgrep -af curl | head
echo "=== qemu.yaml exists ==="
ls -l /home/tuonghk/.cuckoocwd/conf/machineries/qemu.yaml
echo "=== vmcloak images ==="
ls -lh /home/tuonghk/.vmcloak/vms/qemu 2>/dev/null || echo NO_VMCLOAK_VMS
