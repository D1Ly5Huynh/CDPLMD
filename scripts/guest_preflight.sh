#!/usr/bin/env bash
set -euo pipefail
echo "=== user ==="
id
echo "=== sudo ==="
sudo -n true && echo sudo_nopass_ok || echo sudo_needs_password
echo "=== kvm tun ==="
ls -l /dev/kvm /dev/net/tun 2>/dev/null || true
echo nested=$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || echo unknown)
echo "=== disk/mem ==="
df -h / /home
free -h
echo "=== bridge helper ==="
ls -l /usr/lib/qemu/qemu-bridge-helper /usr/libexec/qemu-bridge-helper 2>/dev/null || true
echo "=== ip ==="
ip -br link; ip -br addr
echo "=== existing vmcloak ==="
ls -ld "$HOME/vmcloak" "$HOME/.vmcloak" 2>/dev/null || true
command -v vmcloak || true
echo "=== cuckoo api ==="
ss -lnt | grep 8090 || echo api_down
echo "=== iso search ==="
find "$HOME" /mnt/c/Users/tuonghk -maxdepth 4 \( -iname '*win10*.iso' -o -iname '*windows*10*.iso' \) 2>/dev/null | head
echo "DONE_PREFLIGHT"
