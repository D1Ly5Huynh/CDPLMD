#!/usr/bin/env bash
# Run as root: wsl -d Ubuntu-22.04 -u root -- bash this
set -euo pipefail
BRIDGE=br0
CIDR=192.168.30.1/24

if [[ "$(id -u)" -ne 0 ]]; then
  echo "need root (wsl -u root)"
  exit 1
fi

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  bridge-utils iproute2 iptables qemu-system-x86 qemu-utils qemu-system-common \
  genisoimage cpu-checker >/dev/null

if [[ ! -d "/sys/class/net/$BRIDGE/bridge" ]]; then
  ip link add name "$BRIDGE" type bridge stp_state 0
fi
if ! ip -4 addr show "$BRIDGE" | grep -q "192.168.30.1"; then
  ip addr add "$CIDR" dev "$BRIDGE" || true
fi
ip link set "$BRIDGE" up

mkdir -p /etc/qemu
grep -qxF "allow $BRIDGE" /etc/qemu/bridge.conf 2>/dev/null || echo "allow $BRIDGE" >> /etc/qemu/bridge.conf
chmod u+s /usr/lib/qemu/qemu-bridge-helper
chmod 666 /dev/kvm || true
mkdir -p /mnt/win10x64

sysctl -w net.ipv4.ip_forward=1 >/dev/null
# NAT guest traffic out of WSL eth0 so Win10 can fetch Python/deps.
iptables -t nat -C POSTROUTING -s 192.168.30.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 192.168.30.0/24 -o eth0 -j MASQUERADE
iptables -C FORWARD -i br0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i br0 -o eth0 -j ACCEPT
iptables -C FORWARD -i eth0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i eth0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "=== net ==="
ip -br addr show "$BRIDGE"
ls -l /usr/lib/qemu/qemu-bridge-helper
cat /etc/qemu/bridge.conf
echo "DONE_GUEST_NET"
