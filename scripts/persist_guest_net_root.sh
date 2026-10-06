#!/usr/bin/env bash
# wsl -d Ubuntu-22.04 -u root -- bash this
# Install a oneshot systemd unit so br0/NAT survive WSL restarts.
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
  echo "need root (wsl -u root)" >&2
  exit 1
fi

install -d -m 0755 /usr/local/sbin /etc/qemu /mnt/win10x64
cat >/usr/local/sbin/cuckoo-guest-net.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
BRIDGE=br0
CIDR=192.168.30.1/24
if [[ ! -d "/sys/class/net/$BRIDGE/bridge" ]]; then
  ip link add name "$BRIDGE" type bridge stp_state 0
fi
if ! ip -4 addr show "$BRIDGE" | grep -q "192.168.30.1"; then
  ip addr add "$CIDR" dev "$BRIDGE" || true
fi
ip link set "$BRIDGE" up
grep -qxF "allow $BRIDGE" /etc/qemu/bridge.conf 2>/dev/null || echo "allow $BRIDGE" >> /etc/qemu/bridge.conf
chmod u+s /usr/lib/qemu/qemu-bridge-helper || true
chmod 666 /dev/kvm || true
mkdir -p /mnt/win10x64
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -C POSTROUTING -s 192.168.30.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 192.168.30.0/24 -o eth0 -j MASQUERADE
iptables -C FORWARD -i br0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i br0 -o eth0 -j ACCEPT
iptables -C FORWARD -i eth0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i eth0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT
ip -br addr show "$BRIDGE"
EOS
chmod 0755 /usr/local/sbin/cuckoo-guest-net.sh

cat >/etc/systemd/system/cuckoo-br0.service <<'EOF'
[Unit]
Description=Cuckoo QEMU br0 192.168.30.0/24 and NAT
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cuckoo-guest-net.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

/usr/local/sbin/cuckoo-guest-net.sh
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now cuckoo-br0.service
  systemctl is-enabled cuckoo-br0.service
  systemctl --no-pager --full status cuckoo-br0.service | head -20
fi
echo "DONE_PERSIST_NET"
