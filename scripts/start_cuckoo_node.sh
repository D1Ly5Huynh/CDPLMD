#!/usr/bin/env bash
# Start Cuckoo 3 backend (machinery + resultserver + node info dump).
# API is a separate process on :8090.
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
export CUCKOO_CWD="$HOME/.cuckoocwd"
LOG="$HOME/cuckoo_node.log"
if ! ip -br addr show br0 2>/dev/null | grep -q "192.168.30.1"; then
  echo "br0 192.168.30.1 missing; run persist_guest_net_root.sh as root" >&2
  exit 3
fi
echo "=== starting cuckoo backend $(date -Is) ===" | tee -a "$LOG"
exec cuckoo --debug
