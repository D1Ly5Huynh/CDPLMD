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
# A dead backend leaves these sockets. `cuckoo api` does not use them.
if ! pgrep -f 'cuckoo --debug' >/dev/null 2>&1; then
  rm -f "$CUCKOO_CWD/operational/sockets/"*.sock
fi
# Cuckoo 3 reads signatures/cuckoo/pattern/<platform>. The yml files live
# under signatures/pattern/<platform>.
PAT="$CUCKOO_CWD/signatures/cuckoo/pattern"
LEGACY="$CUCKOO_CWD/signatures/pattern"
mkdir -p "$PAT"
for kind in network windows; do
  if [[ ! -e "$PAT/$kind" && -d "$LEGACY/$kind" ]]; then
    ln -s "../../pattern/$kind" "$PAT/$kind"
  fi
done
echo "=== starting cuckoo backend $(date -Is) ===" | tee -a "$LOG"
exec cuckoo --debug
