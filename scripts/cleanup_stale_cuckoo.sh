#!/usr/bin/env bash
set -euo pipefail
SOCKDIR="$HOME/.cuckoocwd/operational/sockets"
# Kill leftover backend only. Keep `cuckoo api`.
for pid in $(pgrep -f 'cuckoo --debug' || true); do
  kill "$pid" 2>/dev/null || true
done
sleep 1
rm -f "$SOCKDIR"/*.sock
echo "removed socks in $SOCKDIR"
ls -l "$SOCKDIR" || true
ss -lnt | grep -E '8090|2042' || echo "no 2042 (ok)"
echo "DONE_CLEAN"
