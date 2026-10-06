#!/usr/bin/env bash
echo "=== listen ==="
ss -lnt | grep -E '8090|2042' || true
echo "=== procs ==="
pgrep -af 'cuckoo|qemu-system' || echo none
echo "=== sig windows sample ==="
ls "$HOME/.cuckoocwd/signatures/cuckoo/pattern/windows" | head
echo "=== node log tail ==="
tail -5 "$HOME/cuckoo_node.log" 2>/dev/null || true
