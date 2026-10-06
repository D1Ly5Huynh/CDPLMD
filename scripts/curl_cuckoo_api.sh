#!/usr/bin/env bash
set -euo pipefail
TOKEN="a4d74fef75dd173a76e23ce8697b647b2950c70e"
echo "=== listen ==="
ss -lnt | grep 8090 || true
echo "=== curl / ==="
curl -sS -m 5 -D - -o /tmp/cuckoo_root.body http://127.0.0.1:8090/ | head -30
echo "=== body / ==="
head -c 400 /tmp/cuckoo_root.body; echo
echo "=== curl /submit/platforms token ==="
curl -sS -m 5 -D - -o /tmp/cuckoo_plat.body -H "Authorization: Token $TOKEN" http://127.0.0.1:8090/submit/platforms | head -30
echo "=== body platforms ==="
head -c 500 /tmp/cuckoo_plat.body; echo
echo "=== curl /submit/platforms bearer ==="
curl -sS -m 5 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8090/submit/platforms | head -c 400; echo
echo "DONE_CURL"
