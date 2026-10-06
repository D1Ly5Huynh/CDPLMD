#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"

# Lab policy: no VirusTotal uploads/lookups from this Cuckoo instance.
VT="$HOME/.cuckoocwd/conf/processing/virustotal.yaml"
if grep -q 'enabled: True' "$VT"; then
  sed -i 's/enabled: True/enabled: False/' "$VT"
  echo "disabled_vt"
fi
grep -n enabled "$VT" | head

echo "=== api urls ==="
python - <<'PY'
import os
p="/home/tuonghk/cuckoo3/web"
for root, dirs, files in os.walk(p):
    for f in files:
        if f.endswith(('.py','.urls')):
            fp=os.path.join(root,f)
            try:
                t=open(fp,encoding='utf-8',errors='replace').read()
            except Exception:
                continue
            if 'path(' in t or 'url(' in t or 'router' in t:
                if 'status' in t.lower() or 'submit' in t.lower() or 'task' in t.lower():
                    print(fp)
PY
echo "=== grep status/submit ==="
grep -nR "status\|submit\|tasks" /home/tuonghk/cuckoo3/web/cuckoo/web/api --include='*.py' | head -60 || true
echo "=== host default ==="
sed -n '540,580p' /home/tuonghk/cuckoo3/core/cuckoo/main.py
echo "DONE"
