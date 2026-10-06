#!/usr/bin/env bash
# CERT-EE Win10 1703 ISO. Resume-safe: wget -c, never curl --retry-all-errors
# (that discards the partial file on HTTP 200 after FortiGate SSL reset).
set -uo pipefail
URL="https://cuckoo-hatch.cert.ee/static/vm/Win10_1703_English_x64.iso"
DEST="$HOME/win10x64.iso"
EXPECT_SHA1="ce8005a659e8df7fe9b080352cb1c313c3e9adce"
EXPECT=4334315520
LOG="$HOME/win10_iso_download.log"

size_now() { stat -c%s "$DEST" 2>/dev/null || echo 0; }

mkdir -p "$(dirname "$DEST")"
if [[ -f "$DEST" ]]; then
  sz=$(size_now)
  if [[ "$sz" -eq "$EXPECT" ]]; then
    have=$(sha1sum "$DEST" | awk '{print $1}')
    if [[ "$have" == "$EXPECT_SHA1" ]]; then
      echo "ISO_ALREADY_OK $DEST $have"
      exit 0
    fi
    echo "ISO_SIZE_OK_SHA1_BAD have=$have, deleting" | tee -a "$LOG"
    rm -f "$DEST"
  fi
fi

echo "DOWNLOAD_START $(date -Is) size=$(size_now) -> $DEST" | tee -a "$LOG"

attempt=0
while [[ "$(size_now)" -lt "$EXPECT" ]]; do
  attempt=$((attempt+1))
  echo "RESUME attempt=$attempt size=$(size_now) $(date -Is)" | tee -a "$LOG"
  if wget -c --tries=0 --timeout=30 --read-timeout=60 --waitretry=5 \
    --retry-connrefused --progress=bar:force:noscroll \
    -O "$DEST" "$URL" >>"$LOG" 2>&1; then
    break
  fi
  echo "wget_fail size=$(size_now) sleep 8 $(date -Is)" | tee -a "$LOG"
  sleep 8
done

sz=$(size_now)
if [[ "$sz" -ne "$EXPECT" ]]; then
  echo "ISO_SIZE_FAIL size=$sz expected=$EXPECT" >&2
  exit 2
fi
have=$(sha1sum "$DEST" | awk '{print $1}')
ls -lh "$DEST"
echo "sha1=$have expected=$EXPECT_SHA1"
if [[ "$have" != "$EXPECT_SHA1" ]]; then
  echo "ISO_SHA1_FAIL" >&2
  exit 2
fi
echo "ISO_OK $DEST"
