#!/bin/bash

WAIT=2
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
mkdir -p "$OUT"

# Check any RTSP-capable port
for DPORT in 554 8554 37777; do
  nc -nw $WAIT "$1" $DPORT < /dev/null 2>/dev/null || continue
  echo "[*] RTSP/cam port $DPORT open on $1"
  nmap -Pn -n -p "$DPORT" --script rtsp-methods "$1" 2>/dev/null \
    | tee "$OUT/rtsp-methods-${1}_${DPORT}_${TIME}.txt"
  nmap -Pn -n -p "$DPORT" --script rtsp-url-brute "$1" -oX /tmp/rtsp_${1}_${DPORT}.xml 2>/dev/null
  if url=$(xmllint --xpath '//table[@key="discovered"]/elem/text()' \
           /tmp/rtsp_${1}_${DPORT}.xml 2>/dev/null); then
    echo "[*] Stream URL: $url" | tee -a "$OUT/rtsp-methods-${1}_${DPORT}_${TIME}.txt"
    timeout 20 cvlc "$url" --sout="file/ts:$OUT/stream-${1}_${DPORT}_${TIME}.ts" \
      >/dev/null 2>&1 || true
    [ -s "$OUT/stream-${1}_${DPORT}_${TIME}.ts" ] && \
      echo "[+] stream captured: $OUT/stream-${1}_${DPORT}_${TIME}.ts"
  fi
done
