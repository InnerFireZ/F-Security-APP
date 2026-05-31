#!/bin/bash
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
mkdir -p "$OUT"
OUTFILE="$OUT/ip-forward-${1}_${TIME}.txt"

echo "[*] checking IP forwarding on $1" | tee "$OUTFILE"
nmap -sn -n "$1" --script ip-forwarding --script-args="ip-forwarding.target=${3}" \
	2>/dev/null | tee -a "$OUTFILE"

if grep -q 'ip forwarding enabled' "$OUTFILE"; then
	echo "[+] IP forwarding ENABLED on $1" | tee -a "$OUTFILE"
fi
