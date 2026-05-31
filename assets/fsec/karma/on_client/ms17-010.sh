#!/bin/bash
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

WAIT=2
DPORT=445
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
mkdir -p "$OUT"
OUTFILE="$OUT/ms17010-${1}_${TIME}.txt"

if ! nc -nw $WAIT "$1" $DPORT </dev/null 2>/dev/null; then
	exit 0
fi

echo "[*] checking MS17-010 (EternalBlue) on $1" | tee "$OUTFILE"
nmap -Pn -n -p 445 --script smb-vuln-ms17-010 "$1" 2>/dev/null | tee -a "$OUTFILE"

if grep -q 'VULNERABLE' "$OUTFILE"; then
	echo "[!!!] MS17-010 VULNERABLE: $1" | tee -a "$OUTFILE"
else
	echo "[-] MS17-010 not vulnerable: $1" | tee -a "$OUTFILE"
fi
