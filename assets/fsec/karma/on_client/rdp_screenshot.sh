#!/bin/bash
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

WAIT=2
TIMEOUT=30
DPORT=3389
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
mkdir -p "$OUT"

if ! nc -nw $WAIT "$1" $DPORT </dev/null 2>/dev/null; then
	exit 0
fi

echo "[*] RDP port open on $1 — attempting screenshot"

# Try freerdp screenshot (no X11 needed — headless capable)
if command -v xfreerdp &>/dev/null; then
	IMG="$OUT/rdp-${1}_${TIME}.png"
	timeout $TIMEOUT xfreerdp /v:"$1":$DPORT /u:'' /p:'' /cert-ignore \
		/size:1280x800 /screenshot /screenshot-file:"$IMG" /log-level:OFF >/dev/null 2>/dev/null
	[ -s "$IMG" ] && echo "[+] RDP screenshot: $IMG"
fi

# Try rdesktop if X11 available
if [ -n "${DISPLAY:-}" ] && command -v rdesktop &>/dev/null; then
	IMG="$OUT/rdp-${1}_${TIME}_rdesktop.png"
	echo yes | timeout $TIMEOUT rdesktop -u '' "$1" >/dev/null 2>/dev/null &
	RDPID=$!
	sleep $((TIMEOUT - 5))
	window_id=$(xwininfo -root -tree 2>/dev/null | grep '("rdesktop" "rdesktop")' | awk '{print $1}')
	if [ -n "$window_id" ]; then
		import -window "$window_id" "$IMG" && echo "[+] RDP screenshot: $IMG"
		xkill -id "$window_id" >/dev/null 2>&1
	fi
	kill $RDPID 2>/dev/null || true
fi
