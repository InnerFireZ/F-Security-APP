#!/bin/bash
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

WAIT=2
TIMEOUT=30
HTTP_PORTS=(80 8080)
HTTPS_PORTS=(443 8443)
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
mkdir -p "$OUT"

function www_screenshot(){
	local url=$1 ip=$2 port=$3
	local base="$OUT/www-${ip}_${port}_${TIME}"

	if [ -n "${DISPLAY:-}" ] && command -v surf &>/dev/null; then
		local out="${base}.png"
		timeout $TIMEOUT surf -t "$url" >/dev/null 2>/dev/null &
		sleep $((TIMEOUT-2))
		window_id=$(xwininfo -root -tree 2>/dev/null | grep '.*|.*("surf" "Surf")' | awk '{print $1}')
		if [ -n "$window_id" ]; then
			import -window "$window_id" "$out" && echo "[+] screenshot: $out"
			xkill -id "$window_id" >/dev/null 2>&1
		fi

	elif command -v wkhtmltoimage &>/dev/null; then
		local out="${base}.png"
		timeout $TIMEOUT wkhtmltoimage --quiet --width 1280 "$url" "$out" >/dev/null 2>/dev/null
		[ -s "$out" ] && echo "[+] screenshot: $out"

	elif command -v firefox-esr &>/dev/null || command -v firefox &>/dev/null; then
		local out="${base}.png"
		local ffbin
		ffbin=$(command -v firefox-esr 2>/dev/null || command -v firefox)
		MOZ_HEADLESS=1 timeout $TIMEOUT "$ffbin" --headless \
			--screenshot "$out" --window-size=1280,800 "$url" >/dev/null 2>/dev/null
		[ -s "$out" ] && echo "[+] screenshot: $out"

	elif command -v cutycapt &>/dev/null; then
		local out="${base}.png"
		xvfb-run --auto-servernum \
			timeout $TIMEOUT cutycapt --url="$url" --out="$out" --delay=3000 >/dev/null 2>/dev/null
		[ -s "$out" ] && echo "[+] screenshot: $out"

	else
		local html="${base}.html"
		curl -sk --max-time $TIMEOUT -L "$url" -o "$html" 2>/dev/null
		[ -s "$html" ] && echo "[+] HTML saved: $html"
	fi
}

for port in "${HTTP_PORTS[@]}"; do
	if nc -nw $WAIT "$1" "$port" </dev/null 2>/dev/null; then
		echo "[*] screenshotting http://$1:$port"
		www_screenshot "http://$1:$port" "$1" "$port"
	fi
done

for port in "${HTTPS_PORTS[@]}"; do
	if nc -nw $WAIT "$1" "$port" </dev/null 2>/dev/null; then
		echo "[*] screenshotting https://$1:$port"
		www_screenshot "https://$1:$port" "$1" "$port"
	fi
done
