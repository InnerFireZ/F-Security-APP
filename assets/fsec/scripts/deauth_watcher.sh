#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "DEAUTH WATCHER" "passive deauth/disassoc detector · channel hopper · attacker tracking"

require_tool tshark "apt install tshark"
require_tool iw     "apt install iw"

outdir="$(make_outdir)"

# ── Interface selection ────────────────────────────────────────────────────────
section "WIRELESS INTERFACE"

mapfile -t _wifi < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')
if [[ ${#_wifi[@]} -eq 0 ]]; then
  printf '  %s[!]%s No wireless interfaces found%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="${_wifi[0]}"
  CHANNELS="1,36,6,149,11,40,44,48,153,157,161,165"
  DWELL="0.5"
  printf '  %s[CHAIN]%s Pipeline auto — iface: %s, channels: %s%s\n\n' \
    "${CYAN}" "${RESET}" "$IFACE" "$CHANNELS" "${RESET}"
else
  for i in "${!_wifi[@]}"; do
    _mode=$(iw dev "${_wifi[$i]}" info 2>/dev/null | awk '/type/{print $2}')
    printf '  %s[%02d]%s  %-12s  %s%s%s\n' "${CYAN}" "$((i+1))" "${RESET}" \
      "${_wifi[$i]}" "${DIM}" "${_mode:-?}" "${RESET}"
  done
  printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_wifi[@]}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_wifi[@]} )); then
    printf '  %s[!]%s Invalid selection%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
  fi
  IFACE="${_wifi[$((_sel-1))]}"
  printf '\n  %s[*]%s Channels (comma-sep, default 2.4+5GHz interleaved):\n' "${CYAN}" "${RESET}"
  printf '  %s>>%s Channels [1,36,6,149,11,40,44,48,153,157,161,165]: ' "${CYAN}" "${RESET}"
  read -r _ch
  CHANNELS="${_ch:-1,36,6,149,11,40,44,48,153,157,161,165}"
  printf '  %s>>%s Channel dwell time in seconds [0.5]: ' "${CYAN}" "${RESET}"
  read -r _dw
  DWELL="${_dw:-0.5}"
fi

printf '\n  %s[SYS]%s Interface : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf '  %s[SYS]%s Channels  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$CHANNELS" "${RESET}"

# ── Colors (override lib.sh for this script's live display) ───────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

LOG_FILE="$outdir/deauth_watcher.log"
SSID_CACHE="/tmp/deauth_ssid_cache.$$"
MON_IFACE=""
HOP_PID=""; CAP_PID=""; BEACON_PID=""
_TSHARK_PIPE=""
DEAUTH_COUNT=0; DISASSOC_COUNT=0
declare -A ATTACKER_COUNT
declare -A SSID_MAP

log_raw() { printf '%s\n' "$1" >> "$LOG_FILE"; }
info()  { printf "${CYAN}[*]${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}[+]${NC} %s\n" "$*"; }
err()   { printf "${RED}[!]${NC} %s\n" "$*" >&2; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }

cleanup() {
  echo ""
  info "Stopping..."
  [[ -n "$HOP_PID" ]]    && kill "$HOP_PID"    2>/dev/null
  [[ -n "$CAP_PID" ]]    && kill "$CAP_PID"    2>/dev/null
  [[ -n "$BEACON_PID" ]] && kill "$BEACON_PID" 2>/dev/null
  rm -f "$SSID_CACHE" "$_TSHARK_PIPE" 2>/dev/null
  sleep 0.3

  ok "Detected $DEAUTH_COUNT deauth, $DISASSOC_COUNT disassoc frames"
  log_raw ""; log_raw "[+] Detected $DEAUTH_COUNT deauth, $DISASSOC_COUNT disassoc frames"

  if [[ ${#ATTACKER_COUNT[@]} -gt 0 ]]; then
    warn "Top attackers:"; log_raw "[!] Top attackers:"
    for mac in "${!ATTACKER_COUNT[@]}"; do
      printf '    %s: %s\n' "$mac" "${ATTACKER_COUNT[$mac]}"
      log_raw "    $mac: ${ATTACKER_COUNT[$mac]}"
    done | sort -t: -k2 -rn | head -10
  fi

  info "Restoring $IFACE to managed mode..."
  if command -v airmon-ng &>/dev/null && [[ "$MON_IFACE" == *mon ]]; then
    airmon-ng stop "$MON_IFACE" &>/dev/null || true
  fi
  ip link set "$IFACE" down 2>/dev/null   || true
  iw dev "$IFACE" set type managed 2>/dev/null || true
  ip link set "$IFACE" up 2>/dev/null     || true

  log_raw "[*] Session ended: $(date)"
  ok "Log: $LOG_FILE"
  mark_done "$LOG_FILE" 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

# ── Monitor mode ──────────────────────────────────────────────────────────────
PHY=$(iw dev "$IFACE" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
[[ -z "$PHY" ]] && { err "Cannot get phy for $IFACE"; exit 1; }

ORIGINAL_MODE=$(iw dev "$IFACE" info 2>/dev/null | awk '/type/{print $2}')
info "Interface: $IFACE ($PHY) — $ORIGINAL_MODE"

if [[ "$ORIGINAL_MODE" == "monitor" ]]; then
  ok "Already in monitor mode"; MON_IFACE="$IFACE"
else
  info "Enabling monitor mode..."
  if command -v airmon-ng &>/dev/null; then
    airmon-ng check kill &>/dev/null || true
    airmon-ng start "$IFACE" &>/dev/null || true
    ip link show "${IFACE}mon" &>/dev/null && MON_IFACE="${IFACE}mon" || MON_IFACE="$IFACE"
  else
    pkill -9 wpa_supplicant 2>/dev/null || true
    MON_IFACE="$IFACE"
  fi
  if ! iw dev "$MON_IFACE" info 2>/dev/null | grep -q "type monitor"; then
    ip link set "$IFACE" down
    iw dev "$IFACE" set type monitor || { err "Monitor mode failed"; exit 1; }
    ip link set "$IFACE" up
    MON_IFACE="$IFACE"
  fi
fi

ip link set "$MON_IFACE" up 2>/dev/null || true
sleep 0.3
iw dev "$MON_IFACE" info 2>/dev/null | grep -q "type monitor" || { err "Monitor mode failed"; exit 1; }
ok "Monitor mode active on $MON_IFACE"

# ── OUI lookup ────────────────────────────────────────────────────────────────
_oui_db=""
for _p in /usr/share/ieee-data/oui.txt /usr/share/wireshark/manuf /var/lib/ieee-data/oui.txt; do
  [[ -f "$_p" ]] && { _oui_db="$_p"; break; }
done

hex_to_ascii() {
  local hc="${1//:/}"
  if [[ "$hc" =~ ^[0-9a-fA-F]+$ ]] && (( ${#hc} % 2 == 0 && ${#hc} >= 2 )); then
    local i
    for (( i=0; i<${#hc}; i+=2 )); do [[ "${hc:$i:2}" == "00" ]] && { echo "$1"; return; }; done
    local d; d=$(printf '%s' "$hc" | xxd -r -p 2>/dev/null)
    [[ -n "$d" && "$d" =~ ^[[:print:]]+$ ]] && echo "$d" || echo "$1"
  else
    echo "$1"
  fi
}

beacon_capture() {
  tshark -i "$MON_IFACE" -l -n \
    -Y "wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05" \
    -T fields -e wlan.bssid -e wlan.ssid -E separator='|' 2>/dev/null \
  | while IFS='|' read -r bssid ssid; do
    [[ -n "$bssid" && -n "$ssid" ]] && \
      printf '%s|%s\n' "$bssid" "$(hex_to_ascii "$ssid")" >> "$SSID_CACHE"
  done
}

ssid_lookup() {
  local bssid="${1,,}"
  [[ -z "$bssid" || ! -f "$SSID_CACHE" ]] && return
  grep -i "^${bssid}|" "$SSID_CACHE" 2>/dev/null | tail -1 | cut -d'|' -f2 | cut -c1-20
}

target_type() {
  [[ "${1,,}" == "ff:ff:ff:ff:ff:ff" ]] && echo "BROADCAST" || echo "CLIENT"
}

channel_hop() {
  IFS=',' read -ra _chs <<< "$CHANNELS"
  while true; do
    for ch in "${_chs[@]}"; do
      iw dev "$MON_IFACE" set channel "$ch" 2>/dev/null; sleep "$DWELL"
    done
  done
}

reason_text() {
  case "$1" in
    1) echo "Unspecified";;       2) echo "Prev-auth invalid";;
    3) echo "Leaving BSS";;       4) echo "Inactivity";;
    5) echo "AP overloaded";;     6) echo "Class2 non-auth";;
    7) echo "Class3 non-assoc";;  8) echo "Disassoc leaving";;
    9) echo "Not authenticated";; *) echo "Code:$1";;
  esac
}

# ── Log init ──────────────────────────────────────────────────────────────────
{
  printf '========================================\nDeauth Watcher Log\nStarted: %s\n' "$(date)"
  printf 'Interface: %s\nChannels: %s\n========================================\n\n' "$MON_IFACE" "$CHANNELS"
  printf 'LEGEND:\n  TARGET: ALL=broadcast, CLIENT=specific device\n  RSSI: weaker than AP = attacker further away\n  SEQ: out of sync = spoofed frame\n\n'
} > "$LOG_FILE"

info "Channels: $CHANNELS  (dwell: ${DWELL}s)"
info "Log: $LOG_FILE"
warn "TARGET: ALL=broadcast attack | CLIENT=specific device"
info "Press Ctrl+C to stop"

channel_hop & HOP_PID=$!
touch "$SSID_CACHE"
beacon_capture & BEACON_PID=$!
info "Building SSID map from beacons..."
sleep 1; echo ""

HEADER=$(printf "%-10s %-8s %-10s %-20s %-19s %-6s %-6s %s" "TIME" "TYPE" "TARGET" "SSID" "DEST" "RSSI" "SEQ" "REASON")
SEP="$(printf '%.0s-' {1..105})"
printf '%s\n%s\n' "$HEADER" "$SEP"
log_raw "$HEADER"; log_raw "$SEP"

# ── Attack detection ──────────────────────────────────────────────────────────
declare -A BURST_COUNT BURST_START NOTIFIED

# Returns 0 (true) when heuristics indicate a real attack, not a normal disconnect.
# Legitimate reason codes: 3=Leaving BSS, 4=Inactivity, 8=Disassoc leaving.
_is_attack() {
  local target="$1" reason_code="$2" burst="$3"
  # Burst ≥ 5 frames from same source within 5s → always attack
  (( burst >= 5 )) && return 0
  # Broadcast deauth with non-legitimate reason + at least 2 frames → attack
  if [[ "$target" == "BROADCAST" ]] \
     && [[ "$reason_code" != "3" && "$reason_code" != "4" && "$reason_code" != "8" ]] \
     && (( burst >= 2 )); then
    return 0
  fi
  return 1
}

_TSHARK_PIPE=$(mktemp -u /tmp/deauth_tshark.XXXXXX)
mkfifo "$_TSHARK_PIPE"

tshark -i "$MON_IFACE" -l -n \
  -f "wlan type mgt subtype deauth or wlan type mgt subtype disassoc" \
  -Y "wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a" \
  -T fields \
  -e frame.time_epoch -e wlan.fc.type_subtype -e wlan.sa -e wlan.da \
  -e wlan.bssid -e wlan.fixed.reason_code -e radiotap.dbm_antsignal -e wlan.seq \
  -E separator='|' 2>/dev/null > "$_TSHARK_PIPE" &
CAP_PID=$!

while IFS='|' read -r ts subtype sa da bssid reason rssi seq; do
  [[ -z "$sa" ]] && continue
  time_str=$(date -d "@${ts%.*}" "+%H:%M:%S" 2>/dev/null || date "+%H:%M:%S")
  [[ "$subtype" == 0x* || "$subtype" == 0X* ]] \
    && subtype_dec=$(( 16#${subtype#0[xX]} )) \
    || subtype_dec=$(( 10#${subtype:-0} ))
  case "$subtype_dec" in
    12) type="DEAUTH";   ((DEAUTH_COUNT++));;
    10) type="DISASSOC"; ((DISASSOC_COUNT++));;
    *)  type="UNKNOWN";;
  esac
  ATTACKER_COUNT["$sa"]=$(( ${ATTACKER_COUNT["$sa"]:-0} + 1 ))
  ssid=$(ssid_lookup "$bssid"); [[ -z "$ssid" ]] && ssid="<unknown>"
  target=$(target_type "$da")
  [[ "$target" == "BROADCAST" ]] && tc="${RED}" ts_short="ALL" || { tc="${YELLOW}"; ts_short="CLIENT"; }
  reason_str=$(reason_text "${reason:-0}")
  rssi_str="${rssi:--?}"; [[ "$rssi_str" != "-?" ]] && rssi_str="${rssi_str}dB"
  printf "${RED}%-10s${NC} ${YELLOW}%-8s${NC} ${tc}%-10s${NC} %-20s %-19s ${CYAN}%-6s${NC} %-6s %s\n" \
    "$time_str" "$type" "$ts_short" "${ssid:0:18}" "${da:-?}" "$rssi_str" "${seq:-?}" "$reason_str"
  printf "%-10s %-8s %-10s %-20s %-19s %-6s %-6s %s\n" \
    "$time_str" "$type" "$ts_short" "${ssid:0:18}" "${da:-?}" "$rssi_str" "${seq:-?}" "$reason_str" >> "$LOG_FILE"

  # ── Burst tracking per source MAC ─────────────────────────────────────────
  _now=$(date '+%s')
  _bstart="${BURST_START[$sa]:-$_now}"
  if (( _now - _bstart > 5 )); then
    BURST_COUNT["$sa"]=1; BURST_START["$sa"]=$_now
  else
    BURST_COUNT["$sa"]=$(( ${BURST_COUNT["$sa"]:-0} + 1 ))
  fi

  # Normalize reason code (tshark may give hex or decimal)
  _reason="${reason:-0}"
  [[ "$_reason" == 0x* || "$_reason" == 0X* ]] && _reason=$(( 16#${_reason#0[xX]} ))

  # ── Emit attack line (deduplicated per burst window per attacker) ──────────
  if _is_attack "$target" "$_reason" "${BURST_COUNT[$sa]}"; then
    _nkey="${sa}_${BURST_START[$sa]}"
    if [[ "${NOTIFIED[$_nkey]:-0}" == "0" ]]; then
      NOTIFIED["$_nkey"]=1
      printf '[DEAUTH ATTACK] ATTACKER: %s  TARGET: %s  SSID: %s  BURST: %s  REASON: %s\n' \
        "$sa" "$ts_short" "${ssid:0:30}" "${BURST_COUNT[$sa]}" "$reason_str"
      log_raw "[DEAUTH ATTACK] ATTACKER: $sa  TARGET: $ts_short  SSID: ${ssid:0:30}  BURST: ${BURST_COUNT[$sa]}  REASON: $reason_str"
    fi
  fi
done < "$_TSHARK_PIPE"
rm -f "$_TSHARK_PIPE" 2>/dev/null
