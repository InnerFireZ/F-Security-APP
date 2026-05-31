#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "WIFITE" "automated WiFi auditor — WPA handshake · WPS Pixie · PMKID · WEP"

require_tool wifite "apt install wifite"
require_tool iw     "apt install iw"

outdir="$(make_outdir)"
outfile="$outdir/wifite.log"
: > "$outfile"

IFACE=""

# ── Cleanup ────────────────────────────────────────────────────────────────────
_cleanup() {
  printf '\n  %s[*]%s Restoring interface to managed mode...\n' "${CYAN}" "${RESET}"
  if [[ -n "$IFACE" ]]; then
    ip link set "$IFACE" down 2>/dev/null || true
    iw dev "$IFACE" set type managed 2>/dev/null || true
    ip link set "$IFACE" up 2>/dev/null || true
  fi
  printf '  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
}
trap '_cleanup' EXIT

# ── Interface selection ────────────────────────────────────────────────────────
section "WIRELESS INTERFACE"

mapfile -t _wifi < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')
if [[ ${#_wifi[@]} -eq 0 ]]; then
  printf '  %s[!]%s No wireless interfaces found\n' "${RED}" "${RESET}"; exit 1
fi

for i in "${!_wifi[@]}"; do
  _mode_str=$(iw dev "${_wifi[$i]}" info 2>/dev/null | awk '/type/{print $2}')
  printf '  %s[%02d]%s  %-14s  %s%s%s\n' \
    "${CYAN}" "$((i+1))" "${RESET}" "${_wifi[$i]}" "${DIM}" "${_mode_str:-managed}" "${RESET}"
done

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="$(resolve_iface wifi)"
  _mode=1; _mode_flags=(); _p=60; _pillage_flag=(-p 60)
  _default_dict="/usr/share/dict/wordlist-probable.txt"; _dict="$_default_dict"
  _mac_flag=()
  printf '  %s[CHAIN]%s Interface: %s  Mode: All  Pillage: 60s  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "$IFACE" "${RESET}"
else
  printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_wifi[@]}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_wifi[@]} )); then
    printf '  %s[!]%s Invalid selection\n' "${RED}" "${RESET}"; exit 1
  fi
  IFACE="${_wifi[$((_sel-1))]}"
  printf '\n  %s[SYS]%s Interface : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"

  section "ATTACK MODE"
  printf '  %s[01]%s  All targets    WPA handshake + WPS Pixie/PIN + PMKID %s(default)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s  WPA only       Handshake capture + dictionary crack\n'                 "${CYAN}" "${RESET}"
  printf '  %s[03]%s  WPS only       Pixie Dust + WPS PIN brute-force\n'                     "${CYAN}" "${RESET}"
  printf '  %s[04]%s  PMKID only     Clientless PMKID capture\n'                             "${CYAN}" "${RESET}"
  printf '  %s[05]%s  WEP only       IVS capture + aircrack crack\n'                         "${CYAN}" "${RESET}"
  printf '\n  %s>>%s Mode [1-5, default 1]: ' "${CYAN}" "${RESET}"
  read -r _mode; _mode="${_mode:-1}"
  case "$_mode" in
    1) _mode_flags=() ;; 2) _mode_flags=(--wpa --no-pmkid) ;;
    3) _mode_flags=(--wps-only) ;; 4) _mode_flags=(--pmkid) ;; 5) _mode_flags=(--wep) ;;
    *) printf '  %s[!]%s Invalid mode\n' "${RED}" "${RESET}"; exit 1 ;;
  esac
  printf '\n  %s>>%s Auto-attack after scan (seconds, 0 = interactive select): ' "${CYAN}" "${RESET}"
  read -r _p; _p="${_p:-0}"
  _pillage_flag=()
  [[ "$_p" =~ ^[0-9]+$ ]] && (( _p > 0 )) && _pillage_flag=(-p "$_p")
  _default_dict="/usr/share/dict/wordlist-probable.txt"
  printf '  %s>>%s Wordlist [%s]: ' "${CYAN}" "${RESET}" "$_default_dict"
  read -r _dict; _dict="${_dict:-$_default_dict}"
  printf '  %s>>%s Randomize MAC? [y/N]: ' "${CYAN}" "${RESET}"
  read -r _mac
  _mac_flag=()
  [[ "${_mac,,}" == "y" ]] && _mac_flag=(--random-mac)
fi

# ── Summary ────────────────────────────────────────────────────────────────────
printf '\n'
printf '  %s[SYS]%s Interface : %s%s%s\n'  "${CYAN}" "${RESET}" "${GREEN}" "$IFACE"   "${RESET}"
printf '  %s[SYS]%s Mode      : %s%d%s\n'  "${CYAN}" "${RESET}" "${GREEN}" "$_mode"   "${RESET}"
printf '  %s[SYS]%s Wordlist  : %s%s%s\n'  "${CYAN}" "${RESET}" "${DIM}"   "$_dict"   "${RESET}"
[[ ${#_pillage_flag[@]} -gt 0 ]] && \
printf '  %s[SYS]%s Pillage   : %s%ss%s\n' "${CYAN}" "${RESET}" "${DIM}"   "$_p"      "${RESET}"
[[ ${#_mac_flag[@]} -gt 0 ]] && \
printf '  %s[SYS]%s MAC       : %srandom%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '\n'

# ── Run ────────────────────────────────────────────────────────────────────────
section "ATTACK"

printf '  %s[*]%s Starting wifite on %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf '  %s[*]%s Handshakes/PMKID saved to: %s%s/hs/%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"
printf '  %s[*]%s Press %sCTRL+C%s to stop\n\n' "${CYAN}" "${RESET}" "${BOLD}" "${RESET}"

# cd to outdir so wifite drops hs/ and cracked.json into the session folder
cd "$outdir"

# run_fg writes wifite's PID to /tmp/.fsec_tool.pid before exec'ing it.
# This lets the app's tap (soft Ctrl+C) send SIGINT only to wifite so it
# stops scanning and shows the target menu — without killing this bash.
# No pipe to tee: wifite needs a real TTY for its interactive display.
run_fg wifite \
  -i "$IFACE" \
  --kill \
  --daemon \
  --dict "$_dict" \
  "${_mode_flags[@]}" \
  "${_pillage_flag[@]}" \
  "${_mac_flag[@]}" || true

# ── Pipeline chain: publish cracked WiFi keys → chain_creds.txt ───────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  _cracked_json="$outdir/cracked.json"
  if [[ -f "$_cracked_json" ]]; then
    python3 - "$_cracked_json" <<'PYEOF' >> "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
import json, sys
try:
  data = json.load(open(sys.argv[1]))
  if isinstance(data, dict): data = [data]
  for r in data:
    ssid = r.get('essid', r.get('bssid', 'wifi'))
    key  = r.get('key', r.get('password', ''))
    if key:
      print(f'[wifi]    login: {ssid}   password: {key}')
except Exception:
  pass
PYEOF
    sort -u "${SESSION_DIR}/chain_creds.txt" -o "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
    _wc=$(wc -l < "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || echo 0)
    [[ "$_wc" -gt 0 ]] && printf '  %s[CHAIN]%s chain_creds.txt: %s WiFi key(s) published%s\n\n' \
      "${CYAN}" "${RESET}" "$_wc" "${RESET}"
  fi
fi
mark_done "$outdir"
