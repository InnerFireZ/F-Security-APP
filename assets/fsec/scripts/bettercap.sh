#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "BETTERCAP" "ARP MITM · net.sniff · net.probe · http.proxy (no SSL)"

require_tool bettercap "apt install bettercap"

outdir="$(make_outdir)"
outfile="$outdir/bettercap.log"
: > "$outfile"

# ── Interface selection ────────────────────────────────────────────────────────
section "INTERFACE"

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="$(resolve_iface any)"
  printf '  %s[CHAIN]%s Interface: %s%s%s  (auto-detected)\n\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
  _mode=2  # ARP MITM in pipeline mode
  printf '  %s[CHAIN]%s Mode: ARP MITM (pipeline auto-select)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
else
  mapfile -t _ifaces < <(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | grep -vE '^(rmnet|r_rmnet|bond|dummy)')
  if [[ ${#_ifaces[@]} -eq 0 ]]; then
    printf '  %s[!]%s No network interfaces found%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
  fi
  for i in "${!_ifaces[@]}"; do
    _ip=$(ip -o -4 addr show "${_ifaces[$i]}" 2>/dev/null | awk '{print $4}' | head -1)
    printf '  %s[%02d]%s  %-14s  %s%s%s\n' \
      "${CYAN}" "$((i+1))" "${RESET}" "${_ifaces[$i]}" "${DIM}" "${_ip:-no IPv4}" "${RESET}"
  done
  printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_ifaces[@]}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_ifaces[@]} )); then
    printf '  %s[!]%s Invalid selection%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
  fi
  IFACE="${_ifaces[$((_sel-1))]}"
  printf '\n  %s[SYS]%s Interface : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"

  # ── Mode selection ──────────────────────────────────────────────────────────
  section "MODE"
  printf '  %s[01]%s  Discovery         net.probe + net.sniff  (passive, no MITM)\n'          "${CYAN}" "${RESET}"
  printf '  %s[02]%s  ARP MITM          net.probe + arp.spoof + net.sniff\n'                   "${CYAN}" "${RESET}"
  printf '  %s[03]%s  ARP MITM + HTTP   net.probe + arp.spoof + net.sniff + http.proxy\n'     "${CYAN}" "${RESET}"
  printf '\n  %s[!]%s  HTTPS/SSL-strip disabled — causes errors on this setup%s\n\n' "${YELLOW}" "${RESET}" "${RESET}"
  printf '  %s>>%s Mode [1-3, default 2]: ' "${CYAN}" "${RESET}"
  read -r _mode; _mode="${_mode:-2}"
fi

_arp_target="${TARGET:-}"
if [[ -z "${SESSION_DIR:-}" ]] && [[ "$_mode" == "2" || "$_mode" == "3" ]]; then
  printf '  %s>>%s ARP spoof target IP/range (empty = whole subnet): ' "${CYAN}" "${RESET}"
  read -r _arp_target
fi

case "$_mode" in
  1) printf '\n  %s[SYS]%s Mode : %sDiscovery — passive%s\n\n' "${CYAN}" "${RESET}" "${GREEN}"  "${RESET}" ;;
  2) printf '\n  %s[SYS]%s Mode : %sARP MITM%s\n\n'            "${CYAN}" "${RESET}" "${RED}"    "${RESET}" ;;
  3) printf '\n  %s[SYS]%s Mode : %sARP MITM + HTTP proxy%s\n\n' "${CYAN}" "${RESET}" "${RED}"  "${RESET}" ;;
  *) printf '  %s[!]%s Invalid mode%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1 ;;
esac

# ── Build eval commands ────────────────────────────────────────────────────────
_cmds=""
case "$_mode" in
  1)
    _cmds="net.recon on; net.probe on; net.sniff on"
    ;;
  2)
    [[ -n "$_arp_target" ]] && _cmds="set arp.spoof.targets $_arp_target; "
    _cmds+="set arp.spoof.fullduplex true; net.recon on; net.probe on; arp.spoof on; net.sniff on"
    ;;
  3)
    [[ -n "$_arp_target" ]] && _cmds="set arp.spoof.targets $_arp_target; "
    _cmds+="set arp.spoof.fullduplex true; net.recon on; net.probe on; arp.spoof on; net.sniff on; http.proxy on"
    ;;
esac

# ── Run ────────────────────────────────────────────────────────────────────────
section "CAPTURE"

printf '  %s[*]%s Starting bettercap on %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf '  %s[*]%s Log  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '  %s[*]%s Press %sCTRL+C%s to stop\n\n' "${CYAN}" "${RESET}" "${BOLD}" "${RESET}"

bettercap -iface "$IFACE" -no-history -eval "$_cmds" 2>&1 | (trap '' SIGINT; tee "$outfile") || true

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish discovered hosts → alive_hosts.txt ────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outfile" ]]; then
  grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$outfile" 2>/dev/null \
    | grep -vE '^(0\.0\.0\.0|127\.|255\.|224\.)' \
    | sort -u >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  _ah=$(wc -l < "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || echo 0)
  [[ "$_ah" -gt 0 ]] && printf '  %s[CHAIN]%s alive_hosts.txt: %s host(s) from bettercap%s\n\n' \
    "${CYAN}" "${RESET}" "$_ah" "${RESET}"
fi
mark_done "$outdir"
