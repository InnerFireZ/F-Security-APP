#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "MASSCAN" "ultra-fast port scanner · million packets/sec"

require_tool masscan "apt install masscan"

outdir="$(make_outdir)"
outfile="$outdir/masscan.log"
: > "$outfile"

section "TARGET"
if [[ -n "${SESSION_DIR:-}" && -n "${TARGET:-}" ]]; then
  _target="$TARGET"
  printf '  %s[CHAIN]%s Target: %s%s%s  (env)\n' "${CYAN}" "${RESET}" "${GREEN}" "$_target" "${RESET}"
else
  printf '  %s>>%s Target range (e.g. 10.0.0.0/8  192.168.1.0/24  10.1.1.1-50): ' "${CYAN}" "${RESET}"
  read -r _target
  [[ -z "$_target" ]] && { printf '  %s[!]%s Target required\n' "${RED}" "${RESET}"; exit 1; }
fi

section "SCAN PROFILE"
if [[ -n "${SESSION_DIR:-}" ]]; then
  _prof=2; _ports="--top-ports 1000"; _rate=1000; _srcip=""
  printf '  %s[CHAIN]%s Profile: Top-1000  Rate: 1000 pps  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
else
  printf '\n'
  printf '  %s[01]%s Top 100 ports   — ultra-fast recon\n'                "${CYAN}" "${RESET}"
  printf '  %s[02]%s Top 1000 ports  — standard sweep\n'                  "${CYAN}" "${RESET}"
  printf '  %s[03]%s All TCP ports   — full 1-65535 (slow on /8)\n'       "${CYAN}" "${RESET}"
  printf '  %s[04]%s Common services — 21,22,23,25,53,80,110,135,139,\n'  "${CYAN}" "${RESET}"
  printf '          443,445,1433,1521,3306,3389,5985,8080,8443,9200\n'
  printf '  %s[05]%s Custom ports\n'                                       "${CYAN}" "${RESET}"
  printf '\n  %s>>%s Profile [2]: ' "${CYAN}" "${RESET}"
  read -r _prof; _prof="${_prof:-2}"
  case "$_prof" in
    1) _ports="--top-ports 100" ;;
    2) _ports="--top-ports 1000" ;;
    3) _ports="-p1-65535" ;;
    4) _ports="-p21,22,23,25,53,80,110,135,139,443,445,1433,1521,3306,3389,5985,5986,8080,8443,9200" ;;
    5) printf '  %s>>%s Ports (e.g. 80,443,8080-8090): ' "${CYAN}" "${RESET}"; read -r _cp
       _ports="-p${_cp}" ;;
    *) _ports="--top-ports 1000" ;;
  esac
  printf '  %s>>%s Rate (packets/sec) [1000 — careful on VPN/cloud]: ' "${CYAN}" "${RESET}"
  read -r _rate; _rate="${_rate:-1000}"
  printf '  %s>>%s Source IP %s(blank = auto · use your actual IP on VPN)%s: ' \
    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  read -r _srcip
fi

_extra_args=()
[[ -n "${_srcip:-}" ]] && _extra_args+=(--source-ip "$_srcip")

printf '\n  %s[*]%s masscan → %s%s%s  at %s pps\n\n' \
  "${CYAN}" "${RESET}" "${GREEN}" "$_target" "${RESET}" "$_rate"
printf '  %s[!]%s Ctrl+C to stop. Output: %s%s%s\n\n' \
  "${YELLOW}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# shellcheck disable=SC2086
run_fg masscan "$_target" \
  ${_ports} \
  --rate "$_rate" \
  --open-only \
  -oG "$outdir/masscan_grepable.txt" \
  "${_extra_args[@]}" \
  2>&1 | tee -a "$outfile" || true

# Parse results summary
if [[ -f "$outdir/masscan_grepable.txt" ]]; then
  printf '\n  %s[+]%s Open ports found:\n' "${GREEN}" "${RESET}"
  grep "^Host:" "$outdir/masscan_grepable.txt" 2>/dev/null | \
    awk '{printf "  %s  %s\n", $2, $5}' | sort -V | tee -a "$outfile" || true
fi

printf '\n  %s[SYS]%s Log    : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '  %s[SYS]%s Grepable: %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir/masscan_grepable.txt" "${RESET}"

# ── Pipeline: write alive_hosts.txt + chain_ports.txt ────────────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outdir/masscan_grepable.txt" ]]; then
  # alive_hosts.txt — unique IPs
  grep "^Host:" "$outdir/masscan_grepable.txt" 2>/dev/null \
    | awk '{print $2}' | sort -u >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  # chain_ports.txt — ip:port pairs from masscan grepable
  grep "^Host:" "$outdir/masscan_grepable.txt" 2>/dev/null \
    | awk 'match($0, /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*Ports: ([0-9]+)/, a) {printf "%s:%s\n", a[1], a[2]}' \
    | sort -u >> "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_ports.txt" -o "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  _ah=$(wc -l < "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || echo 0)
  _ap=$(wc -l < "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || echo 0)
  printf '  %s[CHAIN]%s %s alive host(s), %s open port(s) in chain files%s\n' \
    "${CYAN}" "${RESET}" "$_ah" "$_ap" "${RESET}"
fi

mark_done "$outdir"
