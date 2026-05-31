#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

banner "FSCAN" "fast internal network scanner"

ip=$(prompt_target)
outdir=$(make_outdir)
printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$ip" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir/fscan.txt" "${RESET}"
printf '\n'

run_fg "$(dirname "$0")/../fscan" -h "$ip" | (trap '' SIGINT; tee "$outdir/fscan.txt")

# ── Pipeline chain: extract alive hosts and open ports ────────────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outdir/fscan.txt" ]]; then
  # Extract IPs with open ports → alive_hosts.txt
  grep -oE '\[[\*\+]\].*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$outdir/fscan.txt" 2>/dev/null \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  # Extract host:port pairs → chain_ports.txt
  grep -oE '\[\*\].*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' "$outdir/fscan.txt" 2>/dev/null \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | sort -u >> "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_ports.txt" -o "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  _ah=$(wc -l < "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || echo 0)
  _ap=$(wc -l < "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || echo 0)
  printf '  %s[CHAIN]%s %s alive host(s), %s open port(s) published%s\n' \
    "${CYAN}" "${RESET}" "$_ah" "$_ap" "${RESET}"
fi

mark_done "$outdir"
