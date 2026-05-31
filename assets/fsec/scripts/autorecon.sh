#!/usr/bin/env bash
# Ping sweep → AutoRecon (TCP only, rootless-safe)
source "$(dirname "$0")/../lib.sh"
require_tool autorecon "pip install git+https://github.com/Tib3rius/AutoRecon.git"

banner "AUTORECON" "ping sweep + automated multi-tool recon · rootless TCP"

iface="${1:-wlan0}"
max_jobs="${MAX_JOBS:-50}"
timeout_s=1

cidr="$(prompt_target)"

# ── Existing nmap.txt? ────────────────────────────────────────────────────────
_nmap_load="$(pick_nmap_file)"

network="${cidr%.*/*}"
outfile="alive_${network//./-}.txt"
: > "$outfile"

if [[ -n "$_nmap_load" ]]; then
  # Extract unique IPs with any open port from existing nmap.txt
  _nmap_txt="${_nmap_load##*|}"
  awk '/report for/{ip=$NF} /\/tcp.*open/{print ip}' "$_nmap_txt" \
    | sort -u > "$outfile"
  _loaded=$(wc -l < "$outfile")
  printf '  %s[+]%s %d host(s) loaded from nmap.txt — skipping ping sweep%s\n\n' \
    "${GREEN}" "${RESET}" "$_loaded" "${RESET}"
else
  if [[ -z "$cidr" ]]; then
    printf '  %s[!] Could not determine IPv4 for interface "%s"%s\n' "${RED}" "$iface" "${RESET}"
    exit 1
  fi
  if [[ "$cidr" != */* ]]; then
    printf '  %s[!] Need a subnet CIDR (e.g. 192.168.1.0/24), got: %s%s\n' "${RED}" "$cidr" "${RESET}"
    exit 1
  fi

  lockfile="${outfile}.lock"
  touch "$lockfile"
  trap 'rm -f "$lockfile"' EXIT

  on_int() {
    printf '\n  %s[!] Ctrl-C received — stopping scan%s\n' "${YELLOW}" "${RESET}"
    jobs -p | xargs -r kill 2>/dev/null
    wait
    printf '  %s[~] Partial results saved in %s%s\n' "${YELLOW}" "$outfile" "${RESET}"
    exit 130
  }
  trap on_int INT

  scan_host() {
    local ip="$1"
    if ping -c 1 -W "$timeout_s" "$ip" > /dev/null 2>&1; then
      printf '  %s[+]%s %s is alive\n' "${GREEN}" "${RESET}" "$ip"
      { exec 9>"$lockfile"; flock -x 9; echo "$ip" >> "$outfile"; flock -u 9; exec 9>&-; } 2>/dev/null
    fi
  }

  printf '  %s[*]%s Sweeping %s.1–%s.254  (up to %d parallel pings)%s\n' \
    "${CYAN}" "${RESET}" "$network" "$network" "$max_jobs" "${RESET}"
  printf '  %s[*]%s Press Ctrl-C to stop early — results save incrementally%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"

  for i in {1..254}; do
    scan_host "${network}.${i}" &
    while (( $(jobs -r | wc -l) >= max_jobs )); do sleep 0.05; done
  done
  wait
fi

if [[ -s "$outfile" ]]; then
  ardir="results/autorecon_$(date '+%Y-%m-%d_%H-%M-%S')"
  printf '\n  %s[+]%s Alive hosts found — launching AutoRecon%s\n' "${GREEN}" "${RESET}" "${RESET}"
  printf '  %s[SYS]%s Output: %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$ardir" "${RESET}"
  autorecon -t "$outfile" --nmap "-sS -sV -sC --reason --open" -o "$ardir"

  # ── Pipeline chain: publish discovered IPs ──────────────────────────────────
  if [[ -n "${SESSION_DIR:-}" ]]; then
    cat "$outfile" >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
    sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
    _ah=$(wc -l < "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || echo 0)
    printf '  %s[CHAIN]%s alive_hosts.txt: %s host(s) from autorecon%s\n\n' \
      "${CYAN}" "${RESET}" "$_ah" "${RESET}"
  fi
else
  printf '\n  %s[!] No alive hosts found.%s\n' "${YELLOW}" "${RESET}"
fi

mark_done "$outfile"
