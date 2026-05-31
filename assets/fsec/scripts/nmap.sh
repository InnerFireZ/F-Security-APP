#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
require_tool nmap

banner "NMAP SCANNER" "port discovery · version detection · two-stage"

ip=$(prompt_target)
outdir=$(make_outdir)

printf '  %s[SYS]%s Target : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$ip" "${RESET}"
printf '  %s[SYS]%s Output : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"

# ── Helpers ───────────────────────────────────────────────────────────────────

# Extracts comma-separated open TCP port numbers from a nmap output file.
_open_ports() {
  grep -E '^[0-9]+/tcp.*open' "$1" \
    | cut -d'/' -f1 \
    | tr '\n' ',' \
    | sed 's/,$//'
}

# Stage 1 — fast port sweep without version probes.
# Separating discovery from version detection is what avoids "increasing send delay":
# nmap only triggers congestion control when it floods many probes per port (-sV/-sC).
# A plain SYN sweep is lightweight and stays fast.
#
# Writes to nmap.txt (compatible with pick_nmap_file + all downstream tools).
# Sets global _OPEN_PORTS after run.
_OPEN_PORTS=""
_stage1() {
  local portflag="$1"   # "" = top 1000, "-p-" = all 65535
  local label="$2"
  printf '\n  %s[*]%s Stage 1 — port sweep (%s)\n' "${CYAN}" "${RESET}" "$label"
  printf '  %s[~]%s No version probes (-sV/-sC skipped) — fast and clean%s\n\n' \
    "${DIM}" "${RESET}" "${RESET}"

  # shellcheck disable=SC2086
  run_fg nmap -sS -Pn -n -T4 --max-retries 2 \
    --max-scan-delay 10ms --min-rate 300 \
    -oN "$outdir/nmap.txt" \
    -v $portflag "$ip"

  _OPEN_PORTS=$(_open_ports "$outdir/nmap.txt")
  local count
  count=$(echo "$_OPEN_PORTS" | tr ',' '\n' | grep -c '[0-9]' 2>/dev/null || echo 0)
  printf '\n  %s[+]%s Open ports (%s) : %s%s%s\n' \
    "${GREEN}" "${RESET}" "$count" "${CYAN}" "${_OPEN_PORTS:-none}" "${RESET}"
  printf '  %s[SYS]%s Saved to : %s%s%s\n' \
    "${CYAN}" "${RESET}" "${DIM}" "$outdir/nmap.txt" "${RESET}"
}

# Stage 2 — version + script scan on confirmed-open ports only.
# Because we target only open ports (not thousands of closed ones),
# nmap never floods the network and send delay stays at 0.
_stage2() {
  local ports="$1"
  if [[ -z "$ports" ]]; then
    printf '\n  %s[!] No open ports to scan — stage 2 skipped%s\n' "${YELLOW}" "${RESET}"
    return
  fi
  local count
  count=$(echo "$ports" | tr ',' '\n' | grep -c '[0-9]' 2>/dev/null || echo 0)
  printf '\n  %s[*]%s Stage 2 — version + scripts on %s open port(s): %s%s%s\n' \
    "${CYAN}" "${RESET}" "$count" "${GREEN}" "$ports" "${RESET}"
  printf '  %s[~]%s Targeting only open ports — no send-delay issue%s\n\n' \
    "${DIM}" "${RESET}" "${RESET}"

  run_fg nmap -sV -sC -Pn -n -p "$ports" --max-retries 2 \
    --max-scan-delay 10ms \
    -oN "$outdir/nmap_full.txt" \
    -v "$ip"

  printf '\n  %s[SYS]%s Discovery : %s%s%s\n' \
    "${CYAN}" "${RESET}" "${DIM}" "$outdir/nmap.txt" "${RESET}"
  printf '  %s[SYS]%s Full scan  : %s%s%s\n' \
    "${CYAN}" "${RESET}" "${DIM}" "$outdir/nmap_full.txt" "${RESET}"
}

# ── Menu ──────────────────────────────────────────────────────────────────────

printf '\n'
printf '  %s──────────────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
printf '  %s[1]%s Quick  — top 1000 ports, no version  %s(fast · feeds other tools)%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[2]%s Full   — top 1000 discovery + version/scripts on open ports%s\n' \
  "${CYAN}" "${RESET}" "${RESET}"
printf '  %s[3]%s Deep   — ALL 65535 ports discovery + version/scripts on open ports%s\n' \
  "${CYAN}" "${RESET}" "${RESET}"
printf '  %s[4]%s Custom — enter port range, version scan directly%s\n' \
  "${CYAN}" "${RESET}" "${RESET}"
printf '  %s[0]%s Exit\n' "${DIM}" "${RESET}"
printf '  %s──────────────────────────────────────────────────────%s\n\n' "${DIM}" "${RESET}"
if [[ -n "${SESSION_DIR:-}" ]]; then
  choice=2  # Full scan (discovery + version) in pipeline mode
  printf '  %s[CHAIN]%s Mode: Full scan  (pipeline auto-select)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
else
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r choice
fi

case "$choice" in
  1)
    _stage1 "" "top 1000 ports, no version"
    ;;
  2)
    _stage1 "" "top 1000 ports, no version"
    _stage2 "$_OPEN_PORTS"
    ;;
  3)
    _stage1 "-p-" "all 65535 ports, no version"
    _stage2 "$_OPEN_PORTS"
    ;;
  4)
    printf '  %s[>]%s Ports (e.g.  22,80,443  or  1-1024): ' "${CYAN}" "${RESET}"
    read -r custom_ports
    if [[ -z "$custom_ports" ]]; then
      printf '  %s[!] No ports entered%s\n' "${RED}" "${RESET}"
    else
      printf '\n  %s[*]%s Version scan on ports: %s%s%s\n\n' \
        "${CYAN}" "${RESET}" "${GREEN}" "$custom_ports" "${RESET}"
      run_fg nmap -sV -sC -Pn -n -p "$custom_ports" --max-retries 2 \
        --max-scan-delay 10ms \
        -oN "$outdir/nmap.txt" \
        -v "$ip"
      printf '\n  %s[SYS]%s Saved to : %s%s%s\n' \
        "${CYAN}" "${RESET}" "${DIM}" "$outdir/nmap.txt" "${RESET}"
    fi
    ;;
  0)
    exit 0
    ;;
  *)
    printf '  %s[!] Invalid option%s\n' "${RED}" "${RESET}"
    ;;
esac

# ── Pipeline: write alive_hosts.txt + chain_ports.txt from nmap results ───────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outdir/nmap.txt" ]]; then
  # alive_hosts.txt — unique IPs with any open port
  grep -oE 'report for [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$outdir/nmap.txt" \
    | awk '{print $3}' | sort -u >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  _ah=$(wc -l < "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || echo 0)
  # chain_ports.txt — structured ip:port for targeted downstream scans
  _cur_ip=""
  while IFS= read -r _nline; do
    if [[ "$_nline" =~ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur_ip="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur_ip" && "$_nline" =~ ^([0-9]+)/tcp.*open ]]; then
      printf '%s:%s\n' "$_cur_ip" "${BASH_REMATCH[1]}" >> "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
    fi
  done < "$outdir/nmap.txt"
  sort -u "${SESSION_DIR}/chain_ports.txt" -o "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  _ap=$(wc -l < "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || echo 0)
  printf '  %s[CHAIN]%s %s alive host(s), %s open port(s) → chain_ports.txt%s\n' \
    "${CYAN}" "${RESET}" "$_ah" "$_ap" "${RESET}"
fi

mark_done "$outdir"
