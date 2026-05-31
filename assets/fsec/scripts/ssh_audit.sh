#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "SSH AUDIT" "algorithm · cipher · key-exchange security scanner"

# ── Tool detection ────────────────────────────────────────────────────────────
SCANNER_CMD=()

for _c in ssh-audit /usr/bin/ssh-audit ssh_audit; do
  if command -v "$_c" &>/dev/null; then
    SCANNER_CMD=("$_c")
    break
  fi
done

if [[ ${#SCANNER_CMD[@]} -eq 0 ]]; then
  _py="$(dirname "$0")/../ssh_audit.py"
  if [[ -f "$_py" ]] && command -v python3 &>/dev/null; then
    SCANNER_CMD=(python3 "$_py")
  else
    printf '  %s[!]%s ssh-audit not found.%s\n\n' "${RED}" "${RESET}" "${RESET}"
    printf '      apt install ssh-audit\n\n'
    exit 1
  fi
fi

printf '  %s[SYS]%s Scanner : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "${SCANNER_CMD[*]}" "${RESET}"

# ── Target & port ─────────────────────────────────────────────────────────────
target="$(prompt_target)"

section "OPTIONS"
if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '  %s>>%s SSH port [22]: ' "${CYAN}" "${RESET}"
  read -r PORT; PORT="${PORT:-22}"
  printf '  %s[01]%s ▶  info    %s(all findings)%s\n'        "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s ▶  warn    %s(warnings + failures)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[03]%s ▶  fail    %s(critical failures only)%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s>>%s Level [1]: ' "${CYAN}" "${RESET}"
  read -r _lvl
else
  PORT="${PORT:-22}"
  _lvl=1
  printf '  %s[CHAIN]%s Port: %s  Level: info  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "$PORT" "${RESET}"
fi
case "${_lvl:-1}" in
  2) LEVEL="warn" ;;
  3) LEVEL="fail" ;;
  *) LEVEL="info" ;;
esac

# ── Existing nmap.txt? ────────────────────────────────────────────────────────
_nmap_load="$(pick_nmap_file)"

declare -a EP_HOSTS=()

if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_ports.txt" ]]; then
  # Pipeline chain: use chain_ports.txt — find hosts with this SSH port open
  outdir="$(make_outdir)"
  outfile="$outdir/ssh_audit.txt"; : > "$outfile"
  section "ENDPOINT DISCOVERY  (from chain_ports.txt)"
  while IFS=: read -r _cp_ip _cp_port; do
    [[ "$_cp_port" == "$PORT" ]] && EP_HOSTS+=("$_cp_ip")
  done < "${SESSION_DIR}/chain_ports.txt"
  printf '  %s[CHAIN]%s Found %d SSH host(s) on port %s from chain_ports.txt%s\n\n' \
    "${CYAN}" "${RESET}" "${#EP_HOSTS[@]}" "$PORT" "${RESET}"
elif [[ -n "$_nmap_load" ]]; then
  outdir="${_nmap_load%%|*}"
  _nmap_txt="${_nmap_load##*|}"
  outfile="$outdir/ssh_audit.txt"
  : > "$outfile"

  section "ENDPOINT DISCOVERY  (from nmap.txt)"
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur" && "$_line" =~ ^${PORT}/tcp.*open ]]; then
      EP_HOSTS+=("$_cur")
    fi
  done < "$_nmap_txt"
else
  outdir="$(make_outdir)"
  outfile="$outdir/ssh_audit.txt"
  : > "$outfile"

  section "ENDPOINT DISCOVERY"
  # Pipeline chain: if alive_hosts.txt exists, scan only discovered hosts
  local _scan_target="$target"
  if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/alive_hosts.txt" ]]; then
    _scan_target=$(paste -sd' ' "${SESSION_DIR}/alive_hosts.txt")
    printf '  %s[CHAIN]%s Targeting %s discovered host(s) from alive_hosts.txt%s\n' \
      "${CYAN}" "${RESET}" "$(wc -l < "${SESSION_DIR}/alive_hosts.txt")" "${RESET}"
  else
    printf '  %s[*]%s Scanning %s for port %s/tcp...%s\n' \
      "${CYAN}" "${RESET}" "$target" "$PORT" "${RESET}"
  fi

  start_spin "nmap scan running"
  # shellcheck disable=SC2086
  mapfile -t _scan < <(
    nmap -sS -Pn -n -T4 --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
         -p "$PORT" --open $_scan_target 2>/dev/null
  )
  stop_spin

  _cur=""
  for _line in "${_scan[@]}"; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "${_cur}" && "$_line" =~ ^${PORT}/tcp.*open ]]; then
      EP_HOSTS+=("$_cur")
    fi
  done
fi

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Port    : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}"   "$PORT"   "${RESET}"
printf '  %s[SYS]%s Level   : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}"   "$LEVEL"  "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# Handle single-host target (not CIDR) with no nmap.txt
if [[ ${#EP_HOSTS[@]} -eq 0 ]]; then
  if [[ ! "$target" =~ /[0-9]+$ ]]; then
    EP_HOSTS+=("$target")
  else
    printf '\n  %s[!]%s No hosts found with port %s open on %s\n' \
      "${YELLOW}" "${RESET}" "$PORT" "$target"
    if [[ -n "${SESSION_DIR:-}" ]]; then
      printf '  %s[CHAIN]%s No SSH hosts found — skipping SSH audit%s\n' "${CYAN}" "${RESET}" "${RESET}"
      exit 0
    fi
    printf '  %s>>%s Enter host manually (or Enter to exit): ' "${CYAN}" "${RESET}"
    read -r _manual
    [[ -z "$_manual" ]] && exit 0
    EP_HOSTS+=("$_manual")
  fi
fi

printf '\n  %s[+]%s %d host(s) to audit:\n\n' "${GREEN}" "${RESET}" "${#EP_HOSTS[@]}"
for _h in "${EP_HOSTS[@]}"; do
  printf '  %s  ●%s  %s\n' "${CYAN}" "${RESET}" "$_h"
done
printf '\n'

# ── Finding summariser ────────────────────────────────────────────────────────
_summarise() {
  local logfile="$1"
  [[ ! -f "$logfile" ]] && return
  local _fails=0 _warns=0

  while IFS= read -r _l; do
    if [[ "$_l" == *"-- [fail]"* || "$_l" == *$'\x60- [fail]'* ]]; then
      printf '  %s[✗]%s %s\n' "${RED}" "${RESET}" "$_l"
      (( _fails++ )) || true
    elif [[ "$_l" == *"-- [warn]"* || "$_l" == *$'\x60- [warn]'* ]]; then
      printf '  %s[~]%s %s\n' "${YELLOW}" "${RESET}" "$_l"
      (( _warns++ )) || true
    fi
  done < "$logfile"

  printf '\n'
  if (( _fails > 0 )); then
    printf '  %s[✗] %d failure(s)  ·  %d warning(s)%s\n' "${RED}" "$_fails" "$_warns" "${RESET}"
  elif (( _warns > 0 )); then
    printf '  %s[~] %d warning(s) — review recommended%s\n' "${YELLOW}" "$_warns" "${RESET}"
  else
    printf '  %s[✓]%s Clean — no failures or warnings\n' "${GREEN}" "${RESET}"
  fi
}

# ── Per-host scanner (runs in background job) ─────────────────────────────────
_run_scan() {
  local host="$1"
  local ep_log="$outdir/ssh_${host//./_}_${PORT}.txt"

  printf '\n  %s▶%s  %s:%s\n' "${CYAN}${BOLD}" "${RESET}" "$host" "$PORT"
  printf '  %s──────────────────────────────────────────────%s\n\n' "${DIM}" "${RESET}"

  "${SCANNER_CMD[@]}" --no-colors --level="$LEVEL" -p "$PORT" "$host" 2>&1 \
    | (trap '' SIGINT; tee "$ep_log") || true

  printf '\n  %s▶ FINDINGS%s\n' "${CYAN}${BOLD}" "${RESET}"
  _summarise "$ep_log"
}

# ── Execute — parallel host scanning, ordered output ─────────────────────────
section "SCANNING"
_ep_count="${#EP_HOSTS[@]}"

if (( _ep_count > 1 )); then
  printf '  %s[*]%s %d host(s) — parallel (max 4 concurrent)%s\n\n' \
    "${CYAN}" "${RESET}" "$_ep_count" "${RESET}"
else
  printf '  %s[*]%s 1 host queued%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
fi

_PARALLEL_MAX=4
_tmpout=()
_pids=()

for _host in "${EP_HOSTS[@]}"; do
  _tmp="$outdir/.ssh_out_${_host//./_}.tmp"
  _tmpout+=("$_tmp")
  _run_scan "$_host" > "$_tmp" 2>&1 &
  _pids+=($!)
  while (( $(jobs -rp | wc -l) >= _PARALLEL_MAX )); do sleep 0.3; done
done

for i in "${!_pids[@]}"; do
  wait "${_pids[$i]}" 2>/dev/null || true
  [[ -f "${_tmpout[$i]}" ]] && { cat "${_tmpout[$i]}"; rm -f "${_tmpout[$i]}"; }
done

# ── Merge per-host logs into summary outfile ──────────────────────────────────
for _host in "${EP_HOSTS[@]}"; do
  _ep_log="$outdir/ssh_${_host//./_}_${PORT}.txt"
  if [[ -f "$_ep_log" ]]; then
    printf '\n=== %s:%s ===\n' "$_host" "$PORT" >> "$outfile"
    cat "$_ep_log" >> "$outfile"
  fi
done

# ── Final summary ─────────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  AUDIT COMPLETE                                  │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'

_total_fails=0
_total_warns=0
if [[ -s "$outfile" ]]; then
  _total_fails=$(grep -c '-- \[fail\]' "$outfile" 2>/dev/null || echo 0)
  _total_warns=$(grep -c '-- \[warn\]' "$outfile" 2>/dev/null || echo 0)
fi

if (( _total_fails > 0 )); then
  printf '  %s[✗] %d failure(s) · %d warning(s) across all hosts — review report%s\n' \
    "${RED}" "$_total_fails" "$_total_warns" "${RESET}"
elif (( _total_warns > 0 )); then
  printf '  %s[~] %d warning(s) found — hardening recommended%s\n' \
    "${YELLOW}" "$_total_warns" "${RESET}"
else
  printf '  %s[✓]%s No critical issues detected\n' "${GREEN}" "${RESET}"
fi

printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
mark_done "$outfile"
