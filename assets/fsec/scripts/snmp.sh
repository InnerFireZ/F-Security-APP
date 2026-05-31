#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "SNMP SWEEP" "community string brute · MIB walk · device profiling"

# ── Tool checks ────────────────────────────────────────────────────────────────
section "TOOLS"

_HAS_161=0; _HAS_WALK=0; _HAS_CHECK=0; _HAS_SNMPBF=0

check_tool onesixtyone && _HAS_161=1 || true
check_tool snmpwalk    && _HAS_WALK=1 || true
check_tool snmp-check  && _HAS_CHECK=1 || true

if [[ $_HAS_WALK -eq 0 ]]; then
  printf '  %s[!]%s snmpwalk not found — install: apt install snmp snmp-mibs-downloader\n' \
    "${RED}" "${RESET}"; exit 1
fi
[[ $_HAS_161   -eq 1 ]] && printf '  %s[✓]%s onesixtyone : available\n' "${GREEN}" "${RESET}" \
  || printf '  %s[~]%s onesixtyone : not found (apt install onesixtyone) — will use nmap fallback\n' "${YELLOW}" "${RESET}"
[[ $_HAS_WALK  -eq 1 ]] && printf '  %s[✓]%s snmpwalk    : available\n' "${GREEN}" "${RESET}"
[[ $_HAS_CHECK -eq 1 ]] && printf '  %s[✓]%s snmp-check  : available\n' "${GREEN}" "${RESET}" \
  || printf '  %s[~]%s snmp-check  : not found (apt install snmp-check) — skipping formatted output\n' "${YELLOW}" "${RESET}"
printf '\n'

# ── Target ─────────────────────────────────────────────────────────────────────
target="$(prompt_target)"
_nmap_load="$(pick_nmap_file)"

declare -a LIVE_HOSTS=()

if [[ -n "$_nmap_load" ]]; then
  outdir="${_nmap_load%%|*}"
  _nmap_txt="${_nmap_load##*|}"

  section "HOST DISCOVERY  (from nmap.txt)"
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
      LIVE_HOSTS+=("$_cur")
    fi
  done < "$_nmap_txt"
  printf '  %s[+]%s %d host(s) from nmap.txt\n' "${GREEN}" "${RESET}" "${#LIVE_HOSTS[@]}"
else
  outdir="$(make_outdir)"
fi

outfile="$outdir/snmp.txt"
: > "$outfile"

# ── SNMP version ───────────────────────────────────────────────────────────────
section "OPTIONS"

if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '  %s[01]%s SNMPv1 + v2c  %s(most IoT, printers, switches)%s\n' \
    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s SNMPv1 only\n' "${CYAN}" "${RESET}"
  printf '  %s[03]%s SNMPv2c only\n\n' "${CYAN}" "${RESET}"
  printf '  %s>>%s SNMP version [1]: ' "${CYAN}" "${RESET}"
  read -r _vsel; _vsel="${_vsel:-1}"
else
  _vsel=1
  printf '  %s[CHAIN]%s SNMP: v1+v2c, default community list  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
fi
case "$_vsel" in
  2) SNMP_VERS=(1) ;;
  3) SNMP_VERS=(2c) ;;
  *) SNMP_VERS=(1 2c) ;;
esac

# ── Community strings ──────────────────────────────────────────────────────────
_COMM_DEFAULT=(
  public private community manager cisco CISCO admin secret
  snmpd default monitor world internal backup agent network
  read write router switch printer server default1 public123
)

printf '\n  %s[*]%s Default community list (%d strings)\n' \
  "${CYAN}" "${RESET}" "${#_COMM_DEFAULT[@]}"
if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '  %s>>%s Add custom strings? (comma-separated, or Enter to skip): ' "${CYAN}" "${RESET}"
  read -r _custom_comm
else
  _custom_comm=""
fi

_COMMUNITIES=("${_COMM_DEFAULT[@]}")
if [[ -n "$_custom_comm" ]]; then
  IFS=',' read -ra _extra <<< "$_custom_comm"
  for _e in "${_extra[@]}"; do
    _e="${_e// /}"
    [[ -n "$_e" ]] && _COMMUNITIES+=("$_e")
  done
fi
printf '  %s[SYS]%s %d community string(s) to try\n' \
  "${CYAN}" "${RESET}" "${#_COMMUNITIES[@]}"

# ── Write community file ────────────────────────────────────────────────────────
_COMM_FILE="$outdir/.communities.txt"
printf '%s\n' "${_COMMUNITIES[@]}" > "$_COMM_FILE"

# ── Host discovery (UDP 161) ────────────────────────────────────────────────────
if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
  section "HOST DISCOVERY  (nmap UDP 161)"
  printf '  %s[*]%s Scanning %s for SNMP (UDP/161)...\n' "${CYAN}" "${RESET}" "$target"
  printf '  %s[~]%s UDP scan is slower — use nmap.txt from a prior scan to skip this\n\n' \
    "${YELLOW}" "${RESET}"

  start_spin "nmap -sU -p161"
  mapfile -t _udp < <(
    nmap -sU -p 161 -T4 --max-retries 2 --open "$target" 2>/dev/null || true
  )
  stop_spin

  _cur=""
  for _l in "${_udp[@]}"; do
    if [[ "$_l" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur" && "$_l" =~ ^161/udp.*open ]]; then
      LIVE_HOSTS+=("$_cur")
      printf '  %s[+]%s SNMP responsive: %s\n' "${GREEN}" "${RESET}" "$_cur"
    fi
  done
fi

# If onesixtyone available, use it for fast community brute against discovered hosts
declare -a SNMP_HITS=()   # "host|community|version"

if [[ ${#LIVE_HOSTS[@]} -gt 0 ]] && (( _HAS_161 == 1 )); then
  section "COMMUNITY STRING BRUTE  (onesixtyone)"
  _HOSTS_FILE="$outdir/.snmp_hosts.txt"
  printf '%s\n' "${LIVE_HOSTS[@]}" > "$_HOSTS_FILE"
  printf '  %s[*]%s Testing %d strings against %d host(s)...\n\n' \
    "${CYAN}" "${RESET}" "${#_COMMUNITIES[@]}" "${#LIVE_HOSTS[@]}"

  _161_out="$outdir/onesixtyone.txt"
  onesixtyone -c "$_COMM_FILE" -i "$_HOSTS_FILE" 2>/dev/null | tee "$_161_out" || true

  while IFS= read -r _l; do
    # onesixtyone output: "192.168.1.1 [public] ..."
    if [[ "$_l" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ \[([^\]]+)\] ]]; then
      SNMP_HITS+=("${BASH_REMATCH[1]}|${BASH_REMATCH[2]}|auto")
    fi
  done < "$_161_out"

  printf '\n  %s[+]%s %d hit(s) found\n' "${GREEN}" "${RESET}" "${#SNMP_HITS[@]}"
  rm -f "$_HOSTS_FILE"
elif [[ ${#LIVE_HOSTS[@]} -gt 0 ]]; then
  # No onesixtyone — try snmpwalk with each community/version manually
  section "COMMUNITY STRING BRUTE  (snmpwalk fallback)"
  printf '  %s[*]%s Probing %d host(s) × %d strings × %d version(s)...\n\n' \
    "${CYAN}" "${RESET}" "${#LIVE_HOSTS[@]}" "${#_COMMUNITIES[@]}" "${#SNMP_VERS[@]}"
  for _h in "${LIVE_HOSTS[@]}"; do
    for _v in "${SNMP_VERS[@]}"; do
      for _c in "${_COMMUNITIES[@]}"; do
        if snmpwalk -v "$_v" -c "$_c" -t 1 -r 1 "$_h" sysDescr 2>/dev/null | grep -q 'sysDescr'; then
          SNMP_HITS+=("${_h}|${_c}|${_v}")
          printf '  %s[+]%s %s  community=%s%s%s  version=%s\n' \
            "${GREEN}" "${RESET}" "$_h" "${CYAN}" "$_c" "${RESET}" "$_v"
          break 2
        fi
      done
    done
  done
fi

if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
  printf '\n  %s[!]%s No SNMP hosts found on %s\n\n' "${RED}" "${RESET}" "$target"
  mark_done "$outfile"; exit 0
fi

if [[ ${#SNMP_HITS[@]} -eq 0 ]]; then
  printf '\n  %s[!]%s No valid community strings found — SNMP may require v3 (not supported here)\n\n' \
    "${RED}" "${RESET}"
  mark_done "$outfile"; exit 0
fi

# ── Full enumeration ────────────────────────────────────────────────────────────
section "ENUMERATION"
printf '  %s[*]%s %d host/community pair(s) to enumerate\n\n' \
  "${CYAN}" "${RESET}" "${#SNMP_HITS[@]}"

_summarise_host() {
  local host="$1" comm="$2" ver="$3"
  local hfile="$outdir/snmp_${host//./_}.txt"
  : > "$hfile"

  printf '  %s▶%s  %s  %s[community: %s · v%s]%s\n' \
    "${CYAN}${BOLD}" "${RESET}" "$host" "${DIM}" "$comm" "$ver" "${RESET}"
  printf '  %s──────────────────────────────────────────────%s\n\n' "${DIM}" "${RESET}"

  local _args=(-v "$ver" -c "$comm" -t 3 -r 1 -Oa)

  # System group
  printf '  %s[SYS INFO]%s\n' "${CYAN}" "${RESET}"
  local _sys
  _sys="$(snmpwalk "${_args[@]}" "$host" 1.3.6.1.2.1.1 2>/dev/null || true)"
  if [[ -n "$_sys" ]]; then
    printf '%s\n' "$_sys" | while IFS= read -r _l; do
      printf '    %s%s%s\n' "${DIM}" "$_l" "${RESET}"
      printf '%s\n' "$_l" >> "$hfile"
    done
    # Extract key fields
    local _desc _name _contact _loc
    _desc="$(   printf '%s' "$_sys" | grep 'sysDescr'   | head -1 | sed 's/.*STRING: //' || true)"
    _name="$(   printf '%s' "$_sys" | grep 'sysName'    | head -1 | sed 's/.*STRING: //' || true)"
    _contact="$(printf '%s' "$_sys" | grep 'sysContact' | head -1 | sed 's/.*STRING: //' || true)"
    _loc="$(    printf '%s' "$_sys" | grep 'sysLocation'| head -1 | sed 's/.*STRING: //' || true)"
    printf '\n  %s[+]%s Host: %s%s%s\n' "${GREEN}" "${RESET}" "${BOLD}" "${_name:-unknown}" "${RESET}"
    [[ -n "$_desc"    ]] && printf '  %s[+]%s Desc     : %s\n' "${GREEN}" "${RESET}" "$_desc"
    [[ -n "$_contact" ]] && printf '  %s[+]%s Contact  : %s\n' "${GREEN}" "${RESET}" "$_contact"
    [[ -n "$_loc"     ]] && printf '  %s[+]%s Location : %s\n' "${GREEN}" "${RESET}" "$_loc"
  fi
  printf '\n'

  # Interfaces
  printf '  %s[INTERFACES]%s\n' "${CYAN}" "${RESET}"
  snmpwalk "${_args[@]}" "$host" 1.3.6.1.2.1.2.2.1.2 2>/dev/null \
    | grep -v 'No Such' | tee -a "$hfile" | while IFS= read -r _l; do
        printf '    %s%s%s\n' "${DIM}" "$_l" "${RESET}"
      done || true
  printf '\n'

  # Routing table
  local _routes
  _routes="$(snmpwalk "${_args[@]}" "$host" 1.3.6.1.2.1.4.21 2>/dev/null | grep -v 'No Such' || true)"
  if [[ -n "$_routes" ]]; then
    printf '  %s[ROUTING TABLE]%s\n' "${CYAN}" "${RESET}"
    printf '%s\n' "$_routes" | tee -a "$hfile" | while IFS= read -r _l; do
      printf '    %s%s%s\n' "${DIM}" "$_l" "${RESET}"
    done
    printf '\n'
  fi

  # Running processes
  local _procs
  _procs="$(snmpwalk "${_args[@]}" "$host" 1.3.6.1.2.1.25.4.2.1.2 2>/dev/null \
    | grep -v 'No Such' || true)"
  if [[ -n "$_procs" ]]; then
    printf '  %s[RUNNING PROCESSES]%s\n' "${CYAN}" "${RESET}"
    printf '%s\n' "$_procs" | tee -a "$hfile" | while IFS= read -r _l; do
      printf '    %s%s%s\n' "${DIM}" "$_l" "${RESET}"
    done
    printf '\n'
  fi

  # Installed software (Windows/net-snmp)
  local _sw
  _sw="$(snmpwalk "${_args[@]}" "$host" 1.3.6.1.2.1.25.6.3.1.2 2>/dev/null \
    | grep -v 'No Such' || true)"
  if [[ -n "$_sw" ]]; then
    printf '  %s[INSTALLED SOFTWARE]%s\n' "${CYAN}" "${RESET}"
    printf '%s\n' "$_sw" | head -30 | tee -a "$hfile" | while IFS= read -r _l; do
      printf '    %s%s%s\n' "${DIM}" "$_l" "${RESET}"
    done
    printf '\n'
  fi

  # Windows: users / shares (OID .77)
  local _win_users
  _win_users="$(snmpwalk "${_args[@]}" "$host" 1.3.6.1.4.1.77.1.2.25 2>/dev/null \
    | grep -v 'No Such' || true)"
  if [[ -n "$_win_users" ]]; then
    printf '  %s[WINDOWS USERS]%s\n' "${CYAN}" "${RESET}"
    printf '%s\n' "$_win_users" | tee -a "$hfile" | while IFS= read -r _l; do
      printf '    %s%s%s\n' "${GREEN}" "$_l" "${RESET}"
    done
    printf '\n'
  fi

  local _win_shares
  _win_shares="$(snmpwalk "${_args[@]}" "$host" 1.3.6.1.4.1.77.1.2.27 2>/dev/null \
    | grep -v 'No Such' || true)"
  if [[ -n "$_win_shares" ]]; then
    printf '  %s[WINDOWS SHARES]%s\n' "${CYAN}" "${RESET}"
    printf '%s\n' "$_win_shares" | tee -a "$hfile" | while IFS= read -r _l; do
      printf '    %s%s%s\n' "${GREEN}" "$_l" "${RESET}"
    done
    printf '\n'
  fi

  # snmp-check for formatted full output
  if (( _HAS_CHECK == 1 )); then
    printf '  %s[SNMP-CHECK OUTPUT]%s\n' "${CYAN}" "${RESET}"
    local _chk_file="$outdir/snmpcheck_${host//./_}.txt"
    snmp-check -v "$ver" -c "$comm" "$host" 2>/dev/null | tee "$_chk_file" | head -80 | \
      while IFS= read -r _l; do printf '    %s\n' "$_l"; done || true
    printf '\n'
  fi

  # Merge into master report
  printf '\n=== %s  [community: %s · v%s] ===\n' "$host" "$comm" "$ver" >> "$outfile"
  [[ -f "$hfile" ]] && cat "$hfile" >> "$outfile"
}

for _hit in "${SNMP_HITS[@]}"; do
  _h="${_hit%%|*}"; _rest="${_hit#*|}"; _c="${_rest%%|*}"; _v="${_rest##*|}"
  [[ "$_v" == "auto" ]] && _v="${SNMP_VERS[0]}"
  _summarise_host "$_h" "$_c" "$_v"
done

rm -f "$_COMM_FILE"

# ── Summary ─────────────────────────────────────────────────────────────────────
printf '\n  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  SNMP SWEEP COMPLETE                             │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n  %s[+]%s %d host(s) responded · %d community/host pair(s) enumerated\n' \
  "${GREEN}" "${RESET}" "${#LIVE_HOSTS[@]}" "${#SNMP_HITS[@]}"
printf '  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish SNMP hosts to alive_hosts + chain_ports (161/udp) ──
if [[ -n "${SESSION_DIR:-}" ]] && [[ ${#LIVE_HOSTS[@]} -gt 0 ]]; then
  printf '%s\n' "${LIVE_HOSTS[@]}" >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  for _sh in "${LIVE_HOSTS[@]}"; do
    printf '%s:161\n' "$_sh" >> "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  done
  sort -u "${SESSION_DIR}/chain_ports.txt" -o "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  printf '  %s[CHAIN]%s %s SNMP host(s) published to chain files%s\n\n' \
    "${CYAN}" "${RESET}" "${#LIVE_HOSTS[@]}" "${RESET}"
fi

mark_done "$outfile"
