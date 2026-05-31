#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "DNS / ACTIVE DIRECTORY" "zone transfer · SRV discovery · domain enumeration"

require_tool dig  "apt install dnsutils"
require_tool nmap "apt install nmap"

# ── Inputs ────────────────────────────────────────────────────────────────────
target="$(prompt_target)"

# ── Existing nmap.txt? ────────────────────────────────────────────────────────
_nmap_load="$(pick_nmap_file)"

if [[ -n "$_nmap_load" ]]; then
  outdir="${_nmap_load%%|*}"
else
  outdir="$(make_outdir)"
fi
outfile="$outdir/dns_ad.txt"
: > "$outfile"

# Auto-detect domain from resolv.conf, let user confirm or override
_auto_domain="$(grep -E "^(domain|search)" /etc/resolv.conf 2>/dev/null \
  | head -1 | awk '{print $2}' || true)"

printf '  %s[SYS]%s Network : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
# Pipeline mode: use DOMAIN env var if pre-set, or auto-detect without prompting
if [[ -n "${DOMAIN:-}" ]]; then
  printf '  %s[CHAIN]%s Domain  : %s%s%s  (env)\n' "${CYAN}" "${RESET}" "${GREEN}" "$DOMAIN" "${RESET}"
elif [[ -n "${SESSION_DIR:-}" ]]; then
  DOMAIN="${_auto_domain}"
  printf '  %s[CHAIN]%s Domain  : %s%s%s  (auto-detected)\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "${DOMAIN:-<none>}" "${RESET}"
else
  printf '  %s>>%s Domain (e.g. corp.local)' "${CYAN}" "${RESET}"
  [[ -n "${_auto_domain}" ]] && printf ' %s[detected: %s]%s' "${DIM}" "$_auto_domain" "${RESET}"
  printf ': '
  read -r DOMAIN
  [[ -z "$DOMAIN" ]] && DOMAIN="${_auto_domain}"
fi
printf '  %s[SYS]%s Domain  : %s%s%s\n\n' \
  "${CYAN}" "${RESET}" "${GREEN}" "${DOMAIN:-<not set>}" "${RESET}"

declare -a DNS_SERVERS=()
declare -a DC_HOSTS=()
declare -A DC_PORTS=()

# ── Infrastructure scan (or parse existing nmap.txt) ─────────────────────────
if [[ -n "$_nmap_load" ]]; then
  section "INFRASTRUCTURE SCAN  (from nmap.txt)"
  _nmap_txt="${_nmap_load##*|}"
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
      _p="${BASH_REMATCH[1]}"
      if [[ "$_p" == "53" ]]; then
        _seen=0
        for _h in "${DNS_SERVERS[@]}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
        [[ $_seen -eq 0 ]] && DNS_SERVERS+=("$_cur")
      elif [[ ",$_p," == *",88,"* || ",$_p," == *",389,"* || ",$_p," == *",445,"* || \
              ",$_p," == *",636,"* || ",$_p," == *",3268,"* || ",$_p," == *",3269,"* ]]; then
        _seen=0
        for _h in "${DC_HOSTS[@]}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
        [[ $_seen -eq 0 ]] && DC_HOSTS+=("$_cur")
        DC_PORTS["$_cur"]+="${_p} "
      fi
    fi
  done < "$_nmap_txt"
else
  section "INFRASTRUCTURE SCAN"
  printf '  %s[*]%s Scanning %s for DNS / DC services...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"

  start_spin "nmap running"
  mapfile -t _scan < <(
    nmap -sS -Pn -n -T4 --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
         -p "53,88,389,445,636,3268,3269" --open \
         "$target" 2>/dev/null
  )
  stop_spin

  _cur=""
  for _line in "${_scan[@]}"; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "${_cur}" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
      _p="${BASH_REMATCH[1]}"
      if [[ "$_p" == "53" ]]; then
        _seen=0
        for _h in "${DNS_SERVERS[@]}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
        [[ $_seen -eq 0 ]] && DNS_SERVERS+=("$_cur")
      else
        _seen=0
        for _h in "${DC_HOSTS[@]}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
        [[ $_seen -eq 0 ]] && DC_HOSTS+=("$_cur")
        DC_PORTS["$_cur"]+="${_p} "
      fi
    fi
  done
fi

printf '\n'
if [[ ${#DNS_SERVERS[@]} -gt 0 ]]; then
  printf '  %s[+]%s DNS server(s) : %s%s%s\n' \
    "${GREEN}" "${RESET}" "${CYAN}" "${DNS_SERVERS[*]}" "${RESET}"
else
  printf '  %s[~]%s No DNS servers found on target range%s\n' "${DIM}" "${RESET}" "${RESET}"
fi

if [[ ${#DC_HOSTS[@]} -gt 0 ]]; then
  printf '  %s[+]%s DC candidate(s):\n' "${GREEN}" "${RESET}"
  for _h in "${DC_HOSTS[@]}"; do
    printf '      %s%s%s  %s[ports: %s]%s\n' \
      "${CYAN}" "$_h" "${RESET}" "${DIM}" "${DC_PORTS[$_h]:-}" "${RESET}"
  done
else
  printf '  %s[~]%s No Domain Controller ports (88/389/636/3268) found%s\n' \
    "${DIM}" "${RESET}" "${RESET}"
fi

{ printf '=== DISCOVERY ===\nDNS: %s\nDCs: %s\n\n' \
    "${DNS_SERVERS[*]:-none}" "${DC_HOSTS[*]:-none}"; } >> "$outfile"

# ── Mode selection ────────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  RECON MODE                                      │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  DNS        zone transfer · SRV records · PTR sweep\n' "${CYAN}" "${RESET}"
printf '  %s[02]%s ▶  AD / LDAP  domain enum · users · shares\n'             "${CYAN}" "${RESET}"
printf '  %s[03]%s ▶  Full       both in parallel\n'                          "${GREEN}" "${RESET}"
printf '\n'
if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r _mode
  echo
else
  _mode=3
  printf '  %s[CHAIN]%s Mode: Full (pipeline auto-select)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
fi

RUN_DNS=0 RUN_AD=0
case "${_mode:-3}" in
  1) RUN_DNS=1 ;;
  2) RUN_AD=1 ;;
  *) RUN_DNS=1; RUN_AD=1 ;;
esac

# ── DNS recon ─────────────────────────────────────────────────────────────────
if [[ $RUN_DNS -eq 1 ]]; then
  section "DNS RECON"
  _ns="${DNS_SERVERS[0]:-}"

  _dig() {
    local -a _cmd=(dig +short +time=3 +tries=1)
    [[ -n "$_ns" ]] && _cmd+=("@${_ns}")
    "${_cmd[@]}" "$@" 2>/dev/null || true
  }

  # Zone transfer (sequential — one per NS, output matters)
  if [[ -n "${DOMAIN}" && ${#DNS_SERVERS[@]} -gt 0 ]]; then
    printf '  %s[*]%s Zone transfer — %s\n' "${CYAN}" "${RESET}" "$DOMAIN"
    printf '=== ZONE TRANSFERS ===\n' >> "$outfile"
    for _ns_t in "${DNS_SERVERS[@]}"; do
      printf '      @%s → ' "$_ns_t"
      _axfr=$(dig AXFR "$DOMAIN" @"$_ns_t" +time=8 2>/dev/null || true)
      if echo "$_axfr" | grep -qE "Transfer failed|REFUSED|SERVFAIL|timed out|reset" \
         || [[ -z "$_axfr" ]]; then
        printf '%s[✘] blocked%s\n' "${DIM}" "${RESET}"
        printf 'AXFR @%s: blocked\n' "$_ns_t" >> "$outfile"
      else
        printf '%s[✔] SUCCESS — full zone received!%s\n' "${GREEN}" "${RESET}"
        printf '%s\n' "$_axfr" | tee -a "$outfile"
      fi
    done
    printf '\n'
  fi

  # SRV records — fire all 6 queries in parallel, collect in order
  if [[ -n "${DOMAIN}" ]]; then
    printf '  %s[*]%s SRV records  %s(AD service discovery — parallel)%s\n' \
      "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
    printf '=== SRV ===\n' >> "$outfile"

    _srv_list=(
      "_ldap._tcp"
      "_kerberos._tcp"
      "_gc._tcp"
      "_kpasswd._tcp"
      "_ldap._tcp.dc._msdcs"
      "_kerberos._tcp.dc._msdcs"
    )
    _srv_pids=()
    _srv_files=()
    for _srv in "${_srv_list[@]}"; do
      _f="$outdir/.srv_${_srv//[.\/]/_}.tmp"
      _srv_files+=("$_f")
      _dig SRV "${_srv}.${DOMAIN}" > "$_f" 2>/dev/null &
      _srv_pids+=($!)
    done
    wait "${_srv_pids[@]}" 2>/dev/null || true

    for idx in "${!_srv_list[@]}"; do
      _srv="${_srv_list[$idx]}"
      _f="${_srv_files[$idx]}"
      _r="$(cat "$_f" 2>/dev/null || true)"
      rm -f "$_f"
      if [[ -n "$_r" ]]; then
        printf '  %s[+]%s %-38s %s%s%s\n' \
          "${GREEN}" "${RESET}" "${_srv}" "${CYAN}" "$_r" "${RESET}"
        printf '%s.%s  %s\n' "$_srv" "$DOMAIN" "$_r" >> "$outfile"
      else
        printf '  %s[~]%s %-38s no record%s\n' "${DIM}" "${RESET}" "${_srv}" "${RESET}"
      fi
    done
    printf '\n'
  fi

  # NS / SOA / MX — all 3 in parallel
  if [[ -n "${DOMAIN}" ]]; then
    printf '  %s[*]%s NS / SOA / MX  %s(parallel)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
    printf '=== NS/SOA/MX ===\n' >> "$outfile"

    for _type in NS SOA MX; do
      _dig "$_type" "$DOMAIN" > "$outdir/.dns_${_type}.tmp" 2>/dev/null &
    done
    wait 2>/dev/null || true

    for _type in NS SOA MX; do
      _r="$(cat "$outdir/.dns_${_type}.tmp" 2>/dev/null || true)"
      rm -f "$outdir/.dns_${_type}.tmp"
      if [[ -n "$_r" ]]; then
        printf '  %s[+]%s %-5s %s%s%s\n' "${GREEN}" "${RESET}" "$_type" "${DIM}" "$_r" "${RESET}"
        printf '%s: %s\n' "$_type" "$_r" >> "$outfile"
      fi
    done
    printf '\n'
  fi

  # Reverse PTR sweep — already parallel (cap 30)
  if [[ "$target" == */* ]]; then
    IFS='.' read -r _a _b _c _ <<< "${target%%/*}"
    _pfx="${_a}.${_b}.${_c}"
    printf '  %s[*]%s PTR reverse sweep — %s.1-254  %s(30 parallel jobs)%s\n' \
      "${CYAN}" "${RESET}" "$_pfx" "${DIM}" "${RESET}"
    printf '=== PTR SWEEP ===\n' >> "$outfile"
    _ptrtmp="$outdir/.ptr_tmp"
    : > "$_ptrtmp"
    for i in $(seq 1 254); do
      {
        _r=$(dig +short +time=1 +tries=1 -x "${_pfx}.${i}" \
             ${_ns:+@"$_ns"} 2>/dev/null || true)
        if [[ -n "$_r" ]]; then
          printf '  %s[+]%s %-16s → %s\n' "${GREEN}" "${RESET}" "${_pfx}.${i}" "$_r"
          printf '%s.%d  →  %s\n' "$_pfx" "$i" "$_r" >> "$_ptrtmp"
        fi
      } &
      while (( $(jobs -rp | wc -l) >= 30 )); do sleep 0.05; done
    done
    wait
    cat "$_ptrtmp" >> "$outfile" 2>/dev/null || true
    rm -f "$_ptrtmp"
    printf '\n'
  fi

  # dnsrecon — std only (AXFR already done above via dig)
  if check_tool dnsrecon && [[ -n "${DOMAIN}" ]]; then
    printf '  %s[*]%s dnsrecon standard enumeration\n' "${CYAN}" "${RESET}"
    printf '=== DNSRECON ===\n' >> "$outfile"
    dnsrecon -d "$DOMAIN" -t std ${_ns:+-n "$_ns"} 2>/dev/null \
      | tee -a "$outfile" || true
    printf '\n'
  fi
fi

# ── AD / LDAP enumeration ─────────────────────────────────────────────────────
if [[ $RUN_AD -eq 1 ]]; then
  if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
    printf '\n  %s[!]%s No DCs found — enter one manually (or Enter to skip):\n' \
      "${YELLOW}" "${RESET}"
    printf '  %s>>%s DC IP: ' "${CYAN}" "${RESET}"
    read -r _manual_dc 
    [[ -n "${_manual_dc}" ]] && DC_HOSTS+=("$_manual_dc")
  fi

  # ── Per-DC enumeration — parallel when multiple DCs, capped at 2 ──────────
  _dc_tmpout=()
  _dc_pids=()

  for _dc in "${DC_HOSTS[@]}"; do
    _dctmp="$outdir/.dc_${_dc}.tmp"
    _dc_tmpout+=("$_dctmp")

    {
      printf '=== AD: %s ===\n' "$_dc" >> "$outfile"

      # Anonymous LDAP bind — 10 s hard cap
      if check_tool ldapsearch; then
        _ldap=$(timeout 10 ldapsearch -x -H "ldap://${_dc}" \
                  -b "" -s base namingContexts 2>/dev/null || true)
        if [[ -n "$_ldap" ]]; then
          printf '  %s[✔] Anon LDAP succeeded — %s%s\n' "${GREEN}" "$_dc" "${RESET}"
          printf '%s\n' "$_ldap" >> "$outfile"
          _base=$(echo "$_ldap" | grep -i "DC=" | awk '{print $2}' | head -1)
          if [[ -n "$_base" ]]; then
            printf '  %s[*]%s Dumping accounts from %s...%s\n' \
              "${CYAN}" "${RESET}" "$_base" "${RESET}"
            timeout 20 ldapsearch -x -H "ldap://${_dc}" -b "$_base" \
              "(objectClass=user)" sAMAccountName 2>/dev/null \
              | grep "^sAMAccountName:" | tee -a "$outfile" | head -40 || true
          fi
        else
          printf '  %s[~]%s Anon LDAP rejected — %s%s\n' "${DIM}" "${RESET}" "$_dc" "${RESET}"
        fi
      fi

      # enum4linux-ng: -T 15 = 15 s per-request timeout; hard cap 180 s total
      if check_tool enum4linux-ng; then
        printf '\n  %s[*]%s enum4linux-ng -A -T 15 %s  %s(3 min cap)%s\n' \
          "${CYAN}" "${RESET}" "$_dc" "${DIM}" "${RESET}"
        timeout 180 enum4linux-ng -A -T 15 "$_dc" 2>/dev/null \
          | tee -a "$outfile" || true
      elif check_tool enum4linux; then
        printf '\n  %s[*]%s enum4linux -a %s  %s(3 min cap)%s\n' \
          "${CYAN}" "${RESET}" "$_dc" "${DIM}" "${RESET}"
        timeout 180 enum4linux -a "$_dc" 2>/dev/null \
          | tee -a "$outfile" || true
      fi

      # Password policy via crackmapexec
      if check_tool crackmapexec; then
        printf '\n  %s[*]%s Password policy — %s%s\n' "${CYAN}" "${RESET}" "$_dc" "${RESET}"
        timeout 30 crackmapexec smb "$_dc" -u '' -p '' --pass-pol 2>/dev/null \
          | tee -a "$outfile" || true
      fi

    } > "$_dctmp" 2>&1 &

    _dc_pids+=($!)
    # Cap at 2 concurrent DC enumerations
    while (( $(jobs -rp | wc -l) >= 2 )); do sleep 1; done
  done

  # Wait and print DC results in submission order
  for i in "${!_dc_pids[@]}"; do
    _dc="${DC_HOSTS[$i]}"
    section "AD ENUM — $_dc"
    wait "${_dc_pids[$i]}" 2>/dev/null || true
    if [[ -f "${_dc_tmpout[$i]}" ]]; then
      cat "${_dc_tmpout[$i]}"
      rm -f "${_dc_tmpout[$i]}"
    fi
  done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  RESULTS                                         │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[SYS]%s DNS servers : %s%d%s\n' "${CYAN}" "${RESET}" "${DIM}" "${#DNS_SERVERS[@]}" "${RESET}"
printf '  %s[SYS]%s DCs found   : %s%d%s\n' "${CYAN}" "${RESET}" "${DIM}" "${#DC_HOSTS[@]}"    "${RESET}"

_axfr_ok=$(grep -c "\[✔\].*zone" "$outfile" 2>/dev/null || echo 0)
[[ "$_axfr_ok" -gt 0 ]] && \
  printf '  %s[✔] Zone transfer succeeded — full DNS zone captured!%s\n' "${GREEN}" "${RESET}"

_ldap_ok=$(grep -c "Anon LDAP succeeded" "$outfile" 2>/dev/null || echo 0)
[[ "$_ldap_ok" -gt 0 ]] && \
  printf '  %s[✔] Anonymous LDAP — accounts enumerated!%s\n' "${GREEN}" "${RESET}"

printf '\n  %s[SYS]%s Report  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish discovered DCs and domain ─────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  if [[ ${#DC_HOSTS[@]} -gt 0 ]]; then
    printf '%s\n' "${DC_HOSTS[@]}" > "${SESSION_DIR}/chain_dc.txt" 2>/dev/null || true
    # Also add DCs to alive_hosts and chain_ports (88/Kerberos, 389/LDAP, 445/SMB)
    printf '%s\n' "${DC_HOSTS[@]}" >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
    sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
    for _dc_h in "${DC_HOSTS[@]}"; do
      printf '%s:88\n%s:389\n%s:445\n' "$_dc_h" "$_dc_h" "$_dc_h" >> "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
    done
    sort -u "${SESSION_DIR}/chain_ports.txt" -o "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
    printf '  %s[CHAIN]%s chain_dc.txt + chain_ports.txt: %d DC(s) published%s\n' \
      "${CYAN}" "${RESET}" "${#DC_HOSTS[@]}" "${RESET}"
  fi
  if [[ -n "${DOMAIN:-}" ]]; then
    printf '%s\n' "$DOMAIN" > "${SESSION_DIR}/chain_domain.txt" 2>/dev/null || true
    printf '  %s[CHAIN]%s chain_domain.txt: %s published%s\n' \
      "${CYAN}" "${RESET}" "$DOMAIN" "${RESET}"
  fi
fi

mark_done "$outfile"
