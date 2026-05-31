#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "LDAP DUMP" "ldapdomaindump · AD structure · users · groups · computers · GPO"

# ── Tool detection ─────────────────────────────────────────────────────────────
section "DEPENDENCIES"

_LDD=""; _LSEARCH=""
for _n in ldapdomaindump ldapdomaindump3; do
  command -v "$_n" &>/dev/null && { _LDD="$_n"; break; }
done
command -v ldapsearch &>/dev/null && _LSEARCH="ldapsearch"

[[ -n "$_LDD"     ]] && \
  printf '  %s[✓]%s %-18s available\n' "${GREEN}" "${RESET}" "ldapdomaindump" || \
  printf '  %s[~]%s %-18s not found  (pip install ldapdomaindump)\n' "${YELLOW}" "${RESET}" "ldapdomaindump"
[[ -n "$_LSEARCH" ]] && \
  printf '  %s[✓]%s %-18s available\n' "${GREEN}" "${RESET}" "ldapsearch" || \
  printf '  %s[~]%s %-18s not found  (apt install ldap-utils)\n' "${YELLOW}" "${RESET}" "ldapsearch"

if [[ -z "$_LDD" && -z "$_LSEARCH" ]]; then
  printf '\n  %s[!]%s No LDAP tools found.\n' "${RED}" "${RESET}"
  exit 1
fi

outdir="$(make_outdir)"
outfile="$outdir/ldap_dump.log"
: > "$outfile"

# ── Target ─────────────────────────────────────────────────────────────────────
section "TARGET"

if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline: auto-derive DC from chain_dc.txt (written by dns_ad.sh) or TARGET
  _dc=""
  [[ -s "${SESSION_DIR}/chain_dc.txt" ]] && _dc=$(head -1 "${SESSION_DIR}/chain_dc.txt")
  [[ -z "$_dc" ]] && _dc="${TARGET%%/*}"
  # Auto-derive domain from chain_domain.txt or DOMAIN env
  _domain="${DOMAIN:-}"
  [[ -z "$_domain" && -s "${SESSION_DIR}/chain_domain.txt" ]] && _domain=$(head -1 "${SESSION_DIR}/chain_domain.txt")
  [[ -z "$_domain" ]] && _domain="$(grep -E '^(domain|search)' /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}' || true)"
  _user=""; _pass=""
  # Check chain_creds.txt for credentials
  if [[ -s "${SESSION_DIR}/chain_creds.txt" ]]; then
    _cline=$(grep -m1 'login:.*password:' "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true)
    [[ -n "$_cline" ]] && _user=$(echo "$_cline" | grep -oP 'login:\s*\K\S+' || true)
    [[ -n "$_cline" ]] && _pass=$(echo "$_cline" | grep -oP 'password:\s*\K\S+' || true)
  fi
  printf '  %s[CHAIN]%s DC: %s  Domain: %s  Auth: %s  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "${_dc}" "${_domain:-<auto>}" "${_user:-anon}" "${RESET}"
  _mode=1  # ldapdomaindump full dump
else
  printf '  %s>>%s DC / LDAP host (IP or FQDN): '     "${CYAN}" "${RESET}"; read -r _dc
  printf '  %s>>%s Domain (e.g. corp.local): '         "${CYAN}" "${RESET}"; read -r _domain
  printf '  %s>>%s Username %s(blank = anon)%s: '      "${CYAN}" "${RESET}" "${DIM}" "${RESET}"; read -r _user
  printf '  %s>>%s Password %s(blank = anon)%s: '      "${CYAN}" "${RESET}" "${DIM}" "${RESET}"; read -r -s _pass; printf '\n'
  section "SCAN MODE"
  printf '\n'
  [[ -n "$_LDD"     ]] && printf '  %s[01]%s ldapdomaindump  — full AD dump (HTML + JSON + grep-able)\n' "${CYAN}" "${RESET}"
  [[ -n "$_LSEARCH" ]] && printf '  %s[02]%s ldapsearch      — raw LDAP anonymous enum\n'                "${CYAN}" "${RESET}"
  [[ -n "$_LSEARCH" ]] && printf '  %s[03]%s ldapsearch      — users with SPN (Kerberoastable)\n'       "${CYAN}" "${RESET}"
  [[ -n "$_LSEARCH" ]] && printf '  %s[04]%s ldapsearch      — AS-REP roastable users\n'                "${CYAN}" "${RESET}"
  printf '\n  %s>>%s Mode [1]: ' "${CYAN}" "${RESET}"
  read -r _mode; _mode="${_mode:-1}"
fi

[[ -z "$_dc"     ]] && { printf '  %s[!]%s DC host required\n' "${RED}" "${RESET}"; exit 1; }
[[ -z "$_domain" ]] && { printf '  %s[!]%s Domain required\n' "${RED}" "${RESET}"; exit 1; }

# Build LDAP base DN from domain
_base="DC=$(echo "$_domain" | sed 's/\./,DC=/g')"

printf '\n  %s[*]%s Target : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_dc" "${RESET}"
printf '  %s[*]%s Domain : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_domain" "${RESET}"
printf '  %s[*]%s Base DN: %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_base" "${RESET}"

# ── Auth helpers ───────────────────────────────────────────────────────────────
_auth_args() {
  if [[ -n "$_user" && -n "$_pass" ]]; then
    printf -- '-u %s\\%s -p %s' "$_domain" "$_user" "$_pass"
  else
    printf -- ''
  fi
}

case "$_mode" in

# ── ldapdomaindump ─────────────────────────────────────────────────────────────
1)
  [[ -z "$_LDD" ]] && { printf '  %s[!]%s ldapdomaindump not found\n' "${RED}" "${RESET}"; exit 1; }

  _ldd_args=(-d "$_domain" -l "$_dc" -o "$outdir")
  [[ -n "$_user" ]] && _ldd_args+=(-u "${_domain}\\${_user}" -p "$_pass")

  printf '  %s[*]%s Dumping AD structure...\n\n' "${CYAN}" "${RESET}"
  run_fg "$_LDD" "${_ldd_args[@]}" 2>&1 | tee -a "$outfile" || true

  printf '\n  %s[✔]%s Reports saved to %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"
  printf '  %s[*]%s Files: domain_users.html  domain_groups.html  domain_computers.html\n\n' "${CYAN}" "${RESET}"
  ;;

# ── ldapsearch anonymous ───────────────────────────────────────────────────────
2)
  [[ -z "$_LSEARCH" ]] && { printf '  %s[!]%s ldapsearch not found\n' "${RED}" "${RESET}"; exit 1; }

  _lsargs=(-x -H "ldap://${_dc}" -b "$_base")
  [[ -n "$_user" ]] && _lsargs+=(-D "${_user}@${_domain}" -w "$_pass") || _lsargs+=(-LLL)

  printf '  %s[*]%s Enumerating users, groups, computers...\n\n' "${CYAN}" "${RESET}"
  for _filter in \
    "(objectClass=person)(sAMAccountName=*)" \
    "(objectClass=group)" \
    "(objectClass=computer)"; do
    printf '  %s[*]%s Filter: %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_filter" "${RESET}"
    run_fg ldapsearch "${_lsargs[@]}" "(&${_filter})" sAMAccountName displayName memberOf \
      2>&1 | tee -a "$outfile" || true
    printf '\n'
  done
  ;;

# ── SPN users (Kerberoastable) ─────────────────────────────────────────────────
3)
  [[ -z "$_LSEARCH" ]] && { printf '  %s[!]%s ldapsearch not found\n' "${RED}" "${RESET}"; exit 1; }

  _lsargs=(-x -H "ldap://${_dc}" -b "$_base")
  [[ -n "$_user" ]] && _lsargs+=(-D "${_user}@${_domain}" -w "$_pass")

  printf '  %s[*]%s Finding Kerberoastable accounts (servicePrincipalName set)...\n\n' "${CYAN}" "${RESET}"
  run_fg ldapsearch "${_lsargs[@]}" \
    "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))" \
    sAMAccountName servicePrincipalName 2>&1 | tee -a "$outfile" || true
  ;;

# ── AS-REP roastable ──────────────────────────────────────────────────────────
4)
  [[ -z "$_LSEARCH" ]] && { printf '  %s[!]%s ldapsearch not found\n' "${RED}" "${RESET}"; exit 1; }

  _lsargs=(-x -H "ldap://${_dc}" -b "$_base")
  [[ -n "$_user" ]] && _lsargs+=(-D "${_user}@${_domain}" -w "$_pass")

  printf '  %s[*]%s Finding AS-REP roastable accounts (no pre-auth required)...\n\n' "${CYAN}" "${RESET}"
  run_fg ldapsearch "${_lsargs[@]}" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113549.1.1.1:=4194304))" \
    sAMAccountName userAccountControl 2>&1 | tee -a "$outfile" || true
  ;;

*)
  printf '  %s[!]%s Invalid mode\n' "${RED}" "${RESET}"
  ;;
esac

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish AD users to chain_users.txt ──────────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outfile" ]]; then
  # Extract from ldapsearch output (sAMAccountName)
  grep -oiE 'sAMAccountName: ([a-zA-Z0-9._-]+)' "$outfile" 2>/dev/null \
    | awk '{print $2}' | grep -vEi '^\$|^krbtgt$|computer' \
    >> "${SESSION_DIR}/chain_users.txt" 2>/dev/null || true
  # Extract from ldapdomaindump JSON if present
  for _uf in "$outdir"/domain_users*.json "$outdir"/domain_users*.grep; do
    [[ -f "$_uf" ]] || continue
    grep -oiE '"sAMAccountName":\s*"([^"]+)"' "$_uf" 2>/dev/null \
      | sed 's/.*"//;s/"//' >> "${SESSION_DIR}/chain_users.txt" 2>/dev/null || true
  done
  sort -u "${SESSION_DIR}/chain_users.txt" -o "${SESSION_DIR}/chain_users.txt" 2>/dev/null || true
  _uc=$(wc -l < "${SESSION_DIR}/chain_users.txt" 2>/dev/null || echo 0)
  [[ "$_uc" -gt 0 ]] && printf '  %s[CHAIN]%s chain_users.txt: %s AD user(s) published for kerberos/brute%s\n\n' \
    "${CYAN}" "${RESET}" "$_uc" "${RESET}"
fi

mark_done "$outdir"
