#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "ENUM4LINUX" "SMB · NetBIOS · LDAP · RPC · share enum · user listing · policy dump"

# ── Tool detection ─────────────────────────────────────────────────────────────
section "DEPENDENCIES"

_E4L=""
if   command -v enum4linux-ng &>/dev/null; then _E4L="enum4linux-ng"
elif command -v enum4linux    &>/dev/null; then _E4L="enum4linux"
fi

if [[ -z "$_E4L" ]]; then
  printf '  %s[!]%s enum4linux-ng / enum4linux not found\n' "${RED}" "${RESET}"
  printf '      Install: %sapt install enum4linux-ng%s  or  %sapt install enum4linux%s\n' \
    "${CYAN}" "${RESET}" "${CYAN}" "${RESET}"
  exit 1
fi

printf '  %s[✓]%s %s\n\n' "${GREEN}" "${RESET}" "$_E4L"

# ── Optional: nmblookup / smbclient for extras ─────────────────────────────────
command -v nmblookup &>/dev/null && printf '  %s[✓]%s nmblookup\n' "${GREEN}" "${RESET}"
command -v smbclient &>/dev/null && printf '  %s[✓]%s smbclient\n' "${GREEN}" "${RESET}"
printf '\n'

# ── Target ─────────────────────────────────────────────────────────────────────
section "TARGET"

if [[ -n "${SESSION_DIR:-}" && -n "${TARGET:-}" ]]; then
  # Build host list: alive_hosts.txt if available, else single IP from TARGET
  if [[ -s "${SESSION_DIR}/alive_hosts.txt" ]]; then
    mapfile -t _pipeline_hosts < "${SESSION_DIR}/alive_hosts.txt"
    printf '  %s[CHAIN]%s Multi-host: %s host(s) from alive_hosts.txt  (pipeline auto)%s\n\n' \
      "${CYAN}" "${RESET}" "${#_pipeline_hosts[@]}" "${RESET}"
  else
    _pipeline_hosts=("${TARGET%%/*}")
    printf '  %s[CHAIN]%s Target: %s  Auth: null session  Scope: Full  (pipeline auto)%s\n\n' \
      "${CYAN}" "${RESET}" "${TARGET%%/*}" "${RESET}"
  fi
  _host="${_pipeline_hosts[0]}"  # will iterate below
  _user=""; _pass=""; _domain="WORKGROUP"; _scope=1
else
  printf '  %s>>%s Target IP / hostname: ' "${CYAN}" "${RESET}"
  read -r _host; _host="${_host:-}"
  [[ -z "$_host" ]] && { printf '  %s[!]%s No target\n' "${RED}" "${RESET}"; exit 1; }
  printf '  %s>>%s Username %s(blank = null session)%s: ' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  read -r _user
  set +H
  printf '  %s>>%s Password %s(blank = empty)%s: '        "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  read -r _pass
  set -H 2>/dev/null || true
  printf '  %s>>%s Domain   %s(blank = WORKGROUP)%s: '    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  read -r _domain; _domain="${_domain:-WORKGROUP}"
  section "SCAN SCOPE"
  printf '  %s[01]%s Full     — all checks (users · shares · groups · policies · RID cycle)\n' "${CYAN}" "${RESET}"
  printf '  %s[02]%s Users    — user enumeration only\n'   "${CYAN}" "${RESET}"
  printf '  %s[03]%s Shares   — share listing only\n'      "${CYAN}" "${RESET}"
  printf '  %s[04]%s Groups   — group membership only\n'   "${CYAN}" "${RESET}"
  printf '  %s[05]%s Password policy\n'                     "${CYAN}" "${RESET}"
  printf '\n  %s>>%s Scope [1]: ' "${CYAN}" "${RESET}"
  read -r _scope; _scope="${_scope:-1}"
fi

outdir="$(make_outdir)"
outfile="$outdir/enum4linux.log"
: > "$outfile"

_cleanup() { mark_done "$outdir"; }
trap '_cleanup' EXIT

printf '  %s[SYS]%s Auth   : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" \
  "${_user:-<null>}${_user:+:***}@${_domain}" "${RESET}"
printf '  %s[SYS]%s Log    : %s%s%s\n\n'  "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# Build host iteration list: _pipeline_hosts set in pipeline mode, single host otherwise
_scan_hosts=()
if [[ -n "${_pipeline_hosts[*]+set}" ]] && [[ ${#_pipeline_hosts[@]} -gt 0 ]]; then
  _scan_hosts=("${_pipeline_hosts[@]}")
else
  _scan_hosts=("$_host")
fi

# ── Scan each host ─────────────────────────────────────────────────────────────
for _cur_host in "${_scan_hosts[@]}"; do
  section "SCANNING  $_cur_host"
  printf '  %s[SYS]%s Target : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$_cur_host" "${RESET}"

  if [[ "$_E4L" == "enum4linux-ng" ]]; then
    declare -a _args=()
    [[ -n "$_user" ]] && _args+=(-u "$_user")
    [[ -n "$_pass" ]] && _args+=(-p "$_pass")
    [[ -n "$_domain" && "$_domain" != "WORKGROUP" ]] && _args+=(-d "$_domain")
    case "$_scope" in
      2) _args+=(-U) ;;
      3) _args+=(-S) ;;
      4) _args+=(-G) ;;
      5) _args+=(-P) ;;
      *) _args+=(-A) ;;
    esac
    _json="$outdir/enum4linux_${_cur_host}.json"
    _args+=(-oJ "$_json")
    run_fg enum4linux-ng "${_args[@]}" "$_cur_host" 2>&1 | tee -a "$outfile" || true
  else
    declare -a _args=()
    [[ -n "$_user" && -n "$_pass" ]] && _args+=(-u "$_user" -p "$_pass")
    case "$_scope" in
      2) _args+=(-U) ;;
      3) _args+=(-S) ;;
      4) _args+=(-G) ;;
      5) _args+=(-P) ;;
      *) _args+=(-a) ;;
    esac
    run_fg enum4linux "${_args[@]}" "$_cur_host" 2>&1 | tee -a "$outfile" || true
  fi
done

# ── Quick summary ──────────────────────────────────────────────────────────────
section "SUMMARY"

_users=$(grep -cEi '^\s*(user:|username:|Account)' "$outfile" 2>/dev/null || echo 0)
_shares=$(grep -c 'Disk\|IPC\$\|ADMIN\$\|\bprint\b' "$outfile" 2>/dev/null || echo 0)
printf '  %s[*]%s Users found  : %s%d%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_users"  "${RESET}"
printf '  %s[*]%s Share lines  : %s%d%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_shares" "${RESET}"

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish discovered users to chain_users.txt ───────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outfile" ]]; then
  # Extract usernames from enum4linux output formats
  grep -oiE '^\s*user:\[([^\]]+)\]' "$outfile" 2>/dev/null \
    | sed 's/.*\[//;s/\]//' | grep -v '^$\|^None$' \
    >> "${SESSION_DIR}/chain_users.txt" 2>/dev/null || true
  grep -oiE 'username: ([a-zA-Z0-9._-]+)' "$outfile" 2>/dev/null \
    | awk '{print $2}' \
    >> "${SESSION_DIR}/chain_users.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_users.txt" -o "${SESSION_DIR}/chain_users.txt" 2>/dev/null || true
  _uc=$(wc -l < "${SESSION_DIR}/chain_users.txt" 2>/dev/null || echo 0)
  [[ "$_uc" -gt 0 ]] && printf '  %s[CHAIN]%s chain_users.txt: %s user(s) published for kerberos%s\n\n' \
    "${CYAN}" "${RESET}" "$_uc" "${RESET}"
fi
