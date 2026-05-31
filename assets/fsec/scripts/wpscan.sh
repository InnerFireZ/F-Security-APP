#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "WPSCAN" "WordPress vulnerability scanner · user enum · plugin audit"

require_tool wpscan "gem install wpscan  OR  apt install wpscan"

outdir="$(make_outdir)"
outfile="$outdir/wpscan.log"
: > "$outfile"

# ── Target ─────────────────────────────────────────────────────────────────────
section "TARGET"

_token=""
if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline: prefer chain_web_urls.txt (actual discovered web URLs), then chain_ports.txt
  _url=""
  if [[ -s "${SESSION_DIR}/chain_web_urls.txt" ]]; then
    _url=$(head -1 "${SESSION_DIR}/chain_web_urls.txt")
    printf '  %s[CHAIN]%s URL from chain_web_urls.txt: %s%s\n' "${CYAN}" "${RESET}" "$_url" "${RESET}"
  elif [[ -s "${SESSION_DIR}/chain_ports.txt" ]]; then
    while IFS=: read -r _cp_ip _cp_port; do
      case "$_cp_port" in
        443|8443) _url="https://$_cp_ip"; break ;;
        80|8080)  _url="http://$_cp_ip";  break ;;
      esac
    done < "${SESSION_DIR}/chain_ports.txt"
  fi
  [[ -z "$_url" ]] && _url="http://${TARGET%%/*}"
  _prof=2  # Aggressive: full plugin/theme check
  printf '  %s[CHAIN]%s URL: %s  Profile: Aggressive  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "$_url" "${RESET}"
else
  printf '  %s>>%s WordPress URL (http://target/wp): ' "${CYAN}" "${RESET}"
  read -r _url
  [[ -z "$_url" ]] && { printf '  %s[!]%s URL required\n' "${RED}" "${RESET}"; exit 1; }
  printf '  %s>>%s WPScan API token %s(blank = no CVE data)%s: ' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  read -r -s _token; printf '\n'
  section "PROFILE"
  printf '\n'
  printf '  %s[01]%s Passive      — fast, non-aggressive (default)\n'    "${CYAN}" "${RESET}"
  printf '  %s[02]%s Aggressive   — full plugin/theme check\n'           "${CYAN}" "${RESET}"
  printf '  %s[03]%s User enum    — enumerate WordPress users\n'         "${CYAN}" "${RESET}"
  printf '  %s[04]%s Full         — aggressive + users + passwords\n'    "${CYAN}" "${RESET}"
  printf '\n  %s>>%s Profile [1]: ' "${CYAN}" "${RESET}"
  read -r _prof; _prof="${_prof:-1}"
fi

_args=(--url "$_url" --no-banner --random-user-agent)
[[ -n "$_token" ]] && _args+=(--api-token "$_token")

case "$_prof" in
  1)
    _args+=(--enumerate p,t,u --plugins-detection passive)
    ;;
  2)
    _args+=(--enumerate ap,at,u --plugins-detection aggressive --themes-detection aggressive)
    ;;
  3)
    _args+=(--enumerate u --max-threads 5)
    ;;
  4)
    printf '  %s>>%s Password wordlist %s(blank = skip)%s: ' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
    read -r _pwlist
    _args+=(--enumerate ap,at,u --plugins-detection aggressive)
    if [[ -n "$_pwlist" && -f "$_pwlist" ]]; then
      printf '  %s>>%s Username for password spray: ' "${CYAN}" "${RESET}"; read -r _user
      [[ -n "$_user" ]] && _args+=(--usernames "$_user" --passwords "$_pwlist")
    fi
    ;;
  *)
    _args+=(--enumerate p,t,u)
    ;;
esac

printf '\n  %s[*]%s WPScan → %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_url" "${RESET}"
[[ -z "$_token" ]] && printf '  %s[~]%s No API token — CVE vulnerability data disabled%s\n\n' "${YELLOW}" "${RESET}" "${RESET}" \
                  || printf '  %s[*]%s API token set — CVE data enabled%s\n\n' "${CYAN}" "${RESET}" "${RESET}"

run_fg wpscan "${_args[@]}" 2>&1 | tee -a "$outfile" || true

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
mark_done "$outdir"
