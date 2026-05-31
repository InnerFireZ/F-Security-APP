#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "theHARVESTER" "OSINT — emails · subdomains · IPs · URLs · employees"

# ── Dependency ─────────────────────────────────────────────────────────────────
section "DEPENDENCIES"

_HARV=""
if   command -v theHarvester    &>/dev/null; then _HARV="theHarvester"
elif command -v theharvester    &>/dev/null; then _HARV="theharvester"
elif command -v theHarvester.py &>/dev/null; then _HARV="theHarvester.py"
fi

if [[ -z "$_HARV" ]]; then
  printf '  %s[!]%s theHarvester not found\n' "${RED}" "${RESET}"
  printf '      Install: %sapt install theharvester%s  or  %spip3 install theHarvester%s\n' \
    "${CYAN}" "${RESET}" "${CYAN}" "${RESET}"
  exit 1
fi

printf '  %s[✓]%s %s\n\n' "${GREEN}" "${RESET}" "$_HARV"

# ── Target ─────────────────────────────────────────────────────────────────────
section "TARGET"

if [[ -n "${SESSION_DIR:-}" && -n "${TARGET:-}" ]]; then
  # Pipeline: derive domain from TARGET (strip CIDR, use as-is if already a domain)
  _domain="${TARGET%%/*}"
  # If it looks like an IP, can't auto-harvest — skip gracefully
  if [[ "$_domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf '  %s[CHAIN]%s TARGET is an IP — theHarvester needs a domain. Skipping.%s\n' \
      "${CYAN}" "${RESET}" "${RESET}"
    exit 0
  fi
  printf '  %s[CHAIN]%s Domain: %s%s%s  (from TARGET env)\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$_domain" "${RESET}"
  _SOURCES="crtsh,certspotter,dnsdumpster,hackertarget"
  _limit=200
  printf '  %s[CHAIN]%s Sources: %s  Limit: %d  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "$_SOURCES" "$_limit" "${RESET}"
else
  printf '  %s>>%s Domain (e.g. example.com): ' "${CYAN}" "${RESET}"
  read -r _domain; _domain="${_domain:-}"
  [[ -z "$_domain" ]] && { printf '  %s[!]%s No domain\n' "${RED}" "${RESET}"; exit 1; }

  section "SOURCES"
  printf '  %s[01]%s All available sources             %s(comprehensive, slow)%s\n'    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s Passive DNS only                  %s(dnsdumpster, hackertarget)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[03]%s Search engines                    %s(bing, baidu, duckduckgo)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[04]%s Certificate transparency          %s(crtsh, certspotter)%s\n'     "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[05]%s Custom (type source list)\n'                                        "${CYAN}" "${RESET}"
  printf '\n  %s>>%s Source profile [1]: ' "${CYAN}" "${RESET}"
  read -r _src_profile; _src_profile="${_src_profile:-1}"
  case "$_src_profile" in
    2) _SOURCES="dnsdumpster,hackertarget,rapiddns" ;;
    3) _SOURCES="bing,baidu,duckduckgo" ;;
    4) _SOURCES="crtsh,certspotter" ;;
    5)
      printf '  %s>>%s Sources (comma-sep, e.g. bing,dnsdumpster,crtsh): ' "${CYAN}" "${RESET}"
      read -r _SOURCES
      ;;
    *) _SOURCES="all" ;;
  esac
  printf '  %s>>%s Result limit [500]: ' "${CYAN}" "${RESET}"
  read -r _limit; _limit="${_limit:-500}"
fi

outdir="$(make_outdir)"
outfile="$outdir/harvester.log"
_xml="$outdir/harvester.xml"
: > "$outfile"

_cleanup() { mark_done "$outdir"; }
trap '_cleanup' EXIT

printf '\n  %s[SYS]%s Domain  : %s%s%s\n'   "${CYAN}" "${RESET}" "${GREEN}" "$_domain"   "${RESET}"
printf '  %s[SYS]%s Sources : %s%s%s\n'     "${CYAN}" "${RESET}" "${CYAN}"  "$_SOURCES"  "${RESET}"
printf '  %s[SYS]%s Limit   : %s%s%s\n'     "${CYAN}" "${RESET}" "${DIM}"   "$_limit"    "${RESET}"
printf '  %s[SYS]%s Log     : %s%s%s\n\n'   "${CYAN}" "${RESET}" "${DIM}"   "$outfile"   "${RESET}"

section "HARVESTING"

declare -a _args=(
  -d "$_domain"
  -b "$_SOURCES"
  -l "$_limit"
  -f "$_xml"
)

run_fg "$_HARV" "${_args[@]}" 2>&1 | tee -a "$outfile" || true

# ── Summary ─────────────────────────────────────────────────────────────────────
section "SUMMARY"

_emails=$(grep -cE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$outfile" 2>/dev/null || echo 0)
_hosts=$(grep -cE '([a-z0-9-]+\.)+[a-z]{2,}' "$outfile" 2>/dev/null || echo 0)
_ips=$(grep -cE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$outfile" 2>/dev/null || echo 0)

printf '  %s[*]%s Emails     : %s%d%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_emails" "${RESET}"
printf '  %s[*]%s Host lines : %s%d%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_hosts"  "${RESET}"
printf '  %s[*]%s IP lines   : %s%d%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_ips"    "${RESET}"

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish hosts/subdomains → chain_web_urls.txt ─────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outfile" ]]; then
  grep -oE '([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' "$outfile" 2>/dev/null \
    | grep -v '@' | sort -u \
    | while IFS= read -r _h; do
        printf 'http://%s\nhttps://%s\n' "$_h" "$_h"
      done >> "${SESSION_DIR}/chain_web_urls.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_web_urls.txt" -o "${SESSION_DIR}/chain_web_urls.txt" 2>/dev/null || true
  _wu=$(wc -l < "${SESSION_DIR}/chain_web_urls.txt" 2>/dev/null || echo 0)
  [[ "$_wu" -gt 0 ]] && printf '  %s[CHAIN]%s chain_web_urls.txt: %s URL(s) from harvester%s\n\n' \
    "${CYAN}" "${RESET}" "$_wu" "${RESET}"
fi
