#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

WEB_PORTS="80,81,82,443,8000,8001,8008,8080,8081,8443,8888,9090,9443"
HTTPS_PORTS=(443 8443 9443)

# Wordlist — prefer $WORDLIST from settings, then common fallback paths
_WORDLIST="${WORDLIST:-}"
if [[ -z "$_WORDLIST" || ! -f "$_WORDLIST" ]]; then
  for _wl in \
    /usr/share/wordlists/dirb/common.txt \
    /usr/share/dirb/wordlists/common.txt \
    /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
    /usr/share/wordlists/rockyou.txt; do
    [[ -f "$_wl" ]] && { _WORDLIST="$_wl"; break; }
  done
fi

banner "WEB RECON" "whatweb · feroxbuster / gobuster / dirb"

target=$(prompt_target)

# Pipeline mode: wait up to 30s for karma on_client nmap.txt before falling back to own scan
if [[ -n "${SESSION_DIR:-}" ]] && [[ ! -f "${SESSION_DIR}/nmap.txt" ]]; then
  for _w in $(seq 1 30); do
    sleep 1
    [[ -f "${SESSION_DIR}/nmap.txt" ]] && break
  done
fi

# ── Existing nmap.txt? ────────────────────────────────────────────────────────
_nmap_load="$(pick_nmap_file)"

# ── Phase 0: find live hosts with open web ports ──────────────────────────────
_discover_web() {
  require_tool nmap
  local _tmp
  _tmp=$(mktemp /tmp/.fsec_web_nmap.XXXXXX)

  printf '  %s[*]%s Scanning for live web ports on %s%s%s (this may take 1-3 min)...%s\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}" "${RESET}" >&2

  # Stream nmap to a temp file so output is visible as it progresses
  nmap -sS -Pn -n -p "$WEB_PORTS" --open -T4 \
    --max-retries 2 --max-scan-delay 10ms --min-rate 300 "$target" \
    > "$_tmp" 2>&1 &
  local _nmap_pid=$!

  # Spinner on stderr so user sees progress
  local _spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local _si=0
  while kill -0 "$_nmap_pid" 2>/dev/null; do
    printf '\r  %s[%s]%s scanning...' "${DIM}" "${_spin:$(( _si % ${#_spin} )):1}" "${RESET}" >&2
    (( _si++ ))
    sleep 0.15
  done
  printf '\r  %s[✔]%s nmap done.                \n' "${GREEN}" "${RESET}" >&2
  wait "$_nmap_pid"

  if grep -qE "netlink|Permission denied" "$_tmp"; then
    printf '  %s[!] nmap error: %s%s\n' "${RED}" \
      "$(grep -E 'netlink|Permission' "$_tmp" | head -1)" "${RESET}" >&2
    rm -f "$_tmp"
    return 1
  fi

  local ip=""
  while IFS= read -r line; do
    if [[ "$line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      ip="${BASH_REMATCH[1]}"
    elif [[ -n "$ip" && "$line" =~ ^([0-9]+)/tcp.*open ]]; then
      local port="${BASH_REMATCH[1]}" scheme="http"
      for p in "${HTTPS_PORTS[@]}"; do [[ "$port" == "$p" ]] && scheme="https" && break; done
      echo "${scheme}://${ip}:${port}"
    fi
  done < "$_tmp"
  rm -f "$_tmp"
}

# Parse web URLs from an existing nmap.txt
_web_from_nmap() {
  local nfile="$1" ip="" port scheme
  while IFS= read -r line; do
    if [[ "$line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      ip="${BASH_REMATCH[1]}"
    elif [[ -n "$ip" && "$line" =~ ^([0-9]+)/tcp.*open ]]; then
      port="${BASH_REMATCH[1]}"
      if [[ ",$WEB_PORTS," == *",${port},"* ]]; then
        scheme="http"
        for p in "${HTTPS_PORTS[@]}"; do [[ "$port" == "$p" ]] && scheme="https" && break; done
        echo "${scheme}://${ip}:${port}"
      fi
    fi
  done < "$nfile"
}

if [[ -n "$_nmap_load" ]]; then
  outdir="${_nmap_load%%|*}"
  _nmap_txt="${_nmap_load##*|}"
  mapfile -t URLS < <(_web_from_nmap "$_nmap_txt")
else
  outdir=$(make_outdir)
  mapfile -t URLS < <(_discover_web)
fi

printf '  %s[SYS]%s Target   : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output   : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"
printf '  %s[SYS]%s Wordlist : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "${_WORDLIST:-not found}" "${RESET}"

# Pipeline chain: load URLs from chain_web_urls.txt if available
if [[ -n "${SESSION_DIR:-}" ]] && [[ ${#URLS[@]} -eq 0 ]] && [[ -s "${SESSION_DIR}/chain_web_urls.txt" ]]; then
  mapfile -t URLS < "${SESSION_DIR}/chain_web_urls.txt"
  printf '  %s[CHAIN]%s Loaded %d URL(s) from chain_web_urls.txt%s\n\n' \
    "${CYAN}" "${RESET}" "${#URLS[@]}" "${RESET}"
fi

if [[ ${#URLS[@]} -eq 0 ]]; then
  printf '  %s[!] No live hosts with open web ports found.%s\n' "${YELLOW}" "${RESET}"
  if [[ -n "${SESSION_DIR:-}" ]]; then
    printf '  %s[CHAIN]%s No web targets discovered — exiting pipeline step%s\n' "${CYAN}" "${RESET}" "${RESET}"
    mark_done "$outdir"; exit 0
  fi
  printf '  %s>>%s Enter URL manually (e.g. http://192.168.1.1:8080), or Enter to exit: ' "${CYAN}" "${RESET}"
  read -r _manual
  [[ -z "$_manual" ]] && exit 0
  URLS=("$_manual")
else
  printf '  %s[+]%s Found %d web target(s):%s\n' "${GREEN}" "${RESET}" "${#URLS[@]}" "${RESET}"
  for u in "${URLS[@]}"; do printf '      %s%s%s\n' "${DIM}" "$u" "${RESET}"; done
  printf '\n'
fi

# ── Dir brute tool selection ───────────────────────────────────────────────────
_DIR_TOOL=""
_select_dir_tool() {
  local -a _avail=()
  command -v feroxbuster &>/dev/null && _avail+=("feroxbuster")
  command -v gobuster    &>/dev/null && _avail+=("gobuster")
  command -v dirb        &>/dev/null && _avail+=("dirb")

  if [[ ${#_avail[@]} -eq 0 ]]; then
    printf '  %s[~]%s No dir-brute tool found (gobuster / feroxbuster / dirb).%s\n' \
      "${DIM}" "${RESET}" "${RESET}"
    _DIR_TOOL="none"
    return
  fi

  if [[ ${#_avail[@]} -eq 1 ]]; then
    _DIR_TOOL="${_avail[0]}"
    printf '  %s[+]%s Dir-brute tool : %s%s%s\n\n' \
      "${GREEN}" "${RESET}" "${CYAN}" "$_DIR_TOOL" "${RESET}"
    return
  fi

  if [[ -n "${SESSION_DIR:-}" ]]; then
    _DIR_TOOL="${_avail[0]}"
    printf '  %s[CHAIN]%s Dir-brute: %s  (pipeline auto-select)%s\n\n' \
      "${CYAN}" "${RESET}" "$_DIR_TOOL" "${RESET}"
    return
  fi
  printf '  %s[?]%s Multiple dir-brute tools found — pick one:%s\n' "${CYAN}" "${RESET}" "${RESET}"
  local _idx=1
  for _t in "${_avail[@]}"; do
    printf '  %s[%02d]%s  %s\n' "${CYAN}" "$_idx" "${RESET}" "$_t"
    (( _idx++ ))
  done
  printf '  %s>>%s [1]: ' "${CYAN}" "${RESET}"
  read -r _pick
  _pick="${_pick:-1}"
  if [[ "$_pick" =~ ^[0-9]+$ ]] && (( _pick >= 1 && _pick <= ${#_avail[@]} )); then
    _DIR_TOOL="${_avail[$(( _pick - 1 ))]}"
  else
    _DIR_TOOL="${_avail[0]}"
  fi
  printf '  %s[✔]%s Using : %s%s%s\n\n' "${GREEN}" "${RESET}" "${CYAN}" "$_DIR_TOOL" "${RESET}"
}

_select_dir_tool

# ── Helpers ───────────────────────────────────────────────────────────────────
_safe() { echo "${1//[^a-zA-Z0-9._-]/_}"; }

_bar() {
  local cur=$1 tot=$2 width=20
  [[ "$tot" -eq 0 ]] && tot=1
  local pct=$(( cur * 100 / tot ))
  local filled=$(( cur * width / tot ))
  local bar=""
  for (( i=0; i<width; i++ )); do
    (( i < filled )) && bar+="█" || bar+="░"
  done
  printf '[%s] %3d%% [%d/%d]' "$bar" "$pct" "$cur" "$tot"
}

# ── Tool runners ──────────────────────────────────────────────────────────────

run_whatweb() {
  require_tool whatweb "apt install whatweb"
  local outfile="$outdir/whatweb.txt"
  : > "$outfile"
  printf '  %s[*]%s whatweb — %d target(s)%s\n' "${CYAN}" "${RESET}" "${#URLS[@]}" "${RESET}"
  local _i=0
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    run_fg whatweb -a 3 "$url" | (trap '' SIGINT; tee -a "$outfile")
  done
}

run_nikto() {
  require_tool nikto "apt install nikto"
  local outfile="$outdir/nikto.txt"
  : > "$outfile"
  printf '  %s[*]%s nikto — %d target(s)%s\n' "${CYAN}" "${RESET}" "${#URLS[@]}" "${RESET}"
  local _i=0
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    run_fg nikto -h "$url" | (trap '' SIGINT; tee -a "$outfile")
  done
}

run_gobuster() {
  require_tool gobuster "apt install gobuster"
  if [[ -z "$_WORDLIST" || ! -f "$_WORDLIST" ]]; then
    if [[ -n "${SESSION_DIR:-}" ]]; then
      printf '  %s[CHAIN]%s Wordlist not found — skipping gobuster%s\n' "${CYAN}" "${RESET}" "${RESET}"
      return
    fi
    printf '  %s>>%s Wordlist not found. Enter path: ' "${CYAN}" "${RESET}"
    read -r _WORDLIST
  fi
  printf '  %s[*]%s gobuster — %d target(s) · %s%s\n' \
    "${CYAN}" "${RESET}" "${#URLS[@]}" "$_WORDLIST" "${RESET}"
  local _i=0
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    run_fg gobuster dir -u "$url" -w "$_WORDLIST" -t 20 \
      | (trap '' SIGINT; tee "$outdir/dirbust_$(_safe "$url").txt")
  done
}

run_feroxbuster() {
  require_tool feroxbuster "apt install feroxbuster"
  local _i=0
  local _wl_arg=()
  if [[ -n "$_WORDLIST" && -f "$_WORDLIST" ]]; then
    _wl_arg=(-w "$_WORDLIST")
    printf '  %s[*]%s feroxbuster — %d target(s) · %s%s\n' \
      "${CYAN}" "${RESET}" "${#URLS[@]}" "$_WORDLIST" "${RESET}"
  else
    printf '  %s[*]%s feroxbuster — %d target(s) · %s(default wordlist)%s\n' \
      "${CYAN}" "${RESET}" "${#URLS[@]}" "${DIM}" "${RESET}"
  fi
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    run_fg feroxbuster -u "$url" "${_wl_arg[@]}" \
      -q --no-state \
      -o "$outdir/dirbust_$(_safe "$url").txt"
  done
}

run_dirb() {
  require_tool dirb "apt install dirb"
  if [[ -z "$_WORDLIST" || ! -f "$_WORDLIST" ]]; then
    if [[ -n "${SESSION_DIR:-}" ]]; then
      printf '  %s[CHAIN]%s Wordlist not found — skipping dirb%s\n' "${CYAN}" "${RESET}" "${RESET}"
      return
    fi
    printf '  %s>>%s Wordlist not found. Enter path: ' "${CYAN}" "${RESET}"
    read -r _WORDLIST
  fi
  printf '  %s[*]%s dirb — %d target(s) · %s%s\n' \
    "${CYAN}" "${RESET}" "${#URLS[@]}" "$_WORDLIST" "${RESET}"
  local _i=0
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    run_fg dirb "$url" "$_WORDLIST" -o "$outdir/dirbust_$(_safe "$url").txt"
  done
}

run_dirbust() {
  case "$_DIR_TOOL" in
    gobuster)    run_gobuster    ;;
    feroxbuster) run_feroxbuster ;;
    dirb)        run_dirb        ;;
    none)
      printf '  %s[!]%s No dir-brute tool installed. Install gobuster, feroxbuster, or dirb.%s\n' \
        "${RED}" "${RESET}" "${RESET}"
      ;;
    *)
      printf '  %s[!]%s Dir-brute tool not selected.%s\n' "${RED}" "${RESET}" "${RESET}"
      ;;
  esac
}

# ── Menu ──────────────────────────────────────────────────────────────────────
web_menu() {
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  WEB RECON TOOLS                                 │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s[01]%s ▶  whatweb      Identify web technologies\n'                    "${CYAN}"  "${RESET}"
  printf '  %s[02]%s ▶  feroxbuster  Dir/file brute-force\n'                          "${CYAN}"  "${RESET}"
  printf '  %s[03]%s ▶  dir brute    %s%s%s (change with [t])\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "${_DIR_TOOL:-none}" "${RESET}"
  printf '  %s[04]%s ▶  Run all (1–3 in sequence)\n'                                "${GREEN}" "${RESET}"
  printf '  %s[t ]%s ▶  Change dir-brute tool  (current: %s%s%s)\n' \
    "${DIM}" "${RESET}" "${CYAN}" "${_DIR_TOOL:-none}" "${RESET}"
  printf '  %s[00]%s ▶  Back\n'                                                      "${RED}"   "${RESET}"
  printf '\n'
}

_publish_401_urls() {
  [[ -z "${SESSION_DIR:-}" ]] && return
  local _401_file="${SESSION_DIR}/chain_web_401.txt"
  local _count=0
  for _f in "$outdir"/dirbust_*.txt; do
    [[ -f "$_f" ]] || continue
    while IFS= read -r _line; do
      # feroxbuster output: "401      GET   ...  http://host/path"
      if [[ "$_line" =~ ^401[[:space:]] ]]; then
        local _url
        _url=$(printf '%s' "$_line" | grep -oP 'https?://\S+' || true)
        [[ -z "$_url" ]] && continue
        grep -qxF "$_url" "$_401_file" 2>/dev/null || {
          printf '%s\n' "$_url" >> "$_401_file"
          (( _count++ )) || true
        }
      fi
    done < "$_f"
  done
  (( _count > 0 )) && printf '  %s[CHAIN]%s chain_web_401.txt: %d HTTP Basic Auth path(s) for brute%s\n\n' \
    "${CYAN}" "${RESET}" "$_count" "${RESET}"
}

if [[ -n "${SESSION_DIR:-}" ]]; then
  printf '  %s[CHAIN]%s Pipeline mode — running all web scans automatically%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  run_whatweb
  run_dirbust
  _publish_401_urls
else
  while true; do
    web_menu
    printf '  %s>>%s ' "${CYAN}" "${RESET}"
    read -r choice
    case "$choice" in
      1)  run_whatweb  ;;
      2)  run_feroxbuster ;;
      3)  run_dirbust     ;;
      4)  run_whatweb; run_feroxbuster; run_dirbust ;;
      t|T) _select_dir_tool ;;
      0)  break ;;
      *)  printf '  %s[!] Invalid option%s\n' "${RED}" "${RESET}" ;;
    esac
    printf '  %s▶%s Press Enter to continue...' "${DIM}" "${RESET}"
    read -r _
  done
fi

# ── Pipeline chain: publish discovered URLs for wpscan/sqlmap ─────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ ${#URLS[@]} -gt 0 ]]; then
  printf '%s\n' "${URLS[@]}" >> "${SESSION_DIR}/chain_web_urls.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_web_urls.txt" -o "${SESSION_DIR}/chain_web_urls.txt" 2>/dev/null || true
  printf '  %s[CHAIN]%s chain_web_urls.txt: %d URL(s) published for wpscan/sqlmap%s\n\n' \
    "${CYAN}" "${RESET}" "${#URLS[@]}" "${RESET}"
fi

mark_done "$outdir"
