#!/usr/bin/env bash
# Printer audit — port 9100 scan + PJL verify (no false positives) + PRET launcher
source "$(dirname "$0")/../lib.sh"

require_tool nmap "pkg install nmap"
require_tool nc   "pkg install netcat"

banner "PRET — PRINTER EXPLOITATION TOOLKIT" "PJL · PS · PCL — port 9100 scanner + audit"

target=$(prompt_target)
outdir=$(make_outdir)
outfile="$outdir/pret.txt"

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '\n'

# ── Check for PRET ────────────────────────────────────────────────────────────
PRET_BIN=""
for _p in "$(command -v pret.py 2>/dev/null)" "$(command -v pret 2>/dev/null)" \
           "/opt/pret/pret.py" "/usr/local/bin/pret.py" "/root/pret/pret.py"; do
  [[ -n "$_p" && -f "$_p" ]] && { PRET_BIN="$_p"; break; }
done

PRET_PY=""
if [[ -n "$PRET_BIN" ]]; then
  PRET_PY=$(command -v python2 2>/dev/null || command -v python2.7 2>/dev/null \
            || command -v python3 2>/dev/null || echo python3)
  printf '  %s[+]%s PRET found: %s%s%s (using %s)%s\n' \
    "${GREEN}" "${RESET}" "${CYAN}" "$PRET_BIN" "${RESET}" "$PRET_PY" "${RESET}"
else
  printf '  %s[~]%s PRET not installed — PJL raw dump only%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  printf '  %s[~]%s Install: git clone https://github.com/rub-nds/pret /opt/pret%s\n\n' \
    "${DIM}" "${RESET}" "${RESET}"
fi

# ── Discover hosts with port 9100 open ───────────────────────────────────────
section "PORT SCAN — 9100/tcp (JetDirect raw printing)"

NMAP_CACHE="/tmp/fsec_nmap_cache.txt"
SCAN_TMP="$outdir/_pret_9100.tmp"

if [[ -f "$NMAP_CACHE" ]]; then
  printf '  %s[*]%s Re-using cached nmap results for port 9100%s\n' "${CYAN}" "${RESET}" "${RESET}"
  _hosts_9100=$(grep -A1 "report for" "$NMAP_CACHE" 2>/dev/null \
    | awk '/report for/{ip=$NF} /9100\/tcp.*open/{print ip}' | sort -u)
else
  printf '  %s[*]%s Scanning %s for TCP 9100...%s\n\n' "${CYAN}" "${RESET}" "$target" "${RESET}"
  run_fg nmap -sT -Pn -n -T4 -p 9100 --open \
    --max-retries 2 --max-scan-delay 10ms \
    -oN "$SCAN_TMP" "$target" 2>/dev/null || true
  _hosts_9100=$(grep "report for" "$SCAN_TMP" 2>/dev/null | awk '{print $NF}')
fi

if [[ -z "$_hosts_9100" ]]; then
  printf '  %s[!]%s No hosts with port 9100 open.%s\n\n' "${YELLOW}" "${RESET}" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

mapfile -t ALL_HOSTS <<< "$_hosts_9100"
printf '  %s[+]%s %d host(s) with port 9100 open.%s\n\n' \
  "${GREEN}" "${RESET}" "${#ALL_HOSTS[@]}" "${RESET}"

# ── PJL banner verify — eliminate false positives ────────────────────────────
section "PJL VERIFICATION — eliminating false positives"

declare -a PRINTERS=()
declare -A PJL_MODEL=()

for _h in "${ALL_HOSTS[@]}"; do
  printf '  %s[?]%s %-16s  probing PJL...' "${CYAN}" "${RESET}" "$_h"
  _resp=$(printf '\033%%-12345X@PJL INFO ID\r\n\033%%-12345X' \
    | timeout 3 nc -w 3 "$_h" 9100 2>/dev/null) || true
  if printf '%s' "$_resp" | grep -qi '@PJL\|PJL'; then
    _model=$(printf '%s' "$_resp" \
      | strings | grep -v '@PJL' | grep -v '^$' | head -1 | tr -d '"' | xargs 2>/dev/null || echo "Unknown")
    PRINTERS+=("$_h")
    PJL_MODEL["$_h"]="$_model"
    printf '  %s[PRINTER]%s  %s%s%s\n' "${GREEN}" "${RESET}" "${CYAN}" "$_model" "${RESET}"
  else
    printf '  %s[SKIP]%s    not a printer (false positive — no PJL response)%s\n' \
      "${DIM}" "${RESET}" "${RESET}"
  fi
done

printf '\n'

if [[ ${#PRINTERS[@]} -eq 0 ]]; then
  printf '  %s[!]%s No confirmed printers (all were false positives).%s\n\n' \
    "${YELLOW}" "${RESET}" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

printf '  %s[+]%s %d confirmed printer(s):\n\n' "${GREEN}" "${RESET}" "${#PRINTERS[@]}"
for i in "${!PRINTERS[@]}"; do
  printf '  %s[%02d]%s  %-16s  %s%s%s\n' \
    "${CYAN}" "$(( i + 1 ))" "${RESET}" "${PRINTERS[$i]}" "${DIM}" "${PJL_MODEL[${PRINTERS[$i]}]}" "${RESET}"
done
printf '\n'

# Log confirmed printers
{
  printf 'PRET PRINTER SCAN — %s\n' "$(date)"
  printf 'Target: %s\n\n' "$target"
  printf 'Confirmed printers:\n'
  for _h in "${PRINTERS[@]}"; do
    printf '  %-16s  %s\n' "$_h" "${PJL_MODEL[$_h]}"
  done
  printf '\n'
} > "$outfile"

# ── Per-printer action menu ───────────────────────────────────────────────────
_printer_menu() {
  local host="$1"
  local model="${PJL_MODEL[$host]:-Unknown}"

  while true; do
    printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
    printf '  %s│  PRINTER ACTIONS — %-30s│%s\n' "${CYAN}${BOLD}" "$host " "${RESET}"
    printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
    printf '  %s    Model: %s%s\n\n' "${DIM}" "$model" "${RESET}"
    printf '  %s[01]%s ▶  PJL info dump     — id / config / status / variables / memory\n' "${CYAN}" "${RESET}"
    printf '  %s[02]%s ▶  PJL env dump      — all NVRAM variables (passwords, settings)\n' "${CYAN}" "${RESET}"
    printf '  %s[03]%s ▶  IPP probe         — port 631 HTTP info\n' "${CYAN}" "${RESET}"
    if [[ -n "$PRET_BIN" ]]; then
      printf '  %s[04]%s ▶  PRET PJL          — interactive PRET in PJL mode\n' "${GREEN}" "${RESET}"
      printf '  %s[05]%s ▶  PRET PS           — interactive PRET in PostScript mode\n' "${GREEN}" "${RESET}"
      printf '  %s[06]%s ▶  PRET PCL          — interactive PRET in PCL mode\n' "${GREEN}" "${RESET}"
    else
      printf '  %s[04-06] PRET not installed (see above)%s\n' "${DIM}" "${RESET}"
    fi
    printf '  %s[07]%s ▶  nmap scripts      — pjl-ready-message + printer-info\n' "${CYAN}" "${RESET}"
    printf '  %s[00]%s ▶  Back\n\n' "${RED}" "${RESET}"

    printf '  %s>>%s ' "${CYAN}" "${RESET}"
    read -r _pick || return

    case "${_pick:-}" in
      0|00) return ;;
      '')   continue ;;

      1|01)
        section "PJL INFO DUMP — $host"
        printf '\033%%-12345X@PJL INFO ID\r\n@PJL INFO CONFIG\r\n@PJL INFO STATUS\r\n@PJL INFO MEMORY\r\n@PJL INFO FILESYS\r\n\033%%-12345X' \
          | timeout 6 nc -w 6 "$host" 9100 2>/dev/null \
          | strings | grep -Ev '^(\[|@PJL|$)' | head -300 | tee -a "$outfile" || true
        ;;

      2|02)
        section "PJL VARIABLES (NVRAM) — $host"
        printf '\033%%-12345X@PJL INFO VARIABLES\r\n\033%%-12345X' \
          | timeout 6 nc -w 6 "$host" 9100 2>/dev/null \
          | strings | grep -Ev '^(\[|$)' | head -200 | tee -a "$outfile" || true
        ;;

      3|03)
        section "IPP PROBE — $host:631"
        if check_tool curl; then
          curl -s --max-time 5 "http://$host:631/printers" \
            | sed 's/<[^>]*>//g' | grep -v '^[[:space:]]*$' | head -60 | tee -a "$outfile" || true
        else
          printf '  %s[!]%s curl not found%s\n' "${YELLOW}" "${RESET}" "${RESET}"
        fi
        ;;

      4|04|5|05|6|06)
        if [[ -z "$PRET_BIN" ]]; then
          printf '  %s[!]%s PRET not installed%s\n' "${RED}" "${RESET}" "${RESET}"
        else
          case "$_pick" in
            4|04) _pmode="pjl" ;;
            5|05) _pmode="ps"  ;;
            6|06) _pmode="pcl" ;;
          esac
          section "PRET ${_pmode^^} — $host"
          run_fg "$PRET_PY" "$PRET_BIN" "$host" "$_pmode"
        fi
        ;;

      7|07)
        section "NMAP PRINTER SCRIPTS — $host"
        run_fg nmap -sT --unprivileged -p 9100 \
          --script pjl-ready-message,printer-info \
          "$host" 2>/dev/null || true
        ;;

      *)
        printf '  %s[!] Enter 01-07 or 00%s\n' "${YELLOW}" "${RESET}" ;;
    esac

    printf '\n  %s▶%s Press Enter to continue...' "${DIM}" "${RESET}"
    read -r _ || true
  done
}

# ── Main selection loop ───────────────────────────────────────────────────────
trap 'printf "\n  %s[!] Exiting.%s\n\n" "${RED}" "${RESET}"; exit 0' INT

while true; do
  printf '\n'
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  CONFIRMED PRINTERS                              │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  for i in "${!PRINTERS[@]}"; do
    printf '  %s[%02d]%s  %-16s  %s%s%s\n' \
      "${CYAN}" "$(( i + 1 ))" "${RESET}" "${PRINTERS[$i]}" \
      "${DIM}" "${PJL_MODEL[${PRINTERS[$i]}]}" "${RESET}"
  done
  printf '  %s[00]%s  Exit\n\n' "${RED}" "${RESET}"

  if [[ -n "${SESSION_DIR:-}" ]]; then
    printf '  %s[CHAIN]%s Pipeline: auto PJL dump on all printers%s\n\n' \
      "${CYAN}" "${RESET}" "${RESET}"
    for _ph in "${PRINTERS[@]}"; do
      printf '  %s[AUTO]%s PJL NVRAM dump: %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_ph" "${RESET}"
      printf '\033%%-12345X@PJL INFO VARIABLES\r\n\033%%-12345X' \
        | timeout 6 nc -w 6 "$_ph" 9100 2>/dev/null \
        | strings | grep -Ev '^(\[|$)' | tee -a "$outfile" || true
      # Extract PJL NVRAM passwords
      grep -iE 'PASSWORD\s*=\s*\S+' "$outfile" 2>/dev/null \
        | grep -oiE 'PASSWORD\s*=\s*\S+' \
        | while IFS= read -r _pair; do
            _val=$(echo "$_pair" | sed 's/.*=\s*//' | tr -d '\r\n"'"'")
            [[ ${#_val} -ge 1 && "$_val" != "0" ]] && \
              printf '[pret][9100]    login: admin   password: %s\n' "$_val"
          done >> "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
      printf '%s\n' "$_ph" >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
      printf '%s:9100\n' "$_ph" >> "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
    done
    sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
    sort -u "${SESSION_DIR}/chain_ports.txt" -o "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
    sort -u "${SESSION_DIR}/chain_creds.txt" -o "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
    printf '  %s[CHAIN]%s %s printer(s) → alive_hosts.txt + chain_ports.txt%s\n\n' \
      "${CYAN}" "${RESET}" "${#PRINTERS[@]}" "${RESET}"
    mark_done "$outfile"
    exit 0
  fi
  printf '  %s>>%s Select printer (0 to exit): ' "${CYAN}" "${RESET}"
  read -r _hpick || break

  case "${_hpick:-}" in
    0|00|q) printf '  %s[!] Done.%s\n\n' "${RED}" "${RESET}"; exit 0 ;;
    '')     continue ;;
    *)
      if [[ "$_hpick" =~ ^[0-9]+$ ]] && \
         (( _hpick >= 1 && _hpick <= ${#PRINTERS[@]} )); then
        _printer_menu "${PRINTERS[$(( _hpick - 1 ))]}"
      else
        printf '  %s[!] Enter 01-%02d or 00%s\n\n' "${YELLOW}" "${#PRINTERS[@]}" "${RESET}"
      fi
      ;;
  esac
done
