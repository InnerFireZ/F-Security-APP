#!/usr/bin/env bash
# F-Security — portable security audit tool launcher

set -u

cd "$(dirname "$0")" || { echo "Failed to enter script directory."; exit 1; }

source "./lib.sh"

# ── Main banner ───────────────────────────────────────────────────────────────
_fsec_banner() {
  printf '\n'
  printf '  %s╔════════════════════════════════════════════════════╗%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s║   ▓▒░  F - S E C U R I T Y  ░▒▓                 ║%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s║   NETWORK INFILTRATION SUITE                      ║%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s║   · · · · · · · · · · · · · · · · · · · · · ·   ║%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s║   Rootless Kali NetHunter  ·  16 modules          ║%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s╚════════════════════════════════════════════════════╝%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '\n'
  printf '  %s[SYS]%s Network node  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$(get_ip)" "${RESET}"
  printf '\n'
}

_fsec_banner

# ── Menu ──────────────────────────────────────────────────────────────────────
menu() {
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  ctOS :: TOOL MATRIX                             │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s[01]%s ▶  crackmap     SMB / RDP / WinRM null-session\n'   "${CYAN}" "${RESET}"
  printf '  %s[02]%s ▶  fscan        Fast internal network scanner\n'     "${CYAN}" "${RESET}"
  printf '  %s[03]%s ▶  nmap         Service/version scan  (-sT rootless)\n' "${CYAN}" "${RESET}"
  printf '  %s[04]%s ▶  ingram       Webcam auto-exploit\n'              "${CYAN}" "${RESET}"
  printf '  %s[05]%s ▶  rtsp-brute   RTSP stream brute-force\n'          "${CYAN}" "${RESET}"
  printf '  %s[06]%s ▶  nuclei       Vulnerability scan  (LAN / IoT)\n'  "${CYAN}" "${RESET}"
  printf '  %s[07]%s ▶  autorecon    Ping sweep + multi-tool recon\n'    "${CYAN}" "${RESET}"
  printf '  %s[08]%s ▶  web          Web recon suite\n'                  "${CYAN}" "${RESET}"
  printf '  %s[09]%s ▶  iot          IoT / SCADA / Camera discovery\n'   "${CYAN}" "${RESET}"
  printf '  %s[10]%s ▶  brute       Credential brute-force — SSH/FTP/HTTP/SMB\n' "${CYAN}" "${RESET}"
  printf '  %s[11]%s ▶  ssl         TLS/SSL certificate + vulnerability audit\n'  "${CYAN}" "${RESET}"
  printf '  %s[12]%s ▶  dns_ad      DNS zone transfer + AD/LDAP enumeration\n'    "${CYAN}" "${RESET}"
  printf '  %s[13]%s ▶  report      Compile results → HTML pentest report\n'      "${CYAN}" "${RESET}"
  printf '  %s[14]%s ▶  post        Post-discovery action hub\n'                   "${CYAN}" "${RESET}"
  printf '  %s[15]%s ▶  c2          Reverse shell listener + payload generator\n' "${CYAN}" "${RESET}"
  printf '  %s[16]%s ▶  exploit     CVE quick-strike → MSF launcher\n'            "${CYAN}" "${RESET}"
  printf '  %s[00]%s ▶  exit\n'                                          "${RED}"  "${RESET}"
  printf '\n'
}

# ── Script launcher ───────────────────────────────────────────────────────────
run_script() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    printf '  %s[!] Error: "%s" not found in %s%s\n' "${RED}" "$file" "$(pwd)" "${RESET}" >&2
    return 1
  fi
  [[ ! -x "$file" ]] && chmod +x "$file" 2>/dev/null || true

  printf '\n'
  printf '  %s╔══════════════════════════════════════════════╗%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s║  ▶ LAUNCHING: %s%s\n'                         "${CYAN}${BOLD}" "$file" "${RESET}"
  printf '  %s╚══════════════════════════════════════════════╝%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '\n'

  if [[ -x "$file" ]]; then
    "./$file"
  else
    bash "./$file"
  fi

  local status=$?
  printf '\n  %s────────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
  if [[ $status -eq 0 ]]; then
    printf '  %s[✔] %s — completed%s\n' "${GREEN}" "$file" "${RESET}"
  else
    printf '  %s[!] %s — exit code: %d%s\n' "${YELLOW}" "$file" "$status" "${RESET}"
  fi
  printf '  %s────────────────────────────────────────────────%s\n\n' "${DIM}" "${RESET}"
  return $status
}

# ── Main loop ─────────────────────────────────────────────────────────────────
trap 'printf "\n  %s[!] Connection terminated.%s\n\n" "${RED}" "${RESET}"; exit 0' INT

while true; do
  menu
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r choice 
  case "$choice" in
    1) run_script "scripts/crackmap.sh" ;;
    2) run_script "scripts/fscan.sh" ;;
    3) run_script "scripts/nmap.sh" ;;
    4) run_script "Ingram/auto_ingramv2.sh" ;;
    5) run_script "scripts/rtsp_brute_open.sh" ;;
    6) run_script "scripts/nuclei.sh" ;;
    7) run_script "scripts/autorecon.sh" ;;
    8) run_script "scripts/web.sh" ;;
    9)  run_script "scripts/iot.sh" ;;
    10) run_script "scripts/brute.sh" ;;
    11) run_script "scripts/ssl.sh" ;;
    12) run_script "scripts/dns_ad.sh" ;;
    13) run_script "scripts/report.sh" ;;
    14) run_script "scripts/post.sh" ;;
    15) run_script "scripts/c2.sh" ;;
    16) run_script "scripts/exploit.sh" ;;
    0)  printf '  %s[!] Connection terminated.%s\n\n' "${RED}" "${RESET}"; exit 0 ;;
    *)  printf '  %s[!] Invalid option — enter 00-16%s\n\n' "${YELLOW}" "${RESET}" ;;
  esac

  printf '  %s▶%s Press Enter to return to the menu...' "${DIM}" "${RESET}"
  read -r _ 
  _fsec_banner
done
