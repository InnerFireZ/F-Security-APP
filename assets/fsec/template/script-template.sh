#!/usr/bin/env bash
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │  F-Security Script Template                                                 │
# │  Copy to assets/fsec/scripts/your_script.sh and fill in the sections.      │
# │  Register the module in lib/data/modules.dart and add the asset path in     │
# │  lib/services/script_deployer.dart, then bump _currentVersion by 1.        │
# └─────────────────────────────────────────────────────────────────────────────┘
source "$(dirname "$0")/../lib.sh"

# ── Header ────────────────────────────────────────────────────────────────────
banner "MY TOOL" "one-line description of what this module does"

# ── Tool check ────────────────────────────────────────────────────────────────
# require_tool exits with a clear message if the binary is missing.
require_tool mytool "apt install mytool"

# ── Output directory ──────────────────────────────────────────────────────────
# make_outdir creates results/<PROJECT_SLUG>/<timestamp>/ and returns the path.
# All output files must land here — this is what the Results screen shows.
outdir=$(make_outdir)
outfile="$outdir/mytool.log"
: > "$outfile"   # create/truncate

printf '  %s[SYS]%s Output : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"

# ── Cleanup trap (use when your script starts background processes) ────────────
# The trap fires on normal exit AND on SIGINT (stop button), so cleanup always runs.
#
# _cleanup() {
#   kill "$_bg_pid" 2>/dev/null || true
#   printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
# }
# trap '_cleanup' EXIT INT TERM

# ── Interface selection (include only if your tool needs a network interface) ─
section "INTERFACE"

mapfile -t _ifaces < <(ip -o link show \
  | awk -F': ' '{print $2}' \
  | grep -v '^lo$' \
  | grep -vE '^(rmnet|r_rmnet|bond|dummy)')

if [[ ${#_ifaces[@]} -eq 0 ]]; then
  printf '  %s[!]%s No usable interfaces found\n' "${RED}" "${RESET}"; exit 1
fi

for i in "${!_ifaces[@]}"; do
  _ip=$(ip -o -4 addr show "${_ifaces[$i]}" 2>/dev/null | awk '{print $4}' | head -1)
  printf '  %s[%02d]%s  %-14s  %s%s%s\n' \
    "${CYAN}" "$((i+1))" "${RESET}" "${_ifaces[$i]}" "${DIM}" "${_ip:-no IPv4}" "${RESET}"
done

printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_ifaces[@]}"
read -r _sel; _sel="${_sel:-1}"

if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_ifaces[@]} )); then
  printf '  %s[!]%s Invalid selection\n' "${RED}" "${RESET}"; exit 1
fi
IFACE="${_ifaces[$((_sel-1))]}"
printf '\n  %s[SYS]%s Interface : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"

# ── Target input ──────────────────────────────────────────────────────────────
# Use prompt_target if the module takes a target IP/CIDR from the user or
# from a previous pipeline step (via the $TARGET env var injected by the app).
section "TARGET"

target=$(prompt_target)
printf '  %s[SYS]%s Target : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"

# ── Existing nmap results (optional — include if your tool benefits from it) ──
# pick_nmap_file returns "outdir|path_to_nmap.txt" when a prior session exists,
# or empty string when not. Scoped to $PROJECT_SLUG automatically.
#
# _nmap_load=$(pick_nmap_file)
# if [[ -n "$_nmap_load" ]]; then
#   _nmap_txt="${_nmap_load##*|}"
#   # parse _nmap_txt for hosts/ports …
# fi

# ── Run ───────────────────────────────────────────────────────────────────────
section "RUN"

printf '  %s[*]%s Running mytool · output → %s%s%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '  %s[*]%s Press Stop / Ctrl+C to stop%s\n\n' "${CYAN}" "${RESET}" "${RESET}"

# run_fg writes the tool PID to /tmp/.fsec_tool.pid before exec'ing.
# This enables the app's soft Ctrl+C (tap = SIGINT, hold = SIGKILL).
# Use it for single foreground tools:
run_fg mytool "$target" 2>&1 | tee "$outfile"

# For piped / background processes where you need the PID manually:
# _fifo=$(mktemp -u /tmp/.fsec_ns.XXXXXX); mkfifo "$_fifo"
# mytool ... > "$_fifo" 2>&1 &
# _bg_pid=$!
# printf '%s\n' "$_bg_pid" > /tmp/.fsec_tool.pid
# tee "$outfile" < "$_fifo"

# ── Done ──────────────────────────────────────────────────────────────────────
printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
mark_done "$outdir"
