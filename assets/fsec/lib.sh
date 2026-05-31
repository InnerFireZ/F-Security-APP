#!/usr/bin/env bash
# Shared helpers — source this file, do not execute directly.

# Colors
if tput setaf 1 >/dev/null 2>&1; then
  RED="$(tput setaf 1)$(tput bold)"
  GREEN="$(tput setaf 2)$(tput bold)"
  YELLOW="$(tput setaf 3)$(tput bold)"
  CYAN="$(tput setaf 6)$(tput bold)"
  BOLD="$(tput bold)"
  DIM="$(tput dim 2>/dev/null || printf '\033[2m')"
  RESET="$(tput sgr0)"
else
  RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' RESET=''
fi

# ── Watch Dogs / ctOS visual helpers ─────────────────────────────────────────

# banner <TITLE> [subtitle]  — ctOS style tool header box
banner() {
  local title="$1" sub="${2:-}"
  printf '\n'
  printf '  %s╔══════════════════════════════════════════════╗%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s║  ▶ %s%s\n' "${CYAN}${BOLD}" "${title}" "${RESET}"
  [[ -n "$sub" ]] && printf '  %s║    %s%s%s\n' "${CYAN}" "${DIM}" "${sub}" "${RESET}"
  printf '  %s╚══════════════════════════════════════════════╝%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '\n'
}

# section <title>  — styled section marker
section() {
  printf '\n  %s▶ %s%s\n' "${CYAN}${BOLD}" "$*" "${RESET}"
  printf '  %s──────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
}

# Spinner — wrap slow operations: start_spin <msg> … stop_spin
_spin_pid=""
start_spin() {
  local msg="$1"
  ( local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while true; do
      printf "\r  \033[1;36m%s\033[0m %s" "${frames[$i]}" "$msg"
      sleep 0.12
      i=$(( (i + 1) % 10 ))
    done ) &
  _spin_pid=$!
}
stop_spin() {
  [[ -z "${_spin_pid:-}" ]] && return 0
  kill "$_spin_pid" 2>/dev/null || true
  wait "$_spin_pid" 2>/dev/null || true
  printf '\r\033[K'
  _spin_pid=""
}

# _ip_to_network <ip> <prefix>
# Pure-bash: compute network address from host IP + prefix length.
# e.g. _ip_to_network 192.168.68.92 22  ->  192.168.68.0/22
_ip_to_network() {
  local ip="$1" prefix="$2"
  local -i a b c d
  IFS=. read -r a b c d <<< "$ip"
  local -i full=$(( (a<<24) | (b<<16) | (c<<8) | d ))
  local -i mask=$(( prefix > 0 ? (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF : 0 ))
  local -i net=$(( full & mask ))
  printf "%d.%d.%d.%d/%d\n" \
    $(( (net>>24)&0xFF )) $(( (net>>16)&0xFF )) \
    $(( (net>>8)&0xFF  )) $(( net&0xFF )) \
    "$prefix"
}

# _ip_usable: returns 0 only if 'ip' exists AND can actually query addresses
# (on Android rootless, 'ip' exists but fails with "Cannot bind netlink socket")
_ip_usable() {
  command -v ip &>/dev/null && ip -o -4 addr show 2>/dev/null | grep -q .
}

# list_ifaces
# Prints tab-separated "iface <TAB> network/prefix" for every non-loopback IPv4 interface.
list_ifaces() {
  if _ip_usable; then
    # ip -o -4 addr show gives lines like:
    #   2: wlan0    inet 192.168.68.92/22 brd ...
    ip -o -4 addr show 2>/dev/null | while IFS= read -r line; do
      local iface host_cidr
      iface=$(echo "$line" | awk '{print $2}')
      host_cidr=$(echo "$line" | awk '{print $4}')
      [[ "$iface" == "lo" || -z "$host_cidr" ]] && continue
      local host prefix
      host="${host_cidr%%/*}"
      prefix="${host_cidr##*/}"
      [[ -z "$prefix" || "$prefix" == "$host" ]] && prefix=24
      local net
      net=$(_ip_to_network "$host" "$prefix")
      printf "%s\t%s\n" "$iface" "$net"
    done
  else
    # ifconfig fallback — Android/busybox format
    local cur_iface=""
    ifconfig 2>/dev/null | while IFS= read -r line; do
      # Interface line: "wlan0: flags=..."  or  "wlan0  Link encap:..."
      if echo "$line" | grep -qE '^[a-zA-Z][a-zA-Z0-9_.-]+'; then
        cur_iface=$(echo "$line" | awk -F'[ :]' '{print $1}')
      fi
      # inet line: "  inet 192.168.1.5  netmask 255.255.255.0 ..."
      if echo "$line" | grep -q 'inet ' && [[ "$cur_iface" != "lo" ]]; then
        local host mask
        host=$(echo "$line" | grep -oE 'inet [0-9.]+' | awk '{print $2}')
        mask=$(echo "$line" | grep -oE 'netmask [0-9.]+' | awk '{print $2}')
        if [[ -n "$host" ]]; then
          local prefix=24
          if [[ -n "$mask" ]]; then
            # Convert dotted netmask to prefix length
            local IFS=.
            read -r m1 m2 m3 m4 <<< "$mask"
            local -i bits=0
            for oct in $m1 $m2 $m3 $m4; do
              local x=$oct
              while (( x > 0 )); do
                (( bits += x & 1 ))
                (( x >>= 1 ))
              done
            done
            prefix=$bits
          fi
          local net
          net=$(_ip_to_network "$host" "$prefix")
          printf "%s\t%s\n" "$cur_iface" "$net"
        fi
      fi
    done
  fi
}

# _get_addr <iface>
# Returns the IPv4 address for the given interface using whichever tool works.
# On Android rootless, ifconfig <iface> fails — parse full ifconfig output instead.
_get_addr() {
  local _iface="$1"
  if _ip_usable; then
    ip -o -4 addr show "$_iface" 2>/dev/null \
      | awk '{print $4}' | cut -d/ -f1 | head -1
  else
    ifconfig 2>/dev/null | awk -v iface="$_iface" '
      /^[a-zA-Z]/ { cur = $1; gsub(/:/, "", cur) }
      cur == iface && /inet / {
        for (i=1; i<=NF; i++) if ($i == "inet") { print $(i+1); exit }
      }
    '
  fi
}

# get_ip [interface]
# Returns the IPv4 address (no prefix) for the given interface, or the first
# active non-loopback interface if no argument is given.
get_ip() {
  local iface="${1:-}"
  local addr=""

  if [[ -n "$iface" ]]; then
    addr=$(_get_addr "$iface")
    [[ -n "$addr" ]] && echo "$addr" && return
  fi

  # Try common NetHunter / mobile interfaces in order
  for candidate in wlan0 wlan1 eth0 eth1 usb0 usb1 rndis0 tun0; do
    addr=$(_get_addr "$candidate")
    if [[ -n "$addr" ]]; then
      echo "$addr"
      return
    fi
  done

  # Last resort: any non-loopback interface
  if _ip_usable; then
    addr=$(ip -o -4 addr show 2>/dev/null \
      | awk '$2 != "lo" {print $4}' | cut -d/ -f1 | head -1)
  else
    addr=$(ifconfig 2>/dev/null | awk '
      /^[a-zA-Z]/ { cur = $1; gsub(/:/, "", cur) }
      cur != "lo" && /inet / {
        for (i=1; i<=NF; i++) if ($i == "inet") { print $(i+1); exit }
      }
    ')
  fi
  echo "${addr:-N/A}"
}

# auto_iface [wifi|bt|any]
# Returns the best non-loopback interface for pipeline use.
# Mode "wifi" prefers wlan; "bt" prefers bluetooth; default prefers ethernet then wifi.
# In pipeline mode ($SESSION_DIR set), scripts should call this instead of prompting.
auto_iface() {
  local mode="${1:-any}"
  local candidate addr

  if [[ "$mode" == "wifi" ]]; then
    local _order=(wlan0 wlan1 wlan2 wlp0s20f3)
  elif [[ "$mode" == "bt" ]]; then
    echo "hci0"; return
  else
    local _order=(eth0 eth1 usb0 usb1 rndis0 wlan0 wlan1 tun0)
  fi

  for candidate in "${_order[@]}"; do
    addr=$(_get_addr "$candidate")
    [[ -n "$addr" ]] && echo "$candidate" && return
  done

  # Fallback: first active non-loopback with IPv4
  if _ip_usable; then
    ip -o -4 addr show 2>/dev/null \
      | awk '$2 != "lo" {print $2; exit}'
  else
    ifconfig 2>/dev/null | awk '/^[a-zA-Z]/ && $1 != "lo" {print $1; exit}'
  fi
}

# resolve_iface
# Returns IFACE from env if set, otherwise calls auto_iface.
# Use in pipeline scripts instead of prompting when SESSION_DIR is set.
resolve_iface() {
  local mode="${1:-any}"
  if [[ -n "${IFACE:-}" ]]; then
    echo "$IFACE"
  else
    auto_iface "$mode"
  fi
}

# require_tool <tool> [install-hint]
# Exits with an error if the tool is not found in PATH.
require_tool() {
  local tool="$1"
  local hint="${2:-apt install $tool}"
  if ! command -v "$tool" &>/dev/null; then
    echo "${RED}[!] '$tool' not found. Install it with: $hint${RESET}" >&2
    exit 1
  fi
}

# check_tool <tool>
# Returns 0 if found, 1 if not (non-fatal — lets callers decide).
check_tool() {
  command -v "$1" &>/dev/null
}

# run_fg <cmd> [args...]
# Runs a command in the foreground with full PTY (stdin+stdout+stderr intact).
# Before exec'ing, writes the process PID to a well-known file so the app's
# soft Ctrl+C (tap) can send SIGINT only to this tool without touching bash.
FSEC_TOOL_PID="/tmp/.fsec_tool.pid"
run_fg() {
  ( echo "$BASHPID" > "$FSEC_TOOL_PID" 2>/dev/null; exec "$@" )
  local _rc=$?
  rm -f "$FSEC_TOOL_PID" 2>/dev/null || true
  return $_rc
}

# make_outdir
# Creates and prints a timestamped results directory under <fsec_root>/results/.
# Respects $SESSION_DIR env var — if pre-set by the pipeline runner, uses it directly.
# Respects $PROJECT_SLUG env var — places sessions under results/<slug>/ when set.
make_outdir() {
  # Pipeline runner pre-sets SESSION_DIR so all modules share one directory.
  if [[ -n "${SESSION_DIR:-}" ]]; then
    mkdir -p "$SESSION_DIR"
    echo "$SESSION_DIR"
    return
  fi
  local _base
  _base="$(cd "$(dirname "$0")/.." && pwd)"
  local _slug="${PROJECT_SLUG:-}"
  local dir
  if [[ -n "$_slug" ]]; then
    dir="$_base/results/$_slug/$(date '+%Y-%m-%d_%H-%M-%S')"
  else
    dir="$_base/results/$(date '+%Y-%m-%d_%H-%M-%S')"
  fi
  mkdir -p "$dir"
  echo "$dir"
}

# mark_done
# Touches a sentinel file inside a session directory so the app can detect scan completion.
# Accepts either a directory or a file path (derives the directory automatically).
mark_done() {
  local target="${1:-}"
  [[ -z "$target" ]] && return
  local dir
  if [[ -d "$target" ]]; then
    dir="$target"
  else
    dir="$(dirname "$target")"
  fi
  touch "$dir/.fsec_done" 2>/dev/null || true
}

# pick_nmap_file
# Offers to load an existing nmap.txt from a results/ session instead of re-scanning.
# Prints "session_dir|nmap_path" to stdout on success, empty string if skipped/none found.
# All user-facing output goes to stderr so stdout can be captured with $(...).
#
# Pipeline mode: if SESSION_DIR is pre-set and already contains a valid nmap.txt,
# returns it automatically without any user prompt (enables automatic tool chaining).
pick_nmap_file() {
  if [[ -n "${SESSION_DIR:-}" ]] && \
     [[ -f "${SESSION_DIR}/nmap.txt" ]] && \
     grep -qE '^[0-9]+/(tcp|udp).*open' "${SESSION_DIR}/nmap.txt" 2>/dev/null; then
    printf '  %s[CHAIN]%s Auto-loading nmap.txt from pipeline session%s\n' \
      "${CYAN}" "${RESET}" "${RESET}" >&2
    echo "${SESSION_DIR}|${SESSION_DIR}/nmap.txt"
    return
  fi

  local _pnf_base
  _pnf_base="$(cd "$(dirname "$0")/.." && pwd)"
  local _pnf_slug="${PROJECT_SLUG:-}"
  local _pnf_search
  if [[ -n "$_pnf_slug" ]]; then
    _pnf_search="$_pnf_base/results/$_pnf_slug"
  else
    _pnf_search="$_pnf_base/results"
  fi
  local -a _pnf_sessions=()
  while IFS= read -r _d; do
    # Only include sessions where nmap.txt exists AND contains at least one open port
    if [[ -f "${_d}nmap.txt" ]] && \
       grep -qE '^[0-9]+/(tcp|udp).*open' "${_d}nmap.txt" 2>/dev/null; then
      _pnf_sessions+=("$_d")
    fi
  done < <(ls -1dt "$_pnf_search/"*/ 2>/dev/null || true)

  if [[ ${#_pnf_sessions[@]} -eq 0 ]]; then
    echo ""; return
  fi

  printf '  %s>>%s Re-use an existing nmap.txt? [y/N]: ' "${CYAN}" "${RESET}" >&2
  read -r _pnf_ans
  if [[ "${_pnf_ans,,}" != "y" ]]; then
    echo ""; return
  fi

  printf '\n  %s[+]%s Sessions with nmap.txt:\n\n' "${GREEN}" "${RESET}" >&2
  local _pnf_i
  for _pnf_i in "${!_pnf_sessions[@]}"; do
    local _pnf_entry="${_pnf_sessions[$_pnf_i]}"
    local _pnf_ts="${_pnf_entry%/}"; _pnf_ts="${_pnf_ts##*/}"
    local _pnf_hosts _pnf_ports
    _pnf_hosts=$(grep -c 'report for' "${_pnf_entry}nmap.txt" 2>/dev/null || true)
    _pnf_ports=$(grep -cE '^[0-9]+/(tcp|udp).*open' "${_pnf_entry}nmap.txt" 2>/dev/null || true)
    _pnf_hosts="${_pnf_hosts:-0}"; _pnf_ports="${_pnf_ports:-0}"
    printf '  %s[%02d]%s  %s  %s(%s host(s) · %s open port(s))%s\n' \
      "${CYAN}" "$(( _pnf_i + 1 ))" "${RESET}" "$_pnf_ts" \
      "${DIM}" "$_pnf_hosts" "$_pnf_ports" "${RESET}" >&2
  done
  printf '\n  %s>>%s Select [1]: ' "${CYAN}" "${RESET}" >&2
  read -r _pnf_pick
  _pnf_pick="${_pnf_pick:-1}"

  if ! [[ "$_pnf_pick" =~ ^[0-9]+$ ]] || \
     (( _pnf_pick < 1 || _pnf_pick > ${#_pnf_sessions[@]} )); then
    printf '  %s[!]%s Invalid selection — running fresh scan.\n\n' "${RED}" "${RESET}" >&2
    echo ""; return
  fi

  local _pnf_dir="${_pnf_sessions[$(( _pnf_pick - 1 ))]}"
  printf '  %s[✔]%s Using %s%snmap.txt%s\n\n' \
    "${GREEN}" "${RESET}" "${DIM}" "$_pnf_dir" "${RESET}" >&2
  printf '%s|%snmap.txt' "${_pnf_dir%/}" "$_pnf_dir"
}

# prompt_target
# Prints the chosen target network CIDR or IP.
# Pipeline chain priority:
#   1. $TARGET env var (set by pipeline runner)
#   2. $SESSION_DIR/alive_hosts.txt if it exists and TARGET is broad CIDR (pipeline chaining)
#   3. Interactive interface selection
prompt_target() {
  if [[ -n "${TARGET:-}" ]]; then
    # In pipeline mode: if alive_hosts.txt exists and TARGET is a /24 or larger CIDR,
    # return the alive hosts file path so tools can target only discovered IPs.
    # Individual scripts check for alive_hosts.txt themselves; prompt_target returns TARGET.
    echo "$TARGET"
    return
  fi

  echo "${YELLOW}[?] Target selection:${RESET}" >&2

  # Build list of active interfaces
  local -a iface_arr=()
  local -a net_arr=()
  local idx=1

  while IFS=$'\t' read -r _iface _net; do
    [[ -z "$_iface" || -z "$_net" ]] && continue
    iface_arr+=("$_iface")
    net_arr+=("$_net")
    local _host
    _host=$(get_ip "$_iface")
    echo "    ${idx}) ${_iface} — ${_host} → ${_net}" >&2
    (( idx++ ))
  done < <(list_ifaces 2>/dev/null)

  echo "    ${idx}) Enter manually" >&2
  read -rp "    Choice [1]: " _choice 
  _choice="${_choice:-1}"

  if [[ "$_choice" == "$idx" ]] || [[ "$_choice" == "m" ]]; then
    read -rp "    Enter IP or CIDR (e.g. 192.168.1.0/24 or 10.0.0.5): " _manual 
    echo "$_manual"
  elif [[ "$_choice" =~ ^[0-9]+$ ]] && (( _choice >= 1 && _choice < idx )); then
    echo "${net_arr[$((_choice - 1))]}"
  else
    # Fallback: first detected network, or manual
    if [[ ${#net_arr[@]} -gt 0 ]]; then
      echo "${net_arr[0]}"
    else
      read -rp "    No interfaces detected. Enter target manually: " _manual 
      echo "$_manual"
    fi
  fi
}
