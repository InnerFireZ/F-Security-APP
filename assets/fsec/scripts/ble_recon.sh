#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "BLE RECON" "bettercap ble.recon · live BLE scanner · http-ui dashboard"

# ── Dependency check ───────────────────────────────────────────────────────────
section "DEPENDENCIES"

require_tool bettercap "apt install bettercap"

if [[ ! -x /usr/sbin/bluebinder ]]; then
  printf '  %s[!]%s bluebinder not found — apt install bluebinder\n' "${RED}" "${RESET}"; exit 1
fi
printf '  %s[✓]%s bluebinder : OK\n' "${GREEN}" "${RESET}"

# Check for bettercap UI static files (served by http.server module)
_UI_PATH=""
for _p in /usr/local/share/bettercap/ui /usr/share/bettercap/ui; do
  [[ -d "$_p" ]] && { _UI_PATH="$_p"; break; }
done

if [[ -n "$_UI_PATH" ]]; then
  printf '  %s[✓]%s bettercap UI   : %s%s%s\n\n' "${GREEN}" "${RESET}" "${DIM}" "$_UI_PATH" "${RESET}"
else
  printf '  %s[~]%s bettercap UI files not found — web dashboard may not load\n\n' "${YELLOW}" "${RESET}"
fi

# ── BT state vars ──────────────────────────────────────────────────────────────
_BT_STARTED_BLUEBINDER=0
_BT_STOPPED_BLUETOOTHD=0
BLUEBINDER_PID=""
_ANDROID_BT_WAS_ON=0

# ── BT helpers ─────────────────────────────────────────────────────────────────
_hal_pid()        { pgrep -f 'bluetooth@1.0-service' 2>/dev/null | head -1 || true; }
_bt_app_running() { pgrep -f 'com.android.bluetooth' >/dev/null 2>&1; }
_adb()            { nsenter --mount=/proc/1/ns/mnt -- /system/bin/"$@" 2>/dev/null || true; }
_hci_addr()       { timeout 2 hciconfig hci0 2>/dev/null | grep 'BD Address' | awk '{print $3}'; }

_prepare_hal() {
  _bt_app_running && _ANDROID_BT_WAS_ON=1
  printf '  %s[*]%s Blocking BT chip (rfkill)...\n' "${CYAN}" "${RESET}"
  rfkill block bluetooth 2>/dev/null || true; sleep 1
  printf '  %s[*]%s Stopping Android Bluetooth app...\n' "${CYAN}" "${RESET}"
  _adb am force-stop com.android.bluetooth; sleep 2
  printf '  %s[*]%s Unblocking BT chip...\n' "${CYAN}" "${RESET}"
  rfkill unblock bluetooth 2>/dev/null || true; sleep 2
  printf '\n'
}

_restart_hal() {
  local _old; _old=$(_hal_pid)
  if [[ -n "$_old" ]]; then
    printf '  %s[~]%s Restarting BT HAL (PID %s)...\n' "${YELLOW}" "${RESET}" "$_old"
    kill -9 "$_old" 2>/dev/null || true
    local _i
    for _i in $(seq 1 10); do
      local _new; _new=$(_hal_pid)
      if [[ -n "$_new" && "$_new" != "$_old" ]]; then
        printf '  %s[✓]%s HAL restarted (PID %s)\n' "${GREEN}" "${RESET}" "$_new"
        sleep 2; return 0
      fi
      sleep 1
    done
    printf '  %s[~]%s HAL restart not confirmed — continuing\n' "${YELLOW}" "${RESET}"
    sleep 2
  fi
}

_start_bluebinder() {
  if [[ ! -f /var/lib/bluetooth/board-address ]]; then
    local _mac
    _mac=$(ls /var/lib/bluetooth/ 2>/dev/null \
      | grep -E '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' \
      | grep -iv '^00:00' | sort | tail -1)
    if [[ -n "$_mac" ]]; then
      printf '  %s[*]%s Writing board-address: %s\n' "${CYAN}" "${RESET}" "$_mac"
      mkdir -p /var/lib/bluetooth
      echo "$_mac" > /var/lib/bluetooth/board-address
      chmod 644 /var/lib/bluetooth/board-address
    fi
  fi

  local _attempt
  for _attempt in 1 2; do
    printf '  %s[*]%s Starting bluebinder (attempt %s)...\n' "${CYAN}" "${RESET}" "$_attempt"
    /usr/sbin/bluebinder >/tmp/bluebinder_blerecon.log 2>&1 &
    BLUEBINDER_PID=$!; _BT_STARTED_BLUEBINDER=1

    local _hci_ok=0 _i
    for _i in $(seq 1 12); do
      local _addr; _addr=$(_hci_addr)
      if [[ -n "$_addr" && "$_addr" != "00:00:00:00:00:00" ]]; then
        _hci_ok=1; break
      fi
      printf '\r  %s[*]%s Waiting for hci0... (%ds)' "${CYAN}" "${RESET}" "$_i"
      sleep 1
    done
    printf '\r\033[K'

    if (( _hci_ok == 1 )); then
      local _addr; _addr=$(_hci_addr)
      printf '  %s[✓]%s bluebinder ready : hci0  %s%s%s\n' \
        "${GREEN}" "${RESET}" "${CYAN}" "$_addr" "${RESET}"
      return 0
    fi

    printf '  %s[~]%s Attempt %s failed:\n' "${YELLOW}" "${RESET}" "$_attempt"
    tail -4 /tmp/bluebinder_blerecon.log 2>/dev/null | sed 's/^/        /'
    kill "$BLUEBINDER_PID" 2>/dev/null || true
    wait "$BLUEBINDER_PID" 2>/dev/null || true
    BLUEBINDER_PID=""; _BT_STARTED_BLUEBINDER=0
    (( _attempt == 1 )) && _restart_hal
  done

  printf '  %s[!]%s bluebinder failed after 2 attempts\n' "${RED}" "${RESET}"
  return 1
}

_android_bt_restore() {
  (( _ANDROID_BT_WAS_ON == 1 )) && { rfkill unblock bluetooth 2>/dev/null || true; }
}

# ── BT startup ─────────────────────────────────────────────────────────────────
_bt_start() {
  section "BLUETOOTH INIT"

  # Kill stale bluetoothctl sessions to prevent bluetoothd saturation.
  pkill -x bluetoothctl 2>/dev/null || true
  sleep 0.3

  local _addr; _addr=$(_hci_addr)
  if [[ -n "$_addr" && "$_addr" != "00:00:00:00:00:00" ]]; then
    BLUEBINDER_PID=$(pgrep -x bluebinder 2>/dev/null | head -1 || true)
    [[ -n "$BLUEBINDER_PID" ]] && _BT_STARTED_BLUEBINDER=1
    printf '  %s[✓]%s hci0 already up : %s%s%s\n' "${GREEN}" "${RESET}" "${CYAN}" "$_addr" "${RESET}"
  else
    _prepare_hal    || return 1
    _start_bluebinder || return 1
  fi

  # bettercap ble.recon uses raw HCI sockets — bluetoothd claims the device and blocks access
  if pgrep -x bluetoothd >/dev/null 2>&1; then
    printf '  %s[*]%s Stopping bluetoothd (bettercap needs raw HCI)...\n' "${CYAN}" "${RESET}"
    pkill -x bluetoothd 2>/dev/null || true
    _BT_STOPPED_BLUETOOTHD=1
    sleep 1
    printf '  %s[✓]%s bluetoothd stopped\n' "${GREEN}" "${RESET}"
  fi

  timeout 2 hciconfig hci0 up 2>/dev/null || true
  sleep 0.3

  _addr=$(_hci_addr)
  if [[ -z "$_addr" || "$_addr" == "00:00:00:00:00:00" ]]; then
    printf '  %s[!]%s hci0 not available\n' "${RED}" "${RESET}"; return 1
  fi

  printf '  %s[✓]%s hci0 ready : %s%s%s\n\n' "${GREEN}" "${RESET}" "${CYAN}" "$_addr" "${RESET}"
}

_bt_stop() {
  printf '\n  %s[*]%s Cleaning up...\n' "${CYAN}" "${RESET}"
  pkill -x bluetoothctl 2>/dev/null || true
  sleep 0.3

  if (( _BT_STARTED_BLUEBINDER == 1 )) && [[ -n "$BLUEBINDER_PID" ]]; then
    kill "$BLUEBINDER_PID" 2>/dev/null || true
    wait "$BLUEBINDER_PID" 2>/dev/null || true
    printf '  %s[-]%s bluebinder stopped\n' "${CYAN}" "${RESET}"
    sleep 2
  fi

  if (( _BT_STOPPED_BLUETOOTHD == 1 )); then
    printf '  %s[*]%s Restarting bluetoothd...\n' "${CYAN}" "${RESET}"
    /usr/sbin/bluetoothd --nodetach >/tmp/bluetoothd_blerecon.log 2>&1 &
    sleep 1
    printf '  %s[✓]%s bluetoothd restarted\n' "${GREEN}" "${RESET}"
  fi

  _android_bt_restore
}

# ── Main ───────────────────────────────────────────────────────────────────────
_bt_start || exit 1

outdir="$(make_outdir)"
outfile="$outdir/ble_recon.log"
: > "$outfile"

_cleanup() { _bt_stop; mark_done "$outdir"; }
trap '_cleanup' EXIT INT TERM

# ── Network interface ──────────────────────────────────────────────────────────
section "NETWORK INTERFACE"

mapfile -t _ifaces < <(ip -o link show | awk -F': ' '{print $2}' \
  | grep -v '^lo$' | grep -vE '^(rmnet|r_rmnet|bond|dummy)')

if [[ ${#_ifaces[@]} -eq 0 ]]; then
  printf '  %s[!]%s No network interfaces found\n' "${RED}" "${RESET}"; exit 1
fi

for i in "${!_ifaces[@]}"; do
  _ip=$(ip -o -4 addr show "${_ifaces[$i]}" 2>/dev/null | awk '{print $4}' | head -1)
  printf '  %s[%02d]%s  %-14s  %s%s%s\n' \
    "${CYAN}" "$((i+1))" "${RESET}" "${_ifaces[$i]}" "${DIM}" "${_ip:-no IPv4}" "${RESET}"
done

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="$(resolve_iface any)"
  _user="admina"; _pass="passworda"; _ui_port=80; _api_port=8081
  printf '  %s[CHAIN]%s Interface: %s  Default creds  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "$IFACE" "${RESET}"
else
  printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_ifaces[@]}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_ifaces[@]} )); then
    printf '  %s[!]%s Invalid selection\n' "${RED}" "${RESET}"; exit 1
  fi
  IFACE="${_ifaces[$((_sel-1))]}"
  section "WEB UI CREDENTIALS"
  printf '  %s>>%s Username [admina]: ' "${CYAN}" "${RESET}"
  read -r _user; _user="${_user:-admina}"
  printf '  %s>>%s Password [passworda]: ' "${CYAN}" "${RESET}"
  read -r _pass; _pass="${_pass:-passworda}"
  printf '  %s>>%s UI port   [80]:  ' "${CYAN}" "${RESET}"
  read -r _ui_port; _ui_port="${_ui_port:-80}"
  printf '  %s>>%s API port  [8081]: ' "${CYAN}" "${RESET}"
  read -r _api_port; _api_port="${_api_port:-8081}"
fi

LOCAL_IP=$(ip -o -4 addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
LOCAL_IP="${LOCAL_IP:-127.0.0.1}"

# ── Run ────────────────────────────────────────────────────────────────────────
section "BLE RECON"

printf '  %s[SYS]%s Interface : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf '  %s[SYS]%s Log       : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

printf '\n'
printf '  %s┌─────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  %-45s│%s\n' "${CYAN}" "WEB UI ACCESS" "${RESET}"
printf '  %s├─────────────────────────────────────────────┤%s\n' "${CYAN}" "${RESET}"
printf '  %s│%s  UI      : %shttp://%s:%s%s\n' \
  "${CYAN}" "${RESET}" "${BOLD}" "$LOCAL_IP" "$_ui_port" "${RESET}"
printf '  %s│%s  API     : %shttp://%s:%s%s\n' \
  "${CYAN}" "${RESET}" "${DIM}"  "$LOCAL_IP" "$_api_port" "${RESET}"
printf '  %s│%s  User    : %s%s%s\n' "${CYAN}" "${RESET}" "${YELLOW}" "$_user" "${RESET}"
printf '  %s│%s  Pass    : %s%s%s\n' "${CYAN}" "${RESET}" "${YELLOW}" "$_pass" "${RESET}"
printf '  %s└─────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'

printf '  %s[*]%s Press CTRL+C to stop — bettercap output below\n\n' "${CYAN}" "${RESET}"

# Build eval: replicate http-ui caplet but bind on 0.0.0.0 (reachable over WiFi)
_UI_FILES="${_UI_PATH:-/usr/local/share/bettercap/ui}"
_EVAL="set api.rest.address 0.0.0.0; set api.rest.port $_api_port; set api.rest.username $_user; set api.rest.password $_pass; set http.server.address 0.0.0.0; set http.server.port $_ui_port; set http.server.path $_UI_FILES; api.rest on; http.server on; ble.recon on"

run_fg bettercap -iface "$IFACE" -no-history \
  -eval "$_EVAL" \
  2>&1 | (trap '' SIGINT; tee "$outfile") || true
