#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "FLIPPER ZERO DETECTOR" "BLE scan · OUI 80:E1:26 · continuous watch · by InnerFireZ"

# ── Dependency check ───────────────────────────────────────────────────────────
section "DEPENDENCIES"

if [[ ! -x /usr/sbin/bluebinder ]]; then
  printf '  %s[!]%s bluebinder not found — apt install bluebinder\n' "${RED}" "${RESET}"; exit 1
fi
printf '  %s[✓]%s bluebinder : OK\n' "${GREEN}" "${RESET}"

if [[ ! -x /usr/sbin/bluetoothd ]]; then
  printf '  %s[!]%s bluetoothd not found — apt install bluez\n' "${RED}" "${RESET}"; exit 1
fi
printf '  %s[✓]%s bluetoothd : OK\n\n' "${GREEN}" "${RESET}"

# ── State tracking ─────────────────────────────────────────────────────────────
_BT_STARTED_BLUEBINDER=0
_BT_STARTED_BLUETOOTHD=0
BLUEBINDER_PID=""
BLUETOOTHD_PID=""
_ANDROID_BT_WAS_ON=0

# ── Helpers ────────────────────────────────────────────────────────────────────
_hal_pid()        { pgrep -f 'bluetooth@1.0-service' 2>/dev/null | head -1 || true; }
_bt_app_running() { pgrep -f 'com.android.bluetooth' >/dev/null 2>&1; }
_adb()            { nsenter --mount=/proc/1/ns/mnt -- /system/bin/"$@" 2>/dev/null || true; }
_hci_addr()       { timeout 2 hciconfig hci0 2>/dev/null | grep 'BD Address' | awk '{print $3}'; }

# ── Prepare: free the BT HAL from Android ────────────────────────────────────
_prepare_hal() {
  _bt_app_running && _ANDROID_BT_WAS_ON=1

  printf '  %s[*]%s Blocking BT chip (rfkill)...\n' "${CYAN}" "${RESET}"
  rfkill block bluetooth 2>/dev/null || true
  sleep 1

  printf '  %s[*]%s Stopping Android Bluetooth app...\n' "${CYAN}" "${RESET}"
  _adb am force-stop com.android.bluetooth
  sleep 2

  printf '  %s[*]%s Unblocking BT chip...\n' "${CYAN}" "${RESET}"
  rfkill unblock bluetooth 2>/dev/null || true
  sleep 2
  printf '\n'
}

# ── HAL restart (fallback only) ───────────────────────────────────────────────
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

# ── Start bluebinder ───────────────────────────────────────────────────────────
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
    /usr/sbin/bluebinder >/tmp/bluebinder_flipdet.log 2>&1 &
    BLUEBINDER_PID=$!
    _BT_STARTED_BLUEBINDER=1

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
      printf '  %s[✓]%s bluebinder ready   : hci0  %s%s%s\n' \
        "${GREEN}" "${RESET}" "${CYAN}" "$_addr" "${RESET}"
      return 0
    fi

    printf '  %s[~]%s Attempt %s failed:\n' "${YELLOW}" "${RESET}" "$_attempt"
    tail -4 /tmp/bluebinder_flipdet.log 2>/dev/null | sed 's/^/        /'
    kill "$BLUEBINDER_PID" 2>/dev/null || true
    wait "$BLUEBINDER_PID" 2>/dev/null || true
    BLUEBINDER_PID=""
    _BT_STARTED_BLUEBINDER=0

    (( _attempt == 1 )) && _restart_hal
  done

  printf '  %s[!]%s bluebinder failed after 2 attempts\n' "${RED}" "${RESET}"
  return 1
}

# ── Start dbus ─────────────────────────────────────────────────────────────────
_ensure_dbus() {
  if pgrep -x dbus-daemon >/dev/null 2>&1 && [[ -S /run/dbus/system_bus_socket ]]; then
    printf '  %s[✓]%s dbus                : running\n' "${GREEN}" "${RESET}"
    return 0
  fi
  rm -f /run/dbus/system_bus_socket /run/dbus/pid /var/run/dbus/pid 2>/dev/null || true
  mkdir -p /run/dbus /var/run/dbus
  if [[ -x /etc/init.d/dbus ]]; then
    /etc/init.d/dbus start >/tmp/dbus_flipdet.log 2>&1 || true; sleep 1
  fi
  if ! pgrep -x dbus-daemon >/dev/null 2>&1; then
    dbus-daemon --system --nofork >/tmp/dbus_flipdet.log 2>&1 &
    sleep 2
  fi
  if pgrep -x dbus-daemon >/dev/null 2>&1 && [[ -S /run/dbus/system_bus_socket ]]; then
    printf '  %s[✓]%s dbus                : started\n' "${GREEN}" "${RESET}"
    return 0
  fi
  printf '  %s[!]%s dbus failed to start\n' "${RED}" "${RESET}"
  return 1
}

# ── Start bluetoothd ───────────────────────────────────────────────────────────
_ensure_bluetoothd() {
  if pgrep -x bluetoothd >/dev/null 2>&1; then
    printf '  %s[✓]%s bluetoothd          : already running\n' "${GREEN}" "${RESET}"
    return 0
  fi
  if [[ -x /etc/init.d/bluetooth ]]; then
    /etc/init.d/bluetooth start >/tmp/bluetoothd_flipdet.log 2>&1 || true; sleep 1
  fi
  if ! pgrep -x bluetoothd >/dev/null 2>&1; then
    printf '  %s[*]%s Starting bluetoothd...\n' "${CYAN}" "${RESET}"
    /usr/sbin/bluetoothd --nodetach >/tmp/bluetoothd_flipdet.log 2>&1 &
    BLUETOOTHD_PID=$!
    _BT_STARTED_BLUETOOTHD=1
    sleep 2
  fi
  if ! pgrep -x bluetoothd >/dev/null 2>&1; then
    printf '  %s[!]%s bluetoothd failed\n' "${RED}" "${RESET}"
    return 1
  fi
  printf '  %s[✓]%s bluetoothd          : started\n' "${GREEN}" "${RESET}"
}

# ── Android BT restore ─────────────────────────────────────────────────────────
_android_bt_restore() {
  if (( _ANDROID_BT_WAS_ON == 1 )); then
    printf '  %s[*]%s Restoring Android Bluetooth...\n' "${CYAN}" "${RESET}"
    rfkill unblock bluetooth 2>/dev/null || true
    printf '  %s[✓]%s Android Bluetooth will restore automatically\n' "${GREEN}" "${RESET}"
  fi
}

# ── Full BT stack startup ──────────────────────────────────────────────────────
_bt_start() {
  section "BLUETOOTH SERVICES"

  # Kill stale bluetoothctl sessions from previous runs before checking state.
  # Accumulated scan clients cause bluetoothd to become unresponsive after several runs.
  pkill -x bluetoothctl 2>/dev/null || true
  sleep 0.3

  # Fast path: if hci0 is already up (e.g. Air-BT ran first), skip full init
  local _addr
  _addr=$(_hci_addr)
  if [[ -n "$_addr" && "$_addr" != "00:00:00:00:00:00" ]] \
     && pgrep -x bluetoothd >/dev/null 2>&1 \
     && pgrep -x dbus-daemon >/dev/null 2>&1 \
     && [[ -S /run/dbus/system_bus_socket ]]; then
    # Track existing bluebinder so _bt_stop can clean it up on exit.
    BLUEBINDER_PID=$(pgrep -x bluebinder 2>/dev/null | head -1 || true)
    [[ -n "$BLUEBINDER_PID" ]] && _BT_STARTED_BLUEBINDER=1
    # Flush any leftover scan sessions from previous run.
    timeout 3 bluetoothctl scan off >/dev/null 2>&1 || true
    printf '  %s[✓]%s hci0 already up     : %s%s%s\n' "${GREEN}" "${RESET}" "${CYAN}" "$_addr" "${RESET}"
    printf '  %s[✓]%s bluetoothd          : running\n' "${GREEN}" "${RESET}"
    printf '  %s[✓]%s dbus                : running\n' "${GREEN}" "${RESET}"
    printf '\n'
    return 0
  fi

  # Full init
  _prepare_hal       || return 1
  _start_bluebinder  || return 1

  rfkill unblock bluetooth 2>/dev/null || true

  _ensure_dbus       || return 1
  _ensure_bluetoothd || return 1

  sleep 2
  printf 'power on\nquit\n' | timeout 8 bluetoothctl >/dev/null 2>&1 || true
  sleep 2

  if timeout 5 bluetoothctl show 2>/dev/null | grep -q 'Powered: yes'; then
    printf '  %s[✓]%s Adapter powered on\n' "${GREEN}" "${RESET}"
  else
    hciconfig hci0 up 2>/dev/null || true
    sleep 1
    printf '  %s[~]%s Adapter power via hciconfig fallback\n' "${YELLOW}" "${RESET}"
  fi
  printf '\n'
}

# ── BT stack teardown ──────────────────────────────────────────────────────────
_bt_stop() {
  printf '\n  %s[*]%s Cleaning up BT services...\n' "${CYAN}" "${RESET}"

  # Kill all bluetoothctl processes first so they don't block bluetoothd shutdown.
  pkill -x bluetoothctl 2>/dev/null || true
  sleep 0.3

  if (( _BT_STARTED_BLUETOOTHD == 1 )) && [[ -n "$BLUETOOTHD_PID" ]]; then
    kill "$BLUETOOTHD_PID" 2>/dev/null || true
    wait "$BLUETOOTHD_PID" 2>/dev/null || true
    printf '  %s[-]%s bluetoothd stopped\n' "${CYAN}" "${RESET}"
  fi

  if (( _BT_STARTED_BLUEBINDER == 1 )) && [[ -n "$BLUEBINDER_PID" ]]; then
    kill "$BLUEBINDER_PID" 2>/dev/null || true
    wait "$BLUEBINDER_PID" 2>/dev/null || true
    printf '  %s[-]%s bluebinder stopped\n' "${CYAN}" "${RESET}"
    sleep 2
  fi

  _android_bt_restore
}

# ── Main ───────────────────────────────────────────────────────────────────────
_bt_start || exit 1

FLIPPER_OUI="80:E1:26"

section "CONFIGURATION"

if [[ -n "${SESSION_DIR:-}" ]]; then
  SCAN_INTERVAL=15
  MAX_SCANS=20
  printf '  %s[CHAIN]%s Pipeline mode — interval: %ss, max scans: %s%s\n\n' \
    "${CYAN}" "${RESET}" "$SCAN_INTERVAL" "$MAX_SCANS" "${RESET}"
else
  printf '  %s>>%s Scan interval in seconds [15]: ' "${CYAN}" "${RESET}"
  read -r _interval; SCAN_INTERVAL="${_interval:-15}"

  printf '  %s>>%s Max scans before stopping [0=unlimited]: ' "${CYAN}" "${RESET}"
  read -r _max; MAX_SCANS="${_max:-0}"
fi

outdir="$(make_outdir)"
outfile="$outdir/flippers.txt"
: > "$outfile"

printf '\n  %s[SYS]%s Scanning for Flipper Zero %s(%s)%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "$FLIPPER_OUI" "${RESET}"
printf '  %s[SYS]%s Log: %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf 'Flipper Zero Detector — %s\nOUI: %s\n\n' "$(date)" "$FLIPPER_OUI" >> "$outfile"

_resolve_bt_info() {
  local mac="$1"
  local info; info=$(timeout 5 bluetoothctl info "$mac" 2>/dev/null)
  local name rssi
  name=$(awk -F': ' '/^\s+Name:/{print $2}' <<< "$info" | head -1)
  rssi=$(awk '/^\s+RSSI:/{print $2}' <<< "$info" | head -1)
  # bluetoothctl may give RSSI as signed 32-bit hex (e.g. 0xffffffcc = -52)
  if [[ "$rssi" == 0x* || "$rssi" == 0X* ]]; then
    rssi=$(( rssi ))
    (( rssi > 0x7FFFFFFF )) && rssi=$(( rssi - 0x100000000 ))
  fi
  printf '%s|%s' "${name:-unknown}" "${rssi:-?}"
}

_rssi_label() {
  local r="$1"
  [[ "$r" == "?" ]] && echo "?" && return
  if   (( r >= -60 )); then echo "close"
  elif (( r >= -75 )); then echo "near"
  elif (( r >= -85 )); then echo "medium"
  else                       echo "far"
  fi
}

_log() {
  local msg="$1"
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf '  [%s] %s\n' "$ts" "$msg" | tee -a "$outfile"
}

_cleanup() {
  _bt_stop
  printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
  mark_done "$outdir"
}
trap '_cleanup' EXIT INT TERM

section "SCANNING"
printf '  %s[*]%s Press %sCTRL+C%s to stop\n\n' "${CYAN}" "${RESET}" "${BOLD}" "${RESET}"

_scan_count=0

while true; do
  # Kill any leftover bluetoothctl from previous iteration before starting a new scan.
  pkill -x bluetoothctl 2>/dev/null || true
  # Start a timed scan — timeout exits naturally after SCAN_INTERVAL seconds
  timeout "$SCAN_INTERVAL" bluetoothctl scan on >/dev/null 2>&1 || true
  timeout 5              bluetoothctl scan off >/dev/null 2>&1 || true

  _devices=$(timeout 5 bluetoothctl devices 2>/dev/null | grep -i "^Device $FLIPPER_OUI")

  if [[ -n "$_devices" ]]; then
    while IFS= read -r _line; do
      _mac=$(awk '{print $2}' <<< "$_line")
      _info=$(_resolve_bt_info "$_mac")
      _name="${_info%%|*}"
      _rssi="${_info##*|}"
      _prox=$(_rssi_label "$_rssi")
      printf '  %s[✔] FLIPPER FOUND%s — MAC: %s%s%s  Name: %s%s%s  RSSI: %s%sdBm%s (%s)\n' \
        "${GREEN}" "${RESET}" \
        "${CYAN}" "$_mac" "${RESET}" \
        "${BOLD}" "${_name}" "${RESET}" \
        "${CYAN}" "${_rssi}" "${RESET}" "${_prox}"
      _log "Flipper Device found: MAC: $_mac, Name: ${_name}, RSSI: ${_rssi}dBm (${_prox})"
    done <<< "$_devices"
  fi

  ((_scan_count++))
  [[ "$MAX_SCANS" -gt 0 && "$_scan_count" -ge "$MAX_SCANS" ]] && break

  sleep 3
done
