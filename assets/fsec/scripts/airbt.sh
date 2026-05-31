#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "AIR-BT" "BLE security scanner · GATT enum · CVE match · 65 PoCs"

_AIRBT_DIR="$(cd "$(dirname "$0")/../air-bt" && pwd)"

# ── Dependency check ───────────────────────────────────────────────────────────
section "DEPENDENCIES"

if ! command -v python3 &>/dev/null; then
  printf '  %s[!]%s python3 not found — apt install python3\n' "${RED}" "${RESET}"; exit 1
fi
printf '  %s[✓]%s python3 : Python %s\n' "${GREEN}" "${RESET}" "$(python3 --version 2>&1 | awk '{print $2}')"

printf '  %s[*]%s Checking pip packages (bleak · rich · manuf · cryptography)...\n' \
  "${CYAN}" "${RESET}"

if ! python3 -c "import bleak, rich, manuf, cryptography" 2>/dev/null; then
  printf '  %s[~]%s Missing packages — installing from requirements.txt...\n\n' \
    "${YELLOW}" "${RESET}"
  pip3 install -r "$_AIRBT_DIR/requirements.txt" 2>&1 || {
    printf '  %s[!]%s pip3 install failed — run manually:\n' "${RED}" "${RESET}"
    printf '      pip3 install bleak rich manuf cryptography\n\n'; exit 1
  }
  printf '\n'
fi
printf '  %s[✓]%s pip packages : OK\n\n' "${GREEN}" "${RESET}"

# ── State tracking ─────────────────────────────────────────────────────────────
_BT_STARTED_BLUEBINDER=0
_BT_STARTED_BLUETOOTHD=0
BLUEBINDER_PID=""
BLUETOOTHD_PID=""
_ANDROID_BT_WAS_ON=0
ADAPTER="hci0"

# ── Helpers ────────────────────────────────────────────────────────────────────
_hal_pid()     { pgrep -f 'bluetooth@1.0-service' 2>/dev/null | head -1 || true; }
_bt_app_running() { pgrep -f 'com.android.bluetooth' >/dev/null 2>&1; }

# Run Android command via nsenter (accesses /system/bin from inside the chroot)
_adb() { nsenter --mount=/proc/1/ns/mnt -- /system/bin/"$@" 2>/dev/null || true; }

# Safe hciconfig: 2s timeout prevents kernel hang from locking the phone
_hci_addr() { timeout 2 hciconfig hci0 2>/dev/null | grep 'BD Address' | awk '{print $3}'; }

# ── Prepare: free the BT HAL from Android ─────────────────────────────────────
_prepare_hal() {
  section "BLUETOOTH SERVICES"

  _bt_app_running && _ANDROID_BT_WAS_ON=1

  # Block chip via rfkill — Android BT app can't re-initialize after force-stop
  printf '  %s[*]%s Blocking BT chip (rfkill)...\n' "${CYAN}" "${RESET}"
  rfkill block bluetooth 2>/dev/null || true
  sleep 1

  # Kill Android BT app — stays dead because chip is blocked
  printf '  %s[*]%s Stopping Android Bluetooth app...\n' "${CYAN}" "${RESET}"
  _adb am force-stop com.android.bluetooth
  sleep 2

  # Unblock chip — HAL is now free (app is stopped, chip is powered up)
  printf '  %s[*]%s Unblocking BT chip...\n' "${CYAN}" "${RESET}"
  rfkill unblock bluetooth 2>/dev/null || true
  sleep 2
  printf '\n'
}

# ── Kill and restart the HAL (only used as fallback) ──────────────────────────
_restart_hal() {
  local _old; _old=$(_hal_pid)
  if [[ -n "$_old" ]]; then
    printf '  %s[~]%s Restarting BT HAL (PID %s) — clean state...\n' \
      "${YELLOW}" "${RESET}" "$_old"
    kill -9 "$_old" 2>/dev/null || true
    # Wait for init to restart it
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
  if [[ ! -x /usr/sbin/bluebinder ]]; then
    printf '  %s[!]%s /usr/sbin/bluebinder not found — apt install bluebinder\n' \
      "${RED}" "${RESET}"; return 1
  fi

  # Ensure board-address so bluebinder can set the hci MAC
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

  # Try to start bluebinder; if it fails in 10s, restart the HAL and retry once
  local _attempt
  for _attempt in 1 2; do
    printf '  %s[*]%s Starting bluebinder (attempt %s)...\n' "${CYAN}" "${RESET}" "$_attempt"
    /usr/sbin/bluebinder >/tmp/bluebinder_fsec.log 2>&1 &
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
      ADAPTER="hci0"
      return 0
    fi

    # Failed — kill this bluebinder before retry
    printf '  %s[~]%s Attempt %s failed:\n' "${YELLOW}" "${RESET}" "$_attempt"
    tail -4 /tmp/bluebinder_fsec.log 2>/dev/null | sed 's/^/        /'
    kill "$BLUEBINDER_PID" 2>/dev/null || true
    wait "$BLUEBINDER_PID" 2>/dev/null || true
    BLUEBINDER_PID=""
    _BT_STARTED_BLUEBINDER=0

    if (( _attempt == 1 )); then
      # First attempt failed → restart HAL for a truly clean state, then retry
      _restart_hal
    fi
  done

  printf '  %s[!]%s bluebinder failed after 2 attempts\n' "${RED}" "${RESET}"
  return 1
}

# ── Restore Android BT on exit ─────────────────────────────────────────────────
_android_bt_restore() {
  if (( _ANDROID_BT_WAS_ON == 1 )); then
    printf '  %s[*]%s Restoring Android Bluetooth...\n' "${CYAN}" "${RESET}"
    rfkill unblock bluetooth 2>/dev/null || true
    # bluetooth_on=1 setting is unchanged → Android auto-restarts com.android.bluetooth
    printf '  %s[✓]%s Android Bluetooth will restore automatically\n' "${GREEN}" "${RESET}"
  fi
}

# ── Start dbus ─────────────────────────────────────────────────────────────────
_ensure_dbus() {
  if pgrep -x dbus-daemon >/dev/null 2>&1 && [[ -S /run/dbus/system_bus_socket ]]; then
    printf '  %s[✓]%s dbus                : running\n' "${GREEN}" "${RESET}"
    return 0
  fi
  rm -f /run/dbus/system_bus_socket /run/dbus/pid /var/run/dbus/pid 2>/dev/null || true
  mkdir -p /run/dbus /var/run/dbus
  printf '  %s[*]%s Starting dbus-daemon...\n' "${CYAN}" "${RESET}"
  if [[ -x /etc/init.d/dbus ]]; then
    /etc/init.d/dbus start >/tmp/dbus_fsec.log 2>&1 || true; sleep 1
  fi
  if ! pgrep -x dbus-daemon >/dev/null 2>&1; then
    dbus-daemon --system --nofork >/tmp/dbus_fsec.log 2>&1 &
    sleep 2
  fi
  if pgrep -x dbus-daemon >/dev/null 2>&1 && [[ -S /run/dbus/system_bus_socket ]]; then
    printf '  %s[✓]%s dbus                : started\n' "${GREEN}" "${RESET}"
    return 0
  fi
  printf '  %s[!]%s dbus failed to start\n' "${RED}" "${RESET}"
  tail -4 /tmp/dbus_fsec.log 2>/dev/null | sed 's/^/        /'; printf '\n'
  return 1
}

# ── Start bluetoothd ───────────────────────────────────────────────────────────
_ensure_bluetoothd() {
  if pgrep -x bluetoothd >/dev/null 2>&1; then
    printf '  %s[✓]%s bluetoothd          : already running\n' "${GREEN}" "${RESET}"
    return 0
  fi
  if [[ ! -x /usr/sbin/bluetoothd ]]; then
    printf '  %s[!]%s bluetoothd not found — apt install bluez\n' "${RED}" "${RESET}"; return 1
  fi
  if [[ -x /etc/init.d/bluetooth ]]; then
    /etc/init.d/bluetooth start >/tmp/bluetoothd_fsec.log 2>&1 || true; sleep 1
  fi
  if ! pgrep -x bluetoothd >/dev/null 2>&1; then
    printf '  %s[*]%s Starting bluetoothd...\n' "${CYAN}" "${RESET}"
    /usr/sbin/bluetoothd --nodetach >/tmp/bluetoothd_fsec.log 2>&1 &
    BLUETOOTHD_PID=$!
    _BT_STARTED_BLUETOOTHD=1
    sleep 2
  fi
  if ! pgrep -x bluetoothd >/dev/null 2>&1; then
    printf '  %s[!]%s bluetoothd failed to start\n' "${RED}" "${RESET}"
    tail -4 /tmp/bluetoothd_fsec.log 2>/dev/null | sed 's/^/        /'; printf '\n'; return 1
  fi
  printf '  %s[✓]%s bluetoothd          : started\n' "${GREEN}" "${RESET}"
}

# ── Full BT stack startup ──────────────────────────────────────────────────────
_bt_start() {
  # Kill stale bluetoothctl sessions from previous runs to prevent bluetoothd saturation.
  pkill -x bluetoothctl 2>/dev/null || true
  sleep 0.3

  _prepare_hal       || return 1
  _start_bluebinder  || return 1

  rfkill unblock bluetooth 2>/dev/null || true

  _ensure_dbus       || return 1
  _ensure_bluetoothd || return 1

  # Power on adapter — pipe into bluetoothctl with timeout (never call in a loop)
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
  timeout 3 hciconfig 2>/dev/null | while IFS= read -r _l; do
    printf '  %s%s%s\n' "${DIM}" "$_l" "${RESET}"
  done
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
    # SIGTERM → bluebinder calls HAL.close() cleanly before exiting.
    # Do NOT kill -9 here — abrupt kill leaves HAL in bad state.
    # Do NOT kill the HAL service after — Android will auto-reconnect to the
    # clean HAL without needing a restart.
    kill "$BLUEBINDER_PID" 2>/dev/null || true
    wait "$BLUEBINDER_PID" 2>/dev/null || true
    printf '  %s[-]%s bluebinder stopped\n' "${CYAN}" "${RESET}"
    sleep 2
  fi

  _android_bt_restore
}

# ── Main ───────────────────────────────────────────────────────────────────────
_bt_start || exit 1

section "OPTIONS"

if [[ -n "${SESSION_DIR:-}" ]]; then
  _rssi="-80"; _passive="n"; _timeout=10
  printf '  %s[CHAIN]%s RSSI: -80dBm  Passive: no  Timeout: 10s  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
else
  printf '  %s>>%s RSSI threshold dBm [80]: ' "${CYAN}" "${RESET}"
  read -r _rssi; _rssi="${_rssi:-80}"
  _rssi="-${_rssi#-}"
  printf '  %s>>%s Passive scan only? (no auto-probe) [y/N]: ' "${CYAN}" "${RESET}"
  read -r _passive; _passive="${_passive:-n}"
  printf '  %s>>%s Connection timeout seconds [10]: ' "${CYAN}" "${RESET}"
  read -r _timeout; _timeout="${_timeout:-10}"
fi

outdir="$(make_outdir)"
outfile="$outdir/airbt.json"

printf '\n  %s[SYS]%s Adapter  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$ADAPTER"  "${RESET}"
printf '  %s[SYS]%s RSSI min : %s%s dBm%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_rssi" "${RESET}"
printf '  %s[SYS]%s Output   : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile"  "${RESET}"

_cleanup() {
  _bt_stop
  printf '\n  %s[SYS]%s Results : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
  mark_done "$outdir"
}
trap '_cleanup' EXIT

section "SCANNING"

export COLUMNS="${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}"
export TERM="${TERM:-xterm-256color}"

_AIRBT_ARGS=(-i "$ADAPTER" --rssi "$_rssi" --timeout "$_timeout" --output "$outfile")
[[ "${_passive,,}" == "y" ]] && _AIRBT_ARGS+=(--passive)

printf '  %s[*]%s Starting air-bt — press %sCTRL+C%s to stop scan and pick a target\n\n' \
  "${CYAN}" "${RESET}" "${BOLD}" "${RESET}"

cd "$_AIRBT_DIR"
run_fg python3 main.py "${_AIRBT_ARGS[@]}" || true
