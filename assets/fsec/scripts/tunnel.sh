#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "TUNNEL / PIVOT" "chisel · sshuttle · socat · port forward · SOCKS5 proxy"

# ── Tool detection ─────────────────────────────────────────────────────────────
section "DEPENDENCIES"

_CHISEL=""; _SSHUTTLE=""; _SOCAT=""
command -v chisel    &>/dev/null && _CHISEL="chisel"
command -v sshuttle  &>/dev/null && _SSHUTTLE="sshuttle"
command -v socat     &>/dev/null && _SOCAT="socat"

_any_tunnel=0
_show_t() {
  local n="$1" p="$2"
  if [[ -n "$p" ]]; then
    printf '  %s[✓]%s %-12s available\n' "${GREEN}" "${RESET}" "$n"; _any_tunnel=1
  else
    printf '  %s[~]%s %-12s not found\n' "${YELLOW}" "${RESET}" "$n"
  fi
}
_show_t "chisel"   "$_CHISEL"
_show_t "sshuttle" "$_SSHUTTLE"
_show_t "socat"    "$_SOCAT"
printf '\n'

if (( _any_tunnel == 0 )); then
  printf '  %s[!]%s No tunneling tools found\n' "${RED}" "${RESET}"
  printf '      chisel   : %swget https://github.com/jpillora/chisel/releases/...%s\n' "${DIM}" "${RESET}"
  printf '      sshuttle : %sapt install sshuttle%s\n'   "${DIM}" "${RESET}"
  printf '      socat    : %sapt install socat%s\n'       "${DIM}" "${RESET}"
  exit 1
fi

outdir="$(make_outdir)"
outfile="$outdir/tunnel.log"
: > "$outfile"

_cleanup() {
  printf '\n  %s[*]%s Cleaning up tunnels...\n' "${CYAN}" "${RESET}"
  pkill -f 'chisel\|sshuttle\|socat' 2>/dev/null || true
  mark_done "$outdir"
}
trap '_cleanup' EXIT

# ── Pipeline auto-mode ─────────────────────────────────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  if [[ -z "$_CHISEL" ]]; then
    printf '  %s[!]%s chisel not found — skipping tunnel in pipeline\n' "${RED}" "${RESET}"
    mark_done "$outdir"; trap - EXIT; exit 0
  fi
  LOCAL_IP=$(get_ip)
  _pipe_port=8888
  printf '  %s[CHAIN]%s Pipeline: starting chisel SOCKS5 server on %s:%s (background)\n' \
    "${CYAN}" "${RESET}" "$LOCAL_IP" "$_pipe_port"
  nohup chisel server --port "$_pipe_port" --reverse --socks5 >> "$outfile" 2>&1 &
  _chisel_pid=$!
  sleep 2
  if kill -0 "$_chisel_pid" 2>/dev/null; then
    printf '  %s[+]%s chisel server up — PID %s\n' "${GREEN}" "${RESET}" "$_chisel_pid"
    {
      printf '# chisel SOCKS5 server — pipeline auto-mode\n'
      printf '# PID: %s\n' "$_chisel_pid"
      printf '# Pivot client cmd: chisel client %s:%s socks\n' "$LOCAL_IP" "$_pipe_port"
      printf '# proxychains4.conf: socks5  127.0.0.1  1080\n'
    } >> "$outfile"
    printf 'socks5 127.0.0.1 1080\n' > "${SESSION_DIR}/chain_proxy.txt" 2>/dev/null || true
    printf '# pivot cmd: chisel client %s:%s socks\n' "$LOCAL_IP" "$_pipe_port" \
      >> "${SESSION_DIR}/chain_proxy.txt" 2>/dev/null || true
  else
    printf '  %s[!]%s chisel server failed to start\n' "${RED}" "${RESET}"
  fi
  mark_done "$outdir"; trap - EXIT; exit 0
fi

# ── Pivot mode ─────────────────────────────────────────────────────────────────
section "PIVOT MODE"

[[ -n "$_CHISEL"   ]] && printf '  %s[01]%s Chisel SOCKS5     — client → server SOCKS5 proxy through pivot\n' "${CYAN}" "${RESET}"
[[ -n "$_CHISEL"   ]] && printf '  %s[02]%s Chisel server     — run chisel server on this device\n'            "${CYAN}" "${RESET}"
[[ -n "$_CHISEL"   ]] && printf '  %s[03]%s Chisel reverse    — reverse port forward (pivot calls home)\n'     "${CYAN}" "${RESET}"
[[ -n "$_SSHUTTLE" ]] && printf '  %s[04]%s sshuttle          — transparent proxy through SSH host\n'           "${CYAN}" "${RESET}"
[[ -n "$_SOCAT"    ]] && printf '  %s[05]%s socat port relay  — local port → remote host:port forward\n'       "${CYAN}" "${RESET}"
[[ -n "$_SOCAT"    ]] && printf '  %s[06]%s socat SSL wrap    — wrap a listener with SSL\n'                     "${CYAN}" "${RESET}"
printf '\n  %s>>%s Mode [1]: ' "${CYAN}" "${RESET}"
read -r _mode; _mode="${_mode:-1}"

# ── Chisel SOCKS5 client ───────────────────────────────────────────────────────
_chisel_socks() {
  printf '  %s>>%s Chisel server address (IP:port, e.g. 10.10.10.5:8888): ' "${CYAN}" "${RESET}"
  read -r _srv
  printf '  %s>>%s Local SOCKS5 port [1080]: ' "${CYAN}" "${RESET}"
  read -r _lport; _lport="${_lport:-1080}"
  printf '  %s>>%s Auth (user:pass, blank = none): ' "${CYAN}" "${RESET}"
  read -r _auth_str

  printf '\n  %s[*]%s Connecting to %s%s%s as SOCKS5 client on 127.0.0.1:%s...\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$_srv" "${RESET}" "$_lport"
  printf '  %s[*]%s Route traffic via: %sproxychains4 -q %s%s\n\n' \
    "${CYAN}" "${RESET}" "${DIM}" "<cmd>" "${RESET}"

  local -a _args=(client)
  [[ -n "$_auth_str" ]] && _args+=(--auth "$_auth_str")
  _args+=("$_srv" "socks")

  printf '# proxychains config — add to /etc/proxychains4.conf:\n' >> "$outfile"
  printf 'socks5  127.0.0.1  %s\n\n' "$_lport" >> "$outfile"

  run_fg chisel "${_args[@]}" --proxy "socks5://127.0.0.1:${_lport}" 2>&1 | tee -a "$outfile" || true
}

# ── Chisel server ──────────────────────────────────────────────────────────────
_chisel_server() {
  LOCAL_IP=$(get_ip)
  printf '  %s>>%s Listen port [8888]: ' "${CYAN}" "${RESET}"
  read -r _lport; _lport="${_lport:-8888}"
  printf '  %s>>%s Auth (user:pass, blank = none): ' "${CYAN}" "${RESET}"
  read -r _auth_str

  printf '\n  %s[*]%s Server starting on %s%s:%s%s\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$LOCAL_IP" "$_lport" "${RESET}"
  printf '  %s[*]%s Run on pivot: %schisel client %s:%s socks%s\n\n' \
    "${CYAN}" "${RESET}" "${DIM}" "$LOCAL_IP" "$_lport" "${RESET}"

  local -a _args=(server --port "$_lport" --reverse --socks5)
  [[ -n "$_auth_str" ]] && _args+=(--auth "$_auth_str")

  printf '# chisel server started on %s:%s\n' "$LOCAL_IP" "$_lport" >> "$outfile"

  run_fg chisel "${_args[@]}" 2>&1 | tee -a "$outfile" || true
}

# ── Chisel reverse port forward ────────────────────────────────────────────────
_chisel_reverse() {
  printf '  %s>>%s Chisel server (your listener, IP:port): ' "${CYAN}" "${RESET}"
  read -r _srv
  printf '  %s>>%s Remote host to expose (host:port, e.g. 172.16.0.5:445): ' "${CYAN}" "${RESET}"
  read -r _remote
  printf '  %s>>%s Local port to bind [4445]: ' "${CYAN}" "${RESET}"
  read -r _lport; _lport="${_lport:-4445}"

  printf '\n  %s[*]%s Reverse tunnel: 127.0.0.1:%s → %s via %s\n\n' \
    "${CYAN}" "${RESET}" "$_lport" "$_remote" "$_srv"

  run_fg chisel client "$_srv" "R:${_lport}:${_remote}" 2>&1 | tee -a "$outfile" || true
}

# ── sshuttle ──────────────────────────────────────────────────────────────────
_run_sshuttle() {
  printf '  %s>>%s SSH host (user@ip): '           "${CYAN}" "${RESET}"; read -r _ssh_host
  printf '  %s>>%s Subnets to route (e.g. 10.0.0.0/8 172.16.0.0/12): ' "${CYAN}" "${RESET}"
  read -r _subnets
  printf '  %s>>%s SSH port [22]: '                "${CYAN}" "${RESET}"; read -r _ssh_port; _ssh_port="${_ssh_port:-22}"

  printf '\n  %s[*]%s sshuttle → %s%s%s  subnets: %s\n\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$_ssh_host" "${RESET}" "$_subnets"

  # shellcheck disable=SC2086
  run_fg sshuttle -r "$_ssh_host" -e "ssh -p $_ssh_port -o StrictHostKeyChecking=no" \
    $( [[ -n "$_subnets" ]] && printf '%s' "$_subnets" || printf '0.0.0.0/0' ) \
    2>&1 | tee -a "$outfile" || true
}

# ── socat port relay ───────────────────────────────────────────────────────────
_socat_relay() {
  printf '  %s>>%s Local port to listen on: '       "${CYAN}" "${RESET}"; read -r _lport
  printf '  %s>>%s Remote host: '                   "${CYAN}" "${RESET}"; read -r _rhost
  printf '  %s>>%s Remote port: '                   "${CYAN}" "${RESET}"; read -r _rport

  [[ -z "$_lport" || -z "$_rhost" || -z "$_rport" ]] && {
    printf '  %s[!]%s All fields required\n' "${RED}" "${RESET}"; return; }

  printf '\n  %s[*]%s Relay: 0.0.0.0:%s → %s:%s\n\n' \
    "${CYAN}" "${RESET}" "$_lport" "$_rhost" "$_rport"
  printf '# socat relay 0.0.0.0:%s → %s:%s\n' "$_lport" "$_rhost" "$_rport" >> "$outfile"

  run_fg socat "TCP-LISTEN:${_lport},fork,reuseaddr" "TCP:${_rhost}:${_rport}" \
    2>&1 | tee -a "$outfile" || true
}

# ── socat SSL wrap ─────────────────────────────────────────────────────────────
_socat_ssl() {
  printf '  %s>>%s Local SSL port: '                "${CYAN}" "${RESET}"; read -r _lport
  printf '  %s>>%s Backend host:port (plain): '     "${CYAN}" "${RESET}"; read -r _backend
  printf '  %s>>%s Certificate PEM path %s(blank = generate)%s: ' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  read -r _cert

  if [[ -z "$_cert" ]]; then
    _cert="$outdir/ssl_wrap.pem"
    openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
      -keyout "$_cert" -out "$_cert" \
      -subj "/CN=socat" 2>/dev/null || true
    printf '  %s[*]%s Generated cert: %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_cert" "${RESET}"
  fi

  printf '\n  %s[*]%s SSL wrap: 0.0.0.0:%s → %s\n\n' \
    "${CYAN}" "${RESET}" "$_lport" "$_backend"

  run_fg socat "SSL-LISTEN:${_lport},fork,reuseaddr,cert=${_cert},verify=0" \
    "TCP:${_backend}" 2>&1 | tee -a "$outfile" || true
}

printf '\n'

case "$_mode" in
  1) _chisel_socks ;;
  2) _chisel_server ;;
  3) _chisel_reverse ;;
  4) _run_sshuttle ;;
  5) _socat_relay ;;
  6) _socat_ssl ;;
  *) printf '  %s[!]%s Invalid mode\n' "${RED}" "${RESET}" ;;
esac

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
