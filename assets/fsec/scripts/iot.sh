#!/usr/bin/env bash
# IoT / SCADA / Camera device discovery — wrapper for recon_iot_scada.py
source "$(dirname "$0")/../lib.sh"

SCRIPT_DIR="$(dirname "$0")"
PYFILE="$SCRIPT_DIR/../recon_iot_scada.py"
OUI_FILE="$SCRIPT_DIR/../oui.txt"

require_tool python3 "pkg install python"
require_tool nmap    "pkg install nmap"

if ! python3 -c "import nmap" 2>/dev/null; then
  printf '  %s[!] python-nmap not installed. Run: pip install python-nmap%s\n' "${RED}" "${RESET}"
  exit 1
fi

banner "IoT / SCADA SCANNER" "camera · industrial · embedded device discovery"

target=$(prompt_target)
outdir=$(make_outdir)
outfile="$outdir/iot_scada.txt"

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '\n'

# ── Scan options ──────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  SCAN OPTIONS                                    │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Quick   TCP only, no screenshots  %s(rootless-safe)%s\n'  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[02]%s ▶  Full    TCP + UDP + screenshots   %s(needs root)%s\n'     "${YELLOW}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[03]%s ▶  Custom  enter flags manually\n'                            "${DIM}" "${RESET}"
printf '  %s[04]%s ▶  Tuya    find + probe Tuya IoT devices %s(TCP 6668)%s\n'   "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '\n'

if [[ -n "${SESSION_DIR:-}" ]]; then
  _mode=1  # Quick TCP scan in pipeline mode (rootless-safe)
  printf '  %s[CHAIN]%s Mode: Quick TCP  (pipeline auto-select)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
else
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r _mode
  _mode="${_mode:-1}"
fi

if [[ "$_mode" == "4" ]]; then

# ── Tuya probe ────────────────────────────────────────────────────────────────
section "TUYA IoT PROBE"
printf '  %s[*]%s Scanning %s for TCP 6668 (Tuya local API)...%s\n\n' \
  "${CYAN}" "${RESET}" "$target" "${RESET}"

_nmap_tmp="$outdir/_tuya_nmap.tmp"
run_fg nmap -sT -Pn -n -T4 -p 6668 --open \
  --max-retries 2 --max-scan-delay 10ms \
  -oN "$_nmap_tmp" "$target" 2>/dev/null || true

mapfile -t _tuya_hosts < <(grep "report for" "$_nmap_tmp" 2>/dev/null | awk '{print $NF}')
rm -f "$_nmap_tmp"

if [[ ${#_tuya_hosts[@]} -eq 0 ]]; then
  printf '  %s[!]%s No Tuya devices found (port 6668 closed on all hosts).%s\n\n' \
    "${YELLOW}" "${RESET}" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

printf '  %s[+]%s %d Tuya device(s) on port 6668:\n\n' \
  "${GREEN}" "${RESET}" "${#_tuya_hosts[@]}"

python3 - "${_tuya_hosts[@]}" "$outfile" << 'PYEOF'
import sys, socket, struct, json, binascii

hosts   = sys.argv[1:-1]
outfile = sys.argv[-1]

# Tuya local protocol constants
_PREFIX = 0x000055AA
_SUFFIX = 0x0000AA55
_CMD_STATUS = 0x0A

def _build_pkt(cmd, payload=b''):
    # header: prefix(4) seq(4) cmd(4) len(4) + payload + crc(4) + suffix(4)
    hdr = struct.pack('>IIII', _PREFIX, 0, cmd, len(payload))
    body = hdr + payload
    crc = binascii.crc32(body) & 0xFFFFFFFF
    return body + struct.pack('>II', crc, _SUFFIX)

def probe(ip, port=6668, timeout=4):
    res = {'ip': ip, 'open': False}
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        res['open'] = True
        s.send(_build_pkt(_CMD_STATUS))
        data = b''
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 24:
                    break
        except socket.timeout:
            pass
        s.close()
        res['raw'] = data
        res['bytes'] = len(data)

        # Detect protocol version string embedded in data
        for v in [b'3.5', b'3.4', b'3.3', b'3.2', b'3.1', b'2.0', b'1.0']:
            if v in data:
                res['proto'] = v.decode()
                break

        # Try to parse plaintext JSON (unencrypted / legacy v1/v2 firmware)
        try:
            s2 = data.index(b'{')
            e2 = data.rindex(b'}') + 1
            raw_json = data[s2:e2].decode('utf-8', errors='ignore')
            res['json'] = json.loads(raw_json)
        except Exception:
            pass

        # Parse Tuya header fields if data is long enough
        if len(data) >= 16:
            try:
                prefix, seq, cmd, plen = struct.unpack('>IIII', data[:16])
                if prefix == _PREFIX:
                    res['seq'] = seq
                    res['cmd_reply'] = hex(cmd)
                    res['payload_len'] = plen
            except Exception:
                pass
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        res['error'] = str(e)
    return res

GREEN  = '\033[38;5;47m'
CYAN   = '\033[38;5;51m'
YELLOW = '\033[38;5;226m'
RED    = '\033[38;5;196m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

log_lines = []

for ip in hosts:
    print(f'  {CYAN}[*]{RESET} Probing {GREEN}{ip}:6668{RESET} ...')
    r = probe(ip)

    print(f'  ┌─ {BOLD}{ip}{RESET}:6668')
    if not r['open']:
        print(f'  │  {YELLOW}[~] Port closed / filtered{RESET}')
    else:
        proto = r.get('proto', 'unknown')
        print(f'  │  Status    : {GREEN}OPEN{RESET}')
        print(f'  │  Protocol  : Tuya v{proto}' if proto != 'unknown' else f'  │  Protocol  : {DIM}unknown{RESET}')
        print(f'  │  Response  : {r["bytes"]} bytes')

        if 'json' in r:
            j = r['json']
            print(f'  │  {RED}{BOLD}⚠ PLAINTEXT DATA — unencrypted / legacy firmware{RESET}')
            for k, v in j.items():
                print(f'  │    {CYAN}{k}{RESET}: {v}')
        else:
            enc_note = 'AES-128 GCM' if proto in ('3.4','3.5') else 'AES-128 ECB'
            print(f'  │  Encrypted : {enc_note} — localKey required for control')
            if r.get('payload_len', 0) > 0:
                print(f'  │  Payload   : {r["payload_len"]} bytes')

        # tinytuya hint
        try:
            import tinytuya
            print(f'  │  {GREEN}[+] tinytuya installed — run tinytuya.scan() to extract localKey{RESET}')
        except ImportError:
            print(f'  │  {DIM}[~] pip install tinytuya  → localKey extraction + full device control{RESET}')

    print('  └─')
    print()

    # Log line
    entry = f'[TUYA] {ip}:6668'
    if r['open']:
        entry += f' open proto:{r.get("proto","?")}'
        if 'json' in r:
            entry += f' PLAINTEXT:{json.dumps(r["json"])}'
        if 'error' in r:
            entry += f' error:{r["error"]}'
    else:
        entry += ' closed'
    log_lines.append(entry)

with open(outfile, 'a') as f:
    f.write('\n=== TUYA PROBE RESULTS ===\n')
    for l in log_lines:
        f.write(l + '\n')
PYEOF

printf '  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
mark_done "$outfile"

else

# ── IoT/SCADA recon (options 1–3) ─────────────────────────────────────────────
case "$_mode" in
  1) extra_flags="--no-udp --no-screenshots" ;;
  2) extra_flags="" ;;
  3) printf '  %s>>%s Extra flags: ' "${CYAN}" "${RESET}"
     read -r extra_flags  ;;
  *) extra_flags="--no-udp --no-screenshots" ;;
esac

# ── OUI hint ─────────────────────────────────────────────────────────────────
oui_flag=""
if [[ -f "$OUI_FILE" ]]; then
  oui_flag="--oui-file $OUI_FILE"
  printf '  %s[+]%s OUI database loaded: %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$OUI_FILE" "${RESET}"
fi

printf '\n  %s[*]%s Starting IoT/SCADA scan...%s\n\n' "${CYAN}" "${RESET}" "${RESET}"

# shellcheck disable=SC2086
python3 -u "$PYFILE" "$target" \
  --output "$outfile" \
  $oui_flag \
  $extra_flags \
  | (trap '' SIGINT; tee -a "$outfile")

printf '\n  %s[+]%s Results saved to: %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish discovered IoT device IPs ────────────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "$outfile" ]]; then
  grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$outfile" 2>/dev/null \
    | grep -v '^0\.\|^127\.\|^255\.' | sort -u >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  _ah=$(wc -l < "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || echo 0)
  printf '  %s[CHAIN]%s alive_hosts.txt: %s IoT host(s) added%s\n\n' \
    "${CYAN}" "${RESET}" "$_ah" "${RESET}"
fi

mark_done "$outfile"

fi
