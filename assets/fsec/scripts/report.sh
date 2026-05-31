#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

_BASE="$(cd "$(dirname "$0")/.." && pwd)"

banner "REPORT GENERATOR" "compile scan results into a professional HTML pentest report"

require_tool python3 "apt install python3"

# ── Session selection ─────────────────────────────────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  SESSION_DIR="${SESSION_DIR%/}"
  if [[ ! -d "$SESSION_DIR" ]]; then
    printf '  %s[!] SESSION_DIR not found: %s%s\n\n' "${RED}" "$SESSION_DIR" "${RESET}"
    exit 1
  fi
  SESSION_NAME="${SESSION_DIR##*/}"
  REPORT_FILE="${SESSION_DIR}/report.html"
else
  _RESULTS_SEARCH="${_BASE}/results${PROJECT_SLUG:+/$PROJECT_SLUG}"
  mapfile -t SESSIONS < <(ls -1dt "$_RESULTS_SEARCH/"*/ 2>/dev/null || true)

  if [[ ${#SESSIONS[@]} -eq 0 ]]; then
    printf '  %s[!] No scan sessions found in results/.%s\n\n' "${RED}" "${RESET}"
    exit 0
  fi

  printf '  %s[+]%s Available sessions:\n\n' "${GREEN}" "${RESET}"
  printf '  %s  %-4s  %-26s  %s%s\n' "${DIM}" "ID" "SESSION" "FILES" "${RESET}"
  printf '  %s  ──── ────────────────────────── ─────%s\n' "${DIM}" "${RESET}"
  for i in "${!SESSIONS[@]}"; do
    _d="${SESSIONS[$i]}"
    _ts="${_d%/}"; _ts="${_ts##*/}"
    _fc=$(find "$_d" -maxdepth 1 \( -name "*.txt" -o -name "*.log" \) -not -name ".*.txt" 2>/dev/null | wc -l)
    printf '  %s[%02d]%s  %-26s  %d file(s)\n' \
      "${CYAN}" "$(( i + 1 ))" "${RESET}" "$_ts" "$_fc"
  done

  printf '\n  %s>>%s Select session [1]: ' "${CYAN}" "${RESET}"
  read -r _pick  || _pick="1"
  _pick="${_pick:-1}"

  if ! [[ "$_pick" =~ ^[0-9]+$ ]] || (( _pick < 1 || _pick > ${#SESSIONS[@]} )); then
    printf '  %s[!] Invalid selection.%s\n' "${RED}" "${RESET}"
    exit 1
  fi

  SESSION_DIR="${SESSIONS[$(( _pick - 1 ))]%/}"
  SESSION_NAME="${SESSION_DIR##*/}"
  REPORT_FILE="${SESSION_DIR}/report.html"
fi

printf '\n  %s[SYS]%s Session : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$SESSION_NAME" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$REPORT_FILE" "${RESET}"

section "GENERATING REPORT"
printf '  %s[*]%s Parsing + correlating findings...%s\n\n' "${CYAN}" "${RESET}" "${RESET}"

# ── Delegate all parsing and HTML generation to Python ────────────────────────
python3 - "$SESSION_DIR" "$SESSION_NAME" "$REPORT_FILE" << 'PYEOF'
import sys, os, re, html, json
from pathlib import Path
from datetime import datetime

session_dir  = Path(sys.argv[1])
session_name = sys.argv[2]
out_file     = sys.argv[3]

# ── Data model ────────────────────────────────────────────────────────────────
hosts = {}

def get_host(ip):
    if ip not in hosts:
        hosts[ip] = dict(type='Unknown', ports=[], ssl=[], vulns=[],
                         creds=[], warnings=[], probes=[], sources=set())
    return hosts[ip]

IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
ANSI  = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|\[[0-9;]*m|\[[\d;]+m')

def strip_ansi(s):
    return ANSI.sub('', s)

# ── Load all .txt + .log files ────────────────────────────────────────────────
file_data = {}
for fp in sorted(list(session_dir.glob('*.txt')) + list(session_dir.glob('*.log'))):
    try:
        file_data[fp.name] = fp.read_text(errors='replace')
    except Exception:
        pass

# ── Parser: iot_scada.txt ─────────────────────────────────────────────────────
for fname, raw in file_data.items():
    if 'iot_scada' not in fname:
        continue
    content = strip_ansi(raw)
    dev_blocks = re.split(r'-{20,}', content)
    for block in dev_blocks:
        ip_m   = re.search(r'IP Address\s*:\s*(\S+)', block)
        type_m = re.search(r'Device Type\s*:\s*(.+)', block)
        if not ip_m:
            continue
        ip = ip_m.group(1).strip()
        h  = get_host(ip)
        h['sources'].add(fname)
        if type_m:
            h['type'] = type_m.group(1).strip()
        in_ports = False
        for line in block.splitlines():
            if 'Open TCP Ports' in line:
                in_ports = True; continue
            if in_ports:
                pm = re.match(r'\s+(\d+)\s+/tcp\s*(\S*)\s*([^\n]*)', line)
                if pm:
                    svc   = pm.group(2).strip()
                    ver   = pm.group(3).strip()
                    entry = f"{pm.group(1)}/tcp  {svc} {ver}".strip()
                    if entry not in h['ports']:
                        h['ports'].append(entry)
                elif not line.strip() or 'Protocol' in line or ':' in line:
                    in_ports = False
        for pm in re.finditer(r'\[([A-Z_\-]+)\]\s*\n((?:[ \t]+.+\n)*)', block):
            name = pm.group(1)
            data = pm.group(2).strip()
            if data:
                h['probes'].append(f"[{name}] {data[:120]}")
        for vm in re.finditer(r'vendor:\s*(\S+)', block, re.IGNORECASE):
            h['probes'].append(f"[VENDOR] {vm.group(1)}")

# ── Parser: ssl.txt ───────────────────────────────────────────────────────────
for fname, raw in file_data.items():
    if 'ssl' not in fname:
        continue
    content = strip_ansi(raw)
    for bm in re.finditer(r'===\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+===(.*?)(?====|\Z)', content, re.DOTALL):
        ip   = bm.group(1)
        port = bm.group(2)
        blk  = bm.group(3)
        h = get_host(ip)
        h['sources'].add(fname)
        issues = []
        if re.search(r'TLS 1\.1.*offered.*deprecated', blk, re.I):
            issues.append('TLS 1.1 deprecated')
        if re.search(r'TLS 1\s+.*offered.*deprecated', blk, re.I):
            issues.append('TLS 1.0 deprecated')
        if re.search(r'Triple DES.*offered', blk, re.I):
            issues.append('3DES offered')
        if re.search(r'self signed', blk, re.I):
            issues.append('self-signed cert')
        if re.search(r'>= 10 years is way too long', blk, re.I):
            issues.append('cert validity >10 years')
        if re.search(r'Strict Transport Security.*not offered', blk, re.I):
            issues.append('HSTS missing')
        if re.search(r'Chain of trust.*NOT ok', blk, re.I):
            issues.append('broken chain of trust')
        for vm in re.finditer(r'(Heartbleed|POODLE|BEAST|CRIME|ROBOT|FREAK|LOGJAM|DROWN|SWEET32|CVE-\d+-\d+)\s+([^\n]+)', blk, re.I):
            name  = vm.group(1)
            state = vm.group(2)
            if 'VULNERABLE' in state.upper() and 'NOT VULNERABLE' not in state.upper():
                h['vulns'].append(f"SSL CVE — {name} on {ip}:{port}")
        if issues:
            h['warnings'].extend([f"{i} ({ip}:{port})" for i in issues])
        if port not in [s['port'] for s in h['ssl']]:
            h['ssl'].append({'port': port, 'issues': issues})

# ── Parser: nmap.txt ──────────────────────────────────────────────────────────
for fname, raw in file_data.items():
    if 'nmap' not in fname:
        continue
    content = strip_ansi(raw)
    for bm in re.finditer(r'Nmap scan report for (\S+)\n(.*?)(?=Nmap scan report|\Z)', content, re.DOTALL):
        target = bm.group(1)
        blk    = bm.group(2)
        ipm    = IP_RE.search(target)
        if not ipm:
            continue
        ip = ipm.group(1)
        h  = get_host(ip)
        h['sources'].add(fname)
        for pm in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*?)$', blk, re.MULTILINE):
            entry = f"{pm.group(1)}/tcp  {pm.group(2)} {pm.group(3).strip()}".rstrip()
            if entry not in h['ports']:
                h['ports'].append(entry)
        # OS detection
        os_m = re.search(r'OS details:\s*(.+)', blk)
        if os_m:
            h['type'] = os_m.group(1).strip()[:60]

# ── Parser: fscan output ──────────────────────────────────────────────────────
for fname, raw in file_data.items():
    if 'fscan' not in fname:
        continue
    content = strip_ansi(raw)
    for line in content.splitlines():
        l = line.strip()
        # [*] open IP:PORT  or  [+] IP:PORT   service
        m = re.match(r'\[[\*\+]\]\s+(?:open\s+)?(\d+\.\d+\.\d+\.\d+):(\d+)', l)
        if m:
            ip   = m.group(1)
            port = m.group(2)
            h    = get_host(ip)
            h['sources'].add(fname)
            svc  = l.split()[-1] if len(l.split()) > 3 else ''
            entry = f"{port}/tcp  {svc}".strip()
            if entry not in h['ports']:
                h['ports'].append(entry)
        # [+] IP   [service] title
        m2 = re.match(r'\[\+\]\s+(\d+\.\d+\.\d+\.\d+)\s+\[([^\]]+)\]', l)
        if m2:
            ip  = m2.group(1)
            svc = m2.group(2)
            h   = get_host(ip)
            h['sources'].add(fname)
            h['probes'].append(f"[{svc.upper()}] detected")
        # Credential lines
        if ('Login:' in l or 'password:' in l.lower()) and IP_RE.search(l):
            ipm = IP_RE.search(l)
            if ipm:
                h = get_host(ipm.group(1))
                h['creds'].append(l)

# ── Parser: masscan output ────────────────────────────────────────────────────
for fname, raw in file_data.items():
    if 'masscan' not in fname:
        continue
    content = strip_ansi(raw)
    for line in content.splitlines():
        # Host: IP () Ports: PORT/open/tcp//service///
        m = re.match(r'Host:\s+(\d+\.\d+\.\d+\.\d+).*?Ports:\s+(\d+)/open/(\w+)//([^/]*)', line)
        if m:
            ip, port, proto, svc = m.group(1), m.group(2), m.group(3), m.group(4).strip()
            h = get_host(ip)
            h['sources'].add(fname)
            entry = f"{port}/{proto}  {svc}".strip()
            if entry not in h['ports']:
                h['ports'].append(entry)
        # Discovered open port: PORT/tcp on IP
        m2 = re.match(r'Discovered open port (\d+)/(\w+) on (\d+\.\d+\.\d+\.\d+)', line)
        if m2:
            port, proto, ip = m2.group(1), m2.group(2), m2.group(3)
            h = get_host(ip)
            h['sources'].add(fname)
            entry = f"{port}/{proto}"
            if entry not in h['ports']:
                h['ports'].append(entry)

# ── Parser: nuclei.txt ────────────────────────────────────────────────────────
nuclei_findings = []  # {sev, cvss, ip, line} for dedicated section
_CVSS_RANGE = {'critical': '9.0–10.0', 'high': '7.0–8.9',
               'medium': '4.0–6.9',   'low': '0.1–3.9', 'info': '—'}
# Service-detection template keywords — not actual vulnerabilities
_DETECT_PATTERNS = re.compile(
    r'\[(ssh|ftp|http|smtp|rdp|vnc|telnet|snmp|dns|ntp|ldap|smb|'
    r'mssql|mysql|mongodb|redis|elasticsearch|memcached|'
    r'tech-detect|ssl-dns-names|server-detect|service-detect|'
    r'ssl-certificate|mx-detect|dns-resolve)\b',
    re.I)
for fname, raw in file_data.items():
    if 'nuclei' not in fname:
        continue
    content = strip_ansi(raw)
    for line in content.splitlines():
        sm = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
        im = IP_RE.search(line)
        if sm and im:
            sev = sm.group(1).lower()
            ip  = im.group(1)
            h   = get_host(ip)
            h['sources'].add(fname)
            cve_m = re.search(r'CVE-\d{4}-\d+', line, re.I)
            cve   = cve_m.group(0).upper() if cve_m else ''
            nuclei_findings.append({'sev': sev, 'cvss': _CVSS_RANGE.get(sev,'—'),
                                    'ip': ip, 'line': line.strip(), 'cve': cve})
            # Only flag as vuln if it looks like an actual exploit/CVE/misconfiguration,
            # not a bare service-detection hit
            is_detection_only = bool(_DETECT_PATTERNS.search(line)) and not cve and \
                not re.search(r'default.?(login|password|cred)|rce|injection|'
                              r'sqli|xss|lfi|rfi|backdoor|misconfigur|exposed|'
                              r'leak|disclosure|bypass|takeover|exploit', line, re.I)
            if sev in ('critical', 'high') and not is_detection_only:
                h['vulns'].append(line.strip())
            elif sev == 'medium' and not is_detection_only:
                h['warnings'].append(line.strip())
            elif is_detection_only:
                # Downgrade detection-only to probe info
                h['probes'].append(f'[NUCLEI] {line.strip()[:100]}')

# ── Parser: impacket / secretsdump ───────────────────────────────────────────
secretsdump_hashes = []   # (user, rid, lm, ntlm, source)
for fname, raw in file_data.items():
    if not any(k in fname.lower() for k in ('impacket','secret','dump','sam','ntds')):
        continue
    content = strip_ansi(raw)
    for line in content.splitlines():
        l = line.strip()
        # SAM / NTDS format: username:RID:LMhash:NThash:::
        m = re.match(r'^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::', l)
        if m:
            user, rid, lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
            secretsdump_hashes.append({'user': user, 'rid': rid, 'lm': lm,
                                        'ntlm': nt, 'source': fname})
        # [*] Dumping local SAM hashes / [*] Dumping Domain Credentials
        elif re.search(r'Dumping|dumping', l):
            ipm = IP_RE.search(l)
            if ipm:
                h = get_host(ipm.group(1))
                h['sources'].add(fname)
                h['probes'].append('[SECRETSDUMP] hash dump executed')

# ── Parser: WPScan output ─────────────────────────────────────────────────────
wpscan_finds = []   # {target, type, detail}
for fname, raw in file_data.items():
    if 'wpscan' not in fname.lower() and 'wordpress' not in fname.lower():
        continue
    content = strip_ansi(raw)
    target_m = re.search(r'Target URL\s*:\s*(\S+)', content, re.I)
    target   = target_m.group(1) if target_m else fname
    for line in content.splitlines():
        l = line.strip()
        # [!] Title: ...  [+] Name: ...  [i] Version: ...
        m = re.match(r'\[(!|\+|i)\]\s+(?:Title|Name|Plugin|User|Version|Vulnerability):\s*(.+)', l, re.I)
        if m:
            icon = m.group(1)
            detail = m.group(2)
            ftype = 'VULN' if icon == '!' else 'INFO'
            wpscan_finds.append({'target': target, 'type': ftype, 'detail': detail})
        # CVE mentions
        cve_m = re.findall(r'CVE-\d{4}-\d+', l)
        for cve in cve_m:
            wpscan_finds.append({'target': target, 'type': 'CVE', 'detail': f"{cve} — {l[:80]}"})
        # User enumeration
        um = re.match(r'\[\+\]\s+([a-zA-Z0-9_.-]+)\s*\|\s*Roles?:', l)
        if um:
            wpscan_finds.append({'target': target, 'type': 'USER', 'detail': um.group(1)})
        # Vulnerable plugin/theme
        if re.search(r'vulnerable|Outdated', l, re.I) and 'The following' not in l:
            wpscan_finds.append({'target': target, 'type': 'VULN', 'detail': l[:100]})
    # Tag IP as web host
    ipm = IP_RE.search(target)
    if ipm:
        h = get_host(ipm.group(1))
        h['sources'].add(fname)
        h['probes'].append('[WORDPRESS] site scanned')

# ── Parser: SNMP output ───────────────────────────────────────────────────────
snmp_finds = []   # {ip, community, oid, value}
for fname, raw in file_data.items():
    if 'snmp' not in fname.lower():
        continue
    content = strip_ansi(raw)
    for line in content.splitlines():
        l = line.strip()
        # Community string found
        m = re.search(r'Community\s+string\s*[:\=]\s*(\S+)', l, re.I)
        ipm = IP_RE.search(l)
        if m and ipm:
            ip = ipm.group(1)
            community = m.group(1)
            h = get_host(ip)
            h['sources'].add(fname)
            h['warnings'].append(f"SNMP community string: {community} ({ip})")
            snmp_finds.append({'ip': ip, 'community': community, 'detail': l[:100]})
        # OID walk lines (sysDescr, sysName, etc.)
        oid_m = re.search(r'(sysDescr|sysName|sysLocation|ifDescr)\s*[=:]\s*(.+)', l, re.I)
        if oid_m and ipm:
            ip  = ipm.group(1) if ipm else '?'
            h   = get_host(ip)
            h['sources'].add(fname)
            key = oid_m.group(1)
            val = oid_m.group(2).strip()[:80]
            h['probes'].append(f"[SNMP:{key}] {val}")

# ── Parser: credential lines across all files ─────────────────────────────────
for fname, raw in file_data.items():
    content = strip_ansi(raw)
    for line in content.splitlines():
        ll = line.lower()
        im = IP_RE.search(line)
        if not im:
            continue
        ip = im.group(1)
        if ('login:' in ll and 'password:' in ll) or \
           ('[+]' in line and re.search(r'(pass|hash|auth)', ll) and re.search(r'(smb|ssh|ftp|rdp|http)', ll, re.I)):
            h = get_host(ip)
            h['sources'].add(fname)
            if line.strip() not in h['creds']:
                h['creds'].append(line.strip())

# ── Parse pipeline chain files ───────────────────────────────────────────────
# chain_creds.txt: brute-found credentials published by brute.sh / netsniff
chain_creds_raw = []   # all credential lines regardless of IP (for dedicated section)
for chain_f in ['chain_creds.txt', 'chain_hashes.txt', 'chain_dc.txt', 'chain_domain.txt']:
    chain_path = session_dir / chain_f
    if not chain_path.exists():
        continue
    try:
        raw = chain_path.read_text(errors='replace')
    except Exception:
        continue
    file_data[chain_f] = raw
    content = strip_ansi(raw)
    if chain_f == 'chain_creds.txt':
        for line in content.splitlines():
            l = line.strip()
            if not l:
                continue
            chain_creds_raw.append(l)
            im = IP_RE.search(l)
            if im and ('login:' in l.lower() or 'password:' in l.lower()):
                h = get_host(im.group(1))
                h['sources'].add(chain_f)
                if l not in h['creds']:
                    h['creds'].append(l)
    elif chain_f == 'chain_hashes.txt':
        for line in content.splitlines():
            l = line.strip()
            if not l or len(l) < 10:
                continue
            if _NTLM_RE.match(l):
                hashes_found.append((chain_f, l, 'NTLM'))
            elif _NTLMV2_RE.match(l):
                hashes_found.append((chain_f, l, 'NTLMv2'))
            elif _KRB_RE.search(l):
                hashes_found.append((chain_f, l, 'Kerberos'))

# ── Mark IPs from alive_hosts / host list files ───────────────────────────────
for fname, raw in file_data.items():
    if 'alive' not in fname and 'host' not in fname:
        continue
    content = strip_ansi(raw)
    for ip in IP_RE.findall(content):
        h = get_host(ip)
        h['sources'].add(fname)

# ── Global data: hashes, cracked, emails ─────────────────────────────────────
hashes_found  = []
cracked_found = []
emails_found  = []

# NTLM / NTLMv2 / Kerberos hashes
_NTLM_RE   = re.compile(r'^[^:\s]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::')
_NTLMV2_RE = re.compile(r'^[^:\s]+::[^:]+:[a-fA-F0-9]{8,}:[a-fA-F0-9]{8,}:[a-fA-F0-9]+$')
_KRB_RE    = re.compile(r'\$(krb5asrep|krb5tgs)\$', re.I)

for fname, raw in file_data.items():
    content = strip_ansi(raw)
    for line in content.splitlines():
        l = line.strip()
        if not l or l.startswith('#') or len(l) < 10:
            continue
        if _NTLM_RE.match(l):
            hashes_found.append((fname, l, 'NTLM'))
        elif _NTLMV2_RE.match(l):
            hashes_found.append((fname, l, 'NTLMv2'))
        elif _KRB_RE.search(l):
            hashes_found.append((fname, l, 'Kerberos'))

# Cracked passwords (john --show / hashcat)
for fname, raw in file_data.items():
    if 'crack' not in fname.lower():
        continue
    content = strip_ansi(raw)
    for line in content.splitlines():
        l = line.strip()
        if not l or l.startswith('#') or l.startswith('[') or l.startswith('Session'):
            continue
        if ':' in l and len(l) > 5:
            cracked_found.append((fname, l))

# enum4linux: users / shares / password policy
_USER_RE  = re.compile(r'user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]')
_SHARE_RE = re.compile(r'//[\d.]+/(\S+)\s+(?:Disk|IPC)')
_PWLEN_RE = re.compile(r'Minimum\s+[Pp]assword\s+[Ll]ength\s*[:\s]+(\d+)')

for fname, raw in file_data.items():
    if 'enum4linux' not in fname.lower():
        continue
    content = strip_ansi(raw)
    im = IP_RE.search(content)
    if not im:
        continue
    ip = im.group(1)
    h  = get_host(ip)
    h['sources'].add(fname)
    seen_users = set()
    for um in _USER_RE.finditer(content):
        u = um.group(1)
        if u and u not in ('None', '') and u not in seen_users:
            seen_users.add(u)
            h['probes'].append(f'[USER] {u}')
    for sm in _SHARE_RE.finditer(content):
        h['probes'].append(f'[SHARE] {sm.group(1)}')
    for pm in _PWLEN_RE.finditer(content):
        length = int(pm.group(1))
        if length < 8:
            h['warnings'].append(f'Weak password policy: min length {length} ({ip})')

# theHarvester: emails / subdomains
_EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')

for fname, raw in file_data.items():
    if 'harvest' not in fname.lower():
        continue
    content = strip_ansi(raw)
    for em in _EMAIL_RE.findall(content):
        if em not in emails_found:
            emails_found.append(em)

# ── Stats ─────────────────────────────────────────────────────────────────────
total_hosts      = len(hosts)
total_vulns      = sum(len(h['vulns'])    for h in hosts.values())
total_creds      = sum(len(h['creds'])    for h in hosts.values())
total_warns      = sum(len(h['warnings']) for h in hosts.values())
total_ports      = sum(len(h['ports'])    for h in hosts.values())
total_files      = len(file_data)
total_hashes     = len(set(l for _, l, _ in hashes_found))
total_cracked    = len(cracked_found)
total_emails     = len(emails_found)
total_secretdump = len(secretsdump_hashes)
total_wpscan     = len(wpscan_finds)
total_snmp       = len(snmp_finds)

# Overall risk level
if total_vulns > 0 or total_creds > 0 or secretsdump_hashes:
    risk_level = 'CRITICAL'
    risk_color = '#ff3333'
elif total_hashes > 0 or total_warns > 5:
    risk_level = 'HIGH'
    risk_color = '#ff6633'
elif total_warns > 0 or total_wpscan > 0 or total_snmp > 0:
    risk_level = 'MEDIUM'
    risk_color = '#ffaa00'
elif total_hosts > 0:
    risk_level = 'LOW'
    risk_color = '#00cc66'
else:
    risk_level = 'INFO'
    risk_color = '#00ccff'

def host_score(item):
    _, h = item
    return -(len(h['vulns'])*100 + len(h['creds'])*50 + len(h['warnings'])*10 + len(h['ports']))

sorted_hosts = sorted(hosts.items(), key=host_score)

# ── HTML helpers ──────────────────────────────────────────────────────────────
def e(s): return html.escape(str(s))

def colorize_block(text):
    text = strip_ansi(text)
    lines = []
    for ln in text.splitlines():
        esc  = e(ln)
        lo   = esc.lower()
        if ('vulnerable' in lo and 'not vulnerable' not in lo) or 'not ok' in lo:
            lines.append(f'<span class="crit">{esc}</span>')
        elif 'login:' in lo and 'password:' in lo:
            lines.append(f'<span class="crit">{esc}</span>')
        elif re.search(r'\b(critical|high)\b', lo):
            lines.append(f'<span class="crit">{esc}</span>')
        elif ('[+]' in esc or '✔' in esc or '(ok)' in lo or 'not offered (ok)' in lo):
            lines.append(f'<span class="ok">{esc}</span>')
        elif re.search(r'\bmedium\b', lo) or 'deprecated' in lo or 'self signed' in lo or '3des' in lo:
            lines.append(f'<span class="warn">{esc}</span>')
        elif '[~]' in esc or 'expired' in lo or ' weak ' in lo or '[!]' in esc:
            lines.append(f'<span class="warn">{esc}</span>')
        elif '[*]' in esc or '[sys]' in lo or '[info]' in lo:
            lines.append(f'<span class="info">{esc}</span>')
        else:
            lines.append(esc)
    return '\n'.join(lines)

def type_icon(t):
    tl = (t or '').lower()
    if 'camera' in tl or 'cctv' in tl:  return '📷'
    if 'scada' in tl or 'ics'  in tl:   return '⚡'
    if 'iot'   in tl:                   return '◈'
    if 'windows' in tl or 'smb' in tl:  return '⊞'
    if 'linux' in tl or 'unix' in tl:   return '🐧'
    if 'router' in tl or 'cisco' in tl: return '📡'
    return '◉'

def risk_class(h):
    if h['vulns'] or h['creds']:  return 'risk-c', 'CRITICAL'
    if h['warnings']:              return 'risk-w', 'WARN'
    return 'risk-i', 'INFO'

def port_tag(p):
    num = p.split('/')[0].strip()
    return f'<span class="ptag">{e(num)}</span>'

def source_tags(sources):
    tags = []
    for s in sorted(sources):
        name = s.replace('.txt','').replace('.log','').replace('_',' ')
        tags.append(f'<span class="stag">{e(name)}</span>')
    return ' '.join(tags)

def sev_badge(sev):
    colors = {'critical':'#ff3333','high':'#ff6633','medium':'#ffaa00','low':'#4499ff','info':'#556677'}
    col = colors.get(sev.lower(), '#556677')
    return f'<span class="badge" style="color:{col};border-color:{col}">{e(sev.upper())}</span>'

# ── Build recommendations ─────────────────────────────────────────────────────
recommendations = []

if total_vulns > 0:
    recommendations.append(('CRITICAL', 'Remediate confirmed vulnerabilities identified by Nuclei immediately. Prioritize CRITICAL and HIGH findings with CVE scores ≥ 7.0.'))
if total_creds > 0:
    recommendations.append(('CRITICAL', f'{total_creds} credentials were captured. Rotate all affected passwords immediately and enable MFA across all services.'))
if secretsdump_hashes:
    recommendations.append(('CRITICAL', f'{len(secretsdump_hashes)} password hashes were extracted from SAM/NTDS. Force password reset for all domain accounts and implement Protected Users security group.'))
if total_hashes > 0:
    recommendations.append(('HIGH', f'{total_hashes} NTLM/NTLMv2/Kerberos hashes captured. Enable NTLM signing, disable NTLMv1, enforce AES encryption for Kerberos.'))
any_ssl = any(h['ssl'] for h in hosts.values())
if any_ssl:
    recommendations.append(('HIGH', 'SSL/TLS misconfiguration detected. Disable TLS 1.0/1.1, remove 3DES ciphers, enforce HSTS, and use certificates from trusted CAs.'))
weak_policy = any('Weak password policy' in w for h in hosts.values() for w in h['warnings'])
if weak_policy:
    recommendations.append(('HIGH', 'Weak AD password policy detected. Enforce minimum 12 characters, complexity requirements, and account lockout after 5 attempts.'))
if total_snmp > 0:
    recommendations.append(('MEDIUM', f'SNMP community strings discovered ({total_snmp} device(s)). Migrate to SNMPv3 with authentication and encryption. Disable SNMP if not required.'))
if total_wpscan > 0:
    recommendations.append(('MEDIUM', 'WordPress vulnerabilities detected. Keep core, plugins, and themes updated. Remove unused plugins and restrict wp-admin access by IP.'))
if total_emails > 0:
    recommendations.append(('LOW', f'{total_emails} email addresses found via OSINT. Review exposed contact information and implement email address obfuscation on public-facing pages.'))
if total_hosts > 0 and total_vulns == 0:
    recommendations.append(('INFO', 'No confirmed vulnerabilities found. Continue with manual testing and verify scanner coverage is complete.'))

# ── Write HTML ────────────────────────────────────────────────────────────────
now = datetime.now().strftime('%Y-%m-%d %H:%M')

# Build section nav items
nav_items = [
    ('sec-exec',    '◈ EXECUTIVE SUMMARY'),
    ('sec-matrix',  '◉ HOST MATRIX'),
]
if total_vulns > 0 or total_creds > 0:
    nav_items.append(('sec-critical', '▲ CRITICAL FINDINGS'))
if total_warns > 0:
    nav_items.append(('sec-warnings', '◐ WARNINGS'))
if hashes_found:
    nav_items.append(('sec-hashes',   '⚷ CAPTURED HASHES'))
if secretsdump_hashes:
    nav_items.append(('sec-secretsdump', '⊞ SECRETSDUMP'))
if cracked_found:
    nav_items.append(('sec-cracked',  '✓ CRACKED PWDS'))
if chain_creds_raw:
    nav_items.append(('sec-chain-creds', '⇒ PIPELINE CREDS'))
if nuclei_findings:
    nav_items.append(('sec-nuclei',   '⚡ NUCLEI / CVSS'))
if wpscan_finds:
    nav_items.append(('sec-wpscan',   '◈ WORDPRESS'))
if snmp_finds:
    nav_items.append(('sec-snmp',     '◉ SNMP'))
if emails_found:
    nav_items.append(('sec-osint',    '@ OSINT'))
nav_items.append(('sec-hosts',     '◉ HOST DETAILS'))
nav_items.append(('sec-raw',       '≡ RAW OUTPUT'))
if recommendations:
    nav_items.append(('sec-recs',   '► RECOMMENDATIONS'))

with open(out_file, 'w') as f:
    f.write(f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>F-Security Report — {e(session_name)}</title>
<style>
/* ── Variables ── */
:root{{
  --bg:#08090d;--bg2:#0d1117;--bg3:#111820;--bg4:#141c25;
  --bd:#1e2d3d;--bd2:#243040;
  --tx:#8899aa;--tx2:#aabbcc;
  --cy:#00ccff;--cy2:#00aadd;
  --gn:#00cc66;--gn2:#009944;
  --rd:#ff3333;--rd2:#cc2222;
  --or:#ffaa00;--or2:#cc8800;
  --pu:#cc88ff;--pu2:#aa66dd;
  --dim:#3a4a5a;--dim2:#2a3a4a;
}}
/* ── Reset ── */
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--tx);
     font-family:'Courier New',Consolas,monospace;
     font-size:13px;line-height:1.55;padding:0}}

/* ── Sticky top nav ── */
nav{{
  position:sticky;top:0;z-index:100;
  background:rgba(8,9,13,0.96);
  border-bottom:1px solid var(--bd2);
  padding:0 16px;
  display:flex;align-items:center;gap:0;
  overflow-x:auto;white-space:nowrap;
  backdrop-filter:blur(8px);
}}
nav a{{
  color:var(--dim);font-size:0.72em;letter-spacing:0.5px;
  padding:10px 12px;text-decoration:none;
  border-bottom:2px solid transparent;
  transition:color 0.15s,border-color 0.15s;
  flex-shrink:0;
}}
nav a:hover{{color:var(--cy);border-bottom-color:var(--cy)}}
nav .nav-brand{{
  color:var(--cy);font-size:0.85em;font-weight:bold;
  letter-spacing:2px;padding:10px 14px 10px 0;
  border-right:1px solid var(--bd);margin-right:8px;
  flex-shrink:0;
}}
nav .nav-risk{{
  margin-left:auto;padding:4px 10px;
  border-radius:2px;font-size:0.78em;font-weight:bold;
  border:1px solid;letter-spacing:1px;flex-shrink:0;
  color:{risk_color};border-color:{risk_color};
  background:{risk_color}22;
}}

/* ── Page layout ── */
.page{{max-width:1400px;margin:0 auto;padding:20px 20px 40px}}

/* ── Header ── */
header{{
  display:flex;justify-content:space-between;align-items:flex-start;
  flex-wrap:wrap;gap:12px;
  padding:20px 0 16px;
  border-bottom:1px solid var(--bd);margin-bottom:20px;
}}
.hdr-brand{{
  color:var(--cy);font-size:1.3em;font-weight:bold;
  letter-spacing:4px;text-transform:uppercase;
}}
.hdr-sub{{color:var(--dim);font-size:0.78em;margin-top:4px;letter-spacing:1px}}
.hdr-meta{{font-size:0.78em;color:var(--dim);text-align:right}}
.hdr-meta span{{color:var(--cy)}}

/* ── Executive summary ── */
.exec-box{{
  background:var(--bg2);border:1px solid var(--bd);
  border-left:4px solid {risk_color};
  border-radius:4px;padding:16px 20px;margin-bottom:8px;
}}
.exec-risk{{
  font-size:0.7em;letter-spacing:2px;color:{risk_color};
  margin-bottom:6px;display:flex;align-items:center;gap:8px;
}}
.risk-pill{{
  display:inline-block;padding:3px 12px;border-radius:2px;
  font-weight:bold;font-size:1.3em;letter-spacing:2px;
  color:{risk_color};border:1px solid {risk_color};
  background:{risk_color}18;
}}
.exec-summary{{color:var(--tx2);font-size:0.88em;line-height:1.6;margin:10px 0}}
.exec-bullets{{list-style:none;margin-top:8px}}
.exec-bullets li{{
  padding:3px 0;font-size:0.84em;
  display:flex;align-items:flex-start;gap:8px;
}}
.exec-bullets li::before{{content:"▸";color:var(--cy);flex-shrink:0}}

/* ── Stat cards ── */
.cards{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}}
.card{{
  background:var(--bg2);border:1px solid var(--bd);
  border-radius:4px;padding:12px 16px;
  min-width:100px;text-align:center;flex:1;
  transition:border-color 0.2s;
}}
.card:hover{{border-color:var(--bd2)}}
.card .n{{font-size:2em;font-weight:bold;line-height:1;letter-spacing:-1px}}
.card .l{{font-size:0.68em;letter-spacing:1.5px;margin-top:5px;color:var(--dim)}}
.card.r{{border-top:2px solid var(--rd)}}.card.r .n{{color:var(--rd)}}
.card.g{{border-top:2px solid var(--gn)}}.card.g .n{{color:var(--gn)}}
.card.a{{border-top:2px solid var(--or)}}.card.a .n{{color:var(--or)}}
.card.b{{border-top:2px solid var(--cy)}}.card.b .n{{color:var(--cy)}}
.card.p{{border-top:2px solid var(--pu)}}.card.p .n{{color:var(--pu)}}

/* ── Toolbar ── */
.toolbar{{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}}
.toolbar input{{
  background:var(--bg2);border:1px solid var(--bd);color:var(--cy);
  padding:6px 12px;border-radius:3px;font-family:inherit;font-size:0.85em;
  width:220px;outline:none;transition:border-color 0.15s;
}}
.toolbar input:focus{{border-color:var(--cy)}}
.toolbar input::placeholder{{color:var(--dim)}}
button{{
  background:var(--bg2);color:var(--tx);border:1px solid var(--bd);
  padding:6px 13px;cursor:pointer;border-radius:3px;
  font-family:inherit;font-size:0.82em;
  transition:border-color 0.15s,color 0.15s;
}}
button:hover{{border-color:var(--cy);color:var(--cy)}}
.btn-crit{{color:var(--rd);border-color:var(--rd2)}}
.btn-crit:hover{{color:#fff;border-color:var(--rd)}}
.btn-warn{{color:var(--or);border-color:var(--or2)}}
.btn-warn:hover{{color:#fff;border-color:var(--or)}}

/* ── Sections ── */
.sec{{
  background:var(--bg2);border:1px solid var(--bd);
  border-left:3px solid var(--cy);
  border-radius:4px;margin-bottom:10px;overflow:hidden;
}}
.sec.warn-border{{border-left-color:var(--or)}}
.sec.crit-border{{border-left-color:var(--rd)}}
.sec.gn-border{{border-left-color:var(--gn)}}
.sec.pu-border{{border-left-color:var(--pu)}}
.sec h2{{
  background:var(--bg);color:var(--cy);
  padding:9px 14px;font-size:0.82em;letter-spacing:2px;
  border-bottom:1px solid var(--bd);
  cursor:pointer;user-select:none;
  display:flex;justify-content:space-between;align-items:center;
  transition:background 0.15s;
}}
.sec h2:hover{{background:var(--bg3)}}
.sec h2::before{{content:"▶ "}}
.sec.col h2::before{{content:"▷ "}}
.sec-body{{padding:14px 16px}}
.sec.col .sec-body{{display:none}}
.sec-badge{{
  font-size:0.78em;font-weight:normal;
  color:var(--dim);letter-spacing:0;
}}

/* ── Tables ── */
pre{{white-space:pre-wrap;word-break:break-all;font-size:11.5px;line-height:1.45}}
.matrix-wrap{{overflow-x:auto;margin-bottom:4px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{
  background:var(--bg);color:var(--dim);
  padding:7px 10px;text-align:left;
  border-bottom:1px solid var(--bd2);
  font-size:0.75em;letter-spacing:1.5px;white-space:nowrap;
}}
td{{padding:6px 10px;border-bottom:1px solid var(--bd);vertical-align:top}}
tr:hover td{{background:var(--bg4)}}
tr.hide{{display:none}}
.ip-link{{color:var(--cy);text-decoration:none;font-weight:bold}}
.ip-link:hover{{color:#fff;text-decoration:underline}}

/* ── Risk / severity ── */
.risk-c{{color:var(--rd);font-weight:bold;font-size:0.78em;letter-spacing:1px}}
.risk-w{{color:var(--or);font-size:0.78em;letter-spacing:1px}}
.risk-i{{color:var(--dim);font-size:0.78em;letter-spacing:1px}}
.badge{{
  display:inline-block;font-size:0.72em;
  padding:2px 6px;border-radius:2px;
  border:1px solid;margin-right:3px;
  white-space:nowrap;letter-spacing:0.5px;
}}

/* ── Port / source tags ── */
.ptag{{
  display:inline-block;background:var(--bg);
  border:1px solid var(--bd2);
  font-size:0.7em;padding:1px 5px;border-radius:2px;
  color:var(--cy);margin:1px;white-space:nowrap;
}}
.stag{{
  display:inline-block;background:var(--bg);
  border:1px solid var(--bd);
  font-size:0.68em;padding:1px 5px;border-radius:2px;
  color:var(--dim);margin:1px;
}}

/* ── Findings list ── */
.find-list{{list-style:none;padding:0}}
.find-list li{{
  padding:4px 0;border-bottom:1px solid var(--bg4);
  display:flex;gap:10px;align-items:flex-start;
}}
.find-list li:last-child{{border-bottom:none}}
.find-ip{{min-width:110px;color:var(--cy);font-weight:bold;flex-shrink:0;font-size:0.85em}}
.find-txt{{color:var(--tx)}}
.find-txt.crit{{color:var(--rd)}}
.find-txt.warn{{color:var(--or)}}
.find-txt.ok{{color:var(--gn)}}

/* ── Colorizer ── */
.ok{{color:var(--gn)}}.crit{{color:var(--rd);font-weight:bold}}
.warn{{color:var(--or)}}.info{{color:var(--cy)}}

/* ── Host detail cards ── */
.host-card{{
  background:var(--bg3);border:1px solid var(--bd);
  border-radius:4px;padding:12px 16px;margin-bottom:8px;
}}
.hc-ip{{color:var(--cy);font-weight:bold;font-size:1em}}
.hc-type{{color:var(--dim);font-size:0.8em;margin-left:8px}}
.hc-row{{margin-top:5px;font-size:0.82em}}
.hc-label{{color:var(--dim);min-width:82px;display:inline-block;font-size:0.9em}}

/* ── Recommendation cards ── */
.rec-card{{
  background:var(--bg3);border:1px solid var(--bd);
  border-radius:4px;padding:12px 16px;margin-bottom:8px;
  border-left:3px solid var(--cy);
}}
.rec-card.r{{border-left-color:var(--rd)}}
.rec-card.a{{border-left-color:var(--or)}}
.rec-card.b{{border-left-color:var(--cy)}}
.rec-sev{{font-size:0.72em;letter-spacing:1.5px;font-weight:bold;margin-bottom:4px}}
.rec-card.r .rec-sev{{color:var(--rd)}}
.rec-card.a .rec-sev{{color:var(--or)}}
.rec-card.b .rec-sev{{color:var(--cy)}}
.rec-txt{{font-size:0.86em;color:var(--tx2);line-height:1.6}}

/* ── Footer ── */
footer{{
  margin-top:24px;padding-top:12px;
  border-top:1px solid var(--bd);
  color:var(--dim);font-size:0.74em;
  display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px;
}}

/* ── Print ── */
@media print{{
  nav{{display:none}}
  .sec.col .sec-body{{display:block}}
  .sec h2::before{{content:""}}
  body{{font-size:11px;padding:0}}
  .page{{padding:10px}}
  .cards .card{{flex:0 0 130px}}
}}
</style>
</head>
<body>

<!-- Sticky nav -->
<nav>
  <span class="nav-brand">F-SEC</span>
  {''.join(f'<a href="#{nid}">{nlabel}</a>' for nid, nlabel in nav_items)}
  <span class="nav-risk">{risk_level}</span>
</nav>

<div class="page">

<header>
  <div>
    <div class="hdr-brand">▓▒░ F-SECURITY PENTEST REPORT ░▒▓</div>
    <div class="hdr-sub">SESSION: {e(session_name)}</div>
  </div>
  <div class="hdr-meta">
    Generated: <span>{now}</span><br>
    {total_files} source file(s) &nbsp;·&nbsp; {total_hosts} host(s)
  </div>
</header>

<div class="cards">
  <div class="card {'r' if total_vulns else 'b'}">
    <div class="n">{total_vulns}</div><div class="l">VULNERABILITIES</div>
  </div>
  <div class="card {'r' if total_creds else 'b'}">
    <div class="n">{total_creds}</div><div class="l">CREDENTIALS</div>
  </div>
  <div class="card {'r' if total_hashes else 'b'}">
    <div class="n">{total_hashes}</div><div class="l">HASHES</div>
  </div>
  <div class="card {'a' if total_cracked else 'b'}">
    <div class="n">{total_cracked}</div><div class="l">CRACKED</div>
  </div>
  <div class="card {'a' if total_warns else 'b'}">
    <div class="n">{total_warns}</div><div class="l">WARNINGS</div>
  </div>
  <div class="card b">
    <div class="n">{total_ports}</div><div class="l">OPEN PORTS</div>
  </div>
  <div class="card b">
    <div class="n">{total_hosts}</div><div class="l">HOSTS</div>
  </div>
  {'<div class="card r"><div class="n">' + str(total_secretdump) + '</div><div class="l">DUMPED ACCTS</div></div>' if total_secretdump else ''}
  {'<div class="card a"><div class="n">' + str(total_wpscan) + '</div><div class="l">WP FINDINGS</div></div>' if total_wpscan else ''}
  {'<div class="card a"><div class="n">' + str(total_snmp) + '</div><div class="l">SNMP DEVICES</div></div>' if total_snmp else ''}
  {'<div class="card b"><div class="n">' + str(total_emails) + '</div><div class="l">EMAILS (OSINT)</div></div>' if total_emails else ''}
</div>
''')

    # ── Executive Summary ─────────────────────────────────────────────────────
    key_bullets = []
    if total_hosts > 0:
        key_bullets.append(f'{total_hosts} host(s) discovered — {total_ports} open port(s) mapped')
    if total_vulns > 0:
        crits = sum(1 for _, h in sorted_hosts for v in h['vulns'] if 'critical' in v.lower())
        key_bullets.append(f'{total_vulns} vulnerabilities confirmed — {crits} CRITICAL')
    if total_creds > 0:
        key_bullets.append(f'{total_creds} credential(s) captured across services')
    if total_hashes > 0:
        ntlmv2_count = sum(1 for _, _, t in hashes_found if t == 'NTLMv2')
        krb_count    = sum(1 for _, _, t in hashes_found if t == 'Kerberos')
        key_bullets.append(f'{total_hashes} hash(es) intercepted — {ntlmv2_count} NTLMv2, {krb_count} Kerberos')
    if secretsdump_hashes:
        key_bullets.append(f'{len(secretsdump_hashes)} account(s) dumped from SAM/NTDS via Impacket')
    if total_warns > 0:
        key_bullets.append(f'{total_warns} security warning(s) — SSL/TLS, weak policy, misconfig')
    if wpscan_finds:
        key_bullets.append(f'{len(wpscan_finds)} WordPress finding(s) — plugins, users, CVEs')
    if snmp_finds:
        key_bullets.append(f'{len(snmp_finds)} SNMP device(s) with accessible community string(s)')
    if emails_found:
        key_bullets.append(f'{len(emails_found)} email address(es) harvested via OSINT')
    if not key_bullets:
        key_bullets.append('No significant findings in this session — verify scan coverage')

    f.write(f'''
<div class="sec" id="sec-exec">
<h2><span>◈ EXECUTIVE SUMMARY</span>
    <span class="sec-badge">Overall Risk: <strong style="color:{risk_color}">{risk_level}</strong></span></h2>
<div class="sec-body">
<div class="exec-box">
  <div class="exec-risk">OVERALL RISK ASSESSMENT &nbsp; <span class="risk-pill">{risk_level}</span></div>
  <div class="exec-summary">
    Automated penetration testing session <strong style="color:var(--cy)">{e(session_name)}</strong>
    produced the following key findings requiring attention:
  </div>
  <ul class="exec-bullets">
    {''.join(f"<li>{e(b)}</li>" for b in key_bullets)}
  </ul>
</div>
</div></div>
''')

    # ── Toolbar ───────────────────────────────────────────────────────────────
    f.write('''
<div class="toolbar">
  <input type="text" id="ip-filter" placeholder="Filter by IP…" oninput="filterHosts(this.value)">
  <button onclick="filterRisk('crit')" class="btn-crit">▲ CRITICAL</button>
  <button onclick="filterRisk('warn')" class="btn-warn">◐ WARNINGS</button>
  <button onclick="filterRisk('')">ALL HOSTS</button>
  <button onclick="expandAll()">▶ Expand All</button>
  <button onclick="collapseAll()">▷ Collapse All</button>
</div>
''')

    # ── Section: Host Intelligence Matrix ─────────────────────────────────────
    f.write(f'''
<div class="sec" id="sec-matrix">
<h2><span>◉ HOST INTELLIGENCE MATRIX</span>
    <span class="sec-badge">{total_hosts} host(s)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table id="host-table">
<thead><tr>
  <th>IP ADDRESS</th><th>TYPE</th><th>RISK</th><th>OPEN PORTS</th>
  <th>VULNS</th><th>CREDS</th><th>WARN</th><th>SSL</th><th>SOURCES</th>
</tr></thead>
<tbody>
''')
    for ip, h in sorted_hosts:
        rc, rl = risk_class(h)
        ssl_count = sum(len(s['issues']) for s in h['ssl'])
        port_tags = ' '.join(port_tag(p) for p in h['ports'][:14])
        if len(h['ports']) > 14:
            port_tags += f' <span style="color:var(--dim);font-size:0.8em">+{len(h["ports"])-14}</span>'
        row_class = 'data-risk="crit"' if h['vulns'] or h['creds'] else \
                    'data-risk="warn"' if h['warnings'] else 'data-risk="info"'
        f.write(f'''<tr {row_class} data-ip="{e(ip)}">
  <td><a class="ip-link" href="#host-{e(ip.replace(".","_"))}">{e(ip)}</a></td>
  <td style="font-size:0.82em">{type_icon(h["type"])} {e(h["type"][:28])}</td>
  <td><span class="{rc}">{rl}</span></td>
  <td style="max-width:300px">{port_tags if port_tags else '<span style="color:var(--dim)">—</span>'}</td>
  <td style="color:var(--rd);text-align:center">{len(h["vulns"]) or "<span style='color:var(--dim)'>—</span>"}</td>
  <td style="color:var(--gn);text-align:center">{len(h["creds"]) or "<span style='color:var(--dim)'>—</span>"}</td>
  <td style="color:var(--or);text-align:center">{len(h["warnings"]) or "<span style='color:var(--dim)'>—</span>"}</td>
  <td style="color:var(--or);text-align:center;font-size:0.82em">{ssl_count or "<span style='color:var(--dim)'>—</span>"}</td>
  <td>{source_tags(h["sources"])}</td>
</tr>
''')
    f.write('</tbody></table></div></div></div>\n')

    # ── Section: Critical Findings ────────────────────────────────────────────
    all_vulns = [(ip, v) for ip, h in sorted_hosts for v in h['vulns']]
    all_creds = [(ip, c) for ip, h in sorted_hosts for c in h['creds']]
    all_warns = [(ip, w) for ip, h in sorted_hosts for w in h['warnings']]

    if all_vulns or all_creds:
        f.write(f'''
<div class="sec crit-border" id="sec-critical">
<h2><span>▲ CRITICAL FINDINGS</span>
    <span class="sec-badge" style="color:var(--rd)">{len(all_vulns) + len(all_creds)} item(s)</span></h2>
<div class="sec-body">
''')
        if all_vulns:
            f.write('<div style="margin-bottom:12px">\n')
            f.write('<div style="color:var(--rd);font-size:0.78em;letter-spacing:1.5px;margin-bottom:8px">▸ VULNERABILITIES</div>\n')
            f.write('<ul class="find-list">\n')
            for ip, v in all_vulns:
                f.write(f'<li><span class="find-ip">{e(ip)}</span>'
                        f'<span class="find-txt crit">{e(strip_ansi(v))}</span></li>\n')
            f.write('</ul></div>\n')
        if all_creds:
            f.write('<div>\n')
            f.write('<div style="color:var(--gn);font-size:0.78em;letter-spacing:1.5px;margin-bottom:8px">▸ CAPTURED CREDENTIALS</div>\n')
            f.write('<ul class="find-list">\n')
            for ip, c in all_creds:
                f.write(f'<li><span class="find-ip">{e(ip)}</span>'
                        f'<span class="find-txt ok">{e(strip_ansi(c))}</span></li>\n')
            f.write('</ul></div>\n')
        f.write('</div></div>\n')

    if all_warns:
        f.write(f'''
<div class="sec warn-border col" id="sec-warnings">
<h2><span>◐ WARNINGS &amp; ADVISORIES</span>
    <span class="sec-badge" style="color:var(--or)">{len(all_warns)} item(s)</span></h2>
<div class="sec-body"><ul class="find-list">\n''')
        for ip, w in all_warns:
            f.write(f'<li><span class="find-ip">{e(ip)}</span>'
                    f'<span class="find-txt warn">{e(strip_ansi(w))}</span></li>\n')
        f.write('</ul></div></div>\n')

    # ── Section: Nuclei Findings + CVSS ──────────────────────────────────────
    if nuclei_findings:
        sev_order = {'critical':0,'high':1,'medium':2,'low':3,'info':4}
        nuclei_sorted = sorted(nuclei_findings, key=lambda x: sev_order.get(x['sev'],5))
        crit_count = sum(1 for n in nuclei_findings if n['sev'] == 'critical')
        high_count = sum(1 for n in nuclei_findings if n['sev'] == 'high')
        f.write(f'''
<div class="sec crit-border col" id="sec-nuclei">
<h2><span>⚡ NUCLEI SCAN FINDINGS — CVSS SCORES</span>
    <span class="sec-badge" style="color:var(--rd)">{len(nuclei_findings)} finding(s) — {crit_count} critical · {high_count} high</span></h2>
<div class="sec-body">
<div style="margin-bottom:10px;font-size:0.8em;color:var(--dim)">
  CVSS v3.1 base score ranges shown. For exact scores, cross-reference CVE IDs at nvd.nist.gov.</div>
<table>
<thead><tr><th>SEVERITY</th><th>CVSS v3.1</th><th>CVE</th><th>TARGET</th><th>FINDING</th></tr></thead>
<tbody>
''')
        for nf in nuclei_sorted[:500]:
            sev_colors = {'critical':'var(--rd)','high':'var(--or)','medium':'var(--or)','low':'var(--cy)','info':'var(--dim)'}
            col = sev_colors.get(nf['sev'], 'var(--dim)')
            cve_link = f'<a href="https://nvd.nist.gov/vuln/detail/{e(nf["cve"])}" style="color:var(--cy)">{e(nf["cve"])}</a>' if nf['cve'] else '—'
            f.write(f'<tr>'
                    f'<td style="color:{col};font-weight:bold;font-size:0.78em;white-space:nowrap">{e(nf["sev"].upper())}</td>'
                    f'<td style="color:{col};font-size:0.8em;white-space:nowrap">{e(nf["cvss"])}</td>'
                    f'<td style="font-size:0.78em;white-space:nowrap">{cve_link}</td>'
                    f'<td style="color:var(--cy);font-size:0.8em;white-space:nowrap">{e(nf["ip"])}</td>'
                    f'<td style="font-size:0.82em;word-break:break-all">{e(strip_ansi(nf["line"]))}</td>'
                    f'</tr>\n')
        f.write('</tbody></table></div></div>\n')

    # ── Section: Captured Hashes ──────────────────────────────────────────────
    if hashes_found:
        type_counts = {}
        for _, _, t in hashes_found:
            type_counts[t] = type_counts.get(t, 0) + 1
        tc_str = '  '.join(f'{k}:{v}' for k, v in type_counts.items())
        f.write(f'''
<div class="sec crit-border col" id="sec-hashes">
<h2><span>⚷ CAPTURED HASHES</span>
    <span class="sec-badge" style="color:var(--rd)">{len(hashes_found)} hash(es) — {tc_str}</span></h2>
<div class="sec-body">
<div style="margin-bottom:10px;font-size:0.8em;color:var(--dim)">
  Pass to Hash Cracker module → john / hashcat for offline cracking</div>
<table>
<thead><tr><th>TYPE</th><th>HASH</th><th>SOURCE</th></tr></thead>
<tbody>
''')
        for fname, line, htype in hashes_found:
            color = 'var(--rd)' if htype == 'NTLM' else 'var(--or)' if htype == 'NTLMv2' else 'var(--pu)'
            f.write(f'<tr>'
                    f'<td><span style="color:{color};font-weight:bold;font-size:0.8em">{e(htype)}</span></td>'
                    f'<td style="font-size:0.8em;word-break:break-all;color:var(--tx2)">{e(line)}</td>'
                    f'<td><span class="stag">{e(fname)}</span></td>'
                    f'</tr>\n')
        f.write('</tbody></table></div></div>\n')

    # ── Section: Secretsdump / SAM hashes ────────────────────────────────────
    if secretsdump_hashes:
        f.write(f'''
<div class="sec crit-border col" id="sec-secretsdump">
<h2><span>⊞ SECRETSDUMP — EXTRACTED ACCOUNTS</span>
    <span class="sec-badge" style="color:var(--rd)">{len(secretsdump_hashes)} account(s) from SAM/NTDS</span></h2>
<div class="sec-body">
<div style="margin-bottom:10px;font-size:0.8em;color:var(--or)">
  ⚠ These hashes can be used for Pass-the-Hash attacks immediately without cracking</div>
<table>
<thead><tr><th>USERNAME</th><th>RID</th><th>NT HASH</th><th>SOURCE</th></tr></thead>
<tbody>
''')
        for h in secretsdump_hashes:
            aad3 = 'aad3b435b51404eeaad3b435b51404ee'
            empty_lm = h['lm'].lower() == aad3
            f.write(f'<tr>'
                    f'<td style="color:var(--gn);font-weight:bold">{e(h["user"])}</td>'
                    f'<td style="color:var(--dim)">{e(h["rid"])}</td>'
                    f'<td style="color:var(--rd);font-size:0.8em;word-break:break-all">{e(h["ntlm"])}'
                    f'{"<span style=\"color:var(--dim);font-size:0.8em\"> (LM empty)</span>" if empty_lm else ""}</td>'
                    f'<td><span class="stag">{e(h["source"])}</span></td>'
                    f'</tr>\n')
        f.write('</tbody></table></div></div>\n')

    # ── Section: Cracked Passwords ────────────────────────────────────────────
    if cracked_found:
        f.write(f'''
<div class="sec gn-border col" id="sec-cracked">
<h2><span>✓ CRACKED PASSWORDS</span>
    <span class="sec-badge" style="color:var(--gn)">{len(cracked_found)} plaintext password(s)</span></h2>
<div class="sec-body">
<table>
<thead><tr><th>PLAINTEXT CREDENTIAL</th><th>SOURCE FILE</th></tr></thead>
<tbody>
''')
        for fname, line in cracked_found:
            f.write(f'<tr>'
                    f'<td style="color:var(--gn);word-break:break-all;font-weight:bold">{e(line)}</td>'
                    f'<td><span class="stag">{e(fname)}</span></td>'
                    f'</tr>\n')
        f.write('</tbody></table></div></div>\n')

    # ── Section: Pipeline credentials (chain_creds.txt) ───────────────────────
    if chain_creds_raw:
        f.write(f'''
<div class="sec crit-border col" id="sec-chain-creds">
<h2><span>⇒ PIPELINE CAPTURED CREDENTIALS</span>
    <span class="sec-badge" style="color:var(--gn)">{len(chain_creds_raw)} line(s) from chain_creds.txt</span></h2>
<div class="sec-body">
<div style="margin-bottom:8px;font-size:0.8em;color:var(--or)">
  Credentials captured automatically by pipeline modules (brute-force, passive capture, etc.)</div>
<table>
<thead><tr><th>CREDENTIAL LINE</th></tr></thead>
<tbody>
''')
        for cl in chain_creds_raw[:500]:
            f.write(f'<tr><td style="font-size:0.82em;color:var(--gn);word-break:break-all">{e(cl)}</td></tr>\n')
        f.write('</tbody></table></div></div>\n')

    # ── Section: WordPress / WPScan ───────────────────────────────────────────
    if wpscan_finds:
        vuln_wp = [f for f in wpscan_finds if f['type'] in ('VULN','CVE')]
        info_wp = [f for f in wpscan_finds if f['type'] not in ('VULN','CVE')]
        f.write(f'''
<div class="sec warn-border col" id="sec-wpscan">
<h2><span>◈ WORDPRESS FINDINGS</span>
    <span class="sec-badge" style="color:var(--or)">{len(wpscan_finds)} finding(s) — {len(vuln_wp)} vuln(s)</span></h2>
<div class="sec-body">
<table>
<thead><tr><th>SEVERITY</th><th>TARGET</th><th>DETAIL</th></tr></thead>
<tbody>
''')
        for f2 in (vuln_wp + info_wp)[:200]:
            col = 'var(--rd)' if f2['type'] in ('VULN','CVE') else 'var(--cy)' if f2['type'] == 'USER' else 'var(--tx)'
            f.write(f'<tr>'
                    f'<td style="color:{col};font-size:0.78em;font-weight:bold;white-space:nowrap">{e(f2["type"])}</td>'
                    f'<td style="color:var(--dim);font-size:0.8em;white-space:nowrap">{e(f2["target"][:40])}</td>'
                    f'<td style="font-size:0.85em">{e(f2["detail"])}</td>'
                    f'</tr>\n')
        f.write('</tbody></table></div></div>\n')

    # ── Section: SNMP ─────────────────────────────────────────────────────────
    if snmp_finds:
        f.write(f'''
<div class="sec warn-border col" id="sec-snmp">
<h2><span>◉ SNMP — ACCESSIBLE DEVICES</span>
    <span class="sec-badge" style="color:var(--or)">{len(snmp_finds)} device(s) with open SNMP</span></h2>
<div class="sec-body">
<table>
<thead><tr><th>IP ADDRESS</th><th>COMMUNITY STRING</th><th>DETAIL</th></tr></thead>
<tbody>
''')
        for s2 in snmp_finds:
            f.write(f'<tr>'
                    f'<td style="color:var(--cy);font-weight:bold">{e(s2["ip"])}</td>'
                    f'<td style="color:var(--rd)">{e(s2["community"])}</td>'
                    f'<td style="font-size:0.82em;color:var(--tx)">{e(s2["detail"][:80])}</td>'
                    f'</tr>\n')
        f.write('</tbody></table></div></div>\n')

    # ── Section: OSINT Emails ─────────────────────────────────────────────────
    if emails_found:
        f.write(f'''
<div class="sec col" id="sec-osint">
<h2><span>@ OSINT — EMAILS &amp; CONTACTS</span>
    <span class="sec-badge" style="color:var(--cy)">{len(emails_found)} email(s)</span></h2>
<div class="sec-body">
<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px">\n''')
        for em in emails_found:
            f.write(f'<span class="badge" style="color:var(--cy);border-color:var(--cy)">{e(em)}</span>\n')
        f.write('</div></div></div>\n')

    # ── Section: Per-host detail cards ────────────────────────────────────────
    hosts_with_detail = [(ip, h) for ip, h in sorted_hosts
                         if h['ports'] or h['vulns'] or h['creds'] or h['ssl']]
    if hosts_with_detail:
        f.write(f'''
<div class="sec col" id="sec-hosts">
<h2><span>◉ HOST DETAILS</span>
    <span class="sec-badge">{len(hosts_with_detail)} host(s) with data</span></h2>
<div class="sec-body">
''')
        for ip, h in hosts_with_detail:
            anchor = f'host-{ip.replace(".","_")}'
            rc, rl = risk_class(h)
            f.write(f'<div class="host-card" id="{anchor}">\n')
            f.write(f'<span class="hc-ip">{e(ip)}</span>'
                    f'<span class="hc-type">{type_icon(h["type"])} {e(h["type"])}</span>'
                    f'&nbsp;&nbsp;<span class="{rc}">{rl}</span>\n')
            if h['ports']:
                f.write(f'<div class="hc-row"><span class="hc-label">PORTS</span>'
                        + ' '.join(port_tag(p) for p in h['ports']) + '</div>\n')
            if h['ssl']:
                for s3 in h['ssl']:
                    iss = ', '.join(s3['issues']) if s3['issues'] else 'OK'
                    col = 'var(--or)' if s3['issues'] else 'var(--gn)'
                    f.write(f'<div class="hc-row"><span class="hc-label">TLS :{s3["port"]}</span>'
                            f'<span style="color:{col};font-size:0.88em">{e(iss)}</span></div>\n')
            if h['probes']:
                f.write('<div class="hc-row"><span class="hc-label">PROBES</span>'
                        f'<span style="font-size:0.82em;color:var(--dim)">'
                        + ' &nbsp;|&nbsp; '.join(e(p) for p in h['probes'][:8])
                        + '</span></div>\n')
            if h['vulns']:
                for v in h['vulns']:
                    f.write(f'<div class="hc-row" style="color:var(--rd)">'
                            f'<span class="hc-label">VULN</span>{e(strip_ansi(v))}</div>\n')
            if h['creds']:
                for c in h['creds']:
                    f.write(f'<div class="hc-row" style="color:var(--gn)">'
                            f'<span class="hc-label">CRED</span>{e(strip_ansi(c))}</div>\n')
            f.write(f'<div class="hc-row" style="margin-top:5px">'
                    f'<span class="hc-label">SOURCES</span>{source_tags(h["sources"])}</div>\n')
            f.write('</div>\n')
        f.write('</div></div>\n')

    # ── Section: Raw module output ────────────────────────────────────────────
    f.write(f'''
<div class="sec col" id="sec-raw">
<h2><span>≡ RAW MODULE OUTPUT</span>
    <span class="sec-badge">{total_files} file(s)</span></h2>
<div class="sec-body">
''')
    for fname, raw in sorted(file_data.items()):
        lines = raw.count('\n')
        ips_in_file = sorted(set(IP_RE.findall(strip_ansi(raw))))[:8]
        ip_tags = ' '.join(f'<a class="stag" href="#host-{ip.replace(".","_")}" style="color:var(--cy)">{e(ip)}</a>'
                           for ip in ips_in_file)
        has_vuln = bool(re.search(r'vulnerable|NOT ok|CRITICAL|HIGH', raw, re.I))
        has_cred = bool(re.search(r'login:.*password:|password:.*login:', raw, re.I))
        border = ' crit-border' if (has_vuln or has_cred) else ''
        f.write(f'''<div class="sec col{border}" style="margin-bottom:6px">
<h2 style="font-size:0.8em">
  <span style="display:flex;align-items:center;gap:8px">
    <span style="color:var(--cy)">{e(fname)}</span>
    <span style="color:var(--dim);font-size:0.88em">{lines} lines</span>
    <span>{ip_tags}</span>
  </span>
  {"<span style='color:var(--rd);font-size:0.85em'>⚠ findings</span>" if (has_vuln or has_cred) else ""}
</h2>
<div class="sec-body"><pre>{colorize_block(raw)}</pre></div>
</div>
''')
    f.write('</div></div>\n')

    # ── Section: Recommendations ──────────────────────────────────────────────
    if recommendations:
        f.write(f'''
<div class="sec col" id="sec-recs">
<h2><span>► RECOMMENDATIONS</span>
    <span class="sec-badge">{len(recommendations)} action(s)</span></h2>
<div class="sec-body">
''')
        sev_cls = {'CRITICAL': 'r', 'HIGH': 'a', 'MEDIUM': 'b', 'LOW': 'b', 'INFO': 'b'}
        for sev, text in recommendations:
            cls = sev_cls.get(sev, 'b')
            f.write(f'''<div class="rec-card {cls}">
  <div class="rec-sev">{e(sev)}</div>
  <div class="rec-txt">{e(text)}</div>
</div>
''')
        f.write('</div></div>\n')

    # ── Footer + JS ───────────────────────────────────────────────────────────
    f.write(f'''
<footer>
  <span>F-Security Pentest Report &nbsp;·&nbsp; {e(session_name)}</span>
  <span>F-Security NetHunter &nbsp;·&nbsp; {now} &nbsp;·&nbsp; kali-nethunter.com</span>
</footer>

</div><!-- /page -->

<script>
function expandAll()   {{ document.querySelectorAll('.sec').forEach(s=>s.classList.remove('col')); }}
function collapseAll() {{ document.querySelectorAll('.sec').forEach(s=>s.classList.add('col')); }}

document.querySelectorAll('.sec > h2').forEach(h=>{{
  h.addEventListener('click', ()=> h.parentElement.classList.toggle('col'));
}});

function filterHosts(q) {{
  q = q.trim().toLowerCase();
  document.querySelectorAll('#host-table tbody tr').forEach(r => {{
    const ip = (r.dataset.ip || '').toLowerCase();
    r.classList.toggle('hide', q !== '' && !ip.includes(q));
  }});
}}

function filterRisk(level) {{
  document.querySelectorAll('#host-table tbody tr').forEach(r => {{
    if (!level) {{ r.classList.remove('hide'); return; }}
    r.classList.toggle('hide', r.dataset.risk !== level);
  }});
  const fi = document.getElementById('ip-filter');
  if (fi) fi.value = '';
}}

// Highlight active nav section on scroll
const navLinks = document.querySelectorAll('nav a');
const observer = new IntersectionObserver((entries) => {{
  entries.forEach(entry => {{
    if (entry.isIntersecting) {{
      const id = entry.target.id;
      navLinks.forEach(a => {{
        a.style.borderBottomColor = a.href.endsWith('#'+id) ? 'var(--cy)' : 'transparent';
        a.style.color = a.href.endsWith('#'+id) ? 'var(--cy)' : '';
      }});
    }}
  }});
}}, {{ threshold: 0.2, rootMargin: '-60px 0px -70% 0px' }});
document.querySelectorAll('.sec').forEach(s => observer.observe(s));
</script>
</body></html>
''')

print(f"  [+] Report written: {out_file}")
print(f"  [+] Hosts: {total_hosts}  Vulns: {total_vulns}  Creds: {total_creds}  Hashes: {total_hashes}  Risk: {risk_level}")
PYEOF

_py_exit=$?
if [[ $_py_exit -ne 0 ]]; then
  printf '  %s[!] Report generation failed (exit %d).%s\n\n' "${RED}" "$_py_exit" "${RESET}"
  exit 1
fi

_sz=$(du -h "$REPORT_FILE" 2>/dev/null | cut -f1)
printf '\n  %s[✔]%s Report saved — %s%s%s  (%s)\n\n' \
  "${GREEN}" "${RESET}" "${DIM}" "$REPORT_FILE" "${RESET}" "$_sz"

# ── Optional PDF export ───────────────────────────────────────────────────────
PDF_FILE="${REPORT_FILE%.html}.pdf"
if command -v weasyprint &>/dev/null; then
  printf '  %s>>%s Export PDF? [y/N]: ' "${CYAN}" "${RESET}"
  read -r _pdf || _pdf="n"
  if [[ "${_pdf,,}" == "y" ]]; then
    printf '  %s[*]%s Generating PDF...%s\n' "${CYAN}" "${RESET}" "${RESET}"
    weasyprint "$REPORT_FILE" "$PDF_FILE" 2>/dev/null && \
      printf '  %s[✔]%s PDF saved — %s%s%s\n\n' \
        "${GREEN}" "${RESET}" "${DIM}" "$PDF_FILE" "${RESET}" || \
      printf '  %s[!]%s PDF generation failed%s\n\n' "${RED}" "${RESET}" "${RESET}"
  fi
elif command -v chromium &>/dev/null || command -v google-chrome &>/dev/null; then
  _browser=$(command -v chromium 2>/dev/null || command -v google-chrome)
  printf '  %s>>%s Export PDF via Chromium? [y/N]: ' "${CYAN}" "${RESET}"
  read -r _pdf || _pdf="n"
  if [[ "${_pdf,,}" == "y" ]]; then
    printf '  %s[*]%s Generating PDF...%s\n' "${CYAN}" "${RESET}" "${RESET}"
    "$_browser" --headless --no-sandbox --disable-gpu \
      --print-to-pdf="$PDF_FILE" "file://$REPORT_FILE" 2>/dev/null && \
      printf '  %s[✔]%s PDF saved — %s%s%s\n\n' \
        "${GREEN}" "${RESET}" "${DIM}" "$PDF_FILE" "${RESET}" || \
      printf '  %s[!]%s PDF generation failed%s\n\n' "${RED}" "${RESET}" "${RESET}"
  fi
fi

# ── Serve ─────────────────────────────────────────────────────────────────────
printf '  %s>>%s Serve report in browser? [Y/n]: ' "${CYAN}" "${RESET}"
read -r _serve  || _serve="n"
if [[ "${_serve,,}" != "n" ]]; then
  _port=8888
  _ip="$(get_ip)"
  printf '\n'
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  REPORT SERVER                                   │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s[SYS]%s URL  : %shttp://%s:%d/report.html%s\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$_ip" "$_port" "${RESET}"
  printf '  %s[SYS]%s Open this URL on any device on the same network.%s\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  printf '  %s[*]%s Press Ctrl+C to stop the server.\n\n' "${DIM}" "${RESET}"
  cd "$SESSION_DIR" && python3 -m http.server "$_port" 2>/dev/null || true
fi
