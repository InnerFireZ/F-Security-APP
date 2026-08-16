import 'dart:io';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import '../models/project.dart';
import 'nethunter_service.dart';
import 'project_service.dart';

class SessionInfo {
  final String name;     // timestamp folder name only
  final int index;
  final int fileCount;
  final bool hasReport;
  final String? subdir;  // project slug subfolder, null for flat sessions

  const SessionInfo({
    required this.name,
    required this.index,
    required this.fileCount,
    required this.hasReport,
    this.subdir,
  });

  // Relative path from results/ root: "slug/timestamp" or just "timestamp".
  String get fullPath => subdir != null ? '$subdir/$name' : name;
}

class ReportService {
  static String get _resultsPath =>
      '${NetHunterService.chrootPath}${NetHunterService.scriptsPath}/results';

  // ── Session reports (bash-generated) ─────────────────────────────────────

  static Future<List<SessionInfo>> listSessions() async {
    // One single su call: find all session dirs, then for each print
    // "path|filecount|hasreport" — eliminates N round-trips.
    final r = await Process.run('su', ['-c', '''
p="$_resultsPath"
find "\$p" -maxdepth 2 -mindepth 1 -type d 2>/dev/null \\
  | grep -E '/[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}\$' \\
  | sort -r \\
  | while IFS= read -r d; do
      fc=\$(find "\$d" -maxdepth 1 -name "*.txt" 2>/dev/null | wc -l)
      hr=0; [ -f "\$d/report.html" ] && hr=1
      printf '%s|%s|%s\\n' "\$d" "\$fc" "\$hr"
    done
''']);
    final lines = r.stdout.toString().trim().split('\n')
        .where((l) => l.contains('|')).toList();

    final sessions = <SessionInfo>[];
    for (var i = 0; i < lines.length; i++) {
      final parts2 = lines[i].split('|');
      if (parts2.length < 3) continue;
      final absPath = parts2[0].trim();
      final fc      = int.tryParse(parts2[1].trim()) ?? 0;
      final hr      = parts2[2].trim() == '1';
      final rel     = absPath.replaceFirst('$_resultsPath/', '');
      final parts   = rel.split('/');
      final name    = parts.last;
      final subdir  = parts.length == 2 ? parts.first : null;
      sessions.add(SessionInfo(
        name:      name,
        index:     i + 1,
        fileCount: fc,
        hasReport: hr,
        subdir:    subdir,
      ));
    }
    return sessions;
  }

  static Future<bool> generate(SessionInfo session) async {
    final ch = NetHunterService.chrootPath;
    final sp = NetHunterService.scriptsPath;
    // Pass SESSION_DIR so report.sh skips the interactive picker entirely.
    final sessionDirInChroot = NetHunterService.shellQuote('$sp/results/${session.fullPath}');

    final cmd = 'chroot $ch /usr/bin/env -i HOME=/root TERM=dumb PATH=${NetHunterService.linuxPath}'
        ' SESSION_DIR=$sessionDirInChroot'
        ' /bin/bash $sp/scripts/report.sh';

    final process = await Process.start('su', ['-c', cmd]);
    await process.stdin.close();
    // Drain stdout/stderr — a verbose report.sh that fills the ~64KB OS pipe
    // buffer would otherwise block on write and exitCode would never complete.
    final drained = Future.wait([
      process.stdout.drain<void>(),
      process.stderr.drain<void>(),
    ]);
    final code = await process.exitCode;
    await drained;
    return code == 0;
  }

  // sessionFullPath is "slug/timestamp" or just "timestamp" (relative to results/).
  static Future<String> prepareHtmlForView(String sessionFullPath) async {
    final src = '$_resultsPath/$sessionFullPath/report.html';
    final r = await Process.run('su', ['-c', 'cat "$src" 2>/dev/null'],
        stdoutEncoding: null);
    final bytes = r.stdout as List<int>;
    final tmp  = await getTemporaryDirectory();
    final safeId = sessionFullPath.replaceAll('/', '_');
    final dest = File('${tmp.path}/fsec_report_$safeId.html');

    if (bytes.isEmpty) {
      await dest.writeAsString(_errorHtml(
        'Report not found',
        'Could not read<br><code>$src</code><br><br>'
        'Tap <b>GENERATE</b> to (re)create the report,<br>'
        'or check that the session folder exists in the chroot.',
      ));
    } else {
      await dest.writeAsBytes(bytes);
    }
    return dest.path;
  }

  static String _errorHtml(String title, String body) => '''
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$title</title>
<style>
:root{--bg:#0a0c0f;--cy:#00ccff;--rd:#ff3333;--tx:#8899aa;--dim:#3a4a5a}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'Courier New',monospace;
     display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.box{border:1px solid var(--rd);border-left:3px solid var(--rd);
     background:#0f1318;padding:24px 28px;max-width:480px;border-radius:4px}
h1{color:var(--rd);font-size:1em;letter-spacing:2px;margin-bottom:16px}
p{font-size:0.82em;line-height:1.7;color:var(--tx)}
code{color:var(--cy);font-size:0.88em;word-break:break-all}
</style></head><body>
<div class="box">
  <h1>⚠ $title</h1>
  <p>$body</p>
</div>
</body></html>
''';

  static Future<void> shareFile(String chrootPath, String filename) async {
    final r = await Process.run('su', ['-c', 'cat "$chrootPath" 2>/dev/null'],
        stdoutEncoding: null);
    final bytes = r.stdout as List<int>;
    final tmp  = await getTemporaryDirectory();
    final dest = File('${tmp.path}/fsec_export_$filename');
    await dest.writeAsBytes(bytes);
    await Share.shareXFiles([XFile(dest.path)], text: 'F-Security export: $filename');
  }

  // ── Project report (Dart-generated) ──────────────────────────────────────

  static Future<String?> generateProjectReport(Project project) async {
    if (project.id == null) return null;
    try {
      final sessions = await ProjectService.getSessions(project.id!);
      final hosts    = await ProjectService.getHosts(project.id!);
      final creds    = await ProjectService.getCredentials(project.id!);
      final notes    = await ProjectService.getNotes(project.id!);

      // Read raw .txt files from each linked session (one su call per session)
      final rawFiles = <String, Map<String, String>>{};
      for (final s in sessions) {
        rawFiles[s.folderName] = await _readSessionFiles(s.folderName);
      }

      final htmlContent = _buildProjectHtml(project, sessions, hosts, creds, notes, rawFiles);

      final tmp  = await getTemporaryDirectory();
      final dest = File('${tmp.path}/fsec_proj_${project.id}_report.html');
      await dest.writeAsString(htmlContent);
      return dest.path;
    } catch (_) {
      return null;
    }
  }

  // Read all .txt files in a session folder in a single su call
  static Future<Map<String, String>> _readSessionFiles(String folderName) async {
    final dir = '$_resultsPath/$folderName';
    final r = await Process.run('su', ['-c',
      'for f in "$dir"/*.txt; do '
      '  [ -f "\$f" ] || continue; '
      '  echo "<<FSECBND:\$(basename \$f)>>"; '
      '  cat "\$f"; '
      'done 2>/dev/null'
    ]);
    final output = r.stdout.toString();
    final result = <String, String>{};
    // NOTE: use $ for end-of-input, NOT \Z — Dart's RegExp is ECMAScript, where
    // \Z is an identity escape matching a literal 'Z', which truncated content
    // at the first uppercase Z in any file.
    final re = RegExp(r'<<FSECBND:([^>]+)>>\n([\s\S]*?)(?=<<FSECBND:|$)');
    for (final m in re.allMatches(output)) {
      final name = m.group(1)!.trim();
      if (name.isNotEmpty) result[name] = m.group(2)!;
    }
    return result;
  }

  // ── Parsers for key findings ──────────────────────────────────────────────

  // Parse nuclei.txt files across all sessions.
  // Nuclei line format: [template-id] [protocol] [severity] target [extras]
  // Filters out service-detection-only templates that aren't real vulnerabilities.
  static final _detectOnlyRe = RegExp(
    r'^(ssh|ftp|http|smtp|rdp|vnc|telnet|snmp|dns|ntp|ldap|smb|'
    r'mssql|mysql|mongodb|redis|elasticsearch|memcached|'
    r'tech-detect|ssl-dns-names|server-detect|service-detect|'
    r'ssl-certificate|mx-detect|dns-resolve|'
    r'[a-z]+-detect(?:ed)?|[a-z]+-version|[a-z]+-server)',
    caseSensitive: false,
  );
  static final _vulnKeyRe = RegExp(
    r'(CVE-\d{4}-\d+|default.?login|default.?password|rce|injection|sqli|xss|'
    r'lfi|rfi|backdoor|misconfigur|exposed|leak|disclosure|bypass|takeover|exploit)',
    caseSensitive: false,
  );

  static List<Map<String, String>> _parseNucleiFindings(
      Map<String, Map<String, String>> rawFiles) {
    final findings = <Map<String, String>>[];
    final re = RegExp(
        r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*(.*)$');
    for (final sessionFiles in rawFiles.values) {
      for (final entry in sessionFiles.entries) {
        if (!entry.key.toLowerCase().contains('nuclei')) continue;
        for (final line in entry.value.split('\n')) {
          final m = re.firstMatch(line.trim());
          if (m == null) continue;
          final id  = m.group(1)!.trim();
          final sev = m.group(3)!.trim().toLowerCase();
          final extra = m.group(5)!.trim();
          // Skip bare service-detection templates unless they reference a real vuln keyword
          if (_detectOnlyRe.hasMatch(id) && !_vulnKeyRe.hasMatch('$id $extra')) continue;
          findings.add({
            'id':       id,
            'protocol': m.group(2)!.trim(),
            'severity': sev,
            'target':   m.group(4)!.trim(),
            'extra':    extra,
          });
        }
      }
    }
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    findings.sort((a, b) {
      final ai = order.indexOf(a['severity']!);
      final bi = order.indexOf(b['severity']!);
      final ai2 = ai < 0 ? order.length : ai;
      final bi2 = bi < 0 ? order.length : bi;
      return ai2.compareTo(bi2);
    });
    return findings;
  }

  // Parse credential lines from brute.txt, chain_creds.txt, crackmap.txt, vnc.txt, etc.
  // Format: [port][proto] host: IP   login: USER   password: PASS
  static List<Map<String, String>> _parseBruteCreds(
      Map<String, Map<String, String>> rawFiles) {
    final found = <String, Map<String, String>>{};
    final reLogin = RegExp(r'login:\s*(\S+)', caseSensitive: false);
    final rePass  = RegExp(r'password:\s*(.+)',  caseSensitive: false);
    final reHost  = RegExp(r'host:\s*(\S+)',  caseSensitive: false);
    final rePort  = RegExp(r'^\[(\d+)\]\[([^\]]+)\]', caseSensitive: false);
    for (final sessionFiles in rawFiles.values) {
      for (final entry in sessionFiles.entries) {
        // Accept any file that might contain credential lines (not just brute.txt)
        final k = entry.key.toLowerCase();
        final hasCreds = k.contains('brute') || k.contains('chain_creds') ||
            k.contains('crackmap') || k.contains('vnc') || k.contains('wifite') ||
            k.contains('linpeas') || k.contains('pret') || k.contains('netsniff');
        if (!hasCreds) continue;
        for (final line in entry.value.split('\n')) {
          final lo = line.toLowerCase();
          if (!lo.contains('login:') || !lo.contains('password:')) continue;
          final login = reLogin.firstMatch(line)?.group(1)?.trim() ?? '';
          var  pass  = rePass .firstMatch(line)?.group(1)?.trim() ?? '';
          // hydra appends trailing spaces / extra tokens — strip at first space
          pass = pass.split(RegExp(r'\s{2,}'))[0].trim();
          final host  = reHost .firstMatch(line)?.group(1)?.trim() ?? '?';
          final portM = rePort .firstMatch(line.trim());
          final svc   = portM != null ? '${portM.group(2)} :${portM.group(1)}' : '?';
          if (login.isEmpty || pass.isEmpty) continue;
          final key = '$host|$login|$pass';
          found[key] = {'host': host, 'service': svc, 'login': login, 'password': pass};
        }
      }
    }
    return found.values.toList()
      ..sort((a, b) => a['host']!.compareTo(b['host']!));
  }

  // Parse IoT/Ingram output: look for IP lines that suggest found cameras.
  static List<Map<String, String>> _parseIotFindings(
      Map<String, Map<String, String>> rawFiles) {
    final found = <String, Map<String, String>>{};
    final reIp  = RegExp(r'(\d{1,3}(?:\.\d{1,3}){3}):?(\d+)?');
    final reCam = RegExp(
        r'(camera|stream|rtsp|mjpeg|snapshot|channel|dvr|nvr|hikvision|dahua|axis'
        r'|foscam|reolink|wyze|found|pwned|success)',
        caseSensitive: false);
    for (final sessionFiles in rawFiles.values) {
      for (final entry in sessionFiles.entries) {
        final k = entry.key.toLowerCase();
        if (!k.contains('iot') && !k.contains('ingram') &&
            !k.contains('rtsp') && !k.contains('camera') &&
            !k.contains('recon_iot')) { continue; }
        for (final line in entry.value.split('\n')) {
          if (!reCam.hasMatch(line)) continue;
          final ipM = reIp.firstMatch(line);
          if (ipM == null) continue;
          final ip  = ipM.group(1)!;
          final port = ipM.group(2) ?? '';
          final key  = '$ip:$port';
          if (found.containsKey(key)) continue;
          found[key] = {
            'ip': ip, 'port': port, 'info': _stripAnsi(line.trim()),
          };
        }
      }
    }
    return found.values.toList();
  }

  // Parse SSL/TLS issues: critical and high findings from testssl/sslscan output.
  static List<Map<String, String>> _parseSslFindings(
      Map<String, Map<String, String>> rawFiles) {
    final findings = <Map<String, String>>[];
    final reSev = RegExp(r'\((CRITICAL|HIGH|MEDIUM|LOW|OK|INFO)\)',
        caseSensitive: false);
    for (final sessionFiles in rawFiles.values) {
      for (final entry in sessionFiles.entries) {
        if (!entry.key.toLowerCase().contains('ssl')) continue;
        // Try to derive host from filename: ssl_192.168.1.1_443.txt
        final hostM = RegExp(r'ssl[_-](.+?)\.txt', caseSensitive: false)
            .firstMatch(entry.key);
        final host = hostM?.group(1)?.replaceAll('_', ':') ?? '?';
        for (final line in entry.value.split('\n')) {
          final clean = _stripAnsi(line);
          final sevM  = reSev.firstMatch(clean);
          if (sevM == null) continue;
          final sev = sevM.group(1)!.toLowerCase();
          if (sev == 'ok' || sev == 'info') continue;
          // Also catch sslscan "NOT ok" / plain vulnerability lines
          findings.add({
            'host': host, 'severity': sev, 'finding': clean.trim(),
          });
        }
        // sslscan "NOT ok" lines (no severity tag)
        for (final line in entry.value.split('\n')) {
          final clean = _stripAnsi(line);
          if (clean.toLowerCase().contains('not ok') &&
              !reSev.hasMatch(clean)) {
            findings.add({
              'host': host, 'severity': 'medium', 'finding': clean.trim(),
            });
          }
        }
      }
    }
    const order = ['critical', 'high', 'medium', 'low'];
    findings.sort((a, b) {
      final ai = order.indexOf(a['severity']!);
      final bi = order.indexOf(b['severity']!);
      return (ai < 0 ? 99 : ai).compareTo(bi < 0 ? 99 : bi);
    });
    return findings;
  }

  // Parse nikto output: each `+ ` prefixed line is a finding.
  static List<Map<String, String>> _parseWebFindings(
      Map<String, Map<String, String>> rawFiles) {
    final findings = <Map<String, String>>[];
    for (final sessionFiles in rawFiles.values) {
      for (final entry in sessionFiles.entries) {
        final k = entry.key.toLowerCase();
        if (!k.contains('feroxbuster') && !k.contains('web') &&
            !k.contains('whatweb') && !k.contains('dirbust')) { continue; }
        // Derive URL from filename when possible
        final urlM = RegExp(r'dirbust_(.+)\.txt', caseSensitive: false)
            .firstMatch(entry.key);
        final source = urlM?.group(1)?.replaceAll('_', '/') ?? entry.key;
        for (final line in entry.value.split('\n')) {
          final clean = _stripAnsi(line.trim());
          // nikto findings start with "+"
          if (clean.startsWith('+ ') && clean.length > 3) {
            findings.add({'source': source, 'finding': clean.substring(2)});
          }
          // dirbust — lines with status codes (gobuster/feroxbuster)
          else if (RegExp(r'^\d{3}\s').hasMatch(clean) ||
                   RegExp(r'\[Status:\s*(200|301|302|401|403)').hasMatch(clean)) {
            findings.add({'source': source, 'finding': clean});
          }
        }
      }
    }
    return findings;
  }

  // Parse crackmap.sh output: accessible SMB shares / interesting info.
  static List<Map<String, String>> _parseSmbFindings(
      Map<String, Map<String, String>> rawFiles) {
    final findings = <Map<String, String>>[];
    for (final sessionFiles in rawFiles.values) {
      for (final entry in sessionFiles.entries) {
        if (!entry.key.toLowerCase().contains('crack')) continue;
        for (final line in entry.value.split('\n')) {
          final clean = _stripAnsi(line.trim());
          // CME lines start with "SMB"
          if (!clean.startsWith('SMB')) continue;
          final hasShare = RegExp(r'(READ|WRITE|DISK|IPC)', caseSensitive: false)
              .hasMatch(clean);
          final hasSigning = clean.toLowerCase().contains('signing');
          if (hasShare || hasSigning) {
            findings.add({'line': clean});
          }
        }
      }
    }
    return findings;
  }

  // Parse DNS/AD output: user accounts, zone transfer records.
  static List<Map<String, String>> _parseDnsAdFindings(
      Map<String, Map<String, String>> rawFiles) {
    final users = <String>{};
    final zones = <String>[];
    for (final sessionFiles in rawFiles.values) {
      for (final entry in sessionFiles.entries) {
        if (!entry.key.toLowerCase().contains('dns')) continue;
        for (final line in entry.value.split('\n')) {
          final clean = _stripAnsi(line.trim());
          if (RegExp(r'sAMAccountName:', caseSensitive: false).hasMatch(clean)) {
            final u = clean.replaceAll(RegExp(r'sAMAccountName:\s*', caseSensitive: false), '').trim();
            if (u.isNotEmpty) users.add(u);
          }
          if (RegExp(r'\bIN\s+(A|AAAA|CNAME|MX|NS|SOA|TXT)\b').hasMatch(clean)) {
            zones.add(clean);
          }
        }
      }
    }
    final result = <Map<String, String>>[];
    for (final u in users) { result.add({'type': 'user', 'value': u}); }
    for (final z in zones)  { result.add({'type': 'dns',  'value': z}); }
    return result;
  }

  // Parse responder/NTLM relay output: captured hashes.
  static List<Map<String, String>> _parseNtlmHashes(
      Map<String, Map<String, String>> rawFiles) {
    final hashes = <String, Map<String, String>>{};
    // NTLMv2: USERNAME::DOMAIN:challenge:response:response2
    final reHash = RegExp(
        r'([^:]+)::([^:]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)');
    final reSrc  = RegExp(r'(\d{1,3}(?:\.\d{1,3}){3})');
    for (final sessionFiles in rawFiles.values) {
      for (final entry in sessionFiles.entries) {
        final k = entry.key.toLowerCase();
        if (!k.contains('responder') && !k.contains('ntlm') &&
            !k.contains('relay') && !k.contains('hash')) { continue; }
        for (final line in entry.value.split('\n')) {
          final clean = _stripAnsi(line.trim());
          final m = reHash.firstMatch(clean);
          if (m != null) {
            final user   = m.group(1)!.trim();
            final domain = m.group(2)!.trim();
            final key    = '$domain\\$user';
            if (hashes.containsKey(key)) continue;
            final ipM = reSrc.firstMatch(clean);
            hashes[key] = {
              'user': user, 'domain': domain,
              'from': ipM?.group(1) ?? '?',
              'hash': '${m.group(1)}::${m.group(2)}:${m.group(3)}:...',
            };
          }
        }
      }
    }
    return hashes.values.toList();
  }

  // ── HTML builder ──────────────────────────────────────────────────────────

  static String _buildProjectHtml(
    Project project,
    List<ProjectSession> sessions,
    List<ProjectHost> hosts,
    List<Credential> creds,
    List<ProjectNote> notes,
    Map<String, Map<String, String>> rawFiles,
  ) {
    final sb = StringBuffer();
    final now    = DateTime.now();
    final nowStr = '${now.year}-${_pad(now.month)}-${_pad(now.day)} '
                   '${_pad(now.hour)}:${_pad(now.minute)}';

    final totalPorts = hosts.fold(0, (s, h) => s + h.ports.length);

    // Parse key findings from raw files
    final vulns      = _parseNucleiFindings(rawFiles);
    // Drop brute-parsed creds already imported into SQLite (same brute.txt) so
    // stats/tables don't count the same credential twice.
    final credKeys = creds
        .map((c) => '${c.hostIp}|${c.username}|${c.password}')
        .toSet();
    final bruteCreds = _parseBruteCreds(rawFiles)
        .where((c) => !credKeys.contains('${c['host']}|${c['login']}|${c['password']}'))
        .toList();
    final iotFinds   = _parseIotFindings(rawFiles);
    final sslFinds   = _parseSslFindings(rawFiles);
    final webFinds   = _parseWebFindings(rawFiles);
    final smbFinds   = _parseSmbFindings(rawFiles);
    final dnsFinds   = _parseDnsAdFindings(rawFiles);
    final ntlmHashes = _parseNtlmHashes(rawFiles);

    final totalVulns  = vulns.length;
    final totalCreds  = creds.length + bruteCreds.length;

    final sortedSessions = List.of(sessions)..sort((a, b) => a.created.compareTo(b.created));

    // Date range of engagement
    String dateRange = '';
    if (sortedSessions.isNotEmpty) {
      String fmt(DateTime d) => '${d.year}-${_pad(d.month)}-${_pad(d.day)}';
      final f = fmt(sortedSessions.first.created);
      final l = fmt(sortedSessions.last.created);
      dateRange = f == l ? f : '$f → $l';
    }

    final targets = project.target
        .split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();

    // ── Risk level ─────────────────────────────────────────────────────────
    final String riskLevel;
    final String riskColor;
    if (totalVulns > 0 || totalCreds > 0) {
      riskLevel = 'CRITICAL'; riskColor = '#ff3333';
    } else if (ntlmHashes.isNotEmpty || sslFinds.any((f) => f['severity'] == 'critical' || f['severity'] == 'high')) {
      riskLevel = 'HIGH';     riskColor = '#ff6633';
    } else if (sslFinds.isNotEmpty || webFinds.isNotEmpty) {
      riskLevel = 'MEDIUM';   riskColor = '#ffaa00';
    } else if (hosts.isNotEmpty) {
      riskLevel = 'LOW';      riskColor = '#00cc66';
    } else {
      riskLevel = 'INFO';     riskColor = '#00ccff';
    }

    // ── Recommendations ────────────────────────────────────────────────────
    final recs = <({String sev, String text})>[];
    if (totalVulns > 0) {
      recs.add((sev: 'CRITICAL', text: 'Remediate confirmed Nuclei vulnerabilities immediately. Prioritize CRITICAL and HIGH severity findings.'));
    }
    if (totalCreds > 0) {
      recs.add((sev: 'CRITICAL', text: '$totalCreds credential(s) captured. Rotate all affected passwords immediately and enable MFA across all services.'));
    }
    if (ntlmHashes.isNotEmpty) {
      recs.add((sev: 'HIGH', text: '${ntlmHashes.length} NTLM hash(es) intercepted. Enable SMB signing, disable NTLMv1, and enforce AES Kerberos encryption.'));
    }
    if (sslFinds.isNotEmpty) {
      recs.add((sev: 'HIGH', text: 'SSL/TLS misconfigurations detected. Disable TLS 1.0/1.1, remove 3DES ciphers, enforce HSTS, and use trusted CA certificates.'));
    }
    if (smbFinds.any((f) => (f['line'] ?? '').toLowerCase().contains('signing:false'))) {
      recs.add((sev: 'HIGH', text: 'SMB signing disabled — enables relay attacks. Enable SMB signing via Group Policy on all domain controllers and workstations.'));
    }
    if (webFinds.isNotEmpty) {
      recs.add((sev: 'MEDIUM', text: '${webFinds.length} web findings detected. Review exposed directories, server headers, and vulnerable components.'));
    }

    // ── HTML head + CSS ────────────────────────────────────────────────────
    sb.write('''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>F-Security — ${_e(project.name)}</title>
<style>
:root{--bg:#08090d;--bg2:#0d1117;--bg3:#111820;--bg4:#141c25;
      --bd:#1e2d3d;--bd2:#243040;--tx:#8899aa;--tx2:#aabbcc;
      --cy:#00ccff;--gn:#00cc66;--rd:#ff3333;--or:#ffaa00;
      --pu:#cc88ff;--dim:#3a4a5a}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--tx);font-family:'Courier New',Consolas,monospace;
     font-size:13px;line-height:1.55;padding:0}
nav{position:sticky;top:0;z-index:100;background:rgba(8,9,13,0.96);
    border-bottom:1px solid var(--bd2);padding:0 16px;
    display:flex;align-items:center;gap:0;overflow-x:auto;white-space:nowrap;
    backdrop-filter:blur(8px)}
nav a{color:var(--dim);font-size:0.72em;letter-spacing:0.5px;padding:10px 12px;
      text-decoration:none;border-bottom:2px solid transparent;flex-shrink:0}
nav a:hover{color:var(--cy);border-bottom-color:var(--cy)}
.nav-brand{color:var(--cy);font-size:0.85em;font-weight:bold;letter-spacing:2px;
           padding:10px 14px 10px 0;border-right:1px solid var(--bd);
           margin-right:8px;flex-shrink:0}
.nav-risk{margin-left:auto;padding:4px 10px;border-radius:2px;font-size:0.78em;
          font-weight:bold;border:1px solid;letter-spacing:1px;flex-shrink:0;
          color:$riskColor;border-color:$riskColor;background:${riskColor}22}
.page{max-width:1400px;margin:0 auto;padding:20px 20px 40px}
header{display:flex;justify-content:space-between;align-items:flex-start;
       flex-wrap:wrap;gap:12px;padding:20px 0 16px;
       border-bottom:1px solid var(--bd);margin-bottom:20px}
.hdr-brand{color:var(--cy);font-size:1.3em;font-weight:bold;letter-spacing:4px}
.hdr-sub{color:var(--or);font-size:0.82em;letter-spacing:1px;margin-top:4px}
.hdr-meta{font-size:0.78em;color:var(--dim);margin-top:4px}
.hdr-meta span{color:var(--cy)}
.tgt{display:inline-block;padding:2px 8px;border:1px solid var(--or);
     color:var(--or);font-size:0.75em;border-radius:2px;margin:2px}
.exec-box{background:var(--bg2);border:1px solid var(--bd);
          border-left:4px solid $riskColor;border-radius:4px;padding:16px 20px;margin-bottom:8px}
.exec-risk{font-size:0.7em;letter-spacing:2px;color:$riskColor;margin-bottom:6px;
           display:flex;align-items:center;gap:8px}
.risk-pill{display:inline-block;padding:3px 12px;border-radius:2px;font-weight:bold;
           font-size:1.3em;letter-spacing:2px;color:$riskColor;
           border:1px solid $riskColor;background:${riskColor}18}
.exec-summary{color:var(--tx2);font-size:0.88em;line-height:1.6;margin:10px 0}
.exec-bullets{list-style:none;margin-top:8px}
.exec-bullets li{padding:3px 0;font-size:0.84em;display:flex;align-items:flex-start;gap:8px}
.exec-bullets li::before{content:"▸";color:var(--cy);flex-shrink:0}
.cards{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}
.card{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;
      padding:12px 16px;min-width:100px;text-align:center;flex:1}
.card .n{font-size:2em;font-weight:bold;line-height:1}
.card .l{font-size:0.68em;letter-spacing:1.5px;margin-top:5px;color:var(--dim)}
.card.r{border-top:2px solid var(--rd)}.card.r .n{color:var(--rd)}
.card.g{border-top:2px solid var(--gn)}.card.g .n{color:var(--gn)}
.card.a{border-top:2px solid var(--or)}.card.a .n{color:var(--or)}
.card.b{border-top:2px solid var(--cy)}.card.b .n{color:var(--cy)}
.card.p{border-top:2px solid var(--pu)}.card.p .n{color:var(--pu)}
.toolbar{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
button{background:var(--bg2);color:var(--tx);border:1px solid var(--bd);
       padding:6px 13px;cursor:pointer;border-radius:3px;font-family:inherit;font-size:0.82em}
button:hover{border-color:var(--cy);color:var(--cy)}
.sec{background:var(--bg2);border:1px solid var(--bd);border-left:3px solid var(--cy);
     border-radius:4px;margin-bottom:10px;overflow:hidden}
.sec.warn-border{border-left-color:var(--or)}
.sec.crit-border{border-left-color:var(--rd)}
.sec.gn-border{border-left-color:var(--gn)}
.sec.or-border{border-left-color:var(--or)}
.sec.pu-border{border-left-color:var(--pu)}
.sec h2{background:var(--bg);color:var(--cy);padding:9px 14px;font-size:0.82em;
        letter-spacing:2px;border-bottom:1px solid var(--bd);
        cursor:pointer;user-select:none;display:flex;justify-content:space-between;align-items:center}
.sec h2:hover{background:var(--bg3)}
.sec h2::before{content:"▶ "}
.sec.col h2::before{content:"▷ "}
.sec-body{padding:14px 16px}
.sec.col .sec-body{display:none}
.sec-badge{font-size:0.78em;font-weight:normal;color:var(--dim)}
pre{white-space:pre-wrap;word-break:break-all;font-size:11.5px;line-height:1.45}
.matrix-wrap{overflow-x:auto;margin-bottom:4px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:var(--bg);color:var(--dim);padding:7px 10px;text-align:left;
   border-bottom:1px solid var(--bd2);font-size:0.75em;letter-spacing:1.5px;white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid var(--bd);vertical-align:top}
tr:hover td{background:var(--bg4)}
.ptag{display:inline-block;background:var(--bg);border:1px solid var(--bd2);
      font-size:0.7em;padding:1px 5px;border-radius:2px;color:var(--cy);margin:1px;white-space:nowrap}
.stag{display:inline-block;background:var(--bg);border:1px solid var(--bd);
      font-size:0.68em;padding:1px 5px;border-radius:2px;color:var(--dim);margin:1px}
.ok{color:var(--gn)}.crit{color:var(--rd);font-weight:bold}.warn{color:var(--or)}.info{color:var(--cy)}
.note-card{background:var(--bg3);border:1px solid var(--bd);border-left:3px solid var(--or);
           border-radius:4px;padding:12px 16px;margin-bottom:8px}
.note-ts{color:var(--dim);font-size:0.75em;margin-bottom:5px}
.rec-card{background:var(--bg3);border:1px solid var(--bd);border-radius:4px;
          padding:12px 16px;margin-bottom:8px;border-left:3px solid var(--cy)}
.rec-card.r{border-left-color:var(--rd)}.rec-card.a{border-left-color:var(--or)}
.rec-sev{font-size:0.72em;letter-spacing:1.5px;font-weight:bold;margin-bottom:4px}
.rec-card.r .rec-sev{color:var(--rd)}.rec-card.a .rec-sev{color:var(--or)}
.rec-card .rec-sev{color:var(--cy)}.rec-txt{font-size:0.86em;color:var(--tx2);line-height:1.6}
footer{margin-top:24px;padding-top:12px;border-top:1px solid var(--bd);
       color:var(--dim);font-size:0.74em;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px}
@media print{nav{display:none}.sec.col .sec-body{display:block}.sec h2::before{content:""}}
</style>
</head>
<body>
<nav>
  <span class="nav-brand">F-SEC</span>
  <a href="#sec-exec">◈ SUMMARY</a>
  <a href="#sec-timeline">◉ TIMELINE</a>
  ${hosts.isNotEmpty ? '<a href="#sec-hosts">◉ HOSTS</a>' : ''}
  ${vulns.isNotEmpty ? '<a href="#sec-vulns">▲ VULNS</a>' : ''}
  ${sslFinds.isNotEmpty ? '<a href="#sec-ssl">⚿ SSL</a>' : ''}
  ${webFinds.isNotEmpty ? '<a href="#sec-web">◈ WEB</a>' : ''}
  ${(creds.isNotEmpty || bruteCreds.isNotEmpty) ? '<a href="#sec-creds">⚷ CREDS</a>' : ''}
  ${ntlmHashes.isNotEmpty ? '<a href="#sec-ntlm">⚷ NTLM</a>' : ''}
  ${notes.isNotEmpty ? '<a href="#sec-notes">≡ NOTES</a>' : ''}
  ${recs.isNotEmpty ? '<a href="#sec-recs">► RECS</a>' : ''}
  <span class="nav-risk">$riskLevel</span>
</nav>
<div class="page">
''');

    // ── Header ─────────────────────────────────────────────────────────────
    sb.write('''
<header>
  <div>
    <div class="hdr-brand">▓▒░ F-SECURITY PENTEST REPORT ░▒▓</div>
    <div class="hdr-sub">◈ PROJECT: ${_e(project.name)}</div>
    <div class="hdr-meta">
      ${dateRange.isNotEmpty ? 'Period: <span>$dateRange</span> &nbsp;·&nbsp;' : ''}
      Generated: <span>$nowStr</span>
    </div>
    ${targets.isNotEmpty ? '<div style="margin-top:6px">${targets.map((t) => '<span class="tgt">${_e(t)}</span>').join('')}</div>' : ''}
  </div>
  <div style="text-align:right;font-size:0.78em;color:var(--dim)">
    ${sessions.length} session(s)<br>${hosts.length} host(s) &nbsp;·&nbsp; $totalPorts port(s)
  </div>
</header>
''');

    // ── Executive Summary ───────────────────────────────────────────────────
    final execBullets = <String>[];
    if (hosts.isNotEmpty) execBullets.add('${hosts.length} host(s) discovered — $totalPorts open port(s) mapped');
    if (totalVulns > 0) execBullets.add('$totalVulns vulnerability(ies) confirmed via Nuclei scan');
    if (totalCreds > 0) execBullets.add('$totalCreds credential(s) captured (brute-force + live auth)');
    if (ntlmHashes.isNotEmpty) execBullets.add('${ntlmHashes.length} NTLM hash(es) intercepted via Responder/relay');
    if (sslFinds.isNotEmpty) execBullets.add('${sslFinds.length} SSL/TLS issue(s) — weak ciphers, deprecated protocols');
    if (webFinds.isNotEmpty) execBullets.add('${webFinds.length} web finding(s) — misconfigs, exposed endpoints');
    if (iotFinds.isNotEmpty) execBullets.add('${iotFinds.length} IoT/camera device(s) found on the network');
    if (execBullets.isEmpty) execBullets.add('No significant findings recorded — verify scan coverage is complete');

    sb.write('''
<div class="sec" id="sec-exec">
<h2><span>◈ EXECUTIVE SUMMARY</span>
    <span class="sec-badge">Risk: <strong style="color:$riskColor">$riskLevel</strong></span></h2>
<div class="sec-body">
<div class="exec-box">
  <div class="exec-risk">OVERALL RISK ASSESSMENT &nbsp; <span class="risk-pill">$riskLevel</span></div>
  <div class="exec-summary">
    Project <strong style="color:var(--cy)">${_e(project.name)}</strong>
    — ${sessions.length} scan session(s)${dateRange.isNotEmpty ? ' &nbsp;·&nbsp; Period: $dateRange' : ''} —
    produced the following key findings:
  </div>
  <ul class="exec-bullets">
    ${execBullets.map((b) => '<li>${_e(b)}</li>').join('\n    ')}
  </ul>
</div>
</div></div>
''');

    // ── Stat cards ──────────────────────────────────────────────────────────
    sb.write('''
<div class="cards">
  <div class="card b"><div class="n">${sessions.length}</div><div class="l">SESSIONS</div></div>
  <div class="card ${hosts.isNotEmpty ? 'g' : 'b'}"><div class="n">${hosts.length}</div><div class="l">HOSTS</div></div>
  <div class="card b"><div class="n">$totalPorts</div><div class="l">OPEN PORTS</div></div>
  <div class="card ${totalVulns > 0 ? 'r' : 'b'}"><div class="n">$totalVulns</div><div class="l">VULNS</div></div>
  <div class="card ${totalCreds > 0 ? 'r' : 'b'}"><div class="n">$totalCreds</div><div class="l">CREDENTIALS</div></div>
  ${ntlmHashes.isNotEmpty ? '<div class="card r"><div class="n">${ntlmHashes.length}</div><div class="l">NTLM HASHES</div></div>' : ''}
  ${iotFinds.isNotEmpty ? '<div class="card a"><div class="n">${iotFinds.length}</div><div class="l">IoT DEVICES</div></div>' : ''}
  <div class="card a"><div class="n">${notes.length}</div><div class="l">NOTES</div></div>
</div>

<div class="toolbar">
  <button onclick="expandAll()">▶ Expand All</button>
  <button onclick="collapseAll()">▷ Collapse All</button>
</div>
''');

    // ── Attack Timeline ─────────────────────────────────────────────────────
    sb.write('''
<div class="sec" id="sec-timeline">
<h2><span>◈ ATTACK TIMELINE</span>
    <span class="sec-badge">${sessions.length} session(s)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table>
<thead><tr>
  <th>#</th><th>MODULE</th><th>DATE / TIME</th><th>SESSION FOLDER</th><th>FILES</th>
</tr></thead>
<tbody>
''');
    for (var i = 0; i < sortedSessions.length; i++) {
      final s  = sortedSessions[i];
      final dt = s.created;
      final dtStr = '${dt.year}-${_pad(dt.month)}-${_pad(dt.day)}'
                    '  ${_pad(dt.hour)}:${_pad(dt.minute)}:${_pad(dt.second)}';
      final fc = rawFiles[s.folderName]?.length ?? 0;
      sb.write('''<tr>
  <td style="color:var(--dim);font-size:0.85em">${i + 1}</td>
  <td style="color:var(--cy);font-weight:bold">${_e(s.moduleName ?? '—')}</td>
  <td>${_e(dtStr)}</td>
  <td style="color:var(--dim);font-size:0.82em">${_e(s.folderName)}</td>
  <td style="color:var(--dim)">${fc > 0 ? '$fc files' : '—'}</td>
</tr>
''');
    }
    sb.write('</tbody></table></div></div></div>\n');

    // ── Host Map ────────────────────────────────────────────────────────────
    if (hosts.isNotEmpty) {
      sb.write('''
<div class="sec gn-border" id="sec-hosts">
<h2><span>◉ DISCOVERED HOSTS</span>
    <span class="sec-badge">${hosts.length} host(s) &nbsp;·&nbsp; $totalPorts port(s)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table>
<thead><tr>
  <th>IP ADDRESS</th><th>OPEN PORTS / SERVICES</th><th>COUNT</th>
</tr></thead>
<tbody>
''');
      // Sort by IP numerically
      final sortedHosts = List.of(hosts)..sort((a, b) {
        int ipNum(String ip) {
          final p = ip.split('.').map(int.tryParse);
          return p.fold(0, (acc, o) => (acc << 8) | (o ?? 0));
        }
        return ipNum(a.ip).compareTo(ipNum(b.ip));
      });
      for (final h in sortedHosts) {
        final portTags = h.ports.map((p) {
          final svc = p.service != null ? ' <span style="color:var(--dim)">${_e(p.service!)}</span>' : '';
          return '<span class="ptag">${_e(p.number.toString())}/${_e(p.protocol)}$svc</span>';
        }).join(' ');
        sb.write('''<tr>
  <td><span style="color:var(--cy);font-weight:bold">${_e(h.ip)}</span></td>
  <td style="max-width:500px">${portTags.isNotEmpty ? portTags : '<span style="color:var(--dim)">—</span>'}</td>
  <td style="color:var(--dim)">${h.ports.length}</td>
</tr>
''');
      }
      sb.write('</tbody></table></div></div></div>\n');
    }

    // ── Vulnerabilities (nuclei) ────────────────────────────────────────────
    if (vulns.isNotEmpty) {
      final sevColor = {'critical':'var(--rd)','high':'var(--or)','medium':'var(--or)','low':'var(--cy)','info':'var(--dim)'};
      sb.write('''
<div class="sec crit-border" id="sec-vulns">
<h2><span>▲ VULNERABILITIES</span>
    <span class="sec-badge" style="color:var(--rd)">${vulns.length} finding(s)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table>
<thead><tr>
  <th>SEVERITY</th><th>TEMPLATE / CVE</th><th>PROTOCOL</th><th>TARGET</th><th>DETAIL</th>
</tr></thead>
<tbody>
''');
      for (final v in vulns) {
        final col = sevColor[v['severity']] ?? 'var(--tx)';
        sb.write('''<tr>
  <td><span style="color:$col;font-weight:bold;text-transform:uppercase">${_e(v['severity']!)}</span></td>
  <td style="color:var(--cy)">${_e(v['id']!)}</td>
  <td style="color:var(--dim)">${_e(v['protocol']!)}</td>
  <td style="color:var(--gn)">${_e(v['target']!)}</td>
  <td style="font-size:0.85em;color:var(--tx)">${_e(v['extra']!)}</td>
</tr>
''');
      }
      sb.write('</tbody></table></div></div></div>\n');
    }

    // ── SSL/TLS Issues ──────────────────────────────────────────────────────
    if (sslFinds.isNotEmpty) {
      final sevColor = {'critical':'var(--rd)','high':'var(--or)','medium':'var(--or)','low':'var(--cy)'};
      sb.write('''
<div class="sec crit-border" id="sec-ssl">
<h2><span>⚿ SSL / TLS ISSUES</span>
    <span class="sec-badge" style="color:var(--rd)">${sslFinds.length} finding(s)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table>
<thead><tr><th>HOST</th><th>SEVERITY</th><th>FINDING</th></tr></thead>
<tbody>
''');
      for (final f in sslFinds) {
        final col = sevColor[f['severity']] ?? 'var(--tx)';
        sb.write('''<tr>
  <td style="color:var(--cy);white-space:nowrap">${_e(f['host']!)}</td>
  <td><span style="color:$col;font-weight:bold;text-transform:uppercase">${_e(f['severity']!)}</span></td>
  <td style="font-size:0.85em">${_e(f['finding']!)}</td>
</tr>
''');
      }
      sb.write('</tbody></table></div></div></div>\n');
    }

    // ── Web Findings ────────────────────────────────────────────────────────
    if (webFinds.isNotEmpty) {
      sb.write('''
<div class="sec warn-border" id="sec-web">
<h2><span>◈ WEB FINDINGS</span>
    <span class="sec-badge" style="color:var(--or)">${webFinds.length} finding(s)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table>
<thead><tr><th>SOURCE</th><th>FINDING</th></tr></thead>
<tbody>
''');
      for (final f in webFinds.take(200)) {
        sb.write('''<tr>
  <td style="color:var(--cy);font-size:0.8em;white-space:nowrap">${_e(f['source']!)}</td>
  <td style="font-size:0.85em">${_e(f['finding']!)}</td>
</tr>
''');
      }
      if (webFinds.length > 200) {
        sb.write('<tr><td colspan="2" style="color:var(--dim);font-size:0.8em">'
            '… ${webFinds.length - 200} more (see raw output)</td></tr>\n');
      }
      sb.write('</tbody></table></div></div></div>\n');
    }

    // ── Credentials (SQLite + brute-force parsed) ────────────────────────────
    if (creds.isNotEmpty || bruteCreds.isNotEmpty) {
      final totalC = creds.length + bruteCreds.length;
      sb.write('''
<div class="sec crit-border" id="sec-creds">
<h2><span>⚷ CAPTURED CREDENTIALS</span>
    <span class="sec-badge" style="color:var(--rd)">$totalC credential(s)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table>
<thead><tr>
  <th>HOST</th><th>SERVICE</th><th>USERNAME</th><th>PASSWORD</th><th>SOURCE</th>
</tr></thead>
<tbody>
''');
      for (final c in creds) {
        sb.write('''<tr>
  <td style="color:var(--cy);font-weight:bold">${_e(c.hostIp)}</td>
  <td style="color:var(--pu)">${_e(c.service ?? '—')}</td>
  <td style="color:var(--gn)">${_e(c.username)}</td>
  <td style="color:var(--rd)">${_e(c.password)}</td>
  <td style="color:var(--dim);font-size:0.8em">imported</td>
</tr>
''');
      }
      for (final c in bruteCreds) {
        sb.write('''<tr>
  <td style="color:var(--cy);font-weight:bold">${_e(c['host']!)}</td>
  <td style="color:var(--pu)">${_e(c['service']!)}</td>
  <td style="color:var(--gn)">${_e(c['login']!)}</td>
  <td style="color:var(--rd)">${_e(c['password']!)}</td>
  <td style="color:var(--dim);font-size:0.8em">brute.txt</td>
</tr>
''');
      }
      sb.write('</tbody></table></div></div></div>\n');
    }

    // ── SMB / Network Shares ────────────────────────────────────────────────
    if (smbFinds.isNotEmpty) {
      sb.write('''
<div class="sec warn-border" id="sec-smb">
<h2><span>◉ SMB / NETWORK SHARES</span>
    <span class="sec-badge" style="color:var(--or)">${smbFinds.length} line(s)</span></h2>
<div class="sec-body"><pre>
''');
      for (final f in smbFinds) {
        sb.writeln(_colorizeBlock(f['line']!));
      }
      sb.write('</pre></div></div>\n');
    }

    // ── DNS / Active Directory ──────────────────────────────────────────────
    if (dnsFinds.isNotEmpty) {
      final users = dnsFinds.where((f) => f['type'] == 'user').toList();
      final zones = dnsFinds.where((f) => f['type'] == 'dns').toList();
      sb.write('''
<div class="sec" id="sec-dns">
<h2><span>◉ DNS / ACTIVE DIRECTORY</span>
    <span class="sec-badge">${users.length} user(s) &nbsp;·&nbsp; ${zones.length} record(s)</span></h2>
<div class="sec-body">
''');
      if (users.isNotEmpty) {
        sb.write('<div style="margin-bottom:10px"><span style="color:var(--cy);font-size:0.8em;letter-spacing:1px">AD USERS</span><br><br>');
        for (final u in users) {
          sb.write('<span class="stag">${_e(u['value']!)}</span> ');
        }
        sb.write('</div>');
      }
      if (zones.isNotEmpty) {
        sb.write('<pre style="font-size:0.85em">');
        for (final z in zones.take(100)) {
          sb.writeln(_e(z['value']!));
        }
        sb.write('</pre>');
      }
      sb.write('</div></div>\n');
    }

    // ── IoT / Cameras ───────────────────────────────────────────────────────
    if (iotFinds.isNotEmpty) {
      sb.write('''
<div class="sec or-border" id="sec-iot">
<h2><span>◈ IoT / CAMERAS FOUND</span>
    <span class="sec-badge" style="color:var(--or)">${iotFinds.length} device(s)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table>
<thead><tr><th>IP</th><th>PORT</th><th>INFO</th></tr></thead>
<tbody>
''');
      for (final f in iotFinds) {
        sb.write('''<tr>
  <td style="color:var(--cy);font-weight:bold">${_e(f['ip']!)}</td>
  <td style="color:var(--dim)">${_e(f['port']!)}</td>
  <td style="font-size:0.85em">${_e(f['info']!)}</td>
</tr>
''');
      }
      sb.write('</tbody></table></div></div></div>\n');
    }

    // ── NTLM Hashes ─────────────────────────────────────────────────────────
    if (ntlmHashes.isNotEmpty) {
      sb.write('''
<div class="sec crit-border" id="sec-ntlm">
<h2><span>⚷ NTLM HASHES CAPTURED</span>
    <span class="sec-badge" style="color:var(--rd)">${ntlmHashes.length} hash(es)</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table>
<thead><tr><th>DOMAIN</th><th>USER</th><th>FROM IP</th><th>HASH (partial)</th></tr></thead>
<tbody>
''');
      for (final h in ntlmHashes) {
        sb.write('''<tr>
  <td style="color:var(--pu)">${_e(h['domain']!)}</td>
  <td style="color:var(--gn);font-weight:bold">${_e(h['user']!)}</td>
  <td style="color:var(--cy)">${_e(h['from']!)}</td>
  <td style="color:var(--dim);font-size:0.8em">${_e(h['hash']!)}</td>
</tr>
''');
      }
      sb.write('</tbody></table></div></div></div>\n');
    }

    // ── Analyst Notes ───────────────────────────────────────────────────────
    if (notes.isNotEmpty) {
      sb.write('''
<div class="sec or-border" id="sec-notes">
<h2><span>≡ ANALYST NOTES</span>
    <span class="sec-badge" style="color:var(--or)">${notes.length} note(s)</span></h2>
<div class="sec-body">
''');
      for (final n in notes) {
        final dt    = n.created;
        final dtStr = '${dt.year}-${_pad(dt.month)}-${_pad(dt.day)}'
                      '  ${_pad(dt.hour)}:${_pad(dt.minute)}';
        sb.write('''<div class="note-card">
  <div class="note-ts">${_e(dtStr)}</div>
  <pre style="color:var(--tx)">${_e(n.content)}</pre>
</div>
''');
      }
      sb.write('</div></div>\n');
    }

    // ── Raw Module Output (collapsed, per session — nmap files excluded) ─────
    final nonNmapFiles = rawFiles.map((session, files) => MapEntry(
      session,
      Map.fromEntries(files.entries.where(
          (e) => !RegExp(r'^nmap', caseSensitive: false).hasMatch(e.key))),
    ));
    final totalNonNmap = nonNmapFiles.values.fold(0, (s, m) => s + m.length);
    if (totalNonNmap > 0) {
      sb.write('''
<div class="sec col" id="sec-raw">
<h2><span>≡ RAW MODULE OUTPUT</span>
    <span class="sec-badge">${sessions.length} sessions &nbsp;·&nbsp; $totalNonNmap files</span></h2>
<div class="sec-body">
''');
      for (final s in sortedSessions) {
        final files = nonNmapFiles[s.folderName];
        if (files == null || files.isEmpty) continue;
        final modLabel = s.moduleName != null ? '${_e(s.moduleName!)}  ' : '';
        sb.write('''<div class="sec col" style="margin-bottom:8px">
<h2 style="font-size:0.82em">
  <span class="h2l">
    <span style="color:var(--cy)">$modLabel</span>
    <span style="color:var(--dim)">${_e(s.folderName)}</span>
    <span style="color:var(--dim);font-size:0.85em">${files.length} files</span>
  </span>
</h2>
<div class="sec-body">
''');
        for (final entry in files.entries) {
          final hasCrit = _hasCritical(entry.value);
          final borderClass = hasCrit ? ' crit-border' : '';
          sb.write('''<div class="sec col$borderClass" style="margin-bottom:6px">
<h2 style="font-size:0.78em">
  <span class="h2l"><span style="color:var(--cy)">${_e(entry.key)}</span>
  ${hasCrit ? '<span style="color:var(--rd)">⚠ findings</span>' : ''}</span>
</h2>
<div class="sec-body"><pre>${_colorizeBlock(entry.value)}</pre></div>
</div>
''');
        }
        sb.write('</div></div>\n');
      }
      sb.write('</div></div>\n');
    }

    // ── Recommendations ─────────────────────────────────────────────────────
    if (recs.isNotEmpty) {
      sb.write('''
<div class="sec col" id="sec-recs">
<h2><span>► RECOMMENDATIONS</span>
    <span class="sec-badge">${recs.length} action(s)</span></h2>
<div class="sec-body">
''');
      for (final rec in recs) {
        final cls = rec.sev == 'CRITICAL' ? 'r' : rec.sev == 'HIGH' ? 'a' : '';
        sb.write('''<div class="rec-card $cls">
  <div class="rec-sev">${_e(rec.sev)}</div>
  <div class="rec-txt">${_e(rec.text)}</div>
</div>
''');
      }
      sb.write('</div></div>\n');
    }

    // ── Footer + JS ─────────────────────────────────────────────────────────
    sb.write('''
<footer>
  <span>F-Security Project Report &nbsp;·&nbsp; ${_e(project.name)}</span>
  <span>F-Security NetHunter &nbsp;·&nbsp; $nowStr</span>
</footer>
</div><!-- /page -->

<script>
function expandAll()  { document.querySelectorAll('.sec').forEach(s=>s.classList.remove('col')); }
function collapseAll(){ document.querySelectorAll('.sec').forEach(s=>s.classList.add('col')); }
document.querySelectorAll('.sec > h2').forEach(h=>{
  h.addEventListener('click', ()=> h.parentElement.classList.toggle('col'));
});
</script>
</body></html>
''');

    return sb.toString();
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  static String _pad(int n) => n.toString().padLeft(2, '0');

  static String _e(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');

  // Require the ESC byte — a bare "[..m" alternative stripped legitimate text
  // like "[2m" / "[10m" out of tool output. [A-Za-z] already covers the 'm'.
  static final _ansiRe = RegExp(r'\x1B\[[0-9;]*[A-Za-z]');
  static String _stripAnsi(String s) => s.replaceAll(_ansiRe, '');

  static bool _hasCritical(String raw) =>
      RegExp(r'vulnerable|NOT ok|CRITICAL|HIGH|login:.*password:', caseSensitive: false)
          .hasMatch(raw);

  static String _colorizeBlock(String text) {
    text = _stripAnsi(text);
    final sb = StringBuffer();
    for (final line in text.split('\n')) {
      final esc = _e(line);
      final lo  = esc.toLowerCase();
      if ((lo.contains('vulnerable') && !lo.contains('not vulnerable')) ||
          lo.contains('not ok')) {
        sb.writeln('<span class="crit">$esc</span>');
      } else if (lo.contains('login:') && lo.contains('password:')) {
        sb.writeln('<span class="crit">$esc</span>');
      } else if (RegExp(r'\b(critical|high)\b').hasMatch(lo)) {
        sb.writeln('<span class="crit">$esc</span>');
      } else if (esc.contains('[+]') || lo.contains('(ok)') || lo.contains('not offered (ok)')) {
        sb.writeln('<span class="ok">$esc</span>');
      } else if (lo.contains('medium') || lo.contains('deprecated') ||
                 lo.contains('self sign') || esc.contains('[!]')) {
        sb.writeln('<span class="warn">$esc</span>');
      } else if (esc.contains('[*]') || lo.contains('[sys]') || lo.contains('[info]')) {
        sb.writeln('<span class="info">$esc</span>');
      } else {
        sb.writeln(esc);
      }
    }
    return sb.toString();
  }
}
