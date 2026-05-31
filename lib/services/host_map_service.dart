import 'dart:io';
import '../models/host_map.dart';

class HostMapService {
  // Parse nmap.txt + fscan.txt from a session directory into a HostMap.
  // brute.txt is checked to flag hosts with cracked credentials.
  static Future<HostMap> parse(String sessionPath, String sessionName) async {
    final Map<String, Set<String>> raw = {}; // ip → set of "port/proto"

    for (final file in ['nmap.txt', 'fscan.txt']) {
      final content = await _read('$sessionPath/$file');
      if (content.isEmpty) continue;

      if (file == 'nmap.txt') {
        _parseNmap(content, raw);
      } else {
        _parseFscan(content, raw);
      }
    }

    // Build credential set from brute.txt
    final bruteContent = await _read('$sessionPath/brute.txt');
    final hostsWithCreds = <String>{};
    for (final line in bruteContent.split('\n')) {
      final m = RegExp(r'(\d+\.\d+\.\d+\.\d+)').firstMatch(line);
      if (m != null && line.contains('login:')) {
        hostsWithCreds.add(m.group(1)!);
      }
    }

    final hosts = raw.entries.map((e) {
      final ports = e.value.map((p) {
        final parts = p.split('/');
        return DiscoveredPort(
          number: int.tryParse(parts[0]) ?? 0,
          protocol: parts.length > 1 ? parts[1] : 'tcp',
        );
      }).toList()
        ..sort((a, b) => a.number.compareTo(b.number));
      return DiscoveredHost(
        ip: e.key,
        ports: ports,
        hasCredentials: hostsWithCreds.contains(e.key),
      );
    }).toList()
      ..sort((a, b) => _ipToInt(a.ip).compareTo(_ipToInt(b.ip)));

    return HostMap(
      sessionName: sessionName,
      sessionPath: sessionPath,
      hosts: hosts,
    );
  }

  static void _parseNmap(String content, Map<String, Set<String>> out) {
    String? current;
    final hostRe = RegExp(r'scan report for (\d+\.\d+\.\d+\.\d+)');
    final portRe = RegExp(r'^(\d+)/(tcp|udp)\s+open');
    for (final line in content.split('\n')) {
      final hm = hostRe.firstMatch(line);
      if (hm != null) { current = hm.group(1); continue; }
      if (current == null) continue;
      final pm = portRe.firstMatch(line.trim());
      if (pm != null) {
        (out[current] ??= {}).add('${pm.group(1)}/${pm.group(2)}');
      }
    }
  }

  static void _parseFscan(String content, Map<String, Set<String>> out) {
    final re = RegExp(r'\[\*\]\s+(\d+\.\d+\.\d+\.\d+):(\d+)');
    for (final line in content.split('\n')) {
      final m = re.firstMatch(line);
      if (m != null) {
        (out[m.group(1)!] ??= {}).add('${m.group(2)}/tcp');
      }
    }
  }

  static Future<String> _read(String path) async {
    final r = await Process.run('su', ['-c', 'cat "$path" 2>/dev/null']);
    return r.stdout.toString();
  }

  static int _ipToInt(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return 0;
    return parts.fold(0, (v, p) => (v << 8) + (int.tryParse(p) ?? 0));
  }

  // Returns a one-liner shell command to run inside chroot for a given port,
  // or null if no direct action applies.
  static String? actionCommand(String ip, DiscoveredPort port) {
    return switch (port.number) {
      21   => 'curl -s --connect-timeout 5 "ftp://$ip/" --user "anonymous:anonymous" | head -40',
      22   => 'ssh -o StrictHostKeyChecking=no root@$ip',
      23   => 'telnet $ip',
      80   => 'curl -skL --connect-timeout 5 -I "http://$ip:80/" && echo "---" && curl -skL --connect-timeout 5 "http://$ip:80/" | grep -io "<title>[^<]*"',
      443  => 'curl -skL --connect-timeout 5 -I "https://$ip:443/" && echo "---" && curl -skL --connect-timeout 5 "https://$ip:443/" | grep -io "<title>[^<]*"',
      8080 => 'curl -skL --connect-timeout 5 -I "http://$ip:8080/" && echo "---" && curl -skL --connect-timeout 5 "http://$ip:8080/" | grep -io "<title>[^<]*"',
      8443 => 'curl -skL --connect-timeout 5 -I "https://$ip:8443/" && echo "---" && curl -skL --connect-timeout 5 "https://$ip:8443/" | grep -io "<title>[^<]*"',
      445  => 'smbclient -L "//$ip" -N 2>/dev/null || echo "[~] Null session rejected"',
      554  => 'echo "[*] RTSP $ip:554 — stream URLs to try:" && for p in "" live stream cam h264 1/1 channel1; do echo "  rtsp://$ip:554/\$p"; done',
      1883 => 'timeout 10 mosquitto_sub -h $ip -t "#" -v 2>/dev/null || echo "[~] mosquitto_sub not found or no broker"',
      3306 => 'mysql -h $ip -u root --connect-timeout=5 -e "show databases;" 2>/dev/null || echo "[~] No anonymous MySQL access"',
      5432 => 'PGCONNECT_TIMEOUT=4 psql -h $ip -U postgres -d postgres -c "SELECT version();" -t -A 2>/dev/null || echo "[~] No anonymous PostgreSQL access"',
      6379 => 'printf "*1\\r\\n\$4\\r\\nPING\\r\\n" | nc -w 3 $ip 6379',
      2049 => 'showmount -e --no-headers $ip 2>/dev/null || echo "[~] showmount failed — apt install nfs-common"',
      161  => 'snmpwalk -v2c -c public -t 3 $ip 2>/dev/null | head -30',
      8009 => 'nmap -sT --unprivileged -p 8009 --script ajp-request $ip 2>/dev/null',
      7001 => 'printf "t3 12.2.3\\nAS:255\\nHL:19\\nMS:10000000\\n\\n" | nc -w 4 $ip 7001 2>/dev/null | strings | head -5',
      _    => null,
    };
  }

  static String actionLabel(int port) {
    return switch (port) {
      21   => 'FTP anonymous',
      22   => 'SSH connect',
      23   => 'Telnet connect',
      80   => 'HTTP fingerprint',
      443  => 'HTTPS fingerprint',
      8080 => 'HTTP :8080',
      8443 => 'HTTPS :8443',
      445  => 'SMB shares',
      554  => 'RTSP paths',
      1883 => 'MQTT subscribe',
      3306 => 'MySQL probe',
      5432 => 'PostgreSQL probe',
      6379 => 'Redis ping',
      2049 => 'NFS exports',
      161  => 'SNMP walk',
      8009 => 'Ghostcat AJP',
      7001 => 'WebLogic T3',
      _    => 'port $port',
    };
  }
}
