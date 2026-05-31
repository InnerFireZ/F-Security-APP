import 'dart:io';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'nethunter_service.dart';

class ScriptDeployer {
  static const _versionKey    = 'deployed_version';
  static const _currentVersion = '194';
  static const currentVersion  = _currentVersion;

  static const _assetFiles = [
    'assets/fsec/lib.sh',
    'assets/fsec/start.sh',
    'assets/fsec/oui.txt',
    'assets/fsec/routes.txt',
    'assets/fsec/recon_iot_scada.py',
    'assets/fsec/fscan',
    'assets/fsec/kerbrute',
    'assets/fsec/scripts/gen_probe_map.py',
    'assets/fsec/scripts/nmap.sh',
    'assets/fsec/scripts/crackmap.sh',
    'assets/fsec/scripts/fscan.sh',
    'assets/fsec/scripts/autorecon.sh',
    'assets/fsec/scripts/rtsp_brute_open.sh',
    'assets/fsec/scripts/nuclei.sh',
    'assets/fsec/scripts/web.sh',
    'assets/fsec/scripts/iot.sh',
    'assets/fsec/scripts/brute.sh',
    'assets/fsec/scripts/ssl.sh',
    'assets/fsec/scripts/dns_ad.sh',
    'assets/fsec/scripts/report.sh',
    'assets/fsec/scripts/post.sh',
    'assets/fsec/scripts/c2.sh',
    'assets/fsec/scripts/exploit.sh',
    'assets/fsec/scripts/responder.sh',
    'assets/fsec/scripts/deauth_all.sh',
    'assets/fsec/scripts/deauth_clients.sh',
    'assets/fsec/scripts/deauth_watcher.sh',
    'assets/fsec/scripts/flip_detector.sh',
    'assets/fsec/scripts/mac_bypass.sh',
    'assets/fsec/scripts/probe_sniffer.sh',
    'assets/fsec/scripts/wifi_vivacom.sh',
    'assets/fsec/scripts/bettercap.sh',
    'assets/fsec/scripts/ntlm_relay.sh',
    'assets/fsec/scripts/wifite.sh',
    'assets/fsec/scripts/netsniff.sh',
    'assets/fsec/scripts/netkill.sh',
    'assets/fsec/scripts/pret.sh',
    'assets/fsec/scripts/vnc.sh',
    'assets/fsec/scripts/ssh_audit.sh',
    'assets/fsec/scripts/kerberos.sh',
    'assets/fsec/scripts/mitm6.sh',
    'assets/fsec/scripts/certipy.sh',
    'assets/fsec/scripts/snmp.sh',
    'assets/fsec/scripts/airbt.sh',
    'assets/fsec/scripts/ble_recon.sh',
    'assets/fsec/scripts/impacket.sh',
    'assets/fsec/scripts/sqlmap.sh',
    'assets/fsec/scripts/hashcrack.sh',
    'assets/fsec/scripts/enum4linux.sh',
    'assets/fsec/scripts/harvester.sh',
    'assets/fsec/scripts/evilwinrm.sh',
    'assets/fsec/scripts/tunnel.sh',
    'assets/fsec/scripts/linpeas.sh',
    'assets/fsec/scripts/wpscan.sh',
    'assets/fsec/scripts/ldap_dump.sh',
    'assets/fsec/scripts/masscan.sh',
    'assets/fsec/scripts/karma.sh',
    'assets/fsec/air-bt/main.py',
    'assets/fsec/air-bt/models.py',
    'assets/fsec/air-bt/export.py',
    'assets/fsec/air-bt/debug.py',
    'assets/fsec/air-bt/requirements.txt',
    'assets/fsec/air-bt/scanner/__init__.py',
    'assets/fsec/air-bt/scanner/ble.py',
    'assets/fsec/air-bt/scanner/gatt.py',
    'assets/fsec/air-bt/scanner/poc.py',
    'assets/fsec/air-bt/scanner/writer.py',
    'assets/fsec/air-bt/display/__init__.py',
    'assets/fsec/air-bt/display/table.py',
    'assets/fsec/air-bt/payloads/__init__.py',
    'assets/fsec/air-bt/payloads/library.py',
    'assets/fsec/air-bt/data/__init__.py',
    'assets/fsec/air-bt/data/cve.py',
    'assets/fsec/air-bt/data/oui.py',
    'assets/fsec/air-bt/data/protocols.py',
    'assets/fsec/air-bt/data/uuids.py',
    'assets/fsec/vnc_scanner.py',
    'assets/fsec/ssh_audit.py',
    'assets/fsec/Ingram/auto_ingramv2.sh',
    // KARMA rogue-AP suite
    'assets/fsec/karma/karma.py',
    'assets/fsec/karma/known_beacons.py',
    'assets/fsec/karma/iot_wordlist.txt',
    'assets/fsec/karma/essids.txt',
    'assets/fsec/karma/on_client/scan.sh',
    'assets/fsec/karma/on_client/rtsp.sh',
    'assets/fsec/karma/on_client/http_basic_brute.sh',
    'assets/fsec/karma/on_client/www_screenshot.sh',
    'assets/fsec/karma/on_client/rdp_screenshot.sh',
    'assets/fsec/karma/on_client/smb_null.sh',
    'assets/fsec/karma/on_client/ms17-010.sh',
    'assets/fsec/karma/on_client/routersploit.sh',
    'assets/fsec/karma/on_client/ip_forwarding.sh',
    'assets/fsec/karma/on_client/interfaces.py',
    'assets/fsec/karma/on_client/bruteforce/ssh.sh',
    'assets/fsec/karma/on_client/bruteforce/smb.sh',
    'assets/fsec/karma/on_client/bruteforce/rdp.sh',
    'assets/fsec/karma/on_client/bruteforce/piata_ssh_userpass.txt',
    'assets/fsec/karma/on_client/bruteforce/default_pass_for_services_unhash.txt',
    'assets/fsec/karma/on_handshake/bruteforce.sh',
    'assets/fsec/karma/on_network/responder.sh',
    'assets/fsec/karma/on_network/tcpdump.sh',
    'assets/fsec/karma/on_probe/log.sh',
  ];

  static Future<bool> needsDeploy() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_versionKey) != _currentVersion;
  }

  static Future<void> markDeployed() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_versionKey, _currentVersion);
  }

  static Future<void> deploy({
    required void Function(String msg, double progress) onProgress,
  }) async {
    final tmp = await getApplicationDocumentsDirectory();
    final staging = '${tmp.path}/fsec_staging';
    final chroot  = NetHunterService.chrootPath;
    final dest    = NetHunterService.scriptsPath; // /root/f-security

    // 1. Extract assets to app-private staging dir
    for (var i = 0; i < _assetFiles.length; i++) {
      final asset = _assetFiles[i];
      final progress = (i + 1) / (_assetFiles.length + 3);
      onProgress('Extracting ${asset.split('/').last}...', progress);

      final relative = asset.replaceFirst('assets/fsec/', '');
      final outPath  = '$staging/$relative';
      await Directory(File(outPath).parent.path).create(recursive: true);

      final data = await rootBundle.load(asset);
      await File(outPath).writeAsBytes(
        data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes),
      );
    }

    // 2. Create destination structure in chroot
    onProgress('Creating directories in chroot...', 0.88);
    await Process.run('su', ['-c',
      'mkdir -p $chroot$dest/scripts $chroot$dest/Ingram $chroot$dest/results '
      '$chroot$dest/karma/on_client/bruteforce '
      '$chroot$dest/karma/on_handshake '
      '$chroot$dest/karma/on_network '
      '$chroot$dest/karma/on_probe '
      '$chroot$dest/karma/handshakes',
    ]);

    // 3. Copy staging → chroot
    onProgress('Copying files to NetHunter...', 0.92);
    await Process.run('su', ['-c',
      'cp -r $staging/. $chroot$dest/',
    ]);

    // 4. Set permissions
    onProgress('Setting permissions...', 0.96);
    await Process.run('su', ['-c',
      'chmod +x $chroot$dest/lib.sh '
      '$chroot$dest/start.sh '
      '$chroot$dest/fscan '
      '$chroot$dest/kerbrute '
      '$chroot$dest/recon_iot_scada.py '
      '$chroot$dest/vnc_scanner.py '
      '$chroot$dest/ssh_audit.py '
      '$chroot$dest/scripts/*.sh '
      '$chroot$dest/Ingram/*.sh '
      '$chroot$dest/karma/karma.py '
      '$chroot$dest/karma/on_client/*.sh '
      '$chroot$dest/karma/on_client/bruteforce/*.sh '
      '$chroot$dest/karma/on_handshake/*.sh '
      '$chroot$dest/karma/on_network/*.sh '
      '$chroot$dest/karma/on_probe/*.sh 2>/dev/null; '
      'chmod 644 $chroot$dest/oui.txt $chroot$dest/routes.txt 2>/dev/null',
    ]);

    onProgress('Done.', 1.0);
    await markDeployed();
  }
}
