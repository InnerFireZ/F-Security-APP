import 'dart:io';
import 'settings_service.dart';

class NetHunterService {
  static String chrootPath   = '/data/local/nhsystem/kali-arm64';
  static String scriptsPath  = '/root/f-security';

  static Future<bool> hasRoot() async {
    try {
      final r = await Process.run('su', ['-c', 'id']);
      return r.stdout.toString().contains('uid=0');
    } catch (_) {
      return false;
    }
  }

  static Future<bool> hasChrootAt(String path) async {
    try {
      final r = await Process.run('su', ['-c', 'test -d $path && echo yes']);
      return r.stdout.toString().trim() == 'yes';
    } catch (_) {
      return false;
    }
  }

  // Tries the configured path first, then all known NetHunter variants.
  // Returns the first working path, or null if none found.
  static const _candidatePaths = [
    '/data/local/nhsystem/kali-arm64',
    '/data/local/nhsystem/kali-arm',
    '/data/local/nhsystem/kali-aarch64',
    '/data/nhsystem/kali-arm64',
    '/data/nhsystem/kali-arm',
  ];

  static Future<String?> detectChrootPath() async {
    if (await hasChrootAt(chrootPath)) return chrootPath;
    for (final p in _candidatePaths) {
      if (p == chrootPath) continue;
      if (await hasChrootAt(p)) return p;
    }
    return null;
  }

  static Future<bool> hasScripts() async {
    try {
      final r = await Process.run('su', [
        '-c',
        'test -f "$chrootPath$scriptsPath/start.sh" && echo yes',
      ]);
      return r.stdout.toString().trim() == 'yes';
    } catch (_) {
      return false;
    }
  }

  // Sanitize a project name into a safe filesystem slug (lowercase, underscores).
  static String slugify(String name) {
    return name
        .toLowerCase()
        .replaceAll(RegExp(r'[^a-z0-9]+'), '_')
        .replaceAll(RegExp(r'^_+|_+$'), '');
  }

  // PATH used inside the chroot — includes /root/.local/bin for pipx-installed tools.
  static const linuxPath =
      '/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

  // Single-line command — no newlines, avoids su -c parsing issues on Android
  static String buildCommand(String script) {
    return 'chroot $chrootPath /usr/bin/env -i'
        ' HOME=/root TERM=xterm-256color PATH=$linuxPath'
        ' /bin/bash $scriptsPath/$script';
  }

  // Like buildCommand but injects TARGET / SESSION_DIR / PROJECT_SLUG / DOMAIN as env vars.
  static String buildChainedCommand(String script, {
    String? target,
    String? sessionDir,
    String? projectSlug,
    String? domain,
    Map<String, String>? extraEnv,
  }) {
    final extra = StringBuffer();
    if (target != null && target.isNotEmpty) extra.write(' TARGET=${_shellQuote(target)}');
    if (sessionDir != null && sessionDir.isNotEmpty) extra.write(' SESSION_DIR=${_shellQuote(sessionDir)}');
    if (projectSlug != null && projectSlug.isNotEmpty) extra.write(' PROJECT_SLUG=${_shellQuote(projectSlug)}');
    if (domain != null && domain.isNotEmpty) extra.write(' DOMAIN=${_shellQuote(domain)}');
    extra.write(' WORDLIST=${_shellQuote(SettingsService.wordlistPath)}');
    extra.write(' NUCLEI_CONC=${SettingsService.nucleiConc}');
    extraEnv?.forEach((k, v) { if (v.isNotEmpty) extra.write(' $k=${_shellQuote(v)}'); });
    return 'chroot $chrootPath /usr/bin/env -i'
        ' HOME=/root TERM=xterm-256color PATH=$linuxPath$extra'
        ' /bin/bash $scriptsPath/$script';
  }

  // Wrap in single-quotes, escaping any embedded single-quotes.
  static String _shellQuote(String s) => "'${s.replaceAll("'", "'\\''")}'";

  // Public version used by report_service.dart.
  static String shellQuote(String s) => _shellQuote(s);
}
