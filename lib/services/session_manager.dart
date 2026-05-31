import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter_pty/flutter_pty.dart';
import 'package:wakelock_plus/wakelock_plus.dart';
import 'package:xterm/xterm.dart';
import '../models/module.dart';
import 'nethunter_service.dart';
import 'scan_foreground_service.dart';

class ActiveSession {
  final Module module;
  final Pty pty;
  final Terminal terminal;
  final StringBuffer rawOutput;
  final String pidFile;
  bool isRunning;
  final Set<String> _alertedMacs = {};

  ActiveSession({
    required this.module,
    required this.pty,
    required this.terminal,
    required this.rawOutput,
    required this.pidFile,
    this.isRunning = true,
  });

  // Returns true the first time a given MAC is seen — false on repeats.
  bool markAlerted(String mac) => _alertedMacs.add(mac);
}

class SessionManager {
  SessionManager._();
  static final SessionManager instance = SessionManager._();

  final Map<int, ActiveSession> _sessions = {};

  // Any widget can listen to know which module IDs are currently running.
  final ValueNotifier<Set<int>> runningIds = ValueNotifier(const {});

  // ── Public API ───────────────────────────────────────────────────────────

  // Start a session. If one already exists for this module, return it.
  // [onDone] fires when the PTY process exits naturally.
  // [projectSlug] is injected as $PROJECT_SLUG so scripts write into results/<slug>/.
  ActiveSession start({
    required Module module,
    String? projectSlug,
    void Function()? onDone,
  }) {
    final existing = _sessions[module.id];
    if (existing != null) return existing;

    final terminal  = Terminal(maxLines: 10000);
    final rawOutput = StringBuffer();
    final pidFile   = '/data/local/tmp/fsec_${DateTime.now().millisecondsSinceEpoch}.pid';
    final basecmd   = NetHunterService.buildChainedCommand(
      module.script,
      projectSlug: projectSlug,
    );
    final cmd       = 'echo \$\$ > $pidFile; $basecmd';

    final pty = Pty.start(
      'su',
      arguments: ['-c', cmd],
      columns: 120,
      rows: 40,
      environment: {'TERM': 'xterm-256color'},
    );

    final session = ActiveSession(
      module: module,
      pty: pty,
      terminal: terminal,
      rawOutput: rawOutput,
      pidFile: pidFile,
    );

    pty.output
        .cast<List<int>>()
        .transform(const Utf8Decoder(allowMalformed: true))
        .listen(
          (data) {
            terminal.write(data);
            rawOutput.write(data);
            // Flipper Detector live alerts (module 21 only)
            if (module.id == 21 && data.contains('FLIPPER FOUND')) {
              final clean = data.replaceAll(
                  RegExp(r'\x1b\[[0-9;]*[A-Za-z]|\x1b[()][A-Z0-9]'), '');
              final mac = RegExp(
                      r'MAC:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})')
                  .firstMatch(clean)
                  ?.group(1) ?? '';
              final name = RegExp(r'Name:\s*([^\n\r]+)')
                  .firstMatch(clean)
                  ?.group(1)
                  ?.trim() ?? 'unknown';
              if (mac.isNotEmpty && session.markAlerted(mac)) {
                unawaited(ScanForegroundService.showFlipperAlert(mac, name));
              }
            }
            // Deauth Watcher attack alerts (module 20 only)
            if (module.id == 20 && data.contains('[DEAUTH ATTACK]')) {
              final clean = data.replaceAll(
                  RegExp(r'\x1b\[[0-9;]*[A-Za-z]|\x1b[()][A-Z0-9]'), '');
              final attacker = RegExp(
                      r'ATTACKER:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})')
                  .firstMatch(clean)
                  ?.group(1) ?? '';
              final ssid = RegExp(r'SSID:\s*(.*?)\s{2,}')
                  .firstMatch(clean)
                  ?.group(1)
                  ?.trim() ?? '?';
              final burst = RegExp(r'BURST:\s*(\d+)')
                  .firstMatch(clean)
                  ?.group(1) ?? '?';
              final deauthKey = '${attacker}_$ssid';
              if (attacker.isNotEmpty && session.markAlerted(deauthKey)) {
                unawaited(
                    ScanForegroundService.showDeauthAlert(attacker, ssid, burst));
              }
            }
          },
          onDone: () {
            session.isRunning = false;
            _remove(module.id);
            onDone?.call();
            if (_sessions.isEmpty) {
              unawaited(ScanForegroundService.completeScan(module.name));
            } else {
              unawaited(ScanForegroundService.updateLabel(
                  _sessions.values.first.module.name));
            }
          },
        );

    terminal.onOutput = (data) => pty.write(const Utf8Encoder().convert(data));

    _sessions[module.id] = session;
    _notify();
    unawaited(ScanForegroundService.startScan(module.name));
    return session;
  }

  // Kill a session immediately (used by the hard-kill path and back button stop).
  void kill(int moduleId) {
    final s = _sessions.remove(moduleId);
    if (s == null) return;
    s.pty.kill();
    s.isRunning = false;
    _notify();
    // User-initiated stop — no completion notification.
    if (_sessions.isEmpty) {
      unawaited(ScanForegroundService.stopScan());
    } else {
      unawaited(ScanForegroundService.updateLabel(
          _sessions.values.first.module.name));
    }
  }

  ActiveSession? get(int moduleId) => _sessions[moduleId];

  bool isActive(int moduleId) => _sessions.containsKey(moduleId);

  // ── Internals ────────────────────────────────────────────────────────────

  void _remove(int moduleId) {
    _sessions.remove(moduleId);
    _notify();
  }

  void _notify() {
    runningIds.value = Set.unmodifiable(_sessions.keys);
    // Screen stays on while any session is alive; releases when all done.
    if (_sessions.isNotEmpty) {
      WakelockPlus.enable();
    } else {
      WakelockPlus.disable();
    }
  }
}
