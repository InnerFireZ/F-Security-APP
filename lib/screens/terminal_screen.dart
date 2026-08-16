import 'dart:convert';
import 'dart:io';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:xterm/xterm.dart';
import '../data/modules.dart';
import '../models/module.dart';
import '../services/host_map_service.dart';
import '../services/nethunter_service.dart';
import '../services/project_service.dart';
import '../services/session_manager.dart';
import '../services/settings_service.dart';
import '../theme/colors.dart';

class TerminalScreen extends StatefulWidget {
  final Module module;
  final String? projectSlug;
  const TerminalScreen({super.key, required this.module, this.projectSlug});

  @override
  State<TerminalScreen> createState() => _TerminalScreenState();
}

class _TerminalScreenState extends State<TerminalScreen> {
  late ActiveSession _session;
  double _fontSize   = 9.0;
  String _termTheme  = 'grey';

  // Whether the PTY is currently running (tracks _session.isRunning locally
  // so we can call setState when it changes).
  bool _running = true;

  @override
  void initState() {
    super.initState();
    SettingsService.getFontSize().then((v) { if (mounted) setState(() => _fontSize = v); });
    SettingsService.getTerminalTheme().then((v) { if (mounted) setState(() => _termTheme = v); });

    final existing = SessionManager.instance.get(widget.module.id);
    if (existing != null) {
      // Reconnect to already-running session.
      _session = existing;
      _running = existing.isRunning;
      // Re-wire keyboard → PTY (terminal.onOutput is replaced per-attach).
      _session.terminal.onOutput = (data) =>
          _session.pty.write(const Utf8Encoder().convert(data));
      // Re-point completion callback at THIS (live) State — the original screen's
      // closure is dead, so without this a reconnected session shows "running"
      // forever after the process exits.
      _session.onDone = () {
        if (mounted) setState(() => _running = false);
        _syncToProject();
      };
    } else {
      // Launch a new session.
      _session = SessionManager.instance.start(
        module: widget.module,
        projectSlug: widget.projectSlug,
        onDone: () {
          if (mounted) setState(() => _running = false);
          _syncToProject();
        },
      );
      _running = true;
    }

    // Sync PTY size after first frame.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_session.terminal.viewWidth > 0) {
        _session.pty.resize(
          _session.terminal.viewHeight,
          _session.terminal.viewWidth,
        );
      }
    });
  }

  @override
  void dispose() {
    // Do NOT kill the PTY here — session stays alive in SessionManager.
    // We only detach the resize handler.
    _session.terminal.onResize = null;
    super.dispose();
  }

  // ── Project sync ─────────────────────────────────────────────────────────

  Future<void> _syncToProject() async {
    try {
      final project = await ProjectService.getActiveProject();
      if (project == null) return;
      final resultsBase =
          '${NetHunterService.chrootPath}${NetHunterService.scriptsPath}/results';
      final slug = widget.projectSlug;
      final searchPath = (slug != null && slug.isNotEmpty)
          ? '$resultsBase/$slug'
          : resultsBase;
      final tsFolder = await ProjectService.latestSessionFolder(searchPath);
      if (tsFolder == null) return;
      final folderName = (slug != null && slug.isNotEmpty) ? '$slug/$tsFolder' : tsFolder;
      await ProjectService.attachSession(project.id!, folderName, widget.module.name);
      final map = await HostMapService.parse('$searchPath/$tsFolder', folderName);
      if (!map.isEmpty) await ProjectService.mergeHostMap(project.id!, map);
      final r = await Process.run('su',
          ['-c', 'cat "$searchPath/$tsFolder/brute.txt" 2>/dev/null']);
      final bruteTxt = r.stdout.toString();
      if (bruteTxt.trim().isNotEmpty) {
        await ProjectService.importCredentials(project.id!, folderName, bruteTxt);
      }
      // Auto-import cracked passwords from hashcrack module
      final rc = await Process.run('su',
          ['-c', 'cat "$searchPath/$tsFolder/cracked.txt" 2>/dev/null']);
      final crackedTxt = rc.stdout.toString();
      if (crackedTxt.trim().isNotEmpty) {
        await ProjectService.importCracked(project.id!, folderName, crackedTxt);
      }
    } catch (_) {}
  }

  // ── Signal helpers ───────────────────────────────────────────────────────

  // Tap — soft Ctrl+C: SIGINT only to the foreground tool (e.g. wifite).
  void _sendSoftCtrlC() {
    final toolPid = '${NetHunterService.chrootPath}/tmp/.fsec_tool.pid';
    Process.run('su', ['-c',
      'child=\$(cat $toolPid 2>/dev/null); '
      '[ -n "\$child" ] && kill -INT "\$child" 2>/dev/null; '
      'true',
    ]);
  }

  // Long press — hard kill: SIGINT to whole process group, then remove session.
  void _sendCtrlC() {
    HapticFeedback.heavyImpact();
    final pf = _session.pidFile;
    Process.run('su', ['-c',
      'pid=\$(cat $pf 2>/dev/null); '
      '[ -n "\$pid" ] && kill -INT -\$pid 2>/dev/null; '
      'true',
    ]);
    // Remove from manager — the onDone stream may not fire for all scripts.
    SessionManager.instance.kill(widget.module.id);
    if (mounted) setState(() => _running = false);
  }

  // ── Chain suggestion ─────────────────────────────────────────────────────

  List<Module> _chainSuggestions() {
    final out = widget.module.chainOutput;
    final cat = widget.module.category;
    final id  = widget.module.id;

    // ── Hash producers → crack ────────────────────────────────────────────────
    if (out == ChainOutput.hashes) {
      return kModules.where((m) => m.id == 41).toList(); // Hash Cracker
    }

    // ── Credential producers → exploit ────────────────────────────────────────
    if (out == ChainOutput.credentials) {
      return kModules.where((m) => m.id == 39 || m.id == 44 || m.id == 14).toList();
      // Impacket + Evil-WinRM + Post
    }

    // ── Module-specific chain overrides ───────────────────────────────────────
    if (out == ChainOutput.sessionDir) {
      switch (id) {
        // Masscan → nmap for version/service details
        case 49: return kModules.where((m) => m.id == 3 || m.id == 6).toList();
        // Nmap / Fscan / Autorecon → Exploit or Nuclei vuln-check
        case 2: case 3: case 7:
          return kModules.where((m) => m.id == 16 || m.id == 6).toList();
        // Nuclei found vulns → Exploit launcher
        case 6: return kModules.where((m) => m.id == 16).toList();
        // LDAP Dump → Kerberos attack
        case 48: return kModules.where((m) => m.id == 33 || m.id == 12).toList();
        // Enum4linux users → Brute spray
        case 42: return kModules.where((m) => m.id == 10 || m.id == 1).toList();
        // Hash Cracker cracked → use creds in Impacket/Evil-WinRM
        case 41: return kModules.where((m) => m.id == 39 || m.id == 44).toList();
        // Web recon → SQLMap or WPScan
        case 8: return kModules.where((m) => m.id == 40 || m.id == 47).toList();
        // WPScan users found → Brute WP login
        case 47: return kModules.where((m) => m.id == 10).toList();
        // SQLMap → Post (OS shell)
        case 40: return kModules.where((m) => m.id == 14).toList();
        // Impacket secretsdump → Hash Cracker
        case 39: return kModules.where((m) => m.id == 41).toList();
        // ADCS exploit → Evil-WinRM with cert auth
        case 35: return kModules.where((m) => m.id == 44).toList();
        // LinPEAS found privesc → C2 (setup listener for exploit)
        case 46: return kModules.where((m) => m.id == 15).toList();
        // SSH Audit → Brute (known weak algos)
        case 32: return kModules.where((m) => m.id == 10).toList();
        // Post hub → Tunnel/Pivot for lateral movement
        case 14: return kModules.where((m) => m.id == 45 || m.id == 46).toList();
        default: break;
      }

      // Category-based fallbacks
      if (cat == ModuleCategory.network || cat == ModuleCategory.recon) {
        return kModules.where((m) => m.id == 16 || m.id == 6).toList();
      }
      if (cat == ModuleCategory.exploit) {
        return kModules.where((m) => m.id == 46 || m.id == 45).toList();
      }
    }
    return [];
  }

  Widget _buildChainBanner() {
    final suggestions = _chainSuggestions();
    if (suggestions.isEmpty) return const SizedBox.shrink();

    final out = widget.module.chainOutput;
    final Color bannerColor = out == ChainOutput.hashes
        ? FColors.red
        : out == ChainOutput.credentials
            ? FColors.green
            : FColors.cyan;
    final String outputLabel = out == ChainOutput.hashes
        ? 'HASHES captured'
        : out == ChainOutput.credentials
            ? 'CREDENTIALS found'
            : 'Results saved';

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: FColors.bgCard,
        border: Border(top: BorderSide(color: bannerColor.op(0.5))),
      ),
      child: Row(
        children: [
          Icon(Icons.link, color: bannerColor, size: 14),
          const SizedBox(width: 6),
          Text(
            '$outputLabel  →  Chain to:',
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 10,
              color: bannerColor,
              letterSpacing: 0.5,
            ),
          ),
          const SizedBox(width: 8),
          ...suggestions.take(3).map((m) => Padding(
            padding: const EdgeInsets.only(right: 6),
            child: InkWell(
              onTap: () {
                Navigator.pushReplacement(
                  context,
                  MaterialPageRoute(
                    builder: (_) => TerminalScreen(
                      module: m,
                      projectSlug: widget.projectSlug,
                    ),
                  ),
                );
              },
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  border: Border.all(color: bannerColor.op(0.6)),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text(
                  m.name,
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 10,
                    color: bannerColor,
                  ),
                ),
              ),
            ),
          )),
        ],
      ),
    );
  }

  void _copyOutput() {
    final clean = _session.rawOutput.toString()
        .replaceAll(RegExp(r'\x1B\[[0-9;:]*[A-Za-z]'), '')
        .replaceAll(RegExp(r'\x1B\][^\x07]*\x07'), '')
        .replaceAll('\r\n', '\n')
        .replaceAll('\r', '\n');
    Clipboard.setData(ClipboardData(text: clean));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
      content: Text('Output copied',
          style: TextStyle(fontFamily: 'monospace', fontSize: 11)),
      backgroundColor: Color(0xFF0D1117),
      duration: Duration(seconds: 2),
    ));
  }

  // ── Build ────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    // Keep PTY size synced to actual terminal view.
    _session.terminal.onResize = (w, h, pw, ph) =>
        _session.pty.resize(h, w);

    return Scaffold(
      backgroundColor: FColors.bg,
      appBar: AppBar(
        backgroundColor: FColors.bgCard,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
          // Back: detach only — session keeps running in background.
          onPressed: () => Navigator.pop(context),
        ),
        title: Row(
          children: [
            Flexible(
              child: Text(
                '[${widget.module.id.toString().padLeft(2, '0')}] ${widget.module.name}',
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  color: FColors.cyan,
                  fontSize: 13,
                  letterSpacing: 1,
                ),
              ),
            ),
            const SizedBox(width: 8),
            if (_running)
              Container(
                width: 7, height: 7,
                decoration: const BoxDecoration(
                  color: FColors.green, shape: BoxShape.circle),
              )
            else
              const Text('done',
                style: TextStyle(
                  fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.remove, color: FColors.textSecondary, size: 18),
            onPressed: () {
              final s = (_fontSize - 1).clamp(7.0, 20.0);
              setState(() => _fontSize = s);
              SettingsService.saveFontSize(s);
            },
          ),
          IconButton(
            icon: const Icon(Icons.add, color: FColors.textSecondary, size: 18),
            onPressed: () {
              final s = (_fontSize + 1).clamp(7.0, 20.0);
              setState(() => _fontSize = s);
              SettingsService.saveFontSize(s);
            },
          ),
          IconButton(
            icon: const Icon(Icons.copy_outlined, color: FColors.textSecondary, size: 18),
            onPressed: _copyOutput,
          ),
          RawGestureDetector(
            gestures: {
              TapGestureRecognizer:
                GestureRecognizerFactoryWithHandlers<TapGestureRecognizer>(
                  () => TapGestureRecognizer(),
                  (i) => i.onTap = _sendSoftCtrlC,
                ),
              LongPressGestureRecognizer:
                GestureRecognizerFactoryWithHandlers<LongPressGestureRecognizer>(
                  () => LongPressGestureRecognizer(
                      duration: const Duration(milliseconds: 600)),
                  (i) => i.onLongPress = _sendCtrlC,
                ),
            },
            child: const Padding(
              padding: EdgeInsets.symmetric(horizontal: 8, vertical: 8),
              child: Icon(Icons.stop_circle_outlined, color: FColors.red, size: 20),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.refresh, color: FColors.cyan, size: 20),
            tooltip: 'Relaunch',
            onPressed: _running ? null : () {
              // Kill old session if lingering, start fresh.
              SessionManager.instance.kill(widget.module.id);
              _session = SessionManager.instance.start(
                module: widget.module,
                projectSlug: widget.projectSlug,
                onDone: () {
                  if (mounted) setState(() => _running = false);
                  _syncToProject();
                },
              );
              _session.terminal.onOutput = (data) =>
                  _session.pty.write(const Utf8Encoder().convert(data));
              setState(() => _running = true);
            },
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: Column(
        children: [
          Expanded(
            child: TerminalView(
        _session.terminal,
        theme: _termTheme == 'green'
            ? const TerminalTheme(
                cursor:        Color(0xFF00FF41),
                selection:     Color(0x4400FF41),
                foreground:    Color(0xFF00FF41),
                background:    Color(0xFF000000),
                black:         Color(0xFF000000),
                white:         Color(0xFF00FF41),
                red:           Color(0xFFFF5555),
                green:         Color(0xFF00FF41),
                yellow:        Color(0xFFFFB86C),
                blue:          Color(0xFF00E5FF),
                magenta:       Color(0xFFFF79C6),
                cyan:          Color(0xFF00E5FF),
                brightBlack:   Color(0xFF005A1A),
                brightWhite:   Color(0xFF80FF9F),
                brightRed:     Color(0xFFFF6E6E),
                brightGreen:   Color(0xFF69FF47),
                brightYellow:  Color(0xFFFFB86C),
                brightBlue:    Color(0xFF00E5FF),
                brightMagenta: Color(0xFFFF92DF),
                brightCyan:    Color(0xFF67E8F9),
                searchHitBackground:        Color(0xFF00FF41),
                searchHitBackgroundCurrent: Color(0xFF69FF47),
                searchHitForeground:        Color(0xFF000000),
              )
            : TerminalTheme(
                cursor:        FColors.cyan,
                selection:     const Color(0x4400FFFF),
                foreground:    FColors.textPrimary,
                background:    FColors.bg,
                black:         Color(0xFF000000),
                white:         Color(0xFFE2E8F0),
                red:           FColors.red,
                green:         FColors.green,
                yellow:        FColors.amber,
                blue:          FColors.cyanDim,
                magenta:       FColors.magenta,
                cyan:          FColors.cyan,
                brightBlack:   FColors.textDim,
                brightWhite:   Colors.white,
                brightRed:     FColors.red,
                brightGreen:   FColors.green,
                brightYellow:  FColors.amber,
                brightBlue:    FColors.cyanDim,
                brightMagenta: FColors.magenta,
                brightCyan:    FColors.cyan,
                searchHitBackground:        Color(0xFF00FFFF),
                searchHitBackgroundCurrent: Color(0xFF00FF41),
                searchHitForeground:        Color(0xFF060811),
              ),
        textStyle: TerminalStyle(fontSize: _fontSize, fontFamily: 'monospace'),
        autofocus: true,
        backgroundOpacity: 1.0,
        padding: EdgeInsets.zero,
            ),
          ),
          if (!_running) _buildChainBanner(),
        ],
      ),
    );
  }
}
