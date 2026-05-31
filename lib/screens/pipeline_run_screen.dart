import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter/services.dart';
import 'package:flutter_pty/flutter_pty.dart';
import 'package:xterm/xterm.dart';
import '../models/pipeline.dart';
import '../screens/results_screen.dart';
import '../services/host_map_service.dart';
import '../services/nethunter_service.dart';
import '../services/project_service.dart';
import '../services/scan_foreground_service.dart';
import '../services/settings_service.dart';
import '../theme/colors.dart';

enum _StepStatus { pending, running, done, failed }

class _RunStep {
  final PipelineStep step;
  _StepStatus status = _StepStatus.pending;
  Terminal? terminal;
  Pty? pty;
  final StringBuffer rawOutput = StringBuffer();

  _RunStep(this.step);
}

class PipelineRunScreen extends StatefulWidget {
  final Pipeline pipeline;
  const PipelineRunScreen({super.key, required this.pipeline});

  @override
  State<PipelineRunScreen> createState() => _PipelineRunScreenState();
}

class _PipelineRunScreenState extends State<PipelineRunScreen>
    with SingleTickerProviderStateMixin {
  late final List<_RunStep> _runSteps;
  int _currentIdx = 0;  // currently executing step
  int _viewIdx    = 0;  // step whose terminal is displayed (-1 = KARMA terminal)
  bool _started   = false;
  bool _aborted     = false;
  bool _sidebarOpen = true;
  double _fontSize  = 9.0;
  String? _pipelineSessionDir; // shared session dir for all pipeline steps

  // KARMA mode state
  Terminal? _karmaTerm;
  Pty?      _karmaPty;
  Timer?    _clientPollTimer;
  final List<String> _karmaClients      = []; // all seen IPs (dedup)
  final List<String> _karmaPendingQueue = []; // seen but not yet processed
  bool    _karmaRunning      = false;
  bool    _karmaWaiting      = false; // waiting for next client
  String? _karmaCurrentClient;
  int     _karmaClientCount  = 0;
  String? _karmaTargetOverride;

  late final Ticker _ticker;
  final Stopwatch _clock = Stopwatch();

  bool get _inKarmaMode => widget.pipeline.karmaEnabled;

  @override
  void initState() {
    super.initState();
    _runSteps = widget.pipeline.steps.map(_RunStep.new).toList();
    _ticker = createTicker((_) { if (mounted) setState(() {}); });
    SettingsService.getFontSize().then((v) { if (mounted) setState(() => _fontSize = v); });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_inKarmaMode) {
        _initKarmaMode();
      } else {
        _startNext();
      }
    });
  }

  @override
  void dispose() {
    _ticker.dispose();
    _clock.stop();
    _clientPollTimer?.cancel();
    _karmaPty?.kill();
    for (final s in _runSteps) {
      if (s.status == _StepStatus.running) s.pty?.kill();
    }
    super.dispose();
  }

  String? get _projectSlug {
    final name = widget.pipeline.projectName;
    return (name != null && name.isNotEmpty) ? NetHunterService.slugify(name) : null;
  }

  Future<void> _startNext() async {
    if (_aborted || _currentIdx >= _runSteps.length) return;

    if (!_started) {
      _started = true;
      _clock.start();
      _ticker.start();
    }

    final rs   = _runSteps[_currentIdx];
    final m    = rs.step.module;
    final term = Terminal(maxLines: 10000);
    rs.terminal = term;
    rs.status   = _StepStatus.running;

    // Generate one shared session dir for the whole pipeline on first step.
    // This lets each module see previous modules' output (nmap → nuclei → exploit, etc.)
    if (_pipelineSessionDir == null) {
      final now = DateTime.now();
      final ts = '${now.year.toString().padLeft(4, '0')}-'
          '${now.month.toString().padLeft(2, '0')}-'
          '${now.day.toString().padLeft(2, '0')}_'
          '${now.hour.toString().padLeft(2, '0')}-'
          '${now.minute.toString().padLeft(2, '0')}-'
          '${now.second.toString().padLeft(2, '0')}';
      final slug = _projectSlug;
      final base = '${NetHunterService.scriptsPath}/results';
      _pipelineSessionDir = slug != null && slug.isNotEmpty
          ? '$base/$slug/$ts'
          : '$base/$ts';
      // Pre-seed chain files from pipeline config so all modules can read them immediately.
      await _seedChainFiles(_pipelineSessionDir!);
    }

    final stepLabel =
        '${_currentIdx + 1}/${_runSteps.length}: ${m.name}';
    unawaited(ScanForegroundService.startScan(stepLabel));

    final cmd = NetHunterService.buildChainedCommand(
      m.script,
      target: _karmaTargetOverride ?? (widget.pipeline.target.isEmpty ? null : widget.pipeline.target),
      sessionDir: _pipelineSessionDir,
      projectSlug: _projectSlug,
      domain: widget.pipeline.domain.isEmpty ? null : widget.pipeline.domain,
    );
    final pidFile = '/data/local/tmp/fsec_pl_${DateTime.now().millisecondsSinceEpoch}.pid';
    final fullCmd = 'echo \$\$ > $pidFile; $cmd';

    final pty = Pty.start(
      'su',
      arguments: ['-c', fullCmd],
      columns: 110, rows: 40,
      environment: {'TERM': 'xterm-256color'},
    );
    rs.pty = pty;

    pty.output
        .cast<List<int>>()
        .transform(const Utf8Decoder(allowMalformed: true))
        .listen(
          (data) {
            term.write(data);
            rs.rawOutput.write(data);
          },
          onDone: () async {
            if (_aborted) return;
            rs.status = _StepStatus.done;
            await _syncStepToProject(m.name);
            _currentIdx++;
            if (mounted) setState(() {});
            if (_currentIdx < _runSteps.length) {
              _viewIdx = _currentIdx;
              _startNext();
            } else if (_inKarmaMode) {
              // Client pipeline done — go back to waiting for next client
              if (mounted) setState(() {
                _karmaWaiting       = true;
                _karmaCurrentClient = null;
                _karmaTargetOverride = null;
                _viewIdx = -1;
              });
              // Check immediately if another client is already queued
              unawaited(_pollKarmaClients());
            } else {
              _clock.stop();
              _ticker.stop();
              HapticFeedback.heavyImpact();
              if (mounted) setState(() {});
              unawaited(ScanForegroundService.completeScan(
                  widget.pipeline.name));
            }
          },
        );

    term.onOutput = (data) => pty.write(const Utf8Encoder().convert(data));

    setState(() => _viewIdx = _currentIdx);
  }

  // Pre-seed chain files with known pipeline config so modules don't have to wait.
  Future<void> _seedChainFiles(String sessionDir) async {
    final chrootDir = '${NetHunterService.chrootPath}$sessionDir';
    final cmds = <String>['mkdir -p "$chrootDir"'];
    // DOMAIN → chain_domain.txt
    final domain = widget.pipeline.domain.trim();
    if (domain.isNotEmpty) {
      cmds.add('echo ${NetHunterService.shellQuote(domain)} > "$chrootDir/chain_domain.txt"');
    }
    // TARGET → chain_dc.txt: skip in KARMA mode — client IP is unknown at this point;
    // will be written per-client in _seedKarmaClientTarget().
    if (!_inKarmaMode) {
      final target = widget.pipeline.target.trim();
      final isIp   = RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(target.split('/').first);
      if (isIp && !target.contains('/')) {
        cmds.add('echo ${NetHunterService.shellQuote(target)} > "$chrootDir/chain_dc.txt"');
      }
    }
    try {
      await Process.run('su', ['-c', cmds.join(' && ')]);
    } catch (_) {}
  }

  // Write connected client IP to chain_dc.txt so all pipeline scripts target the right host.
  Future<void> _seedKarmaClientTarget(String ip) async {
    if (_pipelineSessionDir == null) return;
    final chrootDir = '${NetHunterService.chrootPath}$_pipelineSessionDir';
    try {
      await Process.run('su', ['-c',
        'echo ${NetHunterService.shellQuote(ip)} > "$chrootDir/chain_dc.txt"',
      ]);
    } catch (_) {}
  }

  // ── KARMA mode ─────────────────────────────────────────────────────────────

  Future<void> _initKarmaMode() async {
    if (!_started) {
      _started = true;
      _clock.start();
      _ticker.start();
    }
    if (widget.pipeline.karmaAttach) {
      await _attachToRunningKarma();
      return;
    }
    if (_pipelineSessionDir == null) {
      final now = DateTime.now();
      final ts = '${now.year.toString().padLeft(4, '0')}-'
          '${now.month.toString().padLeft(2, '0')}-'
          '${now.day.toString().padLeft(2, '0')}_'
          '${now.hour.toString().padLeft(2, '0')}-'
          '${now.minute.toString().padLeft(2, '0')}-'
          '${now.second.toString().padLeft(2, '0')}';
      final slug = _projectSlug;
      final base = '${NetHunterService.scriptsPath}/results';
      _pipelineSessionDir = (slug != null && slug.isNotEmpty) ? '$base/$slug/$ts' : '$base/$ts';
      await _seedChainFiles(_pipelineSessionDir!);
    }
    await _startKarma();
  }

  // Attach to an already-running KARMA session (started from module tab).
  Future<void> _attachToRunningKarma() async {
    final sessionFile = '${NetHunterService.chrootPath}/tmp/karma_running_session';
    final r = await Process.run('su', ['-c', 'cat "$sessionFile" 2>/dev/null || true']);
    final sessionDir = r.stdout.toString().trim();

    if (sessionDir.isEmpty) {
      if (mounted) setState(() {
        _karmaRunning = false;
        _karmaWaiting = false;
      });
      // Show error in first step terminal
      if (_runSteps.isNotEmpty) {
        final term = Terminal(maxLines: 1000);
        _runSteps[0].terminal = term;
        term.write('\r\n\x1b[1;31m[!] No running KARMA session found.\x1b[0m\r\n');
        term.write('\x1b[2m    Start KARMA from the modules tab first, then attach here.\x1b[0m\r\n');
        setState(() { _runSteps[0].status = _StepStatus.running; _viewIdx = 0; });
      }
      return;
    }

    // Use the running session's directory directly
    _pipelineSessionDir = sessionDir;
    await _seedChainFiles(_pipelineSessionDir!);

    setState(() {
      _karmaRunning = true;
      _karmaWaiting = true;
      _viewIdx      = 0;
    });

    // No PTY — karma is already running externally.
    // Poll karma_clients.txt from the running session.
    _clientPollTimer = Timer.periodic(const Duration(seconds: 3), (_) => _pollKarmaClients());
    unawaited(ScanForegroundService.startScan('KARMA — attached to running session'));
    if (mounted) setState(() {});
  }

  Future<void> _startKarma() async {
    final term = Terminal(maxLines: 10000);
    setState(() {
      _karmaRunning = true;
      _karmaWaiting = true;
      _karmaTerm    = term;
      _viewIdx      = -1;
    });

    final cmd = NetHunterService.buildChainedCommand(
      'scripts/karma.sh',
      sessionDir:  _pipelineSessionDir,
      projectSlug: _projectSlug,
      domain:      widget.pipeline.domain.isEmpty ? null : widget.pipeline.domain,
      extraEnv: {
        'KARMA_MODE': widget.pipeline.karmaMode,
        if (widget.pipeline.karmaSsid.isNotEmpty) 'KARMA_SSID': widget.pipeline.karmaSsid,
        if (widget.pipeline.karmaPass.isNotEmpty) 'KARMA_PASS': widget.pipeline.karmaPass,
      },
    );

    final pty = Pty.start(
      'su',
      arguments: ['-c', cmd],
      columns: 110, rows: 40,
      environment: {'TERM': 'xterm-256color'},
    );
    _karmaPty = pty;

    pty.output
        .cast<List<int>>()
        .transform(const Utf8Decoder(allowMalformed: true))
        .listen(
          (data) => term.write(data),
          onDone: () {
            if (!_aborted && mounted) setState(() { _karmaRunning = false; });
            _clientPollTimer?.cancel();
          },
        );

    term.onOutput = (data) => _karmaPty?.write(const Utf8Encoder().convert(data));

    _clientPollTimer = Timer.periodic(const Duration(seconds: 3), (_) => _pollKarmaClients());

    unawaited(ScanForegroundService.startScan('KARMA — rogue AP active'));
    if (mounted) setState(() {});
  }

  Future<void> _pollKarmaClients() async {
    if (_aborted || _pipelineSessionDir == null) return;
    // In attach mode, keep running even without a PTY — external karma is running
    if (!_karmaRunning && !widget.pipeline.karmaAttach) return;
    final file = '${NetHunterService.chrootPath}$_pipelineSessionDir/karma_clients.txt';
    final r = await Process.run('su', ['-c', 'cat "$file" 2>/dev/null || true']);
    final ips = r.stdout.toString().trim().split('\n')
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty && RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(l))
        .toList();
    for (final ip in ips) {
      if (!_karmaClients.contains(ip)) {
        _karmaClients.add(ip);
        if (_karmaWaiting && _runSteps.isNotEmpty) {
          _startPipelineForClient(ip);
          return; // one at a time
        } else {
          // Pipeline busy — queue for later
          if (!_karmaPendingQueue.contains(ip)) _karmaPendingQueue.add(ip);
        }
      }
    }
    // If waiting and nothing new arrived, drain the pending queue
    if (_karmaWaiting && _runSteps.isNotEmpty && _karmaPendingQueue.isNotEmpty) {
      final next = _karmaPendingQueue.removeAt(0);
      _startPipelineForClient(next);
    }
  }

  void _startPipelineForClient(String ip) {
    if (_aborted) return;
    setState(() {
      _karmaWaiting       = false;
      _karmaCurrentClient = ip;
      _karmaClientCount++;
      _karmaTargetOverride = ip;
      for (final rs in _runSteps) {
        rs.pty?.kill();
        rs.status   = _StepStatus.pending;
        rs.terminal = null;
        rs.pty      = null;
      }
      _currentIdx = 0;
      _viewIdx    = 0;
    });
    // Seed chain_dc.txt with client IP so scripts reading the chain file target the right host.
    _seedKarmaClientTarget(ip).then((_) => _startNext());
  }

  // ── End KARMA mode ──────────────────────────────────────────────────────────

  Future<void> _syncStepToProject(String moduleName) async {
    final projectId = widget.pipeline.projectId;
    if (projectId == null || _pipelineSessionDir == null) return;
    try {
      final slug     = _projectSlug;
      final tsFolder = _pipelineSessionDir!.split('/').last;
      final chrootResultsBase =
          '${NetHunterService.chrootPath}${NetHunterService.scriptsPath}/results';
      final searchPath = (slug != null && slug.isNotEmpty)
          ? '$chrootResultsBase/$slug'
          : chrootResultsBase;
      final folderName = (slug != null && slug.isNotEmpty)
          ? '$slug/$tsFolder'
          : tsFolder;
      await ProjectService.attachSession(projectId, folderName, moduleName);
      final map = await HostMapService.parse('$searchPath/$tsFolder', folderName);
      if (!map.isEmpty) await ProjectService.mergeHostMap(projectId, map);
      // Import credentials from all known output files
      for (final credFile in [
        'brute.txt', 'chain_creds.txt', 'crackmap.txt',
        'vnc.txt', 'wifite.txt', 'linpeas.txt', 'netsniff.txt',
      ]) {
        final r = await Process.run('su',
            ['-c', 'cat "$searchPath/$tsFolder/$credFile" 2>/dev/null']);
        final txt = r.stdout.toString();
        if (txt.trim().isNotEmpty) {
          await ProjectService.importCredentials(projectId, folderName, txt);
        }
      }
    } catch (_) {}
  }

  void _abort() {
    HapticFeedback.heavyImpact();
    _aborted = true;
    _clientPollTimer?.cancel();
    _karmaPty?.kill();
    for (final rs in _runSteps) {
      if (rs.status == _StepStatus.running) {
        rs.pty?.kill();
        rs.status = _StepStatus.failed;
      }
    }
    _clock.stop();
    _ticker.stop();
    unawaited(ScanForegroundService.stopScan());
    if (mounted) setState(() {});
  }

  String get _elapsed {
    final s = _clock.elapsed;
    final mm = s.inMinutes.toString().padLeft(2, '0');
    final ss = (s.inSeconds % 60).toString().padLeft(2, '0');
    return '$mm:$ss';
  }

  bool get _allDone {
    if (_inKarmaMode) return false; // KARMA runs until user stops
    return _currentIdx >= _runSteps.length && !_aborted;
  }

  bool get _isRunning {
    if (_inKarmaMode) return _karmaRunning && !_aborted;
    return _started && !_allDone && !_aborted;
  }

  void _confirmBack(BuildContext context) {
    if (!_isRunning) {
      Navigator.pop(context);
      return;
    }
    final nav = Navigator.of(context);
    showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: FColors.bgCard,
        title: const Text('Abort pipeline?',
          style: TextStyle(fontFamily: 'monospace', color: FColors.red, fontSize: 13)),
        content: const Text(
          'Pipeline is still running. Going back will abort all remaining steps.',
          style: TextStyle(fontFamily: 'monospace', color: FColors.textSecondary, fontSize: 11)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('KEEP RUNNING',
              style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 11)),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(context, true);
            },
            child: const Text('ABORT & EXIT',
              style: TextStyle(fontFamily: 'monospace', color: FColors.red, fontSize: 11)),
          ),
        ],
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(4),
          side: BorderSide(color: FColors.red.op(0.4)),
        ),
      ),
    ).then((confirmed) {
      if (confirmed == true && mounted) {
        _abort();
        nav.pop();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final viewStep = (_viewIdx >= 0 && _viewIdx < _runSteps.length) ? _runSteps[_viewIdx] : null;

    return PopScope(
      canPop: !_isRunning,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) _confirmBack(context);
      },
      child: Scaffold(
      backgroundColor: FColors.bg,
      appBar: AppBar(
        backgroundColor: FColors.bgCard,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
          onPressed: () => _confirmBack(context),
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Text(
                widget.pipeline.name.toUpperCase(),
                style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan,
                  fontSize: 12, letterSpacing: 1),
              ),
              if (widget.pipeline.projectName != null) ...[
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                  decoration: BoxDecoration(
                    border: Border.all(color: FColors.amber.op(0.5), width: 0.8),
                    color: FColors.amber.op(0.08),
                  ),
                  child: Text(widget.pipeline.projectName!,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 8,
                      color: FColors.amber)),
                ),
              ],
            ]),
            Text(
              _aborted
                  ? 'aborted · $_elapsed'
                  : _inKarmaMode
                      ? (_karmaWaiting
                          ? 'karma · waiting for client  ·  $_elapsed'
                          : 'karma · client $_karmaClientCount: ${_karmaCurrentClient ?? ''}  ·  step ${(_currentIdx + 1).clamp(1, _runSteps.length)}/${_runSteps.length}  ·  $_elapsed')
                      : _allDone
                          ? 'done · $_elapsed'
                          : 'step ${(_currentIdx + 1).clamp(1, _runSteps.length)} / ${_runSteps.length}  ·  $_elapsed',
              style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 9)),
            if (_pipelineSessionDir != null)
              Text(
              '⇒ ${_pipelineSessionDir!.split('/').last}',
              style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 8),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.remove, color: FColors.textSecondary, size: 16),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            onPressed: () {
              final s = (_fontSize - 1).clamp(7.0, 20.0);
              setState(() => _fontSize = s);
              SettingsService.saveFontSize(s);
            },
          ),
          IconButton(
            icon: const Icon(Icons.add, color: FColors.textSecondary, size: 16),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            onPressed: () {
              final s = (_fontSize + 1).clamp(7.0, 20.0);
              setState(() => _fontSize = s);
              SettingsService.saveFontSize(s);
            },
          ),
          if (!_allDone && !_aborted)
            IconButton(
              icon: const Icon(Icons.stop_circle_outlined, color: FColors.red, size: 22),
              tooltip: 'Abort all',
              onPressed: _abort,
            ),
          if (_allDone || _aborted)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 14),
              child: Icon(Icons.check_circle_outline, color: FColors.green, size: 20),
            ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: Row(
        children: [
          // ── Step sidebar (slideable) ───────────────────────────────────
          AnimatedContainer(
            duration: const Duration(milliseconds: 220),
            curve: Curves.easeInOut,
            width: _sidebarOpen ? 110 : 0,
            clipBehavior: Clip.hardEdge,
            decoration: BoxDecoration(
              color: FColors.bgCard,
              border: Border(right: BorderSide(color: FColors.cyan.op(0.15))),
            ),
            child: GestureDetector(
              onHorizontalDragEnd: (d) {
                if ((d.primaryVelocity ?? 0) < -200) {
                  setState(() => _sidebarOpen = false);
                }
              },
              child: SizedBox(
                width: 110,
                child: Column(
                  children: [
                    if (_inKarmaMode) _KarmaSidebarTile(
                      running: _karmaRunning,
                      waiting: _karmaWaiting,
                      clientCount: _karmaClientCount,
                      currentClient: _karmaCurrentClient,
                      attached: widget.pipeline.karmaAttach,
                      isViewing: _viewIdx == -1,
                      onTap: _karmaTerm != null ? () => setState(() => _viewIdx = -1) : null,
                    ),
                    Expanded(
                      child: ListView.builder(
                        padding: EdgeInsets.only(top: _inKarmaMode ? 0 : 6),
                        itemCount: _runSteps.length,
                        itemBuilder: (_, i) => _SidebarTile(
                          runStep: _runSteps[i],
                          index: i,
                          isViewing: _viewIdx == i,
                          onTap: _runSteps[i].terminal != null
                              ? () => setState(() => _viewIdx = i)
                              : null,
                        ),
                      ),
                    ),
                    if (_pipelineSessionDir != null && _started)
                      _ChainStatusPanel(
                        sessionDir: '${NetHunterService.chrootPath}$_pipelineSessionDir',
                      ),
                  ],
                ),
              ),
            ),
          ),

          // ── Terminal area (with floating reopen tab when sidebar hidden)
          Expanded(
            child: Stack(
              children: [
                // Terminal — KARMA terminal when _viewIdx==-1, step terminal otherwise
                (_viewIdx == -1 && _karmaTerm != null) || viewStep?.terminal != null
                    ? TerminalView(
                        _viewIdx == -1 ? _karmaTerm! : viewStep!.terminal!,
                        theme: TerminalTheme(
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
                      )
                    : Center(
                        child: Text(
                          _inKarmaMode ? 'KARMA starting — rogue AP initializing…' : 'Starting…',
                          style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11)),
                      ),

                // Floating reopen tab — visible only when sidebar is hidden
                if (!_sidebarOpen)
                  Positioned(
                    left: 0,
                    top: 0,
                    bottom: 0,
                    child: Center(
                      child: GestureDetector(
                        onTap: () => setState(() => _sidebarOpen = true),
                        onHorizontalDragEnd: (d) {
                          if ((d.primaryVelocity ?? 0) > 100) {
                            setState(() => _sidebarOpen = true);
                          }
                        },
                        child: Container(
                          width: 22,
                          height: 52,
                          decoration: BoxDecoration(
                            color: FColors.bgCard,
                            borderRadius: const BorderRadius.only(
                              topRight:    Radius.circular(6),
                              bottomRight: Radius.circular(6),
                            ),
                            border: Border.all(color: FColors.cyan.op(0.35), width: 0.8),
                          ),
                          child: const Icon(Icons.chevron_right, color: FColors.cyan, size: 14),
                        ),
                      ),
                    ),
                  ),

                // Completion banner — LAST so it overlays terminal
                if (_allDone || _aborted)
                  Positioned(
                    left: 0, right: 0, bottom: 0,
                    child: _CompletionBanner(
                      allDone: _allDone,
                      elapsed: _elapsed,
                      stepsTotal: _runSteps.length,
                      stepsDone: _runSteps.where((s) => s.status == _StepStatus.done).length,
                      projectId: widget.pipeline.projectId,
                      onViewResults: () => Navigator.push(
                        context, MaterialPageRoute(builder: (_) => const ResultsScreen())),
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    ),   // Scaffold
    );   // PopScope
  }
}

// ── Completion banner ─────────────────────────────────────────────────────────

class _CompletionBanner extends StatelessWidget {
  final bool allDone;
  final String elapsed;
  final int stepsTotal;
  final int stepsDone;
  final int? projectId;
  final VoidCallback onViewResults;

  const _CompletionBanner({
    required this.allDone,
    required this.elapsed,
    required this.stepsTotal,
    required this.stepsDone,
    required this.projectId,
    required this.onViewResults,
  });

  @override
  Widget build(BuildContext context) {
    final color = allDone ? FColors.green : FColors.red;
    final label = allDone ? 'PIPELINE COMPLETE' : 'PIPELINE ABORTED';
    final icon  = allDone ? Icons.check_circle_outline : Icons.cancel_outlined;
    return Container(
      decoration: BoxDecoration(
        color: FColors.bgCard,
        border: Border(
          top: BorderSide(color: color, width: 2),
          left: BorderSide(color: color.op(0.3), width: 3),
        ),
        boxShadow: [BoxShadow(color: color.op(0.18), blurRadius: 16, spreadRadius: 0, offset: const Offset(0, -4))],
      ),
      padding: const EdgeInsets.fromLTRB(14, 14, 14, 0),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Icon(icon, color: color, size: 22),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(label,
                      style: TextStyle(fontFamily: 'monospace', fontSize: 12,
                        color: color, fontWeight: FontWeight.bold, letterSpacing: 2)),
                    Text('$stepsDone / $stepsTotal steps  ·  $elapsed',
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim)),
                  ],
                ),
              ),
              GestureDetector(
                onTap: onViewResults,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  decoration: BoxDecoration(
                    border: Border.all(color: color.op(0.7), width: 1.2),
                    color: color.op(0.12),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(allDone ? 'VIEW RESULTS' : 'VIEW LOG',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 10,
                      color: color, letterSpacing: 1.5, fontWeight: FontWeight.bold)),
                ),
              ),
            ]),
            if (allDone && projectId != null)
              Padding(
                padding: const EdgeInsets.only(top: 8, bottom: 2),
                child: Text('Run Report module on this session to generate HTML report',
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 8, color: FColors.textDim)),
              ),
            const SizedBox(height: 10),
          ],
        ),
      ),
    );
  }
}

// ── Sidebar step tile ─────────────────────────────────────────────────────────

class _SidebarTile extends StatelessWidget {
  final _RunStep runStep;
  final int index;
  final bool isViewing;
  final VoidCallback? onTap;

  const _SidebarTile({
    required this.runStep,
    required this.index,
    required this.isViewing,
    this.onTap,
  });

  Color get _statusColor => switch (runStep.status) {
    _StepStatus.pending => FColors.textDim,
    _StepStatus.running => FColors.green,
    _StepStatus.done    => FColors.cyan,
    _StepStatus.failed  => FColors.red,
  };

  IconData get _statusIcon => switch (runStep.status) {
    _StepStatus.pending => Icons.radio_button_unchecked,
    _StepStatus.running => Icons.play_circle_outline,
    _StepStatus.done    => Icons.check_circle_outline,
    _StepStatus.failed  => Icons.cancel_outlined,
  };

  @override
  Widget build(BuildContext context) {
    final m = runStep.step.module;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.fromLTRB(6, 0, 6, 4),
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        decoration: BoxDecoration(
          color: isViewing ? _statusColor.op(0.12) : Colors.transparent,
          border: Border.all(
            color: isViewing ? _statusColor.op(0.5) : _statusColor.op(0.2),
          ),
          borderRadius: BorderRadius.circular(3),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Text('${index + 1}.',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 8, color: FColors.textDim)),
              const Spacer(),
              Icon(_statusIcon, color: _statusColor, size: 12),
            ]),
            const SizedBox(height: 4),
            Icon(m.icon, color: _statusColor, size: 14),
            const SizedBox(height: 3),
            Text(m.name,
              style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                color: _statusColor, fontWeight: FontWeight.bold),
              overflow: TextOverflow.ellipsis),
          ],
        ),
      ),
    );
  }
}

// ── Chain file status panel (sidebar footer) ──────────────────────────────────

class _ChainStatusPanel extends StatefulWidget {
  final String sessionDir;
  const _ChainStatusPanel({required this.sessionDir});

  @override
  State<_ChainStatusPanel> createState() => _ChainStatusPanelState();
}

class _ChainStatusPanelState extends State<_ChainStatusPanel> {
  Map<String, int> _counts = {};
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 8), (_) => _refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    // Single su call — batch all wc -l into one process to avoid 6× spawn overhead
    final d = widget.sessionDir;
    final r = await Process.run('su', ['-c',
      'for f in alive_hosts.txt chain_ports.txt chain_creds.txt'
      ' chain_hashes.txt chain_dc.txt chain_web_urls.txt chain_users.txt; do'
      ' c=\$(wc -l < "$d/\$f" 2>/dev/null || echo 0); printf "%s=%s\\n" "\$f" "\$c";'
      ' done'
    ]);
    final newCounts = <String, int>{};
    const keys = {
      'alive_hosts.txt': 'hosts',
      'chain_ports.txt': 'ports',
      'chain_creds.txt': 'creds',
      'chain_hashes.txt': 'hashes',
      'chain_dc.txt': 'dc',
      'chain_web_urls.txt': 'urls',
      'chain_users.txt': 'users',
    };
    for (final line in r.stdout.toString().split('\n')) {
      final parts = line.trim().split('=');
      if (parts.length != 2) continue;
      final key = keys[parts[0]];
      if (key != null) newCounts[key] = int.tryParse(parts[1]) ?? 0;
    }
    if (mounted) setState(() => _counts = newCounts);
  }

  @override
  Widget build(BuildContext context) {
    final hasAny = _counts.values.any((v) => v > 0);
    if (!hasAny) return const SizedBox.shrink();
    return Container(
      margin: const EdgeInsets.fromLTRB(4, 0, 4, 6),
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 5),
      decoration: BoxDecoration(
        color: FColors.bg,
        border: Border.all(color: FColors.cyan.op(0.15)),
        borderRadius: BorderRadius.circular(3),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('CHAIN', style: TextStyle(
            fontFamily: 'monospace', fontSize: 7, color: FColors.textDim, letterSpacing: 1)),
          const SizedBox(height: 3),
          ..._counts.entries.where((e) => e.value > 0).map((e) => Padding(
            padding: const EdgeInsets.only(bottom: 1),
            child: Row(children: [
              Expanded(child: Text(e.key,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 7, color: FColors.textDim))),
              Text('${e.value}',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 7, color: FColors.cyan)),
            ]),
          )),
        ],
      ),
    );
  }
}

// ── KARMA sidebar tile ────────────────────────────────────────────────────────

class _KarmaSidebarTile extends StatelessWidget {
  final bool running;
  final bool waiting;
  final int clientCount;
  final String? currentClient;
  final bool attached;
  final bool isViewing;
  final VoidCallback? onTap;

  const _KarmaSidebarTile({
    required this.running,
    required this.waiting,
    required this.clientCount,
    required this.currentClient,
    required this.isViewing,
    this.attached = false,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final color = running ? FColors.red : FColors.textDim;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.fromLTRB(6, 6, 6, 2),
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 7),
        decoration: BoxDecoration(
          color: isViewing ? color.op(0.14) : color.op(0.04),
          border: Border.all(
            color: isViewing ? color.op(0.6) : color.op(0.25),
            width: isViewing ? 1.0 : 0.7,
          ),
          borderRadius: BorderRadius.circular(3),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(
              running
                  ? (waiting ? Icons.wifi_tethering : Icons.wifi_tethering_error)
                  : Icons.wifi_off,
              color: running ? FColors.red : FColors.textDim,
              size: 10,
            ),
            const SizedBox(width: 4),
            Text('KARMA',
              style: TextStyle(
                fontFamily: 'monospace', fontSize: 9,
                color: color, fontWeight: FontWeight.bold, letterSpacing: 1,
              )),
            if (attached) ...[
              const SizedBox(width: 4),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 3, vertical: 1),
                decoration: BoxDecoration(
                  color: FColors.amber.op(0.15),
                  border: Border.all(color: FColors.amber.op(0.5), width: 0.5),
                  borderRadius: BorderRadius.circular(2),
                ),
                child: const Text('LINKED',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 6,
                    color: FColors.amber, letterSpacing: 0.5)),
              ),
            ],
          ]),
          const SizedBox(height: 3),
          Text(
            running
                ? (waiting ? (attached ? 'watching…' : 'waiting…') : currentClient ?? 'active')
                : (attached ? 'no session found' : 'stopped'),
            style: const TextStyle(
              fontFamily: 'monospace', fontSize: 8, color: FColors.textDim),
            overflow: TextOverflow.ellipsis,
          ),
          if (clientCount > 0) ...[
            const SizedBox(height: 2),
            Text(
              '$clientCount client${clientCount == 1 ? '' : 's'}',
              style: const TextStyle(
                fontFamily: 'monospace', fontSize: 8, color: FColors.green),
            ),
          ],
        ]),
      ),
    );
  }
}
