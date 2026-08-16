import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import '../data/modules.dart';
import '../models/module.dart';
import '../models/project.dart';
import '../services/nethunter_service.dart';
import '../services/project_service.dart';
import '../theme/colors.dart';
import '../services/session_manager.dart';
import '../services/settings_service.dart';
import '../widgets/module_card.dart';
import 'terminal_screen.dart';
import 'settings_screen.dart';
import 'results_screen.dart';
import 'report_screen.dart';
import 'project_screen.dart';
import 'pipeline_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen>
    with TickerProviderStateMixin {
  String _ip         = '...';
  String _iface      = '';
  bool   _isMonitor  = false;
  Project? _activeProject;
  ModuleCategory? _filter;
  String _search = '';
  late AnimationController _scan;
  Timer? _ifaceTimer;

  // Edge glow
  late AnimationController _glowCtrl;
  late Animation<double>   _glowAnim;
  String _edgeGlowColor  = SettingsService.defaultEdgeGlow;
  Color  _activeGlowColor = FColors.cyan;
  Set<int> _prevIds = {};

  @override
  void initState() {
    super.initState();
    _scan = AnimationController(vsync: this, duration: const Duration(seconds: 3))
      ..repeat();

    _glowCtrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 2800));
    _glowAnim = TweenSequence<double>([
      TweenSequenceItem(tween: Tween(begin: 0.0, end: 1.0),  weight: 12), // fade in
      TweenSequenceItem(tween: Tween(begin: 1.0, end: 0.55), weight: 10), // dip
      TweenSequenceItem(tween: Tween(begin: 0.55, end: 1.0), weight: 10), // pulse
      TweenSequenceItem(tween: Tween(begin: 1.0, end: 0.55), weight: 8),  // dip 2
      TweenSequenceItem(tween: Tween(begin: 0.55, end: 1.0), weight: 8),  // pulse 2
      TweenSequenceItem(tween: Tween(begin: 1.0, end: 0.0),  weight: 52), // fade out
    ]).animate(_glowCtrl);

    SettingsService.getEdgeGlow().then((v) { if (mounted) setState(() => _edgeGlowColor = v); });
    _prevIds = Set.from(SessionManager.instance.runningIds.value);
    SessionManager.instance.runningIds.addListener(_onRunningChanged);

    _fetchIp();
    _loadActiveProject();
    _ifaceTimer = Timer.periodic(const Duration(seconds: 10), (_) => _fetchIp());
  }

  void _onRunningChanged() {
    final current = SessionManager.instance.runningIds.value;
    // Detect finishes by set difference, not length — a module finishing while
    // another starts leaves the length unchanged but still ended a scan.
    final finished = _prevIds.difference(current);
    if (finished.isNotEmpty && _edgeGlowColor != 'off') {
      final finishedId = finished.firstOrNull;
      Color col;
      if (_edgeGlowColor == 'auto' && finishedId != null) {
        final mod = kModules.where((m) => m.id == finishedId).firstOrNull;
        col = mod != null ? _categoryColor(mod.category) : FColors.cyan;
      } else {
        col = _resolveGlowColor();
      }
      setState(() => _activeGlowColor = col);
      _glowCtrl.forward(from: 0);
    }
    _prevIds = Set.from(current);
  }

  Color _categoryColor(ModuleCategory c) => switch (c) {
    ModuleCategory.network => FColors.cyanDim,
    ModuleCategory.web     => FColors.purple,
    ModuleCategory.iot     => FColors.amber,
    ModuleCategory.brute   => FColors.red,
    ModuleCategory.recon   => FColors.green,
    ModuleCategory.exploit => FColors.magenta,
    ModuleCategory.fire    => FColors.orange,
    _                      => FColors.cyan,
  };

  Future<void> _loadActiveProject() async {
    final p = await ProjectService.getActiveProject();
    if (mounted) setState(() => _activeProject = p);
  }

  @override
  void dispose() {
    _scan.dispose();
    _glowCtrl.dispose();
    _ifaceTimer?.cancel();
    SessionManager.instance.runningIds.removeListener(_onRunningChanged);
    super.dispose();
  }

  Color _resolveGlowColor() => switch (_edgeGlowColor) {
    'green'  => FColors.green,
    'purple' => FColors.purple,
    'amber'  => const Color(0xFFFF2233),
    'white'  => Colors.white,
    _        => FColors.cyan,
  };

  Widget _glowLine({required bool left, required Color color}) => Positioned(
    left:   left ? 0 : null,
    right:  left ? null : 0,
    top:    0,
    bottom: 0,
    child: Container(
      width: 4,
      decoration: BoxDecoration(
        color: color,
        boxShadow: [
          BoxShadow(color: color.op(0.95), blurRadius: 10, spreadRadius: 4),
          BoxShadow(color: color.op(0.60), blurRadius: 28, spreadRadius: 10),
          BoxShadow(color: color.op(0.25), blurRadius: 55, spreadRadius: 18),
        ],
      ),
    ),
  );

  Future<void> _fetchIp() async {
    try {
      // Scan ALL interfaces for monitor type (803=radiotap, 801=raw 802.11)
      // so we detect wlan0mon created by airmon-ng, not just the route interface
      final r = await Process.run('su', ['-c',
        r"MON=$(for f in /sys/class/net/*/type; do "
        r"t=$(cat $f 2>/dev/null); "
        r"if [ $t = 803 ] || [ $t = 801 ]; then basename $(dirname $f); break; fi; "
        r"done 2>/dev/null); "
        r"OUT=$(ip route get 1 2>/dev/null); "
        r"IP=$(echo $OUT | awk '{for(i=1;i<=NF;i++)if($i~/^src$/){print $(i+1);exit}}'); "
        r"DEV=$(echo $OUT | awk '{for(i=1;i<=NF;i++)if($i~/^dev$/){print $(i+1);exit}}'); "
        r"echo $IP'|'$DEV'|'$MON",
      ]);
      final parts    = r.stdout.toString().trim().split('|');
      final ip       = parts.isNotEmpty ? parts[0].trim() : '';
      final routeDev = parts.length > 1 ? parts[1].trim() : '';
      final monDev   = parts.length > 2 ? parts[2].trim() : '';
      final isMonitor = monDev.isNotEmpty;
      final iface = isMonitor ? monDev : (routeDev.isNotEmpty ? routeDev : 'wlan0');
      if (mounted) {
        setState(() {
          if (ip.isNotEmpty) { _ip = ip; }
          _iface     = iface;
          _isMonitor = isMonitor;
        });
      }
    } catch (_) {}
  }

  List<Module> get _filtered {
    final q = _search.trim().toLowerCase();
    return kModules.where((m) {
      final catMatch = _filter == null || m.category == _filter;
      final searchMatch = q.isEmpty ||
          m.name.toLowerCase().contains(q) ||
          m.tag.toLowerCase().contains(q) ||
          m.description.toLowerCase().contains(q);
      return catMatch && searchMatch;
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: FColors.bg,
      body: Stack(
        children: [
          SafeArea(
            child: Column(
              children: [
                _Header(
                  ip: _ip,
                  iface: _iface.isEmpty ? 'wlan0' : _iface,
                  isMonitor: _isMonitor,
                  scanAnim: _scan,
                  activeProject: _activeProject,
                  onSettings: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const SettingsScreen()))
                      .then((_) => SettingsService.getEdgeGlow().then((v) {
                        if (mounted) {
                          setState(() {
                            _edgeGlowColor = v;
                            if (v != 'auto' && v != 'off') { _activeGlowColor = _resolveGlowColor(); }
                          });
                        }
                      })),
                  onResults:  () => Navigator.push(context, MaterialPageRoute(builder: (_) => const ResultsScreen())),
                  onReport:   () => Navigator.push(context, MaterialPageRoute(builder: (_) => const ReportPickerScreen())),
                  onProjects: () => Navigator.push(context,
                    MaterialPageRoute(builder: (_) => const ProjectScreen()),
                  ).then((_) => _loadActiveProject()),
                  onPipeline: () => Navigator.push(context,
                    MaterialPageRoute(builder: (_) => const PipelineScreen())),
                ),
                _FilterBar(selected: _filter, onSelect: (c) => setState(() => _filter = c == null ? null : (_filter == c ? null : c))),
                // Search bar
                Container(
                  height: 34,
                  color: FColors.bg,
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  child: TextField(
                    onChanged: (v) => setState(() => _search = v),
                    style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 11, color: FColors.textPrimary),
                    decoration: InputDecoration(
                      hintText: 'search modules, tags…',
                      hintStyle: const TextStyle(
                        fontFamily: 'monospace', fontSize: 10, color: FColors.textDim),
                      prefixIcon: const Icon(Icons.search, color: FColors.textDim, size: 14),
                      contentPadding: const EdgeInsets.symmetric(vertical: 4),
                      isDense: true,
                      filled: true,
                      fillColor: FColors.bgCard,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(3),
                        borderSide: const BorderSide(color: FColors.textDim, width: 1),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(3),
                        borderSide: BorderSide(color: FColors.cyan.op(0.15), width: 1),
                      ),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(3),
                        borderSide: BorderSide(color: FColors.cyan.op(0.5), width: 1),
                      ),
                    ),
                  ),
                ),
                Expanded(
                  child: GridView.builder(
                    padding: const EdgeInsets.fromLTRB(10, 8, 10, 10),
                    gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                      crossAxisCount: 2,
                      childAspectRatio: 1.15,
                      crossAxisSpacing: 8,
                      mainAxisSpacing: 8,
                    ),
                    itemCount: _filtered.length,
                    itemBuilder: (context, i) {
                      final m = _filtered[i];
                      return ValueListenableBuilder<Set<int>>(
                        valueListenable: SessionManager.instance.runningIds,
                        builder: (_, ids, __) => ModuleCard(
                          module: m,
                          isRunning: ids.contains(m.id),
                          onTap: () => Navigator.push(context,
                            MaterialPageRoute(builder: (_) => TerminalScreen(
                              module: m,
                              projectSlug: _activeProject != null
                                  ? NetHunterService.slugify(_activeProject!.name)
                                  : null,
                            ))),
                        ),
                      );
                    },
                  ),
                ),
              ],
            ),
          ),
          // Edge glow overlay — fires when a script finishes
          if (_edgeGlowColor != 'off')
            AnimatedBuilder(
              animation: _glowAnim,
              builder: (_, __) {
                if (_glowAnim.value == 0) return const SizedBox.shrink();
                final col = _activeGlowColor;
                return IgnorePointer(
                  child: Opacity(
                    opacity: _glowAnim.value,
                    child: Stack(children: [
                      _glowLine(left: true,  color: col),
                      _glowLine(left: false, color: col),
                    ]),
                  ),
                );
              },
            ),
        ],
      ),
    );
  }
}

// ── Header ─────────────────────────────────────────────────────────────────

class _Header extends StatelessWidget {
  final String ip;
  final String iface;
  final bool isMonitor;
  final AnimationController scanAnim;
  final Project? activeProject;
  final VoidCallback onSettings;
  final VoidCallback onResults;
  final VoidCallback onReport;
  final VoidCallback onProjects;
  final VoidCallback onPipeline;

  const _Header({
    required this.ip,
    required this.iface,
    required this.isMonitor,
    required this.scanAnim,
    required this.activeProject,
    required this.onSettings,
    required this.onResults,
    required this.onReport,
    required this.onProjects,
    required this.onPipeline,
  });

  static String _projectLabel(Project p) {
    if (p.target.isEmpty) return p.name;
    final nets = p.target.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    if (nets.isEmpty) return p.name;
    if (nets.length == 1) return '${p.name}  ·  ${nets.first}';
    return '${p.name}  ·  ${nets.first}  +${nets.length - 1}';
  }

  Future<void> _recoverWifi(BuildContext context) async {
    await Process.run('su', ['-c',
      'ip link set wlan0 down 2>/dev/null; '
      'echo 0 > /sys/module/wlan/parameters/con_mode 2>/dev/null; '
      'ip link set wlan0 up 2>/dev/null; '
      'svc wifi enable 2>/dev/null',
    ]);
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text('wlan0 restored', style: TextStyle(fontFamily: 'monospace', fontSize: 11)),
        backgroundColor: Color(0xFF0D1117),
        duration: Duration(seconds: 2),
      ));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: FColors.bgCard,
        border: Border(bottom: BorderSide(color: FColors.cyan.op(0.2), width: 1)),
      ),
      child: Stack(
        children: [
          // Animated scanline
          AnimatedBuilder(
            animation: scanAnim,
            builder: (_, __) => Positioned(
              left: 0,
              right: 0,
              top: scanAnim.value * 72,
              child: Container(height: 1, color: FColors.cyan.op(0.06)),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 12, 8, 10),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    GestureDetector(
                      onTap: onSettings,
                      child: const Text('▓▒░ F-SECURITY ░▒▓',
                        style: TextStyle(fontFamily: 'monospace', fontSize: 14,
                          fontWeight: FontWeight.bold, color: FColors.cyan, letterSpacing: 2)),
                    ),
                    const Spacer(),
                    GestureDetector(
                      onTap: () => _recoverWifi(context),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4),
                        child: Icon(
                          isMonitor ? Icons.wifi_find : Icons.wifi,
                          color: isMonitor ? FColors.red : FColors.green,
                          size: 20,
                        ),
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.account_tree_outlined, color: FColors.purple, size: 20),
                      onPressed: onPipeline,
                      tooltip: 'Pipeline',
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
                    ),
                    IconButton(
                      icon: Icon(Icons.work_outline,
                        color: activeProject != null ? FColors.amber : FColors.textSecondary,
                        size: 20),
                      onPressed: onProjects,
                      tooltip: 'Projects',
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
                    ),
                    IconButton(
                      icon: const Icon(Icons.folder_open_outlined, color: FColors.green, size: 20),
                      onPressed: onResults,
                      tooltip: 'Results',
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
                    ),
                  ],
                ),
                const SizedBox(height: 2),
                Row(children: [
                  _Dot(),
                  const SizedBox(width: 6),
                  Flexible(
                    child: RichText(
                      overflow: TextOverflow.ellipsis,
                      text: TextSpan(
                        style: const TextStyle(fontFamily: 'monospace'),
                        children: [
                          TextSpan(
                            text: iface,
                            style: TextStyle(
                              fontSize: 11,
                              color: isMonitor ? FColors.red : FColors.green,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          TextSpan(
                            text: ip.isNotEmpty && ip != '...' ? '  $ip' : '',
                            style: const TextStyle(fontSize: 11, color: FColors.green),
                          ),
                          const TextSpan(text: '  ·  ', style: TextStyle(fontSize: 10, color: FColors.textDim)),
                          const TextSpan(
                            text: 'NetHunter',
                            style: TextStyle(fontSize: 10, color: FColors.red, fontWeight: FontWeight.bold),
                          ),
                          const TextSpan(text: '  ·  ', style: TextStyle(fontSize: 10, color: FColors.textDim)),
                          TextSpan(
                            text: '${kModules.length} modules',
                            style: const TextStyle(fontSize: 10, color: FColors.cyan),
                          ),
                        ],
                      ),
                    ),
                  ),
                ]),
                if (activeProject != null) ...[
                  const SizedBox(height: 4),
                  GestureDetector(
                    onTap: onProjects,
                    child: Row(
                      children: [
                        const Icon(Icons.work_outline, color: FColors.amber, size: 10),
                        const SizedBox(width: 5),
                        Expanded(
                          child: Text(
                            _projectLabel(activeProject!),
                            style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.amber),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
                const SizedBox(height: 8),
                GestureDetector(
                  onTap: onReport,
                  child: Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(vertical: 7),
                    decoration: BoxDecoration(
                      border: Border.all(color: FColors.amber.op(0.5), width: 1),
                      color: FColors.amber.op(0.07),
                      borderRadius: BorderRadius.circular(2),
                      boxShadow: [BoxShadow(color: FColors.amber.op(0.1), blurRadius: 8)],
                    ),
                    child: const Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.description_outlined, color: FColors.amber, size: 14),
                        SizedBox(width: 7),
                        Text('GENERATE / VIEW REPORT',
                          style: TextStyle(fontFamily: 'monospace', fontSize: 10,
                            color: FColors.amber, letterSpacing: 2, fontWeight: FontWeight.bold)),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _Dot extends StatefulWidget {
  @override
  State<_Dot> createState() => _DotState();
}
class _DotState extends State<_Dot> with SingleTickerProviderStateMixin {
  late AnimationController _c;
  @override
  void initState() {
    super.initState();
    _c = AnimationController(vsync: this, duration: const Duration(milliseconds: 1200))..repeat(reverse: true);
  }
  @override
  void dispose() { _c.dispose(); super.dispose(); }
  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: _c,
    builder: (_, __) => Container(width: 6, height: 6,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: Color.lerp(FColors.green, FColors.green.op(0.2), _c.value),
        boxShadow: [BoxShadow(color: FColors.green.op(0.6 * (1 - _c.value)), blurRadius: 6)],
      )),
  );
}

// ── Filter bar ─────────────────────────────────────────────────────────────

class _FilterBar extends StatelessWidget {
  final ModuleCategory? selected;
  final void Function(ModuleCategory?) onSelect;

  const _FilterBar({required this.selected, required this.onSelect});

  static const _cats = [
    (ModuleCategory.network, 'SCAN'),
    (ModuleCategory.exploit, 'EXPLOIT'),
    (ModuleCategory.fire,    'FIRE'),
    (ModuleCategory.brute,   'BRUTE'),
    (ModuleCategory.recon,   'RECON'),
    (ModuleCategory.iot,     'IoT'),
    (ModuleCategory.web,     'WEB'),
  ];

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<Set<int>>(
      valueListenable: SessionManager.instance.runningIds,
      builder: (_, runningIds, __) {
        final runningCats = <ModuleCategory>{};
        for (final id in runningIds) {
          final mod = kModules.where((m) => m.id == id).firstOrNull;
          if (mod != null) runningCats.add(mod.category);
        }
        return Container(
          height: 36,
          color: FColors.bgCard,
          child: ListView(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            children: [
              _Chip('ALL (${kModules.length})', selected == null, false, () => onSelect(null), FColors.textSecondary),
              ..._cats.map((t) {
                final count = kModules.where((m) => m.category == t.$1).length;
                return _Chip(
                  '${t.$2} ($count)',
                  selected == t.$1,
                  runningCats.contains(t.$1),
                  () => onSelect(t.$1),
                  _catColor(t.$1),
                );
              }),
            ],
          ),
        );
      },
    );
  }

  Color _catColor(ModuleCategory c) => switch (c) {
    ModuleCategory.network => FColors.cyanDim,
    ModuleCategory.web     => FColors.purple,
    ModuleCategory.iot     => FColors.amber,
    ModuleCategory.brute   => FColors.red,
    ModuleCategory.recon   => FColors.green,
    ModuleCategory.exploit => FColors.magenta,
    ModuleCategory.fire    => FColors.orange,
    _                      => FColors.textSecondary,
  };
}

class _Chip extends StatefulWidget {
  final String label;
  final bool active;
  final bool hasRunning;
  final VoidCallback onTap;
  final Color color;
  const _Chip(this.label, this.active, this.hasRunning, this.onTap, this.color);

  @override
  State<_Chip> createState() => _ChipState();
}

class _ChipState extends State<_Chip> with SingleTickerProviderStateMixin {
  late AnimationController _pulse;

  @override
  void initState() {
    super.initState();
    _pulse = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1400),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _pulse.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _pulse,
      builder: (_, __) {
        final t = _pulse.value; // 0..1
        final runGlow = widget.hasRunning
            ? [
                BoxShadow(
                  color: widget.color.op(0.50 + 0.40 * t),
                  blurRadius: 8 + 5 * t,
                  spreadRadius: 0,
                ),
                BoxShadow(
                  color: widget.color.op(0.20 + 0.15 * t),
                  blurRadius: 18 + 6 * t,
                  spreadRadius: 2,
                ),
              ]
            : <BoxShadow>[];

        return GestureDetector(
          onTap: widget.onTap,
          child: Container(
            margin: const EdgeInsets.only(right: 6),
            padding: const EdgeInsets.symmetric(horizontal: 8),
            decoration: BoxDecoration(
              color: widget.active
                  ? widget.color.op(0.18)
                  : widget.hasRunning
                      ? widget.color.op(0.08)
                      : FColors.bgPanel,
              border: Border.all(
                color: widget.active
                    ? widget.color
                    : widget.hasRunning
                        ? widget.color.op(0.45 + 0.55 * t)
                        : FColors.textSecondary.op(0.5),
                width: widget.active || widget.hasRunning ? 1 : 0.8,
              ),
              borderRadius: BorderRadius.circular(2),
              boxShadow: runGlow,
            ),
            child: Center(
              child: Text(widget.label,
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 9,
                  letterSpacing: 1,
                  color: widget.active
                      ? widget.color
                      : widget.hasRunning
                          ? widget.color.op(0.65 + 0.35 * t)
                          : FColors.textSecondary,
                ),
              ),
            ),
          ),
        );
      },
    );
  }
}
