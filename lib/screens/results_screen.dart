import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';
import '../services/nethunter_service.dart';
import '../services/report_service.dart';
import '../theme/colors.dart';
import 'host_map_screen.dart';

class _MapEntry {
  final String label;
  final String slug;
  final String absPath;
  final bool isCumulative;
  _MapEntry({required this.label, required this.slug, required this.absPath, this.isCumulative = true});
}

class _ScanSession {
  final String name;      // timestamp folder name
  final String? subdir;   // project slug, null for flat sessions
  final String absPath;   // Android-absolute path (for su commands)

  _ScanSession({required this.name, this.subdir, required this.absPath});
}

class ResultsScreen extends StatefulWidget {
  const ResultsScreen({super.key});
  @override
  State<ResultsScreen> createState() => _ResultsScreenState();
}

class _ResultsScreenState extends State<ResultsScreen> {
  List<_ScanSession> _sessions = [];
  List<_MapEntry>   _maps     = [];
  bool _loading    = true;
  bool _selectMode = false;
  final Set<int> _selected = {};

  @override
  void initState() {
    super.initState();
    _loadSessions();
  }

  Future<void> _loadSessions() async {
    setState(() => _loading = true);
    try {
      final resultsPath = '${NetHunterService.chrootPath}${NetHunterService.scriptsPath}/results';
      // Find timestamp-named dirs at depth 1 (flat) and depth 2 (slug/timestamp).
      // Only show session dirs that contain at least one real result file.
      // Probe-sniffer sessions (only .jsonl), empty dirs, and dirs with only
      // internal markers (.fsec_done, hidden files) are excluded.
      final r = await Process.run('su', ['-c',
        'find "$resultsPath" -maxdepth 3 -mindepth 2 -type f '
        r"! -name '*.jsonl' ! -name '.fsec_done' ! -name '.*' 2>/dev/null "
        r"| sed 's|/[^/]*$||' "
        r"| grep -E '/[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}$' "
        '| sort -ru',
      ]);
      final lines = r.stdout.toString().trim().split('\n')
          .where((l) => l.isNotEmpty).toList();
      final sessions = lines.map((absPath) {
        final rel   = absPath.replaceFirst('$resultsPath/', '');
        final parts = rel.split('/');
        return _ScanSession(
          name:    parts.last,
          subdir:  parts.length == 2 ? parts.first : null,
          absPath: absPath,
        );
      }).toList();
      setState(() => _sessions = sessions);
    } catch (_) {
      setState(() => _sessions = []);
    }
    await _loadMaps();
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _loadMaps() async {
    try {
      final resultsPath = '${NetHunterService.chrootPath}${NetHunterService.scriptsPath}/results';
      final r = await Process.run('su', ['-c',
        'find "$resultsPath" -maxdepth 3 -name "probe_map.html" 2>/dev/null | sort -r',
      ]);
      final lines = r.stdout.toString().trim().split('\n')
          .where((l) => l.isNotEmpty).toList();
      final tsRe = RegExp(r'^\d{4}-');
      final maps = lines.map((path) {
        final rel   = path.replaceFirst('$resultsPath/', '');
        final parts = rel.split('/');
        // depth1: probe_map.html → global persistent
        // depth2: slug/probe_map.html → project persistent
        // depth2: ts/probe_map.html  → flat session (legacy)
        // depth3: slug/ts/probe_map.html → project session (legacy)
        String slug = '';
        bool isCumulative = true;
        if (parts.length == 2) {
          if (tsRe.hasMatch(parts[0])) { isCumulative = false; }  // ts/file
          else { slug = parts[0]; }                               // slug/file (persistent)
        } else if (parts.length == 3) {
          slug = parts[0]; isCumulative = false;                  // slug/ts/file (session)
        }
        return _MapEntry(label: 'Probe Map', slug: slug, absPath: path, isCumulative: isCumulative);
      }).toList();
      // persistent maps first
      maps.sort((a, b) => a.isCumulative == b.isCumulative ? 0 : (a.isCumulative ? -1 : 1));
      if (mounted) setState(() => _maps = maps);
    } catch (_) {}
  }

  Future<void> _openMap(_MapEntry e) async {
    final dir      = e.absPath.substring(0, e.absPath.lastIndexOf('/') + 1);
    final jsonl    = '${dir}probe_data.jsonl';
    final pyScript = e.absPath.replaceAll('/results/probe_map.html', '/scripts/gen_probe_map.py');

    // If probe_sniffer is still running, the live loop already keeps probe_map.html
    // fresh from probe_data.jsonl + the current session LOG_FILE.
    // Regenerating here would OVERWRITE that with probe_data.jsonl only (missing live data).
    // Only regenerate when the script is offline so fresh dedup/centroid is applied.
    final pidFile = '$dir.probe_pid';
    final pgR = await Process.run('su', ['-c',
      r'p=$(cat "' + pidFile + r'" 2>/dev/null); [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo 1 || echo 0']);
    final isLive = pgR.stdout.toString().trim() == '1';

    if (!isLive) {
      await Process.run('su', ['-c',
        'PROBE_JSONL="$jsonl" PROBE_HTML="${e.absPath}" python3 "$pyScript" 2>/dev/null']);
    }

    final r = await Process.run('su', ['-c', 'cat "${e.absPath}" 2>/dev/null']);
    final html = r.stdout.toString();
    if (!mounted) return;
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => _HtmlViewScreen(
        name: e.label + (e.slug.isNotEmpty ? '  ·  ${e.slug}' : ''),
        html: html,
        absPath: e.absPath,
        onShare: () => ReportService.shareFile(e.absPath, 'probe_map.html'),
      ),
    ));
  }

  Future<void> _deleteMap(_MapEntry e) async {
    if (e.isCumulative) {
      // Cumulative map = wardriving history. "Delete Map only" is misleading because
      // probe_data.jsonl survives and the next session regenerates the HTML with all
      // old data. Always offer a full reset that wipes everything.
      final confirm = await showDialog<bool>(
        context: context,
        builder: (_) => AlertDialog(
          backgroundColor: FColors.bgCard,
          title: const Text('Reset all probe data?',
            style: TextStyle(fontFamily: 'monospace', color: FColors.red, fontSize: 13)),
          content: const Text(
            'Permanently deletes all accumulated probe history:\n'
            '  • probe_map.html\n'
            '  • probe_data.jsonl  (all locations)\n'
            '  • probe_live.json\n\n'
            'The next session starts a fresh map from zero.\nThis cannot be undone.',
            style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11, height: 1.55)),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel', style: TextStyle(color: FColors.textSecondary, fontFamily: 'monospace')),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Yes, Reset', style: TextStyle(color: FColors.red, fontFamily: 'monospace', fontWeight: FontWeight.bold)),
            ),
          ],
        ),
      );
      if (confirm != true) return;
      // Delete probe map files at depth 1 (global) and depth 2 (per-project).
      // This catches orphaned project-level probe_data.jsonl files that survive a global reset.
      final resultsPath = e.absPath.substring(0, e.absPath.lastIndexOf('/results/') + '/results'.length);
      await Process.run('su', ['-c',
        'find "$resultsPath" -maxdepth 2 \\( '
        '-name "probe_map.html" -o -name "probe_data.jsonl" -o -name "probe_live.json" '
        '\\) -delete 2>/dev/null']);
    } else {
      final ok = await showDialog<bool>(
        context: context,
        builder: (_) => AlertDialog(
          backgroundColor: FColors.bgCard,
          title: const Text('Delete map?',
            style: TextStyle(fontFamily: 'monospace', color: FColors.red, fontSize: 14)),
          content: const Text('Delete this session map file?',
            style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11)),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel', style: TextStyle(color: FColors.textSecondary, fontFamily: 'monospace')),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Delete', style: TextStyle(color: FColors.red, fontFamily: 'monospace')),
            ),
          ],
        ),
      );
      if (ok != true) return;
      await Process.run('su', ['-c', 'rm -f "${e.absPath}" 2>/dev/null']);
    }
    await _loadMaps();
  }

  void _enterSelectMode() => setState(() { _selectMode = true; _selected.clear(); });
  void _exitSelectMode()  => setState(() { _selectMode = false; _selected.clear(); });
  void _toggleSelect(int i) => setState(() {
    if (_selected.contains(i)) { _selected.remove(i); } else { _selected.add(i); }
  });

  Future<void> _deleteSelected() async {
    if (_selected.isEmpty) return;
    final count = _selected.length;
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: FColors.bgCard,
        title: Text('Delete $count session${count > 1 ? 's' : ''}?',
          style: const TextStyle(fontFamily: 'monospace', color: FColors.red, fontSize: 14)),
        content: Text('This cannot be undone.',
          style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel', style: TextStyle(color: FColors.textSecondary, fontFamily: 'monospace')),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete all', style: TextStyle(color: FColors.red, fontFamily: 'monospace')),
          ),
        ],
      ),
    );
    if (ok != true) return;
    final toDelete = _selected.toList()..sort((a, b) => b.compareTo(a));
    for (final i in toDelete) {
      await Process.run('su', ['-c', 'rm -rf "${_sessions[i].absPath}" 2>/dev/null; true']);
    }
    _exitSelectMode();
    _loadSessions();
  }

  Widget _sectionLabel(String text, Color color) => Padding(
    padding: const EdgeInsets.fromLTRB(12, 10, 12, 5),
    child: Row(children: [
      Container(width: 3, height: 11, color: color),
      const SizedBox(width: 8),
      Text(text, style: TextStyle(
        fontFamily: 'monospace', fontSize: 9,
        letterSpacing: 2, color: color, fontWeight: FontWeight.bold,
      )),
    ]),
  );

  Future<void> _confirmDelete(_ScanSession s) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: FColors.bgCard,
        title: const Text('Delete session?',
          style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 14)),
        content: Text(s.subdir != null ? '${s.subdir}/${s.name}' : s.name,
          style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel', style: TextStyle(color: FColors.textSecondary, fontFamily: 'monospace')),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete', style: TextStyle(color: FColors.red, fontFamily: 'monospace')),
          ),
        ],
      ),
    );
    if (ok != true) return;
    await Process.run('su', ['-c', 'rm -rf "${s.absPath}" 2>/dev/null; true']);
    _loadSessions();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: FColors.bg,
      appBar: AppBar(
        backgroundColor: FColors.bgCard,
        leading: _selectMode
            ? IconButton(
                icon: const Icon(Icons.close, color: FColors.textSecondary, size: 20),
                onPressed: _exitSelectMode,
              )
            : IconButton(
                icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
                onPressed: () => Navigator.pop(context),
              ),
        title: _selectMode
            ? Text(
                _selected.isEmpty ? 'Select sessions' : '${_selected.length} selected',
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 13,
                  color: _selected.isEmpty ? FColors.textDim : FColors.cyan,
                ),
              )
            : const Text('RESULTS',
                style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, letterSpacing: 3, fontSize: 14)),
        actions: _selectMode
            ? [
                if (_selected.isNotEmpty)
                  IconButton(
                    icon: const Icon(Icons.delete_sweep, color: FColors.red, size: 22),
                    tooltip: 'Delete selected',
                    onPressed: _deleteSelected,
                  ),
              ]
            : [
                IconButton(
                  icon: const Icon(Icons.refresh, color: FColors.cyan, size: 20),
                  onPressed: _loadSessions,
                ),
                IconButton(
                  icon: const Icon(Icons.delete_sweep_outlined, color: FColors.textSecondary, size: 22),
                  tooltip: 'Select to delete',
                  onPressed: _sessions.isEmpty ? null : _enterSelectMode,
                ),
              ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5))
          : CustomScrollView(
              slivers: [
                if (_maps.isNotEmpty) ...[
                  SliverToBoxAdapter(child: _sectionLabel('MAPS', FColors.green)),
                  SliverPadding(
                    padding: const EdgeInsets.symmetric(horizontal: 10),
                    sliver: SliverList(
                      delegate: SliverChildBuilderDelegate(
                        (_, i) => _MapCard(entry: _maps[i], onOpen: () => _openMap(_maps[i]), onDelete: () => _deleteMap(_maps[i])),
                        childCount: _maps.length,
                      ),
                    ),
                  ),
                ],
                SliverToBoxAdapter(child: _sectionLabel('SESSIONS', FColors.cyan)),
                if (_sessions.isEmpty)
                  const SliverFillRemaining(
                    child: Center(child: Text('No scan sessions yet.',
                      style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 12))),
                  )
                else
                  SliverPadding(
                    padding: const EdgeInsets.fromLTRB(10, 0, 10, 10),
                    sliver: SliverList(
                      delegate: SliverChildBuilderDelegate(
                        (_, i) => _SessionTile(
                          session: _sessions[i],
                          selectMode: _selectMode,
                          selected: _selected.contains(i),
                          onTap: _selectMode
                              ? () => _toggleSelect(i)
                              : () => Navigator.push(context,
                                  MaterialPageRoute(builder: (_) => _SessionScreen(session: _sessions[i]))),
                          onLongPress: _selectMode ? null : () {
                            _enterSelectMode();
                            _toggleSelect(i);
                          },
                          onDelete: () => _confirmDelete(_sessions[i]),
                        ),
                        childCount: _sessions.length,
                      ),
                    ),
                  ),
              ],
            ),
    );
  }
}

class _SessionTile extends StatelessWidget {
  final _ScanSession session;
  final bool selectMode;
  final bool selected;
  final VoidCallback onTap;
  final VoidCallback? onLongPress;
  final VoidCallback onDelete;

  const _SessionTile({
    required this.session,
    required this.onTap,
    required this.onDelete,
    this.selectMode = false,
    this.selected = false,
    this.onLongPress,
  });

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    onLongPress: onLongPress,
    child: Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.only(left: 14, right: 4, top: 6, bottom: 6),
      decoration: BoxDecoration(
        color: selected ? FColors.cyan.op(0.08) : FColors.bgCard,
        border: Border.all(
          color: selected ? FColors.cyan.op(0.5) : FColors.cyan.op(0.15),
        ),
        boxShadow: [BoxShadow(color: FColors.cyan.op(0.04), blurRadius: 8)],
      ),
      child: Row(
        children: [
          selectMode
              ? Icon(
                  selected ? Icons.check_box : Icons.check_box_outline_blank,
                  color: selected ? FColors.cyan : FColors.textDim,
                  size: 16,
                )
              : const Icon(Icons.folder_outlined, color: FColors.green, size: 16),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(session.name,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textPrimary)),
                if (session.subdir != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                      decoration: BoxDecoration(
                        border: Border.all(color: FColors.amber.op(0.4), width: 0.8),
                        color: FColors.amber.op(0.06),
                        borderRadius: BorderRadius.circular(2),
                      ),
                      child: Text(session.subdir!,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 8, color: FColors.amber)),
                    ),
                  ),
              ],
            ),
          ),
          if (!selectMode) ...[
            IconButton(
              icon: const Icon(Icons.delete_outline, color: FColors.red, size: 18),
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
              tooltip: 'Delete session',
              onPressed: onDelete,
            ),
            const Icon(Icons.chevron_right, color: FColors.textDim, size: 16),
          ],
        ],
      ),
    ),
  );
}

// ── Single session file list ────────────────────────────────────────────────

class _SessionScreen extends StatefulWidget {
  final _ScanSession session;
  const _SessionScreen({required this.session});
  @override
  State<_SessionScreen> createState() => _SessionScreenState();
}

class _SessionScreenState extends State<_SessionScreen> {
  List<String> _files = [];
  bool _loading = true;

  String get _sessionPath => widget.session.absPath;

  @override
  void initState() {
    super.initState();
    _loadFiles();
  }

  Future<void> _loadFiles() async {
    final r = await Process.run('su', ['-c', 'find $_sessionPath -type f | sort 2>/dev/null']);
    final lines = r.stdout.toString().trim().split('\n')
        .where((l) {
          if (l.isEmpty) return false;
          final name = l.split('/').last;
          return !name.endsWith('.jsonl') && !name.startsWith('.');
        }).toList();
    setState(() { _files = lines; _loading = false; });
  }

  Future<void> _shareFile(String path) async {
    final filename = path.split('/').last;
    await ReportService.shareFile(path, filename);
  }

  Future<void> _viewFile(String path) async {
    final r = await Process.run('su', ['-c', 'cat "$path" 2>/dev/null']);
    final content = r.stdout.toString();
    if (!mounted) return;
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => _FileViewScreen(name: path.split('/').last, content: content, fullPath: path, onShare: () => _shareFile(path)),
    ));
  }

  Future<void> _openHtml(String path) async {
    final r = await Process.run('su', ['-c', 'cat $path 2>/dev/null']);
    final html = r.stdout.toString();
    if (!mounted) return;
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => _HtmlViewScreen(name: path.split('/').last, html: html, onShare: () => _shareFile(path)),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: FColors.bg,
      appBar: AppBar(
        backgroundColor: FColors.bgCard,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(widget.session.name,
          style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 11)),
        actions: [
          IconButton(
            icon: const Icon(Icons.hub_outlined, color: FColors.cyan, size: 20),
            tooltip: 'Host Map',
            onPressed: () => Navigator.push(context, MaterialPageRoute(
              builder: (_) => HostMapScreen(
                sessionPath: _sessionPath,
                sessionName: widget.session.name,
              ),
            )),
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5))
          : _files.isEmpty
              ? const Center(child: Text('No files in this session.',
                  style: TextStyle(fontFamily: 'monospace', color: FColors.textDim)))
              : ListView.builder(
                  padding: const EdgeInsets.all(10),
                  itemCount: _files.length,
                  itemBuilder: (_, i) {
                    final name = _files[i].split('/').last;
                    final isHtml = name.endsWith('.html');
                    return GestureDetector(
                      onTap: () => isHtml ? _openHtml(_files[i]) : _viewFile(_files[i]),
                      child: Container(
                        margin: const EdgeInsets.only(bottom: 6),
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                        decoration: BoxDecoration(
                          color: FColors.bgCard,
                          border: Border.all(color: isHtml
                              ? FColors.amber.op(0.3)
                              : FColors.cyan.op(0.12)),
                        ),
                        child: Row(
                          children: [
                            Icon(isHtml ? Icons.map_outlined : Icons.description_outlined,
                              color: isHtml ? FColors.amber : FColors.textSecondary, size: 15),
                            const SizedBox(width: 10),
                            Expanded(child: Text(name,
                              style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textPrimary))),
                            if (isHtml)
                              IconButton(
                                icon: const Icon(Icons.open_in_new, color: FColors.amber, size: 16),
                                padding: EdgeInsets.zero,
                                constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                                tooltip: 'Open map',
                                onPressed: () => _openHtml(_files[i]),
                              ),
                            IconButton(
                              icon: const Icon(Icons.share, color: FColors.cyan, size: 16),
                              padding: EdgeInsets.zero,
                              constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                              onPressed: () => _shareFile(_files[i]),
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
    );
  }
}

// ── Map card ───────────────────────────────────────────────────────────────

class _MapCard extends StatelessWidget {
  final _MapEntry entry;
  final VoidCallback onOpen;
  final VoidCallback onDelete;
  const _MapCard({required this.entry, required this.onOpen, required this.onDelete});

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onOpen,
    child: Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.only(left: 14, right: 4, top: 8, bottom: 8),
      decoration: BoxDecoration(
        color: FColors.bgCard,
        border: Border.all(color: FColors.green.op(0.35)),
        boxShadow: [BoxShadow(color: FColors.green.op(0.06), blurRadius: 10)],
      ),
      child: Row(
        children: [
          const Icon(Icons.map_outlined, color: FColors.green, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('PROBE MAP',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 11,
                    color: FColors.green, fontWeight: FontWeight.bold, letterSpacing: 1)),
                const SizedBox(height: 3),
                Text(entry.isCumulative ? 'cumulative · all sessions' : 'session',
                  style: TextStyle(
                    fontFamily: 'monospace', fontSize: 9,
                    color: entry.isCumulative ? FColors.green.op(0.7) : FColors.textDim,
                  )),
              ],
            ),
          ),
          IconButton(
            icon: const Icon(Icons.delete_outline, color: FColors.red, size: 18),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
            onPressed: onDelete,
          ),
          const Icon(Icons.open_in_new, color: FColors.green, size: 16),
          const SizedBox(width: 8),
        ],
      ),
    ),
  );
}

// ── HTML / Map viewer (WebView) ─────────────────────────────────────────────

class _HtmlViewScreen extends StatefulWidget {
  final String name;
  final String html;
  final String? absPath;
  final VoidCallback onShare;
  const _HtmlViewScreen({required this.name, required this.html, this.absPath, required this.onShare});
  @override
  State<_HtmlViewScreen> createState() => _HtmlViewScreenState();
}

class _HtmlViewScreenState extends State<_HtmlViewScreen> {
  late final WebViewController _ctrl;
  bool _loading      = true;
  Timer? _liveTimer;
  Timer? _gpsTimer;
  String _lastMtime  = '';
  bool _refreshing   = false;
  bool _isScriptLive = false;
  bool? _gpsAlive;
  double? _lastMyLat;
  double? _lastMyLon;

  // Sibling JSON file written by _live_map_loop every 5s
  String? get _livePath => widget.absPath == null ? null
      : '${widget.absPath!.substring(0, widget.absPath!.lastIndexOf('/') + 1)}probe_live.json';

  @override
  void initState() {
    super.initState();
    _ctrl = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setBackgroundColor(const Color(0xFF0D1117))
      ..setNavigationDelegate(NavigationDelegate(
        onPageFinished: (_) {
          if (mounted) setState(() => _loading = false);
          _injectLastGps();
        },
      ));
    _initGeo();
    _loadHtmlContent(widget.html);
    if (_livePath != null) {
      _liveTimer = Timer.periodic(const Duration(seconds: 5), (_) => _liveRefresh());
    }
    _checkGps();
    _gpsTimer = Timer.periodic(const Duration(seconds: 5), (_) => _checkGps());
  }

  Future<void> _initGeo() async {
    if (_ctrl.platform is AndroidWebViewController) {
      final aCtrl = _ctrl.platform as AndroidWebViewController;
      await aCtrl.setGeolocationEnabled(true);
      await aCtrl.setGeolocationPermissionsPromptCallbacks(
        onShowPrompt: (_) async =>
            const GeolocationPermissionsResponse(allow: true, retain: true),
      );
    }
  }

  void _injectLastGps() {
    final lat = _lastMyLat;
    final lon = _lastMyLon;
    if (lat != null && lon != null) {
      _ctrl.runJavaScript(
        'if(typeof updateMyLocation==="function")updateMyLocation($lat,$lon,30);');
    }
  }

  Future<void> _checkGps() async {
    // GPS relay listens on port 10110 (0x277E); check for LISTEN state (0A) only —
    // lingering ESTABLISHED/CLOSE_WAIT sockets after relay stops must not count.
    final r = await Process.run('su', ['-c',
      "awk 'NR>1 && \$4==\"0A\"{print \$2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null"
      " | grep -qi ':277E\$' && echo 1 || echo 0"]);
    if (!mounted) return;
    final alive = r.stdout.toString().trim() == '1';
    if (alive != _gpsAlive) setState(() => _gpsAlive = alive);
  }

  @override
  void dispose() {
    _liveTimer?.cancel();
    _gpsTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadHtmlContent(String html) async {
    var h = html;
    try {
      final css = await rootBundle.loadString('assets/leaflet.min.css');
      final js  = await rootBundle.loadString('assets/leaflet.min.js');
      h = h
        .replaceFirst(
          '<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>',
          '<style>$css</style>',
        )
        .replaceFirst(
          '<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>',
          '<script>$js</script>',
        );
    } catch (_) {}
    await _ctrl.loadHtmlString(h, baseUrl: 'https://localhost');
  }

  Future<void> _liveRefresh() async {
    if (_refreshing || !mounted) return;
    _refreshing = true;
    try {
      final path = _livePath!;

      // Badge: script writes $$ to .probe_pid on start, removes on stop.
      // kill -0 checks the PID is alive without signalling it.
      final pidFile = path.replaceAll('probe_live.json', '.probe_pid');
      final pgR = await Process.run('su', ['-c',
        'p=\$(cat "$pidFile" 2>/dev/null); [ -n "\$p" ] && kill -0 "\$p" 2>/dev/null && echo 1 || echo 0']);
      final alive = pgR.stdout.toString().trim() == '1';
      if (alive != _isScriptLive && mounted) setState(() => _isScriptLive = alive);

      // Data injection: only re-read probe_live.json when it actually changed
      final statR = await Process.run('su', ['-c', 'stat -c %Y "$path" 2>/dev/null']);
      final mtime = statR.stdout.toString().trim();
      if (mtime.isEmpty || mtime == _lastMtime) return;
      _lastMtime = mtime;

      final r = await Process.run('su', ['-c', 'cat "$path" 2>/dev/null']);
      final raw = r.stdout.toString().trim();
      if (raw.isEmpty || !mounted) return;

      final data       = jsonDecode(raw) as Map<String, dynamic>;
      final probesJson = jsonEncode(data['probes']);
      final summaryJson= jsonEncode(data['summary']);
      final total      = data['total']   ?? 0;
      final clients    = data['clients'] ?? 0;
      final rand       = data['rand']    ?? 0;
      final source     = (data['source'] ?? '').toString().replaceAll('"', '\\"');

      await _ctrl.runJavaScript(
        'if(typeof updateMap==="function")'
        'updateMap($probesJson,$summaryJson,'
        '{total:$total,clients:$clients,rand:$rand,source:"$source"});');

      // Inject GPS (fallback — only when browser watchPosition hasn't fired in 10s)
      final myLat = (data['my_lat'] as num?)?.toDouble();
      final myLon = (data['my_lon'] as num?)?.toDouble();
      if (myLat != null && myLon != null) {
        final moved = _lastMyLat == null ||
            (myLat - _lastMyLat!).abs() > 0.00005 ||
            (myLon - _lastMyLon!).abs() > 0.00005;
        if (moved) {
          _lastMyLat = myLat; _lastMyLon = myLon;
          await _ctrl.runJavaScript(
            'if(typeof updateMyLocation==="function"&&'
            '(Date.now()-(window._geoFresh||0))>10000)'
            'updateMyLocation($myLat,$myLon,30);');
        }
      }
    } catch (_) {
    } finally {
      _refreshing = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: FColors.bgCard,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
          onPressed: () => Navigator.pop(context),
        ),
        title: Row(
          children: [
            Expanded(child: Text(widget.name,
              style: const TextStyle(fontFamily: 'monospace', color: FColors.amber, fontSize: 11),
              overflow: TextOverflow.ellipsis)),
            if (_gpsAlive != null) ...[
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                margin: const EdgeInsets.only(right: 5),
                decoration: BoxDecoration(
                  color: (_gpsAlive! ? FColors.green : FColors.red).op(0.15),
                  border: Border.all(
                    color: (_gpsAlive! ? FColors.green : FColors.red).op(0.5), width: 1),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text('● GPS',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                    color: _gpsAlive! ? FColors.green : FColors.red,
                    letterSpacing: 1, fontWeight: FontWeight.bold)),
              ),
            ],
            if (_isScriptLive) Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: FColors.green.op(0.15),
                border: Border.all(color: FColors.green.op(0.5), width: 1),
                borderRadius: BorderRadius.circular(3),
              ),
              child: const Text('● LIVE',
                style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                  color: FColors.green, letterSpacing: 1, fontWeight: FontWeight.bold)),
            ),
          ],
        ),
        actions: [
          IconButton(icon: const Icon(Icons.share, color: FColors.cyan, size: 20), onPressed: widget.onShare),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.amber.op(0.3)),
        ),
      ),
      body: Stack(
        children: [
          WebViewWidget(controller: _ctrl),
          if (_loading)
            const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5)),
        ],
      ),
    );
  }
}

// ── File content viewer ─────────────────────────────────────────────────────

class _FileViewScreen extends StatelessWidget {
  final String name;
  final String content;
  final String fullPath;
  final VoidCallback onShare;

  const _FileViewScreen({required this.name, required this.content, required this.fullPath, required this.onShare});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: FColors.bg,
      appBar: AppBar(
        backgroundColor: FColors.bgCard,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(name, style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 11)),
        actions: [
          IconButton(icon: const Icon(Icons.share, color: FColors.cyan, size: 20), onPressed: onShare),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(12),
        child: SelectableText(
          content.isEmpty ? '[empty file]' : content,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textPrimary, height: 1.5),
        ),
      ),
    );
  }
}
