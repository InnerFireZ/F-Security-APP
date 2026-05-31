import 'package:flutter/material.dart';
import 'package:share_plus/share_plus.dart';
import 'package:webview_flutter/webview_flutter.dart';
import '../models/project.dart';
import '../services/project_service.dart';
import '../services/report_service.dart';
import '../theme/colors.dart';

// ── Report Picker ───────────────────────────────────────────────────────────

class ReportPickerScreen extends StatefulWidget {
  const ReportPickerScreen({super.key});
  @override
  State<ReportPickerScreen> createState() => _ReportPickerScreenState();
}

class _ReportPickerScreenState extends State<ReportPickerScreen> {
  List<SessionInfo> _sessions = [];
  Project? _activeProject;
  bool _loading = true;
  bool _generatingProject = false;
  String? _generating; // stores session.fullPath of the session being generated

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    final results = await Future.wait([
      ReportService.listSessions(),
      ProjectService.getActiveProject(),
    ]);
    setState(() {
      _sessions = results[0] as List<SessionInfo>;
      _activeProject = results[1] as Project?;
      _loading = false;
    });
  }

  // ── Project report ────────────────────────────────────────────────────────

  Future<void> _openProjectReport() async {
    final project = _activeProject;
    if (project == null) return;
    setState(() => _generatingProject = true);
    final path = await ReportService.generateProjectReport(project);
    setState(() => _generatingProject = false);
    if (!mounted) return;
    if (path == null) {
      _showError('Project report generation failed.');
      return;
    }
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => ReportViewerScreen(
        title: project.name,
        htmlPath: path,
        shareLabel: 'F-Security — ${project.name}',
      ),
    ));
  }

  // ── Session report ────────────────────────────────────────────────────────

  Future<void> _openSession(SessionInfo s) async {
    if (!s.hasReport) {
      setState(() => _generating = s.fullPath);
      final ok = await ReportService.generate(s);
      setState(() => _generating = null);
      if (!ok) {
        if (mounted) _showError('Report generation failed — check python3 is installed in the chroot.');
        return;
      }
      await _load();
    }
    if (!mounted) return;
    final path = await ReportService.prepareHtmlForView(s.fullPath);
    if (!mounted) return;
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => ReportViewerScreen(
        title: _formatDate(s.name),
        htmlPath: path,
        shareLabel: 'F-Security Report — ${s.name}',
      ),
    ));
  }

  void _showError(String msg) => ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(content: Text(msg, style: const TextStyle(fontFamily: 'monospace')),
      backgroundColor: FColors.bgCard),
  );

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: FColors.bg,
      appBar: _AppBar(
        title: 'REPORT',
        actions: [
          IconButton(icon: const Icon(Icons.refresh, color: FColors.cyan, size: 20), onPressed: _load),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5))
          : CustomScrollView(
              slivers: [
                // ── Project report card ───────────────────────────────────
                if (_activeProject != null)
                  SliverToBoxAdapter(
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
                      child: _ProjectReportCard(
                        project: _activeProject!,
                        generating: _generatingProject,
                        onTap: _generatingProject ? null : _openProjectReport,
                      ),
                    ),
                  ),

                // ── Section label ─────────────────────────────────────────
                SliverToBoxAdapter(
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(14, 10, 14, 4),
                    child: Row(children: [
                      const Text('SESSION REPORTS',
                        style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                          color: FColors.textDim, letterSpacing: 1)),
                      const SizedBox(width: 8),
                      Text('(${_sessions.length})',
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 9,
                          color: FColors.textDim)),
                    ]),
                  ),
                ),

                // ── Session list ──────────────────────────────────────────
                _sessions.isEmpty
                    ? const SliverFillRemaining(child: _Empty())
                    : SliverPadding(
                        padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
                        sliver: SliverList(
                          delegate: SliverChildBuilderDelegate(
                            (_, i) => _SessionCard(
                              session: _sessions[i],
                              generating: _generating == _sessions[i].fullPath,
                              onTap: () => _openSession(_sessions[i]),
                            ),
                            childCount: _sessions.length,
                          ),
                        ),
                      ),
              ],
            ),
    );
  }

  String _formatDate(String raw) {
    try {
      final parts = raw.split('_');
      if (parts.length == 2) return '${parts[0]}  ${parts[1].replaceAll('-', ':')}';
    } catch (_) {}
    return raw;
  }
}

// ── Project report card ──────────────────────────────────────────────────────

class _ProjectReportCard extends StatelessWidget {
  final Project project;
  final bool generating;
  final VoidCallback? onTap;

  const _ProjectReportCard({
    required this.project,
    required this.generating,
    this.onTap,
  });

  String get _targetPreview {
    if (project.target.isEmpty) return 'No target';
    final nets = project.target.split(',').map((s) => s.trim())
        .where((s) => s.isNotEmpty).toList();
    if (nets.length == 1) return nets.first;
    return '${nets.first}  +${nets.length - 1} more';
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: generating ? null : onTap,
      child: Container(
        decoration: BoxDecoration(
          color: FColors.bgCard,
          border: Border.all(color: FColors.amber.op(0.55), width: 1.5),
          borderRadius: BorderRadius.circular(4),
          boxShadow: [
            BoxShadow(color: FColors.amber.op(0.12), blurRadius: 14),
          ],
        ),
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(14, 12, 12, 12),
              child: Row(
                children: [
                  // Icon column
                  Container(
                    width: 36, height: 36,
                    decoration: BoxDecoration(
                      border: Border.all(color: FColors.amber.op(0.4)),
                      color: FColors.amber.op(0.08),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: const Icon(Icons.work_outline, color: FColors.amber, size: 18),
                  ),
                  const SizedBox(width: 12),
                  // Text column
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(project.name,
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 13,
                            color: FColors.amber, fontWeight: FontWeight.bold)),
                        const SizedBox(height: 2),
                        Text(_targetPreview,
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 9,
                            color: FColors.textDim)),
                        const SizedBox(height: 3),
                        const Text('Hosts · Credentials · Notes · Timeline',
                          style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                            color: FColors.textDim, letterSpacing: 0.5)),
                      ],
                    ),
                  ),
                  // Action badge
                  if (generating)
                    const SizedBox(width: 18, height: 18,
                      child: CircularProgressIndicator(color: FColors.amber, strokeWidth: 1.5))
                  else
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                      decoration: BoxDecoration(
                        border: Border.all(color: FColors.amber.op(0.6)),
                        color: FColors.amber.op(0.10),
                        borderRadius: BorderRadius.circular(2),
                      ),
                      child: const Text('PROJECT REPORT',
                        style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                          color: FColors.amber, letterSpacing: 1, fontWeight: FontWeight.bold)),
                    ),
                ],
              ),
            ),
            if (generating)
              LinearProgressIndicator(
                color: FColors.amber,
                backgroundColor: FColors.bgPanel,
                minHeight: 2,
              ),
          ],
        ),
      ),
    );
  }
}

// ── Session card ─────────────────────────────────────────────────────────────

class _SessionCard extends StatelessWidget {
  final SessionInfo session;
  final bool generating;
  final VoidCallback onTap;
  const _SessionCard({required this.session, required this.generating, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final hasReport = session.hasReport;
    final color     = hasReport ? FColors.green : FColors.amber;

    return GestureDetector(
      onTap: generating ? null : onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        decoration: BoxDecoration(
          color: FColors.bgCard,
          border: Border.all(color: color.op(0.3), width: 1),
          borderRadius: BorderRadius.circular(4),
          boxShadow: [BoxShadow(color: color.op(0.06), blurRadius: 10)],
        ),
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(14, 11, 12, 11),
              child: Row(
                children: [
                  Icon(hasReport ? Icons.description_outlined : Icons.pending_outlined,
                    color: color, size: 17),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(_formatDate(session.name),
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 12,
                            color: FColors.textPrimary, fontWeight: FontWeight.bold)),
                        const SizedBox(height: 2),
                        Row(children: [
                          if (session.subdir != null) ...[
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                              decoration: BoxDecoration(
                                border: Border.all(color: FColors.amber.op(0.5), width: 0.8),
                                color: FColors.amber.op(0.07),
                                borderRadius: BorderRadius.circular(2),
                              ),
                              child: Text(session.subdir!,
                                style: const TextStyle(fontFamily: 'monospace', fontSize: 8,
                                  color: FColors.amber)),
                            ),
                            const SizedBox(width: 6),
                          ],
                          Text('${session.fileCount} result file(s)',
                            style: const TextStyle(fontFamily: 'monospace', fontSize: 9,
                              color: FColors.textDim)),
                        ]),
                      ],
                    ),
                  ),
                  if (generating)
                    const SizedBox(width: 16, height: 16,
                      child: CircularProgressIndicator(color: FColors.amber, strokeWidth: 1.5))
                  else
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                      decoration: BoxDecoration(
                        border: Border.all(color: color.op(0.5)),
                        color: color.op(0.08),
                        borderRadius: BorderRadius.circular(2),
                      ),
                      child: Text(hasReport ? 'VIEW' : 'GENERATE',
                        style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                          color: color, letterSpacing: 1)),
                    ),
                ],
              ),
            ),
            if (generating)
              LinearProgressIndicator(
                color: FColors.amber, backgroundColor: FColors.bgPanel, minHeight: 2),
          ],
        ),
      ),
    );
  }

  String _formatDate(String raw) {
    try {
      final parts = raw.split('_');
      if (parts.length == 2) return '${parts[0]}  ${parts[1].replaceAll('-', ':')}';
    } catch (_) {}
    return raw;
  }
}

class _Empty extends StatelessWidget {
  const _Empty();
  @override
  Widget build(BuildContext context) => const Center(
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(Icons.folder_off_outlined, color: FColors.textDim, size: 40),
        SizedBox(height: 12),
        Text('No scan sessions found.',
          style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 12)),
        SizedBox(height: 6),
        Text('Run some modules first.',
          style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 10)),
      ],
    ),
  );
}

// ── Report Viewer (WebView) ──────────────────────────────────────────────────

class ReportViewerScreen extends StatefulWidget {
  final String title;
  final String htmlPath;
  final String shareLabel;

  const ReportViewerScreen({
    super.key,
    required this.title,
    required this.htmlPath,
    required this.shareLabel,
  });

  @override
  State<ReportViewerScreen> createState() => _ReportViewerScreenState();
}

class _ReportViewerScreenState extends State<ReportViewerScreen> {
  late final WebViewController _controller;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setBackgroundColor(const Color(0xFF060811))
      ..setNavigationDelegate(NavigationDelegate(
        onPageFinished: (_) => setState(() => _loading = false),
        onWebResourceError: (err) {
          if (mounted) {
            setState(() => _loading = false);
            ScaffoldMessenger.of(context).showSnackBar(SnackBar(
              content: Text('Load error: ${err.description}',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
              backgroundColor: const Color(0xFF0D1117),
              duration: const Duration(seconds: 4),
            ));
          }
        },
      ))
      ..loadFile(widget.htmlPath);
  }

  Future<void> _share() async {
    await Share.shareXFiles(
      [XFile(widget.htmlPath)],
      text: widget.shareLabel,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: FColors.bg,
      appBar: _AppBar(
        title: widget.title,
        actions: [
          if (_loading)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 14, vertical: 16),
              child: SizedBox(width: 16, height: 16,
                child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5)),
            )
          else
            IconButton(
              icon: const Icon(Icons.share, color: FColors.cyan, size: 20),
              onPressed: _share,
              tooltip: 'Share report',
            ),
        ],
      ),
      body: Stack(
        children: [
          WebViewWidget(controller: _controller),
          if (_loading)
            const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5)),
        ],
      ),
    );
  }
}

// ── Shared AppBar ────────────────────────────────────────────────────────────

class _AppBar extends StatelessWidget implements PreferredSizeWidget {
  final String title;
  final List<Widget> actions;
  const _AppBar({required this.title, this.actions = const []});

  @override
  Size get preferredSize => const Size.fromHeight(kToolbarHeight + 1);

  @override
  Widget build(BuildContext context) {
    return AppBar(
      backgroundColor: FColors.bgCard,
      leading: IconButton(
        icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
        onPressed: () => Navigator.pop(context),
      ),
      title: Text(title,
        style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan,
          letterSpacing: 2, fontSize: 13),
        overflow: TextOverflow.ellipsis),
      actions: actions,
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(1),
        child: Container(height: 1, color: FColors.cyan.op(0.25)),
      ),
    );
  }
}
