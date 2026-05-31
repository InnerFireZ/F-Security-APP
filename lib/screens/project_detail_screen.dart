import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import '../models/project.dart';
import '../services/nethunter_service.dart';
import '../services/project_service.dart';
import '../theme/colors.dart';

class ProjectDetailScreen extends StatefulWidget {
  final Project project;
  const ProjectDetailScreen({super.key, required this.project});

  @override
  State<ProjectDetailScreen> createState() => _ProjectDetailScreenState();
}

class _ProjectDetailScreenState extends State<ProjectDetailScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;

  List<ProjectSession> _sessions = [];
  List<ProjectHost> _hosts = [];
  List<Credential> _creds = [];
  List<ProjectNote> _notes = [];

  bool _loading = true;
  final _noteCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 5, vsync: this);
    _load();
  }

  @override
  void dispose() {
    _tabs.dispose();
    _noteCtrl.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    final id = widget.project.id!;
    final results = await Future.wait([
      ProjectService.getSessions(id),
      ProjectService.getHosts(id),
      ProjectService.getCredentials(id),
      ProjectService.getNotes(id),
    ]);
    if (!mounted) return;
    setState(() {
      _sessions = results[0] as List<ProjectSession>;
      _hosts    = results[1] as List<ProjectHost>;
      _creds    = results[2] as List<Credential>;
      _notes    = results[3] as List<ProjectNote>;
      _loading  = false;
    });
  }

  Future<void> _addNote() async {
    final text = _noteCtrl.text.trim();
    if (text.isEmpty) return;
    await ProjectService.addNote(widget.project.id!, text);
    _noteCtrl.clear();
    if (mounted) FocusScope.of(context).unfocus();
    _load();
  }

  Future<void> _deleteNote(int id) async {
    await ProjectService.deleteNote(id);
    _load();
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
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.project.name,
              style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 13)),
            Text(widget.project.target.isEmpty ? 'no target' : widget.project.target,
              style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 9)),
          ],
        ),
        actions: [
          IconButton(icon: const Icon(Icons.refresh, color: FColors.cyan, size: 20), onPressed: _load),
        ],
        bottom: TabBar(
          controller: _tabs,
          labelStyle: const TextStyle(fontFamily: 'monospace', fontSize: 10, letterSpacing: 1),
          unselectedLabelStyle: const TextStyle(fontFamily: 'monospace', fontSize: 10),
          labelColor: FColors.cyan,
          unselectedLabelColor: FColors.textDim,
          indicatorColor: FColors.cyan,
          indicatorWeight: 1.5,
          tabs: [
            Tab(text: 'SESSIONS${_sessions.isEmpty ? "" : " (${_sessions.length})"}'),
            Tab(text: 'HOSTS${_hosts.isEmpty ? "" : " (${_hosts.length})"}'),
            Tab(text: 'CREDS${_creds.isEmpty ? "" : " (${_creds.length})"}'),
            const Tab(text: 'NOTES'),
            const Tab(text: 'IMAGES'),
          ],
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5))
          : TabBarView(
              controller: _tabs,
              children: [
                _SessionsTab(sessions: _sessions),
                _HostsTab(hosts: _hosts),
                _CredsTab(creds: _creds),
                _NotesTab(notes: _notes, ctrl: _noteCtrl, onAdd: _addNote, onDelete: _deleteNote),
                _ImagesTab(sessions: _sessions),
              ],
            ),
    );
  }
}

// ── Sessions tab ──────────────────────────────────────────────────────────────

class _SessionsTab extends StatelessWidget {
  final List<ProjectSession> sessions;
  const _SessionsTab({required this.sessions});

  void _openSession(BuildContext context, ProjectSession s) {
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => _SessionFilesScreen(session: s),
    ));
  }

  @override
  Widget build(BuildContext context) {
    if (sessions.isEmpty) return _empty('No sessions yet.\nRun a module with an active project.');
    return ListView.builder(
      padding: const EdgeInsets.all(10),
      itemCount: sessions.length,
      itemBuilder: (_, i) {
        final s = sessions[i];
        return GestureDetector(
          onTap: () => _openSession(context, s),
          child: Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: FColors.bgCard,
              border: Border.all(color: FColors.cyan.op(0.12)),
            ),
            child: Row(
              children: [
                const Icon(Icons.folder_outlined, color: FColors.cyan, size: 14),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(s.folderName,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textPrimary)),
                      if (s.moduleName != null)
                        Text(s.moduleName!,
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim)),
                    ],
                  ),
                ),
                const Icon(Icons.chevron_right, color: FColors.textDim, size: 16),
              ],
            ),
          ),
        );
      },
    );
  }
}

// ── Session files screen ───────────────────────────────────────────────────────

class _SessionFilesScreen extends StatefulWidget {
  final ProjectSession session;
  const _SessionFilesScreen({required this.session});

  @override
  State<_SessionFilesScreen> createState() => _SessionFilesScreenState();
}

class _SessionFilesScreenState extends State<_SessionFilesScreen> {
  List<String> _files = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadFiles();
  }

  Future<void> _loadFiles() async {
    final base = '${NetHunterService.chrootPath}${NetHunterService.scriptsPath}/results';
    final dir  = '$base/${widget.session.folderName}';
    final r    = await Process.run('su', ['-c', 'ls -1 "$dir" 2>/dev/null']);
    if (!mounted) return;
    setState(() {
      _files = r.stdout.toString().split('\n')
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty)
          .toList();
      _loading = false;
    });
  }

  void _viewFile(String fname) {
    final base = '${NetHunterService.chrootPath}${NetHunterService.scriptsPath}/results';
    final path = '$base/${widget.session.folderName}/$fname';
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => _FileViewScreen(path: path, name: fname),
    ));
  }

  Color _fileColor(String name) {
    if (name.endsWith('.html')) return FColors.amber;
    if (name.endsWith('.log') || name.endsWith('.txt')) return FColors.cyan;
    if (name.endsWith('.pdf')) return FColors.red;
    if (name.startsWith('.')) return FColors.textDim;
    return FColors.textSecondary;
  }

  IconData _fileIcon(String name) {
    if (name.endsWith('.html') || name.endsWith('.pdf')) return Icons.description_outlined;
    if (name.endsWith('.txt') || name.endsWith('.log')) return Icons.article_outlined;
    if (name.startsWith('.')) return Icons.check_circle_outline;
    return Icons.insert_drive_file_outlined;
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
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.session.folderName.split('/').last,
              style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 11, letterSpacing: 1)),
            if (widget.session.moduleName != null)
              Text(widget.session.moduleName!,
                style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 9)),
          ],
        ),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.2)),
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5))
          : _files.isEmpty
              ? const Center(child: Text('No files in this session.',
                  style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11)))
              : ListView.builder(
                  padding: const EdgeInsets.all(10),
                  itemCount: _files.length,
                  itemBuilder: (_, i) {
                    final f = _files[i];
                    final col  = _fileColor(f);
                    final icon = _fileIcon(f);
                    final tappable = !f.startsWith('.');
                    return GestureDetector(
                      onTap: tappable ? () => _viewFile(f) : null,
                      child: Container(
                        margin: const EdgeInsets.only(bottom: 4),
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                        decoration: BoxDecoration(
                          color: FColors.bgCard,
                          border: Border.all(color: col.op(0.15)),
                        ),
                        child: Row(children: [
                          Icon(icon, color: col, size: 14),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(f,
                              style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: col)),
                          ),
                          if (tappable)
                            const Icon(Icons.chevron_right, color: FColors.textDim, size: 14),
                        ]),
                      ),
                    );
                  },
                ),
    );
  }
}

// ── File content viewer ───────────────────────────────────────────────────────

class _FileViewScreen extends StatefulWidget {
  final String path;
  final String name;
  const _FileViewScreen({required this.path, required this.name});

  @override
  State<_FileViewScreen> createState() => _FileViewScreenState();
}

class _FileViewScreenState extends State<_FileViewScreen> {
  String _content = '';
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final r = await Process.run('su', ['-c', 'cat "${widget.path}" 2>/dev/null | head -c 200000']);
    if (!mounted) return;
    setState(() {
      _content = r.stdout.toString();
      _loading = false;
    });
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
        title: Text(widget.name,
          style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 11, letterSpacing: 1)),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.2)),
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5))
          : SingleChildScrollView(
              padding: const EdgeInsets.all(12),
              child: SelectableText(
                _content.isEmpty ? '(empty)' : _content,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textPrimary, height: 1.4),
              ),
            ),
    );
  }
}

// ── Hosts tab ─────────────────────────────────────────────────────────────────

class _HostsTab extends StatelessWidget {
  final List<ProjectHost> hosts;
  const _HostsTab({required this.hosts});

  void _showPorts(BuildContext context, ProjectHost host) {
    showModalBottomSheet(
      context: context,
      backgroundColor: FColors.bgCard,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(12))),
      builder: (_) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 14, 16, 8),
              child: Row(
                children: [
                  const Icon(Icons.computer, color: FColors.cyan, size: 16),
                  const SizedBox(width: 8),
                  Text(host.ip,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 14, color: FColors.cyan)),
                  const Spacer(),
                  Text('${host.ports.length} ports',
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
                ],
              ),
            ),
            const Divider(color: FColors.textDim, height: 1),
            Flexible(
              child: ListView.builder(
                shrinkWrap: true,
                padding: const EdgeInsets.symmetric(vertical: 8),
                itemCount: host.ports.length,
                itemBuilder: (_, i) {
                  final p = host.ports[i];
                  return Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                    child: Row(
                      children: [
                        Text('${p.number}/${p.protocol}',
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.cyan)),
                        const SizedBox(width: 12),
                        Text(p.service ?? '—',
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textDim)),
                      ],
                    ),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (hosts.isEmpty) return _empty('No hosts yet.\nRun Nmap or Fscan with an active project.');
    return ListView.builder(
      padding: const EdgeInsets.all(10),
      itemCount: hosts.length,
      itemBuilder: (_, i) {
        final h = hosts[i];
        return GestureDetector(
          onTap: () => _showPorts(context, h),
          child: Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: FColors.bgCard,
              border: Border.all(color: FColors.cyan.op(0.12)),
            ),
            child: Row(
              children: [
                const Icon(Icons.computer, color: FColors.textDim, size: 14),
                const SizedBox(width: 10),
                Text(h.ip,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: FColors.textPrimary)),
                const Spacer(),
                Text('${h.ports.length} ports',
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
                const SizedBox(width: 6),
                const Icon(Icons.chevron_right, color: FColors.textDim, size: 14),
              ],
            ),
          ),
        );
      },
    );
  }
}

// ── Credentials tab ───────────────────────────────────────────────────────────

class _CredsTab extends StatelessWidget {
  final List<Credential> creds;
  const _CredsTab({required this.creds});

  @override
  Widget build(BuildContext context) {
    if (creds.isEmpty) return _empty('No credentials yet.\nRun Brute or Hash Cracker with an active project.');
    // Split: live creds vs cracked hashes
    final live    = creds.where((c) => c.hostIp != 'cracked').toList();
    final cracked = creds.where((c) => c.hostIp == 'cracked').toList();
    final items   = [...live, ...cracked];
    return Column(
      children: [
        // Export bar
        Container(
          color: FColors.bgCard,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: Row(
            children: [
              Text('${live.length} creds  ·  ${cracked.length} cracked',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
              const Spacer(),
              TextButton.icon(
                icon: const Icon(Icons.copy_all, size: 13, color: FColors.cyan),
                label: const Text('Copy All',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.cyan)),
                style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4)),
                onPressed: () {
                  final lines = items.map((c) =>
                    '${c.hostIp != "cracked" ? "${c.hostIp}  " : ""}${c.username}:${c.password}').join('\n');
                  Clipboard.setData(ClipboardData(text: lines));
                  ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                    content: const Text('All credentials copied',
                      style: TextStyle(fontFamily: 'monospace', fontSize: 11)),
                    backgroundColor: FColors.bgCard,
                    duration: const Duration(seconds: 2),
                  ));
                },
              ),
            ],
          ),
        ),
        Expanded(child: ListView.builder(
          padding: const EdgeInsets.all(10),
      itemCount: items.length,
      itemBuilder: (_, i) {
        final c = items[i];
        final isCracked = c.hostIp == 'cracked';
        final accentColor = isCracked ? FColors.amber : FColors.green;
        return Container(
          margin: const EdgeInsets.only(bottom: 6),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            color: FColors.bgCard,
            border: Border.all(color: accentColor.op(0.25)),
          ),
          child: Row(
            children: [
              Icon(isCracked ? Icons.vpn_key : Icons.lock_open,
                  color: accentColor, size: 14),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Text(isCracked ? 'CRACKED' : c.hostIp,
                          style: TextStyle(fontFamily: 'monospace', fontSize: 10,
                            color: isCracked ? FColors.amber : FColors.textDim)),
                        if (c.service != null) ...[
                          const Text('  ·  ',
                            style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
                          Text(c.service!.toUpperCase(),
                            style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
                        ],
                      ],
                    ),
                    const SizedBox(height: 3),
                    Text('${c.username}  :  ${c.password}',
                      style: TextStyle(fontFamily: 'monospace', fontSize: 12,
                        color: accentColor, fontWeight: FontWeight.bold)),
                  ],
                ),
              ),
              IconButton(
                icon: const Icon(Icons.copy, color: FColors.textSecondary, size: 16),
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: '${c.username}:${c.password}'));
                  ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                    content: const Text('Copied', style: TextStyle(fontFamily: 'monospace', fontSize: 11)),
                    backgroundColor: FColors.bgCard,
                    duration: const Duration(seconds: 1),
                  ));
                },
              ),
            ],
          ),
        );
      },
        )),
      ],
    );
  }
}

// ── Notes tab ─────────────────────────────────────────────────────────────────

class _NotesTab extends StatelessWidget {
  final List<ProjectNote> notes;
  final TextEditingController ctrl;
  final VoidCallback onAdd;
  final void Function(int) onDelete;
  const _NotesTab({required this.notes, required this.ctrl, required this.onAdd, required this.onDelete});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Input row
        Container(
          padding: const EdgeInsets.fromLTRB(12, 8, 8, 8),
          color: FColors.bgPanel,
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: ctrl,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textPrimary),
                  maxLines: null,
                  decoration: const InputDecoration(
                    hintText: 'Add a note...',
                    hintStyle: TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textDim),
                    border: InputBorder.none,
                    isDense: true,
                  ),
                ),
              ),
              IconButton(
                icon: const Icon(Icons.send, color: FColors.cyan, size: 18),
                onPressed: onAdd,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
              ),
            ],
          ),
        ),
        Container(height: 1, color: FColors.cyan.op(0.15)),
        // Notes list
        Expanded(
          child: notes.isEmpty
              ? _empty('No notes yet.')
              : ListView.builder(
                  padding: const EdgeInsets.all(10),
                  itemCount: notes.length,
                  itemBuilder: (_, i) {
                    final n = notes[i];
                    final ts = '${n.created.day.toString().padLeft(2,'0')}/'
                        '${n.created.month.toString().padLeft(2,'0')} '
                        '${n.created.hour.toString().padLeft(2,'0')}:'
                        '${n.created.minute.toString().padLeft(2,'0')}';
                    return Container(
                      margin: const EdgeInsets.only(bottom: 6),
                      padding: const EdgeInsets.fromLTRB(12, 8, 6, 8),
                      decoration: BoxDecoration(
                        color: FColors.bgCard,
                        border: Border.all(color: FColors.cyan.op(0.1)),
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(ts,
                                  style: const TextStyle(fontFamily: 'monospace', fontSize: 8, color: FColors.textDim)),
                                const SizedBox(height: 4),
                                Text(n.content,
                                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textPrimary)),
                              ],
                            ),
                          ),
                          IconButton(
                            icon: const Icon(Icons.delete_outline, color: FColors.textDim, size: 16),
                            padding: EdgeInsets.zero,
                            constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                            onPressed: () => onDelete(n.id!),
                          ),
                        ],
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }
}

Widget _empty(String msg) => Center(
  child: Text(msg,
    textAlign: TextAlign.center,
    style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 12, height: 1.8)),
);

// ── Images tab ────────────────────────────────────────────────────────────────

class _ScreenshotInfo {
  final String androidPath; // Android-absolute path (for su cat)
  final String sessionFolder;

  _ScreenshotInfo({required this.androidPath, required this.sessionFolder});

  String get label => androidPath.split('/').last;

  // "192.168.1.1_80.png" → "192.168.1.1 : 80"
  String get displayLabel {
    var n = label.replaceAll('.png', '').replaceAll('.jpg', '').replaceAll('.jpeg', '');
    final last = n.lastIndexOf('_');
    if (last != -1) n = '${n.substring(0, last)} : ${n.substring(last + 1)}';
    return n;
  }
}

class _ImagesTab extends StatefulWidget {
  final List<ProjectSession> sessions;
  const _ImagesTab({required this.sessions});

  @override
  State<_ImagesTab> createState() => _ImagesTabState();
}

class _ImagesTabState extends State<_ImagesTab> {
  List<_ScreenshotInfo> _shots = [];
  bool _loading = true;

  static String get _resultsBase =>
      '${NetHunterService.chrootPath}${NetHunterService.scriptsPath}/results';

  @override
  void initState() {
    super.initState();
    _findShots();
  }

  Future<void> _findShots() async {
    setState(() => _loading = true);
    final shots = <_ScreenshotInfo>[];
    for (final s in widget.sessions) {
      final dir = '$_resultsBase/${s.folderName}/screenshots';
      final r = await Process.run('su', ['-c',
        'find "$dir" -maxdepth 1 \\( -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" \\) 2>/dev/null | sort',
      ]);
      for (final path in r.stdout.toString().trim().split('\n').where((l) => l.isNotEmpty)) {
        shots.add(_ScreenshotInfo(androidPath: path, sessionFolder: s.folderName));
      }
    }
    if (mounted) setState(() { _shots = shots; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5));
    }
    if (_shots.isEmpty) {
      return _empty('No screenshots yet.\nRun IoT Scan in Full mode\nwith an active project.');
    }
    return RefreshIndicator(
      color: FColors.cyan,
      backgroundColor: FColors.bgCard,
      onRefresh: _findShots,
      child: GridView.builder(
        padding: const EdgeInsets.all(8),
        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: 2,
          crossAxisSpacing: 6,
          mainAxisSpacing: 6,
          childAspectRatio: 16 / 10,
        ),
        itemCount: _shots.length,
        itemBuilder: (_, i) => _ImageTile(shot: _shots[i]),
      ),
    );
  }
}

class _ImageTile extends StatefulWidget {
  final _ScreenshotInfo shot;
  const _ImageTile({required this.shot});

  @override
  State<_ImageTile> createState() => _ImageTileState();
}

class _ImageTileState extends State<_ImageTile> {
  File? _file;
  bool _error = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final tmp  = await getTemporaryDirectory();
      final safe = widget.shot.sessionFolder.replaceAll('/', '_');
      final dest = File('${tmp.path}/fsec_shot_${safe}_${widget.shot.label}');
      if (!await dest.exists()) {
        final r = await Process.run('su',
          ['-c', 'cat "${widget.shot.androidPath}" 2>/dev/null'],
          stdoutEncoding: null,
        );
        final bytes = r.stdout as List<int>;
        if (bytes.isEmpty) throw Exception('empty');
        await dest.writeAsBytes(bytes);
      }
      if (mounted) setState(() => _file = dest);
    } catch (_) {
      if (mounted) setState(() => _error = true);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_error) {
      return Container(
        color: FColors.bgCard,
        child: const Center(child: Icon(Icons.broken_image_outlined, color: FColors.textDim, size: 24)),
      );
    }
    if (_file == null) {
      return Container(
        color: FColors.bgCard,
        child: const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1)),
      );
    }
    return GestureDetector(
      onTap: () => Navigator.push(context, MaterialPageRoute(
        builder: (_) => _FullscreenImageScreen(file: _file!, label: widget.shot.displayLabel),
      )),
      child: Container(
        decoration: BoxDecoration(
          color: FColors.bgCard,
          border: Border.all(color: FColors.cyan.op(0.15)),
        ),
        child: Stack(
          fit: StackFit.expand,
          children: [
            Image.file(_file!, fit: BoxFit.cover),
            Positioned(
              bottom: 0, left: 0, right: 0,
              child: Container(
                color: Colors.black54,
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                child: Text(
                  widget.shot.displayLabel,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 8, color: Colors.white),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _FullscreenImageScreen extends StatelessWidget {
  final File file;
  final String label;
  const _FullscreenImageScreen({required this.file, required this.label});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: FColors.bgCard,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(label,
          style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 12)),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: Center(
        child: InteractiveViewer(
          minScale: 0.5,
          maxScale: 5.0,
          child: Image.file(file),
        ),
      ),
    );
  }
}
