import 'package:flutter/material.dart';
import '../models/project.dart';
import '../services/project_service.dart';
import '../theme/colors.dart';
import 'project_detail_screen.dart';

class ProjectScreen extends StatefulWidget {
  const ProjectScreen({super.key});
  @override
  State<ProjectScreen> createState() => _ProjectScreenState();
}

class _ProjectScreenState extends State<ProjectScreen> {
  List<Project> _projects = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    if (!mounted) return;
    setState(() => _loading = true);
    final projects = await ProjectService.listProjects();
    if (mounted) setState(() { _projects = projects; _loading = false; });
  }

  Future<void> _setActive(Project p) async {
    await ProjectService.setActiveProject(p.id!);
    if (mounted) Navigator.pop(context, true); // signal dashboard to refresh
  }

  Future<void> _clearActive() async {
    await ProjectService.clearActiveProject();
    if (mounted) Navigator.pop(context, true);
  }

  Future<void> _delete(Project p) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: FColors.bgCard,
        title: const Text('Delete project?',
          style: TextStyle(fontFamily: 'monospace', color: FColors.red, fontSize: 13)),
        content: Text('${p.name}\n\nThis removes all sessions, hosts, credentials and notes.',
          style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel', style: TextStyle(color: FColors.textSecondary, fontFamily: 'monospace'))),
          TextButton(onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete', style: TextStyle(color: FColors.red, fontFamily: 'monospace'))),
        ],
      ),
    );
    if (ok != true) return;
    await ProjectService.deleteProject(p.id!);
    _load();
  }

  Future<void> _create() async {
    final result = await showDialog<_NewProjectResult>(
      context: context,
      builder: (_) => const _CreateProjectDialog(),
    );
    if (result == null || result.name.isEmpty) return;
    await ProjectService.createProject(result.name, result.networks.join(', '));
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
        title: const Text('PROJECTS',
          style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, letterSpacing: 3, fontSize: 13)),
        actions: [
          if (_projects.any((p) => p.isActive))
            IconButton(
              icon: const Icon(Icons.cancel_outlined, color: FColors.textDim, size: 20),
              tooltip: 'Clear active project',
              onPressed: _clearActive,
            ),
          IconButton(
            icon: const Icon(Icons.add, color: FColors.cyan, size: 22),
            tooltip: 'New project',
            onPressed: _create,
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5))
          : _projects.isEmpty
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.folder_off_outlined, color: FColors.textDim, size: 36),
                      const SizedBox(height: 12),
                      const Text('No projects yet.',
                        style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 12)),
                      const SizedBox(height: 8),
                      GestureDetector(
                        onTap: _create,
                        child: const Text('+ Create one',
                          style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 12)),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  padding: const EdgeInsets.all(10),
                  itemCount: _projects.length,
                  itemBuilder: (_, i) => _ProjectTile(
                    project: _projects[i],
                    onActivate: () => _setActive(_projects[i]),
                    onDelete: () => _delete(_projects[i]),
                    onDetail: () => Navigator.push(context, MaterialPageRoute(
                      builder: (_) => ProjectDetailScreen(project: _projects[i]),
                    )).then((_) => _load()),
                  ),
                ),
    );
  }
}


class _ProjectTile extends StatelessWidget {
  final Project project;
  final VoidCallback onActivate;
  final VoidCallback onDelete;
  final VoidCallback onDetail;
  const _ProjectTile({required this.project, required this.onActivate, required this.onDelete, required this.onDetail});

  static Widget _subTab(IconData icon, String label) => Padding(
    padding: const EdgeInsets.only(right: 8),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 9, color: FColors.textDim),
        const SizedBox(width: 2),
        Text(label,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 8, color: FColors.textDim, letterSpacing: 0.3)),
      ],
    ),
  );

  @override
  Widget build(BuildContext context) {
    final active = project.isActive;
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: FColors.bgCard,
        border: Border.all(
          color: active ? FColors.amber.op(0.7) : FColors.cyan.op(0.15),
          width: active ? 1.2 : 1,
        ),
        boxShadow: active
            ? [BoxShadow(color: FColors.amber.op(0.08), blurRadius: 10)]
            : null,
      ),
      child: Column(
        children: [
          ListTile(
            dense: true,
            contentPadding: const EdgeInsets.fromLTRB(12, 4, 6, 4),
            leading: Icon(
              active ? Icons.folder_open : Icons.folder_outlined,
              color: active ? FColors.amber : FColors.textSecondary,
              size: 20,
            ),
            title: Row(
              children: [
                Expanded(
                  child: Text(project.name,
                    style: TextStyle(
                      fontFamily: 'monospace', fontSize: 12, fontWeight: FontWeight.bold,
                      color: active ? FColors.amber : FColors.textPrimary,
                    )),
                ),
                if (active)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                    decoration: BoxDecoration(
                      color: FColors.amber.op(0.15),
                      border: Border.all(color: FColors.amber.op(0.5)),
                      borderRadius: BorderRadius.circular(2),
                    ),
                    child: const Text('ACTIVE',
                      style: TextStyle(fontFamily: 'monospace', fontSize: 7, color: FColors.amber)),
                  ),
              ],
            ),
            subtitle: Text(
              '${project.target.isEmpty ? "no target" : project.target}  ·  ${project.sessionCount} session${project.sessionCount == 1 ? "" : "s"}',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim),
            ),
            trailing: IconButton(
              icon: const Icon(Icons.delete_outline, size: 18, color: FColors.red),
              tooltip: 'Delete',
              onPressed: onDelete,
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            ),
          ),
          // ── Details bar ───────────────────────────────────────────────────
          GestureDetector(
            onTap: onDetail,
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.fromLTRB(12, 6, 12, 6),
              decoration: BoxDecoration(
                border: Border(top: BorderSide(color: FColors.cyan.op(0.18))),
                color: FColors.cyan.op(0.05),
              ),
              child: Row(
                children: [
                  _subTab(Icons.terminal, 'SESSIONS'),
                  _subTab(Icons.dns_outlined, 'HOSTS'),
                  _subTab(Icons.key_outlined, 'CREDS'),
                  _subTab(Icons.sticky_note_2_outlined, 'NOTES'),
                  _subTab(Icons.image_outlined, 'IMAGES'),
                  const Spacer(),
                  const Text('DETAILS',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                      color: FColors.cyan, letterSpacing: 1)),
                  const SizedBox(width: 2),
                  const Icon(Icons.chevron_right, size: 14, color: FColors.cyan),
                ],
              ),
            ),
          ),
          if (!active)
            GestureDetector(
              onTap: onActivate,
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(vertical: 5),
                decoration: BoxDecoration(
                  border: Border(top: BorderSide(color: FColors.cyan.op(0.1))),
                  color: FColors.cyan.op(0.04),
                ),
                child: const Center(
                  child: Text('SET AS ACTIVE',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.cyan, letterSpacing: 1)),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

// ── New project dialog ────────────────────────────────────────────────────────

class _NewProjectResult {
  final String name;
  final List<String> networks;
  const _NewProjectResult({required this.name, required this.networks});
}

class _CreateProjectDialog extends StatefulWidget {
  const _CreateProjectDialog();
  @override
  State<_CreateProjectDialog> createState() => _CreateProjectDialogState();
}

class _CreateProjectDialogState extends State<_CreateProjectDialog> {
  final _nameCtrl   = TextEditingController();
  final _manualCtrl = TextEditingController();

  // Detected: list of {iface, cidr}
  List<Map<String, String>> _detected = [];
  bool _detecting = true;

  // Selected networks (from detected or manually added)
  final List<String> _selected = [];

  @override
  void initState() {
    super.initState();
    _detect();
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _manualCtrl.dispose();
    super.dispose();
  }

  Future<void> _detect() async {
    setState(() => _detecting = true);
    final nets = await ProjectService.detectNetworks();
    if (!mounted) return;
    setState(() {
      _detected  = nets;
      _detecting = false;
      // Auto-select if exactly one network found
      if (nets.length == 1) _selected.add(nets.first['cidr']!);
    });
  }

  void _toggleDetected(String cidr) {
    setState(() {
      if (_selected.contains(cidr)) {
        _selected.remove(cidr);
      } else {
        _selected.add(cidr);
      }
    });
  }

  void _addManual() {
    final raw = _manualCtrl.text.trim();
    if (raw.isEmpty) return;
    // Accept plain IP → append /24
    var cidr = raw;
    if (!cidr.contains('/')) cidr = '$cidr/24';
    if (!_selected.contains(cidr)) {
      setState(() => _selected.add(cidr));
    }
    _manualCtrl.clear();
  }

  void _removeSelected(String cidr) {
    setState(() => _selected.remove(cidr));
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: FColors.bgCard,
      titlePadding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      contentPadding: const EdgeInsets.fromLTRB(16, 0, 16, 0),
      actionsPadding: const EdgeInsets.fromLTRB(8, 0, 8, 8),
      title: const Text('NEW PROJECT',
        style: TextStyle(fontFamily: 'monospace', color: FColors.cyan,
          fontSize: 13, letterSpacing: 2)),
      content: SizedBox(
        width: double.maxFinite,
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              // ── Name field ──────────────────────────────────────────────
              TextField(
                controller: _nameCtrl,
                autofocus: true,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: FColors.textPrimary),
                decoration: const InputDecoration(
                  labelText: 'Project name',
                  hintText: 'e.g. Client LAN audit',
                  labelStyle: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim),
                  hintStyle: TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textDim),
                  enabledBorder: UnderlineInputBorder(borderSide: BorderSide(color: FColors.textDim)),
                  focusedBorder: UnderlineInputBorder(borderSide: BorderSide(color: FColors.cyan)),
                ),
              ),
              const SizedBox(height: 16),

              // ── Detected networks ───────────────────────────────────────
              const Text('DETECTED NETWORKS',
                style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                  color: FColors.textDim, letterSpacing: 1)),
              const SizedBox(height: 6),
              if (_detecting)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 6),
                  child: SizedBox(height: 14, width: 14,
                    child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5)),
                )
              else if (_detected.isEmpty)
                const Text('No wlan/eth interfaces found',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim))
              else
                Wrap(
                  spacing: 6,
                  runSpacing: 6,
                  children: _detected.map((n) {
                    final cidr  = n['cidr']!;
                    final iface = n['iface']!;
                    final sel   = _selected.contains(cidr);
                    return GestureDetector(
                      onTap: () => _toggleDetected(cidr),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
                        decoration: BoxDecoration(
                          color: sel ? FColors.cyan.op(0.15) : FColors.bg,
                          border: Border.all(
                            color: sel ? FColors.cyan : FColors.textDim.op(0.4)),
                          borderRadius: BorderRadius.circular(3),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(iface,
                              style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                                color: sel ? FColors.cyan : FColors.textDim)),
                            const Text('  ',
                              style: TextStyle(fontFamily: 'monospace', fontSize: 9)),
                            Text(cidr,
                              style: TextStyle(fontFamily: 'monospace', fontSize: 10,
                                color: sel ? FColors.cyan : FColors.textPrimary,
                                fontWeight: sel ? FontWeight.bold : FontWeight.normal)),
                            const SizedBox(width: 4),
                            Icon(sel ? Icons.check : Icons.add,
                              size: 12,
                              color: sel ? FColors.cyan : FColors.textDim),
                          ],
                        ),
                      ),
                    );
                  }).toList(),
                ),

              const SizedBox(height: 12),

              // ── Manual entry ────────────────────────────────────────────
              const Text('ADD MANUALLY',
                style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                  color: FColors.textDim, letterSpacing: 1)),
              const SizedBox(height: 4),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _manualCtrl,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textPrimary),
                      decoration: const InputDecoration(
                        hintText: '192.168.2.0/24  or  10.0.0.1',
                        hintStyle: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim),
                        enabledBorder: UnderlineInputBorder(borderSide: BorderSide(color: FColors.textDim)),
                        focusedBorder: UnderlineInputBorder(borderSide: BorderSide(color: FColors.cyan)),
                        isDense: true,
                      ),
                      onSubmitted: (_) => _addManual(),
                    ),
                  ),
                  const SizedBox(width: 8),
                  GestureDetector(
                    onTap: _addManual,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                      decoration: BoxDecoration(
                        color: FColors.cyan.op(0.1),
                        border: Border.all(color: FColors.cyan.op(0.5)),
                        borderRadius: BorderRadius.circular(3),
                      ),
                      child: const Text('ADD',
                        style: TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.cyan)),
                    ),
                  ),
                ],
              ),

              // ── Selected networks list ──────────────────────────────────
              if (_selected.isNotEmpty) ...[
                const SizedBox(height: 12),
                const Text('SELECTED',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 9,
                    color: FColors.textDim, letterSpacing: 1)),
                const SizedBox(height: 6),
                Wrap(
                  spacing: 6,
                  runSpacing: 6,
                  children: _selected.map((cidr) => Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: FColors.green.op(0.1),
                      border: Border.all(color: FColors.green.op(0.4)),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(cidr,
                          style: const TextStyle(fontFamily: 'monospace',
                            fontSize: 10, color: FColors.green)),
                        const SizedBox(width: 6),
                        GestureDetector(
                          onTap: () => _removeSelected(cidr),
                          child: const Icon(Icons.close, size: 12, color: FColors.textDim),
                        ),
                      ],
                    ),
                  )).toList(),
                ),
              ],
              const SizedBox(height: 8),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel',
            style: TextStyle(color: FColors.textSecondary, fontFamily: 'monospace')),
        ),
        TextButton(
          onPressed: () {
            final name = _nameCtrl.text.trim();
            if (name.isEmpty) return;
            Navigator.pop(context, _NewProjectResult(name: name, networks: List.from(_selected)));
          },
          child: const Text('CREATE',
            style: TextStyle(color: FColors.cyan, fontFamily: 'monospace', fontWeight: FontWeight.bold)),
        ),
      ],
    );
  }
}
