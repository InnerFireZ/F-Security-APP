import 'package:flutter/material.dart';
import '../data/modules.dart';
import '../data/pipelines.dart';
import '../models/module.dart';
import '../models/pipeline.dart';
import '../models/project.dart';
import '../services/project_service.dart';
import '../theme/colors.dart';
import 'pipeline_run_screen.dart';

class PipelineScreen extends StatefulWidget {
  const PipelineScreen({super.key});

  @override
  State<PipelineScreen> createState() => _PipelineScreenState();
}

class _PipelineScreenState extends State<PipelineScreen> {
  final _nameCtrl     = TextEditingController(text: 'My Pipeline');
  final _targetCtrl   = TextEditingController();
  final _domainCtrl   = TextEditingController();
  final _karmaSsidCtrl = TextEditingController();
  final _karmaPassCtrl = TextEditingController();
  final List<PipelineStep> _steps = [];
  bool   _karmaEnabled = false;
  String _karmaMode    = 'wpa'; // 'wpa' | 'opn' | 'eap'

  List<Project> _projects = [];
  Project? _selectedProject;

  @override
  void initState() {
    super.initState();
    _loadProjects();
  }

  Future<void> _loadProjects() async {
    final projects = await ProjectService.listProjects();
    final active   = await ProjectService.getActiveProject();
    if (!mounted) return;
    setState(() {
      _projects = projects;
      if (active != null) {
        _selectedProject = active;
        _prefillTarget(active);
      }
    });
  }

  void _prefillTarget(Project p) {
    if (_targetCtrl.text.isNotEmpty) return;
    final nets = p.target.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    if (nets.isNotEmpty) _targetCtrl.text = nets.first;
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _targetCtrl.dispose();
    _domainCtrl.dispose();
    _karmaSsidCtrl.dispose();
    _karmaPassCtrl.dispose();
    super.dispose();
  }

  void _addModule(Module m) {
    setState(() => _steps.add(PipelineStep(module: m)));
    Navigator.pop(context);
  }

  void _removeStep(int idx) => setState(() => _steps.removeAt(idx));

  void _runPipeline() {
    if (_steps.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text('Add at least one module', style: TextStyle(fontFamily: 'monospace', fontSize: 11)),
        backgroundColor: Color(0xFF0D1117),
        duration: Duration(seconds: 2),
      ));
      return;
    }
    final pipeline = Pipeline(
      name: _nameCtrl.text.trim().isEmpty ? 'Pipeline' : _nameCtrl.text.trim(),
      steps: List.from(_steps),
      target: _targetCtrl.text.trim(),
      domain: _domainCtrl.text.trim(),
      projectId:    _selectedProject?.id,
      projectName:  _selectedProject?.name,
      karmaEnabled: _karmaEnabled,
      karmaMode:    _karmaMode,
      karmaSsid:    _karmaSsidCtrl.text.trim(),
      karmaPass:    _karmaPassCtrl.text.trim(),
    );
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => PipelineRunScreen(pipeline: pipeline),
    ));
  }

  void _showTemplatePicker() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      clipBehavior: Clip.antiAlias,
      backgroundColor: FColors.bgPanel,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(6)),
      ),
      builder: (_) => _TemplatePickerSheet(
        onLoad: (tpl) {
          Navigator.pop(context);
          if (_steps.isNotEmpty) {
            showDialog(
              context: context,
              builder: (_) => AlertDialog(
                backgroundColor: FColors.bgCard,
                title: Text(tpl.name,
                  style: const TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 13)),
                content: Text(
                  'Replace current ${_steps.length} step(s) with this template?',
                  style: const TextStyle(fontFamily: 'monospace', color: FColors.textSecondary, fontSize: 11)),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('CANCEL', style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11)),
                  ),
                  TextButton(
                    onPressed: () {
                      Navigator.pop(context);
                      _loadTemplate(tpl);
                    },
                    child: const Text('LOAD', style: TextStyle(fontFamily: 'monospace', color: FColors.amber, fontSize: 11)),
                  ),
                ],
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(4),
                  side: BorderSide(color: FColors.amber.op(0.4)),
                ),
              ),
            );
          } else {
            _loadTemplate(tpl);
          }
        },
      ),
    );
  }

  void _loadTemplate(PipelineTemplate tpl) {
    setState(() {
      _nameCtrl.text = tpl.name;
      _steps.clear();
      _steps.addAll(tpl.buildSteps());
    });
  }

  void _showModulePicker() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      clipBehavior: Clip.antiAlias,
      backgroundColor: FColors.bgPanel,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(6)),
      ),
      builder: (_) => _ModulePickerSheet(onAdd: _addModule),
    );
  }

  void _showProjectPicker() {
    showModalBottomSheet(
      context: context,
      backgroundColor: FColors.bgPanel,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(6)),
      ),
      builder: (_) => _ProjectPickerSheet(
        projects: _projects,
        selected: _selectedProject,
        onSelect: (p) {
          Navigator.pop(context);
          setState(() {
            _selectedProject = p;
            if (p != null) {
              final nets = p.target.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
              if (nets.isNotEmpty) _targetCtrl.text = nets.first;
            }
          });
        },
      ),
    );
  }

  Color _chainColor(ChainOutput out) => switch (out) {
    ChainOutput.sessionDir   => FColors.cyan,
    ChainOutput.credentials  => FColors.amber,
    ChainOutput.hashes       => FColors.red,
    ChainOutput.none         => FColors.textDim,
  };

  String _chainLabel(ChainOutput out) => switch (out) {
    ChainOutput.sessionDir   => 'RESULTS',
    ChainOutput.credentials  => 'CREDS',
    ChainOutput.hashes       => 'HASHES',
    ChainOutput.none         => '',
  };

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
        title: const Text('PIPELINE BUILDER',
          style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, fontSize: 13, letterSpacing: 2)),
        actions: [
          IconButton(
            icon: const Icon(Icons.auto_awesome_mosaic_outlined, color: FColors.amber, size: 20),
            tooltip: 'Load Template',
            onPressed: _showTemplatePicker,
          ),
          IconButton(
            icon: const Icon(Icons.play_arrow_rounded, color: FColors.green, size: 26),
            tooltip: 'Run Pipeline',
            onPressed: _runPipeline,
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: Column(
        children: [
          // ── Config section ──────────────────────────────────────────────
          Container(
            color: FColors.bgCard,
            padding: const EdgeInsets.fromLTRB(14, 10, 14, 10),
            child: Column(
              children: [
                // Pipeline name
                _FieldRow(
                  label: 'NAME',
                  child: TextField(
                    controller: _nameCtrl,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textPrimary),
                    decoration: const InputDecoration(
                      border: InputBorder.none, isDense: true,
                      hintText: 'Pipeline name',
                      hintStyle: TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textDim),
                    ),
                  ),
                ),
                const SizedBox(height: 6),
                // Project picker
                _FieldRow(
                  label: 'PROJECT',
                  child: GestureDetector(
                    onTap: _showProjectPicker,
                    child: Row(children: [
                      Icon(Icons.work_outline,
                        color: _selectedProject != null ? FColors.amber : FColors.textDim,
                        size: 13),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          _selectedProject?.name ?? 'None  (tap to link a project)',
                          style: TextStyle(
                            fontFamily: 'monospace', fontSize: 11,
                            color: _selectedProject != null ? FColors.amber : FColors.textDim,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const Icon(Icons.chevron_right, color: FColors.textDim, size: 14),
                    ]),
                  ),
                ),
                // Show project networks as chips if project has multiple
                if (_selectedProject != null && _selectedProject!.target.contains(',')) ...[
                  const SizedBox(height: 6),
                  _NetworkChips(
                    target: _selectedProject!.target,
                    selected: _targetCtrl.text,
                    onSelect: (net) => setState(() => _targetCtrl.text = net),
                  ),
                ],
                const SizedBox(height: 6),
                // Target
                _FieldRow(
                  label: 'TARGET',
                  child: TextField(
                    controller: _targetCtrl,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.green),
                    decoration: const InputDecoration(
                      border: InputBorder.none, isDense: true,
                      hintText: '192.168.1.0/24  (passed as \$TARGET)',
                      hintStyle: TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textDim),
                    ),
                  ),
                ),
                const SizedBox(height: 4),
                // Domain (optional — for AD/SMB pipelines)
                _FieldRow(
                  label: 'DOMAIN',
                  child: TextField(
                    controller: _domainCtrl,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.cyan),
                    decoration: const InputDecoration(
                      border: InputBorder.none, isDense: true,
                      hintText: 'corp.local  (optional — AD/SMB pipelines)',
                      hintStyle: TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textDim),
                    ),
                  ),
                ),
                const SizedBox(height: 6),
                // KARMA mode toggle
                GestureDetector(
                  onTap: () => setState(() => _karmaEnabled = !_karmaEnabled),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 7),
                    decoration: BoxDecoration(
                      color: _karmaEnabled ? FColors.red.op(0.08) : Colors.transparent,
                      border: Border.all(
                        color: _karmaEnabled ? FColors.red.op(0.5) : FColors.textDim.op(0.2),
                        width: 0.8,
                      ),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Row(children: [
                      Icon(Icons.wifi_tethering,
                        color: _karmaEnabled ? FColors.red : FColors.textDim, size: 13),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                          Text('KARMA MODE',
                            style: TextStyle(
                              fontFamily: 'monospace', fontSize: 10,
                              color: _karmaEnabled ? FColors.red : FColors.textDim,
                              fontWeight: FontWeight.bold, letterSpacing: 1,
                            )),
                          Text(
                            _karmaEnabled
                                ? 'Rogue AP starts first — pipeline runs against each connected client'
                                : 'Enable to use evil-twin AP as pipeline entry point (requires wlan1)',
                            style: const TextStyle(
                              fontFamily: 'monospace', fontSize: 8, color: FColors.textDim),
                          ),
                        ]),
                      ),
                      const SizedBox(width: 6),
                      Container(
                        width: 28, height: 16,
                        decoration: BoxDecoration(
                          color: _karmaEnabled ? FColors.red.op(0.7) : FColors.bgPanel,
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: FColors.textDim.op(0.3), width: 0.5),
                        ),
                        child: AnimatedAlign(
                          duration: const Duration(milliseconds: 180),
                          alignment: _karmaEnabled ? Alignment.centerRight : Alignment.centerLeft,
                          child: Container(
                            width: 12, height: 12,
                            margin: const EdgeInsets.symmetric(horizontal: 2),
                            decoration: BoxDecoration(
                              color: _karmaEnabled ? Colors.white : FColors.textDim,
                              shape: BoxShape.circle,
                            ),
                          ),
                        ),
                      ),
                    ]),
                  ),
                ),
                // KARMA config panel — visible only when KARMA is enabled
                AnimatedCrossFade(
                  duration: const Duration(milliseconds: 200),
                  crossFadeState: _karmaEnabled
                      ? CrossFadeState.showSecond
                      : CrossFadeState.showFirst,
                  firstChild: const SizedBox.shrink(),
                  secondChild: Container(
                    margin: const EdgeInsets.only(top: 8),
                    padding: const EdgeInsets.fromLTRB(10, 10, 10, 10),
                    decoration: BoxDecoration(
                      color: FColors.red.op(0.04),
                      border: Border.all(color: FColors.red.op(0.25), width: 0.7),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      // Mode selector
                      const Text('ENCRYPTION',
                        style: TextStyle(fontFamily: 'monospace', fontSize: 8,
                          color: FColors.textDim, letterSpacing: 1)),
                      const SizedBox(height: 6),
                      Row(children: [
                        for (final entry in [
                          ('wpa', 'WPA'),
                          ('opn', 'OPEN'),
                          ('eap', 'EAP'),
                        ]) ...[
                          if (entry.$1 != 'wpa') const SizedBox(width: 6),
                          Expanded(
                            child: GestureDetector(
                              onTap: () => setState(() => _karmaMode = entry.$1),
                              child: Container(
                                padding: const EdgeInsets.symmetric(vertical: 7),
                                decoration: BoxDecoration(
                                  color: _karmaMode == entry.$1
                                      ? FColors.red.op(0.18)
                                      : FColors.bgPanel,
                                  border: Border.all(
                                    color: _karmaMode == entry.$1
                                        ? FColors.red.op(0.7)
                                        : FColors.textDim.op(0.2),
                                    width: _karmaMode == entry.$1 ? 1.0 : 0.6,
                                  ),
                                  borderRadius: BorderRadius.circular(3),
                                ),
                                alignment: Alignment.center,
                                child: Text(entry.$2,
                                  style: TextStyle(
                                    fontFamily: 'monospace', fontSize: 9,
                                    color: _karmaMode == entry.$1
                                        ? FColors.red
                                        : FColors.textDim,
                                    fontWeight: _karmaMode == entry.$1
                                        ? FontWeight.bold
                                        : FontWeight.normal,
                                    letterSpacing: 0.5,
                                  )),
                              ),
                            ),
                          ),
                        ],
                      ]),
                      const SizedBox(height: 10),
                      // SSID field
                      const Text('SSID',
                        style: TextStyle(fontFamily: 'monospace', fontSize: 8,
                          color: FColors.textDim, letterSpacing: 1)),
                      const SizedBox(height: 4),
                      TextField(
                        controller: _karmaSsidCtrl,
                        style: const TextStyle(
                          fontFamily: 'monospace', fontSize: 11, color: FColors.amber),
                        decoration: InputDecoration(
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(3),
                            borderSide: BorderSide(color: FColors.textDim.op(0.3), width: 0.7),
                          ),
                          enabledBorder: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(3),
                            borderSide: BorderSide(color: FColors.textDim.op(0.3), width: 0.7),
                          ),
                          focusedBorder: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(3),
                            borderSide: BorderSide(color: FColors.amber.op(0.6), width: 1.0),
                          ),
                          isDense: true,
                          contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                          hintText: 'auto-mirror probed SSIDs (leave blank for KARMA)',
                          hintStyle: const TextStyle(
                            fontFamily: 'monospace', fontSize: 9, color: FColors.textDim),
                          suffixIcon: _karmaSsidCtrl.text.isNotEmpty
                              ? IconButton(
                                  icon: const Icon(Icons.clear, size: 14, color: FColors.textDim),
                                  padding: EdgeInsets.zero,
                                  onPressed: () => setState(() => _karmaSsidCtrl.clear()),
                                )
                              : null,
                        ),
                        onChanged: (_) => setState(() {}),
                      ),
                      if (_karmaSsidCtrl.text.isNotEmpty) ...[
                        const SizedBox(height: 4),
                        Text('AP will broadcast as  "${_karmaSsidCtrl.text}"  immediately',
                          style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 8, color: FColors.amber)),
                      ] else ...[
                        const SizedBox(height: 4),
                        const Text('AP name auto-copied from victim\'s probe requests',
                          style: TextStyle(
                            fontFamily: 'monospace', fontSize: 8, color: FColors.textDim)),
                      ],
                      // Password field — WPA only
                      if (_karmaMode == 'wpa') ...[
                        const SizedBox(height: 10),
                        const Text('PASSWORD',
                          style: TextStyle(fontFamily: 'monospace', fontSize: 8,
                            color: FColors.textDim, letterSpacing: 1)),
                        const SizedBox(height: 4),
                        TextField(
                          controller: _karmaPassCtrl,
                          obscureText: false,
                          style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 11, color: FColors.red),
                          decoration: InputDecoration(
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(3),
                              borderSide: BorderSide(color: FColors.textDim.op(0.3), width: 0.7),
                            ),
                            enabledBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(3),
                              borderSide: BorderSide(color: FColors.textDim.op(0.3), width: 0.7),
                            ),
                            focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(3),
                              borderSide: BorderSide(color: FColors.red.op(0.6), width: 1.0),
                            ),
                            isDense: true,
                            contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                            hintText: 'auto-generated (leave blank)',
                            hintStyle: const TextStyle(
                              fontFamily: 'monospace', fontSize: 9, color: FColors.textDim),
                            suffixIcon: _karmaPassCtrl.text.isNotEmpty
                                ? IconButton(
                                    icon: const Icon(Icons.clear, size: 14, color: FColors.textDim),
                                    padding: EdgeInsets.zero,
                                    onPressed: () => setState(() => _karmaPassCtrl.clear()),
                                  )
                                : null,
                          ),
                          onChanged: (_) => setState(() {}),
                        ),
                        const SizedBox(height: 4),
                        _karmaPassCtrl.text.isNotEmpty
                            ? Text('WPA passphrase set to  "${_karmaPassCtrl.text}"',
                                style: const TextStyle(
                                  fontFamily: 'monospace', fontSize: 8, color: FColors.red))
                            : const Text('hostapd will use random passphrase if not set',
                                style: TextStyle(
                                  fontFamily: 'monospace', fontSize: 8, color: FColors.textDim)),
                      ],
                    ]),
                  ),
                ),
              ],
            ),
          ),
          Container(height: 1, color: FColors.cyan.op(0.12)),

          // ── Pipeline steps ──────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 8, 14, 4),
            child: Row(children: [
              Text('STEPS (${_steps.length})',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim, letterSpacing: 1)),
              const Spacer(),
              if (_steps.isEmpty)
                const Text('tap + to add modules',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim)),
            ]),
          ),

          Expanded(
            child: _steps.isEmpty
                ? const Center(
                    child: Text('No steps yet.\nTap  +  to add modules.',
                      textAlign: TextAlign.center,
                      style: TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textDim)),
                  )
                : ReorderableListView.builder(
                    padding: const EdgeInsets.fromLTRB(10, 0, 10, 8),
                    itemCount: _steps.length,
                    onReorder: (oldIdx, newIdx) {
                      setState(() {
                        if (newIdx > oldIdx) newIdx--;
                        final item = _steps.removeAt(oldIdx);
                        _steps.insert(newIdx, item);
                      });
                    },
                    itemBuilder: (_, i) {
                      final step = _steps[i];
                      final m = step.module;
                      return _StepTile(
                        key: ValueKey(Object.hashAll([i, m.id])),
                        index: i,
                        module: m,
                        showArrow: i < _steps.length - 1,
                        arrowColor: _chainColor(m.chainOutput),
                        arrowLabel: _chainLabel(m.chainOutput),
                        onRemove: () => _removeStep(i),
                      );
                    },
                  ),
          ),

          // ── Add button ──────────────────────────────────────────────────
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(14, 6, 14, 12),
              child: GestureDetector(
                onTap: _showModulePicker,
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 10),
                  decoration: BoxDecoration(
                    border: Border.all(color: FColors.cyan.op(0.4)),
                    color: FColors.cyan.op(0.06),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: const Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.add, color: FColors.cyan, size: 16),
                      SizedBox(width: 6),
                      Text('ADD MODULE',
                        style: TextStyle(fontFamily: 'monospace', fontSize: 10,
                          color: FColors.cyan, letterSpacing: 2)),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ── Network chip row (multi-network project) ──────────────────────────────────

class _NetworkChips extends StatelessWidget {
  final String target;
  final String selected;
  final void Function(String) onSelect;
  const _NetworkChips({required this.target, required this.selected, required this.onSelect});

  @override
  Widget build(BuildContext context) {
    final nets = target.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    return SizedBox(
      height: 24,
      child: ListView(
        scrollDirection: Axis.horizontal,
        children: nets.map((net) {
          final active = selected == net;
          return GestureDetector(
            onTap: () => onSelect(net),
            child: Container(
              margin: const EdgeInsets.only(right: 6),
              padding: const EdgeInsets.symmetric(horizontal: 8),
              decoration: BoxDecoration(
                color: active ? FColors.green.op(0.15) : FColors.bg,
                border: Border.all(
                  color: active ? FColors.green : FColors.textSecondary.op(0.4)),
                borderRadius: BorderRadius.circular(2),
              ),
              child: Center(
                child: Text(net,
                  style: TextStyle(fontFamily: 'monospace', fontSize: 8,
                    color: active ? FColors.green : FColors.textSecondary)),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }
}

// ── Step tile ─────────────────────────────────────────────────────────────────

class _StepTile extends StatelessWidget {
  final int index;
  final Module module;
  final bool showArrow;
  final Color arrowColor;
  final String arrowLabel;
  final VoidCallback onRemove;

  const _StepTile({
    super.key,
    required this.index,
    required this.module,
    required this.showArrow,
    required this.arrowColor,
    required this.arrowLabel,
    required this.onRemove,
  });

  Color get _tagColor => switch (module.category) {
    ModuleCategory.smb     => FColors.cyan,
    ModuleCategory.network => FColors.cyanDim,
    ModuleCategory.web     => FColors.purple,
    ModuleCategory.iot     => FColors.amber,
    ModuleCategory.brute   => FColors.red,
    ModuleCategory.recon   => FColors.green,
    ModuleCategory.exploit => FColors.magenta,
    ModuleCategory.fire    => FColors.orange,
    ModuleCategory.util    => FColors.textSecondary,
  };

  @override
  Widget build(BuildContext context) {
    return Column(
      key: key,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          margin: const EdgeInsets.only(top: 6),
          decoration: BoxDecoration(
            color: FColors.bgCard,
            border: Border.all(color: _tagColor.op(0.3)),
            borderRadius: BorderRadius.circular(4),
          ),
          child: Row(
            children: [
              Container(
                width: 32,
                padding: const EdgeInsets.symmetric(vertical: 12),
                decoration: BoxDecoration(
                  border: Border(right: BorderSide(color: _tagColor.op(0.25))),
                ),
                child: Text('${index + 1}',
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textDim)),
              ),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10),
                child: Icon(module.icon, color: _tagColor, size: 18),
              ),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(module.name,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 11,
                        color: FColors.textPrimary, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 2),
                    Row(children: [
                      _Badge(module.tag, _tagColor),
                      if (module.chainInput == ChainInput.target) ...[
                        const SizedBox(width: 4),
                        _Badge('TARGET', FColors.green),
                      ],
                      if (module.requiresInteraction) ...[
                        const SizedBox(width: 4),
                        _Badge('MANUAL', FColors.amber),
                      ],
                    ]),
                  ],
                ),
              ),
              const Icon(Icons.drag_handle, color: FColors.textDim, size: 18),
              const SizedBox(width: 4),
              IconButton(
                icon: const Icon(Icons.close, color: FColors.red, size: 16),
                onPressed: onRemove,
                padding: const EdgeInsets.all(8),
                constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
              ),
            ],
          ),
        ),
        if (showArrow)
          Padding(
            padding: const EdgeInsets.only(left: 22),
            child: Row(children: [
              Icon(Icons.arrow_downward, color: arrowColor.op(0.6), size: 14),
              if (arrowLabel.isNotEmpty) ...[
                const SizedBox(width: 3),
                Text(arrowLabel,
                  style: TextStyle(fontFamily: 'monospace', fontSize: 8, color: arrowColor.op(0.7))),
              ],
            ]),
          ),
      ],
    );
  }
}

class _Badge extends StatelessWidget {
  final String text;
  final Color color;
  const _Badge(this.text, this.color);

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
    decoration: BoxDecoration(
      border: Border.all(color: color.op(0.5), width: 0.8),
      color: color.op(0.08),
    ),
    child: Text(text,
      style: TextStyle(fontFamily: 'monospace', fontSize: 8, color: color, letterSpacing: 0.5)),
  );
}

class _FieldRow extends StatelessWidget {
  final String label;
  final Widget child;
  const _FieldRow({required this.label, required this.child});

  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.center,
    children: [
      SizedBox(
        width: 58,
        child: Text(label,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 9,
            color: FColors.textDim, letterSpacing: 1)),
      ),
      Container(width: 1, height: 18, color: FColors.cyan.op(0.2)),
      const SizedBox(width: 10),
      Expanded(child: child),
    ],
  );
}

// ── Project picker bottom sheet ───────────────────────────────────────────────

class _ProjectPickerSheet extends StatelessWidget {
  final List<Project> projects;
  final Project? selected;
  final void Function(Project?) onSelect;

  const _ProjectPickerSheet({
    required this.projects,
    required this.selected,
    required this.onSelect,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(0, 12, 0, 0),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Center(child: Container(
            width: 36, height: 3,
            decoration: BoxDecoration(color: FColors.textDim, borderRadius: BorderRadius.circular(2)))),
          const SizedBox(height: 10),
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 16),
            child: Row(children: [
              Icon(Icons.work_outline, color: FColors.amber, size: 14),
              SizedBox(width: 8),
              Text('LINK PROJECT',
                style: TextStyle(fontFamily: 'monospace', color: FColors.amber,
                  fontSize: 11, letterSpacing: 2)),
            ]),
          ),
          const SizedBox(height: 8),
          Container(height: 1, color: FColors.cyan.op(0.1)),
          // None option
          _ProjectTile(
            label: 'None',
            subtitle: 'Run without linking to a project',
            icon: Icons.block,
            color: FColors.textDim,
            isSelected: selected == null,
            onTap: () => onSelect(null),
          ),
          // Project list
          ...projects.map((p) => _ProjectTile(
            label: p.name,
            subtitle: p.target.isEmpty ? 'No target set' : p.target,
            icon: Icons.work_outline,
            color: FColors.amber,
            isSelected: selected?.id == p.id,
            onTap: () => onSelect(p),
          )),
          const SizedBox(height: 12),
        ],
      ),
    );
  }
}

class _ProjectTile extends StatelessWidget {
  final String label;
  final String subtitle;
  final IconData icon;
  final Color color;
  final bool isSelected;
  final VoidCallback onTap;

  const _ProjectTile({
    required this.label,
    required this.subtitle,
    required this.icon,
    required this.color,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: Container(
      margin: const EdgeInsets.fromLTRB(12, 0, 12, 6),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: isSelected ? color.op(0.12) : FColors.bgCard,
        border: Border.all(
          color: isSelected ? color.op(0.6) : color.op(0.2)),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Row(children: [
        Icon(icon, color: color, size: 16),
        const SizedBox(width: 10),
        Expanded(child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label,
              style: TextStyle(fontFamily: 'monospace', fontSize: 11,
                color: isSelected ? color : FColors.textPrimary,
                fontWeight: FontWeight.bold)),
            Text(subtitle,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim),
              overflow: TextOverflow.ellipsis),
          ],
        )),
        if (isSelected)
          Icon(Icons.check, color: color, size: 14),
      ]),
    ),
  );
}

// ── Module picker bottom sheet ────────────────────────────────────────────────

class _ModulePickerSheet extends StatefulWidget {
  final void Function(Module) onAdd;
  const _ModulePickerSheet({required this.onAdd});

  @override
  State<_ModulePickerSheet> createState() => _ModulePickerSheetState();
}

class _ModulePickerSheetState extends State<_ModulePickerSheet> {
  ModuleCategory? _filter;

  List<Module> get _filtered => _filter == null
      ? kModules
      : kModules.where((m) => m.category == _filter).toList();

  static const _cats = [
    (ModuleCategory.network, 'SCAN'),
    (ModuleCategory.exploit, 'EXPLOIT'),
    (ModuleCategory.brute,   'BRUTE'),
    (ModuleCategory.recon,   'RECON'),
    (ModuleCategory.iot,     'IoT'),
    (ModuleCategory.web,     'WEB'),
  ];

  Color _catColor(ModuleCategory c) => switch (c) {
    ModuleCategory.network => FColors.cyanDim,
    ModuleCategory.web     => FColors.purple,
    ModuleCategory.iot     => FColors.amber,
    ModuleCategory.brute   => FColors.red,
    ModuleCategory.recon   => FColors.green,
    ModuleCategory.exploit => FColors.magenta,
    _                      => FColors.textSecondary,
  };

  @override
  Widget build(BuildContext context) {
    final screenH = MediaQuery.sizeOf(context).height;
    final bottomPad = MediaQuery.paddingOf(context).bottom;
    return SizedBox(
      height: screenH * 0.72 + bottomPad,
      child: Column(children: [
        const SizedBox(height: 8),
        Container(width: 36, height: 3, decoration: BoxDecoration(
          color: FColors.textDim, borderRadius: BorderRadius.circular(2))),
        const SizedBox(height: 8),
        const Padding(
          padding: EdgeInsets.symmetric(horizontal: 14),
          child: Row(children: [
            Text('SELECT MODULE',
              style: TextStyle(fontFamily: 'monospace', fontSize: 11,
                color: FColors.cyan, letterSpacing: 2)),
          ]),
        ),
        const SizedBox(height: 8),
        SizedBox(
          height: 30,
          child: ListView(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 12),
            children: [
              _CatChip('ALL', _filter == null, () => setState(() => _filter = null), FColors.textSecondary),
              ..._cats.map((t) => _CatChip(t.$2, _filter == t.$1, () => setState(() => _filter = t.$1), _catColor(t.$1))),
            ],
          ),
        ),
        const SizedBox(height: 8),
        Container(height: 1, color: FColors.cyan.op(0.1)),
        Expanded(
          child: GridView.builder(
            padding: const EdgeInsets.all(10),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 2,
              childAspectRatio: 2.4,
              crossAxisSpacing: 8,
              mainAxisSpacing: 8,
            ),
            itemCount: _filtered.length,
            itemBuilder: (_, i) {
              final m = _filtered[i];
              final tc = _catColor(m.category);
              return GestureDetector(
                onTap: () => widget.onAdd(m),
                child: Container(
                  decoration: BoxDecoration(
                    color: FColors.bgCard,
                    border: Border.all(color: tc.op(0.3)),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                  child: Row(children: [
                    Icon(m.icon, color: tc, size: 18),
                    const SizedBox(width: 8),
                    Expanded(child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(m.name,
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 10,
                            color: FColors.textPrimary, fontWeight: FontWeight.bold),
                          overflow: TextOverflow.ellipsis),
                        Text(m.tag,
                          style: TextStyle(fontFamily: 'monospace', fontSize: 8, color: tc)),
                      ],
                    )),
                  ]),
                ),
              );
            },
          ),
        ),
      ]),
    );  // SizedBox
  }
}

class _CatChip extends StatelessWidget {
  final String label;
  final bool active;
  final VoidCallback onTap;
  final Color color;
  const _CatChip(this.label, this.active, this.onTap, this.color);

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: Container(
      margin: const EdgeInsets.only(right: 6),
      padding: const EdgeInsets.symmetric(horizontal: 10),
      decoration: BoxDecoration(
        color: active ? color.op(0.15) : FColors.bg,
        border: Border.all(color: active ? color : FColors.textSecondary.op(0.4)),
        borderRadius: BorderRadius.circular(2),
      ),
      child: Center(
        child: Text(label,
          style: TextStyle(fontFamily: 'monospace', fontSize: 9, letterSpacing: 1,
            color: active ? color : FColors.textSecondary)),
      ),
    ),
  );
}

// ── Template picker bottom sheet ──────────────────────────────────────────────

class _TemplatePickerSheet extends StatelessWidget {
  final void Function(PipelineTemplate) onLoad;
  const _TemplatePickerSheet({required this.onLoad});

  @override
  Widget build(BuildContext context) {
    final screenH = MediaQuery.sizeOf(context).height;
    final bottomPad = MediaQuery.paddingOf(context).bottom;
    return SizedBox(
      height: screenH * 0.82 + bottomPad,
      child: Column(
        children: [
          const SizedBox(height: 8),
          Container(width: 36, height: 3,
            decoration: BoxDecoration(color: FColors.textDim, borderRadius: BorderRadius.circular(2))),
          const SizedBox(height: 10),
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 14),
            child: Row(children: [
              Icon(Icons.auto_awesome_mosaic_outlined, color: FColors.amber, size: 14),
              SizedBox(width: 8),
              Text('PIPELINE TEMPLATES',
                style: TextStyle(fontFamily: 'monospace', color: FColors.amber,
                  fontSize: 11, letterSpacing: 2)),
            ]),
          ),
          const SizedBox(height: 6),
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 14),
            child: Text('Professional APT-style attack paths — tap to load',
              style: TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim)),
          ),
          const SizedBox(height: 8),
          Container(height: 1, color: FColors.amber.op(0.15)),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 8, 12, 16),
              itemCount: kPipelineTemplates.length,
              itemBuilder: (_, i) {
                final tpl = kPipelineTemplates[i];
                return _TemplateTile(template: tpl, onLoad: onLoad);
              },
            ),
          ),
        ],
      ),
    );
  }
}

class _TemplateTile extends StatelessWidget {
  final PipelineTemplate template;
  final void Function(PipelineTemplate) onLoad;
  const _TemplateTile({required this.template, required this.onLoad});

  @override
  Widget build(BuildContext context) {
    final tpl = template;
    final steps = tpl.buildSteps();
    return GestureDetector(
      onTap: () => onLoad(tpl),
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: FColors.bgCard,
          border: Border.all(color: tpl.color.op(0.3)),
          borderRadius: BorderRadius.circular(4),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header row
            Row(children: [
              Icon(tpl.icon, color: tpl.color, size: 16),
              const SizedBox(width: 8),
              Expanded(
                child: Text(tpl.name,
                  style: TextStyle(fontFamily: 'monospace', fontSize: 12,
                    color: tpl.color, fontWeight: FontWeight.bold)),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  border: Border.all(color: tpl.color.op(0.5)),
                  color: tpl.color.op(0.1),
                  borderRadius: BorderRadius.circular(2),
                ),
                child: Text(tpl.phase,
                  style: TextStyle(fontFamily: 'monospace', fontSize: 8,
                    color: tpl.color, letterSpacing: 1)),
              ),
            ]),
            const SizedBox(height: 5),
            // Goal line
            Text(tpl.goal,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 9,
                color: FColors.textSecondary)),
            const SizedBox(height: 6),
            // Module chain preview
            Text(tpl.description,
              style: TextStyle(fontFamily: 'monospace', fontSize: 8.5,
                color: tpl.color.op(0.7)),
              maxLines: 2, overflow: TextOverflow.ellipsis),
            const SizedBox(height: 6),
            // Module count + tags
            Row(children: [
              Text('${steps.length} modules',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 8, color: FColors.textDim)),
              const SizedBox(width: 6),
              if (steps.any((s) => s.module.requiresInteraction))
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                  decoration: BoxDecoration(
                    border: Border.all(color: FColors.amber.op(0.5), width: 0.7),
                    color: FColors.amber.op(0.07),
                  ),
                  child: Text(
                    '${steps.where((s) => s.module.requiresInteraction).length} manual',
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 7, color: FColors.amber)),
                ),
              const SizedBox(width: 6),
              Expanded(
                child: SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    children: steps.map((s) => Container(
                      margin: const EdgeInsets.only(right: 4),
                      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                      decoration: BoxDecoration(
                        border: Border.all(color: tpl.color.op(0.35), width: 0.7),
                        color: tpl.color.op(0.07),
                        borderRadius: BorderRadius.circular(2),
                      ),
                      child: Text(s.module.tag,
                        style: TextStyle(fontFamily: 'monospace', fontSize: 7.5,
                          color: tpl.color.op(0.9))),
                    )).toList(),
                  ),
                ),
              ),
            ]),
          ],
        ),
      ),
    );
  }
}
