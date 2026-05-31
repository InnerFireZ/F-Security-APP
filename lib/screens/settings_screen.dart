import 'package:flutter/material.dart';
import '../data/modules.dart';
import '../services/nethunter_service.dart';
import '../services/settings_service.dart';
import '../services/script_deployer.dart';
import '../services/theme_service.dart';
import '../theme/colors.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late TextEditingController _chrootCtrl;
  late TextEditingController _wordlistCtrl;
  double _fontSize    = 9.0;
  double _nucleiConc  = SettingsService.defaultNucleiConc.toDouble();
  String _termTheme   = SettingsService.defaultTermTheme;
  String _edgeGlow    = SettingsService.defaultEdgeGlow;
  bool _oledMode   = false;
  bool _deploying  = false;
  String _deployMsg = '';
  double _deployProgress = 0;

  @override
  void initState() {
    super.initState();
    _chrootCtrl    = TextEditingController(text: NetHunterService.chrootPath);
    _wordlistCtrl  = TextEditingController(text: SettingsService.defaultWordlist);
    SettingsService.getFontSize().then((v) => setState(() => _fontSize = v));
    SettingsService.getWordlist().then((v) => setState(() => _wordlistCtrl.text = v));
    SettingsService.getNucleiConc().then((v) => setState(() => _nucleiConc = v.toDouble()));
    SettingsService.getTerminalTheme().then((v) => setState(() => _termTheme = v));
    SettingsService.getEdgeGlow().then((v) => setState(() => _edgeGlow = v));
    SettingsService.getOledMode().then((v) => setState(() => _oledMode = v));
  }

  @override
  void dispose() {
    _chrootCtrl.dispose();
    _wordlistCtrl.dispose();
    super.dispose();
  }

  Future<void> _redeploy() async {
    setState(() { _deploying = true; _deployMsg = ''; _deployProgress = 0; });
    await ScriptDeployer.deploy(
      onProgress: (msg, p) => setState(() { _deployMsg = msg; _deployProgress = p; }),
    );
    setState(() => _deploying = false);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Scripts deployed successfully', style: TextStyle(fontFamily: 'monospace')),
          backgroundColor: Color(0xFF0D1117),
        ),
      );
    }
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
        title: const Text(
          'SETTINGS',
          style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, letterSpacing: 3, fontSize: 14),
        ),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _Section('QUICK PATHS'),
          _QuickPath('kali-arm64  (64-bit)', '/data/local/nhsystem/kali-arm64', _chrootCtrl),
          _QuickPath('kali-armhf  (32-bit)', '/data/local/nhsystem/kali-armhf', _chrootCtrl),
          const SizedBox(height: 24),
          _Section('NETHUNTER'),
          _Label('Chroot path'),
          const SizedBox(height: 6),
          _MonoField(controller: _chrootCtrl),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(child: _ActionButton('SAVE PATH', FColors.cyan, () async {
                final messenger = ScaffoldMessenger.of(context);
                await SettingsService.saveChrootPath(_chrootCtrl.text.trim());
                messenger.showSnackBar(
                  const SnackBar(content: Text('Chroot path saved', style: TextStyle(fontFamily: 'monospace')), backgroundColor: Color(0xFF0D1117)),
                );
              })),
              const SizedBox(width: 8),
              Expanded(child: _ActionButton('REDEPLOY SCRIPTS', FColors.amber, _deploying ? null : _redeploy)),
            ],
          ),
          if (_deploying) ...[
            const SizedBox(height: 12),
            LinearProgressIndicator(value: _deployProgress, color: FColors.cyan, backgroundColor: FColors.bgPanel),
            const SizedBox(height: 6),
            Text(_deployMsg, style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textSecondary)),
          ],
          const SizedBox(height: 24),
          _Section('DISPLAY'),
          _Label('App background theme'),
          const SizedBox(height: 8),
          Row(children: [
            _ThemeChip(
              label: 'DEFAULT',
              active: !_oledMode,
              fg: FColors.cyan,
              bg: const Color(0xFF060811),
              onTap: () async {
                setState(() => _oledMode = false);
                await SettingsService.saveOledMode(false);
                ThemeService.setOled(false);
              },
            ),
            const SizedBox(width: 10),
            _ThemeChip(
              label: 'OLED BLACK',
              active: _oledMode,
              fg: FColors.green,
              bg: const Color(0xFF000000),
              onTap: () async {
                setState(() => _oledMode = true);
                await SettingsService.saveOledMode(true);
                ThemeService.setOled(true);
              },
            ),
          ]),
          const SizedBox(height: 6),
          Text(
            'Pure black backgrounds — saves battery on OLED screens',
            style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim),
          ),
          const SizedBox(height: 24),
          _Section('TERMINAL'),
          _Label('Default font size: ${_fontSize.toInt()}pt'),
          Slider(
            value: _fontSize,
            min: 7,
            max: 18,
            divisions: 11,
            activeColor: FColors.cyan,
            inactiveColor: FColors.bgPanel,
            onChanged: (v) => setState(() => _fontSize = v),
            onChangeEnd: (v) => SettingsService.saveFontSize(v),
          ),
          const SizedBox(height: 16),
          _Label('Color theme'),
          const SizedBox(height: 8),
          Row(children: [
            _ThemeChip(
              label: 'GREY',
              active: _termTheme == 'grey',
              fg: const Color(0xFFC9D1D9),
              bg: const Color(0xFF0D1117),
              onTap: () async {
                setState(() => _termTheme = 'grey');
                await SettingsService.saveTerminalTheme('grey');
              },
            ),
            const SizedBox(width: 10),
            _ThemeChip(
              label: 'GREEN',
              active: _termTheme == 'green',
              fg: const Color(0xFF00FF41),
              bg: const Color(0xFF000000),
              onTap: () async {
                setState(() => _termTheme = 'green');
                await SettingsService.saveTerminalTheme('green');
              },
            ),
          ]),
          const SizedBox(height: 24),
          _Section('EDGE GLOW'),
          _Label('Pulse color when a script finishes'),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _GlowDot(label: 'AUTO',   color: FColors.cyan,            active: _edgeGlow == 'auto',   onTap: () async { setState(() => _edgeGlow = 'auto');   await SettingsService.saveEdgeGlow('auto');   }, isAuto: true),
              _GlowDot(label: 'OFF',    color: const Color(0xFF444444), active: _edgeGlow == 'off',    onTap: () async { setState(() => _edgeGlow = 'off');    await SettingsService.saveEdgeGlow('off');    }),
              _GlowDot(label: 'CYAN',   color: FColors.cyan,            active: _edgeGlow == 'cyan',   onTap: () async { setState(() => _edgeGlow = 'cyan');   await SettingsService.saveEdgeGlow('cyan');   }),
              _GlowDot(label: 'GREEN',  color: FColors.green,           active: _edgeGlow == 'green',  onTap: () async { setState(() => _edgeGlow = 'green');  await SettingsService.saveEdgeGlow('green');  }),
              _GlowDot(label: 'PURPLE', color: FColors.purple,          active: _edgeGlow == 'purple', onTap: () async { setState(() => _edgeGlow = 'purple'); await SettingsService.saveEdgeGlow('purple'); }),
              _GlowDot(label: 'RED',    color: const Color(0xFFFF2233), active: _edgeGlow == 'amber',  onTap: () async { setState(() => _edgeGlow = 'amber');  await SettingsService.saveEdgeGlow('amber');  }),
              _GlowDot(label: 'WHITE',  color: Colors.white,            active: _edgeGlow == 'white',  onTap: () async { setState(() => _edgeGlow = 'white');  await SettingsService.saveEdgeGlow('white');  }),
            ],
          ),
          const SizedBox(height: 24),
          _Section('BRUTE FORCE'),
          _Label('Wordlist path'),
          const SizedBox(height: 6),
          _MonoField(controller: _wordlistCtrl),
          const SizedBox(height: 8),
          _ActionButton('SAVE WORDLIST', FColors.cyan, () async {
            final messenger = ScaffoldMessenger.of(context);
            await SettingsService.saveWordlist(_wordlistCtrl.text.trim());
            messenger.showSnackBar(
              const SnackBar(content: Text('Wordlist path saved', style: TextStyle(fontFamily: 'monospace')), backgroundColor: Color(0xFF0D1117)),
            );
          }),
          const SizedBox(height: 24),
          _Section('NUCLEI'),
          _Label('Max concurrency: ${_nucleiConc.toInt()}  (templates in parallel)'),
          Slider(
            value: _nucleiConc,
            min: 5,
            max: 50,
            divisions: 9,
            activeColor: FColors.cyan,
            inactiveColor: FColors.bgPanel,
            onChanged: (v) => setState(() => _nucleiConc = v),
            onChangeEnd: (v) => SettingsService.saveNucleiConc(v.toInt()),
          ),
          const SizedBox(height: 24),
          _Section('ABOUT'),
          const _InfoRow('App',     'F-Security'),
          _InfoRow('Scripts', 'v${ScriptDeployer.currentVersion}'),
          const _InfoRow('Author',  'InnerFireZ'),
          const _InfoRow('Target',  'Rooted NetHunter Android'),
          _InfoRow('Modules', '${kModules.length} pentest modules'),
          const SizedBox(height: 20),
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: FColors.red.op(0.05),
              border: Border.all(color: FColors.red.op(0.35), width: 1),
              borderRadius: BorderRadius.circular(2),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(children: [
                  const Icon(Icons.warning_amber_rounded, color: FColors.red, size: 14),
                  const SizedBox(width: 7),
                  const Text('LEGAL DISCLAIMER',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 10,
                      color: FColors.red, fontWeight: FontWeight.bold, letterSpacing: 1.5)),
                ]),
                const SizedBox(height: 10),
                const Text(
                  'This application is intended for authorized security testing, '
                  'penetration testing on systems you own or have explicit written '
                  'permission to test, and educational purposes only.\n\n'
                  'Unauthorized access to computer systems is illegal and punishable '
                  'by law in most jurisdictions. The author (InnerFireZ) assumes no '
                  'responsibility or liability for any misuse, damage, or illegal '
                  'actions performed with this tool.\n\n'
                  'USE AT YOUR OWN RISK.',
                  style: TextStyle(
                    fontFamily: 'monospace', fontSize: 10,
                    color: FColors.textDim, height: 1.6,
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

class _Section extends StatelessWidget {
  final String title;
  const _Section(this.title);
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 10),
    child: Text(title,
      style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.cyan, letterSpacing: 3),
    ),
  );
}

class _Label extends StatelessWidget {
  final String text;
  const _Label(this.text);
  @override
  Widget build(BuildContext context) => Text(text,
    style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textSecondary),
  );
}

class _MonoField extends StatelessWidget {
  final TextEditingController controller;
  const _MonoField({required this.controller});
  @override
  Widget build(BuildContext context) => TextField(
    controller: controller,
    style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: FColors.textPrimary),
    decoration: InputDecoration(
      filled: true,
      fillColor: FColors.bgPanel,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(2),
        borderSide: const BorderSide(color: FColors.cyan, width: 0.5),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(2),
        borderSide: BorderSide(color: FColors.cyan.op(0.3), width: 0.5),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(2),
        borderSide: const BorderSide(color: FColors.cyan, width: 1),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
    ),
  );
}

class _ActionButton extends StatelessWidget {
  final String label;
  final Color color;
  final VoidCallback? onTap;
  const _ActionButton(this.label, this.color, this.onTap);
  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: Container(
      padding: const EdgeInsets.symmetric(vertical: 10),
      decoration: BoxDecoration(
        border: Border.all(color: onTap != null ? color.op(0.5) : FColors.textDim, width: 1),
        color: onTap != null ? color.op(0.07) : Colors.transparent,
      ),
      child: Text(
        label,
        textAlign: TextAlign.center,
        style: TextStyle(
          fontFamily: 'monospace',
          fontSize: 10,
          letterSpacing: 1,
          color: onTap != null ? color : FColors.textDim,
        ),
      ),
    ),
  );
}

class _QuickPath extends StatelessWidget {
  final String label;
  final String path;
  final TextEditingController ctrl;
  const _QuickPath(this.label, this.path, this.ctrl);
  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: () => ctrl.text = path,
    child: Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: FColors.bgCard,
        border: Border.all(color: FColors.cyan.op(0.15)),
      ),
      child: Row(
        children: [
          Expanded(child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label, style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textSecondary)),
              Text(path,  style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
            ],
          )),
          const Icon(Icons.chevron_right, color: FColors.textDim, size: 16),
        ],
      ),
    ),
  );
}

class _GlowDot extends StatelessWidget {
  final String label;
  final Color color;
  final bool active;
  final VoidCallback onTap;
  final bool isAuto;
  const _GlowDot({required this.label, required this.color, required this.active, required this.onTap, this.isAuto = false});

  static const _autoColors = [
    Color(0xFF00BCD4), // cyan  (network)
    Color(0xFF9C27B0), // purple (web)
    Color(0xFF4CAF50), // green (recon)
    Color(0xFFFF9800), // amber (iot — AUTO only; manual chip now shows red)
    Color(0xFFF44336), // red (brute)
    Color(0xFFE91E63), // magenta (exploit)
  ];

  @override
  Widget build(BuildContext context) {
    final borderCol = active
        ? (isAuto ? const Color(0xFF00BCD4) : color)
        : FColors.textDim.op(0.25);
    return GestureDetector(
    onTap: onTap,
    child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: active ? (isAuto ? const Color(0xFF00BCD4) : color).op(0.12) : FColors.bgCard,
        border: Border.all(color: borderCol, width: active ? 1.5 : 0.8),
        borderRadius: BorderRadius.circular(2),
        boxShadow: active ? [BoxShadow(color: (isAuto ? const Color(0xFF00BCD4) : color).op(0.35), blurRadius: 10, spreadRadius: 1)] : null,
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        if (isAuto)
          Container(
            width: 12, height: 12,
            decoration: const BoxDecoration(
              shape: BoxShape.circle,
              gradient: SweepGradient(colors: _autoColors),
            ),
          )
        else
        Container(
          width: 12, height: 12,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: label == 'OFF' ? Colors.transparent : color,
            border: Border.all(color: color, width: label == 'OFF' ? 1.5 : 0),
            boxShadow: active && label != 'OFF'
                ? [BoxShadow(color: color.op(0.7), blurRadius: 8, spreadRadius: 1)]
                : null,
          ),
          child: label == 'OFF' ? Center(child: Text('×', style: TextStyle(fontSize: 9, color: color, height: 1.1))) : null,
        ),
        const SizedBox(width: 7),
        Text(label, style: TextStyle(
          fontFamily: 'monospace', fontSize: 10, letterSpacing: 1,
          color: active ? (isAuto ? const Color(0xFF00BCD4) : color) : FColors.textSecondary,
          fontWeight: active ? FontWeight.bold : FontWeight.normal,
        )),
      ]),
    ),
  );
  }
}

class _ThemeChip extends StatelessWidget {
  final String label;
  final bool active;
  final Color fg;
  final Color bg;
  final VoidCallback onTap;
  const _ThemeChip({required this.label, required this.active, required this.fg, required this.bg, required this.onTap});

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: active ? fg.op(0.08) : FColors.bgCard,
        border: Border.all(
          color: active ? fg : FColors.textDim.op(0.3),
          width: active ? 1.5 : 0.8,
        ),
        borderRadius: BorderRadius.circular(2),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Container(
          width: 28, height: 16,
          decoration: BoxDecoration(
            color: bg,
            border: Border.all(color: fg.op(0.6), width: 1),
            borderRadius: BorderRadius.circular(2),
          ),
          child: Center(
            child: Text('A', style: TextStyle(
              fontFamily: 'monospace', fontSize: 10,
              color: fg, fontWeight: FontWeight.bold,
            )),
          ),
        ),
        const SizedBox(width: 8),
        Text(label, style: TextStyle(
          fontFamily: 'monospace', fontSize: 10, letterSpacing: 1,
          color: active ? fg : FColors.textSecondary,
          fontWeight: active ? FontWeight.bold : FontWeight.normal,
        )),
        if (active) ...[
          const SizedBox(width: 6),
          Icon(Icons.check, color: fg, size: 13),
        ],
      ]),
    ),
  );
}

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;
  const _InfoRow(this.label, this.value);
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(
      children: [
        SizedBox(width: 80, child: Text(label, style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim))),
        Text(value, style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textSecondary)),
      ],
    ),
  );
}
