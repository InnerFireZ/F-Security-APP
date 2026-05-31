import 'package:flutter/material.dart';
import '../data/modules.dart';
import '../services/nethunter_service.dart';
import '../services/project_service.dart';
import '../services/script_deployer.dart';
import '../services/settings_service.dart';
import '../theme/colors.dart';
import 'dashboard_screen.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});
  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> with SingleTickerProviderStateMixin {
  late AnimationController _pulse;

  String  _status      = 'INITIALIZING...';
  bool    _hasRoot     = false;
  bool    _hasChroot   = false;
  bool    _failed      = false;
  bool    _deploying   = false;
  double  _deployProg  = 0;
  String  _deployMsg   = '';

  @override
  void initState() {
    super.initState();
    _pulse = AnimationController(vsync: this, duration: const Duration(milliseconds: 900))
      ..repeat(reverse: true);
    _runChecks();
  }

  @override
  void dispose() {
    _pulse.dispose();
    super.dispose();
  }

  Future<void> _runChecks() async {
    setState(() { _failed = false; _status = 'LOADING SETTINGS...'; });
    await SettingsService.load();
    await ProjectService.init();
    await Future.delayed(const Duration(milliseconds: 300));

    setState(() => _status = 'CHECKING ROOT ACCESS...');
    _hasRoot = await NetHunterService.hasRoot();

    setState(() => _status = 'CHECKING NETHUNTER CHROOT...');
    final detectedPath = await NetHunterService.detectChrootPath();
    if (detectedPath != null) {
      _hasChroot = true;
      if (detectedPath != NetHunterService.chrootPath) {
        await SettingsService.saveChrootPath(detectedPath);
      }
    } else {
      _hasChroot = false;
    }

    if (!_hasRoot || !_hasChroot) {
      setState(() { _status = 'SYSTEM CHECK FAILED'; _failed = true; });
      return;
    }

    // Deploy scripts if needed
    final needsDeploy = await ScriptDeployer.needsDeploy();
    if (needsDeploy) {
      setState(() { _deploying = true; _status = 'DEPLOYING SCRIPTS...'; });
      await ScriptDeployer.deploy(
        onProgress: (msg, p) => setState(() { _deployMsg = msg; _deployProg = p; }),
      );
      setState(() { _deploying = false; });
    }

    setState(() => _status = 'SYSTEM READY');
    await Future.delayed(const Duration(milliseconds: 600));
    if (mounted) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const DashboardScreen()),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: FColors.bg,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Banner
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(vertical: 22, horizontal: 20),
                decoration: BoxDecoration(
                  color: FColors.bgCard,
                  border: Border.all(color: FColors.cyan.op(0.35), width: 1),
                  boxShadow: [BoxShadow(color: FColors.cyan.op(0.08), blurRadius: 20, spreadRadius: 2)],
                ),
                child: Column(children: [
                  const Text('▓▒░  F-SECURITY  ░▒▓',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 18, fontWeight: FontWeight.bold, color: FColors.cyan, letterSpacing: 4)),
                  const SizedBox(height: 5),
                  const Text('NETWORK INFILTRATION SUITE',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textSecondary, letterSpacing: 3)),
                  const SizedBox(height: 2),
                  Text('${kModules.length} modules  ·  NetHunter  ·  Rootless',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim, letterSpacing: 1)),
                ]),
              ),
              const SizedBox(height: 36),

              // Checks
              _CheckRow('ROOT ACCESS',       _hasRoot),
              const SizedBox(height: 10),
              _CheckRow('NETHUNTER CHROOT',  _hasChroot),
              const SizedBox(height: 10),
              _CheckRow('F-SECURITY SCRIPTS', !_failed && !_deploying),
              const SizedBox(height: 28),

              // Deploy progress
              if (_deploying) ...[
                LinearProgressIndicator(
                  value: _deployProg,
                  color: FColors.cyan,
                  backgroundColor: FColors.bgPanel,
                  minHeight: 2,
                ),
                const SizedBox(height: 8),
                Text(_deployMsg,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
                const SizedBox(height: 16),
              ],

              // Status
              AnimatedBuilder(
                animation: _pulse,
                builder: (_, __) => Text(_status,
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    letterSpacing: 2,
                    color: _failed
                        ? FColors.red
                        : Color.lerp(FColors.cyan, FColors.cyan.op(0.5), _pulse.value)!,
                  ),
                ),
              ),

              // Error hints
              if (_failed) ...[
                const SizedBox(height: 20),
                if (!_hasRoot)
                  _Hint('→ Root access required (Magisk / SuperSU)', FColors.red),
                if (!_hasChroot) ...[
                  const SizedBox(height: 4),
                  _Hint('→ NetHunter chroot not found:', FColors.amber),
                  _Hint(NetHunterService.chrootPath, FColors.textDim),
                ],
                const SizedBox(height: 20),
                GestureDetector(
                  onTap: _runChecks,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 10),
                    decoration: BoxDecoration(
                      border: Border.all(color: FColors.cyan.op(0.5)),
                      color: FColors.cyan.op(0.06),
                    ),
                    child: const Text('[ RETRY ]',
                      style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, letterSpacing: 3)),
                  ),
                ),
              ] else if (_status != 'SYSTEM READY' && !_deploying)
                const Padding(
                  padding: EdgeInsets.only(top: 20),
                  child: SizedBox(width: 18, height: 18,
                    child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5)),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _CheckRow extends StatelessWidget {
  final String label;
  final bool ok;
  const _CheckRow(this.label, this.ok);
  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Text(ok ? '[✓]' : '[ ]',
        style: TextStyle(fontFamily: 'monospace', fontSize: 13, color: ok ? FColors.green : FColors.textDim)),
      const SizedBox(width: 12),
      Text(label,
        style: TextStyle(fontFamily: 'monospace', fontSize: 13, letterSpacing: 1,
          color: ok ? FColors.textPrimary : FColors.textDim)),
    ],
  );
}

class _Hint extends StatelessWidget {
  final String text;
  final Color color;
  const _Hint(this.text, this.color);
  @override
  Widget build(BuildContext context) => Text(text,
    textAlign: TextAlign.center,
    style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: color));
}
