import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_pty/flutter_pty.dart';
import 'package:xterm/xterm.dart';
import '../services/nethunter_service.dart';
import '../services/settings_service.dart';
import '../theme/colors.dart';

// Terminal screen for one-shot ad-hoc commands (host map port actions, etc.)
// Takes a raw shell command that runs inside the chroot.
class AdHocTerminalScreen extends StatefulWidget {
  final String title;
  final String command; // runs inside chroot via bash -c

  const AdHocTerminalScreen({
    super.key,
    required this.title,
    required this.command,
  });

  @override
  State<AdHocTerminalScreen> createState() => _AdHocTerminalScreenState();
}

class _AdHocTerminalScreenState extends State<AdHocTerminalScreen> {
  late final Terminal _terminal;
  late final TerminalController _controller;
  Pty? _pty;
  bool _running = false;
  double _fontSize = 9.0;

  @override
  void initState() {
    super.initState();
    _terminal = Terminal(maxLines: 5000);
    _controller = TerminalController();
    SettingsService.getFontSize().then((v) { if (mounted) setState(() => _fontSize = v); });
    _launch();
  }

  @override
  void dispose() {
    _pty?.kill();
    _controller.dispose();
    super.dispose();
  }

  void _launch() {
    setState(() => _running = true);
    const linuxPath = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
    final cmd =
        'chroot ${NetHunterService.chrootPath} /usr/bin/env -i'
        ' HOME=/root TERM=xterm-256color PATH=$linuxPath'
        ' /bin/bash -c \'${widget.command.replaceAll("'", "'\\''")}\'';

    try {
      _pty = Pty.start(
        'su',
        arguments: ['-c', cmd],
        columns: 120,
        rows: 40,
        environment: {'TERM': 'xterm-256color'},
      );

      _pty!.output
          .cast<List<int>>()
          .transform(const Utf8Decoder(allowMalformed: true))
          .listen(
            (data) => _terminal.write(data),
            onDone: () { if (mounted) setState(() => _running = false); },
          );

      _terminal.onOutput = (data) => _pty?.write(const Utf8Encoder().convert(data));
      _terminal.onResize = (w, h, pw, ph) => _pty?.resize(h, w);
    } catch (e) {
      _terminal.write('\r\n[!] Launch failed: $e\r\n');
      if (mounted) setState(() => _running = false);
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
          onPressed: () { _pty?.kill(); Navigator.pop(context); },
        ),
        title: Row(
          children: [
            Flexible(
              child: Text(
                widget.title,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  color: FColors.cyan,
                  fontSize: 12,
                  letterSpacing: 1,
                ),
              ),
            ),
            const SizedBox(width: 8),
            if (_running)
              Container(
                width: 7, height: 7,
                decoration: const BoxDecoration(color: FColors.green, shape: BoxShape.circle),
              )
            else
              const Text('done',
                style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.remove, color: FColors.textSecondary, size: 18),
            onPressed: () { final s = (_fontSize - 1).clamp(7.0, 20.0); setState(() => _fontSize = s); SettingsService.saveFontSize(s); },
          ),
          IconButton(
            icon: const Icon(Icons.add, color: FColors.textSecondary, size: 18),
            onPressed: () { final s = (_fontSize + 1).clamp(7.0, 20.0); setState(() => _fontSize = s); SettingsService.saveFontSize(s); },
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: TerminalView(
        _terminal,
        controller: _controller,
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
      ),
    );
  }
}
