import 'package:flutter/material.dart';
import '../models/module.dart';
import '../theme/colors.dart';

class ModuleCard extends StatefulWidget {
  final Module module;
  final VoidCallback onTap;
  final bool isRunning;

  const ModuleCard({
    super.key,
    required this.module,
    required this.onTap,
    this.isRunning = false,
  });

  @override
  State<ModuleCard> createState() => _ModuleCardState();
}

class _ModuleCardState extends State<ModuleCard>
    with SingleTickerProviderStateMixin {
  late AnimationController _pulse;
  late Animation<double> _glow;

  @override
  void initState() {
    super.initState();
    _pulse = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1400),
    );
    _glow = Tween<double>(begin: 0.3, end: 1.0).animate(
      CurvedAnimation(parent: _pulse, curve: Curves.easeInOut),
    );
    if (widget.isRunning) _pulse.repeat(reverse: true);
  }

  @override
  void didUpdateWidget(ModuleCard old) {
    super.didUpdateWidget(old);
    if (widget.isRunning && !old.isRunning) {
      _pulse.repeat(reverse: true);
    } else if (!widget.isRunning && old.isRunning) {
      _pulse.stop();
      _pulse.value = 0;
    }
  }

  @override
  void dispose() {
    _pulse.dispose();
    super.dispose();
  }

  Color get _chainOutputColor => switch (widget.module.chainOutput) {
    ChainOutput.credentials => FColors.green,
    ChainOutput.hashes      => FColors.red,
    ChainOutput.sessionDir  => FColors.cyanDim,
    ChainOutput.none        => FColors.textDim,
  };

  String get _chainOutputLabel => switch (widget.module.chainOutput) {
    ChainOutput.credentials => 'CREDS',
    ChainOutput.hashes      => 'HASHES',
    ChainOutput.sessionDir  => 'RESULTS',
    ChainOutput.none        => '',
  };

  Color get _tagColor {
    switch (widget.module.category) {
      case ModuleCategory.smb:     return FColors.cyan;
      case ModuleCategory.network: return FColors.cyanDim;
      case ModuleCategory.web:     return FColors.purple;
      case ModuleCategory.iot:     return FColors.amber;
      case ModuleCategory.brute:   return FColors.red;
      case ModuleCategory.recon:   return FColors.green;
      case ModuleCategory.exploit: return FColors.magenta;
      case ModuleCategory.fire:    return FColors.orange;
      case ModuleCategory.util:    return FColors.textSecondary;
    }
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: widget.onTap,
      child: AnimatedBuilder(
        animation: _glow,
        builder: (_, child) {
          final glowAlpha = widget.isRunning ? _glow.value : 0.0;
          return Container(
            decoration: BoxDecoration(
              color: FColors.bgCard,
              border: Border.all(
                color: widget.isRunning
                    ? FColors.green.op(0.55 + 0.45 * _glow.value)
                    : _tagColor.op(0.35),
                width: widget.isRunning ? 2.2 : 1,
              ),
              borderRadius: BorderRadius.circular(4),
              boxShadow: [
                if (widget.isRunning) ...[
                  BoxShadow(
                    color: FColors.green.op(0.45 * glowAlpha),
                    blurRadius: 18,
                    spreadRadius: 3,
                  ),
                  BoxShadow(
                    color: FColors.green.op(0.2 * glowAlpha),
                    blurRadius: 6,
                    spreadRadius: 1,
                  ),
                ],
                BoxShadow(
                  color: _tagColor.op(0.08),
                  blurRadius: 10,
                ),
              ],
            ),
            child: child,
          );
        },
        child: Stack(
          children: [
            // ID badge top-left
            Positioned(
              top: 7, left: 9,
              child: Text(
                '[${widget.module.id.toString().padLeft(2, '0')}]',
                style: const TextStyle(
                  fontFamily: 'monospace', fontSize: 10, color: FColors.cyan),
              ),
            ),
            // Category tag top-right (hidden when LIVE badge shown)
            if (!widget.isRunning)
              Positioned(
                top: 7, right: 7,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                  decoration: BoxDecoration(
                    border: Border.all(color: _tagColor.op(0.5), width: 1),
                    color: _tagColor.op(0.07),
                  ),
                  child: Text(
                    widget.module.tag,
                    style: TextStyle(
                      fontFamily: 'monospace', fontSize: 9,
                      color: _tagColor, letterSpacing: 1),
                  ),
                ),
              ),
            // LIVE badge (replaces tag when running)
            if (widget.isRunning)
              Positioned(
                top: 7, right: 7,
                child: _LiveBadge(),
              ),
            // Center: icon + name + desc
            Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const SizedBox(height: 10),
                  Icon(
                    widget.module.icon,
                    color: widget.isRunning ? FColors.green : FColors.cyan,
                    size: 24,
                  ),
                  const SizedBox(height: 6),
                  Text(
                    widget.module.name,
                    style: TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: widget.isRunning
                          ? FColors.green
                          : FColors.textPrimary,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 1,
                    ),
                  ),
                  const SizedBox(height: 3),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 6),
                    child: Text(
                      widget.module.description,
                      textAlign: TextAlign.center,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 9,
                        color: FColors.textSecondary,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            // Interactive indicator (bottom-right) — shows ⌨ if module needs user input
            if (widget.module.requiresInteraction && !widget.isRunning)
              const Positioned(
                bottom: 6, right: 7,
                child: Icon(Icons.keyboard_outlined, size: 10, color: FColors.textDim),
              ),
            // Chain output badge (bottom-left)
            if (widget.module.chainOutput != ChainOutput.none)
              Positioned(
                bottom: 6, left: 7,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                  decoration: BoxDecoration(
                    border: Border.all(
                      color: _chainOutputColor.op(0.5), width: 1),
                    color: _chainOutputColor.op(0.06),
                    borderRadius: BorderRadius.circular(2),
                  ),
                  child: Text(
                    '→ $_chainOutputLabel',
                    style: TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 7.5,
                      color: _chainOutputColor,
                      letterSpacing: 0.5,
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

// Animated LIVE badge
class _LiveBadge extends StatefulWidget {
  @override
  State<_LiveBadge> createState() => _LiveBadgeState();
}

class _LiveBadgeState extends State<_LiveBadge>
    with SingleTickerProviderStateMixin {
  late AnimationController _c;

  @override
  void initState() {
    super.initState();
    _c = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 900))
      ..repeat(reverse: true);
  }

  @override
  void dispose() { _c.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _c,
      builder: (_, __) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
        decoration: BoxDecoration(
          color: FColors.green.op(0.08 + 0.12 * _c.value),
          border: Border.all(
              color: FColors.green.op(0.4 + 0.5 * _c.value), width: 1),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 5, height: 5,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: FColors.green.op(0.5 + 0.5 * _c.value),
              ),
            ),
            const SizedBox(width: 4),
            Text(
              'LIVE',
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 9,
                color: FColors.green.op(0.7 + 0.3 * _c.value),
                letterSpacing: 1,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
