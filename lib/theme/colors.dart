import 'package:flutter/material.dart';

class FColors {
  // Set before runApp; toggled by ThemeService
  static bool oled = false;

  // Background — pure black on OLED, dark blue-grey default
  static Color get bg      => oled ? const Color(0xFF000000) : const Color(0xFF060811);
  static Color get bgCard  => oled ? const Color(0xFF080808) : const Color(0xFF0D1117);
  static Color get bgPanel => oled ? const Color(0xFF101010) : const Color(0xFF111827);

  static const Color cyan     = Color(0xFF00FFFF);
  static const Color cyanDim  = Color(0xFF0EA5E9);
  static const Color green    = Color(0xFF00FF41);
  static const Color red      = Color(0xFFFF0044);
  static const Color amber    = Color(0xFFFFB800);
  static const Color magenta  = Color(0xFFFF0080);
  static const Color purple   = Color(0xFF8B5CF6);
  static const Color orange   = Color(0xFFFF6600);

  static const Color textPrimary   = Color(0xFFE2E8F0);
  static const Color textSecondary = Color(0xFF94A3B8);
  static const Color textDim       = Color(0xFF475569);
}

// Drop-in replacement for the deprecated Color.withOpacity()
extension FColorOp on Color {
  Color op(double opacity) =>
      withAlpha((opacity.clamp(0.0, 1.0) * 255).round());
}
