import 'package:flutter/material.dart';
import 'colors.dart';

class AppTheme {
  // Colors come from FColors getters keyed off the FColors.oled global (set at
  // startup / on toggle), so build takes no parameter.
  static ThemeData build() => ThemeData(
    brightness: Brightness.dark,
    scaffoldBackgroundColor: FColors.bg,
    colorScheme: ColorScheme.dark(
      primary: FColors.cyan,
      secondary: FColors.magenta,
      surface: FColors.bgCard,
      error: FColors.red,
    ),
    appBarTheme: AppBarTheme(
      backgroundColor: FColors.bgCard,
      foregroundColor: FColors.textPrimary,
      elevation: 0,
    ),
    useMaterial3: true,
  );

  static ThemeData get dark => build();
}
