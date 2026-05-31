import 'package:flutter/material.dart';
import 'colors.dart';

class AppTheme {
  static ThemeData build(bool oled) => ThemeData(
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

  static ThemeData get dark => build(FColors.oled);
}
