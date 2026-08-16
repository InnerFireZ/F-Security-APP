import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'services/scan_foreground_service.dart';
import 'services/settings_service.dart';
import 'services/theme_service.dart';
import 'theme/app_theme.dart';
import 'theme/colors.dart';
import 'screens/splash_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  SystemChrome.setPreferredOrientations([DeviceOrientation.portraitUp]);
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor: Colors.transparent,
    statusBarIconBrightness: Brightness.light,
  ));
  // Load OLED pref before first build so colors are correct from the start
  FColors.oled = await SettingsService.getOledMode();
  ThemeService.notifier.value = FColors.oled;
  await ScanForegroundService.init();
  runApp(const FSecurity());
}

class FSecurity extends StatefulWidget {
  const FSecurity({super.key});

  @override
  State<FSecurity> createState() => _FSecurityState();
}

class _FSecurityState extends State<FSecurity> {
  @override
  void initState() {
    super.initState();
    ThemeService.notifier.addListener(_onThemeChange);
  }

  void _onThemeChange() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    ThemeService.notifier.removeListener(_onThemeChange);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'F-Security',
      theme: AppTheme.build(),
      home: const SplashScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}
