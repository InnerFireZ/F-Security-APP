import 'package:shared_preferences/shared_preferences.dart';
import 'nethunter_service.dart';

class SettingsService {
  static const _chrootKey       = 'chroot_path';
  static const _fontSizeKey     = 'terminal_font_size';
  static const _wordlistKey     = 'brute_wordlist';
  static const defaultWordlist  = '/usr/share/wordlists/rockyou.txt';
  static const _nucleiConcKey   = 'nuclei_concurrency';
  static const defaultNucleiConc = 20;
  static const _termThemeKey    = 'terminal_theme';
  static const defaultTermTheme = 'grey';

  static String wordlistPath  = defaultWordlist;
  static int nucleiConc       = defaultNucleiConc;

  static Future<void> load() async {
    final prefs = await SharedPreferences.getInstance();
    NetHunterService.chrootPath =
        prefs.getString(_chrootKey) ?? '/data/local/nhsystem/kali-arm64';
    wordlistPath = prefs.getString(_wordlistKey) ?? defaultWordlist;
    nucleiConc   = prefs.getInt(_nucleiConcKey)  ?? defaultNucleiConc;
  }

  static Future<void> saveChrootPath(String path) async {
    NetHunterService.chrootPath = path;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_chrootKey, path);
  }

  static Future<double> getFontSize() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getDouble(_fontSizeKey) ?? 9.0;
  }

  static Future<void> saveFontSize(double size) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setDouble(_fontSizeKey, size);
  }

  static Future<String> getWordlist() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_wordlistKey) ?? defaultWordlist;
  }

  static Future<void> saveWordlist(String path) async {
    wordlistPath = path;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_wordlistKey, path);
  }

  static Future<int> getNucleiConc() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getInt(_nucleiConcKey) ?? defaultNucleiConc;
  }

  static Future<void> saveNucleiConc(int value) async {
    nucleiConc = value;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_nucleiConcKey, value);
  }

  static Future<String> getTerminalTheme() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_termThemeKey) ?? defaultTermTheme;
  }

  static Future<void> saveTerminalTheme(String theme) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_termThemeKey, theme);
  }

  static const _edgeGlowKey    = 'edge_glow_color';
  static const defaultEdgeGlow = 'auto';

  static Future<String> getEdgeGlow() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_edgeGlowKey) ?? defaultEdgeGlow;
  }

  static Future<void> saveEdgeGlow(String color) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_edgeGlowKey, color);
  }

  static const _oledKey = 'oled_mode';

  static Future<bool> getOledMode() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(_oledKey) ?? false;
  }

  static Future<void> saveOledMode(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_oledKey, value);
  }
}
