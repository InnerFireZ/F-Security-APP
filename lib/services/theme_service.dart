import 'package:flutter/foundation.dart';
import '../theme/colors.dart';

class ThemeService {
  static final notifier = ValueNotifier<bool>(false);

  static void setOled(bool v) {
    FColors.oled = v;
    notifier.value = v;
  }
}
