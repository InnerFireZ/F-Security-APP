import 'dart:async';
import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

// Must be a top-level function with this pragma for the background isolate.
@pragma('vm:entry-point')
void _fsecTaskCallback() {
  FlutterForegroundTask.setTaskHandler(_FsecTaskHandler());
}

class _FsecTaskHandler extends TaskHandler {
  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {}

  @override
  void onRepeatEvent(DateTime timestamp) {}

  @override
  Future<void> onDestroy(DateTime timestamp) async {}
}

class ScanForegroundService {
  ScanForegroundService._();

  static final _notif = FlutterLocalNotificationsPlugin();
  static int _notifId = 0;
  static bool _initialized = false;

  // ── Init ─────────────────────────────────────────────────────────────────

  static Future<void> init() async {
    if (_initialized) return;

    FlutterForegroundTask.initCommunicationPort();

    FlutterForegroundTask.init(
      androidNotificationOptions: AndroidNotificationOptions(
        channelId: 'fsec_scan_running',
        channelName: 'F-Security Active Scan',
        channelDescription: 'Shown while a scan is running in background',
        channelImportance: NotificationChannelImportance.LOW,
        priority: NotificationPriority.LOW,
      ),
      iosNotificationOptions: const IOSNotificationOptions(),
      foregroundTaskOptions: ForegroundTaskOptions(
        eventAction: ForegroundTaskEventAction.nothing(),
        autoRunOnBoot: false,
        allowWakeLock: false,
        allowWifiLock: false,
      ),
    );

    await _notif.initialize(
      const InitializationSettings(
        android: AndroidInitializationSettings('@mipmap/ic_launcher'),
      ),
    );

    // Request POST_NOTIFICATIONS permission (Android 13+, no-op on older).
    final androidPlugin = _notif
        .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin>();
    await androidPlugin?.requestNotificationsPermission();

    _initialized = true;
  }

  // ── Service lifecycle ─────────────────────────────────────────────────────

  /// Start (or update if already running) the foreground service with [label].
  static Future<void> startScan(String label) async {
    if (!_initialized) return;
    if (await FlutterForegroundTask.isRunningService) {
      await FlutterForegroundTask.updateService(
        notificationTitle: 'fsec  |  scanning',
        notificationText: label,
      );
    } else {
      await FlutterForegroundTask.startService(
        serviceId: 1001,
        notificationTitle: 'fsec  |  scanning',
        notificationText: label,
        callback: _fsecTaskCallback,
      );
    }
  }

  /// Update the status-bar label without changing the service state.
  static Future<void> updateLabel(String label) async {
    if (!_initialized) return;
    if (await FlutterForegroundTask.isRunningService) {
      await FlutterForegroundTask.updateService(
        notificationTitle: 'fsec  |  scanning',
        notificationText: label,
      );
    }
  }

  /// Scan ended naturally — stop service and fire a completion notification.
  static Future<void> completeScan(String label) async {
    await stopScan();
    await _showDoneNotification(label);
  }

  /// User aborted — stop service silently, no notification.
  static Future<void> stopScan() async {
    if (!_initialized) return;
    if (await FlutterForegroundTask.isRunningService) {
      await FlutterForegroundTask.stopService();
    }
  }

  // ── Flipper Zero alert ────────────────────────────────────────────────────

  static Future<void> showFlipperAlert(String mac, String name) async {
    if (!_initialized) return;
    final id = ++_notifId;
    await _notif.show(
      id,
      'Flipper Zero Detected',
      '$name  ·  $mac',
      const NotificationDetails(
        android: AndroidNotificationDetails(
          'fsec_flipper_alert',
          'F-Security Flipper Alert',
          channelDescription: 'Fired when a Flipper Zero is detected nearby',
          importance: Importance.max,
          priority: Priority.max,
          playSound: true,
          enableVibration: true,
        ),
      ),
    );
  }

  // ── Deauth attack alert ───────────────────────────────────────────────────

  static Future<void> showDeauthAlert(
      String attacker, String ssid, String burst) async {
    if (!_initialized) return;
    final id = ++_notifId;
    await _notif.show(
      id,
      'Deauth Attack Detected',
      '$attacker  ·  SSID: $ssid  ·  $burst frames',
      const NotificationDetails(
        android: AndroidNotificationDetails(
          'fsec_deauth_alert',
          'F-Security Deauth Alert',
          channelDescription:
              'Fired when a deauthentication attack is detected',
          importance: Importance.max,
          priority: Priority.max,
          playSound: true,
          enableVibration: true,
        ),
      ),
    );
  }

  // ── Completion notification ───────────────────────────────────────────────

  static Future<void> _showDoneNotification(String label) async {
    final id = ++_notifId;
    await _notif.show(
      id,
      'Scan complete',
      label,
      const NotificationDetails(
        android: AndroidNotificationDetails(
          'fsec_scan_done',
          'F-Security Scan Complete',
          channelDescription: 'Fired when a scan finishes',
          importance: Importance.high,
          priority: Priority.high,
          playSound: true,
          enableVibration: true,
        ),
      ),
    );
  }
}
