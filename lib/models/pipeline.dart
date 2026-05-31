import 'module.dart';

class PipelineStep {
  final Module module;
  bool enabled;

  PipelineStep({required this.module, this.enabled = true});
}

class Pipeline {
  final String name;
  final List<PipelineStep> steps;
  final String target;
  final String domain;
  final int? projectId;
  final String? projectName;
  final bool karmaEnabled;
  final String karmaMode;  // 'wpa' | 'opn' | 'eap'
  final String karmaSsid;  // empty = auto-mirror
  final String karmaPass;  // WPA passphrase; empty = random/default

  Pipeline({
    required this.name,
    required this.steps,
    this.target = '',
    this.domain = '',
    this.projectId,
    this.projectName,
    this.karmaEnabled = false,
    this.karmaMode    = 'wpa',
    this.karmaSsid    = '',
    this.karmaPass    = '',
  });
}
