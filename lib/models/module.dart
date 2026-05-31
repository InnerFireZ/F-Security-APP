import 'package:flutter/material.dart';

enum ModuleCategory { smb, network, web, iot, brute, recon, exploit, fire, util }

// What a module needs to start (can be supplied by a previous step)
enum ChainInput { none, target }

// What a module produces (available to subsequent steps)
enum ChainOutput { none, sessionDir, credentials, hashes }

class Module {
  final int id;
  final String name;
  final String description;
  final String script;
  final IconData icon;
  final ModuleCategory category;
  final String tag;
  final ChainInput chainInput;
  final ChainOutput chainOutput;
  // True = prompts for user input (interface picker, URL, etc.) — warn in pipeline
  final bool requiresInteraction;

  const Module({
    required this.id,
    required this.name,
    required this.description,
    required this.script,
    required this.icon,
    required this.category,
    required this.tag,
    this.chainInput = ChainInput.none,
    this.chainOutput = ChainOutput.none,
    this.requiresInteraction = false,
  });
}
