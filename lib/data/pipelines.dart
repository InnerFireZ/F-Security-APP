import 'package:flutter/material.dart';
import 'modules.dart';
import '../models/pipeline.dart';

class PipelineTemplate {
  final String id;
  final String name;
  final String description;
  final String goal;
  final String phase;
  final IconData icon;
  final Color color;
  final List<int> moduleIds;

  const PipelineTemplate({
    required this.id,
    required this.name,
    required this.description,
    required this.goal,
    required this.phase,
    required this.icon,
    required this.color,
    required this.moduleIds,
  });

  List<PipelineStep> buildSteps() {
    final steps = <PipelineStep>[];
    for (final mid in moduleIds) {
      final m = kModules.where((m) => m.id == mid).firstOrNull;
      // A template referencing an unknown module id is a developer error — fail
      // loudly in debug instead of silently dropping a pipeline phase.
      assert(m != null, 'Pipeline template references unknown module id $mid');
      if (m != null) steps.add(PipelineStep(module: m));
    }
    return steps;
  }
}

const List<PipelineTemplate> kPipelineTemplates = [
  PipelineTemplate(
    id: 'external_recon',
    name: 'External Recon',
    description: 'OSINT → DNS/AD → SSL/TLS → Web fingerprint → Vuln scan → Exploit',
    goal: 'Map external attack surface and discover public-facing weaknesses',
    phase: 'EXTERNAL',
    icon: Icons.travel_explore,
    color: Color(0xFF00CC66),
    moduleIds: [43, 12, 11, 8, 6, 16],
  ),
  PipelineTemplate(
    id: 'internal_lan',
    name: 'Internal LAN Sweep',
    description: 'Masscan → Nmap → Fscan → Nuclei → SSH audit → Brute-force',
    goal: 'Full internal network enumeration and vulnerability discovery',
    phase: 'INTERNAL',
    icon: Icons.lan,
    color: Color(0xFF00CCFF),
    moduleIds: [49, 3, 2, 6, 32, 10],
  ),
  PipelineTemplate(
    id: 'ad_attack',
    name: 'Active Directory Chain',
    description: 'Nmap → DNS/AD → Crackmap → Enum4linux → LDAP dump → Kerberoast → Relay → Crack → PTH → PrivEsc',
    goal: 'Full AD compromise via Kerberoasting, NTLM relay, and pass-the-hash',
    phase: 'AD',
    icon: Icons.account_tree,
    color: Color(0xFFCC88FF),
    moduleIds: [3, 12, 1, 42, 48, 33, 17, 26, 34, 41, 39, 44, 46],
  ),
  PipelineTemplate(
    id: 'smb_windows',
    name: 'SMB / Windows Attack',
    description: 'Nmap → Crackmap → Enum4linux → Brute-force → NTLM relay → Impacket → Hash crack',
    goal: 'SMB null-session enum, credential spraying, and lateral movement',
    phase: 'SMB',
    icon: Icons.storage,
    color: Color(0xFF00CCFF),
    moduleIds: [3, 1, 42, 10, 26, 39, 41],
  ),
  PipelineTemplate(
    id: 'web_pentest',
    name: 'Web Application Pentest',
    description: 'Web recon → WordPress → SQLi → Vuln scan → Credential brute',
    goal: 'Web application security assessment following OWASP methodology',
    phase: 'WEB',
    icon: Icons.language,
    color: Color(0xFFCC88FF),
    moduleIds: [8, 47, 40, 6, 10],
  ),
  PipelineTemplate(
    id: 'wifi_assault',
    name: 'WiFi Assault',
    description: 'Probe sniff → WPA/WPS crack → Deauth clients → ARP MITM → Credential harvest',
    goal: 'Wireless network compromise and client-side credential interception',
    phase: 'WIFI',
    icon: Icons.wifi,
    color: Color(0xFFFFAA00),
    moduleIds: [23, 27, 19, 25, 28],
  ),
  PipelineTemplate(
    id: 'iot_ot',
    name: 'IoT / OT Discovery',
    description: 'IoT scan → SNMP walk → Printer exploit → Camera takeover → BLE recon',
    goal: 'Discover and probe IoT, SCADA, and OT/ICS devices on the network',
    phase: 'IoT',
    icon: Icons.device_hub,
    color: Color(0xFFFFAA00),
    moduleIds: [9, 36, 30, 4, 38, 37],
  ),
  PipelineTemplate(
    id: 'post_exploit',
    name: 'Post-Exploitation',
    description: 'PrivEsc enum → Secrets dump → C2 shell → Pivot → ADCS abuse',
    goal: 'Maximize access after initial compromise via PrivEsc and persistence',
    phase: 'POST',
    icon: Icons.manage_accounts,
    color: Color(0xFFFF3333),
    moduleIds: [46, 39, 15, 45, 35],
  ),
  PipelineTemplate(
    id: 'full_apt',
    name: 'Full APT Kill Chain',
    description: 'OSINT → Recon → Port scan → Vuln scan → Exploit → Brute → Dump → PrivEsc → C2 → Pivot',
    goal: 'Complete APT simulation — all phases from reconnaissance to persistence',
    phase: 'APT',
    icon: Icons.local_fire_department,
    color: Color(0xFFFF3333),
    moduleIds: [43, 12, 7, 49, 3, 6, 16, 10, 39, 46, 15, 45],
  ),
  PipelineTemplate(
    id: 'quick_audit',
    name: 'Quick Network Audit',
    description: 'Masscan → Nmap → Nuclei vuln scan → SSH audit → Credential brute',
    goal: 'Fast, broad assessment of SOHO or branch-office network — discover open ports, misconfigs, and weak credentials in minutes',
    phase: 'INTERNAL',
    icon: Icons.speed,
    color: Color(0xFF00CCFF),
    moduleIds: [49, 3, 6, 32, 10],
  ),
  PipelineTemplate(
    id: 'ntlm_harvest',
    name: 'NTLM Hash Harvest',
    description: 'Nmap → LLMNR poison → DHCPv6 attack → NTLM relay → Hash crack → Lateral move',
    goal: 'Passively capture NTLMv2 hashes via network poisoning, relay to services, crack offline, and move laterally',
    phase: 'AD',
    icon: Icons.key,
    color: Color(0xFFCC88FF),
    moduleIds: [3, 17, 34, 26, 41, 39],
  ),
  PipelineTemplate(
    id: 'stealth_recon',
    name: 'Internal Stealth Survey',
    description: 'Nmap → SNMP walk → Enum4linux → LDAP dump → Kerberos enum → Crackmap',
    goal: 'Slow, passive internal enumeration — no exploits, no brute-force; build a complete asset inventory without triggering IDS',
    phase: 'INTERNAL',
    icon: Icons.visibility_off,
    color: Color(0xFF00CC66),
    moduleIds: [3, 36, 42, 48, 33, 1],
  ),
];
