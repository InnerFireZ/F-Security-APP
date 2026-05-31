import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:sqflite/sqflite.dart';
import '../models/host_map.dart';
import '../models/project.dart';

class ProjectService {
  static Database? _db;

  static Future<void> init() async {
    if (_db != null) return;
    final dir = await getApplicationDocumentsDirectory();
    final dbPath = p.join(dir.path, 'fsecurity_projects.db');
    _db = await openDatabase(
      dbPath,
      version: 1,
      onCreate: (db, _) async {
        await db.execute('''
          CREATE TABLE projects (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            target   TEXT NOT NULL,
            created  INTEGER NOT NULL,
            updated  INTEGER NOT NULL,
            is_active INTEGER DEFAULT 0
          )
        ''');
        await db.execute('''
          CREATE TABLE sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            folder_name TEXT NOT NULL,
            module_name TEXT,
            created     INTEGER NOT NULL,
            UNIQUE(project_id, folder_name)
          )
        ''');
        await db.execute('''
          CREATE TABLE hosts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            ip         TEXT NOT NULL,
            UNIQUE(project_id, ip)
          )
        ''');
        await db.execute('''
          CREATE TABLE ports (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            number   INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            service  TEXT,
            UNIQUE(host_id, number, protocol)
          )
        ''');
        await db.execute('''
          CREATE TABLE credentials (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            host_ip        TEXT NOT NULL,
            username       TEXT NOT NULL,
            password       TEXT NOT NULL,
            service        TEXT,
            source_session TEXT,
            found_at       INTEGER NOT NULL,
            UNIQUE(project_id, host_ip, username, password)
          )
        ''');
        await db.execute('''
          CREATE TABLE notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            content    TEXT NOT NULL,
            created    INTEGER NOT NULL
          )
        ''');
      },
    );
  }

  static Database get _d {
    assert(_db != null, 'ProjectService.init() must be called first');
    return _db!;
  }

  // ── Projects ───────────────────────────────────────────────────────────────

  static Future<List<Project>> listProjects() async {
    final rows = await _d.rawQuery('''
      SELECT p.*, COUNT(s.id) AS session_count
      FROM projects p
      LEFT JOIN sessions s ON s.project_id = p.id
      GROUP BY p.id
      ORDER BY p.updated DESC
    ''');
    return rows.map((r) => Project.fromMap(r, sessionCount: r['session_count'] as int? ?? 0)).toList();
  }

  static Future<Project?> getActiveProject() async {
    final rows = await _d.query('projects', where: 'is_active = 1', limit: 1);
    if (rows.isEmpty) return null;
    return Project.fromMap(rows.first);
  }

  static Future<Project> createProject(String name, String target) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final id = await _d.insert('projects', {
      'name': name, 'target': target,
      'created': now, 'updated': now, 'is_active': 0,
    });
    return Project(
      id: id, name: name, target: target,
      created: DateTime.fromMillisecondsSinceEpoch(now),
      updated: DateTime.fromMillisecondsSinceEpoch(now),
    );
  }

  static Future<void> setActiveProject(int id) async {
    await _d.transaction((txn) async {
      await txn.update('projects', {'is_active': 0});
      await txn.update('projects', {'is_active': 1}, where: 'id = ?', whereArgs: [id]);
    });
  }

  static Future<void> clearActiveProject() async {
    await _d.update('projects', {'is_active': 0});
  }

  static Future<void> deleteProject(int id) async {
    await _d.delete('projects', where: 'id = ?', whereArgs: [id]);
  }

  static Future<void> updateProjectTimestamp(int id) async {
    await _d.update('projects',
      {'updated': DateTime.now().millisecondsSinceEpoch},
      where: 'id = ?', whereArgs: [id]);
  }

  // ── Sessions ───────────────────────────────────────────────────────────────

  static Future<void> attachSession(int projectId, String folderName, String? moduleName) async {
    await _d.insert('sessions', {
      'project_id': projectId,
      'folder_name': folderName,
      'module_name': moduleName,
      'created': DateTime.now().millisecondsSinceEpoch,
    }, conflictAlgorithm: ConflictAlgorithm.ignore);
    await updateProjectTimestamp(projectId);
  }

  static Future<List<ProjectSession>> getSessions(int projectId) async {
    final rows = await _d.query('sessions',
      where: 'project_id = ?', whereArgs: [projectId],
      orderBy: 'created DESC');
    return rows.map(ProjectSession.fromMap).toList();
  }

  // ── Hosts & Ports ──────────────────────────────────────────────────────────

  static Future<void> mergeHostMap(int projectId, HostMap map) async {
    await _d.transaction((txn) async {
      for (final host in map.hosts) {
        // Insert host (ignore if already exists)
        await txn.insert('hosts', {'project_id': projectId, 'ip': host.ip},
          conflictAlgorithm: ConflictAlgorithm.ignore);

        // Get host id
        final hostRows = await txn.query('hosts',
          columns: ['id'], where: 'project_id = ? AND ip = ?',
          whereArgs: [projectId, host.ip]);
        if (hostRows.isEmpty) continue;
        final hostId = hostRows.first['id'] as int;

        // Merge ports
        for (final port in host.ports) {
          // Use replace so that service names discovered later (e.g. nmap after
          // fscan) overwrite the earlier null/empty value.
          await txn.insert('ports', {
            'host_id': hostId,
            'number': port.number,
            'protocol': port.protocol,
            'service': port.service,
          }, conflictAlgorithm: ConflictAlgorithm.replace);
        }
      }
    });
  }

  static Future<List<ProjectHost>> getHosts(int projectId) async {
    final hostRows = await _d.query('hosts',
      where: 'project_id = ?', whereArgs: [projectId],
      orderBy: 'ip');

    final hosts = <ProjectHost>[];
    for (final hr in hostRows) {
      final hostId = hr['id'] as int;
      final portRows = await _d.query('ports',
        where: 'host_id = ?', whereArgs: [hostId],
        orderBy: 'number');
      hosts.add(ProjectHost(
        id: hostId,
        projectId: projectId,
        ip: hr['ip'] as String,
        ports: portRows.map(ProjectPort.fromMap).toList(),
      ));
    }
    return hosts;
  }

  // ── Credentials ────────────────────────────────────────────────────────────

  static Future<void> importCredentials(
      int projectId, String sessionFolder, String bruteTxt) async {
    // Hydra format: [port][service] host: <ip>   login: <user>   password: <pass>
    final re = RegExp(
      r'\[(\d+)\]\[(\w+)\]\s+host:\s+(\d+\.\d+\.\d+\.\d+)\s+login:\s+(\S+)\s+password:\s+(.+)',
    );
    final now = DateTime.now().millisecondsSinceEpoch;
    await _d.transaction((txn) async {
      for (final line in bruteTxt.split('\n')) {
        final m = re.firstMatch(line.trim());
        if (m == null) continue;
        await txn.insert('credentials', {
          'project_id': projectId,
          'host_ip': m.group(3),
          'username': m.group(4),
          'password': m.group(5)!.trim(),
          'service': m.group(2),
          'source_session': sessionFolder,
          'found_at': now,
        }, conflictAlgorithm: ConflictAlgorithm.ignore);
      }
    });
  }

  // hashcat output: hash:password  /  john --show: user:password:uid:gid:...
  static final _crackedToolNoise = RegExp(
    r'^(Using |Created |Loaded |Remaining |Session |Press |Approaching |Resumed |Paused |'
    r'Warning|Error|NOTE:|INFO:|No pass|[0-9]+ password|[0-9]+ hash)',
    caseSensitive: false,
  );
  // Username must not contain spaces (tool noise lines have multi-word "users")
  static final _crackedUserRe = RegExp(r'^\S+$');

  static Future<void> importCracked(
      int projectId, String sessionFolder, String crackedTxt) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    await _d.transaction((txn) async {
      for (final line in crackedTxt.split('\n')) {
        final l = line.trim();
        if (l.isEmpty || l.startsWith('#') || l.startsWith('[')) continue;
        if (_crackedToolNoise.hasMatch(l)) continue;
        final parts = l.split(':');
        if (parts.length < 2) continue;
        final user = parts[0];
        if (!_crackedUserRe.hasMatch(user)) continue; // multi-word = tool noise
        if (user.length > 64) continue; // hash lines are long — skip
        // hashcat: hash:password (2 parts) / john --show: user:pass:uid:gid:... (>=3 parts)
        final pass = parts[1].trim();
        if (pass.isEmpty || pass == '*' || pass == '!') continue;
        await txn.insert('credentials', {
          'project_id': projectId,
          'host_ip': 'cracked',
          'username': user,
          'password': pass,
          'service': 'hash',
          'source_session': sessionFolder,
          'found_at': now,
        }, conflictAlgorithm: ConflictAlgorithm.ignore);
      }
    });
  }

  static Future<List<Credential>> getCredentials(int projectId) async {
    final rows = await _d.query('credentials',
      where: 'project_id = ?', whereArgs: [projectId],
      orderBy: 'found_at DESC');
    return rows.map(Credential.fromMap).toList();
  }

  // ── Notes ──────────────────────────────────────────────────────────────────

  static Future<void> addNote(int projectId, String content) async {
    await _d.insert('notes', {
      'project_id': projectId,
      'content': content.trim(),
      'created': DateTime.now().millisecondsSinceEpoch,
    });
    await updateProjectTimestamp(projectId);
  }

  static Future<void> deleteNote(int noteId) async {
    await _d.delete('notes', where: 'id = ?', whereArgs: [noteId]);
  }

  static Future<List<ProjectNote>> getNotes(int projectId) async {
    final rows = await _d.query('notes',
      where: 'project_id = ?', whereArgs: [projectId],
      orderBy: 'created DESC');
    return rows.map(ProjectNote.fromMap).toList();
  }

  // ── Utility: find latest results session folder name ───────────────────────
  static Future<String?> latestSessionFolder(String resultsPath) async {
    final r = await Process.run('su', ['-c', 'ls -1t "$resultsPath" 2>/dev/null | head -1']);
    final name = r.stdout.toString().trim();
    return name.isEmpty ? null : name;
  }

  // ── Network detection ──────────────────────────────────────────────────────
  // Returns list of {iface, cidr} maps for non-mobile interfaces (wlan*, eth*).
  // Calculates network address from host IP + prefix so the result is always
  // the network CIDR (e.g. 192.168.1.105/24 → 192.168.1.0/24).
  static Future<List<Map<String, String>>> detectNetworks() async {
    final r = await Process.run('su', ['-c',
      "ip -o -4 addr show 2>/dev/null | awk '{print \$2, \$4}'"
    ]);
    final lines = r.stdout.toString().trim().split('\n');
    final results = <Map<String, String>>[];

    for (final line in lines) {
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.length < 2) continue;
      final iface = parts[0];
      final cidr  = parts[1];

      // Only keep wlan and eth — skip lo, rmnet, ccmni, ap, p2p, dummy, etc.
      if (!RegExp(r'^(wlan|eth)\d').hasMatch(iface)) continue;

      final network = _cidrToNetwork(cidr);
      if (network == null) continue;
      results.add({'iface': iface, 'cidr': network});
    }
    return results;
  }

  // Convert host CIDR (e.g. 192.168.1.105/24) to network CIDR (192.168.1.0/24).
  static String? _cidrToNetwork(String cidr) {
    final slash = cidr.indexOf('/');
    if (slash < 0) return null;
    final ip     = cidr.substring(0, slash);
    final prefix = int.tryParse(cidr.substring(slash + 1));
    if (prefix == null) return null;
    final octets = ip.split('.');
    if (octets.length != 4) return null;
    var addr = 0;
    for (final o in octets) { addr = (addr << 8) | (int.tryParse(o) ?? 0); }
    final mask = prefix > 0 ? (~0 << (32 - prefix)) & 0xFFFFFFFF : 0;
    final net  = addr & mask;
    return '${(net >> 24) & 0xFF}.${(net >> 16) & 0xFF}.'
           '${(net >> 8) & 0xFF}.${net & 0xFF}/$prefix';
  }
}
