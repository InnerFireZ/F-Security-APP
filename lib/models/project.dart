class Project {
  final int? id;
  final String name;
  final String target;
  final DateTime created;
  final DateTime updated;
  final bool isActive;
  final int sessionCount;

  const Project({
    this.id,
    required this.name,
    required this.target,
    required this.created,
    required this.updated,
    this.isActive = false,
    this.sessionCount = 0,
  });

  Project copyWith({bool? isActive}) => Project(
    id: id, name: name, target: target,
    created: created, updated: updated,
    isActive: isActive ?? this.isActive,
    sessionCount: sessionCount,
  );

  Map<String, dynamic> toMap() => {
    'name': name,
    'target': target,
    'created': created.millisecondsSinceEpoch,
    'updated': updated.millisecondsSinceEpoch,
    'is_active': isActive ? 1 : 0,
  };

  factory Project.fromMap(Map<String, dynamic> m, {int sessionCount = 0}) => Project(
    id: m['id'] as int?,
    name: m['name'] as String,
    target: m['target'] as String,
    created: DateTime.fromMillisecondsSinceEpoch(m['created'] as int),
    updated: DateTime.fromMillisecondsSinceEpoch(m['updated'] as int),
    isActive: (m['is_active'] as int?) == 1,
    sessionCount: sessionCount,
  );
}

class ProjectSession {
  final int? id;
  final int projectId;
  final String folderName;
  final String? moduleName;
  final DateTime created;

  const ProjectSession({
    this.id,
    required this.projectId,
    required this.folderName,
    this.moduleName,
    required this.created,
  });

  factory ProjectSession.fromMap(Map<String, dynamic> m) => ProjectSession(
    id: m['id'] as int?,
    projectId: m['project_id'] as int,
    folderName: m['folder_name'] as String,
    moduleName: m['module_name'] as String?,
    created: DateTime.fromMillisecondsSinceEpoch(m['created'] as int),
  );
}

class ProjectHost {
  final int? id;
  final int projectId;
  final String ip;
  final List<ProjectPort> ports;

  const ProjectHost({
    this.id,
    required this.projectId,
    required this.ip,
    this.ports = const [],
  });
  // No fromMap: hosts are loaded via ProjectService.getHosts, which populates
  // ports from the separate ports table. A fromMap here would silently yield
  // ports == [] and mislead every host.ports.length reader.
}

class ProjectPort {
  final int? id;
  final int hostId;
  final int number;
  final String protocol;
  final String? service;

  const ProjectPort({
    this.id,
    required this.hostId,
    required this.number,
    required this.protocol,
    this.service,
  });

  factory ProjectPort.fromMap(Map<String, dynamic> m) => ProjectPort(
    id: m['id'] as int?,
    hostId: m['host_id'] as int,
    number: m['number'] as int,
    protocol: m['protocol'] as String,
    service: m['service'] as String?,
  );
}

class Credential {
  final int? id;
  final int projectId;
  final String hostIp;
  final String username;
  final String password;
  final String? service;
  final String? sourceSession;
  final DateTime foundAt;

  const Credential({
    this.id,
    required this.projectId,
    required this.hostIp,
    required this.username,
    required this.password,
    this.service,
    this.sourceSession,
    required this.foundAt,
  });

  factory Credential.fromMap(Map<String, dynamic> m) => Credential(
    id: m['id'] as int?,
    projectId: m['project_id'] as int,
    hostIp: m['host_ip'] as String,
    username: m['username'] as String,
    password: m['password'] as String,
    service: m['service'] as String?,
    sourceSession: m['source_session'] as String?,
    foundAt: DateTime.fromMillisecondsSinceEpoch(m['found_at'] as int),
  );

  Map<String, dynamic> toMap() => {
    'project_id': projectId,
    'host_ip': hostIp,
    'username': username,
    'password': password,
    'service': service,
    'source_session': sourceSession,
    'found_at': foundAt.millisecondsSinceEpoch,
  };
}

class ProjectNote {
  final int? id;
  final int projectId;
  final String content;
  final DateTime created;

  const ProjectNote({
    this.id,
    required this.projectId,
    required this.content,
    required this.created,
  });

  factory ProjectNote.fromMap(Map<String, dynamic> m) => ProjectNote(
    id: m['id'] as int?,
    projectId: m['project_id'] as int,
    content: m['content'] as String,
    created: DateTime.fromMillisecondsSinceEpoch(m['created'] as int),
  );
}
