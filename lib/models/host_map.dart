class DiscoveredPort {
  final int number;
  final String protocol;
  final String? service;

  const DiscoveredPort({
    required this.number,
    required this.protocol,
    this.service,
  });

  @override
  String toString() => '$number/$protocol${service != null ? ' ($service)' : ''}';
}

class DiscoveredHost {
  final String ip;
  final List<DiscoveredPort> ports;
  final bool hasCredentials;

  const DiscoveredHost({
    required this.ip,
    required this.ports,
    this.hasCredentials = false,
  });
}

class HostMap {
  final String sessionName;
  final String sessionPath;
  final List<DiscoveredHost> hosts;

  const HostMap({
    required this.sessionName,
    required this.sessionPath,
    required this.hosts,
  });

  bool get isEmpty => hosts.isEmpty;
}
