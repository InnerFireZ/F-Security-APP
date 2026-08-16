import 'package:flutter/material.dart';
import '../models/host_map.dart';
import '../services/host_map_service.dart';
import '../theme/colors.dart';
import 'adhoc_terminal_screen.dart';

class HostMapScreen extends StatefulWidget {
  final String sessionPath;
  final String sessionName;

  const HostMapScreen({
    super.key,
    required this.sessionPath,
    required this.sessionName,
  });

  @override
  State<HostMapScreen> createState() => _HostMapScreenState();
}

class _HostMapScreenState extends State<HostMapScreen> {
  HostMap? _map;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final map = await HostMapService.parse(widget.sessionPath, widget.sessionName);
      if (!mounted) return;
      setState(() { _map = map; _loading = false; });
    } catch (e) {
      if (!mounted) return;
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  void _showHostSheet(DiscoveredHost host) {
    showModalBottomSheet(
      context: context,
      backgroundColor: FColors.bgCard,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(12)),
      ),
      builder: (_) => _HostSheet(host: host),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: FColors.bg,
      appBar: AppBar(
        backgroundColor: FColors.bgCard,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, color: FColors.cyan, size: 18),
          onPressed: () => Navigator.pop(context),
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('HOST MAP',
              style: TextStyle(fontFamily: 'monospace', color: FColors.cyan, letterSpacing: 2, fontSize: 13)),
            Text(widget.sessionName,
              style: const TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 9)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, color: FColors.cyan, size: 20),
            onPressed: _load,
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: FColors.cyan.op(0.25)),
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: FColors.cyan, strokeWidth: 1.5))
          : _error != null
              ? Center(child: Text(_error!,
                  style: const TextStyle(fontFamily: 'monospace', color: FColors.red, fontSize: 11)))
              : _map!.isEmpty
                  ? const Center(child: Text(
                      'No hosts found.\nRun Nmap or Fscan first.',
                      textAlign: TextAlign.center,
                      style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 12, height: 1.8),
                    ))
                  : _buildGrid(),
    );
  }

  Widget _buildGrid() {
    final hosts = _map!.hosts;
    final totalPorts = hosts.fold(0, (s, h) => s + h.ports.length);
    final withCreds = hosts.where((h) => h.hasCredentials).length;

    return Column(
      children: [
        // Summary bar
        Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          color: FColors.bgPanel,
          child: Row(
            children: [
              _StatChip(label: 'HOSTS', value: '${hosts.length}', color: FColors.cyan),
              const SizedBox(width: 12),
              _StatChip(label: 'PORTS', value: '$totalPorts', color: FColors.textSecondary),
              if (withCreds > 0) ...[
                const SizedBox(width: 12),
                _StatChip(label: 'CREDS', value: '$withCreds', color: FColors.green),
              ],
              const Spacer(),
              const Text('tap to inspect',
                style: TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim)),
            ],
          ),
        ),
        // Grid
        Expanded(
          child: GridView.builder(
            padding: const EdgeInsets.all(10),
            gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: MediaQuery.of(context).size.width > 600 ? 3 : 2,
              crossAxisSpacing: 8,
              mainAxisSpacing: 8,
              childAspectRatio: 1.55,
            ),
            itemCount: hosts.length,
            itemBuilder: (_, i) => _HostCard(
              host: hosts[i],
              onTap: () => _showHostSheet(hosts[i]),
            ),
          ),
        ),
      ],
    );
  }
}

// ── Stat chip ─────────────────────────────────────────────────────────────────

class _StatChip extends StatelessWidget {
  final String label;
  final String value;
  final Color color;
  const _StatChip({required this.label, required this.value, required this.color});

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Text(value, style: TextStyle(fontFamily: 'monospace', fontSize: 13, color: color, fontWeight: FontWeight.bold)),
      const SizedBox(width: 4),
      Text(label, style: const TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim)),
    ],
  );
}

// ── Host card ─────────────────────────────────────────────────────────────────

class _HostCard extends StatelessWidget {
  final DiscoveredHost host;
  final VoidCallback onTap;
  const _HostCard({required this.host, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final hasCreds = host.hasCredentials;
    final borderColor = hasCreds ? FColors.green : FColors.cyan.op(0.3);
    final topPorts = host.ports.take(6).map((p) => '${p.number}').join('  ');
    final extra = host.ports.length > 6 ? '+${host.ports.length - 6}' : '';

    return GestureDetector(
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          color: FColors.bgCard,
          border: Border.all(color: borderColor, width: 1),
          borderRadius: BorderRadius.circular(4),
          boxShadow: hasCreds
              ? [BoxShadow(color: FColors.green.op(0.1), blurRadius: 10)]
              : null,
        ),
        padding: const EdgeInsets.all(10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // IP + creds badge
            Row(
              children: [
                Icon(
                  hasCreds ? Icons.lock_open : Icons.computer,
                  size: 12,
                  color: hasCreds ? FColors.green : FColors.textDim,
                ),
                const SizedBox(width: 5),
                Expanded(
                  child: Text(
                    host.ip,
                    style: TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      color: hasCreds ? FColors.green : FColors.textPrimary,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (hasCreds)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                    decoration: BoxDecoration(
                      color: FColors.green.op(0.15),
                      border: Border.all(color: FColors.green.op(0.4)),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: const Text('CREDS',
                      style: TextStyle(fontFamily: 'monospace', fontSize: 7, color: FColors.green)),
                  ),
              ],
            ),
            const Spacer(),
            // Port count
            Text(
              '${host.ports.length} open port${host.ports.length == 1 ? '' : 's'}',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.textDim),
            ),
            const SizedBox(height: 4),
            // Port numbers
            if (topPorts.isNotEmpty)
              Text(
                extra.isNotEmpty ? '$topPorts  $extra' : topPorts,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.cyan),
                overflow: TextOverflow.ellipsis,
              ),
            const Spacer(),
            // Tap hint
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: const [
                Text('INSPECT ›',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 8, color: FColors.textDim)),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

// ── Host port sheet ───────────────────────────────────────────────────────────

class _HostSheet extends StatelessWidget {
  final DiscoveredHost host;
  const _HostSheet({required this.host});

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.55,
      minChildSize: 0.35,
      maxChildSize: 0.92,
      expand: false,
      builder: (_, controller) => Column(
        children: [
          // Drag handle
          Container(
            margin: const EdgeInsets.only(top: 10, bottom: 6),
            width: 36,
            height: 3,
            decoration: BoxDecoration(
              color: FColors.textDim,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          // Header
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 10),
            child: Row(
              children: [
                Icon(
                  host.hasCredentials ? Icons.lock_open : Icons.computer,
                  color: host.hasCredentials ? FColors.green : FColors.cyan,
                  size: 16,
                ),
                const SizedBox(width: 10),
                Text(host.ip,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 15, color: FColors.cyan)),
                if (host.hasCredentials) ...[
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: FColors.green.op(0.15),
                      border: Border.all(color: FColors.green.op(0.4)),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: const Text('CREDS',
                      style: TextStyle(fontFamily: 'monospace', fontSize: 8, color: FColors.green)),
                  ),
                ],
                const Spacer(),
                Text('${host.ports.length} ports',
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
              ],
            ),
          ),
          Container(height: 1, color: FColors.cyan.op(0.15), margin: const EdgeInsets.symmetric(horizontal: 16)),
          // Port list
          Expanded(
            child: host.ports.isEmpty
                ? const Center(child: Text('No open ports recorded.',
                    style: TextStyle(fontFamily: 'monospace', color: FColors.textDim, fontSize: 11)))
                : ListView.builder(
                    controller: controller,
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    itemCount: host.ports.length,
                    itemBuilder: (_, i) {
                      final port = host.ports[i];
                      final cmd = HostMapService.actionCommand(host.ip, port);
                      final label = HostMapService.actionLabel(port.number);
                      return _PortRow(
                        port: port,
                        label: label,
                        hasAction: cmd != null,
                        onAction: cmd == null ? null : () {
                          Navigator.pop(context);
                          Navigator.push(context, MaterialPageRoute(
                            builder: (_) => AdHocTerminalScreen(
                              title: '${host.ip}:${port.number} — $label',
                              command: cmd,
                            ),
                          ));
                        },
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

class _PortRow extends StatelessWidget {
  final DiscoveredPort port;
  final String label;
  final bool hasAction;
  final VoidCallback? onAction;

  const _PortRow({
    required this.port,
    required this.label,
    required this.hasAction,
    this.onAction,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 3),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
      decoration: BoxDecoration(
        color: FColors.bg,
        border: Border.all(color: FColors.cyan.op(0.1)),
        borderRadius: BorderRadius.circular(3),
      ),
      child: Row(
        children: [
          SizedBox(
            width: 56,
            child: Text(
              '${port.number}/${port.protocol}',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.cyan),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(label,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textPrimary)),
          ),
          if (hasAction)
            GestureDetector(
              onTap: onAction,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: FColors.cyan.op(0.1),
                  border: Border.all(color: FColors.cyan.op(0.4)),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: const Text('RUN',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 9, color: FColors.cyan)),
              ),
            )
          else
            const Text('—',
              style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: FColors.textDim)),
        ],
      ),
    );
  }
}
