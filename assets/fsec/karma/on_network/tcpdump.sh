#!/bin/bash
# Args: $1=iface  $2=essid
# Env:  KARMA_OUT

IFACE="$1"
ESSID="${2:-unknown}"
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
TIME="$(date +'%H:%M:%S_%d.%m.%Y')"
mkdir -p "$OUT"

PCAP="$OUT/capture_${ESSID}_${TIME}_${RANDOM}.pcap"

printf '\n\033[1;33m  ┌── TCPDUMP ────────────────────────────────────┐\033[0m\n'
printf '\033[1;33m  │\033[0m  %-8s  SSID: \033[1;36m%-28s\033[0m\033[1;33m│\033[0m\n' "$IFACE" "$ESSID"
printf '\033[1;33m  │\033[0m  Saving: \033[2m%s\033[0m\n' "$(basename "$PCAP")"
printf '\033[1;33m  └─────────────────────────────────────────────────\033[0m\n\n'

tcpdump -i "$IFACE" -nn -w "$PCAP" 2>/dev/null
