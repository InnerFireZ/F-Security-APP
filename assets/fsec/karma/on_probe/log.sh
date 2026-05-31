#!/bin/bash
# Args: $1=essid $2=sta $3=freq $4=signal $5=vendor
# Write to file only — karma.py already prints probes to terminal
OUT="${KARMA_OUT:-$(dirname "$0")/..}"
printf '[%s] essid="%s" sta=%s freq=%s signal=%s vendor="%s"\n' \
  "$(date +'%H:%M:%S_%d.%m.%Y')" "$1" "$2" "$3" "$4" "$5" \
  >> "$OUT/probes.log"
