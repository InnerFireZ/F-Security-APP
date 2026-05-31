#!/usr/bin/env bash
# nuclei.sh — Nuclei LAN/IoT vulnerability scanner (rootless Android optimised)
source "$(dirname "$0")/../lib.sh"
require_tool nuclei "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

set -u

banner "NUCLEI" "fast vulnerability scanner · LAN / IoT optimised"

# ── Target ────────────────────────────────────────────────────────────────────
target="$(prompt_target)"

# ── Existing nmap.txt? ────────────────────────────────────────────────────────
_nmap_load="$(pick_nmap_file)"
if [[ -n "$_nmap_load" ]]; then
  outdir="${_nmap_load%%|*}"
  _nmap_txt="${_nmap_load##*|}"
  outfile="$outdir/nuclei.txt"
  hosts_file="$outdir/alive_hosts.txt"
  scan_file="$outdir/scan_targets.txt"
  nuclei_targets="$outdir/nuclei_targets.txt"
  : > "$scan_file"
  : > "$nuclei_targets"
  awk '/report for/{ip=$NF} /\/tcp.*open/{print ip}' "$_nmap_txt" \
    | sort -u > "$scan_file"
  # Web ports → full URLs so nuclei skips httpx probe; network ports → ip:port
  awk '/report for/{ip=$NF} /\/tcp.*open/{
      split($1,a,"/"); p=a[1]
      if (p==443||p==8443)                       print "https://"ip":"p
      else if (p==80||p==8080||p==8554||p==9100) print "http://"ip":"p
      else                                        print ip":"p
  }' "$_nmap_txt" | sort -u > "$nuclei_targets"
  _loaded=$(wc -l < "$scan_file")
  printf '  %s[SYS]%s Target  : %s%s%s  %s(from nmap.txt — %d host(s))%s\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}" "${DIM}" "$_loaded" "${RESET}"
  printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
  _skip_discovery=1
else
  outdir="$(make_outdir)"
  outfile="$outdir/nuclei.txt"
  hosts_file="$outdir/alive_hosts.txt"
  scan_file="$outdir/scan_targets.txt"
  nuclei_targets="$outdir/nuclei_targets.txt"
  : > "$scan_file"
  : > "$nuclei_targets"
  # Pipeline chain: prefer chain_ports.txt (exact open ports) over alive_hosts.txt
  if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_ports.txt" ]]; then
    _ap=$(wc -l < "${SESSION_DIR}/chain_ports.txt")
    printf '  %s[CHAIN]%s Building nuclei targets from %s known-open port(s)%s\n\n' \
      "${CYAN}" "${RESET}" "$_ap" "${RESET}"
    # Convert ip:port → http/https/raw targets
    while IFS=: read -r _ip _port; do
      case "$_port" in
        443|8443|4443) printf 'https://%s:%s\n' "$_ip" "$_port" ;;
        80|8080|8000|8888|9100|9200) printf 'http://%s:%s\n' "$_ip" "$_port" ;;
        *) printf '%s:%s\n' "$_ip" "$_port" ;;
      esac
    done < "${SESSION_DIR}/chain_ports.txt" > "$nuclei_targets" 2>/dev/null || true
    # Also populate scan_file with unique IPs
    cut -d: -f1 "${SESSION_DIR}/chain_ports.txt" | sort -u > "$scan_file" 2>/dev/null || true
    _skip_discovery=1
  elif [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/alive_hosts.txt" ]]; then
    cp "${SESSION_DIR}/alive_hosts.txt" "$scan_file"
    _ah=$(wc -l < "$scan_file" || echo 0)
    printf '  %s[CHAIN]%s Using %s discovered host(s) from alive_hosts.txt%s\n\n' \
      "${CYAN}" "${RESET}" "$_ah" "${RESET}"
    # Build nuclei targets from alive hosts with common ports
    while IFS= read -r _hst; do
      printf "http://%s:80\nhttps://%s:443\nhttp://%s:8080\nhttps://%s:8443\n%s:22\n%s:445\n%s:3389\n" \
        "$_hst" "$_hst" "$_hst" "$_hst" "$_hst" "$_hst" "$_hst"
    done < "$scan_file" > "$nuclei_targets" 2>/dev/null || true
    _skip_discovery=1
  else
    : > "$hosts_file"
    printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
    printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
    _skip_discovery=0
  fi
fi

# ── Template check + update ───────────────────────────────────────────────────
_tpl_dir="${HOME}/.config/nuclei/templates"
[[ ! -d "$_tpl_dir" ]] && _tpl_dir="${HOME}/nuclei-templates"
if [[ ! -d "$_tpl_dir" ]] || [[ -z "$(ls -A "$_tpl_dir" 2>/dev/null)" ]]; then
    printf '  %s[!]%s No nuclei templates found — downloading now...%s\n' \
        "${RED}" "${RESET}" "${RESET}"
    nuclei -update-templates 2>&1 | tail -5
    printf '\n'
else
    if [[ -z "${SESSION_DIR:-}" ]]; then
      printf '  %s>>%s Update nuclei templates? [y/N]: ' "${CYAN}" "${RESET}"
      read -r _upd
      if [[ "${_upd,,}" == "y" ]]; then
          printf '  %s[*]%s Updating templates...%s\n' "${CYAN}" "${RESET}" "${RESET}"
          nuclei -update-templates 2>&1 | tail -5
          printf '\n'
      fi
    else
      printf '  %s[CHAIN]%s Skipping template update in pipeline mode%s\n' "${CYAN}" "${RESET}" "${RESET}"
    fi
fi

# ── Live host discovery + port check ─────────────────────────────────────────
# Both paths produce:
#   scan_file       — unique IPs (for display)
#   nuclei_targets  — http://ip:port, https://ip:port, or ip:port per service

COMMON_PORTS="21,22,23,25,53,80,443,445,554,1883,3389,8080,8443,8554,9100"
MAX_PING_JOBS=50
PING_TIMEOUT=1

_fmt_target() {
    local _ip="$1" _port="$2"
    case "$_port" in
        443|8443)           echo "https://$_ip:$_port" ;;
        80|8080|8554|9100)  echo "http://$_ip:$_port"  ;;
        *)                  echo "$_ip:$_port"          ;;
    esac
}

if [[ "$_skip_discovery" -eq 0 ]]; then

if [[ "$target" == */* ]]; then
    # ── CIDR path ─────────────────────────────────────────────────────────────
    if check_tool nmap; then
        printf '  %s[*]%s nmap host+port discovery on %s...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"
        _disc_tmp="$outdir/_nmap_disc.tmp"
        nmap -sS -Pn -n -T4 -p "$COMMON_PORTS" --open \
             --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
             "$target" 2>/dev/null > "$_disc_tmp"
        awk '/report for/{ip=$NF} /open/{print ip; ip=""}' "$_disc_tmp" \
            | sort -u > "$scan_file"
        awk '/report for/{ip=$NF} /\/tcp.*open/{
            split($1,a,"/"); p=a[1]
            if (p==443||p==8443)                       print "https://"ip":"p
            else if (p==80||p==8080||p==8554||p==9100) print "http://"ip":"p
            else                                        print ip":"p
        }' "$_disc_tmp" | sort -u > "$nuclei_targets"
        rm -f "$_disc_tmp"
    else
        # Fallback: bash ping sweep
        network="${target%.*/*}"
        printf '  %s[*]%s Ping sweep on %s (up to %d parallel)...%s\n' "${CYAN}" "${RESET}" "$target" "$MAX_PING_JOBS" "${RESET}"
        lockfile="${hosts_file}.lock"
        touch "$lockfile"
        trap 'rm -f "$lockfile"' EXIT

        _ping_one() {
            local _ip="$1"
            if ping -c 1 -W "$PING_TIMEOUT" "$_ip" &>/dev/null; then
                { exec 9>"$lockfile"; flock -x 9
                  echo "$_ip" >> "$hosts_file"
                  flock -u 9; exec 9>&-; } 2>/dev/null
            fi
        }

        for i in $(seq 1 254); do
            _ping_one "${network}.${i}" &
            while (( $(jobs -r | wc -l) >= MAX_PING_JOBS )); do sleep 0.05; done
        done
        wait

        sort -t. -k4 -n "$hosts_file" -o "$hosts_file"
        alive=$(wc -l < "$hosts_file")
        printf '  %s[+]%s %d live host(s) found%s\n' "${GREEN}" "${RESET}" "$alive" "${RESET}"
        [[ "$alive" -eq 0 ]] && { printf '  %s[!] No live hosts.%s\n' "${RED}" "${RESET}"; exit 1; }

        printf '  %s[*]%s Checking for open ports (/dev/tcp)...%s\n' "${CYAN}" "${RESET}" "${RESET}"
        IFS=',' read -ra _ports <<< "$COMMON_PORTS"
        while IFS= read -r _ip; do
            _first=1
            for _port in "${_ports[@]}"; do
                if timeout 1 bash -c "echo > /dev/tcp/$_ip/$_port" 2>/dev/null; then
                    printf '  %s[+]%s %s — port %s open\n' "${GREEN}" "${RESET}" "$_ip" "$_port"
                    _fmt_target "$_ip" "$_port" >> "$nuclei_targets"
                    if [[ "$_first" -eq 1 ]]; then
                        echo "$_ip" >> "$scan_file"
                        _first=0
                    fi
                fi
            done
        done < "$hosts_file"
    fi

else
    # ── Single IP path ────────────────────────────────────────────────────────
    printf '  %s[*]%s Checking %s for open ports...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"

    if check_tool nmap; then
        _disc_tmp="$outdir/_nmap_disc.tmp"
        nmap -sS -Pn -n -T4 -p "$COMMON_PORTS" --open \
             --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
             "$target" 2>/dev/null > "$_disc_tmp"
        open_count=$(grep -c "/tcp" "$_disc_tmp" 2>/dev/null) || open_count=0
        awk '/\/tcp.*open/{
            split($1,a,"/"); p=a[1]
            if (p==443||p==8443)                       print "https://'"$target"':"p
            else if (p==80||p==8080||p==8554||p==9100) print "http://'"$target"':"p
            else                                        print "'"$target"':"p
        }' "$_disc_tmp" | sort -u > "$nuclei_targets"
        rm -f "$_disc_tmp"
    else
        open_count=0
        IFS=',' read -ra _ports <<< "$COMMON_PORTS"
        for _port in "${_ports[@]}"; do
            if timeout 1 bash -c "echo > /dev/tcp/$target/$_port" 2>/dev/null; then
                (( open_count++ ))
                _fmt_target "$target" "$_port" >> "$nuclei_targets"
            fi
        done
    fi

    if [[ "$open_count" -eq 0 ]]; then
        printf '  %s[!] No open ports found on %s — skipping.%s\n' "${RED}" "$target" "${RESET}"
        exit 1
    fi
    printf '  %s[+]%s %d open port(s) on %s%s\n' "${GREEN}" "${RESET}" "$open_count" "$target" "${RESET}"
    echo "$target" > "$scan_file"
fi

fi  # _skip_discovery

# ── Validate we have something to scan ───────────────────────────────────────
scan_count=$(wc -l < "$scan_file")
if [[ "$scan_count" -eq 0 ]]; then
    printf '  %s[!] No live hosts with open ports found. Exiting.%s\n' "${RED}" "${RESET}"
    exit 1
fi
echo
printf '  %s[+]%s %d host(s) queued for nuclei%s\n' "${GREEN}" "${RESET}" "$scan_count" "${RESET}"
sed 's/^/      /' "$scan_file"
if [[ -s "$nuclei_targets" ]]; then
    _ep_count=$(wc -l < "$nuclei_targets")
    _web_prev=$(grep -cE '^https?://' "$nuclei_targets" 2>/dev/null || true)
    _net_prev=$(( _ep_count - _web_prev ))
    printf '  %s[*]%s %d endpoint(s): %s%d web%s + %s%d network%s\n' \
        "${DIM}" "${RESET}" "$_ep_count" \
        "${CYAN}" "$_web_prev" "${RESET}" \
        "${GREEN}" "$_net_prev" "${RESET}"
fi
printf '\n'

# ── Scan mode ─────────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  SCAN MODE                                       │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Quick     critical+high severity, fast\n'                         "${CYAN}" "${RESET}"
printf '  %s[02]%s ▶  LAN/IoT   default-logins, exposure, misconfiguration %s(recommended)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[03]%s ▶  Full      all templates, reduced rate %s(slow on phone)%s\n'      "${YELLOW}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[04]%s ▶  Custom    enter flags manually\n'                                 "${DIM}" "${RESET}"
printf '\n'
if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r _mode
  _mode="${_mode:-2}"
  echo
else
  _mode=2
  printf '  %s[CHAIN]%s Mode: LAN/IoT (pipeline auto-select)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
fi

# Base concurrency from app settings (injected as $NUCLEI_CONC, default 20)
_BASE_CONC="${NUCLEI_CONC:-20}"
CONCURRENCY="$_BASE_CONC"
RATE=$(( _BASE_CONC * 5 ))
BULK="$_BASE_CONC"
TIMEOUT=5
RETRIES=1
# Web templates run against http:// targets; network templates run against ip:port targets.
# This prevents web templates flooding network-only endpoints and vice-versa.
WEB_FLAGS=""
NET_FLAGS=""
# Exclude slow/irrelevant types for all non-custom modes
BASE_FLAGS="-ept headless,javascript,code,file"

case "$_mode" in
    1)  label="Quick (critical+high)"
        CONCURRENCY=$(( _BASE_CONC + 5 )); RATE=$(( (CONCURRENCY) * 6 )); BULK="$CONCURRENCY"; TIMEOUT=3
        WEB_FLAGS="-severity critical,high"
        NET_FLAGS="-severity critical,high"
        ;;
    2)  label="LAN / IoT"
        WEB_FLAGS="-tags default-logins,exposure,misconfiguration"
        NET_FLAGS="-tags network,default-logins"
        ;;
    3)  label="Full (all templates)"
        CONCURRENCY=$(( _BASE_CONC - 5 < 5 ? 5 : _BASE_CONC - 5 ))
        RATE=$(( CONCURRENCY * 5 )); BULK="$CONCURRENCY"; TIMEOUT=5
        WEB_FLAGS=""
        NET_FLAGS=""
        ;;
    4)  printf '  %s>>%s Extra nuclei flags: ' "${CYAN}" "${RESET}"
        read -r _custom
        WEB_FLAGS="$_custom"
        NET_FLAGS="$_custom"
        BASE_FLAGS=""
        label="Custom"
        ;;
    *)  label="LAN / IoT"
        WEB_FLAGS="-tags default-logins,exposure,misconfiguration"
        NET_FLAGS="-tags network,default-logins"
        ;;
esac

printf '\n'
printf '  %s[SYS]%s Mode    : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$label" "${RESET}"
printf '  %s[SYS]%s Speed   : %s%d req/s  bulk=%d  concurrency=%d  timeout=%ds%s\n' \
    "${CYAN}" "${RESET}" "${DIM}" "$RATE" "$BULK" "$CONCURRENCY" "$TIMEOUT" "${RESET}"
if [[ "$WEB_FLAGS" == "$NET_FLAGS" && -n "$WEB_FLAGS" ]]; then
    printf '  %s[SYS]%s Filters : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$WEB_FLAGS" "${RESET}"
else
    [[ -n "$WEB_FLAGS" ]] && printf '  %s[SYS]%s Web     : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$WEB_FLAGS" "${RESET}"
    [[ -n "$NET_FLAGS" ]] && printf '  %s[SYS]%s Network : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$NET_FLAGS" "${RESET}"
fi
[[ -n "$BASE_FLAGS" ]] && printf '  %s[SYS]%s Exclude : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$BASE_FLAGS" "${RESET}"
printf '\n'

# ── Scan type ─────────────────────────────────────────────────────────────────
printf '  %s[1]%s Web only   %s[2]%s Network only   %s[3]%s Both %s(default)%s\n' \
    "${CYAN}" "${RESET}" "${CYAN}" "${RESET}" "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s>>%s Scan type [1/2/3]: ' "${CYAN}" "${RESET}"
if [[ -z "${SESSION_DIR:-}" ]]; then
  read -r _type; _type="${_type:-3}"
else
  _type=3
fi
_run_web=1; _run_net=1
case "$_type" in
    1) _run_net=0; printf '  %s[SYS]%s Scope   : %sWeb only%s\n\n' "${CYAN}" "${RESET}" "${CYAN}" "${RESET}" ;;
    2) _run_web=0; printf '  %s[SYS]%s Scope   : %sNetwork only%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "${RESET}" ;;
    *) printf '  %s[SYS]%s Scope   : %sBoth web + network%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}" ;;
esac

# ── Split targets: web URLs vs network endpoints ──────────────────────────────
_nuclei_input="$nuclei_targets"
[[ ! -s "$_nuclei_input" ]] && _nuclei_input="$scan_file"

_web_file="$outdir/nuclei_web.txt"
_net_file="$outdir/nuclei_net.txt"
grep -E '^https?://' "$_nuclei_input" > "$_web_file" 2>/dev/null || true
grep -vE '^https?://' "$_nuclei_input" > "$_net_file" 2>/dev/null || true

_web_c=0; _net_c=0
[[ -s "$_web_file" ]] && _web_c=$(wc -l < "$_web_file")
[[ -s "$_net_file" ]] && _net_c=$(wc -l < "$_net_file")

_nuclei_run() {
    local _label="$1" _list="$2" _flags="$3" _out="$4"
    local _cnt; _cnt=$(wc -l < "$_list")
    printf '  %s[*]%s %s (%d endpoint(s))%s\n' \
        "${CYAN}" "${RESET}" "$_label" "$_cnt" "${RESET}"
    touch "$_out"   # ensure file exists even when nuclei finds 0 results
    # shellcheck disable=SC2086
    run_fg nuclei -l "$_list" \
        -c          "$CONCURRENCY" \
        -rate-limit "$RATE" \
        -bulk-size  "$BULK" \
        -timeout    "$TIMEOUT" \
        -retries    "$RETRIES" \
        -ni -duc -stats \
        $BASE_FLAGS \
        $_flags \
        -o "$_out"
    local _found; _found=$(wc -l < "$_out")
    printf '  %s[%s]%s %d finding(s) from %s\n\n' \
        "${GREEN}" "+" "${RESET}" "$_found" "$_label"
}

# ── Run nuclei — two phases, no cross-contamination ──────────────────────────
[[ -f "$outdir/nuclei_web_res.txt" ]] && rm -f "$outdir/nuclei_web_res.txt"
[[ -f "$outdir/nuclei_net_res.txt" ]] && rm -f "$outdir/nuclei_net_res.txt"

if [[ "$_web_c" -gt 0 && "$_run_web" -eq 1 ]]; then
    _nuclei_run "HTTP scan" "$_web_file" "$WEB_FLAGS" "$outdir/nuclei_web_res.txt"
fi

if [[ "$_net_c" -gt 0 && "$_run_net" -eq 1 ]]; then
    _nuclei_run "Network scan" "$_net_file" "$NET_FLAGS" "$outdir/nuclei_net_res.txt"
fi

# ── Merge results ─────────────────────────────────────────────────────────────
: > "$outfile"
[[ -f "$outdir/nuclei_web_res.txt" ]] && cat "$outdir/nuclei_web_res.txt" >> "$outfile"
[[ -f "$outdir/nuclei_net_res.txt" ]] && cat "$outdir/nuclei_net_res.txt" >> "$outfile"
rm -f "$outdir/nuclei_web_res.txt" "$outdir/nuclei_net_res.txt" \
      "$outdir/nuclei_web.txt" "$outdir/nuclei_net.txt"

printf '\n'
if [[ -s "$outfile" ]]; then
    count=$(wc -l < "$outfile")
    printf '  %s[!] %d finding(s) — saved to: %s%s\n' "${RED}" "$count" "$outfile" "${RESET}"
else
    printf '  %s[+] No findings. Results: %s%s\n' "${GREEN}" "$outfile" "${RESET}"
fi
mark_done "$outfile"
