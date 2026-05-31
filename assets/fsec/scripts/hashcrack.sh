#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
set -uo pipefail

banner "HASH CRACKER" "john + hashcat · NTLMv2 · NTLM · Kerberos TGS/AS-REP · auto-source"

# ── Tool check ─────────────────────────────────────────────────────────────────
section "DEPENDENCIES"

_JOHN=""; _HASHCAT=""
command -v john     &>/dev/null && _JOHN="john"
command -v hashcat  &>/dev/null && _HASHCAT="hashcat"

[[ -n "$_JOHN"    ]] && printf '  %s[✓]%s john\n'    "${GREEN}" "${RESET}"
[[ -z "$_JOHN"    ]] && printf '  %s[~]%s john     not found (apt install john)\n' "${YELLOW}" "${RESET}"
[[ -n "$_HASHCAT" ]] && printf '  %s[✓]%s hashcat\n' "${GREEN}" "${RESET}"
[[ -z "$_HASHCAT" ]] && printf '  %s[~]%s hashcat  not found (apt install hashcat)\n' "${YELLOW}" "${RESET}"

if [[ -z "$_JOHN" && -z "$_HASHCAT" ]]; then
  printf '\n  %s[!]%s No cracking tools found — install john or hashcat\n' "${RED}" "${RESET}"
  exit 1
fi

_WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"
if [[ ! -f "$_WORDLIST" ]]; then
  printf '  %s[~]%s rockyou.txt not at %s%s%s\n' "${YELLOW}" "${RESET}" "${DIM}" "$_WORDLIST" "${RESET}"
  printf '  %s[~]%s gunzip /usr/share/wordlists/rockyou.txt.gz if needed\n' "${DIM}" "${RESET}"
fi
printf '\n'

outdir="$(make_outdir)"
outfile="$outdir/cracked.txt"
hashfile="$outdir/hashes_input.txt"
: > "$outfile"
: > "$hashfile"

_cleanup() { mark_done "$outdir"; }
trap '_cleanup' EXIT

# ── Hash source ────────────────────────────────────────────────────────────────
section "HASH SOURCE"

# Pipeline chain: if chain_hashes.txt exists, use it directly without prompting
if [[ -n "${SESSION_DIR:-}" ]] && [[ -s "${SESSION_DIR}/chain_hashes.txt" ]]; then
  _hc=$(wc -l < "${SESSION_DIR}/chain_hashes.txt")
  printf '  %s[CHAIN]%s Auto-loading %s hash(es) from chain_hashes.txt%s\n\n' \
    "${CYAN}" "${RESET}" "$_hc" "${RESET}"
  cat "${SESSION_DIR}/chain_hashes.txt" >> "$hashfile" 2>/dev/null || true
  _engine="${_JOHN:+1}${_HASHCAT:+2}"
  [[ -z "$_engine" ]] && _engine=1
  printf '  %s[CHAIN]%s Using %s for cracking%s\n\n' \
    "${CYAN}" "${RESET}" "${_JOHN:-hashcat}" "${RESET}"
  # Jump straight to cracking — skip all prompts
  _total=$(grep -c '' "$hashfile" 2>/dev/null || echo 0)
  if (( _total == 0 )); then
    printf '  %s[!]%s chain_hashes.txt is empty — nothing to crack%s\n' "${RED}" "${RESET}" "${RESET}"
    exit 0
  fi
else

_BASE="$(cd "$(dirname "$0")/.." && pwd)"
declare -a _found_files=()

# Auto-search: responder NTLMv2 logs, impacket hashes, kerberos output
while IFS= read -r _f; do
  _cnt=$(grep -cE '::' "$_f" 2>/dev/null || echo 0)
  (( _cnt > 0 )) && _found_files+=("$_f ($_cnt hashes)")
done < <(
  find "$_BASE/results" \( \
    -name 'Responder-Session.log' -o \
    -name 'hashes.txt'            -o \
    -name 'kerberos.log'          -o \
    -name '*.ntds'                -o \
    -name 'asrep.txt'             -o \
    -name 'tgs.txt'               \
  \) 2>/dev/null | head -20
)

if [[ ${#_found_files[@]} -gt 0 ]]; then
  printf '  %s[+]%s Hash files found in results:\n\n' "${GREEN}" "${RESET}"
  for _i in "${!_found_files[@]}"; do
    printf '  %s[%02d]%s  %s\n' "${CYAN}" "$(( _i + 1 ))" "${RESET}" "${_found_files[$_i]}"
  done
  printf '\n  %s>>%s Load file(s) (space-sep IDs, a=all, Enter=skip): ' "${CYAN}" "${RESET}"
  read -r _picks
  if [[ "${_picks,,}" == "a" ]]; then
    for _entry in "${_found_files[@]}"; do
      _path="${_entry%% *}"
      grep -E '::' "$_path" >> "$hashfile" 2>/dev/null || true
    done
  elif [[ -n "$_picks" ]]; then
    for _id in $_picks; do
      if [[ "$_id" =~ ^[0-9]+$ ]] && (( _id >= 1 && _id <= ${#_found_files[@]} )); then
        _path="${_found_files[$(( _id - 1 ))]}"; _path="${_path%% *}"
        grep -E '::' "$_path" >> "$hashfile" 2>/dev/null || true
      fi
    done
  fi
fi

if [[ -z "${SESSION_DIR:-}" ]]; then
  printf '\n  %s>>%s Paste additional hashes (one per line, blank line to finish):\n' "${CYAN}" "${RESET}"
  printf '  %s    Formats: NTLMv2 (user::domain:...), NTLM (:hash), Kerberos ($krb5...)\n\n' "${DIM}" "${RESET}"
  while IFS= read -r _line; do
    [[ -z "$_line" ]] && break
    printf '%s\n' "$_line" >> "$hashfile"
  done
fi

_total=$(grep -c '' "$hashfile" 2>/dev/null || echo 0)
if (( _total == 0 )); then
  printf '  %s[!]%s No hashes to crack\n' "${RED}" "${RESET}"; exit 0
fi
printf '\n  %s[+]%s %d hash line(s) loaded\n' "${GREEN}" "${RESET}" "$_total"

fi  # end pipeline/interactive branch

# ── Hash type detection ────────────────────────────────────────────────────────
section "HASH TYPE DETECTION"

_sample=$(head -1 "$hashfile")
_HTYPE="auto"
_HC_MODE=""

if [[ "$_sample" == *'$krb5tgs$'* ]]; then
  _HTYPE="Kerberos TGS (Kerberoast)"; _HC_MODE="13100"
elif [[ "$_sample" == *'$krb5asrep$'* ]]; then
  _HTYPE="Kerberos AS-REP (ASREPRoast)"; _HC_MODE="18200"
elif [[ "$_sample" =~ ^[^:]+::[^:]+:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}: ]]; then
  _HTYPE="NTLMv2 (Net-NTLMv2)"; _HC_MODE="5600"
elif [[ "$_sample" =~ ^[^:]+:[0-9]+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}::: ]]; then
  _HTYPE="NTLM (SAM/NTDS)"; _HC_MODE="1000"
elif [[ "$_sample" =~ ^[0-9a-fA-F]{32}$ ]]; then
  _HTYPE="MD5"; _HC_MODE="0"
elif [[ "$_sample" =~ ^\$2[aby]\$ ]]; then
  _HTYPE="bcrypt"; _HC_MODE="3200"
else
  _HTYPE="Unknown (will try auto-detect)"
fi

printf '  %s[*]%s Detected: %s%s%s\n' "${CYAN}" "${RESET}" "${BOLD}" "$_HTYPE" "${RESET}"
[[ -n "$_HC_MODE" ]] && printf '  %s[*]%s Hashcat mode: %s%s%s\n\n' "${CYAN}" "${RESET}" "${CYAN}" "$_HC_MODE" "${RESET}"

# ── Cracking mode ──────────────────────────────────────────────────────────────
section "CRACKING ENGINE"

if [[ -n "${SESSION_DIR:-}" ]]; then
  # Auto-select: prefer john (CPU, no GPU needed on phone), fallback hashcat
  _engine=1
  [[ -z "$_JOHN" && -n "$_HASHCAT" ]] && _engine=2
  printf '  %s[CHAIN]%s Engine: %s  (pipeline auto-select)%s\n\n' \
    "${CYAN}" "${RESET}" "${_JOHN:-hashcat}" "${RESET}"
else
  printf '  %s[01]%s John the Ripper  %s(CPU — wordlist)%s\n'    "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  [[ -n "$_HASHCAT" ]] && \
  printf '  %s[02]%s Hashcat          %s(GPU/CPU — wordlist + rules)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
  printf '\n  %s>>%s Engine [1]: ' "${CYAN}" "${RESET}"
  read -r _engine; _engine="${_engine:-1}"
fi

section "CRACKING"
printf '  %s[SYS]%s Hashes : %s%d%s\n'    "${CYAN}" "${RESET}" "${GREEN}" "$_total" "${RESET}"
printf '  %s[SYS]%s Type   : %s%s%s\n'    "${CYAN}" "${RESET}" "${CYAN}" "$_HTYPE" "${RESET}"
printf '  %s[SYS]%s Output : %s%s%s\n\n'  "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

if [[ "$_engine" == "2" && -n "$_HASHCAT" ]]; then
  if [[ -z "$_HC_MODE" ]]; then
    printf '  %s>>%s Hashcat mode number (see hashcat --help): ' "${CYAN}" "${RESET}"
    read -r _HC_MODE
  fi
  if [[ ! -f "$_WORDLIST" ]]; then
    printf '  %s[!]%s Wordlist not found: %s\n' "${RED}" "${RESET}" "$_WORDLIST"; exit 1
  fi
  run_fg hashcat -m "$_HC_MODE" "$hashfile" "$_WORDLIST" \
    -r /usr/share/hashcat/rules/best64.rule \
    --status --status-timer=10 \
    --outfile="$outfile" --outfile-format=2 \
    --force 2>&1 | tee -a "$outdir/hashcat.log" || true

  # Show cracked
  if [[ -s "$outfile" ]]; then
    printf '\n  %s[✔]%s Cracked:\n' "${GREEN}" "${RESET}"
    while IFS= read -r _l; do
      printf '  %s  ▶  %s%s\n' "${GREEN}" "$_l" "${RESET}"
    done < "$outfile"
  fi

else
  # John
  _JOHN_OUT="$outdir/john.pot"
  run_fg john "$hashfile" \
    --wordlist="$_WORDLIST" \
    --pot="$_JOHN_OUT" \
    --fork=2 2>&1 | tee -a "$outfile" || true

  printf '\n'
  john "$hashfile" --pot="$_JOHN_OUT" --show 2>/dev/null | tee -a "$outfile" || true
fi

printf '\n  %s[SYS]%s Log : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
