#!/usr/bin/env bash
#
#  setdns.sh — switch /etc/resolv.conf between popular public DNS providers
#  -----------------------------------------------------------------------
#  * Interactive menu: 1-6 providers, 7 custom, 8 restore, 9 status, 0 quit
#  * One-shot:         sudo ./setdns.sh cloudflare | 3 | "1.1.1.1 8.8.8.8"
#  * Timestamped backups, one-command restore, automatic pruning
#  * Detects systemd-resolved / NetworkManager / connman managed systems and
#    can apply the change persistently through them (--resolved / --nm)
#  * IPv4 + IPv6 servers, EDNS0 + DNSSEC trust-ad resolver options
#  * Optional immutable lock (chattr +i) so nothing overwrites your choice
#  * Dry-run, live verification (dig/nslookup/host/python3/getent fallbacks)
#  * Atomic write, temp-file trap, no dependencies required
#
#  Version 1.4.0
#
set -Eeuo pipefail

VERSION="1.4.0"
TARGET="/etc/resolv.conf"
SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"

# --------------------------------------------------------------------------
# Provider database — array order defines the menu numbers 1..N
# --------------------------------------------------------------------------
PROVIDERS=(cloudflare google quad9 adguard opendns verisign)

declare -A P_LABEL=(
  [cloudflare]="Cloudflare"
  [google]="Google Public DNS"
  [quad9]="Quad9 (malware blocking)"
  [adguard]="AdGuard (ad blocking)"
  [opendns]="OpenDNS (Cisco)"
  [verisign]="Verisign"
)
declare -A P_V4=(
  [cloudflare]="1.1.1.1 1.0.0.1"
  [google]="8.8.8.8 8.8.4.4"
  [quad9]="9.9.9.9 149.112.112.112"
  [adguard]="94.140.14.14 94.140.15.15"
  [opendns]="208.67.222.222 208.67.220.220"
  [verisign]="64.6.64.6 64.6.65.6"
)
declare -A P_V6=(
  [cloudflare]="2606:4700:4700::1111 2606:4700:4700::1001"
  [google]="2001:4860:4860::8888 2001:4860:4860::8844"
  [quad9]="2620:fe::fe 2620:fe::9"
  [adguard]="2a10:50c0::ad1:ff 2a10:50c0::ad2:ff"
  [opendns]="2620:119:35::35 2620:119:53::53"
  [verisign]="2620:74:1b::1:1 2620:75:1b::1:1"
)
declare -A P_NOTE=(
  [cloudflare]="Fastest worldwide; strict no-logging privacy policy."
  [google]="Extremely reliable; huge global anycast network."
  [quad9]="Swiss non-profit; blocks known malicious domains."
  [adguard]="Blocks ads, trackers and malicious sites at DNS level."
  [opendns]="Cisco-backed; good parental-control / family options."
  [verisign]="Privacy focused; no-log, no-sale policy."
)

# Optional DoT (DNS-over-TLS) fingerprints — used by --dot when generating a
# systemd-resolved drop-in. Add yours the same way as the P_* arrays above.
declare -A P_DOT_FP=(
  [cloudflare]="D7A7D0F5C16AF876CE7D129B32CD056DE738FF1DC87B6E26275FCAD8C795ACFEAD95F0356D7377DEB44E7B2E80471DB2"
  [google]="445FF7523759B453EF66C88AB25B8A9839A4BEEFB531DB18598D966CA3C5A5E8"
  [quad9]="AFBEB90848507ECF459C846F6F8A9E9535273F0AC33CC57F8FC0509A0DA3E362"
)

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------
USE_IPV6="auto"      # auto | on | off
IPV6_OK=""           # cached detection result
ADD_OPTIONS=1
DRY_RUN=0
LOCK_AFTER=0
UNLOCK_ONLY=0
FORCE=0
REPLACE_SYMLINK=0
RESOLVED_MODE=0
NM_MODE=0
KEEP_BACKUPS=10
VERIFY_AFTER=1
QUIET=0
IFACE=""
RESTORE_FILE=""
CUSTOM_SERVERS=""
SEL_SERVERS=""
SEL_LABEL="custom"
BLOCK_LABEL="custom"
TMP_FILE=""
PROFILE_MODE=0
DOT_MODE=0
DROPIN_DIR="/etc/systemd/resolved.conf.d"
SEL_KEY=""

# --------------------------------------------------------------------------
# Output helpers (safe under `set -e`: last command always returns 0)
# --------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
  C_BLUE=$'\e[34m'; C_CYAN=$'\e[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""
  C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

info()  { [[ $QUIET -eq 1 ]] && return 0; printf '%s\n' "${C_BLUE}i${C_RESET} $*"; }
ok()    { [[ $QUIET -eq 1 ]] && return 0; printf '%s\n' "${C_GREEN}✔${C_RESET} $*"; }
title() { [[ $QUIET -eq 1 ]] && return 0; printf '\n%s%s%s\n' "$C_BOLD$C_CYAN" "$*" "$C_RESET"; }
warn()  { printf '%s\n' "${C_YELLOW}!${C_RESET} $*" >&2; }
err()   { printf '%s\n' "${C_RED}✖${C_RESET} $*" >&2; }
die()   { err "$*"; exit 1; }

cleanup() { [[ -n "$TMP_FILE" && -e "$TMP_FILE" ]] && rm -f "$TMP_FILE"; return 0; }
trap cleanup EXIT
trap 'err "Interrupted."; exit 130' INT TERM

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }
norm() { printf '%s' "$*" | tr '[:upper:]' '[:lower:]' | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//'; }

# --------------------------------------------------------------------------
# Usage
# --------------------------------------------------------------------------
# Print usage, but only after an external profile has been loaded (so the
# PROVIDERS list in --help is accurate).
usage() {
  if [[ -n "${PROFILE_FILE:-}" ]]; then load_profile "$PROFILE_FILE"; fi
cat <<EOF
${C_BOLD}setdns.sh${C_RESET} v${VERSION} — switch your system DNS provider

${C_BOLD}USAGE${C_RESET}
  sudo ./setdns.sh                      interactive menu
  sudo ./setdns.sh <provider|N|ips>     one-shot
  ./setdns.sh --help

${C_BOLD}PROVIDERS${C_RESET}
$(for i in "${!PROVIDERS[@]}"; do printf '  %d) %-11s %s\n' "$((i+1))" "${PROVIDERS[$i]}" "${P_LABEL[${PROVIDERS[$i]}]}"; done)
  Raw addresses also work:  ./setdns.sh "1.1.1.1 8.8.8.8"

${C_BOLD}COMMANDS${C_RESET}
  -l, --list              list all providers with their addresses
  -c, --current           show the active resolv.conf
  -b, --backups           list the backups that can be restored
  -r, --restore [FILE]    restore a backup (newest one if FILE is omitted)
  -v, --verify [IPS]      test that DNS resolution actually works
      --unlock            remove the immutable lock (chattr -i)
      --selftest          run the built-in test suite against temp files

${C_BOLD}FLAGS${C_RESET}
  -t, --target PATH       file to edit (default: ${TARGET})
  -i, --iface NAME        interface used by --resolved / --nm
      --resolved          apply through systemd-resolved (resolvectl) — persistent
      --nm                apply through NetworkManager (nmcli) — persistent
      --no-ipv6           write IPv4 nameservers only
      --ipv6              always include IPv6 nameservers
                          (default: include them only if the host has IPv6)
      --no-options        omit the "options" line
      --lock              chattr +i after writing (blocks manager overwrites)
      --keep N            backups to retain (default: ${KEEP_BACKUPS})
  -n, --dry-run           show what would change, write nothing
  -f, --force             skip prompts and manager warnings
      --replace-symlink   replace a symlinked resolv.conf with a real file
      --no-verify         skip the post-apply resolution test
      --profile FILE      read servers from an external profile file instead
                          of the built-in table (see --make-profile)
      --make-profile      print a starter profile file to stdout
      --dot               with --resolved: also generate a DNS-over-TLS
                          drop-in in ${DROPIN_DIR} (needs a provider name)
  -q, --quiet             minimal output
  -h, --help              show this help
  -V, --version           show version

${C_BOLD}EXAMPLES${C_RESET}
  sudo ./setdns.sh cloudflare
  sudo ./setdns.sh 3 --no-ipv6 --lock
  sudo ./setdns.sh --resolved google
  sudo ./setdns.sh --resolved --dot cloudflare
  sudo ./setdns.sh --profile ~/my-profiles.txt work
  ./setdns.sh --make-profile > my-providers.txt
  sudo ./setdns.sh --restore
  sudo ./setdns.sh --dry-run "9.9.9.9 149.112.112.112"
EOF
}

list_providers() {
  title "Available DNS providers"
  local i key
  for i in "${!PROVIDERS[@]}"; do
    key="${PROVIDERS[$i]}"
    printf '  %s%d)%s %-28s %s\n' "$C_BOLD" "$((i+1))" "$C_RESET" "$key" "${P_LABEL[$key]}"
    printf '       %sIPv4:%s %s\n' "$C_DIM" "$C_RESET" "${P_V4[$key]}"
    printf '       %sIPv6:%s %s\n' "$C_DIM" "$C_RESET" "${P_V6[$key]}"
    printf '       %s%s%s\n\n' "$C_DIM" "${P_NOTE[$key]}" "$C_RESET"
  done
  printf '  %sTip:%s add your own provider by editing the PROVIDERS/P_* arrays at the top,\n' "$C_DIM" "$C_RESET"
  printf '       %sor keep them outside the script with --profile FILE (see --make-profile).%s\n' "$C_DIM" "$C_RESET"
}

# --------------------------------------------------------------------------
# External profiles — same data, kept out of the script
#   key|label|ipv4 servers|ipv6 servers|note[|DoT fingerprint]
# The file may contain comments (#) and blank lines. Later entries win if a
# key is repeated, so you can override built-ins without editing the script.
# --------------------------------------------------------------------------
PROFILE_FILE=""

load_profile() {
  local file="$1" line key label v4 v6 note fp
  [[ -r "$file" ]] || die "Profile file not readable: $file"
  local -a fields=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"                            # strip trailing comments
    [[ -n "$(norm "$line")" ]] || continue
    IFS='|' read -r -a fields <<<"$line"
    key="$(norm "${fields[0]:-}")"
    [[ -n "$key" ]] || continue
    [[ "$key" =~ ^[A-Za-z0-9._-]+$ ]] || \
      die "Bad profile key '${key}' in ${file} (use letters, digits, . _ -)."
    label="${fields[1]:-}"
    [[ -n "$(norm "$label")" ]] || label="$key"
    v4="$(norm "${fields[2]:-}")"
    v6="$(norm "${fields[3]:-}")"
    note="${fields[4]:-}"
    fp="$(norm "${fields[5]:-}")"
    local w
    for w in $v4 $v6; do
      valid_ip "$w" || die "Profile '${key}': invalid IP '${w}' in ${file}"
    done
    # register (or override) the entry
    local found=0 p
    for p in "${PROVIDERS[@]}"; do [[ "$p" == "$key" ]] && { found=1; break; }; done
    (( found )) || PROVIDERS+=("$key")
    P_LABEL[$key]="$label"
    P_V4[$key]="$v4"
    P_V6[$key]="$v6"
    P_NOTE[$key]="$note"
    [[ -n "$fp" ]] && P_DOT_FP[$key]="$fp"
  done < "$file"
  return 0
}

make_profile() {
  local i key fp
  cat <<EOF
# setdns.sh profile file — generated v${VERSION}
# Format: key|label|ipv4 servers|ipv6 servers|note[|DoT certificate SHA256 fingerprint]
# Use with: sudo setdns.sh --profile THISFILE <key>
$(for i in "${!PROVIDERS[@]}"; do
  key="${PROVIDERS[$i]}"
  fp="${P_DOT_FP[$key]:-}"
  printf '%s|%s|%s|%s|%s%s\n' "$key" "${P_LABEL[$key]}" "${P_V4[$key]}" \
         "${P_V6[$key]}" "${P_NOTE[$key]}" "${fp:+|$fp}"
done)
# Add your own below — e.g. a LAN resolver or a Pi-hole:
# home|Home Pi-hole|192.168.1.10||Blocks ads on the LAN.|
EOF
}

# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
valid_ip() {
  local ip="$1"
  if [[ "$ip" == *:* ]]; then
    [[ "$ip" =~ ^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$ ]] && return 0
    [[ "$ip" == "::" || "$ip" == "::1" ]] && return 0
    return 1
  fi
  local IFS=. a b c d o
  read -r a b c d <<<"$ip"
  [[ -n ${a:-} && -n ${b:-} && -n ${c:-} && -n ${d:-} ]] || return 1
  for o in "$a" "$b" "$c" "$d"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
    (( ${#o} > 1 )) && [[ "${o:0:1}" == "0" ]] && return 1
  done
  return 0
}

# True when the machine actually has usable (global) IPv6 connectivity.
has_ipv6() {
  if [[ -r /proc/net/if_inet6 ]] &&
     awk '$4=="00"{f=1} END{exit !f}' /proc/net/if_inet6 2>/dev/null; then
    return 0
  fi
  if have ip && [[ -n "$(ip -6 route show default 2>/dev/null)" ]]; then
    return 0
  fi
  return 1
}

# Decide once whether IPv6 nameservers should be written.
# "auto" keeps them only if the box has IPv6; explicit custom IPv6 input is
# always honoured (the user typed it on purpose).
ipv6_enabled() {
  if [[ -n "$IPV6_OK" ]]; then [[ "$IPV6_OK" == "1" ]] && return 0 || return 1; fi
  case "$USE_IPV6" in
    on)  IPV6_OK=1 ;;
    off) IPV6_OK=0 ;;
    *)   if has_ipv6; then IPV6_OK=1; else IPV6_OK=0; fi ;;
  esac
  [[ "$IPV6_OK" == "1" ]] && return 0 || return 1
}

# Copy src over dst. Rename is atomic but fails on bind-mounted or
# cross-device targets (Docker/LXC/WSL bind-mount /etc/resolv.conf), so fall
# back to an in-place rewrite that keeps the inode.
install_file() {
  local src="$1" dst="$2"
  if mv -f "$src" "$dst" 2>/dev/null; then
    return 0
  fi
  if cat "$src" > "$dst" 2>/dev/null; then
    rm -f "$src"
    chmod 644 "$dst" 2>/dev/null || true
    return 0
  fi
  rm -f "$src" 2>/dev/null || true
  return 1
}

need_root() {
  is_root && return 0
  # Internal: the self-test writes only to a temp dir it owns.
  if [[ -n "${SETDNS_SKIP_ROOT:-}" && -w "$(dirname "$TARGET")" ]]; then return 0; fi
  if [[ $DRY_RUN -eq 1 ]]; then
    warn "Not root — running in read-only/dry-run mode."
    DRY_RUN=1
    return 0
  fi
  if have sudo; then
    warn "Root privileges required — re-running with sudo."
    exec sudo -E bash "$SELF" ${ARGS[@]+"${ARGS[@]}"}
  fi
  die "Must be run as root (try: sudo $0 ...)."
}

# --------------------------------------------------------------------------
# Manager detection
# --------------------------------------------------------------------------
# Where does the symlink point? (informational, not a warning on its own)
symlink_target() {
  [[ -L "$TARGET" ]] || return 0
  readlink -f "$TARGET" 2>/dev/null || readlink "$TARGET" 2>/dev/null || true
}

# Only *known* managers are reported: those really do rewrite resolv.conf.
detect_manager() {
  local out="" lt=""
  if [[ -L "$TARGET" ]]; then
    lt="$(readlink -f "$TARGET" 2>/dev/null || echo '?')"
    case "$lt" in
      */run/systemd/resolve/*)   out="systemd-resolved (symlink → $lt)" ;;
      */run/NetworkManager/*)    out="NetworkManager (symlink → $lt)" ;;
      */run/connman/*)           out="connman (symlink → $lt)" ;;
      */run/resolvconf/*)        out="resolvconf (symlink → $lt)" ;;
    esac
    if [[ -n "$out" ]]; then printf '%s' "$out"; return 0; fi
  fi
  if have systemctl && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    out="systemd-resolved (active)"
  elif pgrep -x systemd-resolve >/dev/null 2>&1; then
    out="systemd-resolved (active)"
  elif have systemctl && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    out="NetworkManager (active)"
  elif pgrep -x NetworkManager >/dev/null 2>&1; then
    out="NetworkManager (active)"
  fi
  printf '%s' "$out"
}

default_iface() {
  if [[ -n "$IFACE" ]]; then printf '%s' "$IFACE"; return 0; fi
  local i=""
  if have ip; then
    i="$(ip -o -4 route show to default 2>/dev/null \
         | awk '{for(k=1;k<=NF;k++) if($k=="dev"){print $(k+1); exit}}')"
  fi
  if [[ -z "$i" && -r /proc/net/route ]]; then
    i="$(awk 'NR>1 && $2=="00000000"{print $1; exit}' /proc/net/route)"
  fi
  printf '%s' "$i"
}

# --------------------------------------------------------------------------
# Content builder
# --------------------------------------------------------------------------
build_block() {
  local servers="$1" content="" s skipped=0
  content+="# Generated by setdns.sh v${VERSION} — $(date '+%Y-%m-%d %H:%M:%S %Z')"$'\n'
  content+="# Provider: ${BLOCK_LABEL}"$'\n'
  if ! ipv6_enabled; then
    for s in $servers; do [[ "$s" == *:* ]] && skipped=1; done
    (( skipped == 1 )) && \
      content+="# (IPv6 servers omitted — no IPv6 connectivity detected)"$'\n'
  fi
  for s in $servers; do
    if [[ "$s" == *:* ]] && ! ipv6_enabled; then continue; fi
    content+="nameserver ${s}"$'\n'
  done
  if [[ $ADD_OPTIONS -eq 1 ]]; then
    content+="options edns0 trust-ad timeout:2 attempts:3"$'\n'
  fi
  printf '%s' "$content"
}

show_current() {
  title "Current ${TARGET}"
  if [[ ! -e "$TARGET" ]]; then warn "${TARGET} does not exist."; return 0; fi
  local m l
  m="$(detect_manager)"
  l="$(symlink_target)"
  [[ -n "$m" ]] && info "Managed by: ${C_BOLD}${m}${C_RESET}"
  [[ -n "$l" && -z "$m" ]] && info "Symlink → ${C_BOLD}${l}${C_RESET}"
  # shellcheck disable=SC2012  # human-readable listing, names are fixed
  ls -l "$TARGET" 2>/dev/null | sed 's/^/  /'
  echo
  sed 's/^/  /' "$TARGET" 2>/dev/null || warn "(cannot read ${TARGET})"
  echo
  return 0
}

# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------
probe_one() {  # probe_one <server> <hostname>
  local srv="$1" host="${2:-example.com}"
  if have dig; then
    dig +short +time=3 +tries=1 "@${srv}" "$host" A >/dev/null 2>&1
  elif have nslookup; then
    nslookup "$host" "$srv" >/dev/null 2>&1
  elif have host; then
    host -W 3 "$host" "$srv" >/dev/null 2>&1
  elif have python3; then
    python3 - "$srv" "$host" <<'PY' >/dev/null 2>&1
import socket, struct, sys, random
srv, name = sys.argv[1], sys.argv[2]
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
for part in name.split("."):
    q += bytes([len(part)]) + part.encode()
q += b"\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET6 if ":" in srv else socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
s.sendto(q, (srv, 53))
data, _ = s.recvfrom(4096)
sys.exit(0 if (data[3] & 0x0F) == 0 and len(data) > 12 else 1)
PY
  else
    getent hosts "$host" >/dev/null 2>&1
  fi
}

verify_dns() {
  local servers="${1:-}" srv rc=0 tested=0
  title "Verifying DNS"
  if [[ -z "$servers" ]]; then
    [[ -e "$TARGET" ]] || { warn "${TARGET} missing — nothing to verify."; return 1; }
    servers="$(awk '/^[[:space:]]*nameserver/{print $2}' "$TARGET" | tr '\n' ' ')"
  fi
  if [[ -z "$(norm "$servers")" ]]; then warn "No nameservers to test."; return 1; fi
  local skipped_v6=0
  for srv in $servers; do
    if [[ "$srv" == *:* ]] && ! ipv6_enabled; then skipped_v6=1; continue; fi
    tested=$((tested + 1))
    if probe_one "$srv"; then
      ok "${srv} answered — resolution works."
    else
      err "${srv} did NOT answer (unreachable, IPv6 unavailable, or blocked)."
      rc=1
    fi
  done
  if have getent && getent hosts example.com >/dev/null 2>&1; then
    ok "System resolver works (getent hosts example.com)."
  else
    warn "System resolver could not resolve example.com."
    rc=1
  fi
  (( skipped_v6 == 1 )) && info "Skipped IPv6 servers — this host has no global IPv6 address."
  (( tested == 0 )) && rc=1
  return $rc
}

# --------------------------------------------------------------------------
# Backups
# --------------------------------------------------------------------------
file_mtime() {
  stat -c '%y' "$1" 2>/dev/null | cut -d. -f1 ||
    stat -f '%Sm' "$1" 2>/dev/null || echo "?"
}

file_epoch() {
  stat -c '%Y' "$1" 2>/dev/null || stat -f '%m' "$1" 2>/dev/null || echo 0
}

# Backups of $TARGET, newest first (glob-based, no ls|grep).
backups_newest_first() {
  local -a files=()
  local f e
  shopt -s nullglob
  for f in "${TARGET}".bak.*; do
    case "$f" in *.content|*.link) continue ;; esac
    [[ -f "$f" ]] || continue
    files+=("$f")
  done
  shopt -u nullglob
  (( ${#files[@]} == 0 )) && return 0
  for f in "${files[@]}"; do
    e="$(file_epoch "$f")"
    printf '%s\t%s\n' "$e" "$f"
  done | sort -rn | cut -f2-
  return 0
}

newest_backup() {
  backups_newest_first | head -1
}

list_backups() {
  local f
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    printf '  %s  %s\n' "$(file_mtime "$f")" "$f"
  done < <(backups_newest_first)
  return 0
}

prune_backups() {
  local -a all=()
  local n
  while IFS= read -r n; do [[ -n "$n" ]] && all+=("$n"); done < <(backups_newest_first)
  if (( ${#all[@]} > KEEP_BACKUPS )); then
    for f in "${all[@]:KEEP_BACKUPS}"; do
      rm -f "$f" "${f}.content" "${f}.link" 2>/dev/null || true
    done
    info "Pruned old backups (keeping the last ${KEEP_BACKUPS})."
  fi
  return 0
}

backup_target() {
  local path="$1" ts stamp
  [[ -e "$path" || -L "$path" ]] || return 0
  ts="$(date +%Y%m%d-%H%M%S)"
  stamp="${path}.bak.${ts}"
  local n=0
  while [[ -e "$stamp" || -e "${stamp}.link" ]]; do          # never clobber a backup
    n=$((n + 1))
    stamp="${path}.bak.${ts}-${n}"
  done
  if [[ -L "$path" ]]; then
    readlink "$path" > "${stamp}.link"
    cp -aL "$path" "${stamp}" 2>/dev/null || printf '' > "${stamp}"
  else
    cp -a "$path" "$stamp"
  fi
  info "Backup saved: ${C_BOLD}${stamp}${C_RESET}"
  prune_backups "$path"
  return 0
}

restore_backup() {
  local f="${1:-}" link="" write_path="$TARGET"
  if [[ -z "$f" ]]; then
    f="$(newest_backup)"
    [[ -z "$f" ]] && die "No backups found for ${TARGET} (use --restore <file>)."
  fi
  [[ -e "$f" || -L "$f" ]] || die "Backup not found: $f"
  need_root
  unlock_file

  # If the backup came from a symlink, make sure the link itself still exists.
  if [[ -f "${f}.link" ]]; then
    link="$(cat "${f}.link")"
    if [[ ! -L "$TARGET" ]]; then
      if [[ $DRY_RUN -eq 1 ]]; then
        info "[dry-run] would recreate symlink ${TARGET} → ${link}"
      else
        ln -sfn "$link" "$TARGET"
        ok "Recreated symlink ${TARGET} → ${link}"
      fi
    fi
  fi

  # Content goes to the real file behind the link (same policy as when writing).
  if [[ -L "$TARGET" && $REPLACE_SYMLINK -eq 0 ]]; then
    write_path="$(readlink -f "$TARGET" 2>/dev/null || printf '%s' "$TARGET")"
  fi

  if [[ ! -s "$f" ]]; then
    warn "Backup ${f} has no content (it only recorded a symlink)."
    show_current
    return 0
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] would restore ${f} → ${write_path}"
    sed 's/^/    /' "$f" 2>/dev/null || true
    return 0
  fi

  TMP_FILE="$(mktemp "${write_path}.setdns.XXXXXX" 2>/dev/null || mktemp)"
  cat "$f" > "$TMP_FILE"
  chmod 644 "$TMP_FILE"
  if is_root; then chown root:root "$TMP_FILE" 2>/dev/null || true; fi
  install_file "$TMP_FILE" "$write_path" \
    || die "Could not write ${write_path} (read-only filesystem or permission denied)."
  TMP_FILE=""
  ok "Restored ${C_BOLD}${f}${C_RESET} → ${write_path}"
  show_current
  return 0
}

# --------------------------------------------------------------------------
# Immutable lock
# --------------------------------------------------------------------------
file_locked() {
  have lsattr || return 1
  [[ -e "$TARGET" ]] || return 1
  lsattr "$TARGET" 2>/dev/null | awk '{print $1}' | grep -q 'i'
}

lock_file() {
  if have chattr && chattr +i "$TARGET" 2>/dev/null; then
    ok "Locked ${TARGET} (chattr +i) — managers can no longer overwrite it."
  else
    warn "Could not lock ${TARGET} (chattr missing or unsupported filesystem)."
  fi
  return 0
}

unlock_file() {
  if have chattr && file_locked; then
    chattr -i "$TARGET" 2>/dev/null && info "Unlocked ${TARGET} (chattr -i)."
  fi
  return 0
}

# --------------------------------------------------------------------------
# Persistent apply paths (survive reboot / reconnect)
# --------------------------------------------------------------------------
apply_resolved() {
  local servers="$1" iface s
  iface="$(default_iface)"
  [[ -n "$iface" ]] || die "Could not detect the default interface — pass --iface NAME."
  have resolvectl || die "resolvectl not found; cannot use --resolved on this system."
  local cmd=(resolvectl dns "$iface")
  for s in $servers; do
    [[ "$s" == *:* ]] && ! ipv6_enabled && continue
    cmd+=("$s")
  done
  info "Applying through systemd-resolved on interface ${C_BOLD}${iface}${C_RESET}"
  if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] ${cmd[*]}"; return 0; fi
  "${cmd[@]}"
  ok "systemd-resolved DNS servers set for ${iface}."
  resolvectl status "$iface" 2>/dev/null | sed 's/^/  /' || true
  info "To make this permanent, also set DNS= in /etc/systemd/resolved.conf."
  return 0
}

# Generate a persistent systemd-resolved drop-in. With --dot the provider's
# certificate fingerprint is pinned (server~SHA256) and DNSOverTLS=yes; without
# it only a plain DNS= line is written.
apply_dropin() {
  local servers="$1" key="$2" dot="$3"
  local conf="${DROPIN_DIR}/setdns.conf" tmp s list="" out=""
  have systemctl || die "systemctl not found; drop-ins only work with systemd."
  [[ -d "$DROPIN_DIR" ]] || die "${DROPIN_DIR} does not exist — no systemd-resolved here."

  for s in $servers; do
    [[ "$s" == *:* ]] && ! ipv6_enabled && continue
    if (( dot == 1 )) && [[ -n "${P_DOT_FP[$key]:-}" ]]; then
      out+="${out:+ }${s}~${P_DOT_FP[$key]}"
    else
      list+="${list:+ }${s}"
    fi
  done
  if (( dot == 1 )) && [[ -z "$out" ]]; then
    warn "No DoT fingerprint known for '${key}' — writing servers unpinned."
  fi
  local dnsval="${out:-$list}"
  [[ -n "$dnsval" ]] || die "No nameservers to write into the drop-in."

  tmp="$(mktemp "${TMPDIR:-/tmp}/setdns-dropin.XXXXXX")"
  TMP_FILE="$tmp"
  {
    printf '# Generated by setdns.sh v%s on %s\n' "$VERSION" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    [[ -n "$key" ]] && printf '# Provider: %s\n' "$key"
    printf '[Resolve]\nDNS=%s\n' "$dnsval"
    if (( dot == 1 )); then printf 'DNSOverTLS=yes\n'; fi
    true
  } > "$tmp"

  title "[drop-in] Contents of ${conf}"
  sed 's/^/  /' "$tmp"; echo

  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] nothing written; would also run: systemctl restart systemd-resolved"
    return 0
  fi

  mkdir -p "$DROPIN_DIR" 2>/dev/null || die "Cannot create ${DROPIN_DIR} (need root?)."
  cp -f "$tmp" "$conf" || die "Could not write ${conf}."
  chmod 644 "$conf"
  TMP_FILE=""
  rm -f "$tmp"
  ok "Wrote ${C_BOLD}${conf}${C_RESET}"

  if systemctl restart systemd-resolved 2>/dev/null; then
    ok "Restarted systemd-resolved — settings persist across reboots."
  else
    warn "Could not restart systemd-resolved automatically; do it manually:"
    warn "  sudo systemctl restart systemd-resolved"
  fi
  if (( dot == 1 )); then
    info "DNS-over-TLS enabled. Verify with: resolvectl status"
  fi
  return 0
}

apply_nmcli() {
  local servers="$1" conn iface list="" s
  have nmcli || die "nmcli not found; cannot use --nm on this system."
  iface="$(default_iface)"
  conn="$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null \
          | awk -F: -v i="$iface" '$2==i{print $1; exit}')"
  [[ -n "$conn" ]] || die "No active NetworkManager connection found on '${iface}'."
  for s in $servers; do
    [[ "$s" == *:* ]] && ! ipv6_enabled && continue
    list+="${list:+ }${s}"
  done
  info "Applying through NetworkManager connection ${C_BOLD}${conn}${C_RESET}"
  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] nmcli connection modify \"$conn\" ipv4.dns \"$list\" ipv4.ignore-auto-dns yes"
    return 0
  fi
  nmcli connection modify "$conn" ipv4.dns "$list" ipv4.ignore-auto-dns yes
  nmcli connection up "$conn" >/dev/null 2>&1 || true
  ok "NetworkManager DNS updated — this persists across reboots."
  return 0
}

# --------------------------------------------------------------------------
# Core write
# --------------------------------------------------------------------------
apply_servers() {
  local servers="$1" write_path="$TARGET" manager content
  BLOCK_LABEL="$SEL_LABEL"

  if [[ -L "$TARGET" ]]; then
    if [[ $REPLACE_SYMLINK -eq 1 ]]; then
      info "--replace-symlink: ${TARGET} will become a regular file."
    else
      write_path="$(readlink -f "$TARGET")"
      info "${TARGET} is a symlink → writing to its real target ${C_BOLD}${write_path}${C_RESET}"
    fi
  fi

  manager="$(detect_manager)"
  if [[ -n "$manager" && $FORCE -eq 0 && $DRY_RUN -eq 0 ]]; then
    warn "${TARGET} looks managed by ${C_BOLD}${manager}${C_RESET}."
    warn "Your edit may be reverted on the next reconnect or reboot."
    if [[ "$manager" == systemd-resolved* ]] && have resolvectl; then
      warn "Persistent alternative: ${C_BOLD}$0 --resolved <provider>${C_RESET}"
    elif [[ "$manager" == NetworkManager* ]] && have nmcli; then
      warn "Persistent alternative: ${C_BOLD}$0 --nm <provider>${C_RESET}"
    fi
    if [[ -t 0 ]]; then
      read -r -p "Write to the file anyway? [y/N] " ans
      [[ "$(norm "$ans")" =~ ^(y|yes)$ ]] || die "Aborted by user."
    else
      die "Re-run with --force to write anyway."
    fi
  fi

  content="$(build_block "$servers")"   # note: $(...) strips the final newline

  if [[ $DRY_RUN -eq 1 ]]; then
    title "[dry-run] Would write to ${write_path}"
    printf '%s\n' "$content" | sed 's/^/  /'
    if [[ -e "$TARGET" ]]; then
      title "[dry-run] Current contents"
      sed 's/^/  /' "$TARGET"; echo
    fi
    return 0
  fi

  if [[ ! -w "$write_path" && -e "$write_path" ]] && ! is_root; then
    die "No write permission for ${write_path}."
  fi

  backup_target "$TARGET"
  unlock_file

  TMP_FILE="$(mktemp "${write_path}.setdns.XXXXXX" 2>/dev/null || mktemp)"
  printf '%s\n' "$content" > "$TMP_FILE"
  chmod 644 "$TMP_FILE"
  if is_root; then chown root:root "$TMP_FILE" 2>/dev/null || true; fi
  install_file "$TMP_FILE" "$write_path" \
    || die "Could not write ${write_path} (read-only filesystem or permission denied)."
  TMP_FILE=""

  if [[ "$USE_IPV6" == "auto" ]] && ! has_ipv6; then
    info "No IPv6 connectivity detected — only IPv4 nameservers were written."
  fi
  ok "DNS provider set to ${C_BOLD}${BLOCK_LABEL}${C_RESET}"
  sed 's/^/  /' "$write_path"
  [[ $LOCK_AFTER -eq 1 ]] && lock_file
  return 0
}

# Accepts a provider name, a menu number, or a list of raw IP addresses.
resolve_selection() {
  local sel key word
  sel="$(norm "$1")"
  [[ -n "$sel" ]] || die "Empty selection."

  if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#PROVIDERS[@]} )); then
    key="${PROVIDERS[$((sel - 1))]}"
    SEL_SERVERS="${P_V4[$key]} ${P_V6[$key]}"
    SEL_LABEL="${P_LABEL[$key]}"
    SEL_KEY="$key"
    return 0
  fi

  for key in "${PROVIDERS[@]}"; do
    if [[ "$key" == "$sel" ]]; then
      SEL_SERVERS="${P_V4[$key]} ${P_V6[$key]}"
      SEL_LABEL="${P_LABEL[$key]}"
      SEL_KEY="$key"
      return 0
    fi
  done

  SEL_SERVERS=""
  local saw_v6=0
  for word in $sel; do
    valid_ip "$word" || die "Not a provider name and not a valid IP: ${C_BOLD}${word}${C_RESET}"
    [[ "$word" == *:* ]] && saw_v6=1
    SEL_SERVERS+="${SEL_SERVERS:+ }${word}"
  done
  [[ -n "$SEL_SERVERS" ]] || die "Nothing to apply: ${C_BOLD}$1${C_RESET} (see --list)"
  # explicit addresses are used exactly as typed
  if (( saw_v6 == 1 )) && [[ "$USE_IPV6" == "auto" ]]; then USE_IPV6="on"; IPV6_OK=""; fi
  SEL_LABEL="custom"
  return 0
}

set_provider() {
  resolve_selection "$1"
  need_root
  if [[ $PROFILE_MODE -eq 1 ]]; then
    apply_dropin "$SEL_SERVERS" "$SEL_KEY" "$DOT_MODE"
  elif [[ $RESOLVED_MODE -eq 1 ]]; then
    apply_resolved "$SEL_SERVERS"
  elif [[ $NM_MODE -eq 1 ]]; then
    apply_nmcli "$SEL_SERVERS"
  else
    apply_servers "$SEL_SERVERS"
    if [[ $VERIFY_AFTER -eq 1 && $DRY_RUN -eq 0 ]]; then
      verify_dns "$SEL_SERVERS" || warn "Some checks failed — inspect firewall / IPv6."
    fi
  fi
  return 0
}

# --------------------------------------------------------------------------
# Self-test: exercises every code path against throwaway files
# --------------------------------------------------------------------------
selftest() {
  local tmp pass=0 fail=0 rc
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/setdns-selftest.XXXXXX")" || die "mktemp failed"

  assert_eq()    { if [[ "$2" == "$3" ]]; then ok "$1"; pass=$((pass+1));
                   else err "$1 (expected '$2', got '$3')"; fail=$((fail+1)); fi; }
  assert_true()  { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; pass=$((pass+1));
                   else err "$d"; fail=$((fail+1)); fi; }
  assert_false() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then err "$d"; fail=$((fail+1));
                   else ok "$d"; pass=$((pass+1)); fi; }
  run() { ( SETDNS_SKIP_ROOT=1 bash "$SELF" "$@" ); }
  count_baks() {           # count_baks <path> -> number of backups
    local -a f=()
    local g
    shopt -s nullglob
    for g in "$1".bak.*; do
      case "$g" in *.content|*.link) continue ;; esac
      f+=("$g")
    done
    shopt -u nullglob
    printf '%s' "${#f[@]}"
  }

  local rc_conf="${tmp}/resolv.conf"
  printf 'nameserver 10.0.0.1\n' > "$rc_conf"

  title "setdns.sh self-test  ${C_DIM}(${tmp})${C_RESET}"

  # 1 — sanity
  assert_eq "--version reports ${VERSION}" "0" "$(run --version >/dev/null 2>&1; echo $?)"
  assert_eq "--list exits 0"               "0" "$(run --list >/dev/null 2>&1; echo $?)"
  assert_eq "--help exits 0"               "0" "$(run --help >/dev/null 2>&1; echo $?)"

  # 2 — dry-run must not touch the file
  run --dry-run --no-verify -t "$rc_conf" 1 >/dev/null 2>&1
  assert_eq "dry-run leaves file untouched" "nameserver 10.0.0.1" "$(cat "$rc_conf")"
  assert_eq "dry-run creates no backup" "0" "$(count_baks "$rc_conf")"

  # 3 — apply by menu number
  run --no-verify -q -t "$rc_conf" 1 >/dev/null 2>&1
  assert_true "menu number 1 writes Cloudflare" grep -q '^nameserver 1.1.1.1$' "$rc_conf"
  assert_true "a backup was created"            bash -c "ls ${rc_conf}.bak.* >/dev/null 2>&1"

  # 4 — apply by provider name
  run --no-verify -q --force --ipv6 -t "$rc_conf" google >/dev/null 2>&1
  assert_true "name 'google' writes 8.8.8.8"    grep -q '^nameserver 8.8.8.8$' "$rc_conf"
  assert_true "--ipv6 includes IPv6 server"     grep -q '^nameserver 2001:4860:4860::8888$' "$rc_conf"

  # 5 — IPv4-only mode
  run --no-verify -q --force --no-ipv6 -t "$rc_conf" quad9 >/dev/null 2>&1
  assert_true  "--no-ipv6 writes 9.9.9.9"       grep -q '^nameserver 9.9.9.9$' "$rc_conf"
  assert_false "--no-ipv6 omits IPv6"           grep -q '^nameserver 2620:' "$rc_conf"

  # 6 — trailing newline + resolver options
  assert_eq "file ends with a newline" "0" \
    "$(bash -c '[ "$(tail -c 1 '"$rc_conf"' | od -An -c | tr -d " \n")" = "\n" ]'; echo $?)"
  run --no-verify -q --force --no-ipv6 -t "$rc_conf" adguard >/dev/null 2>&1
  assert_true "options line present" grep -q '^options edns0' "$rc_conf"
  run --no-verify -q --force --no-options --no-ipv6 -t "$rc_conf" adguard >/dev/null 2>&1
  assert_false "--no-options drops it" grep -q '^options ' "$rc_conf"

  # 7 — custom addresses
  run --no-verify -q --force -t "$rc_conf" "1.1.1.1 9.9.9.9" >/dev/null 2>&1
  assert_eq "custom IPs written" "2" "$(grep -c '^nameserver ' "$rc_conf")"
  assert_true "custom IP 9.9.9.9 present" grep -q '^nameserver 9.9.9.9$' "$rc_conf"

  # 8 — input validation
  assert_false "rejects 999.1.1.1"  run --no-verify -q -t "$rc_conf" 999.1.1.1
  assert_false "rejects 1.2.3"      run --no-verify -q -t "$rc_conf" 1.2.3
  assert_false "rejects 'foobar'"   run --no-verify -q -t "$rc_conf" foobar
  assert_false "rejects unknown flag" run --no-verify -q --bogus
  assert_false "rejects out-of-range menu number" run --no-verify -q -t "$rc_conf" 99
  assert_eq "file untouched after bad input" "2" "$(grep -c '^nameserver ' "$rc_conf")"

  # 9 — restore round-trip
  printf 'nameserver 10.20.30.40\n' > "$rc_conf"
  run --no-verify -q --force -t "$rc_conf" cloudflare >/dev/null 2>&1
  run --no-verify -q -t "$rc_conf" --restore >/dev/null 2>&1
  assert_eq "--restore brings back previous content" "nameserver 10.20.30.40" "$(cat "$rc_conf")"

  # 10 — backup pruning
  rm -f "${rc_conf}".bak.* 2>/dev/null || true
  local i
  for i in 1 2 3 4 5; do run --no-verify -q --force --keep 2 -t "$rc_conf" "$i" >/dev/null 2>&1; done
  assert_eq "--keep 2 retains exactly 2 backups" "2" \
    "$(count_baks "$rc_conf")"

  # 11 — same-second backups must not collide
  rm -f "${rc_conf}".bak.* 2>/dev/null || true
  run --no-verify -q --force -t "$rc_conf" 1 >/dev/null 2>&1
  run --no-verify -q --force -t "$rc_conf" 2 >/dev/null 2>&1
  run --no-verify -q --force -t "$rc_conf" 3 >/dev/null 2>&1
  assert_eq "3 rapid writes keep 3 distinct backups" "3" \
    "$(count_baks "$rc_conf")"

  # 12 — symlinked resolv.conf: write through the link, keep the link
  local ldir="${tmp}/link" real="${tmp}/real.conf"
  mkdir -p "$ldir"; printf 'nameserver 10.7.7.7\n' > "$real"
  ln -s "$real" "${ldir}/resolv.conf"
  run --no-verify -q --force -t "${ldir}/resolv.conf" opendns >/dev/null 2>&1
  assert_true "symlink still a symlink" test -L "${ldir}/resolv.conf"
  assert_true "content written through the link" grep -q '^nameserver 208.67.222.222$' "$real"

  # 13 — --replace-symlink converts to a regular file, restore puts it back
  run --no-verify -q --force --replace-symlink -t "${ldir}/resolv.conf" verisign >/dev/null 2>&1
  assert_false "--replace-symlink removed the link" test -L "${ldir}/resolv.conf"
  run --no-verify -q -t "${ldir}/resolv.conf" --restore >/dev/null 2>&1
  assert_true "--restore recreated the symlink" test -L "${ldir}/resolv.conf"

  # 14 — verify reports unreachable servers without crashing
  rc=0; run -q -t "$rc_conf" --verify "240.0.0.1" >/dev/null 2>&1 || rc=$?
  assert_eq "--verify flags an unreachable server" "1" "$rc"

  # 15 — external profile: add, override and validate
  local prof="${tmp}/profile.txt"
  {
    printf '# comment line\n'
    printf 'home|HomePiHole|192.168.1.10||LAN ad blocker.|\n'
    printf 'google|GoogleCustomPin|8.8.8.8 8.8.4.4||custom pin test|DEADBEEF\n'
  } > "$prof"
  run --profile "$prof" --list >/dev/null 2>&1
  assert_true "--profile adds a new key to the listing" grep -q "HomePiHole" <(run --profile "$prof" --list 2>/dev/null)
  assert_true "--profile overrides a built-in label"   grep -q "GoogleCustomPin" <(run --profile "$prof" --list 2>/dev/null)
  run --no-verify -q --force --profile "$prof" -t "$rc_conf" home >/dev/null 2>&1
  assert_true "profile entry applies its servers" grep -q '^nameserver 192.168.1.10$' "$rc_conf"
  printf 'evil|Bad|999.1.1.1|||\n' > "${tmp}/bad-profile.txt"
  assert_false "rejects invalid IP in profile file" run --profile "${tmp}/bad-profile.txt" --list

  # 16 — systemd drop-in generation (fake systemctl on PATH for the test)
  local fakebin="${tmp}/bin" ddir="${tmp}/resolved.conf.d"
  mkdir -p "$fakebin" "$ddir"
  printf '#!/bin/sh\nexit 0\n' > "${fakebin}/systemctl"; chmod +x "${fakebin}/systemctl"
  local old_path="$PATH"
  PATH="${fakebin}:$PATH"
  run --dropin-dir "$ddir" --dot cloudflare --dry-run >/dev/null 2>&1
  assert_false "drop-in dry-run writes nothing" test -s "${ddir}/setdns.conf"
  run --dropin-dir "$ddir" --dot cloudflare >/dev/null 2>&1
  assert_true "drop-in written"                test -s "${ddir}/setdns.conf"
  assert_true "drop-in pins DoT fingerprint"   grep -q 'DNS=1\.1\.1\.1~D7A7D0F5.*' "${ddir}/setdns.conf"
  assert_true "drop-in enables DNSOverTLS"     grep -q '^DNSOverTLS=yes$' "${ddir}/setdns.conf"
  assert_true "drop-in has [Resolve] section"  grep -q '^\[Resolve\]$' "${ddir}/setdns.conf"
  PATH="$old_path"

  echo
  if (( fail == 0 )); then
    ok "All ${pass} self-tests passed."
  else
    err "${fail} of $((pass + fail)) self-tests FAILED."
  fi
  rm -rf "$tmp"
  (( fail == 0 ))
}

# --------------------------------------------------------------------------
# Interactive menu
# --------------------------------------------------------------------------
confirm() {
  local prompt="${1:-Are you sure?}" ans
  [[ $FORCE -eq 1 ]] && return 0
  [[ -t 0 ]] || return 0
  read -r -p "${prompt} [y/N] " ans
  [[ "$(norm "$ans")" =~ ^(y|yes)$ ]]
}

menu() {
  local n=${#PROVIDERS[@]} choice key i f
  while true; do
    title "Select a DNS provider   ${C_DIM}(editing ${TARGET})${C_RESET}"
    for i in "${!PROVIDERS[@]}"; do
      key="${PROVIDERS[$i]}"
      printf '  %s%2d)%s %-30s %s\n' "$C_BOLD$C_GREEN" "$((i + 1))" "$C_RESET" \
             "${P_LABEL[$key]}" "${C_DIM}${P_V4[$key]}${C_RESET}"
    done
    printf '  %s%2d)%s %-30s\n' "$C_BOLD$C_GREEN" "$((n + 1))" "$C_RESET" "Custom — enter IP(s)"
    printf '  %s%2d)%s %-30s\n' "$C_BOLD$C_GREEN" "$((n + 2))" "$C_RESET" "Restore previous backup"
    printf '  %s%2d)%s %-30s\n' "$C_BOLD$C_GREEN" "$((n + 3))" "$C_RESET" "Show current + verify"
    printf '  %s%2d)%s %-30s\n' "$C_BOLD$C_GREEN" 0 "$C_RESET" "Quit"
    echo
    printf '%sChoice:%s ' "$C_BOLD$C_GREEN" "$C_RESET"
    IFS= read -r choice || { echo; break; }
    choice="$(norm "$choice")"

    case "$choice" in
      ""|q|quit|exit|0) echo; break ;;
      "$((n + 1))")
        printf 'Enter nameserver(s), space separated: '
        IFS= read -r CUSTOM_SERVERS || continue
        [[ -n "$(norm "$CUSTOM_SERVERS")" ]] || { warn "Nothing entered."; continue; }
        set_provider "$CUSTOM_SERVERS" || true ;;
      "$((n + 2))")
        f="$(newest_backup)"
        if [[ -z "$f" ]]; then warn "No backups found for ${TARGET}."; continue; fi
        info "Newest backup: ${f}"
        sed 's/^/    /' "$f" 2>/dev/null || true
        if confirm "Restore this backup?"; then restore_backup "$f" || true; fi ;;
      "$((n + 3))")
        show_current; verify_dns "" || true ;;
      *)
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= n )); then
          key="${PROVIDERS[$((choice - 1))]}"
          info "${P_LABEL[$key]} — ${P_NOTE[$key]}"
          if confirm "Apply ${P_LABEL[$key]}?"; then set_provider "$key" || true; fi
        else
          warn "Invalid choice: '${choice}'"
        fi ;;
    esac
    echo
  done
  return 0
}

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
ARGS=("$@")
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)      usage; exit 0 ;;
    -V|--version)   echo "setdns.sh ${VERSION}"; exit 0 ;;
    -l|--list)      if [[ -n "${PROFILE_FILE:-}" ]]; then load_profile "$PROFILE_FILE"; fi
                    list_providers; exit 0 ;;
    -c|--current)   show_current; exit 0 ;;
    -b|--backups)   if [[ -z "$(newest_backup)" ]]; then
                      warn "No backups found for ${TARGET}."
                    else
                      title "Backups of ${TARGET} (newest first)"; list_backups
                    fi
                    exit 0 ;;
    -r|--restore)   shift
                    if [[ $# -gt 0 && "${1:0:1}" != "-" ]]; then RESTORE_FILE="$1"; shift; fi
                    need_root; restore_backup "$RESTORE_FILE"; exit 0 ;;
    -v|--verify)    shift
                    if [[ $# -gt 0 && "${1:0:1}" != "-" ]]; then CUSTOM_SERVERS="$1"; shift; fi
                    verify_dns "$CUSTOM_SERVERS"; exit 0 ;;
    -t|--target)    TARGET="${2:---target needs a path}"; shift 2 ;;
    -i|--iface)     IFACE="${2:---iface needs a name}"; shift 2 ;;
    --resolved)     RESOLVED_MODE=1; shift ;;
    --nm|--networkmanager) NM_MODE=1; shift ;;
    --ipv6)         USE_IPV6="on"; shift ;;
    --no-ipv6)      USE_IPV6="off"; shift ;;
    --no-options)   ADD_OPTIONS=0; shift ;;
    --lock)         LOCK_AFTER=1; shift ;;
    --unlock)       UNLOCK_ONLY=1; shift ;;
    --selftest)     selftest; exit $? ;;
    --keep)         KEEP_BACKUPS="${2:---keep needs a number}"; shift 2 ;;
    -n|--dry-run)   DRY_RUN=1; shift ;;
    -f|--force)     FORCE=1; shift ;;
    --replace-symlink) REPLACE_SYMLINK=1; shift ;;
    --no-verify)    VERIFY_AFTER=0; shift ;;
    --profile)      PROFILE_MODE=1; PROFILE_FILE="${2:---profile needs a file}"; shift 2 ;;
    --dropin-dir)   PROFILE_MODE=1; DROPIN_DIR="${2:---dropin-dir needs a path}"; shift 2 ;;
    --dot)          PROFILE_MODE=1; DOT_MODE=1; shift ;;
    --make-profile) shift
                    if [[ $# -gt 0 && "${1:0:1}" != "-" ]]; then load_profile "$1"; fi
                    make_profile; exit 0 ;;
    -q|--quiet)     QUIET=1; shift ;;
    --)             shift; while [[ $# -gt 0 ]]; do POSITIONAL+=("$1"); shift; done; break ;;
    -*)             die "Unknown option: $1 (see --help)" ;;
    *)              POSITIONAL+=("$1"); shift ;;
  esac
done

if [[ ${#POSITIONAL[@]} -gt 0 ]]; then set -- "${POSITIONAL[@]}"; else set --; fi

# Load an external profile before anything else touches the provider table.
if [[ -n "$PROFILE_FILE" ]]; then load_profile "$PROFILE_FILE"; fi

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
if [[ $UNLOCK_ONLY -eq 1 ]]; then
  need_root
  unlock_file
  ok "${TARGET} is writable again."
  exit 0
fi

if [[ $# -eq 0 ]]; then
  if [[ -t 0 && -t 1 ]]; then
    need_root
    show_current
    menu
    exit 0
  fi
  usage
  exit 1
fi

set_provider "$*"
