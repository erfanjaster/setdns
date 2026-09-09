# setdns.sh

A single-file Bash tool that switches `/etc/resolv.conf` between the popular
public DNS providers, with an interactive menu (1–6), one-shot mode, backups,
restore, and live verification.

```
$ sudo ./setdns.sh

Select a DNS provider   (editing /etc/resolv.conf)
   1) Cloudflare                     1.1.1.1 1.0.0.1
   2) Google Public DNS              8.8.8.8 8.8.4.4
   3) Quad9 (malware blocking)       9.9.9.9 149.112.112.112
   4) AdGuard (ad blocking)          94.140.14.14 94.140.15.15
   5) OpenDNS (Cisco)                208.67.222.222 208.67.220.220
   6) Verisign                       64.6.64.6 64.6.65.6
   7) Custom — enter IP(s)
   8) Restore previous backup
   9) Show current + verify
   0) Quit

Choice:
```

## Install

```bash
chmod +x setdns.sh
sudo mv setdns.sh /usr/local/bin/setdns      # optional: run it from anywhere
setdns --list
```

Requires Bash 4+ (associative arrays). No other dependencies — `dig`,
`nslookup`, `host`, `python3` or `getent` are used for verification, whichever
exists first.

## Quick start

```bash
sudo ./setdns.sh                    # interactive menu
sudo ./setdns.sh cloudflare         # by name
sudo ./setdns.sh 3                  # by menu number (Quad9)
sudo ./setdns.sh "1.1.1.1 9.9.9.9"  # your own addresses
sudo ./setdns.sh --restore          # undo — restores the newest backup
```

## Providers

| # | key         | IPv4                      | What it is                              |
|---|-------------|---------------------------|-----------------------------------------|
| 1 | `cloudflare`| 1.1.1.1 / 1.0.0.1         | Fastest worldwide, strict no-log policy |
| 2 | `google`    | 8.8.8.8 / 8.8.4.4         | Extremely reliable, huge anycast net    |
| 3 | `quad9`     | 9.9.9.9 / 149.112.112.112 | Non-profit, blocks malicious domains    |
| 4 | `adguard`   | 94.140.14.14 / .15.15     | Blocks ads & trackers at DNS level      |
| 5 | `opendns`   | 208.67.222.222 / .220.220 | Cisco, good family/parental options     |
| 6 | `verisign`  | 64.6.64.6 / 64.6.65.6     | Privacy focused, no-log                 |

Each entry also carries the provider's IPv6 addresses.

## Commands & flags

| Option | Meaning |
|---|---|
| `-l, --list` | list providers with all addresses |
| `-c, --current` | show the active `resolv.conf` |
| `-b, --backups` | list restorable backups (newest first) |
| `-r, --restore [FILE]` | restore a backup (newest if omitted) |
| `-v, --verify [IPS]` | test that resolution actually works |
| `--unlock` | remove the immutable lock (`chattr -i`) |
| `--selftest` | run the 30 built-in tests |
| `-t, --target PATH` | edit another file (default `/etc/resolv.conf`) |
| `-i, --iface NAME` | interface for `--resolved` / `--nm` |
| `--resolved` | apply via `resolvectl` (systemd-resolved, persistent) |
| `--nm` | apply via `nmcli` (NetworkManager, persistent) |
| `--ipv6` / `--no-ipv6` | force IPv6 servers on / off (default: auto) |
| `--no-options` | omit the `options edns0 trust-ad …` line |
| `--lock` | `chattr +i` after writing, so managers can't overwrite it |
| `--keep N` | how many backups to retain (default 10) |
| `-n, --dry-run` | show the change, write nothing |
| `-f, --force` | skip prompts and manager warnings |
| `--replace-symlink` | turn a symlinked `resolv.conf` into a real file |
| `--no-verify` | skip the post-apply resolution test |
| `-q, --quiet` | minimal output |

## What makes it safe

- **Backups first.** Every write copies the current file to
  `/etc/resolv.conf.bak.YYYYmmdd-HHMMSS`. Same-second runs get a `-1`, `-2`
  suffix so nothing is ever clobbered. Old backups are pruned to `--keep`.
- **Atomic write.** Content goes to a temp file in the same directory, then
  `mv` replaces the target. If the target is **bind-mounted** (Docker, LXC,
  WSL) `mv` fails with `EBUSY`, so it transparently falls back to an in-place
  rewrite that keeps the inode and the mount.
- **Symlink aware.** If `/etc/resolv.conf` is a symlink it writes through to
  the real file and leaves the link intact. `--replace-symlink` converts it to
  a regular file and records the link in a `.link` backup so `--restore` puts
  it back.
- **Manager detection.** Warns when systemd-resolved / NetworkManager /
  connman / resolvconf own the file (your edit would be reverted), and offers
  the persistent route: `--resolved` or `--nm`. Non-interactive runs stop and
  ask for `--force` instead of silently doing something that won't stick.
- **IPv6 auto-detection.** If the host has no global IPv6 address, IPv6
  nameservers are skipped (they only add query latency) and the file records
  why. Override with `--ipv6`; addresses you type yourself are always honoured.
- **Validation.** Provider names, menu numbers and IP literals (v4 and v6) are
  validated before anything is written; bad input changes nothing.
- **Verification.** After applying, each nameserver is probed with a real DNS
  query, plus a system-resolver check. Falls back to a dependency-free raw
  UDP DNS query in Python when `dig`/`nslookup`/`host` are missing.
- **Root handling.** Re-executes itself under `sudo` if needed (preserving all
  arguments), resolves its own absolute path, and degrades to read-only
  dry-run mode when neither root nor sudo is available.
- `shellcheck` clean, `set -Eeuo pipefail`, temp-file trap on EXIT/INT/TERM.

## Examples

```bash
sudo ./setdns.sh 4 --no-ipv6 --lock     # AdGuard, IPv4 only, locked against overwrite
sudo ./setdns.sh --resolved google      # persistent on a systemd-resolved system
sudo ./setdns.sh --nm cloudflare        # persistent on a NetworkManager system
sudo ./setdns.sh --dry-run "9.9.9.9"    # preview only
./setdns.sh --backups                   # what can I roll back to?
sudo ./setdns.sh --restore /etc/resolv.conf.bak.20260909-001019
sudo ./setdns.sh --unlock               # after using --lock
```

## Troubleshooting

**"Device or resource busy" / changes revert** — a manager owns the file.
Use `--resolved` or `--nm`, or `--lock` to pin it.

**Nothing resolves after switching** — roll back instantly with
`sudo ./setdns.sh --restore`. If your network blocks outbound DNS to third
parties, verify with `sudo ./setdns.sh --verify`.

**IPv6 servers show as unreachable** — normal on IPv4-only networks; they are
auto-skipped by default and don't affect resolution.

**Flush the cache after switching** —
`sudo systemd-resolve --flush-caches` or `sudo resolvectl flush-caches`.

## Add your own provider

Edit the arrays near the top of the script — the menu builds itself from them:

```bash
PROVIDERS=(cloudflare google quad9 adguard opendns verisign mydns)
P_LABEL[mydns]="My Local Resolver"
P_V4[mydns]="192.168.1.1"
P_V6[mydns]="fd00::1"
P_NOTE[mydns]="Router DNS with LAN split-horizon."
```

## Test

```bash
./setdns.sh --selftest     # 30 assertions: writes, backups, restore,
                           # symlinks, validation, pruning, verification
```
