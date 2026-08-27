# system-administration

[![CI](https://github.com/Nostraxiten/system-administration/actions/workflows/ci.yml/badge.svg)](https://github.com/Nostraxiten/system-administration/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows%20Server-lightgrey.svg)](#platform-support)

An interactive attack-surface and health scanner for a single Linux or Windows
Server host. It reads what the machine already knows about itself, classifies
what it finds, and hands back a report a system administrator can act on
without reading the whole dump.

Read this in Spanish: [README.es.md](README.es.md).

<img width="600" height="366" alt="image" src="https://github.com/user-attachments/assets/ef9aad9c-da88-4cba-ab68-fd026ec6999a" />

## Table of contents

- [Description](#description)
- [Scope](#scope)
- [Installation](#installation)
- [Usage](#usage)
- [Reports](#reports)
- [Modules](#modules)
- [Vulnerability database](#vulnerability-database)
- [Privileges](#privileges)
- [Platform support](#platform-support)
- [Building from source](#building-from-source)
- [Design notes](#design-notes)
- [Limitations](#limitations)
- [License](#license)

## Description

`system-administration` is a single self-contained binary with no runtime
dependencies. It is aimed at the moment an administrator inherits a server and
needs to know, quickly, what is exposed, what is running, who can log in, and
whether anything has been left behind.

Nine diagnostic modules run in sequence. Each one states what it inspected,
what it found, and how serious each finding is on a three-level scale:
informational, attention, critical. The summary lifts every attention and
critical finding to the top, so a full read is optional rather than mandatory.

There are no flags, no subcommands and no help text to memorise. Launching the
executable starts a guided sequence: choose a language, confirm the detected
system, watch the scan progress, choose where the report goes.

## Scope

The tool inspects the machine it runs on and nothing else. It contains no
remote scanning, no exploitation, no credential testing and no lateral
movement, and it is not built to acquire access it was not given.

The single network operation in the whole program is an HTTP `HEAD` request to
`127.0.0.1` on ports where a local web server is already listening, used to
read the response headers that server sends to every visitor. No other host is
contacted, and no data leaves the machine.

## Installation

### One line

Linux, any distribution:

```
curl -fsSL https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.sh | sh
```

Windows Server, from PowerShell:

```
irm https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.ps1 | iex
```

Either one leaves a single executable on your `PATH`, so from then on the tool
runs from anywhere by name:

```
system-administration
```

The installer downloads the published binary for your platform when one exists
and compiles the source otherwise, which is what makes it work on distributions
and architectures with no published build. The Linux binary is linked
statically against musl, so it does not depend on the distribution's glibc.
Nothing else is installed: no service is registered and no file is written
until a report is saved.

Where the executable lands:

| Platform | Installed by | Directory |
| --- | --- | --- |
| Linux | `root` | `/usr/local/bin` |
| Linux | any other user | `~/.local/bin` |
| Windows | any user | `%LOCALAPPDATA%\Programs\system-administration` |

### Installer options

On Linux they are flags, passed after `sh -s --`:

```
curl -fsSL https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.sh | sh -s -- --dir /opt/bin
```

| Flag | Environment variable | Effect |
| --- | --- | --- |
| `--dir DIR` | `SYSADM_INSTALL_DIR` | install into another directory |
| `--version TAG` | `SYSADM_VERSION` | install a given release instead of the latest |
| `--source` | `SYSADM_FROM_SOURCE=1` | always compile, never download |

On Windows only the environment variables apply, because `iex` cannot forward
arguments:

```
$env:SYSADM_INSTALL_DIR = 'C:\tools'
irm https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.ps1 | iex
```

### Manual install

Download the archive for your platform from
[Releases](https://github.com/Nostraxiten/system-administration/releases), check
it against the published `.sha256`, and put the executable anywhere on `PATH`:

```
# Linux
tar -xzf system-administration-x86_64-unknown-linux-musl.tar.gz
sudo install -m 755 system-administration /usr/local/bin/

# Windows Server
Expand-Archive system-administration-x86_64-pc-windows-msvc.zip -DestinationPath .
```

### Removing it

The installer adds one file, so deleting that file is the entire uninstall:

```
# Linux
rm -f /usr/local/bin/system-administration

# Windows Server
Remove-Item "$env:LOCALAPPDATA\Programs\system-administration" -Recurse
```

Running as `root` or as an administrator is optional but recommended; see
[Privileges](#privileges).

## Usage

The whole run is a sequence of prompts, each with a safe default, so the scan
can be completed by pressing Enter through it.

1. **Language.** Spanish or English. Everything that follows, including the
   report, is produced in the chosen language.
2. **System confirmation.** The system is detected automatically, from
   `/etc/os-release` on Linux and from `Win32_OperatingSystem` on Windows, and
   the evidence behind the guess is shown. Answering *no* opens a catalogue of
   supported systems whose first entry is a recommendation derived from that
   evidence: package manager, kernel or build number, init system. The choice
   never depends on recognising a distribution by name.
3. **Diagnostics.** All nine modules run behind a progress bar that names the
   module and the phase it is in.
4. **Report.** Answering *yes* to saving asks for a folder name (default
   `sys`) and a destination path; leaving the path empty creates the folder
   next to the executable. Answering *no* prints the report on screen, one
   module per page.

## Reports

Saving to a folder writes plain UTF-8 text:

| File | Contents |
| --- | --- |
| `00-overall-summary.<lang>.txt` | Header, totals, module index and every attention and critical finding |
| `01-users.<lang>.txt` … `09-hosts.<lang>.txt` | One file per module: what was checked, what was found, evidence |
| `findings.<lang>.csv` | Every finding as a row, most serious first, for a ticket system or a spreadsheet |

The screen report contains exactly the same text, coloured by severity and
paginated so nothing scrolls past unread.

Every report carries a header with the host, the detected system, the kernel or
build, the architecture, the uptime, the operator account, whether the scan ran
with elevated privileges, and how long it took.

## Modules

| Module | What it looks at |
| --- | --- |
| **System users** | Local accounts and their shell, UID 0 or administrator membership, password state, privileged groups and passwordless elevation rules, last logins and dormant accounts, home directory permissions, authorised SSH keys |
| **Running processes** | Process inventory with owner and command line, real binary path, processes whose binary was deleted after starting, execution from writable or temporary paths, names imitating system processes, reverse shell patterns in command lines, CPU and memory outliers, processes hidden from the standard listing |
| **Shells and persistence** | Scheduled tasks system-wide and per user, timers and units, services outside the packaged set, autostart hooks and boot scripts, shell startup files, command history searched for reverse shells, history disabled or redirected, globally preloaded libraries, authorised keys as a persistence mechanism |
| **Dangerous or disguised files** | Deep walk of the critical paths, double extensions, bidirectional and invisible control characters in names, trailing spaces, SUID/SGID binaries outside the baseline, world-writable critical paths, hidden files in system directories, executables in temporary directories, files with no valid owner, alternate data streams |
| **Ports and network** | Listening TCP and UDP ports with their bind address and owning process, ports exposed on every interface, known risky services reachable, established connections and their remote endpoint, interfaces with addresses, MAC, MTU and counters, promiscuous mode, IP forwarding, local firewall state |
| **Web services** | Web servers running and the ports they own, version taken from the binary, response headers read over loopback, version disclosure, missing hardening headers, directory listing enabled, default sites left untouched, configuration file permissions, PHP settings that leak information |
| **Version checker** | Kernel release or build number, distribution version and support status, package inventory from the native package manager, versions of the exposed services, matches against the local vulnerability database, pending updates, pending reboot |
| **Authentication logs** | Location and readability of each log source, failed authentication grouped by origin, brute force patterns and how they ended, successful logins following a burst of failures, direct root or administrator logins, privilege elevation usage and failures, account creation, logs that are empty, truncated or cleared |
| **IP addresses on the network** | The host's own ARP/NDP neighbour table, gateway and local subnets, names resolved from local files only, MAC addresses repeated across several IPs, unresolved entries, remote endpoints of established connections |

Modules live in `src/modules/`, one file each, behind a common `Scanner` trait.
Adding one means writing that file and listing it in `modules::all()`.

## Vulnerability database

The version checker matches against `data/vuln-db.txt`, which is compiled into
the binary. The check therefore works on an isolated network and contacts no
external service.

To use fresher data without rebuilding, place a file in the same format next to
the executable as `vuln-db.txt`, or point `SYSADM_VULN_DB` at one. External
records override built-in records with the same product and identifier.

The format is one record per line, pipe separated:

```
kind|product|fixed_in|severity|id|description
```

`kind` is `pkg` for an installed package, `svc` for a running service matched by
its version banner, or `os` for a distribution release. `fixed_in` is the first
version that is not affected; write `from..fixed` when only a window of
versions is affected, so a long-term branch that never carried the flaw is not
reported for being numerically older than the fix.

Matching is by version number. Distributions routinely fix a vulnerability with
a backported patch and no version bump, so a match is a prompt to check the
package changelog, not a verdict. The report says so on every run.

## Privileges

The scan runs without elevated privileges and says so in the report, listing
the sources it could not read. With elevated privileges it additionally sees:

- password state from `/etc/shadow`, and the ACLs behind Windows accounts;
- the process behind each listening socket;
- per-user scheduled tasks and other users' home directories;
- the authentication logs on most configurations.

Findings that depend on privilege are worded accordingly: a listening port with
no identifiable process is informational for an unprivileged scan and an
attention finding for a privileged one, because only in the second case does it
mean something.

## Platform support

| Platform | Status |
| --- | --- |
| Linux, glibc or musl, kernel 3.x and newer | Supported |
| Windows Server 2012 R2 and newer | Supported |
| Windows 10 and 11 | Supported |
| Android (Termux), aarch64 and x86_64 | **Not supported.** Building from source fails on Termux's Rust toolchain; see the warning above |
| macOS, BSD | Not supported; the build fails with an explicit message |

The Linux collector reads `/proc` and `/etc` directly, so it behaves the same
on a minimal container and on a full server and keeps working when `ss`,
`netstat` or `systemctl` are absent. External tools are used only as a
fallback.

The Windows collector uses PowerShell for structured queries, the registry for
boot-time hooks, and the classic console tools where they are faster. It reads
the software inventory from the uninstall registry rather than through
`Win32_Product`, which would reconfigure every installed MSI package.

## Building from source

Requires Rust 1.82 or newer.

```
git clone https://github.com/Nostraxiten/system-administration.git
cd system-administration
cargo build --release
```

The binary is written to `target/release/system-administration`.

Cross-compiling and checking the other platform:

```
rustup target add x86_64-pc-windows-msvc
cargo check --target x86_64-pc-windows-msvc
```

Tests, lints and formatting, the same three the CI runs:

```
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

> [!CAUTION]
> **NO SUPPORT FOR TERMUX.** Building from source on Termux/Android fails
> with `error: crate `std` required to be available in rlib format, but was
> not found in this form` — a limitation of Termux's own Rust packaging
> (its `std` is shipped only as a dynamic library, not as `.rlib` files),
> not something this project can fix in its own source. Track it upstream:
> [termux/termux-packages issues](https://github.com/termux/termux-packages/issues).
> Do not open issues here about Termux builds; they will be closed as
> not-supported.

## Design notes

- **One shared surface.** `src/platform/mod.rs` declares the types and function
  signatures both collectors implement. Modules are written once against it,
  and `cfg(target_os)` decides which collector is compiled in, so a Linux build
  contains no Windows code and vice versa.
- **Translation is a compile-time contract.** Every user-visible string is a
  field of a `const` catalogue in `src/i18n/`. Adding a language is a compile
  error until every field is filled in, and no string can be missing at
  runtime.
- **Findings are grouped before they are reported.** A hundred entries for one
  unpacked directory buries the one entry that matters, so categories that
  occur in bulk are summarised with a count and a sample.
- **False positives are treated as defects.** Symbolic links are excluded from
  permission checks because their mode is always `0777` and means nothing;
  thread ids are excluded from the hidden-process check because every thread is
  addressable but unlisted; a locked account reachable by SSH key is the
  recommended configuration and is not reported as a problem.

## Limitations

- Version matching cannot see backported patches; see
  [Vulnerability database](#vulnerability-database).
- NTFS access is decided per file by an ACL, and evaluating one for every file
  on a server is not practical, so the Windows file walk reports names,
  placement and streams while ACLs are checked individually on the paths that
  matter.
- The neighbour inventory is passive: it reports what the host already knows.
  A host on the same network that this machine has never talked to will not
  appear, which is the deliberate consequence of not scanning the network.
- Log analysis reads the current files and the journal; a rotated and
  compressed archive is not expanded.

## License

MIT. See [LICENSE](LICENSE).
