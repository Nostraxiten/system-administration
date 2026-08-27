//! Linux data collection.
//!
//! Wherever possible this reads `/proc` and `/etc` directly instead of parsing
//! the output of external tools: the results are then identical on a minimal
//! container and on a full server, and the scan keeps working when `ss`,
//! `netstat` or `systemctl` are absent. External commands are used only as a
//! fallback, and their absence never aborts a module.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    has_binary, read_file, read_lines, run, AutostartEntry, AutostartKind, Family, FileAttributes,
    FirewallState, InterfaceInfo, LogSource, NeighborEntry, OsIdentity, PackageInfo, PasswordState,
    RootKind, ScanRoot, ScheduledTask, ServiceEntry, SocketEntry, SudoRule, UserAccount,
};

/// Shells that never yield an interactive session.
const NON_INTERACTIVE_SHELLS: &[&str] = &[
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/usr/bin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/dev/null",
    "/bin/sync",
    "/usr/sbin/shutdown",
    "/usr/sbin/halt",
    "",
];

/// Groups that hand out administrative power on the common distributions.
const ADMIN_GROUPS: &[&str] = &["sudo", "wheel", "admin", "root", "adm", "sudoers"];

/// SUID/SGID binaries shipped by the base system of mainstream distributions.
/// Anything outside this list is reported for review rather than assumed bad.
const KNOWN_SUID: &[&str] = &[
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/passwd",
    "/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/mount",
    "/bin/mount",
    "/usr/bin/umount",
    "/bin/umount",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/bin/pkexec",
    "/usr/bin/crontab",
    "/usr/bin/at",
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/bin/screen",
    "/usr/bin/expiry",
    "/usr/bin/chage",
    "/usr/bin/ssh-agent",
    "/usr/bin/staprun",
    "/usr/bin/pmount",
    "/usr/bin/pumount",
    "/usr/bin/ping",
    "/bin/ping",
    "/bin/ping6",
    "/usr/bin/ping6",
    "/usr/bin/traceroute6.iputils",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/lib/eject/dmcrypt-get-device",
    "/usr/lib/snapd/snap-confine",
    "/usr/lib/xorg/Xorg.wrap",
    "/usr/sbin/unix_chkpwd",
    "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/lib/utempter/utempter",
    "/usr/libexec/utempter/utempter",
    "/usr/bin/utempter",
    "/sbin/unix_chkpwd",
    "/usr/sbin/pam_timestamp_check",
    "/usr/sbin/mount.nfs",
    "/usr/sbin/postdrop",
    "/usr/sbin/postqueue",
    "/usr/bin/mlocate",
    "/usr/bin/locate",
    "/usr/bin/dotlockfile",
    "/usr/bin/bsd-write",
];

/// Kernel TCP/UDP state codes as exposed in `/proc/net/*`.
fn socket_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// True when the scan runs with full read access to the system.
pub fn is_elevated() -> bool {
    // SAFETY: geteuid is always safe to call and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The package manager present on this machine, if any.
pub fn package_manager() -> Option<String> {
    const MANAGERS: &[(&str, &str)] = &[
        ("apt", "apt/dpkg"),
        ("dnf", "dnf/rpm"),
        ("yum", "yum/rpm"),
        ("zypper", "zypper/rpm"),
        ("pacman", "pacman"),
        ("apk", "apk"),
        ("emerge", "portage"),
        ("xbps-install", "xbps"),
        ("nix-env", "nix"),
        ("swupd", "swupd"),
        ("eopkg", "eopkg"),
        ("slackpkg", "slackpkg"),
    ];
    MANAGERS
        .iter()
        .find(|(binary, _)| has_binary(binary))
        .map(|(_, label)| (*label).to_string())
}

/// The init system in charge of PID 1.
pub fn init_system() -> Option<String> {
    if Path::new("/run/systemd/system").is_dir() {
        return Some("systemd".to_string());
    }
    let comm = read_file("/proc/1/comm")?;
    let name = comm.trim();
    let label = match name {
        "systemd" => "systemd",
        "init" => {
            if Path::new("/etc/inittab").exists() {
                "sysvinit"
            } else {
                "init"
            }
        }
        "runit" => "runit",
        "openrc-init" => "openrc",
        "s6-svscan" => "s6",
        "dinit" => "dinit",
        other => return Some(other.to_string()),
    };
    Some(label.to_string())
}

/// Detect the running distribution from `/etc/os-release` and friends.
pub fn identify() -> OsIdentity {
    let mut evidence = Vec::new();
    let mut fields: HashMap<String, String> = HashMap::new();

    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Some(text) = read_file(path) {
            evidence.push(format!("{path}: present"));
            for line in text.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim().trim_matches('"').trim_matches('\'');
                    fields
                        .entry(key.trim().to_string())
                        .or_insert_with(|| value.to_string());
                }
            }
            break;
        }
    }

    let id = fields
        .get("ID")
        .cloned()
        .unwrap_or_else(|| "linux".to_string());
    let version = fields
        .get("VERSION_ID")
        .cloned()
        .or_else(|| fields.get("BUILD_ID").cloned())
        .unwrap_or_default();
    let name = fields
        .get("PRETTY_NAME")
        .cloned()
        .or_else(|| fields.get("NAME").cloned())
        .unwrap_or_else(|| "Linux".to_string());

    if let Some(id_like) = fields.get("ID_LIKE") {
        evidence.push(format!("ID_LIKE={id_like}"));
    }

    // Distribution files that predate os-release, still present on old servers.
    for legacy in [
        "/etc/redhat-release",
        "/etc/debian_version",
        "/etc/alpine-release",
        "/etc/arch-release",
        "/etc/gentoo-release",
        "/etc/SuSE-release",
        "/etc/slackware-version",
    ] {
        if let Some(text) = read_file(legacy) {
            evidence.push(format!("{legacy}: {}", text.trim()));
        }
    }

    let kernel = read_file("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !kernel.is_empty() {
        evidence.push(format!("kernel {kernel}"));
    }

    let hostname = read_file("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|| read_file("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let arch = read_file("/proc/sys/kernel/arch")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::consts::ARCH.to_string());

    let package_manager = package_manager();
    if let Some(manager) = &package_manager {
        evidence.push(format!("package manager: {manager}"));
    }
    let init = init_system();
    if let Some(init) = &init {
        evidence.push(format!("init: {init}"));
    }

    if Path::new("/.dockerenv").exists() {
        evidence.push("container marker: /.dockerenv".to_string());
    }
    if let Some(cgroup) = read_file("/proc/1/cgroup") {
        if cgroup.contains("docker") || cgroup.contains("containerd") || cgroup.contains("lxc") {
            evidence.push("container marker: cgroup namespace".to_string());
        }
    }

    let uptime = read_file("/proc/uptime")
        .and_then(|text| {
            text.split_whitespace()
                .next()
                .and_then(|s| s.parse::<f64>().ok())
        })
        .map(|s| s as u64)
        .unwrap_or(0);

    OsIdentity {
        family: Family::Linux,
        id,
        name,
        version,
        kernel,
        hostname,
        arch,
        package_manager,
        init_system: init,
        uptime,
        evidence,
    }
}

/// The full catalogue of systems offered when the operator rejects the guess.
pub fn known_systems() -> Vec<(&'static str, &'static str)> {
    vec![
        ("ubuntu", "Ubuntu Server"),
        ("debian", "Debian GNU/Linux"),
        ("rhel", "Red Hat Enterprise Linux"),
        ("centos", "CentOS / CentOS Stream"),
        ("rocky", "Rocky Linux"),
        ("almalinux", "AlmaLinux"),
        ("fedora", "Fedora Server"),
        ("ol", "Oracle Linux"),
        ("amzn", "Amazon Linux"),
        ("sles", "SUSE Linux Enterprise Server"),
        ("opensuse-leap", "openSUSE Leap"),
        ("opensuse-tumbleweed", "openSUSE Tumbleweed"),
        ("arch", "Arch Linux"),
        ("manjaro", "Manjaro"),
        ("alpine", "Alpine Linux"),
        ("gentoo", "Gentoo"),
        ("void", "Void Linux"),
        ("slackware", "Slackware"),
        ("devuan", "Devuan"),
        ("kali", "Kali Linux"),
        ("parrot", "Parrot OS"),
        ("raspbian", "Raspberry Pi OS"),
        ("proxmox", "Proxmox VE"),
        ("clear-linux-os", "Clear Linux"),
        ("nixos", "NixOS"),
        ("photon", "VMware Photon OS"),
        ("linux", "Otro Linux / Other Linux"),
    ]
}

/// Score how well each known system matches the machine, so the picker can
/// offer a defensible recommendation instead of an alphabetical guess.
pub fn recommend(identity: &OsIdentity) -> (String, String, Vec<String>) {
    let mut reasons = Vec::new();
    let manager = identity.package_manager.clone().unwrap_or_default();

    let (id, label) = if manager.starts_with("apt") {
        reasons.push("dpkg/apt".to_string());
        if Path::new("/etc/lsb-release").exists() {
            ("ubuntu", "Ubuntu Server")
        } else {
            ("debian", "Debian GNU/Linux")
        }
    } else if manager.starts_with("dnf") {
        reasons.push("dnf/rpm".to_string());
        ("rhel", "Red Hat Enterprise Linux")
    } else if manager.starts_with("yum") {
        reasons.push("yum/rpm".to_string());
        ("centos", "CentOS / CentOS Stream")
    } else if manager.starts_with("zypper") {
        reasons.push("zypper/rpm".to_string());
        ("sles", "SUSE Linux Enterprise Server")
    } else if manager.starts_with("pacman") {
        reasons.push("pacman".to_string());
        ("arch", "Arch Linux")
    } else if manager.starts_with("apk") {
        reasons.push("apk".to_string());
        ("alpine", "Alpine Linux")
    } else if manager.starts_with("portage") {
        reasons.push("portage".to_string());
        ("gentoo", "Gentoo")
    } else if manager.starts_with("xbps") {
        reasons.push("xbps".to_string());
        ("void", "Void Linux")
    } else if manager.starts_with("nix") {
        reasons.push("nix".to_string());
        ("nixos", "NixOS")
    } else {
        ("linux", "Otro Linux / Other Linux")
    };

    if !identity.kernel.is_empty() {
        reasons.push(format!("kernel {}", identity.kernel));
    }
    if let Some(init) = &identity.init_system {
        reasons.push(format!("init {init}"));
    }
    (id.to_string(), label.to_string(), reasons)
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

fn shell_is_interactive(shell: &str) -> bool {
    !NON_INTERACTIVE_SHELLS.contains(&shell) && !shell.ends_with("nologin") && !shell.is_empty()
}

/// Group memberships taken from `/etc/group`, keyed by user name.
fn group_map() -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for line in read_lines("/etc/group") {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let group = parts[0].to_string();
        for member in parts[3].split(',').filter(|m| !m.is_empty()) {
            map.entry(member.to_string())
                .or_default()
                .push(group.clone());
        }
    }
    map
}

/// Password state per account from `/etc/shadow`, when readable.
fn shadow_map() -> Option<HashMap<String, PasswordState>> {
    let text = read_file("/etc/shadow")?;
    let mut map = HashMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        let hash = parts[1];
        let state = if hash.is_empty() {
            PasswordState::Empty
        } else if hash.starts_with('!') || hash.starts_with('*') {
            PasswordState::Locked
        } else {
            PasswordState::Hashed
        };
        map.insert(parts[0].to_string(), state);
    }
    Some(map)
}

/// Last login per account, from `lastlog` when available.
fn lastlog_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(text) = run("lastlog", &[]) {
        for line in text.lines().skip(1) {
            let mut parts = line.split_whitespace();
            let Some(user) = parts.next() else { continue };
            let rest = line[user.len()..].trim();
            if rest.starts_with("**Never logged in**") || rest.is_empty() {
                continue;
            }
            map.insert(user.to_string(), rest.to_string());
        }
    }
    if map.is_empty() {
        if let Some(text) = run("last", &["-F", "-n", "200"]) {
            for line in text.lines() {
                let mut parts = line.split_whitespace();
                let Some(user) = parts.next() else { continue };
                if user == "reboot" || user == "wtmp" || user.is_empty() {
                    continue;
                }
                map.entry(user.to_string())
                    .or_insert_with(|| line[user.len()..].trim().to_string());
            }
        }
    }
    map
}

/// Every local account with the security facts the users module needs.
pub fn users() -> Vec<UserAccount> {
    let groups = group_map();
    let shadow = shadow_map();
    let logins = lastlog_map();
    let sudoers = sudo_rules();

    let mut accounts = Vec::new();
    for line in read_lines("/etc/passwd") {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 7 {
            continue;
        }
        let name = parts[0].to_string();
        let uid = parts[2].to_string();
        let gid = parts[3].to_string();
        let home = parts[5].to_string();
        let shell = parts[6].to_string();

        let mut membership = groups.get(&name).cloned().unwrap_or_default();
        // The primary group is not listed in the member column of /etc/group.
        if let Some(primary) = primary_group(&gid) {
            if !membership.contains(&primary) {
                membership.insert(0, primary);
            }
        }

        let mut privilege_source = Vec::new();
        if uid == "0" {
            privilege_source.push("uid=0".to_string());
        }
        for group in &membership {
            if ADMIN_GROUPS.contains(&group.as_str()) {
                privilege_source.push(format!("group:{group}"));
            }
        }
        for rule in &sudoers {
            if rule.rule.split_whitespace().next() == Some(name.as_str())
                || rule.rule.starts_with(&format!("%{name}"))
            {
                privilege_source.push(format!("sudoers:{}", rule.source));
            }
        }

        let password_state = shadow
            .as_ref()
            .and_then(|map| map.get(&name).copied())
            .unwrap_or(PasswordState::Unknown);

        accounts.push(UserAccount {
            interactive: shell_is_interactive(&shell),
            privileged: !privilege_source.is_empty(),
            privilege_source,
            password_state,
            groups: membership,
            last_login: logins.get(&name).cloned(),
            enabled: password_state != PasswordState::Locked,
            password_never_expires: false,
            name,
            uid,
            gid,
            home,
            shell,
        });
    }
    accounts
}

fn primary_group(gid: &str) -> Option<String> {
    read_lines("/etc/group").into_iter().find_map(|line| {
        let parts: Vec<&str> = line.split(':').collect();
        (parts.len() >= 3 && parts[2] == gid).then(|| parts[0].to_string())
    })
}

/// Passwordless elevation rules from the sudoers files.
pub fn sudo_rules() -> Vec<SudoRule> {
    let mut rules = Vec::new();
    let mut files = vec![PathBuf::from("/etc/sudoers")];
    if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            if entry.path().is_file() {
                files.push(entry.path());
            }
        }
    }
    for file in files {
        let Some(text) = read_file(&file) else {
            continue;
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.contains("NOPASSWD") {
                rules.push(SudoRule {
                    source: file.display().to_string(),
                    rule: trimmed.to_string(),
                });
            }
        }
    }
    rules
}

/// Authorised SSH key files for an account: path, key count, permissions.
pub fn ssh_authorized_keys(home: &str) -> Vec<(String, usize, String)> {
    let mut found = Vec::new();
    for name in ["authorized_keys", "authorized_keys2"] {
        let path = Path::new(home).join(".ssh").join(name);
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        let keys = read_lines(&path)
            .into_iter()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with('#')
            })
            .count();
        found.push((
            path.display().to_string(),
            keys,
            format!("{:o}", metadata.permissions().mode() & 0o7777),
        ));
    }
    found
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// Every PID the kernel currently exposes under `/proc`.
pub fn kernel_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids
}

/// True when the process still runs but its executable was unlinked.
pub fn exe_deleted(pid: u32) -> Option<String> {
    let link = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let text = link.to_string_lossy().into_owned();
    text.ends_with(" (deleted)")
        .then(|| text.trim_end_matches(" (deleted)").to_string())
}

/// uid -> account name, for cheap repeated lookups.
pub fn uid_names() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in read_lines("/etc/passwd") {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if let Ok(uid) = parts[2].parse::<u32>() {
                map.insert(uid, parts[0].to_string());
            }
        }
    }
    map
}

/// Directories a normal binary is expected to live in.
pub fn system_binary_prefixes() -> &'static [&'static str] {
    &[
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/lib/",
        "/lib64/",
        "/opt/",
        "/snap/",
        "/nix/store/",
    ]
}

/// Directories where an executing binary is inherently suspicious.
pub fn volatile_prefixes() -> &'static [&'static str] {
    &[
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/shm/",
        "/var/spool/",
        "/home/",
        "/root/",
        "/mnt/",
        "/media/",
    ]
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Decode the little-endian hex address used by `/proc/net/*`.
fn decode_address(hex: &str) -> String {
    match hex.len() {
        8 => {
            let Ok(raw) = u32::from_str_radix(hex, 16) else {
                return hex.to_string();
            };
            let octets = raw.to_le_bytes();
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
        }
        32 => {
            let mut segments = [0u16; 8];
            for word in 0..4 {
                let Ok(raw) = u32::from_str_radix(&hex[word * 8..word * 8 + 8], 16) else {
                    return hex.to_string();
                };
                let bytes = raw.to_le_bytes();
                segments[word * 2] = u16::from_be_bytes([bytes[0], bytes[1]]);
                segments[word * 2 + 1] = u16::from_be_bytes([bytes[2], bytes[3]]);
            }
            std::net::Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )
            .to_string()
        }
        _ => hex.to_string(),
    }
}

/// socket inode -> (pid, process name), built by walking every `/proc/*/fd`.
/// Without elevated privileges only the current user's sockets resolve, which
/// is exactly what the report says when a port ends up unattributed.
fn socket_inode_owners() -> HashMap<u64, (u32, String)> {
    let mut owners = HashMap::new();
    for pid in kernel_pids() {
        let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        let name = read_file(format!("/proc/{pid}/comm"))
            .map(|text| text.trim().to_string())
            .unwrap_or_else(|| pid.to_string());
        for entry in entries.flatten() {
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if let Some(rest) = target.strip_prefix("socket:[") {
                if let Ok(inode) = rest.trim_end_matches(']').parse::<u64>() {
                    owners.insert(inode, (pid, name.clone()));
                }
            }
        }
    }
    owners
}

fn parse_proc_net(
    path: &str,
    proto: &str,
    owners: &HashMap<u64, (u32, String)>,
) -> Vec<SocketEntry> {
    let mut entries = Vec::new();
    for line in read_lines(path).into_iter().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some((local_hex, local_port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let Some((remote_hex, remote_port_hex)) = fields[2].split_once(':') else {
            continue;
        };
        let local_port = u16::from_str_radix(local_port_hex, 16).unwrap_or(0);
        let remote_port = u16::from_str_radix(remote_port_hex, 16).unwrap_or(0);
        let inode: u64 = fields[9].parse().unwrap_or(0);
        let owner = owners.get(&inode);

        let state = if proto.starts_with("udp") {
            if remote_port == 0 {
                "LISTEN"
            } else {
                "ESTABLISHED"
            }
        } else {
            socket_state(fields[3])
        };

        entries.push(SocketEntry {
            proto: proto.to_string(),
            local_addr: decode_address(local_hex),
            local_port,
            remote_addr: decode_address(remote_hex),
            remote_port,
            state: state.to_string(),
            pid: owner.map(|(pid, _)| *pid),
            process: owner.map(|(_, name)| name.clone()),
        });
    }
    entries
}

/// Every socket the kernel knows about, listening and established alike.
pub fn sockets() -> Vec<SocketEntry> {
    let owners = socket_inode_owners();
    let mut all = Vec::new();
    for (path, proto) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp6"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp6"),
    ] {
        all.extend(parse_proc_net(path, proto, &owners));
    }
    if all.is_empty() {
        // Fall back to userland tooling on hosts with a restricted /proc.
        if let Some(text) = run("ss", &["-tulpnH"]).or_else(|| run("netstat", &["-tulpn"])) {
            all.extend(parse_ss_output(&text));
        }
    }
    all
}

/// Minimal parser for `ss`/`netstat` output, used only as a fallback.
fn parse_ss_output(text: &str) -> Vec<SocketEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let proto = fields[0].to_lowercase();
        if !proto.starts_with("tcp") && !proto.starts_with("udp") {
            continue;
        }
        let local = fields[fields.len().saturating_sub(3)];
        let Some((addr, port)) = local.rsplit_once(':') else {
            continue;
        };
        let process = line
            .split_once("users:((\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(name, _)| name.to_string());
        let pid = line
            .split_once("pid=")
            .and_then(|(_, rest)| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse::<u32>().ok());
        entries.push(SocketEntry {
            proto,
            local_addr: addr.trim_matches(|c| c == '[' || c == ']').to_string(),
            local_port: port.parse().unwrap_or(0),
            remote_addr: String::new(),
            remote_port: 0,
            state: "LISTEN".to_string(),
            pid,
            process,
        });
    }
    entries
}

/// Network interfaces with counters, MAC, MTU and promiscuous flag.
pub fn interfaces() -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return interfaces;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let base = entry.path();
        let read_number = |file: &str| -> u64 {
            read_file(base.join(file))
                .and_then(|text| text.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        let flags = read_file(base.join("flags"))
            .and_then(|text| u32::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        interfaces.push(InterfaceInfo {
            addresses: interface_addresses(&name),
            mac: read_file(base.join("address"))
                .map(|text| text.trim().to_string())
                .unwrap_or_default(),
            mtu: read_number("mtu"),
            // IFF_PROMISC is bit 8 of the interface flags.
            promiscuous: flags & 0x100 != 0,
            received: read_number("statistics/rx_bytes"),
            transmitted: read_number("statistics/tx_bytes"),
            rx_errors: read_number("statistics/rx_errors"),
            tx_errors: read_number("statistics/tx_errors"),
            name,
        });
    }
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

/// Addresses bound to an interface, taken from `ip` when present and from
/// `/proc/net/fib_trie` otherwise.
fn interface_addresses(name: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    if let Some(text) = run("ip", &["-o", "addr", "show", "dev", name]) {
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            while let Some(field) = fields.next() {
                if field == "inet" || field == "inet6" {
                    if let Some(address) = fields.next() {
                        addresses.push(address.to_string());
                    }
                }
            }
        }
    }
    addresses
}

/// Whether the kernel routes packets between interfaces.
pub fn ip_forwarding() -> Option<bool> {
    read_file("/proc/sys/net/ipv4/ip_forward").map(|text| text.trim() == "1")
}

/// Local firewall engine and whether it holds any effective rule.
pub fn firewall() -> FirewallState {
    if let Some(text) = run("nft", &["list", "ruleset"]) {
        let rules = text
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with('}') && !line.starts_with("table")
            })
            .count();
        if rules > 0 {
            return FirewallState {
                engine: "nftables".to_string(),
                active: true,
                rule_count: rules,
            };
        }
    }
    if let Some(text) = run("iptables", &["-S"]) {
        let rules = text.lines().filter(|line| line.starts_with("-A")).count();
        return FirewallState {
            engine: "iptables".to_string(),
            active: rules > 0,
            rule_count: rules,
        };
    }
    if let Some(text) = run("ufw", &["status"]) {
        let active = text.contains("active") && !text.contains("inactive");
        return FirewallState {
            engine: "ufw".to_string(),
            active,
            rule_count: text
                .lines()
                .filter(|line| line.contains("ALLOW") || line.contains("DENY"))
                .count(),
        };
    }
    if let Some(text) = run("firewall-cmd", &["--state"]) {
        return FirewallState {
            engine: "firewalld".to_string(),
            active: text.trim() == "running",
            rule_count: 0,
        };
    }
    FirewallState {
        engine: "none".to_string(),
        active: false,
        rule_count: 0,
    }
}

/// Neighbours known to this host, read from the kernel tables only.
pub fn neighbors() -> Vec<NeighborEntry> {
    let mut entries = Vec::new();
    let hosts = local_host_names();

    for line in read_lines("/proc/net/arp").into_iter().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let ip = fields[0].to_string();
        let mac = fields[3].to_string();
        let state = if mac == "00:00:00:00:00:00" {
            "INCOMPLETE"
        } else {
            "REACHABLE"
        };
        entries.push(NeighborEntry {
            hostname: hosts.get(&ip).cloned(),
            ip,
            mac,
            interface: fields[5].to_string(),
            state: state.to_string(),
        });
    }

    // IPv6 neighbours never appear in /proc/net/arp.
    if let Some(text) = run("ip", &["-6", "neigh", "show"]) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let ip = fields[0].to_string();
            let mac = fields
                .iter()
                .position(|f| *f == "lladdr")
                .and_then(|index| fields.get(index + 1))
                .map(|mac| (*mac).to_string())
                .unwrap_or_else(|| "-".to_string());
            entries.push(NeighborEntry {
                hostname: hosts.get(&ip).cloned(),
                ip,
                mac,
                interface: fields[2].to_string(),
                state: fields.last().copied().unwrap_or("UNKNOWN").to_string(),
            });
        }
    }
    entries
}

/// Name resolution restricted to local files: no DNS query leaves the host.
pub fn local_host_names() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in read_lines("/etc/hosts") {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut fields = line.split_whitespace();
        let Some(ip) = fields.next() else { continue };
        if let Some(name) = fields.next() {
            map.insert(ip.to_string(), name.to_string());
        }
    }
    map
}

/// Default gateways configured on this host.
pub fn gateways() -> Vec<String> {
    let mut gateways = Vec::new();
    for line in read_lines("/proc/net/route").into_iter().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 || fields[1] != "00000000" {
            continue;
        }
        let address = decode_address(fields[2]);
        if address != "0.0.0.0" {
            gateways.push(format!("{address} ({})", fields[0]));
        }
    }
    gateways
}

/// Subnets directly attached to this host.
pub fn local_subnets() -> Vec<String> {
    interfaces()
        .into_iter()
        .filter(|interface| interface.name != "lo")
        .flat_map(|interface| interface.addresses)
        .collect()
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Every scheduled task reachable on this host: system crontab, drop-ins,
/// per-user crontabs, the periodic directories and systemd timers.
pub fn scheduled_tasks() -> Vec<ScheduledTask> {
    let mut tasks = Vec::new();

    // System crontab and drop-in directory: six fields plus a user column.
    let mut cron_files = vec![PathBuf::from("/etc/crontab")];
    if let Ok(entries) = fs::read_dir("/etc/cron.d") {
        cron_files.extend(entries.flatten().map(|entry| entry.path()));
    }
    for file in cron_files {
        for line in read_lines(&file) {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || !line.starts_with(|c: char| c.is_ascii_digit() || c == '*' || c == '@')
            {
                continue;
            }
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() < 7 {
                continue;
            }
            tasks.push(ScheduledTask {
                kind: "cron".to_string(),
                name: file.display().to_string(),
                schedule: fields[..5].join(" "),
                command: fields[6..].join(" "),
                owner: fields[5].to_string(),
                source: file.display().to_string(),
            });
        }
    }

    // Per-user crontabs: five schedule fields and no user column.
    for spool in ["/var/spool/cron/crontabs", "/var/spool/cron"] {
        let Ok(entries) = fs::read_dir(spool) else {
            continue;
        };
        for entry in entries.flatten() {
            let owner = entry.file_name().to_string_lossy().into_owned();
            for line in read_lines(entry.path()) {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let fields: Vec<&str> = trimmed.split_whitespace().collect();
                if fields.len() < 6 {
                    continue;
                }
                tasks.push(ScheduledTask {
                    kind: "crontab".to_string(),
                    name: format!("{owner} crontab"),
                    schedule: fields[..5].join(" "),
                    command: fields[5..].join(" "),
                    owner: owner.clone(),
                    source: entry.path().display().to_string(),
                });
            }
        }
    }

    // Periodic directories run every script they contain.
    for (directory, period) in [
        ("/etc/cron.hourly", "hourly"),
        ("/etc/cron.daily", "daily"),
        ("/etc/cron.weekly", "weekly"),
        ("/etc/cron.monthly", "monthly"),
    ] {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.path().is_file() {
                continue;
            }
            tasks.push(ScheduledTask {
                kind: "cron.periodic".to_string(),
                name: entry.file_name().to_string_lossy().into_owned(),
                schedule: period.to_string(),
                command: entry.path().display().to_string(),
                owner: "root".to_string(),
                source: directory.to_string(),
            });
        }
    }

    // systemd timers.
    if let Some(text) = run(
        "systemctl",
        &["list-timers", "--all", "--no-pager", "--no-legend"],
    ) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let unit = fields.iter().find(|f| f.ends_with(".timer"));
            let Some(unit) = unit else { continue };
            tasks.push(ScheduledTask {
                kind: "systemd.timer".to_string(),
                name: (*unit).to_string(),
                schedule: fields[..2].join(" "),
                command: unit.replace(".timer", ".service"),
                owner: "root".to_string(),
                source: "systemd".to_string(),
            });
        }
    }

    // at(1) queue.
    if let Some(text) = run("atq", &[]) {
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            tasks.push(ScheduledTask {
                kind: "at".to_string(),
                name: line.split_whitespace().next().unwrap_or("job").to_string(),
                schedule: line.trim().to_string(),
                command: "at job".to_string(),
                owner: line.split_whitespace().last().unwrap_or("-").to_string(),
                source: "atq".to_string(),
            });
        }
    }

    tasks
}

/// Services and units, with their unit file path and whether the vendor
/// shipped them.
pub fn services() -> Vec<ServiceEntry> {
    let mut services = Vec::new();
    let owned = package_owned_paths();

    if let Some(text) = run(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
            "--plain",
        ],
    ) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            let name = fields[0].to_string();
            let unit_path = unit_file_path(&name).unwrap_or_default();
            let vendor = unit_path.is_empty()
                || owned.contains(&unit_path)
                || unit_path.starts_with("/lib/")
                || unit_path.starts_with("/usr/lib/");
            services.push(ServiceEntry {
                exec: unit_exec_start(&unit_path),
                state: fields[3].to_string(),
                start_mode: fields[1].to_string(),
                vendor_supplied: vendor,
                unit_path,
                name,
            });
        }
    }

    // SysV style init scripts, still in use on older servers.
    if let Ok(entries) = fs::read_dir("/etc/init.d") {
        for entry in entries.flatten() {
            if !entry.path().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if services
                .iter()
                .any(|service| service.name.starts_with(&name))
            {
                continue;
            }
            let path = entry.path().display().to_string();
            services.push(ServiceEntry {
                name,
                state: "sysv".to_string(),
                start_mode: "init.d".to_string(),
                vendor_supplied: owned.contains(&path),
                exec: path.clone(),
                unit_path: path,
            });
        }
    }

    services
}

/// Every filesystem path claimed by an installed package.
///
/// Read once from the package database rather than shelled out per file:
/// `dpkg` records this in plain text, and knowing whether a package owns a
/// service definition is the difference between "this daemon came with the
/// distribution" and "somebody installed this by hand", which is the only
/// version of that question worth reporting.
pub fn package_owned_paths() -> BTreeSet<String> {
    let mut owned = BTreeSet::new();
    if let Ok(entries) = fs::read_dir("/var/lib/dpkg/info") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("list") {
                continue;
            }
            for line in read_lines(&path) {
                if line.starts_with('/') {
                    owned.insert(line);
                }
            }
        }
    }
    if owned.is_empty() && has_binary("rpm") {
        if let Some(text) = run("rpm", &["-qal"]) {
            for line in text.lines() {
                if line.starts_with('/') {
                    owned.insert(line.to_string());
                }
            }
        }
    }
    owned
}

fn unit_file_path(unit: &str) -> Option<String> {
    for directory in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/usr/local/lib/systemd/system",
    ] {
        let candidate = Path::new(directory).join(unit);
        if candidate.exists() {
            return Some(candidate.display().to_string());
        }
    }
    None
}

fn unit_exec_start(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    read_lines(path)
        .into_iter()
        .find(|line| line.trim_start().starts_with("ExecStart="))
        .map(|line| {
            line.trim_start()
                .trim_start_matches("ExecStart=")
                .to_string()
        })
        .unwrap_or_default()
}

/// Boot hooks that are neither services nor scheduled tasks.
pub fn autostart() -> Vec<AutostartEntry> {
    let mut entries = Vec::new();

    for path in ["/etc/rc.local", "/etc/rc.d/rc.local"] {
        let Some(text) = read_file(path) else {
            continue;
        };
        let active: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| {
                !line.is_empty()
                    && !line.starts_with('#')
                    && *line != "exit 0"
                    && !line.starts_with("#!")
            })
            .collect();
        if !active.is_empty() {
            entries.push(AutostartEntry {
                kind: AutostartKind::BootScript,
                source: path.to_string(),
                name: "rc.local".to_string(),
                value: active.join(" ; "),
            });
        }
    }

    if let Ok(profile) = fs::read_dir("/etc/profile.d") {
        for entry in profile.flatten() {
            entries.push(AutostartEntry {
                kind: AutostartKind::Profile,
                source: "/etc/profile.d".to_string(),
                name: entry.file_name().to_string_lossy().into_owned(),
                value: entry.path().display().to_string(),
            });
        }
    }

    for home in home_directories() {
        let autostart_dir = home.join(".config/autostart");
        let Ok(items) = fs::read_dir(&autostart_dir) else {
            continue;
        };
        for entry in items.flatten() {
            let exec = read_lines(entry.path())
                .into_iter()
                .find(|line| line.starts_with("Exec="))
                .unwrap_or_default();
            entries.push(AutostartEntry {
                kind: AutostartKind::DesktopSession,
                source: autostart_dir.display().to_string(),
                name: entry.file_name().to_string_lossy().into_owned(),
                value: exec,
            });
        }
    }

    entries
}

/// Libraries injected into every process on the system.
pub fn preload_libraries() -> Vec<(String, String)> {
    let mut found = Vec::new();
    if let Some(text) = read_file("/etc/ld.so.preload") {
        let contents = text.trim();
        if !contents.is_empty() {
            found.push(("/etc/ld.so.preload".to_string(), contents.to_string()));
        }
    }
    if let Ok(value) = std::env::var("LD_PRELOAD") {
        if !value.trim().is_empty() {
            found.push(("LD_PRELOAD".to_string(), value));
        }
    }
    found
}

/// Home directories of every account, including root.
pub fn home_directories() -> Vec<PathBuf> {
    let mut homes: BTreeSet<PathBuf> = BTreeSet::new();
    for line in read_lines("/etc/passwd") {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 6 {
            continue;
        }
        let home = Path::new(parts[5]);
        if home.is_dir() && parts[5] != "/" && parts[5] != "/nonexistent" {
            homes.insert(home.to_path_buf());
        }
    }
    homes.into_iter().collect()
}

/// Shell startup files, per account.
pub fn shell_rc_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for home in home_directories() {
        for name in [
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".zshenv",
            ".kshrc",
            ".cshrc",
            ".config/fish/config.fish",
        ] {
            let candidate = home.join(name);
            if candidate.is_file() {
                files.push(candidate);
            }
        }
    }
    for system in ["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"] {
        if Path::new(system).is_file() {
            files.push(PathBuf::from(system));
        }
    }
    files
}

/// Shell history files, per account.
pub fn history_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for home in home_directories() {
        for name in [
            ".bash_history",
            ".zsh_history",
            ".sh_history",
            ".ksh_history",
            ".history",
            ".local/share/fish/fish_history",
            ".python_history",
            ".mysql_history",
        ] {
            let candidate = home.join(name);
            if candidate.exists() {
                files.push(candidate);
            }
        }
    }
    files
}

// ---------------------------------------------------------------------------
// Packages and versions
// ---------------------------------------------------------------------------

/// Installed packages plus the name of the manager that reported them.
pub fn packages() -> (Vec<PackageInfo>, String) {
    let queries: &[(&str, &[&str], &str)] = &[
        ("dpkg-query", &["-W", "-f=${Package}\t${Version}\n"], "dpkg"),
        (
            "rpm",
            &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
            "rpm",
        ),
        ("pacman", &["-Q"], "pacman"),
        ("apk", &["info", "-v"], "apk"),
        ("xbps-query", &["-l"], "xbps"),
    ];

    for (program, args, label) in queries {
        if !has_binary(program) {
            continue;
        }
        let Some(text) = run(program, args) else {
            continue;
        };
        let mut packages = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (name, version) = if let Some((name, version)) = line.split_once('\t') {
                (name.to_string(), version.to_string())
            } else if *label == "apk" || *label == "xbps" {
                // apk and xbps print name-version with the version last.
                match line.rsplit_once('-') {
                    Some((name, version)) => (name.to_string(), version.to_string()),
                    None => (line.to_string(), String::new()),
                }
            } else {
                match line.split_once(' ') {
                    Some((name, version)) => (name.to_string(), version.to_string()),
                    None => (line.to_string(), String::new()),
                }
            };
            packages.push(PackageInfo { name, version });
        }
        if !packages.is_empty() {
            return (packages, (*label).to_string());
        }
    }
    (Vec::new(), "unknown".to_string())
}

/// Versions of the services that matter most when they are exposed.
pub fn service_versions() -> Vec<(String, String)> {
    const PROBES: &[(&str, &[&str])] = &[
        ("sshd", &["-V"]),
        ("nginx", &["-v"]),
        ("apache2", &["-v"]),
        ("httpd", &["-v"]),
        ("mysqld", &["--version"]),
        ("mariadbd", &["--version"]),
        ("postgres", &["--version"]),
        ("redis-server", &["--version"]),
        ("php", &["-v"]),
        ("python3", &["--version"]),
        ("openssl", &["version"]),
        ("bash", &["--version"]),
        ("sudo", &["-V"]),
        ("vsftpd", &["-v"]),
        ("named", &["-v"]),
        ("smbd", &["-V"]),
        ("dockerd", &["--version"]),
    ];

    let mut versions = Vec::new();
    for (program, args) in PROBES {
        if !has_binary(program) {
            continue;
        }
        let Some(text) = run(program, args) else {
            continue;
        };
        let first = text.lines().next().unwrap_or("").trim().to_string();
        if !first.is_empty() {
            versions.push(((*program).to_string(), first));
        }
    }
    versions
}

/// Pending updates as (total, security), when the package manager can answer
/// from its local cache without hitting the network.
pub fn pending_updates() -> Option<(usize, usize)> {
    if has_binary("apt-get") {
        let text = run("apt-get", &["-s", "-o", "Debug::NoLocking=1", "upgrade"])?;
        let total = text
            .lines()
            .filter(|line| line.starts_with("Inst "))
            .count();
        let security = text
            .lines()
            .filter(|line| line.starts_with("Inst ") && line.contains("security"))
            .count();
        return Some((total, security));
    }
    if has_binary("dnf") {
        let text = run("dnf", &["--cacheonly", "-q", "check-update"])?;
        let total = text
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with(' '))
            .count();
        return Some((total, 0));
    }
    if has_binary("zypper") {
        let text = run("zypper", &["--non-interactive", "list-updates"])?;
        let total = text.lines().filter(|line| line.starts_with("v |")).count();
        return Some((total, 0));
    }
    None
}

/// Whether the running kernel or libraries are older than what is installed.
pub fn reboot_required() -> bool {
    Path::new("/var/run/reboot-required").exists()
        || Path::new("/run/reboot-required").exists()
        || run("needs-restarting", &["-r"]).is_some_and(|text| text.contains("Reboot is required"))
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

/// Authentication log sources, with their contents when readable.
pub fn log_sources(max_lines: usize) -> Vec<LogSource> {
    let mut sources = Vec::new();

    for (name, path) in [
        ("auth.log", "/var/log/auth.log"),
        ("secure", "/var/log/secure"),
        ("faillog", "/var/log/faillog"),
        ("btmp", "/var/log/btmp"),
        ("wtmp", "/var/log/wtmp"),
    ] {
        let metadata = fs::metadata(path).ok();
        let available = metadata.is_some();
        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
        // wtmp and btmp are binary; their contents come through `last`/`lastb`.
        let lines = if available && (name == "auth.log" || name == "secure") {
            let all = read_lines(path);
            let start = all.len().saturating_sub(max_lines);
            all[start..].to_vec()
        } else {
            Vec::new()
        };
        let readable = if available && (name == "auth.log" || name == "secure") {
            !lines.is_empty() || size == 0
        } else {
            available
        };
        sources.push(LogSource {
            name: name.to_string(),
            path: path.to_string(),
            available,
            readable,
            size,
            lines,
        });
    }

    // journald replaces the plain files on most modern systems.
    if has_binary("journalctl") {
        let lines = run(
            "journalctl",
            &[
                "--no-pager",
                "-q",
                "SYSLOG_FACILITY=10",
                "SYSLOG_FACILITY=4",
                "-n",
                "4000",
            ],
        )
        .map(|text| text.lines().map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();
        sources.push(LogSource {
            name: "journald".to_string(),
            path: "journalctl".to_string(),
            available: true,
            readable: !lines.is_empty(),
            size: lines.len() as u64,
            lines,
        });
    }

    // Failed login records, decoded by lastb.
    if has_binary("lastb") {
        let lines = run("lastb", &["-F", "-n", "500"])
            .map(|text| text.lines().map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default();
        sources.push(LogSource {
            name: "lastb".to_string(),
            path: "/var/log/btmp".to_string(),
            available: true,
            readable: !lines.is_empty(),
            size: lines.len() as u64,
            lines,
        });
    }

    sources
}

// ---------------------------------------------------------------------------
// Web
// ---------------------------------------------------------------------------

/// Web server configuration files worth inspecting.
pub fn web_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let candidates = [
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled",
        "/etc/nginx/conf.d",
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-enabled",
        "/etc/apache2/conf-enabled",
        "/etc/httpd/conf/httpd.conf",
        "/etc/httpd/conf.d",
        "/etc/lighttpd/lighttpd.conf",
        "/etc/caddy/Caddyfile",
        "/etc/php.ini",
        "/etc/php/8.3/apache2/php.ini",
        "/etc/php/8.3/fpm/php.ini",
        "/etc/php/8.2/fpm/php.ini",
        "/etc/php/8.1/fpm/php.ini",
        "/etc/php/7.4/fpm/php.ini",
    ];
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.is_file() {
            paths.push(path.to_path_buf());
        } else if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                paths.extend(
                    entries
                        .flatten()
                        .map(|entry| entry.path())
                        .filter(|p| p.is_file()),
                );
            }
        }
    }
    paths
}

/// Default document roots, used to spot untouched welcome pages.
pub fn web_default_pages() -> Vec<PathBuf> {
    [
        "/var/www/html/index.html",
        "/var/www/html/index.nginx-debian.html",
        "/usr/share/nginx/html/index.html",
        "/var/www/index.html",
        "/srv/http/index.html",
        "/usr/share/apache2/default-site/index.html",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|path| path.is_file())
    .collect()
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

/// The roots the file module walks, with the depth that keeps a full server
/// scan bounded while still reaching the places that matter.
pub fn scan_roots() -> Vec<ScanRoot> {
    let mut roots = vec![
        ScanRoot {
            path: "/usr/bin".into(),
            max_depth: 2,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/usr/sbin".into(),
            max_depth: 2,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/bin".into(),
            max_depth: 2,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/sbin".into(),
            max_depth: 2,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/usr/local/bin".into(),
            max_depth: 3,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/usr/local/sbin".into(),
            max_depth: 3,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/usr/libexec".into(),
            max_depth: 3,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/usr/lib".into(),
            max_depth: 3,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/opt".into(),
            max_depth: 4,
            kind: RootKind::System,
        },
        ScanRoot {
            path: "/etc".into(),
            max_depth: 4,
            kind: RootKind::Config,
        },
        ScanRoot {
            path: "/var/www".into(),
            max_depth: 5,
            kind: RootKind::Config,
        },
        ScanRoot {
            path: "/tmp".into(),
            max_depth: 4,
            kind: RootKind::Temp,
        },
        ScanRoot {
            path: "/var/tmp".into(),
            max_depth: 4,
            kind: RootKind::Temp,
        },
        ScanRoot {
            path: "/dev/shm".into(),
            max_depth: 3,
            kind: RootKind::Temp,
        },
        ScanRoot {
            path: "/var/spool".into(),
            max_depth: 4,
            kind: RootKind::Temp,
        },
    ];
    for home in home_directories() {
        roots.push(ScanRoot {
            path: home.display().to_string(),
            max_depth: 3,
            kind: RootKind::Home,
        });
    }
    roots.retain(|root| Path::new(&root.path).is_dir());
    roots
}

/// Paths never worth descending into: kernel interfaces, mounts and caches
/// that produce noise without evidence.
pub fn skip_paths() -> &'static [&'static str] {
    &[
        "/proc",
        "/sys",
        "/dev/pts",
        "/dev/mqueue",
        "/run/user",
        "/var/lib/docker",
        "/var/lib/containers",
        "/snap",
        "/nix/store",
        "/.git",
        "/node_modules",
        "/var/cache",
        "/usr/share/man",
        "/usr/share/doc",
        "/usr/share/locale",
    ]
}

/// System paths that should not contain hidden files.
pub fn critical_directories() -> &'static [&'static str] {
    &[
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/etc",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/var/www",
    ]
}

/// Whether a SUID/SGID binary is part of the expected base system.
///
/// A literal path comparison is not enough: on a merged-`/usr` distribution
/// `/bin` is a symlink to `/usr/bin`, so the same binary is reached under two
/// paths and half of them miss the list. Distributions also move helpers
/// between `/usr/lib/<project>` and `/usr/libexec`. Matching the file name
/// inside a system directory covers both without widening the baseline to
/// anything a user could drop anywhere.
pub fn is_baseline_suid(path: &str) -> bool {
    if KNOWN_SUID.contains(&path) {
        return true;
    }
    if let Ok(resolved) = fs::canonicalize(path) {
        if KNOWN_SUID.contains(&resolved.to_string_lossy().as_ref()) {
            return true;
        }
    }
    let Some(name) = Path::new(path).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let in_system_directory = system_binary_prefixes()
        .iter()
        .any(|prefix| path.starts_with(prefix));
    in_system_directory
        && KNOWN_SUID.iter().any(|known| {
            Path::new(known)
                .file_name()
                .and_then(|known_name| known_name.to_str())
                == Some(name)
        })
}

/// Ownership and permission facts for one file.
pub fn file_attributes(
    _path: &Path,
    metadata: &fs::Metadata,
    uid_names: &HashMap<u32, String>,
) -> FileAttributes {
    let mode = metadata.permissions().mode();
    let uid = metadata.uid();
    let owner_known = uid_names.contains_key(&uid);
    let modified_secs_ago = metadata
        .modified()
        .ok()
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX);

    FileAttributes {
        mode: format!("{:04o}", mode & 0o7777),
        owner: uid_names
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string()),
        owner_id: uid,
        owner_known,
        suid: mode & 0o4000 != 0,
        sgid: mode & 0o2000 != 0,
        world_writable: mode & 0o0002 != 0,
        executable: mode & 0o0111 != 0,
        size: metadata.len(),
        modified: format_mtime(metadata),
        modified_secs_ago,
    }
}

fn format_mtime(metadata: &fs::Metadata) -> String {
    let Ok(modified) = metadata.modified() else {
        return "unknown".to_string();
    };
    let Ok(since_epoch) = modified.duration_since(UNIX_EPOCH) else {
        return "unknown".to_string();
    };
    chrono::DateTime::from_timestamp(since_epoch.as_secs() as i64, 0)
        .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Extensions that make a double-extension name executable in practice.
pub fn executable_extensions() -> &'static [&'static str] {
    &[
        "sh", "bash", "py", "pl", "rb", "elf", "bin", "run", "so", "ko", "out", "php", "cgi",
    ]
}

/// Documents whose extension is used as the visible half of a disguise.
pub fn document_extensions() -> &'static [&'static str] {
    &[
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif",
        "mp3", "mp4", "avi", "zip", "rar", "csv", "rtf", "odt",
    ]
}

/// Permission problem on a home directory, expressed as its octal mode.
///
/// Returns `None` when the directory is missing, when its mode is tight enough
/// that no other local account can read or write it, or when the directory is
/// not really that account's home. The last case is what stops the check from
/// reporting `/bin`, `/dev` and `/var/mail`: system accounts such as `bin`,
/// `sys` and `mail` carry those paths as a placeholder home, root owns them,
/// and their permissions have nothing to do with the account.
pub fn home_permission_issue(home: &str, uid: &str) -> Option<String> {
    let owner: u32 = uid.parse().ok()?;
    let metadata = fs::metadata(home).ok()?;
    if metadata.uid() != owner {
        return None;
    }
    let mode = metadata.permissions().mode() & 0o7777;
    // Any bit for "other", or write for the group, lets someone who is not the
    // owner into the directory. Group read alone (0750) is a normal setting on
    // a server and is not reported.
    let reachable_by_others = mode & 0o007 != 0 || mode & 0o020 != 0;
    reachable_by_others.then(|| format!("{mode:04o}"))
}

/// Whether a path exists and is a directory.
pub fn directory_exists(path: &str) -> bool {
    Path::new(path).is_dir()
}

/// Alternate data streams under a root.
///
/// Linux filesystems have no equivalent of an NTFS alternate data stream, so
/// this is always empty here; the Windows collector implements it for real and
/// the files module calls the same function on both.
pub fn alternate_data_streams(_root: &Path) -> Vec<(String, String)> {
    Vec::new()
}

/// PIDs the kernel answers for but that do not appear when `/proc` is listed.
///
/// A userland rootkit that hooks directory reads hides a process from `ls
/// /proc` while `stat /proc/<pid>` still succeeds, because the two go through
/// different paths. Comparing both is the cheapest reliable way to notice.
///
/// Two ordinary situations produce the same mismatch and must be excluded, or
/// the check reports dozens of rootkits on a healthy machine:
///
///  * **Threads.** Every thread has an addressable `/proc/<tid>` that is
///    deliberately absent from the directory listing. Only a thread group
///    leader (`Tgid == pid`) is a process.
///  * **Processes that start mid-scan.** A PID created between the listing and
///    the probe was never hidden. Re-listing afterwards and requiring the PID
///    to be absent from both listings removes that race.
pub fn hidden_pids() -> Vec<u32> {
    let before: BTreeSet<u32> = kernel_pids().into_iter().collect();
    let pid_max = read_file("/proc/sys/kernel/pid_max")
        .and_then(|text| text.trim().parse::<u32>().ok())
        .unwrap_or(32_768)
        .min(131_072);

    let mut candidates = Vec::new();
    for pid in 1..=pid_max {
        if before.contains(&pid) {
            continue;
        }
        let Some(status) = read_file(format!("/proc/{pid}/status")) else {
            continue;
        };
        let thread_group = status
            .lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .and_then(|value| value.trim().parse::<u32>().ok());
        if thread_group == Some(pid) {
            candidates.push(pid);
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let after: BTreeSet<u32> = kernel_pids().into_iter().collect();
    candidates
        .retain(|pid| !after.contains(pid) && Path::new(&format!("/proc/{pid}/status")).exists());
    candidates
}

/// Names of processes that only ever run from a system path.
pub fn system_process_names() -> &'static [&'static str] {
    &[
        "systemd",
        "init",
        "sshd",
        "cron",
        "crond",
        "rsyslogd",
        "dbus-daemon",
        "login",
        "agetty",
        "getty",
        "bash",
        "sh",
        "dash",
        "zsh",
        "sudo",
        "su",
        "nginx",
        "apache2",
        "httpd",
        "mysqld",
        "postgres",
        "docker",
        "containerd",
        "kthreadd",
        "ksoftirqd",
        "systemd-journal",
        "systemd-logind",
        "NetworkManager",
        "chronyd",
        "ntpd",
        "auditd",
        "polkitd",
    ]
}

/// Whether any user on the system can write to this path.
pub fn path_is_world_writable(path: &str) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o0002 != 0)
        .unwrap_or(false)
}

/// Whether a path is a symlink pointing at the null device, the usual way to
/// throw a shell history away without deleting the file.
pub fn points_to_null(path: &Path) -> bool {
    fs::read_link(path)
        .map(|target| target == Path::new("/dev/null"))
        .unwrap_or(false)
}

/// Octal mode of a path when anyone other than its owner can write to it.
pub fn writable_permission_issue(path: &str) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    let mode = metadata.permissions().mode() & 0o7777;
    (mode & 0o022 != 0).then(|| format!("{mode:04o}"))
}

/// The account running the scan.
pub fn current_user() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| {
            // SAFETY: geteuid cannot fail and returns a plain integer.
            let uid = unsafe { libc::geteuid() };
            uid_names()
                .get(&uid)
                .cloned()
                .unwrap_or_else(|| uid.to_string())
        })
}
