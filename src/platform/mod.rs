//! Platform abstraction.
//!
//! Every module in `crate::modules` is written once against the types and
//! functions declared here. The per-OS collectors live in [`linux`] and
//! [`windows`] and are selected at compile time, so a Linux build carries no
//! Windows code and vice versa.

pub mod detect;

// Android is a Linux-kernel target (Termux and friends): the `/proc`- and
// `/etc`-based collectors below work there unchanged, just against a sparser
// filesystem, so it rides on the same collector instead of getting its own.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux as sys;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows as sys;

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
compile_error!(
    "system-administration targets Linux and Windows Server only. \
     Build with --target x86_64-unknown-linux-gnu or x86_64-pc-windows-msvc."
);

use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Broad OS family. Modules branch on this for wording, never for logic that
/// belongs in a platform collector.
///
/// Only one variant is ever constructed in a given build, by that platform's
/// collector; the other exists so the shared code can be written once.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    Linux,
    Windows,
}

/// Identity of the running system, as detected or as chosen by the operator.
#[derive(Clone, Debug)]
pub struct OsIdentity {
    pub family: Family,
    /// Machine readable id: `ubuntu`, `rhel`, `windows-server-2022`...
    pub id: String,
    /// Human readable name shown in prompts and reports.
    pub name: String,
    pub version: String,
    /// Kernel release on Linux, build number on Windows.
    pub kernel: String,
    pub hostname: String,
    pub arch: String,
    pub package_manager: Option<String>,
    pub init_system: Option<String>,
    /// Uptime in seconds.
    pub uptime: u64,
    /// Raw observations backing the detection, shown when the operator asks
    /// whether the guess is right.
    pub evidence: Vec<String>,
}

impl OsIdentity {
    pub fn label(&self) -> String {
        // `PRETTY_NAME` usually carries the version already; appending it again
        // produces "Ubuntu 24.04.4 LTS 24.04".
        if self.version.is_empty() || self.name.contains(&self.version) {
            self.name.clone()
        } else {
            format!("{} {}", self.name, self.version)
        }
    }
}

/// A local account.
#[derive(Clone, Debug)]
pub struct UserAccount {
    pub name: String,
    pub uid: String,
    pub gid: String,
    pub home: String,
    pub shell: String,
    /// `true` when the shell can be used to get an interactive session.
    pub interactive: bool,
    pub privileged: bool,
    /// Where the privilege comes from: group name, sudoers rule, SID...
    pub privilege_source: Vec<String>,
    /// `locked`, `empty`, `hashed`, `unknown`.
    pub password_state: PasswordState,
    pub groups: Vec<String>,
    pub last_login: Option<String>,
    pub enabled: bool,
    pub password_never_expires: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PasswordState {
    Locked,
    Empty,
    Hashed,
    Unknown,
}

/// A passwordless privilege elevation rule.
#[derive(Clone, Debug)]
pub struct SudoRule {
    pub source: String,
    pub rule: String,
}

/// One listening socket or established connection.
#[derive(Clone, Debug)]
pub struct SocketEntry {
    pub proto: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

/// A network interface as reported by the OS.
#[derive(Clone, Debug)]
pub struct InterfaceInfo {
    pub name: String,
    pub addresses: Vec<String>,
    pub mac: String,
    pub mtu: u64,
    pub promiscuous: bool,
    pub received: u64,
    pub transmitted: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// A scheduled task: cron entry, systemd timer or Windows scheduled task.
#[derive(Clone, Debug)]
pub struct ScheduledTask {
    pub kind: String,
    pub name: String,
    pub schedule: String,
    pub command: String,
    pub owner: String,
    pub source: String,
}

/// A service, daemon or unit.
#[derive(Clone, Debug)]
pub struct ServiceEntry {
    pub name: String,
    pub state: String,
    pub start_mode: String,
    pub exec: String,
    pub unit_path: String,
    /// `true` when the unit lives outside the vendor directories.
    pub vendor_supplied: bool,
}

/// An autostart hook that is neither a service nor a scheduled task.
#[derive(Clone, Debug)]
pub struct AutostartEntry {
    pub kind: AutostartKind,
    pub source: String,
    pub name: String,
    pub value: String,
}

/// What sort of hook an [`AutostartEntry`] is, so the report can name it
/// precisely instead of calling every mechanism "autostart".
///
/// Each variant is produced by exactly one platform collector, so on any
/// single build the other platform's variants are constructed nowhere. That is
/// the point of the enum, not an oversight.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AutostartKind {
    /// Unix boot script such as `/etc/rc.local`.
    BootScript,
    /// Shell profile fragment.
    Profile,
    /// Desktop session autostart entry.
    DesktopSession,
    /// Windows registry Run/RunOnce value.
    RunKey,
    /// Windows Startup folder item.
    StartupFolder,
    /// Permanent WMI event subscription.
    WmiSubscription,
}

/// An installed package.
#[derive(Clone, Debug)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
}

/// A neighbour in the local ARP/NDP table.
#[derive(Clone, Debug)]
pub struct NeighborEntry {
    pub ip: String,
    pub mac: String,
    pub interface: String,
    pub state: String,
    pub hostname: Option<String>,
}

/// A log source and whether it could actually be read.
#[derive(Clone, Debug)]
pub struct LogSource {
    pub name: String,
    pub path: String,
    pub available: bool,
    pub readable: bool,
    pub size: u64,
    pub lines: Vec<String>,
}

/// Local firewall state.
#[derive(Clone, Debug)]
pub struct FirewallState {
    pub engine: String,
    pub active: bool,
    pub rule_count: usize,
}

// ---------------------------------------------------------------------------
// Shared helpers used by both platform back ends.
// ---------------------------------------------------------------------------

/// Run a command and capture stdout, returning `None` when the binary is
/// absent or the call fails. Never panics: a missing tool degrades the report
/// instead of aborting the scan.
pub fn run(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.trim().is_empty() && !output.stderr.is_empty() {
        text = String::from_utf8_lossy(&output.stderr).into_owned();
    }
    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Whether an executable is reachable through `PATH`.
pub fn has_binary(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    let separator = if cfg!(windows) { ';' } else { ':' };
    let extensions: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    };
    path.split(separator).any(|dir| {
        extensions
            .iter()
            .any(|ext| Path::new(dir).join(format!("{name}{ext}")).is_file())
    })
}

/// Read a whole file, returning `None` on any error.
pub fn read_file(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read(path.as_ref())
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Read a file and return its lines, ignoring errors.
pub fn read_lines(path: impl AsRef<Path>) -> Vec<String> {
    read_file(path)
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Render a byte count in human units.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Render a duration in a compact, readable form.
pub fn human_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    let millis = duration.subsec_millis();
    if total == 0 {
        return format!("{millis} ms");
    }
    let (hours, minutes, seconds) = (total / 3600, (total % 3600) / 60, total % 60);
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}.{:01}s", millis / 100)
    }
}

/// Render an uptime in seconds as days/hours/minutes.
pub fn human_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3600;
    let minutes = (seconds % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

/// True when the address is routable on the public internet.
pub fn is_public_ip(addr: &str) -> bool {
    let cleaned = addr.trim_matches(|c| c == '[' || c == ']');
    if let Ok(v4) = cleaned.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        let private = o[0] == 10
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 192 && o[1] == 168)
            || (o[0] == 169 && o[1] == 254)
            || o[0] == 127
            || o[0] == 0
            || v4.is_multicast()
            || v4.is_broadcast();
        return !private;
    }
    if let Ok(v6) = cleaned.parse::<std::net::Ipv6Addr>() {
        let segments = v6.segments();
        let private = v6.is_loopback()
            || v6.is_unspecified()
            || v6.is_multicast()
            || (segments[0] & 0xfe00) == 0xfc00
            || (segments[0] & 0xffc0) == 0xfe80;
        return !private;
    }
    false
}

/// True when the bind address accepts traffic from any interface.
pub fn is_wildcard_bind(addr: &str) -> bool {
    matches!(
        addr,
        "0.0.0.0" | "::" | "*" | "[::]" | "0000:0000:0000:0000:0000:0000:0000:0000"
    )
}

/// True when the address only accepts local traffic.
pub fn is_loopback_bind(addr: &str) -> bool {
    addr.starts_with("127.") || addr == "::1" || addr == "[::1]"
}

/// A filesystem root the file module walks, and how deep it should go.
#[derive(Clone, Debug)]
pub struct ScanRoot {
    pub path: String,
    pub max_depth: usize,
    pub kind: RootKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RootKind {
    /// Directories holding system binaries and libraries.
    System,
    /// Configuration trees.
    Config,
    /// World-writable temporary storage.
    Temp,
    /// User home directories.
    Home,
}

/// Ownership and permission facts about a single file.
///
/// Filled in by `sys::file_attributes`, which each platform implements from
/// whatever its filesystem actually records; fields with no local equivalent
/// are left neutral rather than guessed at.
#[derive(Clone, Debug)]
pub struct FileAttributes {
    pub mode: String,
    pub owner: String,
    pub owner_id: u32,
    pub owner_known: bool,
    pub suid: bool,
    pub sgid: bool,
    pub world_writable: bool,
    pub executable: bool,
    pub size: u64,
    pub modified: String,
    pub modified_secs_ago: u64,
}
