//! Windows Server data collection.
//!
//! Windows exposes no `/proc`, so this back end asks the operating system
//! through the interfaces an administrator would use by hand: PowerShell for
//! anything structured, the classic console tools where they are faster, and
//! the registry for the boot-time hooks. Every command is invoked without a
//! profile and non-interactively, and a missing or refused command degrades
//! the report instead of aborting the scan.
//!
//! The module mirrors `platform::linux` function for function; the diagnostic
//! modules are written once against this shared surface.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    has_binary, read_lines, run, AutostartEntry, AutostartKind, Family, FileAttributes,
    FirewallState, InterfaceInfo, LogSource, NeighborEntry, OsIdentity, PackageInfo, PasswordState,
    RootKind, ScanRoot, ScheduledTask, ServiceEntry, SocketEntry, SudoRule, UserAccount,
};

/// `FILE_ATTRIBUTE_READONLY`.
const ATTRIBUTE_READONLY: u32 = 0x0000_0001;
/// `FILE_ATTRIBUTE_HIDDEN`.
const ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
/// `FILE_ATTRIBUTE_SYSTEM`.
const ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
/// `FILE_ATTRIBUTE_DIRECTORY`.
const ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// Groups that carry administrative power.
const ADMIN_GROUPS: &[&str] = &["Administrators", "Domain Admins", "Enterprise Admins"];

/// Access rights in an ACL that let a non-owner change a file.
const WRITE_RIGHTS: &[&str] = &[
    "(F)",
    "(M)",
    "(W)",
    "(RX,W)",
    "FullControl",
    "Modify",
    "Write",
];

/// Principals that mean "anyone who can log on".
const OPEN_PRINCIPALS: &[&str] = &[
    "Everyone",
    "Todos",
    "BUILTIN\\Users",
    "NT AUTHORITY\\Authenticated Users",
];

/// Run a PowerShell snippet and capture stdout.
///
/// `-NoProfile` keeps a customised profile from changing the output format and
/// `-NonInteractive` guarantees the call cannot block waiting for input.
fn ps(script: &str) -> Option<String> {
    run(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
    )
}

/// Split a pipe-delimited line produced by one of the PowerShell snippets.
fn fields(line: &str, expected: usize) -> Option<Vec<String>> {
    let parts: Vec<String> = line
        .split('|')
        .map(|part| part.trim().to_string())
        .collect();
    (parts.len() >= expected).then_some(parts)
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// True when the process holds a high integrity level, which is what actually
/// governs whether the sensitive queries below return anything.
pub fn is_elevated() -> bool {
    run("whoami", &["/groups"])
        .map(|text| text.contains("S-1-16-12288") || text.contains("S-1-16-16384"))
        .unwrap_or(false)
}

/// The package manager present on this machine, if any.
pub fn package_manager() -> Option<String> {
    const MANAGERS: &[(&str, &str)] = &[
        ("winget", "winget"),
        ("choco", "chocolatey"),
        ("scoop", "scoop"),
    ];
    MANAGERS
        .iter()
        .find(|(binary, _)| has_binary(binary))
        .map(|(_, label)| (*label).to_string())
}

/// Windows always starts services through the Service Control Manager.
pub fn init_system() -> Option<String> {
    Some("Service Control Manager".to_string())
}

/// Identify the running Windows edition and build.
pub fn identify() -> OsIdentity {
    let mut evidence = Vec::new();

    // One CIM query answers everything the header needs.
    let summary = ps(
        "$os = Get-CimInstance Win32_OperatingSystem; \
         $cs = Get-CimInstance Win32_ComputerSystem; \
         $uptime = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds; \
         \"$($os.Caption)|$($os.Version)|$($os.BuildNumber)|$($cs.Name)|$($os.OSArchitecture)|$uptime|$($os.ProductType)\"",
    );

    let mut name = "Windows".to_string();
    let mut version = String::new();
    let mut build = String::new();
    let mut hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());
    let mut arch = std::env::consts::ARCH.to_string();
    let mut uptime = 0u64;
    let mut product_type = String::new();

    if let Some(parts) = summary
        .as_deref()
        .and_then(|text| text.lines().find(|line| line.contains('|')))
        .and_then(|line| fields(line, 7))
    {
        name = parts[0].clone();
        version = parts[1].clone();
        build = parts[2].clone();
        if !parts[3].is_empty() {
            hostname = parts[3].clone();
        }
        if !parts[4].is_empty() {
            arch = parts[4].clone();
        }
        uptime = parts[5].parse().unwrap_or(0);
        product_type = parts[6].clone();
        evidence.push(format!(
            "Win32_OperatingSystem: {name} {version} build {build}"
        ));
    } else {
        // wmic is deprecated but still present on the older server builds this
        // tool is most likely to be pointed at.
        if let Some(text) = run(
            "wmic",
            &["os", "get", "Caption,Version,BuildNumber", "/value"],
        ) {
            for line in text.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    match key.trim() {
                        "Caption" => name = value.trim().to_string(),
                        "Version" => version = value.trim().to_string(),
                        "BuildNumber" => build = value.trim().to_string(),
                        _ => {}
                    }
                }
            }
            evidence.push("wmic os: present".to_string());
        }
    }

    // ProductType 2 is a domain controller, 3 a member server, 1 a workstation.
    let id = derive_id(&name, &product_type);
    if !product_type.is_empty() {
        evidence.push(format!("ProductType={product_type}"));
    }
    if let Some(manager) = package_manager() {
        evidence.push(format!("package manager: {manager}"));
    }
    if Path::new(r"C:\inetpub").is_dir() {
        evidence.push(r"IIS root present: C:\inetpub".to_string());
    }

    OsIdentity {
        family: Family::Windows,
        id,
        name,
        version,
        kernel: build,
        hostname,
        arch,
        package_manager: package_manager(),
        init_system: init_system(),
        uptime,
        evidence,
    }
}

/// Map a product caption onto the catalogue id used by the database.
fn derive_id(caption: &str, product_type: &str) -> String {
    let lowered = caption.to_lowercase();
    for (needle, id) in [
        ("2025", "windows-server-2025"),
        ("2022", "windows-server-2022"),
        ("2019", "windows-server-2019"),
        ("2016", "windows-server-2016"),
        ("2012", "windows-server-2012"),
        ("2008", "windows-server-2008"),
        ("windows 11", "windows-11"),
        ("windows 10", "windows-10"),
    ] {
        if lowered.contains(needle) {
            return id.to_string();
        }
    }
    if product_type == "1" {
        "windows-client".to_string()
    } else {
        "windows-server".to_string()
    }
}

/// The full catalogue of systems offered when the operator rejects the guess.
pub fn known_systems() -> Vec<(&'static str, &'static str)> {
    vec![
        ("windows-server-2025", "Windows Server 2025"),
        ("windows-server-2022", "Windows Server 2022"),
        ("windows-server-2019", "Windows Server 2019"),
        ("windows-server-2016", "Windows Server 2016"),
        ("windows-server-2012", "Windows Server 2012 / 2012 R2"),
        ("windows-server-2008", "Windows Server 2008 / 2008 R2"),
        ("windows-server-core", "Windows Server Core"),
        ("windows-server-hyperv", "Hyper-V Server"),
        ("windows-11", "Windows 11"),
        ("windows-10", "Windows 10"),
        (
            "windows-client",
            "Otro Windows cliente / Other Windows client",
        ),
        (
            "windows-server",
            "Otro Windows Server / Other Windows Server",
        ),
    ]
}

/// The profile that best fits the observed evidence, and why.
pub fn recommend(identity: &OsIdentity) -> (String, String, Vec<String>) {
    let mut reasons = Vec::new();
    if !identity.kernel.is_empty() {
        reasons.push(format!("build {}", identity.kernel));
    }
    if !identity.version.is_empty() {
        reasons.push(format!("version {}", identity.version));
    }
    if let Some(manager) = &identity.package_manager {
        reasons.push(manager.clone());
    }

    // The build number is the reliable discriminator; the caption can be
    // rebranded and the version number repeats across releases.
    let build: u32 = identity.kernel.parse().unwrap_or(0);
    let (id, label) = match build {
        26100.. => ("windows-server-2025", "Windows Server 2025"),
        20348..=26099 => ("windows-server-2022", "Windows Server 2022"),
        17763..=20347 => ("windows-server-2019", "Windows Server 2019"),
        14393..=17762 => ("windows-server-2016", "Windows Server 2016"),
        9200..=14392 => ("windows-server-2012", "Windows Server 2012 / 2012 R2"),
        6001..=9199 => ("windows-server-2008", "Windows Server 2008 / 2008 R2"),
        _ => {
            let systems = known_systems();
            let fallback = systems
                .iter()
                .find(|(id, _)| *id == identity.id)
                .copied()
                .unwrap_or((
                    "windows-server",
                    "Otro Windows Server / Other Windows Server",
                ));
            fallback
        }
    };
    (id.to_string(), label.to_string(), reasons)
}

/// The account running the scan.
pub fn current_user() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| {
        run("whoami", &[])
            .map(|text| text.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    })
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// Every local account with the security facts the users module needs.
pub fn users() -> Vec<UserAccount> {
    let mut accounts = Vec::new();

    // Get-LocalUser is the modern interface; `net user` covers the builds that
    // predate it.
    let listing = ps(
        "Get-LocalUser | ForEach-Object { \
         $last = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }; \
         \"$($_.Name)|$($_.SID.Value)|$($_.Enabled)|$($_.PasswordRequired)|$($_.PasswordExpires)|$last|$($_.Description)\" }",
    );

    // Local Administrators is the usual source of privilege, but a domain
    // joined server hands it out through the domain groups as well.
    let admin_members: BTreeSet<String> = ADMIN_GROUPS
        .iter()
        .flat_map(|group| group_members(group))
        .collect();
    let remote_members = group_members("Remote Desktop Users");

    if let Some(text) = listing {
        for line in text.lines() {
            let Some(parts) = fields(line, 6) else {
                continue;
            };
            let name = parts[0].clone();
            if name.is_empty() {
                continue;
            }
            let sid = parts[1].clone();
            // The relative identifier is the closest thing Windows has to a
            // uid, and 500 is the built-in Administrator.
            let rid = sid.rsplit('-').next().unwrap_or("0").to_string();
            let enabled = parts[2].eq_ignore_ascii_case("true");
            let password_required = parts[3].eq_ignore_ascii_case("true");
            let password_expires = parts[4].trim().to_string();
            let last_login = (!parts[5].is_empty()).then(|| parts[5].clone());

            let mut groups = Vec::new();
            let mut privilege_source = Vec::new();
            if admin_members.contains(&name) {
                groups.push("Administrators".to_string());
                privilege_source.push("group:Administrators".to_string());
            }
            if !parts[6].is_empty() {
                groups.push(parts[6].clone());
            }
            if remote_members.contains(&name) {
                groups.push("Remote Desktop Users".to_string());
            }
            if rid == "500" {
                privilege_source.push("rid=500".to_string());
            }

            let password_state = if !password_required {
                PasswordState::Empty
            } else if !enabled {
                PasswordState::Locked
            } else {
                PasswordState::Hashed
            };

            accounts.push(UserAccount {
                home: format!(r"C:\Users\{name}"),
                // Windows has no per-account shell; an enabled account is the
                // equivalent of one with an interactive shell.
                shell: if enabled { "interactive" } else { "disabled" }.to_string(),
                interactive: enabled,
                privileged: !privilege_source.is_empty(),
                privilege_source,
                password_state,
                groups,
                last_login,
                enabled,
                password_never_expires: password_expires.is_empty(),
                gid: sid.clone(),
                uid: rid,
                name,
            });
        }
    }

    if accounts.is_empty() {
        // Minimal fallback so the module still has something to report.
        if let Some(text) = run("net", &["user"]) {
            for line in text.lines().skip(4) {
                for name in line.split_whitespace() {
                    if name.starts_with("The command") || name.is_empty() {
                        continue;
                    }
                    accounts.push(UserAccount {
                        name: name.to_string(),
                        uid: "-".to_string(),
                        gid: "-".to_string(),
                        home: format!(r"C:\Users\{name}"),
                        shell: "unknown".to_string(),
                        interactive: true,
                        privileged: admin_members.contains(name),
                        privilege_source: Vec::new(),
                        password_state: PasswordState::Unknown,
                        groups: Vec::new(),
                        last_login: None,
                        enabled: true,
                        password_never_expires: false,
                    });
                }
            }
        }
    }

    accounts
}

/// Members of a local group, by name.
fn group_members(group: &str) -> BTreeSet<String> {
    let script = format!(
        "Get-LocalGroupMember -Group '{group}' -ErrorAction SilentlyContinue | ForEach-Object {{ ($_.Name -split '\\\\')[-1] }}"
    );
    ps(&script)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Windows has no sudoers file; elevation is governed by group membership,
/// which the users module already reports.
pub fn sudo_rules() -> Vec<SudoRule> {
    Vec::new()
}

/// Authorised SSH key files for an account: path, key count, permissions.
pub fn ssh_authorized_keys(home: &str) -> Vec<(String, usize, String)> {
    let mut found = Vec::new();
    let mut candidates = vec![PathBuf::from(home).join(".ssh").join("authorized_keys")];
    // OpenSSH on Windows reads administrator keys from a single shared file.
    candidates.push(PathBuf::from(
        r"C:\ProgramData\ssh\administrators_authorized_keys",
    ));

    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let keys = read_lines(&path)
            .into_iter()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with('#')
            })
            .count();
        let display = path.display().to_string();
        let acl = writable_permission_issue(&display).unwrap_or_else(|| "restricted".to_string());
        found.push((display, keys, acl));
    }
    found
}

/// Permission problem on a home directory, expressed as the offending ACE.
pub fn home_permission_issue(home: &str, _sid: &str) -> Option<String> {
    if !Path::new(home).is_dir() {
        return None;
    }
    writable_permission_issue(home)
}

/// Whether a path exists and is a directory.
pub fn directory_exists(path: &str) -> bool {
    Path::new(path).is_dir()
}

// ---------------------------------------------------------------------------
// Access control
// ---------------------------------------------------------------------------

/// The first access control entry that lets a broad principal write to a path.
///
/// `icacls` is used rather than a native security descriptor call because it is
/// present on every supported build and needs no extra dependency; the cost is
/// one process per path, so callers check specific paths, never a whole tree.
pub fn writable_permission_issue(path: &str) -> Option<String> {
    let text = run("icacls", &[path])?;
    for line in text.lines() {
        let Some((principal, rights)) = line.split_once(':') else {
            continue;
        };
        let principal = principal.trim();
        let principal = principal.rsplit(' ').next().unwrap_or(principal);
        if !OPEN_PRINCIPALS
            .iter()
            .any(|open| principal.eq_ignore_ascii_case(open))
        {
            continue;
        }
        if WRITE_RIGHTS.iter().any(|right| rights.contains(right)) {
            return Some(format!("{principal}:{}", rights.trim()));
        }
    }
    None
}

/// Whether any user on the system can write to this path.
pub fn path_is_world_writable(path: &str) -> bool {
    writable_permission_issue(path).is_some()
}

/// Windows has no `/dev/null` symlink convention for discarding history.
pub fn points_to_null(_path: &Path) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// PIDs reported by the WMI process provider.
fn wmi_pids() -> BTreeSet<u32> {
    ps("Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }")
        .map(|text| {
            text.lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// PIDs reported by the toolhelp snapshot that `tasklist` walks.
fn tasklist_pids() -> BTreeSet<u32> {
    run("tasklist", &["/fo", "csv", "/nh"])
        .map(|text| {
            text.lines()
                .filter_map(|line| {
                    let column = line.split("\",\"").nth(1)?;
                    column.trim_matches('"').trim().parse::<u32>().ok()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Processes visible through one enumeration interface but not the other.
///
/// WMI and the toolhelp snapshot reach the process list by different paths, so
/// a rootkit that unlinks an entry from one usually leaves it in the other. As
/// on Linux, the comparison is taken twice so a process that merely started
/// mid-scan is not mistaken for a hidden one.
pub fn hidden_pids() -> Vec<u32> {
    let wmi = wmi_pids();
    let toolhelp = tasklist_pids();
    if wmi.is_empty() || toolhelp.is_empty() {
        // One of the two interfaces did not answer; a comparison against an
        // empty set would report every process as hidden.
        return Vec::new();
    }

    let mut candidates: Vec<u32> = wmi.difference(&toolhelp).copied().collect();
    if candidates.is_empty() {
        return candidates;
    }
    let confirm = tasklist_pids();
    candidates.retain(|pid| !confirm.contains(pid));
    candidates
}

/// True when the process still runs but its executable is gone from disk.
pub fn exe_deleted(pid: u32) -> Option<String> {
    let script = format!(
        "$p = Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' -ErrorAction SilentlyContinue; \
         if ($p -and $p.ExecutablePath) {{ $p.ExecutablePath }}"
    );
    let path = ps(&script)?.trim().to_string();
    if path.is_empty() {
        return None;
    }
    (!Path::new(&path).exists()).then_some(path)
}

/// Windows resolves account names through SIDs rather than numeric ids, so the
/// numeric map the file walk takes is empty here and ownership is never
/// reported as orphaned on this platform.
pub fn uid_names() -> HashMap<u32, String> {
    HashMap::new()
}

/// Directories a normal binary is expected to live in.
pub fn system_binary_prefixes() -> &'static [&'static str] {
    &[
        r"C:\Windows\",
        r"C:\Program Files\",
        r"C:\Program Files (x86)\",
        r"C:\ProgramData\Microsoft\",
        r"\??\C:\Windows\",
        r"\SystemRoot\",
    ]
}

/// Directories where an executing binary is inherently suspicious.
pub fn volatile_prefixes() -> &'static [&'static str] {
    &[
        r"C:\Windows\Temp\",
        r"C:\Temp\",
        r"C:\Users\Public\",
        r"C:\PerfLogs\",
        r"C:\$Recycle.Bin\",
        r"\AppData\Local\Temp\",
        r"\Downloads\",
    ]
}

/// Names of processes that only ever run from a system path.
pub fn system_process_names() -> &'static [&'static str] {
    &[
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "csrss.exe",
        "winlogon.exe",
        "wininit.exe",
        "smss.exe",
        "explorer.exe",
        "spoolsv.exe",
        "taskhostw.exe",
        "dwm.exe",
        "RuntimeBroker.exe",
        "conhost.exe",
        "lsm.exe",
        "SearchIndexer.exe",
        "wmiprvse.exe",
        "msdtc.exe",
        "dllhost.exe",
        "w3wp.exe",
        "sqlservr.exe",
    ]
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Split a `netstat` endpoint into address and port.
fn split_endpoint(endpoint: &str) -> (String, u16) {
    match endpoint.rsplit_once(':') {
        Some((address, port)) => (
            address.trim_matches(|c| c == '[' || c == ']').to_string(),
            port.parse().unwrap_or(0),
        ),
        None => (endpoint.to_string(), 0),
    }
}

/// pid -> image name, so a socket can name its owner.
fn process_names() -> HashMap<u32, String> {
    let mut names = HashMap::new();
    if let Some(text) = run("tasklist", &["/fo", "csv", "/nh"]) {
        for line in text.lines() {
            let columns: Vec<&str> = line.split("\",\"").collect();
            if columns.len() < 2 {
                continue;
            }
            let name = columns[0].trim_matches('"').trim().to_string();
            if let Ok(pid) = columns[1].trim_matches('"').trim().parse::<u32>() {
                names.insert(pid, name);
            }
        }
    }
    names
}

/// Every socket the system knows about, listening and established alike.
pub fn sockets() -> Vec<SocketEntry> {
    let names = process_names();
    let mut entries = Vec::new();

    // `netstat -ano` is dramatically faster than the CIM equivalent and is
    // present on every build.
    let Some(text) = run("netstat", &["-ano"]) else {
        return entries;
    };

    for line in text.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 4 {
            continue;
        }
        let proto = columns[0].to_lowercase();
        if !proto.starts_with("tcp") && !proto.starts_with("udp") {
            continue;
        }
        let (local_addr, local_port) = split_endpoint(columns[1]);
        let (remote_addr, remote_port) = split_endpoint(columns[2]);

        // UDP rows carry no state column, so the PID moves one place left.
        let (state, pid_column) = if proto.starts_with("udp") {
            let state = if remote_port == 0 {
                "LISTEN"
            } else {
                "ESTABLISHED"
            };
            (state.to_string(), columns.get(3))
        } else {
            (columns[3].to_uppercase(), columns.get(4))
        };

        let pid = pid_column.and_then(|value| value.parse::<u32>().ok());
        entries.push(SocketEntry {
            proto,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
            process: pid.and_then(|pid| names.get(&pid).cloned()),
        });
    }
    entries
}

/// Network interfaces with counters, MAC, MTU and promiscuous flag.
pub fn interfaces() -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();
    let listing = ps(
        "Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { \
         $name = $_.Name; \
         $stats = Get-NetAdapterStatistics -Name $name -ErrorAction SilentlyContinue; \
         $addresses = (Get-NetIPAddress -InterfaceAlias $name -ErrorAction SilentlyContinue | \
             ForEach-Object { \"$($_.IPAddress)/$($_.PrefixLength)\" }) -join ','; \
         \"$name|$addresses|$($_.MacAddress)|$($_.MtuSize)|$($_.PromiscuousMode)|$($stats.ReceivedBytes)|$($stats.SentBytes)|$($stats.ReceivedDiscardedPackets)|$($stats.OutboundDiscardedPackets)\" }",
    );

    if let Some(text) = listing {
        for line in text.lines() {
            let Some(parts) = fields(line, 9) else {
                continue;
            };
            if parts[0].is_empty() {
                continue;
            }
            interfaces.push(InterfaceInfo {
                name: parts[0].clone(),
                addresses: parts[1]
                    .split(',')
                    .filter(|address| !address.is_empty())
                    .map(str::to_string)
                    .collect(),
                mac: parts[2].clone(),
                mtu: parts[3].parse().unwrap_or(0),
                promiscuous: parts[4].eq_ignore_ascii_case("true"),
                received: parts[5].parse().unwrap_or(0),
                transmitted: parts[6].parse().unwrap_or(0),
                rx_errors: parts[7].parse().unwrap_or(0),
                tx_errors: parts[8].parse().unwrap_or(0),
            });
        }
    }
    interfaces
}

/// Whether the host routes packets between interfaces.
pub fn ip_forwarding() -> Option<bool> {
    let text = ps("if (Get-NetIPInterface -ErrorAction SilentlyContinue | \
         Where-Object { $_.Forwarding -eq 'Enabled' }) { 'yes' } else { 'no' }")?;
    Some(text.trim() == "yes")
}

/// Local firewall state, read per profile.
pub fn firewall() -> FirewallState {
    if let Some(text) = ps(
        "$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue; \
         $on = ($profiles | Where-Object { $_.Enabled -eq 'True' }).Count; \
         $rules = (Get-NetFirewallRule -ErrorAction SilentlyContinue | \
             Where-Object { $_.Enabled -eq 'True' }).Count; \
         \"$on|$rules\"",
    ) {
        if let Some(parts) = text.lines().find_map(|line| fields(line, 2)) {
            let enabled: usize = parts[0].parse().unwrap_or(0);
            let rules: usize = parts[1].parse().unwrap_or(0);
            return FirewallState {
                engine: "Windows Defender Firewall".to_string(),
                active: enabled > 0,
                rule_count: rules,
            };
        }
    }
    if let Some(text) = run("netsh", &["advfirewall", "show", "allprofiles", "state"]) {
        let active = text.to_uppercase().contains("ON");
        return FirewallState {
            engine: "Windows Defender Firewall".to_string(),
            active,
            rule_count: 0,
        };
    }
    FirewallState {
        engine: "unknown".to_string(),
        active: false,
        rule_count: 0,
    }
}

/// Neighbours known to this host, read from the local tables only.
pub fn neighbors() -> Vec<NeighborEntry> {
    let hosts = local_host_names();
    let mut entries = Vec::new();

    if let Some(text) = ps(
        "Get-NetNeighbor -ErrorAction SilentlyContinue | ForEach-Object { \
         \"$($_.IPAddress)|$($_.LinkLayerAddress)|$($_.InterfaceAlias)|$($_.State)\" }",
    ) {
        for line in text.lines() {
            let Some(parts) = fields(line, 4) else {
                continue;
            };
            if parts[0].is_empty() {
                continue;
            }
            entries.push(NeighborEntry {
                hostname: hosts.get(&parts[0]).cloned(),
                ip: parts[0].clone(),
                mac: parts[1].clone(),
                interface: parts[2].clone(),
                state: parts[3].to_uppercase(),
            });
        }
    }

    if entries.is_empty() {
        if let Some(text) = run("arp", &["-a"]) {
            for line in text.lines() {
                let columns: Vec<&str> = line.split_whitespace().collect();
                if columns.len() < 3 || !columns[0].contains('.') {
                    continue;
                }
                entries.push(NeighborEntry {
                    hostname: hosts.get(columns[0]).cloned(),
                    ip: columns[0].to_string(),
                    mac: columns[1].to_string(),
                    interface: "-".to_string(),
                    state: columns[2].to_uppercase(),
                });
            }
        }
    }
    entries
}

/// Name resolution restricted to the local hosts file: no query leaves the
/// machine.
pub fn local_host_names() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in read_lines(r"C:\Windows\System32\drivers\etc\hosts") {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut columns = line.split_whitespace();
        let Some(ip) = columns.next() else { continue };
        if let Some(name) = columns.next() {
            map.insert(ip.to_string(), name.to_string());
        }
    }
    map
}

/// Default gateways configured on this host.
pub fn gateways() -> Vec<String> {
    ps(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
        ForEach-Object { \"$($_.NextHop) ($($_.InterfaceAlias))\" }",
    )
    .map(|text| {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// Subnets directly attached to this host.
pub fn local_subnets() -> Vec<String> {
    interfaces()
        .into_iter()
        .flat_map(|interface| interface.addresses)
        .filter(|address| !address.starts_with("127.") && !address.starts_with("::1"))
        .collect()
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Scheduled tasks, with the command each one runs.
pub fn scheduled_tasks() -> Vec<ScheduledTask> {
    let mut tasks = Vec::new();

    let listing = ps(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { \
         $action = ($_.Actions | ForEach-Object { \"$($_.Execute) $($_.Arguments)\" }) -join ' ; '; \
         $trigger = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','; \
         \"$($_.TaskName)|$($_.TaskPath)|$trigger|$action|$($_.Principal.UserId)|$($_.State)\" }",
    );

    if let Some(text) = listing {
        for line in text.lines() {
            let Some(parts) = fields(line, 6) else {
                continue;
            };
            if parts[0].is_empty() {
                continue;
            }
            tasks.push(ScheduledTask {
                kind: "scheduled-task".to_string(),
                name: format!("{}{}", parts[1], parts[0]),
                schedule: format!("{} ({})", parts[2], parts[5]),
                command: parts[3].trim().to_string(),
                owner: parts[4].clone(),
                source: "Task Scheduler".to_string(),
            });
        }
    }

    if tasks.is_empty() {
        // schtasks is available on builds without the PowerShell module.
        if let Some(text) = run("schtasks", &["/query", "/fo", "CSV", "/v", "/nh"]) {
            for line in text.lines() {
                let columns: Vec<&str> = line.split("\",\"").collect();
                if columns.len() < 9 {
                    continue;
                }
                tasks.push(ScheduledTask {
                    kind: "scheduled-task".to_string(),
                    name: columns[1].trim_matches('"').to_string(),
                    schedule: columns[2].trim_matches('"').to_string(),
                    command: columns[8].trim_matches('"').to_string(),
                    owner: columns[7].trim_matches('"').to_string(),
                    source: "schtasks".to_string(),
                });
            }
        }
    }
    tasks
}

/// Services, with the binary each one starts.
pub fn services() -> Vec<ServiceEntry> {
    let mut services = Vec::new();
    let listing = ps("Get-CimInstance Win32_Service | ForEach-Object { \
         \"$($_.Name)|$($_.State)|$($_.StartMode)|$($_.PathName)|$($_.StartName)\" }");

    if let Some(text) = listing {
        for line in text.lines() {
            let Some(parts) = fields(line, 5) else {
                continue;
            };
            if parts[0].is_empty() {
                continue;
            }
            let path = parts[3].clone();
            // A service whose image lives under the Windows or Program Files
            // trees came with the system or with an installer; anything else
            // was placed by hand and is what the report should surface.
            let vendor = system_binary_prefixes().iter().any(|prefix| {
                path.trim_start_matches('"')
                    .to_lowercase()
                    .starts_with(&prefix.to_lowercase())
            });
            services.push(ServiceEntry {
                name: parts[0].clone(),
                state: parts[1].clone(),
                start_mode: parts[2].clone(),
                exec: path.clone(),
                unit_path: path,
                vendor_supplied: vendor,
            });
        }
    }
    services
}

/// Registry run keys, startup folders and permanent WMI subscriptions.
pub fn autostart() -> Vec<AutostartEntry> {
    let mut entries = Vec::new();

    const RUN_KEYS: &[&str] = &[
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    for key in RUN_KEYS {
        let Some(text) = run("reg", &["query", key]) else {
            continue;
        };
        for line in text.lines() {
            let columns: Vec<&str> = line.split_whitespace().collect();
            // `name  REG_SZ  value...`
            if columns.len() < 3 || !columns[1].starts_with("REG_") {
                continue;
            }
            entries.push(AutostartEntry {
                kind: AutostartKind::RunKey,
                source: (*key).to_string(),
                name: columns[0].to_string(),
                value: columns[2..].join(" "),
            });
        }
    }

    const STARTUP_FOLDERS: &[&str] = &[
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        r"C:\Users\All Users\Microsoft\Windows\Start Menu\Programs\StartUp",
    ];
    let mut folders: Vec<PathBuf> = STARTUP_FOLDERS.iter().map(PathBuf::from).collect();
    for home in home_directories() {
        folders.push(home.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    for folder in folders {
        let Ok(items) = fs::read_dir(&folder) else {
            continue;
        };
        for item in items.flatten() {
            entries.push(AutostartEntry {
                kind: AutostartKind::StartupFolder,
                source: folder.display().to_string(),
                name: item.file_name().to_string_lossy().into_owned(),
                value: item.path().display().to_string(),
            });
        }
    }

    // A permanent event subscription survives reboots and runs without a
    // service or a scheduled task to point at.
    if let Some(text) = ps(
        "Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding \
         -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.Filter)|$($_.Consumer)\" }",
    ) {
        for line in text.lines() {
            let Some(parts) = fields(line, 2) else {
                continue;
            };
            if parts[0].is_empty() {
                continue;
            }
            entries.push(AutostartEntry {
                kind: AutostartKind::WmiSubscription,
                source: r"root\subscription".to_string(),
                name: parts[0].clone(),
                value: parts[1].clone(),
            });
        }
    }

    entries
}

/// Libraries injected into every process that loads user32.
///
/// `AppInit_DLLs` is the Windows counterpart of `LD_PRELOAD`, and the same
/// reasoning applies: a value here affects the whole system.
pub fn preload_libraries() -> Vec<(String, String)> {
    let mut found = Vec::new();
    const KEYS: &[&str] = &[
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        r"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ];
    for key in KEYS {
        let Some(text) = run("reg", &["query", key, "/v", "AppInit_DLLs"]) else {
            continue;
        };
        for line in text.lines() {
            let columns: Vec<&str> = line.split_whitespace().collect();
            if columns.len() >= 3 && columns[0] == "AppInit_DLLs" {
                let value = columns[2..].join(" ");
                if !value.trim().is_empty() {
                    found.push(((*key).to_string(), value));
                }
            }
        }
    }
    found
}

/// Home directories of every local profile.
pub fn home_directories() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    let Ok(entries) = fs::read_dir(r"C:\Users") else {
        return homes;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        // These are templates and service profiles, not user data.
        if !path.is_dir()
            || name.eq_ignore_ascii_case("Default")
            || name.eq_ignore_ascii_case("Default User")
            || name.eq_ignore_ascii_case("All Users")
            || name.eq_ignore_ascii_case("Public")
        {
            continue;
        }
        homes.push(path);
    }
    homes
}

/// PowerShell profiles, the closest equivalent of a shell startup file.
pub fn shell_rc_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for home in home_directories() {
        for relative in [
            r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
            r"Documents\WindowsPowerShell\profile.ps1",
            r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
            r"Documents\PowerShell\profile.ps1",
        ] {
            let candidate = home.join(relative);
            if candidate.is_file() {
                files.push(candidate);
            }
        }
    }
    for system in [
        r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
    ] {
        if Path::new(system).is_file() {
            files.push(PathBuf::from(system));
        }
    }
    files
}

/// Command history files.
pub fn history_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for home in home_directories() {
        let candidate = home.join(
            r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        );
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

// ---------------------------------------------------------------------------
// Packages and versions
// ---------------------------------------------------------------------------

/// Installed software, read from the uninstall registry rather than through
/// `Win32_Product`.
///
/// Querying `Win32_Product` triggers a consistency check that reconfigures
/// every installed MSI package, which on a production server is both slow and
/// disruptive. The registry holds the same inventory and is only read.
pub fn packages() -> (Vec<PackageInfo>, String) {
    let mut packages = Vec::new();
    let listing = ps("$paths = @( \
         'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', \
         'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); \
         Get-ItemProperty $paths -ErrorAction SilentlyContinue | \
         Where-Object { $_.DisplayName } | \
         ForEach-Object { \"$($_.DisplayName)|$($_.DisplayVersion)\" }");
    if let Some(text) = listing {
        for line in text.lines() {
            let Some(parts) = fields(line, 2) else {
                continue;
            };
            if parts[0].is_empty() {
                continue;
            }
            packages.push(PackageInfo {
                name: parts[0].clone(),
                version: parts[1].clone(),
            });
        }
    }

    // Installed updates are part of the version picture on Windows.
    if let Some(text) = ps(
        "Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.HotFixID)|$($_.InstalledOn)\" }",
    ) {
        for line in text.lines() {
            let Some(parts) = fields(line, 2) else { continue };
            if parts[0].is_empty() {
                continue;
            }
            packages.push(PackageInfo {
                name: parts[0].clone(),
                version: parts[1].clone(),
            });
        }
    }

    (packages, "registry+hotfix".to_string())
}

/// Versions of the services that matter most when they are exposed.
pub fn service_versions() -> Vec<(String, String)> {
    let mut versions = Vec::new();

    const BINARIES: &[(&str, &str)] = &[
        ("sshd", r"C:\Windows\System32\OpenSSH\sshd.exe"),
        ("iis", r"C:\Windows\System32\inetsrv\w3wp.exe"),
        (
            "sqlservr",
            r"C:\Program Files\Microsoft SQL Server\MSSQL\Binn\sqlservr.exe",
        ),
        (
            "powershell",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
    ];
    for (label, path) in BINARIES {
        if !Path::new(path).exists() {
            continue;
        }
        let script = format!("(Get-Item '{path}').VersionInfo.ProductVersion");
        if let Some(version) = ps(&script) {
            let version = version.trim().to_string();
            if !version.is_empty() {
                versions.push(((*label).to_string(), version));
            }
        }
    }

    if let Some(text) = ps("$PSVersionTable.PSVersion.ToString()") {
        let version = text.trim().to_string();
        if !version.is_empty() {
            versions.push(("powershell-engine".to_string(), version));
        }
    }
    versions
}

/// Pending updates are not read here: the only reliable source is the Windows
/// Update agent, which needs to reach a server, and this tool must work on an
/// isolated network.
pub fn pending_updates() -> Option<(usize, usize)> {
    None
}

/// Whether the system is waiting for a restart to finish applying updates.
pub fn reboot_required() -> bool {
    const KEYS: &[&str] = &[
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    ];
    if KEYS
        .iter()
        .any(|key| run("reg", &["query", key]).is_some_and(|text| text.contains(key)))
    {
        return true;
    }
    run(
        "reg",
        &[
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            "/v",
            "PendingFileRenameOperations",
        ],
    )
    .is_some_and(|text| text.contains("PendingFileRenameOperations"))
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

/// Normalise Security log events into the syntax the shared log analysis
/// already understands.
///
/// The logic that spots brute force, escalation and account creation lives in
/// one module for both platforms; rather than duplicate it, the Windows
/// collector renders each relevant event id into the equivalent syslog phrase.
/// The translation is one-directional and lossless for the fields the analysis
/// reads: user name, source address and event type.
const SECURITY_LOG_SCRIPT: &str = "\
$ids = 4624,4625,4648,4672,4720,4726,4740,1102; \
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids} -MaxEvents 4000 -ErrorAction SilentlyContinue | \
ForEach-Object { \
  $x = [xml]$_.ToXml(); \
  $get = { param($n) ($x.Event.EventData.Data | Where-Object { $_.Name -eq $n } | Select-Object -First 1).'#text' }; \
  $user = & $get 'TargetUserName'; \
  $subject = & $get 'SubjectUserName'; \
  $address = & $get 'IpAddress'; \
  if (-not $address -or $address -eq '-') { $address = & $get 'WorkstationName' } \
  if (-not $address) { $address = 'local' } \
  $time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); \
  switch ($_.Id) { \
    4625 { \"$time Security sshd: Failed password for $user from $address port 0 win32\" } \
    4624 { \"$time Security sshd: Accepted password for $user from $address port 0 win32\" } \
    4648 { \"$time Security sshd: Accepted password for $user from $address port 0 explicit\" } \
    4672 { \"$time Security sudo: $subject : COMMAND=special privileges assigned\" } \
    4720 { \"$time Security useradd: new user: name=$user\" } \
    4726 { \"$time Security userdel: deleted user: name=$user\" } \
    4740 { \"$time Security sshd: authentication failure for $user from $address (account locked out)\" } \
    1102 { \"$time Security: The audit log was cleared\" } \
  } \
}";

/// Authentication log sources, with their contents when readable.
pub fn log_sources(max_lines: usize) -> Vec<LogSource> {
    let mut sources = Vec::new();

    let security = ps(SECURITY_LOG_SCRIPT);
    let mut lines: Vec<String> = security
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if lines.len() > max_lines {
        let start = lines.len() - max_lines;
        lines = lines[start..].to_vec();
    }
    let count = lines.len() as u64;
    sources.push(LogSource {
        name: "Security".to_string(),
        path: "Event Log: Security".to_string(),
        available: true,
        readable: !lines.is_empty(),
        size: count,
        lines,
    });

    // The System log records the service installs that often accompany a
    // persistence mechanism.
    let system = ps(
        "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045,7030,104} -MaxEvents 500 \
         -ErrorAction SilentlyContinue | ForEach-Object { \
         \"$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) System: $($_.Message -replace '\\r?\\n',' ')\" }",
    );
    let system_lines: Vec<String> = system
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    sources.push(LogSource {
        name: "System".to_string(),
        path: "Event Log: System".to_string(),
        available: true,
        readable: !system_lines.is_empty(),
        size: system_lines.len() as u64,
        lines: system_lines,
    });

    sources
}

// ---------------------------------------------------------------------------
// Web
// ---------------------------------------------------------------------------

/// Web server configuration files worth inspecting.
pub fn web_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for candidate in [
        r"C:\Windows\System32\inetsrv\config\applicationHost.config",
        r"C:\Windows\System32\inetsrv\config\administration.config",
        r"C:\inetpub\wwwroot\web.config",
        r"C:\php\php.ini",
        r"C:\Program Files\PHP\php.ini",
        r"C:\tools\php\php.ini",
    ] {
        let path = Path::new(candidate);
        if path.is_file() {
            paths.push(path.to_path_buf());
        }
    }

    // Every application under the default site can carry its own web.config.
    if let Ok(entries) = fs::read_dir(r"C:\inetpub\wwwroot") {
        for entry in entries.flatten() {
            let candidate = entry.path().join("web.config");
            if candidate.is_file() {
                paths.push(candidate);
            }
        }
    }
    paths
}

/// Default document roots, used to spot untouched welcome pages.
pub fn web_default_pages() -> Vec<PathBuf> {
    [
        r"C:\inetpub\wwwroot\iisstart.htm",
        r"C:\inetpub\wwwroot\iisstart.html",
        r"C:\inetpub\wwwroot\index.htm",
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
            path: r"C:\Windows\System32".into(),
            max_depth: 2,
            kind: RootKind::System,
        },
        ScanRoot {
            path: r"C:\Windows\SysWOW64".into(),
            max_depth: 2,
            kind: RootKind::System,
        },
        ScanRoot {
            path: r"C:\Program Files".into(),
            max_depth: 4,
            kind: RootKind::System,
        },
        ScanRoot {
            path: r"C:\Program Files (x86)".into(),
            max_depth: 4,
            kind: RootKind::System,
        },
        ScanRoot {
            path: r"C:\ProgramData".into(),
            max_depth: 3,
            kind: RootKind::Config,
        },
        ScanRoot {
            path: r"C:\inetpub".into(),
            max_depth: 5,
            kind: RootKind::Config,
        },
        ScanRoot {
            path: r"C:\Windows\Temp".into(),
            max_depth: 4,
            kind: RootKind::Temp,
        },
        ScanRoot {
            path: r"C:\Temp".into(),
            max_depth: 4,
            kind: RootKind::Temp,
        },
        ScanRoot {
            path: r"C:\PerfLogs".into(),
            max_depth: 3,
            kind: RootKind::Temp,
        },
        ScanRoot {
            path: r"C:\Users\Public".into(),
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

/// Paths never worth descending into: component stores and caches that produce
/// enormous listings without evidence.
pub fn skip_paths() -> &'static [&'static str] {
    &[
        r"C:\Windows\WinSxS",
        r"C:\Windows\Installer",
        r"C:\Windows\SoftwareDistribution",
        r"C:\Windows\servicing",
        r"C:\Windows\assembly",
        r"C:\Windows\System32\DriverStore",
        r"C:\Windows\System32\CatRoot",
        r"C:\Windows\System32\LogFiles",
        r"C:\$Recycle.Bin",
        r"C:\System Volume Information",
        r"\node_modules",
        r"\.git",
        r"\AppData\Local\Microsoft\Windows\INetCache",
        r"\AppData\Local\Packages",
    ]
}

/// System paths that should not contain hidden or stray files.
pub fn critical_directories() -> &'static [&'static str] {
    &[
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\inetpub",
    ]
}

/// Windows has no set-user-id bit; elevation is governed by tokens and ACLs,
/// which are reported through the access control helpers instead.
pub fn is_baseline_suid(_path: &str) -> bool {
    true
}

/// Ownership and permission facts for one file.
///
/// The permission columns a Unix walk fills in are deliberately left neutral
/// here: NTFS access is decided by an ACL, and evaluating one per file across a
/// whole server would take hours. Paths that matter are checked individually
/// through [`writable_permission_issue`].
pub fn file_attributes(
    path: &Path,
    metadata: &fs::Metadata,
    _uid_names: &HashMap<u32, String>,
) -> FileAttributes {
    let attributes = metadata.file_attributes();
    let mut flags = String::new();
    if attributes & ATTRIBUTE_READONLY != 0 {
        flags.push('R');
    }
    if attributes & ATTRIBUTE_HIDDEN != 0 {
        flags.push('H');
    }
    if attributes & ATTRIBUTE_SYSTEM != 0 {
        flags.push('S');
    }
    if attributes & ATTRIBUTE_DIRECTORY != 0 {
        flags.push('D');
    }
    if flags.is_empty() {
        flags.push('-');
    }

    let modified_secs_ago = metadata
        .modified()
        .ok()
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX);

    FileAttributes {
        mode: flags,
        owner: "-".to_string(),
        owner_id: 0,
        // Ownership is a SID here, so the numeric orphan check does not apply
        // and must not produce a finding.
        owner_known: true,
        suid: false,
        sgid: false,
        world_writable: false,
        executable: is_executable(path, attributes),
        size: metadata.len(),
        modified: format_mtime(metadata),
        modified_secs_ago,
    }
}

/// Windows decides executability by extension, not by a permission bit.
fn is_executable(path: &Path, attributes: u32) -> bool {
    if attributes & ATTRIBUTE_DIRECTORY != 0 {
        return false;
    }
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| executable_extensions().contains(&extension.to_lowercase().as_str()))
        .unwrap_or(false)
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
        "exe", "dll", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "scr", "com",
        "pif", "msi", "msp", "hta", "cpl", "jar", "sys", "lnk",
    ]
}

/// Documents whose extension is used as the visible half of a disguise.
pub fn document_extensions() -> &'static [&'static str] {
    &[
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif",
        "mp3", "mp4", "avi", "zip", "rar", "csv", "rtf", "odt",
    ]
}

/// Alternate data streams under a root.
///
/// Enumerating streams costs a call per file, so this runs only over the trees
/// where a hidden payload is plausible and someone could have written it:
/// temporary directories, published web content and user profiles. The system
/// directories are skipped, where legitimate streams such as the zone
/// identifier are both common and uninteresting.
pub fn alternate_data_streams(root: &Path) -> Vec<(String, String)> {
    let path = root.to_string_lossy().to_string();
    let interesting = [
        r"C:\Temp",
        r"C:\Windows\Temp",
        r"C:\inetpub",
        r"C:\Users",
        r"C:\PerfLogs",
    ];
    if !interesting
        .iter()
        .any(|prefix| path.to_lowercase().starts_with(&prefix.to_lowercase()))
    {
        return Vec::new();
    }

    let script = format!(
        "Get-ChildItem -LiteralPath '{path}' -Recurse -Force -File -ErrorAction SilentlyContinue | \
         Select-Object -First 4000 | \
         ForEach-Object {{ Get-Item -LiteralPath $_.FullName -Stream * -ErrorAction SilentlyContinue }} | \
         Where-Object {{ $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }} | \
         ForEach-Object {{ \"$($_.FileName)|$($_.Stream)\" }}"
    );
    ps(&script)
        .map(|text| {
            text.lines()
                .filter_map(|line| fields(line, 2))
                .filter(|parts| !parts[0].is_empty())
                .map(|parts| (parts[0].clone(), parts[1].clone()))
                .collect()
        })
        .unwrap_or_default()
}
