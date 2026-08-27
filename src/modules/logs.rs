//! Authentication logs: brute force, privilege escalation and tampering.

use std::collections::{BTreeMap, BTreeSet};

use crate::i18n::{fill, Catalog};
use crate::modules::{Finding, ModuleReport, ScanContext, Scanner};
use crate::platform::sys;

pub struct Logs;

/// How many failures from one source turn a bad password into a campaign.
const BRUTE_FORCE_THRESHOLD: usize = 10;

/// Lines pulled from each text source. Enough to cover a rotation window
/// without holding a multi-gigabyte log in memory.
const MAX_LINES: usize = 20_000;

/// The token following `from` in an auth log line is the source address.
fn source_address(line: &str) -> Option<String> {
    let mut tokens = line.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if token == "from" {
            let candidate = tokens.peek()?;
            if candidate.contains('.') || candidate.contains(':') {
                return Some((*candidate).to_string());
            }
        }
    }
    None
}

/// The user name an auth line refers to.
fn subject_user(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    for (index, token) in tokens.iter().enumerate() {
        if *token == "for" {
            // `Failed password for invalid user admin from ...`
            let mut offset = index + 1;
            if tokens.get(offset) == Some(&"invalid") {
                offset += 1;
            }
            if tokens.get(offset) == Some(&"user") {
                offset += 1;
            }
            return tokens.get(offset).map(|user| (*user).to_string());
        }
        if let Some(user) = token.strip_prefix("user=") {
            return Some(user.to_string());
        }
    }
    None
}

impl Scanner for Logs {
    fn id(&self) -> &'static str {
        "logs"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.logs_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report = ModuleReport::new("logs", c.m.logs_t, c.m.logs_d, c.m.logs_c);

        // --- pass 1: locate the sources --------------------------------
        ctx.phase(c.f.l_phase_sources);
        let sources = sys::log_sources(MAX_LINES);
        let available: Vec<_> = sources.iter().filter(|source| source.available).collect();
        report.push(
            Finding::info(fill(c.f.l_sources, &[&available.len().to_string()])).evidence_all(
                sources.iter().map(|source| {
                    format!(
                        "{} · {} · {}",
                        source.name,
                        source.path,
                        if source.readable {
                            "ok"
                        } else if source.available {
                            "unreadable"
                        } else {
                            "missing"
                        }
                    )
                }),
            ),
        );

        for source in &sources {
            if !source.available {
                // Only the plain-file sources are expected everywhere; a
                // journald-only host legitimately has no /var/log/secure.
                if source.name == "auth.log" || source.name == "secure" {
                    continue;
                }
                report.push(Finding::info(fill(c.f.l_source_missing, &[&source.path])));
            } else if !source.readable && !ctx.elevated {
                report.limit(fill(
                    c.f.l_source_unreadable,
                    &[&format!("{} ({})", source.path, c.f.needs_privilege)],
                ));
            }
        }

        // A wiped authentication log on a host that has been up for a while is
        // the single strongest tampering signal this module can produce.
        ctx.phase(c.f.l_phase_integrity);
        let uptime_days = ctx.profile.identity.uptime / 86_400;
        for source in &sources {
            if (source.name == "auth.log" || source.name == "secure")
                && source.available
                && source.size == 0
                && uptime_days >= 1
            {
                report.push(
                    Finding::critical(fill(c.f.l_log_truncated, &[&source.path]))
                        .detail(c.f.l_log_truncated_detail)
                        .evidence(format!("uptime {uptime_days}d, size 0")),
                );
            }
        }

        // --- pass 2: authentication events -----------------------------
        ctx.phase(c.f.l_phase_auth);
        let lines: Vec<&String> = sources
            .iter()
            .filter(|source| source.readable)
            .flat_map(|source| source.lines.iter())
            .collect();

        if lines.is_empty() {
            report.limit(fill(c.f.l_source_unreadable, &["auth log"]));
            return report;
        }
        report.push(Finding::info(fill(
            c.f.l_lines_read,
            &[&lines.len().to_string()],
        )));

        let mut failures_by_source: BTreeMap<String, usize> = BTreeMap::new();
        let mut users_by_source: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut accepted_by_source: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut root_logins: BTreeMap<String, usize> = BTreeMap::new();
        let mut total_failures = 0usize;
        let mut total_accepted = 0usize;
        let mut invalid_users = 0usize;
        let mut sudo_uses = 0usize;
        let mut sudo_failures: BTreeSet<String> = BTreeSet::new();
        let mut created_accounts: Vec<String> = Vec::new();
        let mut cleared_logs: Vec<String> = Vec::new();

        for line in &lines {
            let lowered = line.to_lowercase();

            if lowered.contains("failed password")
                || lowered.contains("failed publickey")
                || lowered.contains("authentication failure")
                || lowered.contains("failed none")
            {
                total_failures += 1;
                if let Some(address) = source_address(line) {
                    *failures_by_source.entry(address.clone()).or_default() += 1;
                    if let Some(user) = subject_user(line) {
                        users_by_source.entry(address).or_default().insert(user);
                    }
                }
            }

            if lowered.contains("invalid user") || lowered.contains("illegal user") {
                invalid_users += 1;
            }

            if lowered.contains("accepted password")
                || lowered.contains("accepted publickey")
                || lowered.contains("accepted keyboard-interactive")
            {
                total_accepted += 1;
                let user = subject_user(line).unwrap_or_else(|| "-".to_string());
                if let Some(address) = source_address(line) {
                    accepted_by_source
                        .entry(address.clone())
                        .or_default()
                        .insert(user.clone());
                    if user == "root" || user == "Administrator" {
                        *root_logins.entry(address).or_default() += 1;
                    }
                }
            }

            // --- pass 3 material: privilege escalation -----------------
            if lowered.contains("sudo:") || lowered.contains("pkexec") || lowered.contains("su:") {
                if lowered.contains("command=") || lowered.contains("session opened") {
                    sudo_uses += 1;
                }
                if lowered.contains("authentication failure")
                    || lowered.contains("incorrect password")
                    || lowered.contains("3 incorrect")
                {
                    sudo_failures.insert(subject_user(line).unwrap_or_else(|| "-".to_string()));
                }
            }

            if lowered.contains("new user:")
                || lowered.contains("useradd")
                || lowered.contains("adduser")
                || lowered.contains("new group:")
            {
                created_accounts.push(line.trim().to_string());
            }

            // Windows event 1102 and the systemd/journald equivalents.
            if lowered.contains("the audit log was cleared")
                || lowered.contains("event log was cleared")
                || lowered.contains("1102")
                    && (lowered.contains("eventlog") || lowered.contains("audit"))
            {
                cleared_logs.push(line.trim().to_string());
            }
        }

        report.push(Finding::info(fill(
            c.f.l_failed_total,
            &[&total_failures.to_string()],
        )));
        report.push(Finding::info(fill(
            c.f.l_accepted_total,
            &[&total_accepted.to_string()],
        )));
        if invalid_users > 0 {
            report.push(Finding::info(fill(
                c.f.l_invalid_user,
                &[&invalid_users.to_string()],
            )));
        }

        for (address, count) in &failures_by_source {
            if *count < BRUTE_FORCE_THRESHOLD {
                continue;
            }
            let tried = users_by_source
                .get(address)
                .map(|users| users.iter().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default();

            // Failures alone are noise on any internet-facing host. Failures
            // followed by a success from the same address are an incident.
            if let Some(accepted) = accepted_by_source.get(address) {
                let user = accepted.iter().next().cloned().unwrap_or_default();
                report.push(
                    Finding::critical(fill(c.f.l_bruteforce_success, &[address]))
                        .detail(fill(
                            c.f.l_bruteforce_success_detail,
                            &[&count.to_string(), &user],
                        ))
                        .evidence(tried),
                );
            } else {
                report.push(
                    Finding::critical(fill(c.f.l_bruteforce, &[address, &count.to_string()]))
                        .detail(fill(c.f.l_bruteforce_detail, &[&tried])),
                );
            }
        }

        ctx.phase(c.f.l_phase_escalation);
        for (address, count) in &root_logins {
            report.push(
                Finding::attention(fill(c.f.l_root_login, &[address]))
                    .detail(fill(c.f.l_root_login_detail, &[&count.to_string()])),
            );
        }

        if sudo_uses > 0 {
            report.push(Finding::info(fill(
                c.f.l_sudo_use,
                &[&sudo_uses.to_string()],
            )));
        }
        if !sudo_failures.is_empty() {
            report.push(
                Finding::attention(fill(
                    c.f.l_sudo_failures,
                    &[&sudo_failures.len().to_string()],
                ))
                .detail(fill(
                    c.f.l_sudo_failures_detail,
                    &[&sudo_failures.iter().cloned().collect::<Vec<_>>().join(", ")],
                )),
            );
        }

        for entry in created_accounts.iter().take(20) {
            report.push(
                Finding::attention(fill(c.f.l_account_created, &["-"]))
                    .detail(fill(c.f.l_account_created_detail, &[entry])),
            );
        }

        for entry in cleared_logs.iter().take(10) {
            report.push(
                Finding::critical(fill(c.f.l_log_cleared, &["-"]))
                    .detail(fill(c.f.l_log_cleared_detail, &[entry])),
            );
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_address_is_the_token_after_from() {
        let line =
            "Jan  1 00:00:00 host sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2";
        assert_eq!(source_address(line), Some("203.0.113.9".to_string()));
    }

    #[test]
    fn invalid_user_prefix_is_skipped() {
        let line = "sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 22";
        assert_eq!(subject_user(line), Some("admin".to_string()));
    }

    #[test]
    fn plain_user_is_read_directly() {
        let line = "sshd[1]: Accepted publickey for deploy from 10.0.0.4 port 55000 ssh2";
        assert_eq!(subject_user(line), Some("deploy".to_string()));
    }

    #[test]
    fn a_line_without_a_source_yields_none() {
        assert_eq!(
            source_address("sudo: pam_unix(sudo:auth): auth failure"),
            None
        );
    }
}
