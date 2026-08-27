//! System users: who exists, what they can do, and when they last did it.

use std::collections::BTreeMap;

use crate::i18n::{fill, Catalog};
use crate::modules::{Finding, ModuleReport, ScanContext, Scanner};
use crate::platform::{sys, PasswordState};

pub struct Users;

/// Accounts whose UID 0 is legitimate.
const EXPECTED_ROOT_NAMES: &[&str] = &["root", "Administrator", "toor"];

impl Scanner for Users {
    fn id(&self) -> &'static str {
        "users"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.users_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report = ModuleReport::new("users", c.m.users_t, c.m.users_d, c.m.users_c);

        // --- pass 1: the account table --------------------------------
        ctx.phase(c.f.u_phase_accounts);
        let accounts = sys::users();
        if accounts.is_empty() {
            report.limit(fill(c.f.source_unreadable, &["/etc/passwd"]));
            return report;
        }

        let interactive: Vec<_> = accounts.iter().filter(|a| a.interactive).collect();
        report.push(
            Finding::info(fill(c.f.u_total, &[&accounts.len().to_string()]))
                .detail(fill(c.f.u_interactive, &[&interactive.len().to_string()]))
                .evidence_all(accounts.iter().map(|account| {
                    fill(
                        c.f.u_shell_list,
                        &[
                            &account.name,
                            &format!("{}:{}", account.uid, account.gid),
                            &account.shell,
                        ],
                    )
                })),
        );

        // Duplicate UIDs make two accounts indistinguishable for auditing.
        let mut by_uid: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for account in &accounts {
            by_uid
                .entry(account.uid.as_str())
                .or_default()
                .push(account.name.as_str());
        }
        for (uid, names) in &by_uid {
            if names.len() > 1 {
                report.push(
                    Finding::attention(fill(c.f.u_dup_uid, &[uid, &names.join(", ")]))
                        .detail(c.f.u_dup_uid_detail),
                );
            }
        }

        // Key-based access makes a locked password the recommended state, so
        // the two facts have to be read together rather than separately.
        let reachable_by_key: std::collections::HashSet<String> = accounts
            .iter()
            .filter(|account| {
                sys::ssh_authorized_keys(&account.home)
                    .iter()
                    .any(|(_, keys, _)| *keys > 0)
            })
            .map(|account| account.name.clone())
            .collect();

        // --- pass 2: privileges ---------------------------------------
        ctx.phase(c.f.u_phase_privileges);
        for account in &accounts {
            if account.uid == "0" && !EXPECTED_ROOT_NAMES.contains(&account.name.as_str()) {
                report.push(
                    Finding::critical(fill(c.f.u_uid0, &[&account.name]))
                        .detail(c.f.u_uid0_detail)
                        .evidence(format!(
                            "{}:{}:{}",
                            account.name, account.uid, account.shell
                        )),
                );
            }

            match account.password_state {
                PasswordState::Empty => report.push(
                    Finding::critical(fill(c.f.u_nopass, &[&account.name]))
                        .detail(c.f.u_nopass_detail),
                ),
                // A locked password plus an authorised key is how a hardened
                // server is meant to look; only a shell nobody can reach at all
                // is a leftover worth removing.
                // Root and anyone with elevation rights uses that shell after
                // `sudo`, and service accounts are entered with `sudo -u`, so
                // for them a locked password is the intended configuration.
                // What is left is a human account someone locked but never
                // finished retiring.
                PasswordState::Locked
                    if account.interactive
                        && !reachable_by_key.contains(&account.name)
                        && !account.privileged
                        && account.uid.parse::<u32>().is_ok_and(|uid| uid >= 1000) =>
                {
                    report.push(
                        Finding::attention(fill(c.f.u_locked_shell, &[&account.name]))
                            .detail(c.f.u_locked_shell_detail)
                            .evidence(account.shell.clone()),
                    )
                }
                _ => {}
            }

            if account.password_never_expires && account.privileged {
                report.push(Finding::attention(fill(
                    c.f.u_pw_never_expires,
                    &[&account.name],
                )));
            }

            if account.privileged && !EXPECTED_ROOT_NAMES.contains(&account.name.as_str()) {
                report.push(
                    Finding::info(fill(c.f.u_admin, &[&account.name]))
                        .detail(fill(
                            c.f.u_admin_detail,
                            &[&account.privilege_source.join(", ")],
                        ))
                        .evidence(account.groups.join(", ")),
                );
            }

            if !account.enabled && account.name.to_lowercase().contains("guest") {
                continue;
            }
            if account.enabled && account.name.to_lowercase() == "guest" {
                report.push(Finding::attention(fill(
                    c.f.u_guest_enabled,
                    &[&account.name],
                )));
            }
        }

        if !ctx.elevated {
            report.limit(fill(
                c.f.source_unreadable,
                &[&format!("/etc/shadow ({})", c.f.needs_privilege)],
            ));
        }

        for rule in sys::sudo_rules() {
            report.push(
                Finding::attention(fill(c.f.u_sudo_nopasswd, &[&rule.rule]))
                    .detail(c.f.u_sudo_nopasswd_detail)
                    .evidence(rule.source),
            );
        }

        // --- pass 3: login activity -----------------------------------
        ctx.phase(c.f.u_phase_logins);
        let mut login_lines = Vec::new();
        for account in &accounts {
            match &account.last_login {
                Some(when) => login_lines.push(fill(c.f.u_last_login, &[&account.name, when])),
                None => {
                    login_lines.push(fill(c.f.u_never_logged, &[&account.name]));
                    // An account nobody uses but anybody could use is surface
                    // area with no upside.
                    if account.interactive
                        && account.password_state != PasswordState::Locked
                        && !EXPECTED_ROOT_NAMES.contains(&account.name.as_str())
                    {
                        report.push(
                            Finding::attention(fill(c.f.u_dormant, &[&account.name]))
                                .detail(c.f.u_dormant_detail)
                                .evidence(format!("shell={} home={}", account.shell, account.home)),
                        );
                    }
                }
            }
        }
        if !login_lines.is_empty() {
            report.push(
                Finding::info(fill(c.f.u_login_summary, &[&login_lines.len().to_string()]))
                    .evidence_all(login_lines),
            );
        }

        // --- pass 4: authorised SSH keys ------------------------------
        ctx.phase(c.f.u_phase_keys);
        for account in &accounts {
            for (path, keys, mode) in sys::ssh_authorized_keys(&account.home) {
                if keys > 0 {
                    report.push(
                        Finding::info(fill(c.f.u_ssh_keys, &[&account.name, &keys.to_string()]))
                            .detail(c.f.u_ssh_keys_detail)
                            .evidence(path.clone()),
                    );
                }
                // 0600 is the only permission set that keeps a key file
                // private; anything looser lets another account add its own.
                let numeric = u32::from_str_radix(&mode, 8).unwrap_or(0);
                if numeric & 0o077 != 0 {
                    report.push(Finding::attention(fill(
                        c.f.u_ssh_key_perm,
                        &[&path, &mode],
                    )));
                }
            }
        }

        // --- pass 5: home directories ---------------------------------
        ctx.phase(c.f.u_phase_homes);
        for account in &accounts {
            if account.home.is_empty() || account.home == "/" || account.home == "/nonexistent" {
                continue;
            }
            if !sys::directory_exists(&account.home) {
                if account.interactive {
                    report.push(Finding::info(fill(c.f.u_home_missing, &[&account.name])));
                }
                continue;
            }
            if let Some(mode) = sys::home_permission_issue(&account.home, &account.uid) {
                report.push(
                    Finding::attention(fill(c.f.u_home_loose, &[&account.home]))
                        .detail(fill(c.f.u_home_loose_detail, &[&mode])),
                );
            }
        }

        report
    }
}
