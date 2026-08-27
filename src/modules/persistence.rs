//! Shells and persistence: what would bring an intruder back after a reboot.

use std::collections::BTreeMap;

use crate::i18n::{fill, Catalog};
use crate::modules::{
    reverse_shell_match, suspicious_command_match, Finding, ModuleReport, ScanContext, Scanner,
};
use crate::platform::{sys, AutostartKind};

pub struct Persistence;

impl Scanner for Persistence {
    fn id(&self) -> &'static str {
        "persistence"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.persistence_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report = ModuleReport::new(
            "persistence",
            c.m.persistence_t,
            c.m.persistence_d,
            c.m.persistence_c,
        );

        // --- pass 1: scheduled tasks ----------------------------------
        ctx.phase(c.f.s_phase_cron);
        let tasks = sys::scheduled_tasks();
        let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
        for task in &tasks {
            *by_kind.entry(task.kind.as_str()).or_default() += 1;
        }
        report.push(
            Finding::info(fill(c.f.s_cron_total, &[&tasks.len().to_string()])).evidence_all(
                tasks.iter().map(|task| {
                    fill(
                        c.f.s_cron_entry,
                        &[&task.owner, &task.schedule, &task.command],
                    )
                }),
            ),
        );

        for task in &tasks {
            if let Some(pattern) = suspicious_command_match(&task.command) {
                let severity_is_shell = reverse_shell_match(&task.command).is_some();
                let finding = if severity_is_shell {
                    Finding::critical(fill(c.f.s_cron_suspicious, &[&task.name]))
                } else {
                    Finding::attention(fill(c.f.s_cron_suspicious, &[&task.name]))
                };
                report.push(
                    finding
                        .detail(fill(
                            c.f.s_cron_suspicious_detail,
                            &[&task.command, pattern],
                        ))
                        .evidence(task.source.clone()),
                );
            }

            // A task that runs a file anyone can rewrite is a scheduled
            // handover of whatever privileges the task runs with.
            let target = task.command.split_whitespace().next().unwrap_or("");
            if target.starts_with('/') && sys::path_is_world_writable(target) {
                report.push(
                    Finding::critical(fill(c.f.s_cron_writable, &[&task.name]))
                        .detail(target.to_string())
                        .evidence(format!("{} · {}", task.owner, task.source)),
                );
            }
        }

        // --- pass 2: services -----------------------------------------
        ctx.phase(c.f.s_phase_services);
        let services = sys::services();
        report.push(Finding::info(fill(
            c.f.s_service_total,
            &[&services.len().to_string()],
        )));

        let volatile = sys::volatile_prefixes();
        for service in &services {
            if !service.vendor_supplied && !service.exec.is_empty() {
                report.push(
                    Finding::attention(fill(c.f.s_service_nonstandard, &[&service.name]))
                        .detail(fill(c.f.s_service_nonstandard_detail, &[&service.exec]))
                        .evidence(format!(
                            "{} · {} · {}",
                            service.state, service.start_mode, service.unit_path
                        )),
                );
            }
            let binary = service.exec.split_whitespace().next().unwrap_or("");
            if !binary.is_empty() && volatile.iter().any(|prefix| binary.starts_with(prefix)) {
                report.push(
                    Finding::critical(fill(c.f.s_service_volatile, &[&service.name]))
                        .detail(service.exec.clone())
                        .evidence(service.unit_path.clone()),
                );
            }
        }

        // --- pass 3: autostart hooks ----------------------------------
        ctx.phase(c.f.s_phase_autostart);
        let autostart = sys::autostart();
        if !autostart.is_empty() {
            report.push(
                Finding::info(fill(c.f.s_autostart_total, &[&autostart.len().to_string()]))
                    .evidence_all(
                        autostart.iter().map(|entry| {
                            fill(c.f.s_autostart_entry, &[&entry.source, &entry.name])
                        }),
                    ),
            );
        }
        for entry in &autostart {
            // Windows hooks get their own wording: "registry run entry" tells
            // an operator where to look, "autostart entry" does not.
            match entry.kind {
                AutostartKind::RunKey => report.push(
                    Finding::info(fill(c.f.s_run_key, &[&entry.name]))
                        .detail(entry.value.clone())
                        .evidence(entry.source.clone()),
                ),
                AutostartKind::StartupFolder => report.push(
                    Finding::info(fill(c.f.s_startup_folder, &[&entry.name]))
                        .detail(entry.value.clone())
                        .evidence(entry.source.clone()),
                ),
                AutostartKind::WmiSubscription => report.push(
                    // A permanent WMI subscription is a persistence mechanism
                    // with no legitimate use on most servers.
                    Finding::attention(fill(c.f.s_wmi_subscription, &[&entry.name]))
                        .detail(entry.value.clone())
                        .evidence(entry.source.clone()),
                ),
                _ => {}
            }

            if let Some(pattern) = suspicious_command_match(&entry.value) {
                report.push(
                    Finding::attention(fill(c.f.s_autostart_suspicious, &[&entry.name]))
                        .detail(fill(c.f.s_cron_suspicious_detail, &[&entry.value, pattern]))
                        .evidence(entry.source.clone()),
                );
            }
            if entry.name == "rc.local" {
                report.push(
                    Finding::info(fill(c.f.s_rc_local, &[&entry.source]))
                        .evidence(entry.value.clone()),
                );
            }
        }

        // --- pass 4: shell configuration and history -------------------
        ctx.phase(c.f.s_phase_history);
        for file in sys::shell_rc_files() {
            let path = file.display().to_string();
            for line in crate::platform::read_lines(&file) {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some(pattern) = reverse_shell_match(trimmed) {
                    report.push(
                        Finding::critical(fill(c.f.s_shellrc_suspicious, &[&path]))
                            .detail(fill(c.f.s_shellrc_detail, &[trimmed]))
                            .evidence(pattern.to_string()),
                    );
                } else if trimmed.to_lowercase().contains("histfile=/dev/null")
                    || trimmed.to_lowercase().contains("unset histfile")
                    || trimmed.to_lowercase().contains("histsize=0")
                {
                    report.push(
                        Finding::attention(fill(c.f.s_history_disabled, &[&path]))
                            .detail(c.f.s_history_disabled_detail)
                            .evidence(trimmed.to_string()),
                    );
                }
            }
        }

        for file in sys::history_files() {
            let path = file.display().to_string();
            if sys::points_to_null(&file) {
                report.push(
                    Finding::attention(fill(c.f.s_history_disabled, &[&path]))
                        .detail(c.f.s_history_disabled_detail)
                        .evidence("-> /dev/null".to_string()),
                );
                continue;
            }
            for line in crate::platform::read_lines(&file) {
                if let Some(pattern) = reverse_shell_match(&line) {
                    report.push(
                        Finding::critical(fill(c.f.s_history_revshell, &[&path]))
                            .detail(fill(c.f.s_history_revshell_detail, &[line.trim()]))
                            .evidence(pattern.to_string()),
                    );
                }
            }
        }

        // --- pass 5: globally preloaded libraries ----------------------
        ctx.phase(c.f.s_phase_preload);
        for (source, contents) in sys::preload_libraries() {
            report.push(
                Finding::critical(fill(c.f.s_preload, &[&source]))
                    .detail(fill(c.f.s_preload_detail, &[&contents])),
            );
        }

        // Authorised keys are persistence as much as they are access.
        for home in sys::home_directories() {
            for (path, keys, _mode) in sys::ssh_authorized_keys(&home.display().to_string()) {
                if keys > 0 {
                    report.push(Finding::info(fill(
                        c.f.s_authorized_keys,
                        &[&path, &keys.to_string()],
                    )));
                }
            }
        }

        if !ctx.elevated {
            report.limit(fill(
                c.f.source_unreadable,
                &[&format!("/var/spool/cron ({})", c.f.needs_privilege)],
            ));
        }

        report
    }
}
