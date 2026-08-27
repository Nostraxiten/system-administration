//! Running processes: what executes, as whom, from where, and at what cost.

use std::collections::{BTreeMap, BTreeSet};

use sysinfo::{ProcessesToUpdate, System, Users as SysUsers};

use crate::i18n::{fill, Catalog};
use crate::modules::{reverse_shell_match, Finding, ModuleReport, ScanContext, Scanner};
use crate::platform::{human_bytes, sys};

pub struct Processes;

/// A process holding more than this share of a core for the whole measurement
/// window is worth naming in the report.
const CPU_ALERT: f32 = 80.0;
/// Same idea for resident memory, as a share of installed RAM.
const MEMORY_ALERT_RATIO: f64 = 0.20;

impl Scanner for Processes {
    fn id(&self) -> &'static str {
        "processes"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.processes_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report = ModuleReport::new(
            "processes",
            c.m.processes_t,
            c.m.processes_d,
            c.m.processes_c,
        );

        // --- pass 1: enumerate, then measure --------------------------
        ctx.phase(c.f.p_phase_enumerate);
        let mut system = System::new_all();
        let users = SysUsers::new_with_refreshed_list();

        // CPU usage is a delta, so a single snapshot always reads zero. The
        // second refresh after the kernel's minimum interval is what turns it
        // into a real measurement.
        ctx.phase(c.f.p_phase_resources);
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        system.refresh_processes(ProcessesToUpdate::All, true);

        let total_memory = system.total_memory().max(1);
        // The scanner runs from wherever it was copied to, so without this it
        // reports itself as a binary outside the system paths on every run.
        let own_pid = std::process::id();
        let own_exe = std::env::current_exe().ok();
        let processes: Vec<_> = system
            .processes()
            .values()
            // Threads carry their own task id and would otherwise be counted
            // and judged as if they were separate processes.
            .filter(|process| process.thread_kind().is_none())
            .filter(|process| {
                process.pid().as_u32() != own_pid && process.exe() != own_exe.as_deref()
            })
            .collect();
        report.push(Finding::info(fill(
            c.f.p_total,
            &[&processes.len().to_string()],
        )));

        let mut owners: BTreeSet<String> = BTreeSet::new();
        let mut no_exe = 0usize;
        let mut per_user: BTreeMap<String, usize> = BTreeMap::new();

        // --- pass 2: binary paths -------------------------------------
        ctx.phase(c.f.p_phase_paths);
        let system_prefixes = sys::system_binary_prefixes();
        let volatile_prefixes = sys::volatile_prefixes();
        let system_names = sys::system_process_names();

        for process in &processes {
            let pid = process.pid().as_u32();
            let name = process.name().to_string_lossy().into_owned();
            let owner = process
                .user_id()
                .and_then(|uid| users.get_user_by_id(uid))
                .map(|user| user.name().to_string())
                .unwrap_or_else(|| "-".to_string());
            owners.insert(owner.clone());
            *per_user.entry(owner.clone()).or_default() += 1;

            let exe = process.exe().map(|path| path.display().to_string());

            // A binary unlinked after starting leaves the process running with
            // nothing left on disk to inspect: the point of the technique.
            if let Some(original) = sys::exe_deleted(pid) {
                report.push(
                    Finding::critical(fill(c.f.p_deleted_binary, &[&pid.to_string(), &name]))
                        .detail(fill(c.f.p_deleted_binary_detail, &[&original]))
                        .evidence(format!("user={owner}")),
                );
                continue;
            }

            let Some(exe) = exe else {
                no_exe += 1;
                continue;
            };

            if volatile_prefixes
                .iter()
                .any(|prefix| exe.starts_with(prefix) && !exe.starts_with("/home/"))
            {
                report.push(
                    Finding::critical(fill(c.f.p_volatile_path, &[&pid.to_string(), &name]))
                        .detail(fill(c.f.p_volatile_path_detail, &[&exe]))
                        .evidence(format!("user={owner}")),
                );
            } else if !system_prefixes.iter().any(|prefix| exe.starts_with(prefix)) {
                report.push(
                    Finding::attention(fill(c.f.p_unusual_path, &[&pid.to_string(), &name]))
                        .detail(fill(c.f.p_unusual_path_detail, &[&exe]))
                        .evidence(format!("user={owner}")),
                );
            }

            // A process called `sshd` running out of a user's home is not sshd.
            if system_names.contains(&name.as_str())
                && !system_prefixes.iter().any(|prefix| exe.starts_with(prefix))
            {
                report.push(
                    Finding::critical(fill(c.f.p_masquerade, &[&pid.to_string(), &name]))
                        .detail(fill(c.f.p_masquerade_detail, &[&exe])),
                );
            }

            let command = process
                .cmd()
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            if let Some(pattern) = reverse_shell_match(&command) {
                report.push(
                    Finding::critical(fill(c.f.p_revshell_cmdline, &[&pid.to_string(), &name]))
                        .detail(fill(c.f.p_revshell_cmdline_detail, &[pattern]))
                        .evidence(command.clone()),
                );
            }
        }

        report.push(
            Finding::info(fill(c.f.p_by_user, &[&owners.len().to_string()])).evidence_all(
                per_user
                    .iter()
                    .map(|(user, count)| format!("{user}: {count}")),
            ),
        );
        if no_exe > 0 {
            report.push(Finding::info(fill(c.f.p_no_exe, &[&no_exe.to_string()])));
        }

        // --- pass 3: lineage ------------------------------------------
        ctx.phase(c.f.p_phase_lineage);
        for process in &processes {
            let pid = process.pid().as_u32();
            if pid <= 2 {
                continue;
            }
            let orphaned = process
                .parent()
                .map(|parent| !system.processes().contains_key(&parent))
                .unwrap_or(true);
            let root_owned = process
                .user_id()
                .and_then(|uid| users.get_user_by_id(uid))
                .map(|user| user.name() == "root" || user.name() == "SYSTEM")
                .unwrap_or(false);
            if orphaned && root_owned {
                report.push(Finding::info(fill(
                    c.f.p_orphan_root,
                    &[&pid.to_string(), &process.name().to_string_lossy()],
                )));
            }
        }

        // --- pass 4: resource outliers --------------------------------
        for process in &processes {
            let cpu = process.cpu_usage();
            if cpu >= CPU_ALERT {
                report.push(Finding::attention(fill(
                    c.f.p_high_cpu,
                    &[
                        &process.pid().as_u32().to_string(),
                        &process.name().to_string_lossy(),
                        &format!("{cpu:.0}"),
                    ],
                )));
            }
            let memory = process.memory();
            if (memory as f64 / total_memory as f64) >= MEMORY_ALERT_RATIO {
                report.push(Finding::attention(fill(
                    c.f.p_high_mem,
                    &[
                        &process.pid().as_u32().to_string(),
                        &process.name().to_string_lossy(),
                        &human_bytes(memory),
                    ],
                )));
            }
        }

        // --- pass 5: processes hiding from the standard listing --------
        ctx.phase(c.f.p_phase_hidden);
        for pid in sys::hidden_pids() {
            report.push(
                Finding::critical(fill(c.f.p_hidden_pid, &[&pid.to_string()]))
                    .detail(c.f.p_hidden_pid_detail),
            );
        }

        // Processes owning a listening socket, correlated with the network view.
        let listeners: BTreeSet<String> = sys::sockets()
            .into_iter()
            .filter(|socket| socket.state == "LISTEN")
            .filter_map(|socket| socket.process)
            .collect();
        if !listeners.is_empty() {
            report.push(
                Finding::info(fill(c.f.p_listener_procs, &[&listeners.len().to_string()]))
                    .evidence_all(listeners),
            );
        }

        if !ctx.elevated {
            report.limit(fill(
                c.f.source_unreadable,
                &[&format!("/proc/*/exe ({})", c.f.needs_privilege)],
            ));
        }

        report
    }
}
