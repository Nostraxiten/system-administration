//! system-administration — local security posture and forensic health scanner.
//!
//! The tool takes no flags and has no subcommands: running the executable
//! walks the operator through language, system confirmation, the full battery
//! of diagnostic modules and finally the report, on screen or on disk.
//!
//! Scope is deliberately narrow and enforced by construction: every collector
//! reads the machine it runs on. There is no remote scanning, no exploitation
//! and no lateral movement anywhere in this program.

mod i18n;
mod modules;
mod platform;
mod report;
mod ui;

use std::time::Instant;

use chrono::Local;

use crate::i18n::fill;
use crate::modules::{run_scanner, ScanContext, Severity};
use crate::platform::detect;
use crate::platform::{human_duration, Family};
use crate::report::{to_folder, to_screen};
use crate::ui::progress::ScanProgress;

fn main() {
    // 1. Banner, painted with a real per-cell gradient.
    let bootstrap = i18n::Language::Spanish.catalog();
    ui::banner::show(bootstrap.ui.tagline, bootstrap.ui.scope_banner);

    // 2. Language. Everything after this point speaks the chosen one.
    let language = ui::language::choose();
    let catalog = language.catalog();
    println!();

    // 3. System detection, confirmed or corrected by the operator.
    let identity = detect::detect();
    let family = identity.family;
    let profile = ui::confirm_system(catalog, identity);

    // 4. Privilege notice: say up front what the scan will and will not see.
    let elevated = detect::is_elevated();
    if elevated {
        println!("  {}", catalog.ui.privilege_full);
    } else if family == Family::Windows {
        println!("  {}", catalog.ui.privilege_admin);
    } else {
        println!("  {}", catalog.ui.privilege_root);
    }
    println!();

    // 5. The full battery of modules.
    println!("  {}", catalog.ui.scan_heading);
    println!();
    let scanners = modules::all();
    let progress = ScanProgress::new(scanners.len());
    let started_at = Local::now();
    let clock = Instant::now();
    let mut reports = Vec::with_capacity(scanners.len());

    for (index, scanner) in scanners.iter().enumerate() {
        progress.start_module(index, scanner.title(catalog), catalog.ui.scan_module_of);
        let context = ScanContext {
            catalog,
            profile: &profile,
            elevated,
            reporter: &progress,
        };
        let report = run_scanner(scanner.as_ref(), &context);
        progress.println(&format!(
            "  {:<38} {}",
            report.title,
            fill(
                catalog.rep.module_totals,
                &[
                    &report.count(Severity::Critical).to_string(),
                    &report.count(Severity::Attention).to_string(),
                    &report.count(Severity::Info).to_string(),
                ]
            )
        ));
        reports.push(report);
        progress.finish_module();
    }

    let duration = clock.elapsed();
    progress.finish();

    let run = report::assemble(profile, language, elevated, started_at, duration, reports);

    println!();
    println!(
        "  {}",
        fill(catalog.ui.scan_finished, &[&human_duration(duration)])
    );
    println!(
        "  {}",
        fill(
            catalog.ui.scan_tally,
            &[
                &run.count(Severity::Critical).to_string(),
                &run.count(Severity::Attention).to_string(),
                &run.count(Severity::Info).to_string(),
            ]
        )
    );
    println!();

    // 6. Reports: to a folder, or paginated on screen.
    match ui::ask_output(catalog) {
        Some((name, path)) => {
            let directory = to_folder::resolve_directory(&name, &path);
            println!("  {}", catalog.ui.saving);
            match to_folder::write(&run, &directory) {
                Ok(written) => {
                    println!(
                        "  {}",
                        fill(
                            catalog.ui.saved_to,
                            &[&written.directory.display().to_string()]
                        )
                    );
                    for file in &written.files {
                        println!("    - {}", file.display());
                    }
                }
                Err(error) => {
                    println!("  {}", fill(catalog.ui.save_failed, &[&error.to_string()]));
                    // Falling back to the screen means the work is never lost
                    // because a path was wrong or a disk was full.
                    to_screen::render(&run);
                }
            }
        }
        None => to_screen::render(&run),
    }

    println!();
    println!("  {}", catalog.ui.farewell);
}
