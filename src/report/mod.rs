//! Report assembly.
//!
//! The same text is produced for the screen and for the files on disk; only
//! the presentation differs, so a report read in the terminal and one opened
//! from the output folder say exactly the same thing.

pub mod to_folder;
pub mod to_screen;

use std::time::Duration;

use chrono::{DateTime, Local};

use crate::i18n::{fill, Catalog, Language};
use crate::modules::{Finding, ModuleReport, Severity};
use crate::platform::{detect::SystemProfile, human_duration, human_uptime, sys};

/// Version stamped into every report.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Everything one execution produced.
pub struct ScanRun {
    pub started: DateTime<Local>,
    pub duration: Duration,
    pub profile: SystemProfile,
    pub language: Language,
    pub elevated: bool,
    pub operator: String,
    pub modules: Vec<ModuleReport>,
}

/// A finding together with the module it came from, for the summary.
pub struct AttributedFinding<'a> {
    pub module: &'a str,
    pub finding: &'a Finding,
}

impl ScanRun {
    pub fn catalog(&self) -> &'static Catalog {
        self.language.catalog()
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.modules
            .iter()
            .map(|module| module.count(severity))
            .sum()
    }

    /// Critical first, then attention, each in module order. This is the list
    /// a sysadmin in a hurry reads instead of the whole dump.
    pub fn priority_findings(&self) -> Vec<AttributedFinding<'_>> {
        let mut findings = Vec::new();
        for severity in [Severity::Critical, Severity::Attention] {
            for module in &self.modules {
                for finding in &module.findings {
                    if finding.severity == severity {
                        findings.push(AttributedFinding {
                            module: &module.title,
                            finding,
                        });
                    }
                }
            }
        }
        findings
    }

    /// The header block shared by the screen output and every file.
    pub fn header_lines(&self) -> Vec<(String, String)> {
        let c = self.catalog();
        let identity = &self.profile.identity;
        let mut lines = vec![
            (
                c.ui.label_date.to_string(),
                self.started.format("%Y-%m-%d %H:%M:%S %:z").to_string(),
            ),
            (c.ui.label_host.to_string(), identity.hostname.clone()),
            (c.ui.label_system.to_string(), identity.label()),
            (
                c.ui.label_profile.to_string(),
                format!(
                    "{} ({})",
                    self.profile.label,
                    if self.profile.auto_confirmed {
                        c.ui.profile_auto
                    } else {
                        c.ui.profile_manual
                    }
                ),
            ),
            (c.ui.label_kernel.to_string(), identity.kernel.clone()),
            (c.ui.label_arch.to_string(), identity.arch.clone()),
            (c.ui.label_uptime.to_string(), human_uptime(identity.uptime)),
            (
                c.ui.label_operator.to_string(),
                format!(
                    "{} ({})",
                    self.operator,
                    if self.elevated {
                        c.ui.privilege_tag_full
                    } else {
                        c.ui.privilege_tag_limited
                    }
                ),
            ),
            (
                c.ui.label_duration.to_string(),
                human_duration(self.duration),
            ),
        ];
        if let Some(manager) = &identity.package_manager {
            lines.push((c.ui.label_packages.to_string(), manager.clone()));
        }
        if let Some(init) = &identity.init_system {
            lines.push((c.ui.label_init.to_string(), init.clone()));
        }
        lines
    }

    /// The totals line.
    pub fn totals_line(&self) -> String {
        fill(
            self.catalog().rep.totals,
            &[
                &self.count(Severity::Critical).to_string(),
                &self.count(Severity::Attention).to_string(),
                &self.count(Severity::Info).to_string(),
            ],
        )
    }
}

/// Build the run metadata around a set of module reports.
pub fn assemble(
    profile: SystemProfile,
    language: Language,
    elevated: bool,
    started: DateTime<Local>,
    duration: Duration,
    modules: Vec<ModuleReport>,
) -> ScanRun {
    ScanRun {
        started,
        duration,
        profile,
        language,
        elevated,
        operator: sys::current_user(),
        modules,
    }
}

// ---------------------------------------------------------------------------
// Plain text rendering, shared by both outputs.
// ---------------------------------------------------------------------------

/// Width used for the rules that separate sections.
pub const WIDTH: usize = 78;

pub fn rule(character: char) -> String {
    character.to_string().repeat(WIDTH)
}

/// A centred, ruled heading.
pub fn heading(text: &str) -> String {
    let mut out = String::new();
    out.push_str(&rule('='));
    out.push('\n');
    let padding = WIDTH.saturating_sub(text.chars().count()) / 2;
    out.push_str(&" ".repeat(padding));
    out.push_str(text);
    out.push('\n');
    out.push_str(&rule('='));
    out
}

/// One finding as plain text, indented under its severity tag.
pub fn finding_block(finding: &Finding, catalog: &Catalog, show_evidence: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "[{}] {}\n",
        finding.severity.label(catalog),
        finding.title
    ));
    if !finding.detail.is_empty() {
        for line in finding.detail.lines() {
            out.push_str(&format!("      {line}\n"));
        }
    }
    if show_evidence && !finding.evidence.is_empty() {
        out.push_str(&format!("      {}:\n", catalog.rep.evidence));
        for line in &finding.evidence {
            out.push_str(&format!("        - {line}\n"));
        }
    }
    out
}

/// A whole module as plain text.
pub fn module_block(module: &ModuleReport, catalog: &Catalog, show_evidence: bool) -> String {
    let mut out = String::new();
    out.push_str(&heading(&module.title.to_uppercase()));
    out.push('\n');
    out.push_str(&module.description);
    out.push_str("\n\n");

    out.push_str(&format!("{}:\n", catalog.rep.checked));
    for line in &module.checked {
        out.push_str(&format!("  - {line}\n"));
    }
    out.push('\n');

    if !module.limitations.is_empty() {
        out.push_str(&format!("{}:\n", catalog.rep.partial));
        for reason in &module.limitations {
            out.push_str(&format!(
                "  - {}\n",
                fill(catalog.rep.partial_reason, &[reason])
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!("{}:\n", catalog.rep.found));
    if module.findings.is_empty() {
        out.push_str(&format!("  {}\n", catalog.rep.no_findings));
    } else {
        for finding in module.sorted() {
            out.push_str(&finding_block(finding, catalog, show_evidence));
            out.push('\n');
        }
    }

    out.push_str(&format!(
        "{}\n",
        fill(
            catalog.rep.module_totals,
            &[
                &module.count(Severity::Critical).to_string(),
                &module.count(Severity::Attention).to_string(),
                &module.count(Severity::Info).to_string(),
            ]
        )
    ));
    out.push_str(&fill(
        catalog.rep.duration_module,
        &[&human_duration(module.duration)],
    ));
    out.push('\n');
    out
}

/// The executive summary as plain text.
pub fn summary_block(run: &ScanRun) -> String {
    let c = run.catalog();
    let mut out = String::new();
    out.push_str(&heading(c.rep.title));
    out.push_str("\n\n");

    let width = run
        .header_lines()
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    for (label, value) in run.header_lines() {
        out.push_str(&format!("  {label:<width$} : {value}\n"));
    }
    out.push('\n');
    out.push_str(&format!("  {}\n", c.rep.scope_note));
    out.push('\n');

    out.push_str(&heading(c.rep.summary_title));
    out.push_str("\n\n");
    out.push_str(&format!("  {}\n\n", run.totals_line()));

    out.push_str(&format!("{}:\n", c.rep.module_index));
    for (index, module) in run.modules.iter().enumerate() {
        out.push_str(&format!(
            "  {:>2}. {:<34} {}\n",
            index + 1,
            module.title,
            fill(
                c.rep.module_totals,
                &[
                    &module.count(Severity::Critical).to_string(),
                    &module.count(Severity::Attention).to_string(),
                    &module.count(Severity::Info).to_string(),
                ]
            )
        ));
    }
    out.push('\n');

    out.push_str(&heading(c.rep.priority_title));
    out.push_str("\n\n");
    let priority = run.priority_findings();
    if priority.is_empty() {
        out.push_str(&format!("  {}\n", c.rep.priority_empty));
    } else {
        for item in priority {
            out.push_str(&format!(
                "[{}] {} · {}\n",
                item.finding.severity.label(c),
                item.module,
                item.finding.title
            ));
            if !item.finding.detail.is_empty() {
                for line in item.finding.detail.lines() {
                    out.push_str(&format!("      {line}\n"));
                }
            }
            out.push('\n');
        }
    }

    out.push_str(&rule('-'));
    out.push('\n');
    out.push_str(&fill(c.rep.generated_by, &[VERSION]));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::Finding;
    use crate::platform::{Family, OsIdentity};

    fn identity() -> OsIdentity {
        OsIdentity {
            family: Family::Linux,
            id: "ubuntu".into(),
            name: "Ubuntu 24.04 LTS".into(),
            version: "24.04".into(),
            kernel: "6.8.0-31-generic".into(),
            hostname: "server01".into(),
            arch: "x86_64".into(),
            package_manager: Some("apt/dpkg".into()),
            init_system: Some("systemd".into()),
            uptime: 90_061,
            evidence: vec!["/etc/os-release: present".into()],
        }
    }

    fn run_with(language: Language) -> ScanRun {
        let mut users = ModuleReport::new(
            "users",
            "Usuarios",
            "Cuentas y privilegios.",
            &["Inventario de cuentas"],
        );
        users.push(Finding::critical("Cuenta con UID 0").detail("Puerta trasera clásica."));
        users.push(Finding::info("Cuentas: 12"));

        let mut network = ModuleReport::new("network", "Red", "Puertos.", &["Puertos en escucha"]);
        network.push(Finding::attention("Puerto 23 expuesto"));
        network.limit("privilegios insuficientes");

        ScanRun {
            started: Local::now(),
            duration: Duration::from_secs(12),
            profile: SystemProfile::from_detection(identity()),
            language,
            elevated: true,
            operator: "root".into(),
            modules: vec![users, network],
        }
    }

    #[test]
    fn totals_add_up_across_modules() {
        let run = run_with(Language::Spanish);
        assert_eq!(run.count(Severity::Critical), 1);
        assert_eq!(run.count(Severity::Attention), 1);
        assert_eq!(run.count(Severity::Info), 1);
    }

    #[test]
    fn priority_findings_lead_with_the_critical_one() {
        let run = run_with(Language::Spanish);
        let priority = run.priority_findings();
        assert_eq!(
            priority.len(),
            2,
            "info findings must stay out of the summary"
        );
        assert_eq!(priority[0].finding.severity, Severity::Critical);
        assert_eq!(priority[1].finding.severity, Severity::Attention);
    }

    #[test]
    fn the_summary_is_written_in_the_chosen_language() {
        let spanish = summary_block(&run_with(Language::Spanish));
        assert!(spanish.contains("INFORME DE DIAGNÓSTICO DEL SISTEMA"));
        assert!(spanish.contains("HALLAZGOS PRIORITARIOS"));
        assert!(spanish.contains("[CRÍTICO]"));

        let english = summary_block(&run_with(Language::English));
        assert!(english.contains("SYSTEM DIAGNOSTICS REPORT"));
        assert!(english.contains("PRIORITY FINDINGS"));
        assert!(english.contains("[CRITICAL]"));
        assert!(
            !english.contains("HALLAZGOS"),
            "an English report must not leak Spanish chrome"
        );
    }

    #[test]
    fn the_header_reports_the_machine_it_ran_on() {
        let summary = summary_block(&run_with(Language::English));
        assert!(summary.contains("server01"));
        assert!(summary.contains("6.8.0-31-generic"));
        assert!(summary.contains("apt/dpkg"));
        // 90_061 seconds is one day, one hour and one minute.
        assert!(summary.contains("1d 1h 1m"));
    }

    #[test]
    fn a_module_block_states_what_it_checked_and_what_it_could_not() {
        let run = run_with(Language::English);
        let block = module_block(&run.modules[1], run.catalog(), true);
        assert!(block.contains("What was checked"));
        assert!(block.contains("Puertos en escucha"));
        assert!(block.contains("Partial data"));
        assert!(block.contains("privilegios insuficientes"));
    }

    #[test]
    fn a_module_with_nothing_to_report_still_says_so() {
        let empty = ModuleReport::new("web", "Web", "HTTP.", &["Servers running"]);
        let block = module_block(&empty, Language::English.catalog(), true);
        assert!(block.contains("Nothing of note in this module."));
        assert!(block.contains("Servers running"));
    }
}
