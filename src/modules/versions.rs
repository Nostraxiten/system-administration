//! Version checker: kernel, distribution and packages matched against a local
//! database.
//!
//! The database is compiled into the binary, so the check works on an isolated
//! network with no external service involved. An operator who wants fresher
//! data drops an updated file next to the executable or points
//! `SYSADM_VULN_DB` at one, and those records take precedence.

use std::cmp::Ordering;
use std::path::PathBuf;

use crate::i18n::{fill, Catalog};
use crate::modules::{Finding, ModuleReport, ScanContext, Scanner};
use crate::platform::{read_file, sys};

pub struct Versions;

/// The database shipped with the binary.
const BUILTIN_DB: &str = include_str!("../../data/vuln-db.txt");

/// Environment variable pointing at a replacement database.
const DB_ENV: &str = "SYSADM_VULN_DB";

/// File name looked up next to the executable.
const DB_FILE: &str = "vuln-db.txt";

#[derive(Clone, Debug)]
struct Record {
    kind: String,
    product: String,
    /// First version that is not affected.
    fixed_in: String,
    /// First affected version, when the flaw only exists in a range.
    ///
    /// Without this, a stable branch that never carried the flaw is reported
    /// simply for being numerically older than the fix. The xz backdoor is the
    /// clearest case: 5.6.0 and 5.6.1 were backdoored, 5.4.5 never was, and it
    /// is 5.4.5 that distributions shipped as the remedy.
    introduced: Option<String>,
    severity: String,
    id: String,
    description: String,
}

fn parse_db(text: &str) -> Vec<Record> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let fields: Vec<&str> = line.splitn(6, '|').collect();
            if fields.len() != 6 {
                return None;
            }
            // `A..B` is the affected range; a bare `B` means everything below B.
            let (introduced, fixed_in) = match fields[2].trim().split_once("..") {
                Some((from, to)) => (Some(from.trim().to_string()), to.trim().to_string()),
                None => (None, fields[2].trim().to_string()),
            };
            Some(Record {
                kind: fields[0].trim().to_lowercase(),
                product: fields[1].trim().to_lowercase(),
                fixed_in,
                introduced,
                severity: fields[3].trim().to_lowercase(),
                id: fields[4].trim().to_string(),
                description: fields[5].trim().to_string(),
            })
        })
        .collect()
}

/// Strip distribution packaging from a version so it can be compared with the
/// upstream number in the database: `1:8.9p1-3ubuntu0.6` becomes `8.9p1`.
///
/// Debian and Ubuntu mark a deliberate downgrade with `+really<version>`, which
/// is exactly how the xz backdoor was withdrawn: `5.6.1+really5.4.5` ships
/// upstream 5.4.5 while keeping a version string that sorts above the pulled
/// release. Reading the literal `5.6.1` there reports a critical finding on a
/// machine that was patched, so the part after `+really` wins.
fn upstream_version(raw: &str) -> String {
    let without_epoch = raw.split_once(':').map(|(_, rest)| rest).unwrap_or(raw);
    // The Debian revision is everything after the final hyphen.
    let without_revision = without_epoch
        .rsplit_once('-')
        .map(|(head, _)| head)
        .unwrap_or(without_epoch);
    let effective = without_revision
        .rsplit_once("+really")
        .map(|(_, real)| real)
        .unwrap_or(without_revision);
    effective.trim().to_string()
}

/// Split a version into numeric components plus a trailing suffix, so `8.9p1`
/// compares as `[8, 9]` with suffix `p1`.
fn version_parts(version: &str) -> (Vec<u64>, String) {
    let mut numbers = Vec::new();
    let mut suffix = String::new();
    for component in version.split(['.', '_', '+']) {
        let digits: String = component.chars().take_while(char::is_ascii_digit).collect();
        let rest: String = component.chars().skip(digits.len()).collect();
        if digits.is_empty() {
            suffix.push_str(component);
            break;
        }
        numbers.push(digits.parse::<u64>().unwrap_or(0));
        if !rest.is_empty() {
            suffix = rest;
            break;
        }
    }
    (numbers, suffix)
}

/// Compare two upstream version strings.
fn compare_versions(left: &str, right: &str) -> Ordering {
    let (left_numbers, left_suffix) = version_parts(left);
    let (right_numbers, right_suffix) = version_parts(right);
    let length = left_numbers.len().max(right_numbers.len());
    for index in 0..length {
        let a = left_numbers.get(index).copied().unwrap_or(0);
        let b = right_numbers.get(index).copied().unwrap_or(0);
        match a.cmp(&b) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    suffix_rank(&left_suffix).cmp(&suffix_rank(&right_suffix))
}

/// Order a version suffix against a plain release.
///
/// Pre-release markers sort below the bare release, everything else (`p1`,
/// `patch2`) sorts above it, which is how upstream projects number them.
fn suffix_rank(suffix: &str) -> (u8, String) {
    let lowered = suffix.to_lowercase();
    if lowered.is_empty() {
        return (1, String::new());
    }
    // A leading tilde is Debian's explicit "sorts before everything" marker.
    if lowered.starts_with('~') {
        return (0, lowered);
    }
    const PRERELEASE: &[&str] = &["rc", "alpha", "beta", "pre", "dev", "a", "b"];
    if PRERELEASE.iter().any(|marker| lowered.starts_with(marker)) {
        (0, lowered)
    } else {
        (2, lowered)
    }
}

/// True when `installed` falls inside a record's affected range.
fn is_affected(installed: &str, record: &Record) -> bool {
    let installed = upstream_version(installed);
    if installed.is_empty() {
        return false;
    }
    if compare_versions(&installed, &record.fixed_in) != Ordering::Less {
        return false;
    }
    match &record.introduced {
        Some(from) => compare_versions(&installed, from) != Ordering::Less,
        None => true,
    }
}

/// Pull a version number out of a free-form banner such as
/// `OpenSSH_9.6p1, OpenSSL 3.0.13 30 Jan 2024`.
fn version_from_banner(banner: &str) -> Option<String> {
    let mut current = String::new();
    for character in banner.chars() {
        // A dot or a portable-release `p` continues a number already started;
        // anything else ends it.
        let continues = character.is_ascii_digit()
            || ((character == '.' || character == 'p') && !current.is_empty());
        if continues {
            current.push(character);
        } else if !current.is_empty() {
            if current.contains('.') {
                return Some(current.trim_end_matches(['.', 'p']).to_string());
            }
            current.clear();
        }
    }
    (current.contains('.')).then(|| current.trim_end_matches(['.', 'p']).to_string())
}

/// Load the built-in database plus any external override.
fn load_database() -> (Vec<Record>, Option<String>) {
    let mut records = parse_db(BUILTIN_DB);

    let mut external_path: Option<PathBuf> = std::env::var_os(DB_ENV).map(PathBuf::from);
    if external_path.is_none() {
        if let Ok(executable) = std::env::current_exe() {
            if let Some(directory) = executable.parent() {
                let candidate = directory.join(DB_FILE);
                if candidate.is_file() {
                    external_path = Some(candidate);
                }
            }
        }
    }

    let Some(path) = external_path else {
        return (records, None);
    };
    let Some(text) = read_file(&path) else {
        return (records, None);
    };
    let external = parse_db(&text);
    let count = external.len();
    // External records win over built-in ones for the same product and id.
    for record in external {
        records
            .retain(|existing| !(existing.product == record.product && existing.id == record.id));
        records.push(record);
    }
    (records, Some(format!("{}|{count}", path.display())))
}

impl Scanner for Versions {
    fn id(&self) -> &'static str {
        "versions"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.versions_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report =
            ModuleReport::new("versions", c.m.versions_t, c.m.versions_d, c.m.versions_c);
        report.push(Finding::info(c.f.v_offline_note));
        report.push(Finding::info(c.f.v_backport_note));

        // --- pass 1: kernel and distribution ---------------------------
        ctx.phase(c.f.v_phase_kernel);
        let identity = &ctx.profile.identity;
        report.push(Finding::info(fill(c.f.v_kernel, &[&identity.kernel])));
        report.push(Finding::info(fill(c.f.v_os_release, &[&identity.label()])));

        let (database, external) = load_database();
        match &external {
            Some(info) => {
                let (path, count) = info.split_once('|').unwrap_or((info.as_str(), "0"));
                report.push(Finding::info(fill(c.f.v_db_external, &[path, count])));
            }
            None => report.push(Finding::info(c.f.v_db_missing)),
        }
        report.push(Finding::info(fill(
            c.f.v_db_loaded,
            &[&database.len().to_string()],
        )));

        // Distribution support status.
        for record in database.iter().filter(|record| record.kind == "os") {
            let matches_id = identity.id.to_lowercase() == record.product
                || ctx.profile.id.to_lowercase() == record.product
                || identity
                    .name
                    .to_lowercase()
                    .replace(' ', "-")
                    .contains(&record.product);
            if !matches_id {
                continue;
            }
            let affected =
                identity.version == record.fixed_in || is_affected(&identity.version, record);
            if affected {
                let finding = if record.severity == "critical" {
                    Finding::critical(fill(c.f.v_os_eol, &[&identity.label()]))
                } else {
                    Finding::attention(fill(c.f.v_os_eol, &[&identity.label()]))
                };
                report.push(
                    finding
                        .detail(fill(c.f.v_os_eol_detail, &[&record.description]))
                        .evidence(record.id.clone()),
                );
            }
        }

        // Kernel records are matched against the running kernel release.
        for record in database
            .iter()
            .filter(|record| record.kind == "svc" && record.product == "kernel")
        {
            if is_affected(&identity.kernel, record) {
                let finding = if record.severity == "critical" {
                    Finding::critical(fill(c.f.v_match, &["kernel", &identity.kernel, &record.id]))
                } else {
                    Finding::attention(fill(c.f.v_match, &["kernel", &identity.kernel, &record.id]))
                };
                report.push(finding.detail(fill(
                    c.f.v_match_detail,
                    &[&record.description, &record.fixed_in],
                )));
            }
        }

        // --- pass 2: package inventory ---------------------------------
        ctx.phase(c.f.v_phase_inventory);
        let (packages, manager) = sys::packages();
        if packages.is_empty() {
            report.limit(fill(c.f.source_unreadable, &["package manager"]));
        } else {
            report.push(Finding::info(fill(
                c.f.v_inventory,
                &[&packages.len().to_string(), &manager],
            )));
        }

        // --- pass 3: match --------------------------------------------
        ctx.phase(c.f.v_phase_match);
        for record in database.iter().filter(|record| record.kind == "pkg") {
            for package in &packages {
                if package.name.to_lowercase() != record.product {
                    continue;
                }
                if !is_affected(&package.version, record) {
                    continue;
                }
                let title = fill(c.f.v_match, &[&package.name, &package.version, &record.id]);
                let finding = if record.severity == "critical" {
                    Finding::critical(title)
                } else {
                    Finding::attention(title)
                };
                report.push(
                    finding
                        .detail(fill(
                            c.f.v_match_detail,
                            &[&record.description, &record.fixed_in],
                        ))
                        .evidence(format!("{} {}", package.name, package.version)),
                );
            }
        }

        // Service banners, which often differ from the packaged version.
        let banners = sys::service_versions();
        for (program, banner) in &banners {
            report.push(Finding::info(fill(
                c.f.v_service_version,
                &[program, banner],
            )));
            let Some(version) = version_from_banner(banner) else {
                continue;
            };
            for record in database
                .iter()
                .filter(|record| record.kind == "svc" && record.product == *program)
            {
                if !is_affected(&version, record) {
                    continue;
                }
                let title = fill(c.f.v_match, &[program, &version, &record.id]);
                let finding = if record.severity == "critical" {
                    Finding::critical(title)
                } else {
                    Finding::attention(title)
                };
                report.push(
                    finding
                        .detail(fill(
                            c.f.v_match_detail,
                            &[&record.description, &record.fixed_in],
                        ))
                        .evidence(banner.clone()),
                );
            }
        }

        // --- pass 4: pending updates -----------------------------------
        ctx.phase(c.f.v_phase_updates);
        if let Some((total, security)) = sys::pending_updates() {
            if total > 0 {
                report.push(
                    Finding::attention(fill(c.f.v_pending_updates, &[&total.to_string()]))
                        .detail(fill(c.f.v_pending_updates_detail, &[&security.to_string()])),
                );
            }
        }
        if sys::reboot_required() {
            report.push(
                Finding::attention(c.f.v_reboot_required).detail(c.f.v_reboot_required_detail),
            );
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaging_metadata_is_stripped() {
        assert_eq!(upstream_version("1:8.9p1-3ubuntu0.6"), "8.9p1");
        assert_eq!(upstream_version("2.4.52-1ubuntu4.7"), "2.4.52");
        assert_eq!(upstream_version("5.6.1"), "5.6.1");
    }

    #[test]
    fn a_really_downgrade_reports_the_version_actually_shipped() {
        // Ubuntu withdrew the backdoored xz this way; reading the literal
        // 5.6.1 would raise a critical finding on a patched machine.
        assert_eq!(upstream_version("5.6.1+really5.4.5-1ubuntu0.2"), "5.4.5");
        let xz = ranged("5.6.0", "5.6.2");
        assert!(!is_affected("5.6.1+really5.4.5-1ubuntu0.2", &xz));
        assert!(is_affected("5.6.1-1", &xz));
    }

    #[test]
    fn a_tilde_suffix_sorts_below_the_release() {
        assert_eq!(compare_versions("1.0~rc1", "1.0"), Ordering::Less);
    }

    #[test]
    fn prerelease_sorts_below_the_release() {
        assert_eq!(compare_versions("2.0rc1", "2.0"), Ordering::Less);
        assert_eq!(compare_versions("9.8p1", "9.8"), Ordering::Greater);
    }

    #[test]
    fn versions_order_numerically_not_lexically() {
        assert_eq!(compare_versions("1.9.10", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("2.4.52", "2.4.52"), Ordering::Equal);
        assert_eq!(compare_versions("8.9", "9.8"), Ordering::Less);
    }

    /// A record with no lower bound, for the "everything below" tests.
    fn open_ended(fixed_in: &str) -> Record {
        Record {
            kind: "pkg".into(),
            product: "test".into(),
            fixed_in: fixed_in.into(),
            introduced: None,
            severity: "critical".into(),
            id: "TEST".into(),
            description: String::new(),
        }
    }

    fn ranged(introduced: &str, fixed_in: &str) -> Record {
        Record {
            introduced: Some(introduced.into()),
            ..open_ended(fixed_in)
        }
    }

    #[test]
    fn affected_only_below_the_fixed_version() {
        assert!(is_affected("1:8.9p1-3ubuntu0.6", &open_ended("9.8")));
        assert!(!is_affected("9.8p1", &open_ended("9.8")));
        assert!(is_affected("5.6.1", &open_ended("5.6.2")));
        assert!(!is_affected("5.6.2", &open_ended("5.6.2")));
    }

    #[test]
    fn a_range_leaves_older_stable_branches_alone() {
        let xz = ranged("5.6.0", "5.6.2");
        assert!(is_affected("5.6.1", &xz));
        assert!(is_affected("5.6.0", &xz));
        // The branch distributions reverted to was never affected.
        assert!(!is_affected("5.4.5", &xz));
        assert!(!is_affected("5.6.2", &xz));
    }

    #[test]
    fn a_range_is_parsed_from_the_database() {
        let records = parse_db("pkg|xz-utils|5.6.0..5.6.2|critical|CVE-2024-3094|Backdoor.");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].introduced.as_deref(), Some("5.6.0"));
        assert_eq!(records[0].fixed_in, "5.6.2");
    }

    #[test]
    fn version_is_extracted_from_a_banner() {
        assert_eq!(
            version_from_banner("OpenSSH_9.6p1, OpenSSL 3.0.13"),
            Some("9.6p1".to_string())
        );
        assert_eq!(
            version_from_banner("nginx version: nginx/1.24.0"),
            Some("1.24.0".to_string())
        );
    }

    #[test]
    fn builtin_database_parses_completely() {
        let records = parse_db(BUILTIN_DB);
        assert!(records.len() > 40, "expected a populated database");
        assert!(records.iter().all(|record| !record.id.is_empty()));
        assert!(records
            .iter()
            .all(|record| matches!(record.kind.as_str(), "pkg" | "svc" | "os")));
    }
}
