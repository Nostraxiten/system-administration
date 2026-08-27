//! Files with dangerous or disguised names, wrong permissions, or executables
//! sitting where no executable belongs.
//!
//! Findings that occur in bulk are grouped before they are reported. A
//! hundred separate entries for one unpacked directory buries the one entry
//! that matters, which defeats the point of the priority summary.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use walkdir::WalkDir;

use crate::i18n::{fill, Catalog};
use crate::modules::{Finding, ModuleReport, ScanContext, Scanner};
use crate::platform::{human_bytes, sys, RootKind};

pub struct Files;

/// Upper bound per root so a scan of a large server still finishes. Reaching
/// it is recorded as a limitation rather than silently truncating.
const MAX_ENTRIES_PER_ROOT: usize = 60_000;

/// A system binary modified inside this window is worth a look: package
/// updates are the usual explanation, tampering is the other one.
const RECENT_BINARY_DAYS: u64 = 7;
const RECENT_BINARY_SECS: u64 = RECENT_BINARY_DAYS * 24 * 3600;

/// Above this count a category is summarised instead of listed one by one.
const GROUP_THRESHOLD: usize = 12;

/// Evidence lines kept when a category is summarised.
const EVIDENCE_SAMPLE: usize = 15;

/// Individually reported findings kept per category, so a pathological tree
/// cannot flood the report.
const MAX_INDIVIDUAL: usize = 60;

/// Characters that make a file name display differently from what it is.
fn deceptive_char(name: &str) -> Option<(char, &'static str)> {
    for character in name.chars() {
        let code = character as u32;
        let label = match code {
            // Explicit bidirectional overrides and embeddings.
            0x202A..=0x202E => "bidi override",
            0x2066..=0x2069 => "bidi isolate",
            // Zero width and directional marks.
            0x200B..=0x200F => "zero width",
            0x00AD => "soft hyphen",
            0xFEFF => "byte order mark",
            0x2060..=0x2064 => "invisible operator",
            // Raw control characters, including newlines inside a name.
            0x00..=0x1F | 0x7F => "control character",
            _ => continue,
        };
        return Some((character, label));
    }
    None
}

/// A name that reads as a document but runs as a program.
fn double_extension(name: &str) -> Option<String> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let last = parts[parts.len() - 1].to_lowercase();
    let middle = parts[parts.len() - 2].to_lowercase();
    let executable = sys::executable_extensions();
    let document = sys::document_extensions();
    (executable.contains(&last.as_str()) && document.contains(&middle.as_str()))
        .then(|| format!(".{middle}.{last}"))
}

/// Everything the walk collected, before it is turned into findings.
#[derive(Default)]
struct Collected {
    world_writable: Vec<(String, String)>,
    orphan_owner: BTreeMap<u32, Vec<String>>,
    temp_executables: Vec<(String, String, String)>,
    hidden: Vec<String>,
    recent_binaries: Vec<(String, String)>,
}

/// Emit one finding per item, or a single grouped finding once the list gets
/// long enough that reading it item by item stops being useful.
fn emit_grouped<F>(
    report: &mut ModuleReport,
    catalog: &Catalog,
    items: &[String],
    grouped_title: String,
    grouped_detail: String,
    individual: F,
) where
    F: Fn(&str) -> Finding,
{
    if items.is_empty() {
        return;
    }
    if items.len() <= GROUP_THRESHOLD {
        for item in items.iter().take(MAX_INDIVIDUAL) {
            report.push(individual(item));
        }
        return;
    }
    let mut evidence: Vec<String> = items.iter().take(EVIDENCE_SAMPLE).cloned().collect();
    if items.len() > EVIDENCE_SAMPLE {
        evidence.push(fill(
            catalog.f.fl_more,
            &[&(items.len() - EVIDENCE_SAMPLE).to_string()],
        ));
    }
    report.push(
        Finding::attention(grouped_title)
            .detail(grouped_detail)
            .evidence_all(evidence),
    );
}

impl Scanner for Files {
    fn id(&self) -> &'static str {
        "files"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.files_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report = ModuleReport::new("files", c.m.files_t, c.m.files_d, c.m.files_c);

        let roots = sys::scan_roots();
        let skip = sys::skip_paths();
        let critical = sys::critical_directories();
        let uid_names = sys::uid_names();

        let mut scanned = 0usize;
        let mut known_suid = 0usize;
        let mut symlinks = 0usize;
        let mut denied = 0usize;
        let mut truncated: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut collected = Collected::default();

        // --- one deep pass per root ------------------------------------
        for root in &roots {
            ctx.phase(&format!("{} · {}", c.f.fl_phase_walk, root.path));
            let mut entries_here = 0usize;

            let walker = WalkDir::new(&root.path)
                .max_depth(root.max_depth)
                .follow_links(false)
                .into_iter()
                .filter_entry(|entry| {
                    let path = entry.path().to_string_lossy();
                    !skip.iter().any(|skipped| path.starts_with(skipped))
                });

            for entry in walker {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        denied += 1;
                        continue;
                    }
                };
                entries_here += 1;
                if entries_here > MAX_ENTRIES_PER_ROOT {
                    truncated.push(root.path.clone());
                    break;
                }
                scanned += 1;

                let display = entry.path().to_string_lossy().into_owned();
                if !seen.insert(display.clone()) {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();

                // --- name level disguises, symlinks included ----------
                ctx.phase(c.f.fl_phase_names);
                if let Some((character, kind)) = deceptive_char(&name) {
                    let escaped = name.escape_debug().to_string();
                    if kind == "control character" {
                        report.push(
                            Finding::attention(fill(c.f.fl_control_char, &[&display]))
                                .detail(format!("U+{:04X} ({kind})", character as u32))
                                .evidence(escaped),
                        );
                    } else {
                        report.push(
                            Finding::critical(fill(c.f.fl_bidi, &[&display]))
                                .detail(c.f.fl_bidi_detail)
                                .evidence(format!(
                                    "U+{:04X} ({kind}) · {escaped}",
                                    character as u32
                                )),
                        );
                    }
                }
                if let Some(pair) = double_extension(&name) {
                    report.push(
                        Finding::attention(fill(c.f.fl_double_ext, &[&display]))
                            .detail(c.f.fl_double_ext_detail)
                            .evidence(pair),
                    );
                }
                if name.ends_with(' ') || name.ends_with('\u{00A0}') {
                    report.push(Finding::attention(fill(c.f.fl_trailing_space, &[&display])));
                }

                // A symlink's own mode bits are always 0777 on Linux and carry
                // no meaning; judging one on its permissions produces a finding
                // for every alternatives entry and every certificate link on
                // the system. What matters is the target, which the walk
                // reaches on its own.
                if entry.file_type().is_symlink() {
                    symlinks += 1;
                    continue;
                }

                let Ok(metadata) = entry.metadata() else {
                    denied += 1;
                    continue;
                };
                let attributes = sys::file_attributes(entry.path(), &metadata, &uid_names);
                let in_critical_path = critical.iter().any(|dir| display.starts_with(dir));

                if metadata.is_dir() {
                    if attributes.world_writable && in_critical_path {
                        collected
                            .world_writable
                            .push((display.clone(), attributes.mode.clone()));
                    }
                    continue;
                }

                // --- permissions ---------------------------------------
                ctx.phase(c.f.fl_phase_perms);
                if attributes.suid || attributes.sgid {
                    if sys::is_baseline_suid(&display) {
                        known_suid += 1;
                    } else if attributes.suid {
                        report.push(
                            Finding::critical(fill(c.f.fl_suid_unknown, &[&display]))
                                .detail(fill(
                                    c.f.fl_suid_unknown_detail,
                                    &[&attributes.owner, &attributes.mode],
                                ))
                                .evidence(format!(
                                    "{} · {}",
                                    human_bytes(attributes.size),
                                    attributes.modified
                                )),
                        );
                    } else {
                        report.push(
                            Finding::attention(fill(c.f.fl_sgid_unknown, &[&display])).detail(
                                fill(
                                    c.f.fl_suid_unknown_detail,
                                    &[&attributes.owner, &attributes.mode],
                                ),
                            ),
                        );
                    }
                }

                if attributes.world_writable && in_critical_path {
                    collected
                        .world_writable
                        .push((display.clone(), attributes.mode.clone()));
                }

                if !attributes.owner_known {
                    collected
                        .orphan_owner
                        .entry(attributes.owner_id)
                        .or_default()
                        .push(display.clone());
                }

                // --- placement ------------------------------------------
                match root.kind {
                    RootKind::Temp if attributes.executable => {
                        ctx.phase(c.f.fl_phase_temp);
                        collected.temp_executables.push((
                            display.clone(),
                            human_bytes(attributes.size),
                            attributes.modified.clone(),
                        ));
                    }
                    RootKind::System | RootKind::Config => {
                        if name.starts_with('.')
                            && in_critical_path
                            && !display.starts_with("/etc/")
                        {
                            ctx.phase(c.f.fl_phase_hidden);
                            collected.hidden.push(display.clone());
                        }
                        if root.kind == RootKind::System
                            && attributes.executable
                            && attributes.modified_secs_ago < RECENT_BINARY_SECS
                        {
                            collected
                                .recent_binaries
                                .push((display.clone(), attributes.modified.clone()));
                        }
                    }
                    _ => {}
                }
            }
        }

        // --- turn the collected material into findings ------------------
        ctx.phase(c.f.fl_phase_perms);

        let world_writable_paths: Vec<String> = collected
            .world_writable
            .iter()
            .map(|(path, mode)| format!("{path} ({mode})"))
            .collect();
        let modes: BTreeMap<&str, &str> = collected
            .world_writable
            .iter()
            .map(|(path, mode)| (path.as_str(), mode.as_str()))
            .collect();
        emit_grouped(
            &mut report,
            c,
            &world_writable_paths,
            fill(
                c.f.fl_group_world_writable,
                &[&collected.world_writable.len().to_string()],
            ),
            c.f.fl_world_writable_detail.to_string(),
            |item| {
                let path = item.split(" (").next().unwrap_or(item);
                Finding::attention(fill(c.f.fl_world_writable, &[path])).detail(fill(
                    c.f.fl_world_writable_detail,
                    &[modes.get(path).copied().unwrap_or("-")],
                ))
            },
        );

        // Orphaned files cluster by the uid that owns them, which is the fact
        // an operator acts on: one unpacked archive, not four hundred files.
        for (uid, paths) in &collected.orphan_owner {
            if paths.len() <= GROUP_THRESHOLD {
                for path in paths {
                    report.push(Finding::attention(fill(
                        c.f.fl_orphan_owner,
                        &[path, &uid.to_string()],
                    )));
                }
                continue;
            }
            let mut evidence: Vec<String> = paths.iter().take(EVIDENCE_SAMPLE).cloned().collect();
            if paths.len() > EVIDENCE_SAMPLE {
                evidence.push(fill(
                    c.f.fl_more,
                    &[&(paths.len() - EVIDENCE_SAMPLE).to_string()],
                ));
            }
            report.push(
                Finding::attention(fill(
                    c.f.fl_group_orphan,
                    &[&paths.len().to_string(), &uid.to_string()],
                ))
                .evidence_all(evidence),
            );
        }

        let temp_paths: Vec<String> = collected
            .temp_executables
            .iter()
            .map(|(path, size, modified)| format!("{path} · {size} · {modified}"))
            .collect();
        emit_grouped(
            &mut report,
            c,
            &temp_paths,
            fill(
                c.f.fl_group_temp_exec,
                &[&collected.temp_executables.len().to_string()],
            ),
            c.f.fl_temp_exec_detail.to_string(),
            |item| {
                let mut parts = item.split(" · ");
                let path = parts.next().unwrap_or(item);
                let size = parts.next().unwrap_or("-");
                let modified = parts.next().unwrap_or("-");
                Finding::attention(fill(c.f.fl_temp_exec, &[path]))
                    .detail(fill(c.f.fl_temp_exec_detail, &[size, modified]))
            },
        );

        ctx.phase(c.f.fl_phase_hidden);
        emit_grouped(
            &mut report,
            c,
            &collected.hidden,
            fill(c.f.fl_group_hidden, &[&collected.hidden.len().to_string()]),
            c.f.fl_hidden_critical_detail.to_string(),
            |item| {
                Finding::attention(fill(c.f.fl_hidden_critical, &[item]))
                    .detail(c.f.fl_hidden_critical_detail)
            },
        );

        // Recently touched system binaries are context, not an alert: on a
        // patched server there are always some.
        if !collected.recent_binaries.is_empty() {
            let mut evidence: Vec<String> = collected
                .recent_binaries
                .iter()
                .take(EVIDENCE_SAMPLE)
                .map(|(path, modified)| fill(c.f.fl_recent_system_binary, &[path, modified]))
                .collect();
            if collected.recent_binaries.len() > EVIDENCE_SAMPLE {
                evidence.push(fill(
                    c.f.fl_more,
                    &[&(collected.recent_binaries.len() - EVIDENCE_SAMPLE).to_string()],
                ));
            }
            report.push(
                Finding::info(fill(
                    c.f.fl_group_recent,
                    &[
                        &collected.recent_binaries.len().to_string(),
                        &RECENT_BINARY_DAYS.to_string(),
                    ],
                ))
                .evidence_all(evidence),
            );
        }

        // Alternate data streams hide a payload inside an innocuous file. The
        // call is a no-op on Linux, which has no equivalent mechanism.
        for root in &roots {
            for (path, stream) in sys::alternate_data_streams(Path::new(&root.path)) {
                report.push(Finding::attention(fill(c.f.fl_ads, &[&path])).evidence(stream));
            }
        }

        report.push(
            Finding::info(fill(
                c.f.fl_scanned,
                &[&scanned.to_string(), &roots.len().to_string()],
            ))
            .evidence_all(
                roots
                    .iter()
                    .map(|root| format!("{} (depth {})", root.path, root.max_depth)),
            ),
        );
        if known_suid > 0 {
            report.push(Finding::info(fill(
                c.f.fl_suid_known,
                &[&known_suid.to_string()],
            )));
        }
        if symlinks > 0 {
            report.push(Finding::info(fill(
                c.f.fl_symlinks_skipped,
                &[&symlinks.to_string()],
            )));
        }

        if denied > 0 {
            report.limit(fill(
                c.f.source_unreadable,
                &[&format!("{denied} paths ({})", c.f.needs_privilege)],
            ));
        }
        for root in truncated {
            report.limit(format!("{root} > {MAX_ENTRIES_PER_ROOT}"));
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bidi_override_is_spotted() {
        let name = "invoice\u{202E}fdp.exe";
        let (_, kind) = deceptive_char(name).expect("override must be detected");
        assert_eq!(kind, "bidi override");
    }

    #[test]
    fn ordinary_names_are_left_alone() {
        assert!(deceptive_char("libssl.so.3").is_none());
        assert!(deceptive_char("nginx.conf").is_none());
    }

    #[test]
    fn a_document_extension_hiding_a_script_is_flagged() {
        assert_eq!(
            double_extension("report.pdf.sh"),
            Some(".pdf.sh".to_string())
        );
        assert_eq!(
            double_extension("photo.jpg.py"),
            Some(".jpg.py".to_string())
        );
    }

    #[test]
    fn versioned_libraries_are_not_double_extensions() {
        assert!(double_extension("libc.so.6").is_none());
        assert!(double_extension("archive.tar.gz").is_none());
    }
}
