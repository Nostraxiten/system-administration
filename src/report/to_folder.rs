//! Folder output: one file per module plus an overall summary, written as
//! plain UTF-8 text so the reports travel anywhere.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::modules::Severity;
use crate::report::{module_block, summary_block, ScanRun};

/// Result of writing a report set.
pub struct Written {
    pub directory: PathBuf,
    pub files: Vec<PathBuf>,
}

/// Turn a module id into a stable, sortable file name.
fn file_name(index: usize, id: &str, language: &str) -> String {
    format!("{:02}-{id}.{language}.txt", index + 1)
}

/// Write the summary and every module report into `directory`.
///
/// The directory is created if needed; existing files with the same names are
/// overwritten, which is what re-running a scan into the same folder should do.
pub fn write(run: &ScanRun, directory: &Path) -> io::Result<Written> {
    fs::create_dir_all(directory)?;
    let c = run.catalog();
    let language = run.language.tag();
    let mut files = Vec::new();

    let summary_path = directory.join(format!("00-{}.{language}.txt", c.rep.summary_file));
    fs::write(&summary_path, summary_block(run))?;
    files.push(summary_path);

    for (index, module) in run.modules.iter().enumerate() {
        let path = directory.join(file_name(index, module.id, language));
        fs::write(&path, module_block(module, c, true))?;
        files.push(path);
    }

    // A flat, machine readable index so the findings can be fed into a ticket
    // system without parsing the prose reports.
    let csv_path = directory.join(format!("{}.{language}.csv", c.rep.findings_file));
    fs::write(&csv_path, findings_csv(run))?;
    files.push(csv_path);

    Ok(Written {
        directory: directory.to_path_buf(),
        files,
    })
}

/// Escape a field for CSV.
fn csv_field(value: &str) -> String {
    let cleaned = value.replace(['\n', '\r'], " ");
    if cleaned.contains(',') || cleaned.contains('"') {
        format!("\"{}\"", cleaned.replace('"', "\"\""))
    } else {
        cleaned
    }
}

/// Every finding as one CSV row, most serious first.
fn findings_csv(run: &ScanRun) -> String {
    let c = run.catalog();
    let mut out = String::from("severity,module,title,detail\n");
    for severity in [Severity::Critical, Severity::Attention, Severity::Info] {
        for module in &run.modules {
            for finding in &module.findings {
                if finding.severity != severity {
                    continue;
                }
                out.push_str(&format!(
                    "{},{},{},{}\n",
                    csv_field(finding.severity.label(c)),
                    csv_field(&module.title),
                    csv_field(&finding.title),
                    csv_field(&finding.detail),
                ));
            }
        }
    }
    out
}

/// Resolve the destination folder from the two answers the operator gave.
///
/// An empty path means "next to the executable", which is what an operator who
/// just double-clicked the binary expects; the current directory is the
/// fallback when the executable's own location cannot be determined.
pub fn resolve_directory(name: &str, path: &str) -> PathBuf {
    let name = if name.trim().is_empty() {
        "sys"
    } else {
        name.trim()
    };
    let base = if path.trim().is_empty() {
        std::env::current_exe()
            .ok()
            .and_then(|executable| executable.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        PathBuf::from(path.trim())
    };
    base.join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_are_escaped() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("has,comma"), "\"has,comma\"");
        assert_eq!(csv_field("has\"quote"), "\"has\"\"quote\"");
        assert_eq!(csv_field("two\nlines"), "two lines");
    }

    #[test]
    fn an_empty_name_falls_back_to_sys() {
        let resolved = resolve_directory("  ", "/var/reports");
        assert_eq!(resolved, PathBuf::from("/var/reports/sys"));
    }

    #[test]
    fn an_explicit_path_is_honoured() {
        let resolved = resolve_directory("audit", "/tmp");
        assert_eq!(resolved, PathBuf::from("/tmp/audit"));
    }

    #[test]
    fn module_files_sort_in_run_order() {
        assert_eq!(file_name(0, "users", "es"), "01-users.es.txt");
        assert_eq!(file_name(9, "hosts", "en"), "10-hosts.en.txt");
    }
}
