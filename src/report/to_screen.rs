//! Screen output: the same report as the files, coloured by severity and
//! paginated one module at a time so nothing scrolls past unread.

use std::io::{self, Write};

use crossterm::style::Stylize;

use crate::i18n::fill;
use crate::modules::Severity;
use crate::report::{rule, summary_block, ScanRun, WIDTH};

/// Colour a severity tag without touching the rest of the line.
fn colourise(line: &str, catalog: &crate::i18n::Catalog) -> String {
    let tag_end = match line.find(']') {
        Some(index) if line.starts_with('[') => index + 1,
        _ => return line.to_string(),
    };
    let (tag, rest) = line.split_at(tag_end);
    let inner = &tag[1..tag.len() - 1];
    let painted = if inner == catalog.sev.critical {
        tag.red().bold().to_string()
    } else if inner == catalog.sev.attention {
        tag.yellow().bold().to_string()
    } else if inner == catalog.sev.info {
        tag.cyan().to_string()
    } else {
        tag.to_string()
    };
    format!("{painted}{rest}")
}

/// Print a block, colouring severity tags and rules.
fn print_block(text: &str, catalog: &crate::i18n::Catalog) {
    for line in text.lines() {
        if line.starts_with("===") {
            println!("{}", line.dark_blue());
        } else if line.starts_with("---") {
            println!("{}", line.dark_grey());
        } else if line.starts_with('[') {
            println!("{}", colourise(line, catalog));
        } else {
            println!("{line}");
        }
    }
}

/// Wait for the operator before moving to the next module.
fn wait_for_enter(prompt: &str) {
    print!("\n{} ", prompt.dark_grey());
    let _ = io::stdout().flush();
    let mut discard = String::new();
    let _ = io::stdin().read_line(&mut discard);
}

/// Print the whole report, one page per module.
pub fn render(run: &ScanRun) {
    let c = run.catalog();
    println!();
    print_block(&summary_block(run), c);

    let total = run.modules.len();
    for (index, module) in run.modules.iter().enumerate() {
        wait_for_enter(&format!(
            "{} — {}",
            fill(
                c.rep.page_of,
                &[&(index + 1).to_string(), &total.to_string()]
            ),
            c.ui.press_enter
        ));
        println!();
        print_block(&crate::report::module_block(module, c, true), c);
    }

    println!();
    println!("{}", rule('=').dark_blue());
    let tally = fill(
        c.ui.scan_tally,
        &[
            &run.count(Severity::Critical).to_string(),
            &run.count(Severity::Attention).to_string(),
            &run.count(Severity::Info).to_string(),
        ],
    );
    let centred = " ".repeat(WIDTH.saturating_sub(tally.chars().count()) / 2);
    println!("{centred}{tally}");
    println!("{}", rule('=').dark_blue());
    println!("{}", c.rep.end_of_report.dark_grey());
}
