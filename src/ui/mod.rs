//! Interactive front end.
//!
//! The whole tool is driven by prompts: there are no flags, no subcommands and
//! nothing to memorise. Every prompt has a safe default, so an operator can
//! run a complete scan by pressing Enter through it.

pub mod banner;
pub mod language;
pub mod progress;

use dialoguer::{theme::ColorfulTheme, Input, Select};

use crate::i18n::{fill, Catalog};
use crate::platform::detect::{self, SystemProfile};
use crate::platform::OsIdentity;

/// Yes/no question with a default.
///
/// This is a two item selection rather than a `Confirm` prompt because
/// `Confirm` hard-codes an English `[y/n]`, which would leak into an otherwise
/// Spanish run.
pub fn confirm(catalog: &'static Catalog, prompt: &str, default: bool) -> bool {
    let options = [
        catalog.ui.detect_yes.to_string(),
        catalog.ui.detect_no.to_string(),
    ];
    select(prompt, &options, if default { 0 } else { 1 }) == 0
}

/// Single choice from a list. Returns the default when the prompt is
/// cancelled, so an interrupted run still completes rather than dying.
pub fn select(prompt: &str, items: &[String], default: usize) -> usize {
    Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(items)
        .default(default)
        .max_length(15)
        .interact()
        .unwrap_or(default)
}

/// Free text with a default, and an explanatory hint after the label.
pub fn text(prompt: &str, hint: &str, default: &str) -> String {
    let label = if hint.is_empty() {
        prompt.to_string()
    } else {
        format!("{prompt} ({hint})")
    };
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(label)
        .default(default.to_string())
        .allow_empty(true)
        .interact_text()
        .unwrap_or_else(|_| default.to_string())
}

/// Confirm the detected system, or let the operator pick another one.
///
/// The manual list leads with a recommendation derived from the machine's own
/// evidence — package manager, kernel, init system — so choosing correctly
/// does not depend on the operator recognising a distribution by name.
pub fn confirm_system(catalog: &'static Catalog, identity: OsIdentity) -> SystemProfile {
    println!("  {}", catalog.ui.detect_heading);
    println!(
        "  {}",
        "-".repeat(catalog.ui.detect_heading.chars().count())
    );
    println!("  {}", identity.label());
    if !identity.evidence.is_empty() {
        println!("  {}:", catalog.ui.detect_evidence);
        for line in &identity.evidence {
            println!("    - {line}");
        }
    }
    println!();

    let question = format!("{} [{}]", catalog.ui.detect_question, identity.label());
    if confirm(catalog, &question, true) {
        let profile = SystemProfile::from_detection(identity);
        println!("  {}", fill(catalog.ui.profile_applied, &[&profile.label]));
        println!();
        return profile;
    }

    let (recommended_id, recommended_label, reasons) = detect::recommendation(&identity);
    let mut items = vec![format!(
        "{}: {} ({}: {})",
        catalog.ui.recommended,
        recommended_label,
        catalog.ui.recommended_hint,
        if reasons.is_empty() {
            "-".to_string()
        } else {
            reasons.join(", ")
        }
    )];
    let systems = detect::catalog();
    items.extend(systems.iter().map(|(_, label)| (*label).to_string()));

    let choice = select(catalog.ui.choose_system, &items, 0);
    let profile = if choice == 0 {
        SystemProfile::overridden(identity, &recommended_id, &recommended_label)
    } else {
        let (id, label) = systems[choice - 1];
        SystemProfile::overridden(identity, id, label)
    };
    println!("  {}", fill(catalog.ui.profile_applied, &[&profile.label]));
    println!();
    profile
}

/// Ask where the reports should go. Returns `None` when the operator prefers
/// them on screen.
pub fn ask_output(catalog: &'static Catalog) -> Option<(String, String)> {
    if !confirm(catalog, catalog.ui.save_question, true) {
        return None;
    }
    let name = text(catalog.ui.folder_name_prompt, "", "sys");
    let path = text(
        catalog.ui.folder_path_prompt,
        catalog.ui.folder_path_hint,
        "",
    );
    Some((name, path))
}
