//! Language selection. Spanish is the default and is pre-selected, so the
//! operator can accept it with a single keypress.

use dialoguer::{theme::ColorfulTheme, Select};

use crate::i18n::{es, Language};

/// Ask which language to run in.
///
/// The prompt itself is bilingual because it is shown before a language has
/// been chosen. A failed or cancelled prompt falls back to Spanish rather than
/// aborting the run.
pub fn choose() -> Language {
    let catalog = &es::CATALOG;
    let options = [catalog.ui.language_spanish, catalog.ui.language_english];

    match Select::with_theme(&ColorfulTheme::default())
        .with_prompt(catalog.ui.language_prompt)
        .items(options)
        .default(0)
        .interact()
    {
        Ok(1) => Language::English,
        _ => Language::Spanish,
    }
}
