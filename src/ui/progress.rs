//! The progress bar shown while the modules run.
//!
//! The bar stays on screen for the whole scan and names the phase each module
//! is in, so a long pass over the filesystem reads as work in progress rather
//! than a hang.

use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

use crate::modules::PhaseReporter;

/// Wraps the indicatif bar and implements the reporter the modules call.
pub struct ScanProgress {
    bar: ProgressBar,
    total: usize,
    module_label: std::cell::RefCell<String>,
}

impl ScanProgress {
    pub fn new(total: usize) -> Self {
        let bar = ProgressBar::new(total as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "  {spinner:.blue} [{bar:32.blue/dark_blue}] {pos}/{len}  {wide_msg}",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=> "),
        );
        // The steady tick keeps the spinner alive while a module is inside a
        // long blocking call such as a filesystem walk.
        bar.enable_steady_tick(Duration::from_millis(120));
        Self {
            bar,
            total,
            module_label: std::cell::RefCell::new(String::new()),
        }
    }

    /// Announce the module about to run.
    pub fn start_module(&self, index: usize, title: &str, template: &str) {
        let header = crate::i18n::fill(
            template,
            &[&(index + 1).to_string(), &self.total.to_string()],
        );
        *self.module_label.borrow_mut() = format!("{header} · {title}");
        self.bar.set_message(self.module_label.borrow().clone());
    }

    /// Mark the current module as done.
    pub fn finish_module(&self) {
        self.bar.inc(1);
    }

    /// Remove the bar from the screen.
    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }

    /// Print a line above the bar without corrupting it.
    pub fn println(&self, line: &str) {
        self.bar.println(line);
    }
}

impl PhaseReporter for ScanProgress {
    fn phase(&self, label: &str) {
        let module = self.module_label.borrow().clone();
        self.bar.set_message(format!("{module} · {label}"));
    }
}
