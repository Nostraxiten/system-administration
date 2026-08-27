//! System detection and the profile the operator ends up confirming.
//!
//! Detection never blocks the scan: if the guess is wrong the operator picks
//! from the catalogue, and the "recommended" entry there is the profile that
//! best matches the hard evidence on the machine (package manager, kernel,
//! init system) rather than an alphabetical default.

use super::{sys, OsIdentity};

/// What the rest of the run treats as "the system".
#[derive(Clone, Debug)]
pub struct SystemProfile {
    /// Everything observed on the machine, regardless of what was chosen.
    pub identity: OsIdentity,
    /// Machine readable id of the profile in force.
    pub id: String,
    /// Label shown in prompts and reports.
    pub label: String,
    /// `true` when the operator accepted the automatic detection.
    pub auto_confirmed: bool,
}

impl SystemProfile {
    /// Profile built straight from detection, before the operator answers.
    pub fn from_detection(identity: OsIdentity) -> Self {
        Self {
            id: identity.id.clone(),
            label: identity.label(),
            identity,
            auto_confirmed: true,
        }
    }

    /// Profile the operator picked by hand.
    pub fn overridden(identity: OsIdentity, id: &str, label: &str) -> Self {
        Self {
            identity,
            id: id.to_string(),
            label: label.to_string(),
            auto_confirmed: false,
        }
    }
}

/// Inspect the running system.
pub fn detect() -> OsIdentity {
    sys::identify()
}

/// Every system offered in the manual picker.
pub fn catalog() -> Vec<(&'static str, &'static str)> {
    sys::known_systems()
}

/// The profile that best fits the observed evidence, and why.
///
/// Returned as `(id, label, reasons)`; the reasons are shown next to the
/// "recommended" entry so the choice is auditable rather than magic.
pub fn recommendation(identity: &OsIdentity) -> (String, String, Vec<String>) {
    sys::recommend(identity)
}

/// Whether the scan holds the privileges needed for full visibility.
pub fn is_elevated() -> bool {
    sys::is_elevated()
}
