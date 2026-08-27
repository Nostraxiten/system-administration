//! Bilingual string catalogue.
//!
//! Every user visible string lives here. A `Catalog` is a plain `const`
//! structure of `&'static str`, so the whole translation table is baked into
//! the binary with zero runtime cost and no lookup failures: adding a language
//! is a compile error until every field is filled in.
//!
//! Strings that need runtime data use positional placeholders (`{0}`, `{1}`,
//! ...) so translators can reorder them freely. Substitution goes through
//! [`fill`].

pub mod en;
pub mod es;

/// Language chosen by the operator at start-up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Language {
    Spanish,
    English,
}

impl Language {
    /// The catalogue backing this language.
    pub fn catalog(self) -> &'static Catalog {
        match self {
            Language::Spanish => &es::CATALOG,
            Language::English => &en::CATALOG,
        }
    }

    /// Short tag used in file names and report headers.
    pub fn tag(self) -> &'static str {
        match self {
            Language::Spanish => "es",
            Language::English => "en",
        }
    }
}

/// Replace `{0}`, `{1}`, ... in `template` with `args`.
///
/// Unknown indices are left untouched rather than panicking: a malformed
/// template degrades into visible text instead of taking the scan down.
pub fn fill(template: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(close_rel) = rest[open..].find('}') else {
            break;
        };
        let close = open + close_rel;
        out.push_str(&rest[..open]);
        let key = &rest[open + 1..close];
        match key.parse::<usize>() {
            Ok(index) if index < args.len() => out.push_str(args[index]),
            _ => out.push_str(&rest[open..=close]),
        }
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Full translation table.
pub struct Catalog {
    pub ui: Ui,
    pub sev: Sev,
    pub rep: Rep,
    pub m: Modules,
    pub f: Findings,
}

/// Interactive flow: banner, prompts, progress.
pub struct Ui {
    pub language_prompt: &'static str,
    pub language_spanish: &'static str,
    pub language_english: &'static str,
    pub tagline: &'static str,
    pub scope_banner: &'static str,
    pub privilege_root: &'static str,
    pub privilege_admin: &'static str,
    pub privilege_full: &'static str,
    pub privilege_tag_full: &'static str,
    pub privilege_tag_limited: &'static str,
    pub profile_auto: &'static str,
    pub profile_manual: &'static str,
    pub detect_heading: &'static str,
    pub detect_question: &'static str,
    pub detect_evidence: &'static str,
    pub detect_yes: &'static str,
    pub detect_no: &'static str,
    pub choose_system: &'static str,
    pub recommended: &'static str,
    pub recommended_hint: &'static str,
    pub profile_applied: &'static str,
    pub scan_heading: &'static str,
    pub scan_module_of: &'static str,
    pub scan_finished: &'static str,
    pub scan_tally: &'static str,
    pub save_question: &'static str,
    pub folder_name_prompt: &'static str,
    pub folder_path_prompt: &'static str,
    pub folder_path_hint: &'static str,
    pub saving: &'static str,
    pub saved_to: &'static str,
    pub save_failed: &'static str,
    pub press_enter: &'static str,
    pub farewell: &'static str,
    pub label_host: &'static str,
    pub label_system: &'static str,
    pub label_kernel: &'static str,
    pub label_arch: &'static str,
    pub label_uptime: &'static str,
    pub label_date: &'static str,
    pub label_duration: &'static str,
    pub label_operator: &'static str,
    pub label_profile: &'static str,
    pub label_packages: &'static str,
    pub label_init: &'static str,
}

/// Severity labels.
pub struct Sev {
    pub info: &'static str,
    pub attention: &'static str,
    pub critical: &'static str,
}

/// Report chrome.
pub struct Rep {
    pub title: &'static str,
    pub summary_title: &'static str,
    pub priority_title: &'static str,
    pub priority_empty: &'static str,
    pub module_index: &'static str,
    pub checked: &'static str,
    pub found: &'static str,
    pub evidence: &'static str,
    pub totals: &'static str,
    pub module_totals: &'static str,
    pub no_findings: &'static str,
    pub page_of: &'static str,
    pub scope_note: &'static str,
    pub partial: &'static str,
    pub partial_reason: &'static str,
    pub summary_file: &'static str,
    pub findings_file: &'static str,
    pub duration_module: &'static str,
    pub generated_by: &'static str,
    pub end_of_report: &'static str,
}

/// Module titles, one-line purpose, and the checklist of what each one reads.
pub struct Modules {
    pub users_t: &'static str,
    pub users_d: &'static str,
    pub users_c: &'static [&'static str],
    pub processes_t: &'static str,
    pub processes_d: &'static str,
    pub processes_c: &'static [&'static str],
    pub persistence_t: &'static str,
    pub persistence_d: &'static str,
    pub persistence_c: &'static [&'static str],
    pub files_t: &'static str,
    pub files_d: &'static str,
    pub files_c: &'static [&'static str],
    pub network_t: &'static str,
    pub network_d: &'static str,
    pub network_c: &'static [&'static str],
    pub web_t: &'static str,
    pub web_d: &'static str,
    pub web_c: &'static [&'static str],
    pub versions_t: &'static str,
    pub versions_d: &'static str,
    pub versions_c: &'static [&'static str],
    pub logs_t: &'static str,
    pub logs_d: &'static str,
    pub logs_c: &'static [&'static str],
    pub hosts_t: &'static str,
    pub hosts_d: &'static str,
    pub hosts_c: &'static [&'static str],
}

/// Finding templates, grouped by module prefix.
pub struct Findings {
    // --- shared -----------------------------------------------------
    pub source_unreadable: &'static str,
    pub needs_privilege: &'static str,

    // --- users ---------------------------------------------------------
    pub u_phase_accounts: &'static str,
    pub u_phase_privileges: &'static str,
    pub u_phase_logins: &'static str,
    pub u_phase_keys: &'static str,
    pub u_phase_homes: &'static str,
    pub u_total: &'static str,
    pub u_interactive: &'static str,
    pub u_login_summary: &'static str,
    pub u_uid0: &'static str,
    pub u_uid0_detail: &'static str,
    pub u_admin: &'static str,
    pub u_admin_detail: &'static str,
    pub u_nopass: &'static str,
    pub u_nopass_detail: &'static str,
    pub u_locked_shell: &'static str,
    pub u_locked_shell_detail: &'static str,
    pub u_dormant: &'static str,
    pub u_dormant_detail: &'static str,
    pub u_dup_uid: &'static str,
    pub u_dup_uid_detail: &'static str,
    pub u_sudo_nopasswd: &'static str,
    pub u_sudo_nopasswd_detail: &'static str,
    pub u_last_login: &'static str,
    pub u_never_logged: &'static str,
    pub u_home_loose: &'static str,
    pub u_home_loose_detail: &'static str,
    pub u_home_missing: &'static str,
    pub u_ssh_keys: &'static str,
    pub u_ssh_keys_detail: &'static str,
    pub u_ssh_key_perm: &'static str,
    pub u_guest_enabled: &'static str,
    pub u_pw_never_expires: &'static str,
    pub u_shell_list: &'static str,

    // --- processes -----------------------------------------------------
    pub p_phase_enumerate: &'static str,
    pub p_phase_paths: &'static str,
    pub p_phase_lineage: &'static str,
    pub p_phase_resources: &'static str,
    pub p_phase_hidden: &'static str,
    pub p_total: &'static str,
    pub p_by_user: &'static str,
    pub p_deleted_binary: &'static str,
    pub p_deleted_binary_detail: &'static str,
    pub p_volatile_path: &'static str,
    pub p_volatile_path_detail: &'static str,
    pub p_unusual_path: &'static str,
    pub p_unusual_path_detail: &'static str,
    pub p_masquerade: &'static str,
    pub p_masquerade_detail: &'static str,
    pub p_revshell_cmdline: &'static str,
    pub p_revshell_cmdline_detail: &'static str,
    pub p_hidden_pid: &'static str,
    pub p_hidden_pid_detail: &'static str,
    pub p_high_cpu: &'static str,
    pub p_high_mem: &'static str,
    pub p_orphan_root: &'static str,
    pub p_no_exe: &'static str,
    pub p_listener_procs: &'static str,

    // --- persistence ---------------------------------------------------
    pub s_phase_cron: &'static str,
    pub s_phase_services: &'static str,
    pub s_phase_autostart: &'static str,
    pub s_phase_history: &'static str,
    pub s_phase_preload: &'static str,
    pub s_cron_total: &'static str,
    pub s_cron_entry: &'static str,
    pub s_cron_suspicious: &'static str,
    pub s_cron_suspicious_detail: &'static str,
    pub s_cron_writable: &'static str,
    pub s_service_total: &'static str,
    pub s_service_nonstandard: &'static str,
    pub s_service_nonstandard_detail: &'static str,
    pub s_service_volatile: &'static str,
    pub s_autostart_total: &'static str,
    pub s_autostart_entry: &'static str,
    pub s_autostart_suspicious: &'static str,
    pub s_preload: &'static str,
    pub s_preload_detail: &'static str,
    pub s_rc_local: &'static str,
    pub s_shellrc_suspicious: &'static str,
    pub s_shellrc_detail: &'static str,
    pub s_history_revshell: &'static str,
    pub s_history_revshell_detail: &'static str,
    pub s_history_disabled: &'static str,
    pub s_history_disabled_detail: &'static str,
    pub s_authorized_keys: &'static str,
    pub s_run_key: &'static str,
    pub s_startup_folder: &'static str,
    pub s_wmi_subscription: &'static str,

    // --- files ---------------------------------------------------------
    pub fl_phase_walk: &'static str,
    pub fl_phase_names: &'static str,
    pub fl_phase_perms: &'static str,
    pub fl_phase_hidden: &'static str,
    pub fl_phase_temp: &'static str,
    pub fl_scanned: &'static str,
    pub fl_double_ext: &'static str,
    pub fl_double_ext_detail: &'static str,
    pub fl_bidi: &'static str,
    pub fl_bidi_detail: &'static str,
    pub fl_control_char: &'static str,
    pub fl_trailing_space: &'static str,
    pub fl_suid_unknown: &'static str,
    pub fl_suid_unknown_detail: &'static str,
    pub fl_suid_known: &'static str,
    pub fl_sgid_unknown: &'static str,
    pub fl_world_writable: &'static str,
    pub fl_world_writable_detail: &'static str,
    pub fl_hidden_critical: &'static str,
    pub fl_hidden_critical_detail: &'static str,
    pub fl_temp_exec: &'static str,
    pub fl_temp_exec_detail: &'static str,
    pub fl_orphan_owner: &'static str,
    pub fl_recent_system_binary: &'static str,
    pub fl_ads: &'static str,
    pub fl_group_world_writable: &'static str,
    pub fl_group_orphan: &'static str,
    pub fl_group_temp_exec: &'static str,
    pub fl_group_recent: &'static str,
    pub fl_group_hidden: &'static str,
    pub fl_more: &'static str,
    pub fl_symlinks_skipped: &'static str,

    // --- network -------------------------------------------------------
    pub n_phase_listen: &'static str,
    pub n_phase_conns: &'static str,
    pub n_phase_ifaces: &'static str,
    pub n_phase_firewall: &'static str,
    pub n_listen_total: &'static str,
    pub n_listen_entry: &'static str,
    pub n_listen_public: &'static str,
    pub n_listen_public_detail: &'static str,
    pub n_risky_service: &'static str,
    pub n_risky_service_detail: &'static str,
    pub n_service_unknown: &'static str,
    pub n_unattributed: &'static str,
    pub n_unattributed_detail: &'static str,
    pub n_conn_total: &'static str,
    pub n_conn_entry: &'static str,
    pub n_conn_external: &'static str,
    pub n_conn_external_detail: &'static str,
    pub n_iface_entry: &'static str,
    pub n_iface_promisc: &'static str,
    pub n_iface_promisc_detail: &'static str,
    pub n_forwarding: &'static str,
    pub n_forwarding_detail: &'static str,
    pub n_traffic: &'static str,
    pub n_iface_errors: &'static str,
    pub n_firewall_active: &'static str,
    pub n_firewall_inactive: &'static str,
    pub n_firewall_inactive_detail: &'static str,

    // --- web -----------------------------------------------------------
    pub w_phase_detect: &'static str,
    pub w_phase_banner: &'static str,
    pub w_phase_config: &'static str,
    pub w_phase_perms: &'static str,
    pub w_none: &'static str,
    pub w_server_found: &'static str,
    pub w_server_version: &'static str,
    pub w_banner_version: &'static str,
    pub w_banner_version_detail: &'static str,
    pub w_missing_header: &'static str,
    pub w_missing_header_detail: &'static str,
    pub w_dir_listing: &'static str,
    pub w_dir_listing_detail: &'static str,
    pub w_default_site: &'static str,
    pub w_default_site_detail: &'static str,
    pub w_no_tls: &'static str,
    pub w_no_tls_detail: &'static str,
    pub w_config_perm: &'static str,
    pub w_config_perm_detail: &'static str,
    pub w_php_expose: &'static str,
    pub w_php_errors: &'static str,
    pub w_config_found: &'static str,
    pub w_probe_note: &'static str,

    // --- versions ------------------------------------------------------
    pub v_phase_kernel: &'static str,
    pub v_phase_inventory: &'static str,
    pub v_phase_match: &'static str,
    pub v_phase_updates: &'static str,
    pub v_kernel: &'static str,
    pub v_os_release: &'static str,
    pub v_os_eol: &'static str,
    pub v_os_eol_detail: &'static str,
    pub v_inventory: &'static str,
    pub v_db_loaded: &'static str,
    pub v_db_external: &'static str,
    pub v_db_missing: &'static str,
    pub v_match: &'static str,
    pub v_match_detail: &'static str,
    pub v_service_version: &'static str,
    pub v_pending_updates: &'static str,
    pub v_pending_updates_detail: &'static str,
    pub v_reboot_required: &'static str,
    pub v_reboot_required_detail: &'static str,
    pub v_offline_note: &'static str,
    pub v_backport_note: &'static str,

    // --- logs ----------------------------------------------------------
    pub l_phase_sources: &'static str,
    pub l_phase_auth: &'static str,
    pub l_phase_escalation: &'static str,
    pub l_phase_integrity: &'static str,
    pub l_sources: &'static str,
    pub l_source_missing: &'static str,
    pub l_source_unreadable: &'static str,
    pub l_lines_read: &'static str,
    pub l_failed_total: &'static str,
    pub l_bruteforce: &'static str,
    pub l_bruteforce_detail: &'static str,
    pub l_bruteforce_success: &'static str,
    pub l_bruteforce_success_detail: &'static str,
    pub l_root_login: &'static str,
    pub l_root_login_detail: &'static str,
    pub l_sudo_use: &'static str,
    pub l_sudo_failures: &'static str,
    pub l_sudo_failures_detail: &'static str,
    pub l_account_created: &'static str,
    pub l_account_created_detail: &'static str,
    pub l_log_truncated: &'static str,
    pub l_log_truncated_detail: &'static str,
    pub l_log_cleared: &'static str,
    pub l_log_cleared_detail: &'static str,
    pub l_invalid_user: &'static str,
    pub l_accepted_total: &'static str,

    // --- hosts ---------------------------------------------------------
    pub h_phase_tables: &'static str,
    pub h_phase_names: &'static str,
    pub h_phase_peers: &'static str,
    pub h_passive_note: &'static str,
    pub h_total: &'static str,
    pub h_entry: &'static str,
    pub h_gateway: &'static str,
    pub h_subnet: &'static str,
    pub h_dup_mac: &'static str,
    pub h_dup_mac_detail: &'static str,
    pub h_incomplete: &'static str,
    pub h_peers: &'static str,
    pub h_peer_entry: &'static str,
    pub h_no_neighbors: &'static str,
    pub h_name_source: &'static str,
}
