//! Web services: which HTTP servers run here, what they disclose, and how far
//! their configuration is from a hardened one.
//!
//! The only network traffic this module produces goes to this machine's own
//! loopback interface. Nothing is sent to any other host.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::i18n::{fill, Catalog};
use crate::modules::{Finding, ModuleReport, ScanContext, Scanner, WEB_PORTS};
use crate::platform::{is_loopback_bind, read_file, sys};

pub struct Web;

/// Response headers a hardened site is expected to set.
const HARDENING_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "Strict-Transport-Security"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("content-security-policy", "Content-Security-Policy"),
    ("referrer-policy", "Referrer-Policy"),
];

/// Process names that mean an HTTP server is running.
const WEB_PROCESSES: &[&str] = &[
    "nginx",
    "apache2",
    "httpd",
    "lighttpd",
    "caddy",
    "haproxy",
    "traefik",
    "w3wp",
    "iisexpress",
    "node",
    "gunicorn",
    "uwsgi",
    "tomcat",
    "java",
];

/// Read the status line and headers from a local HTTP port.
fn probe_loopback(port: u16) -> Option<Vec<String>> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(700)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(900)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(900)))
        .ok()?;
    stream
        .write_all(b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\nUser-Agent: system-administration/local-audit\r\n\r\n")
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    while buffer.len() < 8192 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(_) => break,
        }
    }
    if buffer.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&buffer);
    Some(
        text.split("\r\n\r\n")
            .next()
            .unwrap_or(&text)
            .lines()
            .map(str::to_string)
            .collect(),
    )
}

/// A version string embedded in a `Server:` header, when one is there.
fn header_discloses_version(value: &str) -> bool {
    value.chars().any(|character| character.is_ascii_digit())
}

impl Scanner for Web {
    fn id(&self) -> &'static str {
        "web"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.web_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report = ModuleReport::new("web", c.m.web_t, c.m.web_d, c.m.web_c);
        report.push(Finding::info(c.f.w_probe_note));

        // --- pass 1: who is serving HTTP here -------------------------
        ctx.phase(c.f.w_phase_detect);
        let sockets = sys::sockets();
        let mut candidate_ports: BTreeSet<u16> = BTreeSet::new();
        let mut servers: BTreeSet<String> = BTreeSet::new();

        for socket in sockets.iter().filter(|socket| socket.state == "LISTEN") {
            let process = socket.process.clone().unwrap_or_default();
            let looks_web = WEB_PROCESSES
                .iter()
                .any(|name| process.to_lowercase().contains(name));
            if looks_web || WEB_PORTS.contains(&socket.local_port) {
                candidate_ports.insert(socket.local_port);
                if !process.is_empty() {
                    servers.insert(process);
                }
            }
        }

        if candidate_ports.is_empty() {
            report.push(Finding::info(c.f.w_none));
        } else {
            for server in &servers {
                report.push(Finding::info(fill(c.f.w_server_found, &[server])));
            }
            for (program, version) in sys::service_versions() {
                if WEB_PROCESSES.iter().any(|name| program.contains(name)) {
                    report.push(Finding::info(fill(
                        c.f.w_server_version,
                        &[&program, &version],
                    )));
                }
            }
        }

        // --- pass 2: what the server says about itself -----------------
        ctx.phase(c.f.w_phase_banner);
        for port in &candidate_ports {
            let Some(headers) = probe_loopback(*port) else {
                continue;
            };
            let lowered: Vec<String> = headers.iter().map(|line| line.to_lowercase()).collect();

            if let Some(server) = lowered
                .iter()
                .find(|line| line.starts_with("server:"))
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_string())
            {
                if header_discloses_version(&server) {
                    report.push(
                        Finding::attention(fill(c.f.w_banner_version, &[&server]))
                            .detail(fill(c.f.w_banner_version_detail, &[&port.to_string()])),
                    );
                }
            }

            if lowered.iter().any(|line| line.starts_with("x-powered-by:")) {
                let value = lowered
                    .iter()
                    .find(|line| line.starts_with("x-powered-by:"))
                    .cloned()
                    .unwrap_or_default();
                report.push(
                    Finding::attention(fill(c.f.w_banner_version, &[&value]))
                        .detail(fill(c.f.w_banner_version_detail, &[&port.to_string()])),
                );
            }

            // Hardening headers only make sense to demand on a real HTTP
            // response, so this is checked per responding port.
            for (needle, label) in HARDENING_HEADERS {
                let expected_on_plain_http = *needle != "strict-transport-security" || *port == 443;
                if expected_on_plain_http
                    && !lowered
                        .iter()
                        .any(|line| line.starts_with(&format!("{needle}:")))
                {
                    report.push(
                        Finding::attention(fill(c.f.w_missing_header, &[label]))
                            .detail(fill(c.f.w_missing_header_detail, &[&port.to_string()])),
                    );
                }
            }

            let listening_publicly = sockets.iter().any(|socket| {
                socket.local_port == *port
                    && socket.state == "LISTEN"
                    && !is_loopback_bind(&socket.local_addr)
            });
            if *port != 443 && *port != 8443 && listening_publicly {
                report.push(
                    Finding::attention(fill(c.f.w_no_tls, &[&port.to_string()]))
                        .detail(c.f.w_no_tls_detail),
                );
            }
        }

        // --- pass 3: configuration -------------------------------------
        ctx.phase(c.f.w_phase_config);
        let configs = sys::web_config_paths();
        for config in &configs {
            let path = config.display().to_string();
            let Some(text) = read_file(config) else {
                continue;
            };
            report.push(Finding::info(fill(c.f.w_config_found, &[&path])));

            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.starts_with(';') {
                    continue;
                }
                let lowered = trimmed.to_lowercase();

                if lowered.starts_with("autoindex on")
                    || (lowered.starts_with("options")
                        && lowered.contains("indexes")
                        && !lowered.contains("-indexes"))
                {
                    report.push(
                        Finding::attention(fill(c.f.w_dir_listing, &[&path]))
                            .detail(fill(c.f.w_dir_listing_detail, &[trimmed])),
                    );
                }

                if lowered.starts_with("servertokens")
                    && (lowered.contains("full")
                        || lowered.contains("os")
                        || lowered.contains("major"))
                {
                    report.push(
                        Finding::attention(fill(c.f.w_banner_version, &[trimmed]))
                            .detail(fill(c.f.w_banner_version_detail, &[&path])),
                    );
                }
                if lowered.starts_with("server_tokens on") {
                    report.push(
                        Finding::attention(fill(c.f.w_banner_version, &[trimmed]))
                            .detail(fill(c.f.w_banner_version_detail, &[&path])),
                    );
                }
                if lowered.replace(' ', "").starts_with("expose_php=on") {
                    report.push(Finding::attention(fill(c.f.w_php_expose, &[&path])));
                }
                if lowered.replace(' ', "").starts_with("display_errors=on") {
                    report.push(Finding::attention(fill(c.f.w_php_errors, &[&path])));
                }
            }
        }

        for page in sys::web_default_pages() {
            let path = page.display().to_string();
            let Some(text) = read_file(&page) else {
                continue;
            };
            let lowered = text.to_lowercase();
            if lowered.contains("welcome to nginx")
                || lowered.contains("apache2 debian default page")
                || lowered.contains("apache2 ubuntu default page")
                || lowered.contains("it works!")
                || lowered.contains("test page for the")
            {
                report.push(
                    Finding::attention(fill(c.f.w_default_site, &[&path]))
                        .detail(c.f.w_default_site_detail),
                );
            }
        }

        // --- pass 4: configuration permissions -------------------------
        ctx.phase(c.f.w_phase_perms);
        for config in &configs {
            let path = config.display().to_string();
            if let Some(mode) = sys::writable_permission_issue(&path) {
                report.push(
                    Finding::critical(fill(c.f.w_config_perm, &[&path]))
                        .detail(fill(c.f.w_config_perm_detail, &[&mode])),
                );
            }
        }

        report
    }
}
