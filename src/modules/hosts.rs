//! IP addresses on the network, taken passively.
//!
//! This module reads the tables this machine already holds — the ARP/NDP
//! neighbour cache, the route table, `/etc/hosts` — and the remote ends of
//! connections it has itself established. It never sends a probe, a ping or a
//! DNS query to any other host, which keeps the tool inside its own system and
//! usable on a network where active scanning is not authorised.

use std::collections::{BTreeMap, BTreeSet};

use crate::i18n::{fill, Catalog};
use crate::modules::{Finding, ModuleReport, ScanContext, Scanner};
use crate::platform::sys;

pub struct Hosts;

impl Scanner for Hosts {
    fn id(&self) -> &'static str {
        "hosts"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.hosts_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report = ModuleReport::new("hosts", c.m.hosts_t, c.m.hosts_d, c.m.hosts_c);
        report.push(Finding::info(c.f.h_passive_note));

        // --- pass 1: neighbour tables ---------------------------------
        ctx.phase(c.f.h_phase_tables);
        let neighbors = sys::neighbors();
        if neighbors.is_empty() {
            report.push(Finding::info(c.f.h_no_neighbors));
        } else {
            report.push(
                Finding::info(fill(c.f.h_total, &[&neighbors.len().to_string()])).evidence_all(
                    neighbors.iter().map(|neighbor| {
                        fill(
                            c.f.h_entry,
                            &[
                                &neighbor.ip,
                                &neighbor.mac,
                                &neighbor.interface,
                                neighbor.hostname.as_deref().unwrap_or("-"),
                            ],
                        )
                    }),
                ),
            );
        }

        for gateway in sys::gateways() {
            report.push(Finding::info(fill(c.f.h_gateway, &[&gateway])));
        }
        for subnet in sys::local_subnets() {
            report.push(Finding::info(fill(c.f.h_subnet, &[&subnet])));
        }

        let incomplete = neighbors
            .iter()
            .filter(|neighbor| {
                neighbor.state == "INCOMPLETE"
                    || neighbor.state == "FAILED"
                    || neighbor.mac == "00:00:00:00:00:00"
                    || neighbor.mac == "-"
            })
            .count();
        if incomplete > 0 {
            report.push(Finding::info(fill(
                c.f.h_incomplete,
                &[&incomplete.to_string()],
            )));
        }

        // A single MAC answering for several addresses is how ARP poisoning
        // looks from the victim's table. It is also how a router with proxy
        // ARP looks, so this is reported for judgement, not as a verdict.
        let mut by_mac: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for neighbor in &neighbors {
            if neighbor.mac == "00:00:00:00:00:00" || neighbor.mac == "-" || neighbor.mac.is_empty()
            {
                continue;
            }
            by_mac
                .entry(neighbor.mac.as_str())
                .or_default()
                .push(neighbor.ip.as_str());
        }
        for (mac, addresses) in &by_mac {
            if addresses.len() > 1 {
                report.push(
                    Finding::attention(fill(c.f.h_dup_mac, &[mac]))
                        .detail(fill(c.f.h_dup_mac_detail, &[&addresses.join(", ")])),
                );
            }
        }

        // --- pass 2: names, from local files only ----------------------
        ctx.phase(c.f.h_phase_names);
        let names = sys::local_host_names();
        if !names.is_empty() {
            report.push(
                Finding::info(fill(c.f.h_name_source, &["/etc/hosts"])).evidence_all(
                    names
                        .iter()
                        .map(|(address, name)| format!("{address} · {name}")),
                ),
            );
        }

        // --- pass 3: the other end of live connections -----------------
        ctx.phase(c.f.h_phase_peers);
        let mut peers: BTreeSet<String> = BTreeSet::new();
        for socket in sys::sockets() {
            if socket.state != "ESTABLISHED" || socket.remote_addr.is_empty() {
                continue;
            }
            if socket.remote_addr.starts_with("127.") || socket.remote_addr == "::1" {
                continue;
            }
            let name = names
                .get(&socket.remote_addr)
                .cloned()
                .or_else(|| {
                    neighbors
                        .iter()
                        .find(|neighbor| neighbor.ip == socket.remote_addr)
                        .and_then(|neighbor| neighbor.hostname.clone())
                })
                .unwrap_or_else(|| socket.process.clone().unwrap_or_else(|| "-".to_string()));
            peers.insert(fill(c.f.h_peer_entry, &[&socket.remote_addr, &name]));
        }
        if !peers.is_empty() {
            report.push(
                Finding::info(fill(c.f.h_peers, &[&peers.len().to_string()])).evidence_all(peers),
            );
        }

        report
    }
}
