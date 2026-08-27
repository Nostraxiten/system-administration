//! Ports and network: the listening surface, live connections and interfaces.

use std::collections::BTreeSet;

use crate::i18n::{fill, Catalog};
use crate::modules::{port_service_name, risky_port, Finding, ModuleReport, ScanContext, Scanner};
use crate::platform::{human_bytes, is_loopback_bind, is_public_ip, is_wildcard_bind, sys};

pub struct Network;

impl Scanner for Network {
    fn id(&self) -> &'static str {
        "network"
    }

    fn title(&self, catalog: &'static Catalog) -> &'static str {
        catalog.m.network_t
    }

    fn run(&self, ctx: &ScanContext) -> ModuleReport {
        let c = ctx.catalog;
        let mut report = ModuleReport::new("network", c.m.network_t, c.m.network_d, c.m.network_c);

        // --- pass 1: listening sockets --------------------------------
        ctx.phase(c.f.n_phase_listen);
        let sockets = sys::sockets();
        let listening: Vec<_> = sockets
            .iter()
            .filter(|socket| socket.state == "LISTEN")
            .collect();
        let exposed: Vec<_> = listening
            .iter()
            .filter(|socket| !is_loopback_bind(&socket.local_addr))
            .collect();

        report.push(
            Finding::info(fill(
                c.f.n_listen_total,
                &[&listening.len().to_string(), &exposed.len().to_string()],
            ))
            .evidence_all(listening.iter().map(|socket| {
                let owner = socket
                    .process
                    .clone()
                    .map(|name| match socket.pid {
                        Some(pid) => format!("{name} (pid {pid})"),
                        None => name,
                    })
                    .unwrap_or_else(|| match port_service_name(socket.local_port) {
                        "-" => c.f.n_service_unknown.to_string(),
                        known => known.to_string(),
                    });
                fill(
                    c.f.n_listen_entry,
                    &[
                        &socket.local_port.to_string(),
                        &socket.proto,
                        &socket.local_addr,
                        &owner,
                    ],
                )
            })),
        );

        let mut reported_ports: BTreeSet<(String, u16)> = BTreeSet::new();
        for socket in &listening {
            let key = (socket.proto.clone(), socket.local_port);
            let first_time = reported_ports.insert(key);
            let service = socket.process.clone().unwrap_or_else(|| {
                match port_service_name(socket.local_port) {
                    "-" => c.f.n_service_unknown.to_string(),
                    known => known.to_string(),
                }
            });

            if is_wildcard_bind(&socket.local_addr) && first_time {
                // A risky service on every interface is the combination that
                // actually gets servers taken over, so it outranks both parts.
                if let Some((name, reason)) = risky_port(socket.local_port) {
                    report.push(
                        Finding::critical(fill(
                            c.f.n_risky_service,
                            &[&socket.local_port.to_string(), &socket.proto, name],
                        ))
                        .detail(fill(c.f.n_risky_service_detail, &[reason]))
                        .evidence(format!("{} · {service}", socket.local_addr)),
                    );
                } else {
                    report.push(
                        Finding::attention(fill(
                            c.f.n_listen_public,
                            &[&socket.local_port.to_string(), &socket.proto],
                        ))
                        .detail(fill(c.f.n_listen_public_detail, &[&service])),
                    );
                }
            } else if first_time {
                if let Some((name, reason)) = risky_port(socket.local_port) {
                    report.push(
                        Finding::attention(fill(
                            c.f.n_risky_service,
                            &[&socket.local_port.to_string(), &socket.proto, name],
                        ))
                        .detail(fill(c.f.n_risky_service_detail, &[reason]))
                        .evidence(format!("{} · {service}", socket.local_addr)),
                    );
                }
            }

            if socket.process.is_none() && first_time {
                let finding = if ctx.elevated {
                    Finding::attention(fill(
                        c.f.n_unattributed,
                        &[&socket.local_port.to_string(), &socket.proto],
                    ))
                } else {
                    Finding::info(fill(
                        c.f.n_unattributed,
                        &[&socket.local_port.to_string(), &socket.proto],
                    ))
                };
                report.push(finding.detail(c.f.n_unattributed_detail));
            }
        }

        // --- pass 2: established connections ---------------------------
        ctx.phase(c.f.n_phase_conns);
        let established: Vec<_> = sockets
            .iter()
            .filter(|socket| socket.state == "ESTABLISHED")
            .collect();
        report.push(
            Finding::info(fill(c.f.n_conn_total, &[&established.len().to_string()])).evidence_all(
                established.iter().map(|socket| {
                    fill(
                        c.f.n_conn_entry,
                        &[
                            &format!("{}:{}", socket.local_addr, socket.local_port),
                            &format!("{}:{}", socket.remote_addr, socket.remote_port),
                            socket.process.as_deref().unwrap_or("-"),
                        ],
                    )
                }),
            ),
        );

        let mut external_peers: BTreeSet<String> = BTreeSet::new();
        for socket in &established {
            if is_public_ip(&socket.remote_addr)
                && external_peers.insert(socket.remote_addr.clone())
            {
                report.push(
                    Finding::attention(fill(
                        c.f.n_conn_external,
                        &[&format!("{}:{}", socket.remote_addr, socket.remote_port)],
                    ))
                    .detail(fill(
                        c.f.n_conn_external_detail,
                        &[socket.process.as_deref().unwrap_or("-")],
                    )),
                );
            }
        }

        // --- pass 3: interfaces ----------------------------------------
        ctx.phase(c.f.n_phase_ifaces);
        for interface in sys::interfaces() {
            let addresses = if interface.addresses.is_empty() {
                "-".to_string()
            } else {
                interface.addresses.join(", ")
            };
            report.push(Finding::info(fill(
                c.f.n_iface_entry,
                &[
                    &interface.name,
                    &addresses,
                    &interface.mac,
                    &interface.mtu.to_string(),
                ],
            )));

            if interface.promiscuous {
                report.push(
                    Finding::critical(fill(c.f.n_iface_promisc, &[&interface.name]))
                        .detail(c.f.n_iface_promisc_detail),
                );
            }

            report.push(Finding::info(fill(
                c.f.n_traffic,
                &[
                    &interface.name,
                    &human_bytes(interface.received),
                    &human_bytes(interface.transmitted),
                ],
            )));

            if interface.rx_errors > 0 || interface.tx_errors > 0 {
                report.push(Finding::info(fill(
                    c.f.n_iface_errors,
                    &[
                        &interface.name,
                        &interface.rx_errors.to_string(),
                        &interface.tx_errors.to_string(),
                    ],
                )));
            }
        }

        if sys::ip_forwarding() == Some(true) {
            report.push(Finding::attention(c.f.n_forwarding).detail(c.f.n_forwarding_detail));
        }

        // --- pass 4: firewall ------------------------------------------
        ctx.phase(c.f.n_phase_firewall);
        let firewall = sys::firewall();
        if firewall.active {
            report.push(
                Finding::info(fill(c.f.n_firewall_active, &[&firewall.engine]))
                    .detail(format!("{} rules", firewall.rule_count)),
            );
        } else if !exposed.is_empty() {
            report.push(
                Finding::attention(c.f.n_firewall_inactive)
                    .detail(c.f.n_firewall_inactive_detail)
                    .evidence(firewall.engine),
            );
        } else {
            report.push(Finding::info(c.f.n_firewall_inactive).evidence(firewall.engine));
        }

        if !ctx.elevated {
            report.limit(fill(
                c.f.source_unreadable,
                &[&format!("/proc/<pid>/fd ({})", c.f.needs_privilege)],
            ));
        }

        report
    }
}
