// SPDX-License-Identifier: Apache-2.0

//! Egress health, measured from the host and never inferred from the config.
//!
//! The TUI half of the GUI's `hostfacts`: the same rows (default route, IPv6,
//! DNS, guard, routes, restarts) and the same verdict sentence. Everything
//! here is read-only (`ip`, `resolvectl`, `systemctl show/is-active`, one
//! journal tail), so unlike the trial actions no privilege rule applies.

use std::process::Command;

/// The measured host facts behind one tunnel interface.
#[derive(Debug, Clone, Default)]
pub struct HealthFacts {
    pub interface: String,
    pub unit: String,
    pub route4: Option<String>,
    pub route6: Option<String>,
    pub dns: Vec<String>,
    pub dns_upstream: Vec<String>,
    pub guard_active: String,
    pub quick_active: String,
    pub unit_active: String,
    pub restarts: u64,
    pub last_death: String,
    pub interface_present: bool,
    pub expected_full: bool,
    pub down_since: Option<String>,
}

impl HealthFacts {
    #[must_use]
    pub fn route4_via_tunnel(&self) -> bool {
        self.route4.as_deref() == Some(self.interface.as_str())
    }

    #[must_use]
    pub fn route6_via_tunnel(&self) -> bool {
        self.route6.as_deref() == Some(self.interface.as_str())
    }

    /// The system resolver is usually systemd-resolved's stub (127.0.0.53);
    /// what decides "DNS rides the tunnel" is whether the tunnel LINK carries
    /// upstream servers. Reading only resolv.conf turns a working setup into
    /// a false FAIL — the same trap the GUI's facts document.
    #[must_use]
    pub fn dns_via_tunnel(&self) -> bool {
        !self.dns.is_empty() && (!self.dns_upstream.is_empty() || self.route_via(self.dns.first()))
    }

    fn route_via(&self, server: Option<&String>) -> bool {
        match server {
            Some(server) => {
                route_device(server, server.contains(':')).as_deref()
                    == Some(self.interface.as_str())
            }
            None => false,
        }
    }
}

/// How the verdict renders: live green, stale amber, fault red. SPLIT is
/// amber on purpose — a split host is the configuration working, not a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

/// The one sentence the console exists to say: is traffic going through the
/// tunnel, or around it? Ported from the GUI's `egressVerdict` so both
/// consoles answer identically.
#[must_use]
pub fn verdict(facts: &HealthFacts) -> (String, String, Level) {
    let tunnelled = facts.route4_via_tunnel();
    let guarded = facts.guard_active == "active";
    // A route outside the tunnel is only a leak if nothing drops it: with the
    // guard active, v6 packets die in the policy table — a corpse, not an exit.
    let v6_leaks = facts.route6.is_some() && !facts.route6_via_tunnel() && !guarded;
    // DNS is the leak a routed default hides. Only a fault when the config
    // asked for a full tunnel — a split host resolving locally is the design.
    let dns_leaks = facts.expected_full && !facts.dns.is_empty() && !facts.dns_via_tunnel();
    if tunnelled && dns_leaks {
        return (
            "DNS LEAK".to_owned(),
            format!(
                "lookups leave via {} instead of the tunnel",
                facts.dns.join(", ")
            ),
            Level::Fail,
        );
    }
    if tunnelled && !v6_leaks {
        return (
            "PROTECTED".to_owned(),
            format!(
                "default route via {}",
                facts.route4.as_deref().unwrap_or("the tunnel")
            ),
            Level::Ok,
        );
    }
    if tunnelled && v6_leaks {
        return (
            "V6 LEAK".to_owned(),
            format!(
                "IPv6 leaves via {}",
                facts.route6.as_deref().unwrap_or("the physical link")
            ),
            Level::Fail,
        );
    }
    if guarded {
        return (
            "UNPROTECTED".to_owned(),
            "guard is on but traffic is not tunnelled".to_owned(),
            Level::Fail,
        );
    }
    // A full-tunnel host that is not tunnelled is not "split by design". The
    // daemon publishes what the config asked for; when it asked for full and
    // nothing enters the tunnel, the split picture reads as a fault.
    if facts.expected_full {
        let why = if facts.unit_active != "active" {
            format!("{} is {}", facts.unit, facts.unit_active)
        } else {
            format!("no default route through {}", facts.interface)
        };
        return (
            "UNPROTECTED".to_owned(),
            format!("full tunnel configured, {why}"),
            Level::Fail,
        );
    }
    (
        "SPLIT".to_owned(),
        format!(
            "traffic leaves via {} — the tunnel carries only its own subnet",
            facts.route4.as_deref().unwrap_or("no route")
        ),
        Level::Warn,
    )
}

/// Read the host: routes, resolvers, unit states, the last death. Every
/// command degrades to silence when its tool is missing — a container without
/// `ip` gets "unknown" rows, not a panic.
#[must_use]
pub fn measure(interface: &str, unit: &str, expected_full: bool) -> HealthFacts {
    let guard = format!("vallum-guard@{interface}");
    let quick = format!("vallum-quick@{interface}");
    let unit_active = systemctl(&["is-active", unit]);
    let show = |property: &str| {
        Command::new("systemctl")
            .args(["show", unit, "-p", property])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix(property)?.strip_prefix('='))
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            })
    };
    let restarts: u64 = show("NRestarts").and_then(|v| v.parse().ok()).unwrap_or(0);
    let last_death = Command::new("journalctl")
        .args(["-u", unit, "-n", "400", "--no-pager", "-o", "cat"])
        .output()
        .ok()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .rfind(|line| {
                    line.contains("status=31/SYS")
                        || line.contains("Failed with result")
                        || line.contains("Main process exited")
                })
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .unwrap_or_default();
    HealthFacts {
        interface: interface.to_owned(),
        unit: unit.to_owned(),
        route4: route_device("1.1.1.1", false),
        route6: route_device("2001:4860:4860::8888", true),
        dns: nameservers(),
        dns_upstream: link_dns_servers(interface),
        guard_active: systemctl(&["is-active", &guard]),
        quick_active: systemctl(&["is-active", &quick]),
        unit_active: unit_active.clone(),
        restarts,
        last_death,
        interface_present: std::path::Path::new(&format!("/sys/class/net/{interface}")).exists(),
        expected_full,
        down_since: if unit_active != "active" {
            show("InactiveEnterTimestamp")
        } else {
            None
        },
    }
}

/// The Health view body: verdict first, then the GUI's rows as text. Each row
/// carries an ok/fail word beside the value — colour alone says nothing to
/// the ~8% of men who cannot separate red from green.
#[must_use]
pub fn lines(facts: &HealthFacts) -> Vec<String> {
    let (label, detail, _) = verdict(facts);
    let armed = facts.expected_full;
    let guard_on = facts.guard_active == "active";
    let v6_blocked = facts.route6.is_none() || (guard_on && !facts.route6_via_tunnel());
    let mut out = vec![
        format!("{label} — {detail}"),
        String::new(),
        format!(
            "default route   {} via {}",
            word(armed && facts.route4_via_tunnel() || !armed),
            facts.route4.as_deref().unwrap_or("no route"),
        ),
        format!(
            "ipv6            {} {}",
            word(armed && (v6_blocked || facts.route6_via_tunnel()) || !armed),
            if !armed {
                format!(
                    "rides {} · split by design",
                    facts.route6.as_deref().unwrap_or("physical")
                )
            } else if v6_blocked {
                if guard_on && !facts.route6_via_tunnel() {
                    format!(
                        "blocked by the guard{}",
                        facts
                            .route6
                            .as_ref()
                            .map_or(String::new(), |via| format!(" · route via {via} dropped"))
                    )
                } else {
                    "no route".to_owned()
                }
            } else if facts.route6_via_tunnel() {
                format!(
                    "tunnelled via {}",
                    facts.route6.as_deref().unwrap_or("the tunnel")
                )
            } else {
                format!(
                    "leaks via {}",
                    facts.route6.as_deref().unwrap_or("physical")
                )
            },
        ),
        format!(
            "dns             {} {}",
            word(!armed || (!facts.dns.is_empty() && facts.dns_via_tunnel())),
            if facts.dns_upstream.is_empty() {
                facts.dns.join(" · ")
            } else {
                format!(
                    "{} → {} (tunnel)",
                    facts.dns.first().map_or("none", String::as_str),
                    facts.dns_upstream.join(" · ")
                )
            },
        ),
        format!(
            "guard           {} {}",
            word(!armed || guard_on),
            if guard_on {
                "blocking egress".to_owned()
            } else if armed {
                "inactive — armed full tunnel with no egress block".to_owned()
            } else {
                "not needed in split mode".to_owned()
            },
        ),
        format!(
            "routes          {} {}",
            word(!armed || facts.quick_active == "active"),
            if facts.quick_active == "active" {
                "applied".to_owned()
            } else if armed {
                "inactive — full tunnel without routes".to_owned()
            } else {
                "not needed in split mode".to_owned()
            },
        ),
        format!("restarts        {}", facts.restarts),
    ];
    if !facts.last_death.is_empty() {
        out.push(format!("last exit: {}", facts.last_death));
    }
    if let Some(since) = &facts.down_since {
        out.push(format!("down since: {since}"));
    }
    out
}

fn word(ok: bool) -> &'static str {
    if ok {
        "ok  "
    } else {
        "fail"
    }
}

fn systemctl(args: &[&str]) -> String {
    Command::new("systemctl")
        .args(args)
        .output()
        .ok()
        .map(|out| {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            text.trim().to_owned()
        })
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn route_device(address: &str, v6: bool) -> Option<String> {
    let mut command = Command::new("ip");
    command.arg(if v6 { "-6" } else { "-4" });
    command.args(["route", "get", address]);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();
    fields
        .iter()
        .position(|field| *field == "dev")
        .and_then(|at| fields.get(at + 1))
        .map(|dev| (*dev).to_owned())
}

fn link_dns_servers(interface: &str) -> Vec<String> {
    Command::new("resolvectl")
        .args(["dns", interface])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| {
            text.lines()
                .next()
                .and_then(|line| line.split_once(':'))
                .map(|(_, tail)| tail.to_owned())
        })
        .map(|tail| {
            tail.split_whitespace()
                .filter(|token| token.parse::<std::net::IpAddr>().is_ok())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn nameservers() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|text| {
            text.lines()
                .filter_map(|line| line.trim().strip_prefix("nameserver "))
                .map(|server| server.trim().to_owned())
                .filter(|server| !server.is_empty())
                .collect()
        })
        .unwrap_or_default()
}
