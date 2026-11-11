//! Host facts and the plan-before-apply computation — the console's inner ring.
//!
//! Everything here answers one question: "what is this host actually doing,
//! and what would arming the full tunnel change about it?" Every fact is
//! measured from the host, never inferred from a config: a config that says
//! `0.0.0.0/0` and a route that says `wlp0s20f3` are the difference between a
//! product and a claim.
//!
//! Layering (clean architecture): the measurement functions touch the world
//! (`ip`, `resolvectl`, `systemctl`, the filesystem) and nothing else does;
//! [`plan_from_facts`] is a pure function over the measured facts and is the
//! only part with unit tests, because it is the only part with decisions in it.

use serde_json::json;

/// The measured state of one tunnel interface and the host around it.
#[derive(Debug, Clone)]
pub(crate) struct HostFacts {
    pub unit: String,
    pub interface: String,
    pub route4: Option<String>,
    pub route6: Option<String>,
    pub dns: Vec<String>,
    pub dns_upstream: Vec<String>,
    pub restarts: u64,
    pub last_death: String,
    pub guard_active: String,
    pub quick_active: String,
}

impl HostFacts {
    pub fn route4_via_tunnel(&self) -> bool {
        self.route4.as_deref() == Some(self.interface.as_str())
    }

    pub fn route6_via_tunnel(&self) -> bool {
        self.route6.as_deref() == Some(self.interface.as_str())
    }

    /// The system resolver is usually systemd-resolved's stub (127.0.0.53);
    /// what decides "DNS rides the tunnel" is whether the tunnel LINK carries
    /// upstream servers — resolved forwards there. Reading only resolv.conf
    /// turns a working setup into a false FAIL.
    pub fn dns_via_tunnel(&self) -> bool {
        !self.dns.is_empty()
            && (!self.dns_upstream.is_empty() || self.route_via(self.dns.first()))
    }

    fn route_via(&self, server: Option<&String>) -> bool {
        match server {
            Some(server) => route_device(server, server.contains(':')).as_deref()
                == Some(self.interface.as_str()),
            None => false,
        }
    }
}

/// Read the host: routes, resolvers, unit state, the last death.
pub(crate) fn measure(socket: &std::path::Path) -> HostFacts {
    let unit = crate::unit_for(socket);
    let interface = socket
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
        .to_owned();
    let quick = format!("vallum-quick@{interface}");
    let guard = format!("vallum-guard@{interface}");

    let route4 = route_device("1.1.1.1", false);
    let route6 = route_device("2001:4860:4860::8888", true);
    let servers = nameservers();
    let link_dns = link_dns_servers(&interface);

    let show = std::process::Command::new("systemctl")
        .args(["show", &unit, "-p", "NRestarts", "-p", "ExecMainStatus"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default();
    let field = |name: &str| -> Option<String> {
        show.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .map(str::to_owned)
    };
    let restarts: u64 = field("NRestarts").and_then(|v| v.parse().ok()).unwrap_or(0);

    let last_death = std::process::Command::new("journalctl")
        .args(["-u", &unit, "-n", "400", "--no-pager", "-o", "cat"])
        .output()
        .ok()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|line| {
                    line.contains("status=31/SYS")
                        || line.contains("Failed with result")
                        || line.contains("Main process exited")
                })
                .next_back()
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .unwrap_or_default();

    HostFacts {
        unit,
        interface,
        route4,
        route6,
        dns: servers,
        dns_upstream: link_dns,
        restarts,
        last_death,
        guard_active: crate::systemctl(&["is-active", &guard])
            .unwrap_or_else(|| "unknown".to_owned()),
        quick_active: crate::systemctl(&["is-active", &quick])
            .unwrap_or_else(|| "unknown".to_owned()),
    }
}

/// The wire form the cockpit renders. Plain data across the boundary; the
/// facts themselves stay a struct.
pub(crate) fn health_json(facts: &HostFacts) -> serde_json::Value {
    json!({
        "unit": facts.unit,
        "interface": facts.interface,
        "route4": facts.route4,
        "route4_via_tunnel": facts.route4_via_tunnel(),
        "route6": facts.route6,
        "route6_via_tunnel": facts.route6_via_tunnel(),
        "dns": facts.dns,
        "dns_via_tunnel": facts.dns_via_tunnel(),
        "dns_upstream": facts.dns_upstream,
        "restarts": facts.restarts,
        "last_death": facts.last_death,
        "guard": {
            "unit": format!("vallum-guard@{}", facts.interface),
            "active": facts.guard_active,
        },
        "quick": {
            "unit": format!("vallum-quick@{}", facts.interface),
            "active": facts.quick_active,
        },
    })
}

/// Same measurement, wire form: the console's health answer.
pub(crate) fn health(socket: &std::path::Path) -> serde_json::Value {
    let facts = measure(socket);
    health_json(&facts)
}

/// The plan-before-apply payload: what the full tunnel will change on THIS
/// host, measured now — plus the one command that undoes all of it. The UI
/// must show this and take a typed confirmation before the apply button arms.
pub(crate) fn plan(socket: &std::path::Path) -> serde_json::Value {
    let facts = measure(socket);
    let already_full = match crate::snapshot::fetch(socket) {
        Ok(snap) => snap
            .peers
            .iter()
            .any(|peer| peer.allowed_ips.iter().any(|ip| ip == "0.0.0.0/0")),
        Err(_) => false,
    };
    plan_from_facts(&facts, already_full)
}

/// Pure: the plan is a function of the measured facts and whether the tunnel
/// is already full. This is the decision; everything else around it is IO.
pub(crate) fn plan_from_facts(facts: &HostFacts, already_full: bool) -> serde_json::Value {
    let interface = facts.interface.clone();
    json!({
        "already_full": already_full,
        "interface": interface,
        "current": {
            "route4": facts.route4,
            "route4_via_tunnel": facts.route4_via_tunnel(),
            "dns_via_tunnel": facts.dns_via_tunnel(),
            "guard": facts.guard_active,
        },
        "steps": [
            {"step": "save the split config", "change": "backed up to /etc/vallum/vallum0.split.bak"},
            {"step": "switch to the full-tunnel config", "change": "peer allowed_ips becomes 0.0.0.0/0, fwmark 51820, DNS attached to the tunnel link"},
            {"step": "restart the daemon", "change": "handshake must return within 45 s or the change reverts automatically"},
            {"step": "arm the dead-man", "change": "checks every 10 s; a dead tunnel drops the egress block and restores DNS"},
            {"step": "trial with a 90 s deadline", "change": "guard on, routes and DNS applied, every check verified — any failure reverts and restores the split tunnel"},
        ],
        "undo": "sudo vallum-panic; sudo cp /etc/vallum/vallum0.split.bak /etc/vallum/vallum0.toml; sudo systemctl restart vallum@vallum0",
    })
}

/// The control-surface write gate. Every endpoint that can change host state
/// or touch the tunnel refuses to act unless the control socket is 0600 and
/// the runtime directory is not world-writable. A wider socket mode exposes
/// `--dump` (the private key) to every local user, so writes fail loudly
/// rather than succeed silently in a broken deployment.
pub(crate) fn write_gate(socket: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(socket)
        .map_err(|error| format!("control socket unreadable: {error}"))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "control socket is {:o}, not 0600 — writes refused: a wider mode exposes --dump (the private key)",
            mode
        ));
    }
    if let Some(dir) = socket.parent() {
        if let Ok(dir_meta) = std::fs::metadata(dir) {
            if dir_meta.permissions().mode() & 0o002 != 0 {
                return Err("runtime directory is world-writable — writes refused".to_owned());
            }
        }
    }
    Ok(())
}

fn link_dns_servers(interface: &str) -> Vec<String> {
    std::process::Command::new("resolvectl")
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

fn route_device(address: &str, v6: bool) -> Option<String> {
    let mut command = std::process::Command::new("ip");
    command.arg(if v6 { "-6" } else { "-4" });
    command.args(["route", "get", address]);
    let output = command.output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();
    fields
        .iter()
        .position(|field| *field == "dev")
        .and_then(|at| fields.get(at + 1))
        .map(|dev| (*dev).to_owned())
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

#[cfg(test)]
mod plan_tests {
    use super::HostFacts;

    fn facts(route4: &str, via_tunnel: bool) -> HostFacts {
        HostFacts {
            unit: "vallum@vallum0".to_owned(),
            interface: "vallum0".to_owned(),
            route4: Some(route4.to_owned()),
            route6: Some("wlp0s20f3".to_owned()),
            dns: vec!["127.0.0.53".to_owned()],
            dns_upstream: if via_tunnel { vec!["1.1.1.1".to_owned()] } else { vec![] },
            restarts: 0,
            last_death: String::new(),
            guard_active: "inactive".to_owned(),
            quick_active: "inactive".to_owned(),
        }
    }

    #[test]
    fn plan_on_a_split_host_names_the_changes_and_the_undo() {
        let plan = super::plan_from_facts(&facts("wlp0s20f3", false), false);
        assert_eq!(plan["already_full"], false);
        assert!(plan["undo"].as_str().unwrap().contains("vallum-panic"));
        assert_eq!(plan["steps"].as_array().map(Vec::len), Some(5));
    }

    #[test]
    fn plan_on_a_full_tunnel_says_so() {
        let plan = super::plan_from_facts(&facts("vallum0", true), true);
        assert_eq!(plan["already_full"], true);
    }

    #[test]
    fn dns_rides_the_tunnel_only_through_a_real_upstream() {
        let via = facts("vallum0", true);
        assert!(via.dns_via_tunnel());
        let stub_only = facts("wlp0s20f3", false);
        assert!(!stub_only.dns_via_tunnel());
    }
}
