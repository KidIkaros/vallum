// SPDX-License-Identifier: Apache-2.0

//! Route management: derive the routes a config needs, plan the exact `ip`
//! invocations, record them on install and reverse them on teardown.
//!
//! Stored verbatim from the original single-file layout; see `main.rs` for
//! how a command drives these.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use vallum_config::Config;
pub(crate) use vallum_core::Prefix;

/// The peer prefixes this host must route.
///
/// A prefix the interface's own address already covers is skipped: on a server
/// `allowed_ips = ["10.7.0.2/32"]` is inside the interface's `10.7.0.1/24`, so
/// `attach` is a no-op there and only the client's default route is added.
pub(crate) fn managed_routes(
    config: &Config,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> Result<Vec<Prefix>, Box<dyn std::error::Error>> {
    if table == "off" {
        return Ok(Vec::new());
    }
    let own = interface_networks(interface, dry_run)?;
    let mut routes = Vec::new();
    for peer in &config.peers {
        for prefix in &peer.allowed_ips {
            let prefix: Prefix = prefix.parse()?;
            if own.iter().any(|network| covers(network, &prefix)) {
                continue;
            }
            routes.push(prefix);
        }
    }
    Ok(routes)
}

/// The routing table a full tunnel keeps its default route in.
pub(crate) const POLICY_TABLE: &str = "51820";

/// A full-tunnel route plan, or `None` when no managed route is a default.
///
/// A default route cannot go in the main table: it would beat every other
/// default regardless of metric, and a dead tunnel becomes a dead internet.
/// WireGuard's model avoids that — the default lives in its own table, `not
/// fwmark <mark>` sends all unmarked traffic there, and `suppress_prefixlength
/// 0` leaves every non-default route to the main table. The daemon marks its
/// own UDP packets (`[interface] fwmark` → `SO_MARK`), so its handshake and
/// data escape to the real gateway while everything else enters the tunnel.
#[derive(Debug)]
pub(crate) struct Policy {
    pub(crate) table: String,
    pub(crate) mark: u32,
    pub(crate) v4: bool,
    pub(crate) v6: bool,
}

/// Whether a default route is among the managed routes, and if so the policy
/// needed to install it safely.
pub(crate) fn policy_for(
    config: &Config,
    routes: &[Prefix],
    table: &str,
) -> Result<Option<Policy>, Box<dyn std::error::Error>> {
    if !routes
        .iter()
        .any(|prefix| prefix.as_ipnet().prefix_len() == 0)
    {
        return Ok(None);
    }
    if table == "off" {
        return Err("a full tunnel (allowed_ips 0.0.0.0/0) cannot use [quick] table = off".into());
    }
    let mark = config.interface.fwmark.filter(|mark| *mark != 0).ok_or(
        "a full tunnel (allowed_ips 0.0.0.0/0) needs `[interface] fwmark` so the \
             tunnel's own packets can reach the real gateway; set e.g. `fwmark = 51820` \
             in the config, or a dead tunnel leaves this host with no route at all",
    )?;
    Ok(Some(Policy {
        table: if table == "auto" {
            POLICY_TABLE.to_owned()
        } else {
            table.to_owned()
        },
        mark,
        v4: routes
            .iter()
            .any(|p| matches!(p.as_ipnet(), ipnet::IpNet::V4(net) if net.prefix_len() == 0)),
        v6: routes
            .iter()
            .any(|p| matches!(p.as_ipnet(), ipnet::IpNet::V6(net) if net.prefix_len() == 0)),
    }))
}

/// Where an attach records the plan it executed.
///
/// Not `/run/vallum`: that directory is cleared at boot, and a teardown that
/// runs after a reboot still needs the record to know what to remove. Not
/// `/etc/vallum` either: this is state, not configuration.
const STATE_DIR: &str = "/var/lib/vallum";

fn state_dir() -> PathBuf {
    // Overridable for the same reason `VALLUM_BIN` is: a test harness needs to
    // exercise the record without writing to the host's `/var/lib`.
    std::env::var_os("VALLUM_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(STATE_DIR))
}

pub(crate) fn state_path(interface: &str) -> PathBuf {
    state_dir().join(format!("{interface}.quick"))
}

pub(crate) fn read_plan(path: &Path) -> Option<RoutePlan> {
    let plan = RoutePlan::parse(&fs::read_to_string(path).ok()?);
    if plan.commands.is_empty() {
        None
    } else {
        Some(plan)
    }
}

fn write_plan(path: &Path, plan: &RoutePlan) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, plan.render())?;
    Ok(())
}

/// The exact `ip` invocations an attach performs, and the record of them that
/// teardown replays in reverse.
///
/// Teardown used to re-derive the plan from the config, so any edit made
/// between attach and detach — a narrowed `allowed_ips`, a cleared `fwmark`, a
/// changed `[quick] table` — made `policy_for` return `None` and the policy
/// rules were never removed. One of those rules suppresses the main table's
/// default route, so the host kept its gateway and lost the internet until it
/// was rebooted. The plan is recorded and reversed verbatim instead.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RoutePlan {
    pub(crate) commands: Vec<Vec<String>>,
}

impl RoutePlan {
    fn rule(&mut self, v6: bool, args: &[&str]) {
        let mut command: Vec<String> = Vec::with_capacity(args.len() + 1);
        if v6 {
            command.push("-6".to_owned());
        }
        command.extend(args.iter().map(|arg| (*arg).to_owned()));
        self.commands.push(command);
    }

    fn route(&mut self, interface: &str, prefix: &Prefix, table: &str) {
        let mut command: Vec<String> = Vec::new();
        if matches!(prefix.as_ipnet(), ipnet::IpNet::V6(_)) {
            command.push("-6".to_owned());
        }
        command.extend(["route", "add", &prefix.to_string(), "dev", interface].map(str::to_owned));
        if table != "auto" && table != "off" {
            command.extend(["table".to_owned(), table.to_owned()]);
        }
        self.commands.push(command);
    }

    fn blackhole(&mut self, prefix: &Prefix, table: &str) {
        let mut command: Vec<String> = Vec::new();
        if matches!(prefix.as_ipnet(), ipnet::IpNet::V6(_)) {
            command.push("-6".to_owned());
        }
        command.extend(["route", "replace", "blackhole", &prefix.to_string()].map(str::to_owned));
        if table != "auto" && table != "off" {
            command.extend(["table".to_owned(), table.to_owned()]);
        }
        self.commands.push(command);
    }

    /// `add`/`replace` → `del`, last command first: installation order reversed.
    pub(crate) fn reversed(&self) -> Self {
        let mut commands: Vec<Vec<String>> = self.commands.iter().rev().cloned().collect();
        for command in &mut commands {
            if let Some(verb) = command
                .iter_mut()
                .find(|arg| *arg == "add" || *arg == "del" || *arg == "replace")
            {
                *verb = if *verb == "add" || *verb == "replace" {
                    "del".to_owned()
                } else {
                    "add".to_owned()
                };
            }
        }
        Self { commands }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        for command in &self.commands {
            out.push_str(&command.join(" "));
            out.push('\n');
        }
        out
    }

    pub(crate) fn parse(text: &str) -> Self {
        Self {
            commands: text
                .lines()
                .map(|line| {
                    line.split_whitespace()
                        .map(str::to_owned)
                        .collect::<Vec<String>>()
                })
                .filter(|command| !command.is_empty())
                .collect(),
        }
    }

    /// The two policy rules a full tunnel's default route needs, in the order
    /// they are installed: the lookup rule, then the suppression of the main
    /// table's own default.
    fn policy_rules(&mut self, policy: &Policy) {
        let mark = policy.mark.to_string();
        for v6 in [false, true] {
            if (v6 && !policy.v6) || (!v6 && !policy.v4) {
                continue;
            }
            self.rule(
                v6,
                &[
                    "rule",
                    "add",
                    "not",
                    "fwmark",
                    &mark,
                    "table",
                    &policy.table,
                ],
            );
            self.rule(
                v6,
                &["rule", "add", "table", "main", "suppress_prefixlength", "0"],
            );
        }
    }

    /// The routing table a prefix goes into: a full tunnel's default route
    /// lives in the policy table, everything else in whatever the caller said.
    fn route_table<'a>(prefix: &Prefix, policy: Option<&'a Policy>, table: &'a str) -> &'a str {
        match policy {
            Some(policy) if prefix.as_ipnet().prefix_len() == 0 => policy.table.as_str(),
            _ => table,
        }
    }

    /// Every command must succeed: a half-applied plan is the failure this
    /// type exists to prevent.
    ///
    /// The one exception is a route that already points where this one would.
    /// A restarted unit, or a host that already owns the prefix on the same
    /// interface, should be a no-op rather than `RTNETLINK answers: File
    /// exists` and a failed unit. A prefix routed via *anything else* keeps
    /// failing, because that is a real conflict.
    pub(crate) fn run(&self, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
        for command in &self.commands {
            match ip(command, dry_run) {
                Ok(()) => {}
                Err(error) => {
                    if !dry_run && route_already_present(command) {
                        continue;
                    }
                    if !dry_run && is_route_add(command) {
                        let mut replace_cmd = command.clone();
                        if let Some(pos) = replace_cmd.iter().position(|arg| arg == "add") {
                            replace_cmd[pos] = "replace".to_owned();
                            if ip(&replace_cmd, dry_run).is_ok() {
                                continue;
                            }
                        }
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Removing something that is not there is not a failure.
    pub(crate) fn run_lenient(&self, dry_run: bool) {
        for command in &self.commands {
            let _ = ip(command, dry_run);
        }
    }
}

fn is_route_add(command: &[String]) -> bool {
    command.iter().any(|arg| arg == "route") && command.iter().any(|arg| arg == "add")
}

/// Whether a failed `ip route add` is already satisfied by a route to the same
/// prefix via the same interface.
///
/// Only that case is a no-op. A prefix routed via something else is a real
/// conflict and keeps its own error.
fn route_already_present(command: &[String]) -> bool {
    let (Some(query), Some(dev)) = (route_query(command), dev_of(command)) else {
        return false;
    };
    let Ok(output) = Command::new("ip").args(&query).output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair[0] == "dev" && pair[1] == dev)
    })
}

/// The `ip route show` query that answers whether `command`'s route exists.
///
/// `None` for anything that is not a route add: a failed rule add is never
/// idempotent, and guessing otherwise is how a half-applied plan gets waved
/// through.
pub(crate) fn route_query(command: &[String]) -> Option<Vec<String>> {
    if !command.iter().any(|arg| arg == "route") {
        return None;
    }
    let mut v6 = false;
    let mut prefix = None;
    let mut table = None;
    let mut index = 0;
    while index < command.len() {
        match command[index].as_str() {
            "-6" => v6 = true,
            "add" => prefix = command.get(index + 1).cloned(),
            "table" => table = command.get(index + 1).cloned(),
            _ => {}
        }
        index += 1;
    }
    let mut query: Vec<String> = Vec::new();
    if v6 {
        query.push("-6".to_owned());
    }
    query.extend([
        "-o".to_owned(),
        "route".to_owned(),
        "show".to_owned(),
        prefix?,
    ]);
    if let Some(table) = table {
        query.extend(["table".to_owned(), table]);
    }
    Some(query)
}

pub(crate) fn dev_of(command: &[String]) -> Option<&str> {
    let index = command.iter().position(|arg| arg == "dev")?;
    command.get(index + 1).map(String::as_str)
}

/// Everything an attach installs, in order, without touching the host.
pub(crate) fn plan_routes(
    config: &Config,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> Result<RoutePlan, Box<dyn std::error::Error>> {
    let routes = managed_routes(config, interface, table, dry_run)?;
    let policy = policy_for(config, &routes, table)?;
    let mut plan = RoutePlan::default();
    if let Some(policy) = &policy {
        // Rules before routes, so no lookup can find an empty table.
        plan.policy_rules(policy);
    }
    for prefix in &routes {
        let route_table = RoutePlan::route_table(prefix, policy.as_ref(), table);
        plan.route(interface, prefix, route_table);
    }
    Ok(plan)
}

/// Blackhole routes installed on session failure (fail-closed).
pub(crate) fn plan_blackhole_routes(
    config: &Config,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> Result<RoutePlan, Box<dyn std::error::Error>> {
    let routes = managed_routes(config, interface, table, dry_run)?;
    let policy = policy_for(config, &routes, table)?;
    let mut plan = RoutePlan::default();
    for prefix in &routes {
        let route_table = RoutePlan::route_table(prefix, policy.as_ref(), table);
        plan.blackhole(prefix, route_table);
    }
    Ok(plan)
}

pub(crate) fn apply_blackhole_routes(config: &Config, interface: &str, table: &str, dry_run: bool) {
    if table == "off" {
        return;
    }
    if let Ok(plan) = plan_blackhole_routes(config, interface, table, dry_run) {
        let _ = plan.run(dry_run);
    }
}

/// Install the routes, and policy rules if a default route is among them.
pub(crate) fn apply_routes(
    config: &Config,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if table == "off" {
        return Ok(());
    }
    let path = state_path(interface);
    // Undo a previous attach first: `ip rule add` does not dedupe, so a second
    // attach would otherwise stack a duplicate of every policy rule.
    if let Some(previous) = read_plan(&path) {
        previous.reversed().run_lenient(dry_run);
    }

    let plan = plan_routes(config, interface, table, dry_run)?;
    if !dry_run {
        // Recorded before it runs: a plan that fails halfway still has to be
        // reversible, and a failed attach is exactly when teardown matters.
        write_plan(&path, &plan)?;
    }
    plan.run(dry_run)
}

/// What teardown executes: the recorded plan reversed, or — for an install
/// made before the record existed — one re-derived from the config.
///
/// The two are not equivalent, which is the whole point. A config edited
/// between attach and detach re-derives to *nothing*, so the recorded plan
/// wins whenever there is one.
pub(crate) fn teardown_plan(
    recorded: Option<&RoutePlan>,
    config: &Config,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> RoutePlan {
    if let Some(plan) = recorded {
        return plan.reversed();
    }
    // No record: the config is the only evidence left. This is the path that
    // stranded rules on a config edit; it is kept solely to clean up after
    // installs made before the record existed.
    let routes = managed_routes(config, interface, table, dry_run).unwrap_or_default();
    let mut plan = RoutePlan::default();
    if let Some(policy) = policy_for(config, &routes, table).ok().flatten() {
        for prefix in &routes {
            if prefix.as_ipnet().prefix_len() == 0 {
                plan.route(interface, prefix, &policy.table);
            }
        }
        plan.policy_rules(&policy);
    }
    for prefix in &routes {
        if prefix.as_ipnet().prefix_len() != 0 {
            plan.route(interface, prefix, table);
        }
    }
    plan.reversed()
}

/// Undo [`apply_routes`] — what was installed, not what the config now implies.
pub(crate) fn remove_routes(config: &Config, interface: &str, table: &str, dry_run: bool) {
    if table == "off" {
        return;
    }
    let path = state_path(interface);
    let recorded = read_plan(&path);
    let plan = teardown_plan(recorded.as_ref(), config, interface, table, dry_run);
    plan.run_lenient(dry_run);
    if let Ok(blackholes) = plan_blackhole_routes(config, interface, table, dry_run) {
        blackholes.reversed().run_lenient(dry_run);
    }
    if recorded.is_some() && !dry_run {
        let _ = fs::remove_file(&path);
    }
}

/// The networks already assigned to the interface.
///
/// Under `--dry-run` the interface may not exist, so nothing is read and every
/// route is printed — the plan the operator is being shown.
fn interface_networks(
    interface: &str,
    dry_run: bool,
) -> Result<Vec<ipnet::IpNet>, Box<dyn std::error::Error>> {
    if dry_run {
        return Ok(Vec::new());
    }
    let output = Command::new("ip")
        .args(["-o", "addr", "show", "dev", interface])
        .output()?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut networks = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        for (index, field) in fields.iter().enumerate() {
            if (*field == "inet" || *field == "inet6") && fields.get(index + 1).is_some() {
                if let Ok(network) = fields[index + 1].parse::<ipnet::IpNet>() {
                    networks.push(network);
                }
            }
        }
    }
    Ok(networks)
}

/// Whether `outer` contains every address in `inner`.
pub(crate) fn covers(outer: &ipnet::IpNet, inner: &Prefix) -> bool {
    let inner = inner.as_ipnet();
    outer.addr().is_ipv4() == inner.addr().is_ipv4()
        && outer.prefix_len() <= inner.prefix_len()
        && outer.contains(&inner.addr())
}

fn ip(args: &[String], dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if dry_run {
        println!("ip {}", args.join(" "));
        return Ok(());
    }
    let status = Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(format!("ip {} failed", args.join(" ")).into());
    }
    Ok(())
}
