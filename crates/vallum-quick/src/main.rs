// SPDX-License-Identifier: Apache-2.0

//! `vallum-quick`: the OS-level helper.
//!
//! The daemon owns the tunnel and nothing else. This tool owns the parts that
//! are inherently distribution- and host-specific: routes, DNS, firewall/NAT,
//! and the operator's hooks. It reads the same TOML, including a `[quick]`
//! table the daemon ignores.

use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use clap::{Parser, Subcommand};
use vallum_config::{Config, ConfigError};
use vallum_tunnel::Prefix;

#[derive(Parser)]
#[command(version, about = "Bring a Vallum config up with its routes and DNS")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Start the daemon, then add routes, DNS and hooks.
    Up {
        /// The configuration file.
        config: PathBuf,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
        /// Run hooks even though this config is not root-owned (they run as
        /// root, so a config another user can edit is root execution).
        #[arg(long)]
        allow_insecure_config: bool,
    },
    /// Run the down hooks, remove routes and DNS, and stop the daemon.
    Down {
        /// The configuration file.
        config: PathBuf,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
        /// Run hooks even though this config is not root-owned (they run as
        /// root, so a config another user can edit is root execution).
        #[arg(long)]
        allow_insecure_config: bool,
    },
    /// Apply routes, DNS and hooks to an interface a supervisor already owns.
    ///
    /// This is the systemd form: `vallum@.service` starts the daemon and
    /// `vallum-quick@.service` runs `attach`, so routes and DNS are applied
    /// without spawning a second daemon or weakening the daemon's sandbox.
    Attach {
        /// The configuration file.
        config: PathBuf,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
        /// Run hooks even though this config is not root-owned (they run as
        /// root, so a config another user can edit is root execution).
        #[arg(long)]
        allow_insecure_config: bool,
    },
    /// Remove what `attach` applied, leaving the daemon running.
    Detach {
        /// The configuration file.
        config: PathBuf,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
        /// Run hooks even though this config is not root-owned (they run as
        /// root, so a config another user can edit is root execution).
        #[arg(long)]
        allow_insecure_config: bool,
    },
    /// Print the config without its `[quick]` table.
    Strip {
        /// The configuration file.
        config: PathBuf,
    },
    /// Export the running daemon as a config (via `vallum showconf`).
    Save {
        /// The configuration file, for its `control` path.
        config: PathBuf,
        /// Write to this file instead of stdout. Never the config itself.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Include the private-key path and preshared keys in the export.
        #[arg(long)]
        include_secrets: bool,
        /// Replace the config with the export, keeping a `.bak`.
        #[arg(long)]
        in_place: bool,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let outcome = match &cli.command {
        Action::Up {
            config,
            dry_run,
            allow_insecure_config,
        } => up(config, *dry_run, *allow_insecure_config),
        Action::Down {
            config,
            dry_run,
            allow_insecure_config,
        } => down(config, *dry_run, *allow_insecure_config),
        Action::Attach {
            config,
            dry_run,
            allow_insecure_config,
        } => attach(config, *dry_run, *allow_insecure_config),
        Action::Detach {
            config,
            dry_run,
            allow_insecure_config,
        } => detach(config, *dry_run, *allow_insecure_config),
        Action::Strip { config } => strip(config),
        Action::Save {
            config,
            output,
            include_secrets,
            in_place,
        } => save(config, output.as_deref(), *include_secrets, *in_place),
    };
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vallum-quick: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Load a config the way materialization would have written it.
///
/// The completed mark lives in the returned value only. Persisting it is a
/// separate, explicit step ([`heal_config_on_disk`]) because a command that
/// prints its plan must not edit the file it read, and a config another user
/// can edit must not be rewritten before that is refused.
fn load_normalized(config_path: &Path) -> Result<Config, ConfigError> {
    Config::load_normalized(config_path)
}

/// Persist the completed local routing mark so every later tool — `down`,
/// `detach`, `vallum uninstall` — computes the same one this attach used.
fn heal_config_on_disk(config_path: &Path, dry_run: bool) {
    if dry_run {
        return;
    }
    let Ok(text) = std::fs::read_to_string(config_path) else {
        return;
    };
    let normalized = vallum_config::with_local_fwmark(&text);
    if normalized != text {
        let _ = std::fs::write(config_path, normalized);
    }
}

fn up(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_normalized(config_path)?;
    check_config_ownership(config_path, &config, allow_insecure_config)?;
    heal_config_on_disk(config_path, dry_run);
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    for hook in &config.quick.pre_up {
        run_hook(hook, dry_run)?;
    }

    let result = up_after_pre(&config, config_path, &interface, table, dry_run);
    if result.is_err() {
        // A partially applied `up` must not leave a daemon or routes behind.
        rollback(&config, config_path, &interface, table, dry_run);
    }
    result
}

fn up_after_pre(
    config: &Config,
    config_path: &Path,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // The daemon first: it creates the interface the routes point at.
    let binary = std::env::var("VALLUM_BIN").unwrap_or_else(|_| "vallum".to_owned());
    let mut child = if dry_run {
        println!("{binary} run --config {}", config_path.display());
        None
    } else {
        let child = Command::new(&binary)
            .arg("run")
            .arg("--config")
            .arg(config_path)
            .spawn()?;
        let pidfile = config_path.with_extension("pid");
        if let Err(error) = fs::write(&pidfile, child.id().to_string()) {
            // The pidfile failed after the daemon started; do not leave it
            // orphaned.
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        Some(child)
    };

    if !dry_run {
        wait_for_interface(interface)?;
        wait_for_session(config, config_path, interface)?;
    }

    apply_routes(config, interface, table, dry_run)?;

    if !config.quick.dns.is_empty() {
        set_dns(
            interface,
            &config.quick.dns,
            dns_domain(config).as_deref(),
            dry_run,
        )?;
    }

    for hook in &config.quick.post_up {
        run_hook(hook, dry_run)?;
    }

    if let Some(mut child) = child.take() {
        // A short-lived daemon is a failure; report it rather than leaving a
        // pidfile pointing at nothing.
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("vallum exited during startup: {status}").into());
        }
    }
    Ok(())
}

/// Undo whatever a failed `up` may have applied.
fn rollback(config: &Config, config_path: &Path, interface: &str, table: &str, dry_run: bool) {
    remove_routes(config, interface, table, dry_run);
    if !config.quick.dns.is_empty() {
        let _ = unset_dns(interface, dry_run);
    }
    let pidfile = config_path.with_extension("pid");
    if let Ok(pid) = fs::read_to_string(&pidfile) {
        let pid = pid.trim();
        if dry_run {
            println!("kill -TERM {pid}");
        } else {
            let _ = Command::new("kill").arg("-TERM").arg(pid).status();
        }
    }
    if !dry_run {
        let _ = fs::remove_file(&pidfile);
    }
}

fn down(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_normalized(config_path)?;
    check_config_ownership(config_path, &config, allow_insecure_config)?;
    heal_config_on_disk(config_path, dry_run);
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    for hook in &config.quick.pre_down {
        run_hook(hook, dry_run)?;
    }

    remove_routes(&config, &interface, table, dry_run);
    if !config.quick.dns.is_empty() {
        unset_dns(&interface, dry_run)?;
    }

    let pidfile = config_path.with_extension("pid");
    if let Ok(pid) = fs::read_to_string(&pidfile) {
        let pid = pid.trim();
        if dry_run {
            println!("kill -TERM {pid}");
        } else {
            let _ = Command::new("kill").arg("-TERM").arg(pid).status();
            let _ = fs::remove_file(&pidfile);
        }
    }

    for hook in &config.quick.post_down {
        run_hook(hook, dry_run)?;
    }
    Ok(())
}

/// Apply the config's host-level work to an interface someone else started.
///
/// `vallum@.service` owns the daemon and `vallum-quick@.service` runs this, so
/// routes and DNS are applied without spawning a second daemon and without
/// widening the daemon's sandbox to let it write `/etc/resolv.conf`.
fn attach(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_normalized(config_path)?;
    check_config_ownership(config_path, &config, allow_insecure_config)?;
    heal_config_on_disk(config_path, dry_run);
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    for hook in &config.quick.pre_up {
        run_hook(hook, dry_run)?;
    }

    if !dry_run {
        wait_for_interface(&interface)?;
        wait_for_session(&config, config_path, &interface)?;
    }

    apply_routes(&config, &interface, table, dry_run)?;

    if !config.quick.dns.is_empty() {
        set_dns(
            &interface,
            &config.quick.dns,
            dns_domain(&config).as_deref(),
            dry_run,
        )?;
    }

    for hook in &config.quick.post_up {
        run_hook(hook, dry_run)?;
    }
    Ok(())
}

/// Remove what [`attach`] applied, leaving the daemon running.
fn detach(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_normalized(config_path)?;
    check_config_ownership(config_path, &config, allow_insecure_config)?;
    heal_config_on_disk(config_path, dry_run);
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    for hook in &config.quick.pre_down {
        run_hook(hook, dry_run)?;
    }

    remove_routes(&config, &interface, table, dry_run);

    if !config.quick.dns.is_empty() {
        unset_dns(&interface, dry_run)?;
    }

    for hook in &config.quick.post_down {
        run_hook(hook, dry_run)?;
    }
    Ok(())
}

/// The peer prefixes this host must route.
///
/// A prefix the interface's own address already covers is skipped: on a server
/// `allowed_ips = ["10.7.0.2/32"]` is inside the interface's `10.7.0.1/24`, so
/// `attach` is a no-op there and only the client's default route is added.
fn managed_routes(
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
const POLICY_TABLE: &str = "51820";

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
struct Policy {
    table: String,
    mark: u32,
    v4: bool,
    v6: bool,
}

/// Whether a default route is among the managed routes, and if so the policy
/// needed to install it safely.
fn policy_for(
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
        "a full tunnel (allowed_ips 0.0.0.0/0) needs `[interface] fwmark` so the          tunnel's own packets can reach the real gateway; set e.g. `fwmark = 51820`          in the config, or a dead tunnel leaves this host with no route at all",
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
/// Not `/run/vallum`: that is the daemon's `RuntimeDirectory`, and systemd
/// deletes it when the daemon stops — exactly when teardown needs the record.
/// Not `/etc/vallum` either: this is state, not configuration.
const STATE_DIR: &str = "/var/lib/vallum";

fn state_dir() -> PathBuf {
    // Overridable for the same reason `VALLUM_BIN` is: a test harness needs to
    // exercise the record without writing to the host's `/var/lib`.
    std::env::var_os("VALLUM_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(STATE_DIR))
}

fn state_path(interface: &str) -> PathBuf {
    state_dir().join(format!("{interface}.quick"))
}

fn read_plan(path: &Path) -> Option<RoutePlan> {
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
struct RoutePlan {
    commands: Vec<Vec<String>>,
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

    /// `add` → `del`, last command first: installation order reversed.
    fn reversed(&self) -> Self {
        let mut commands: Vec<Vec<String>> = self.commands.iter().rev().cloned().collect();
        for command in &mut commands {
            if let Some(verb) = command
                .iter_mut()
                .find(|arg| *arg == "add" || *arg == "del")
            {
                *verb = if *verb == "add" {
                    "del".to_owned()
                } else {
                    "add".to_owned()
                };
            }
        }
        Self { commands }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for command in &self.commands {
            out.push_str(&command.join(" "));
            out.push('\n');
        }
        out
    }

    fn parse(text: &str) -> Self {
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

    /// Every command must succeed: a half-applied plan is the failure this
    /// type exists to prevent.
    fn run(&self, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
        for command in &self.commands {
            ip(command, dry_run)?;
        }
        Ok(())
    }

    /// Removing something that is not there is not a failure.
    fn run_lenient(&self, dry_run: bool) {
        for command in &self.commands {
            let _ = ip(command, dry_run);
        }
    }
}

/// Everything an attach installs, in order, without touching the host.
fn plan_routes(
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
        let mark = policy.mark.to_string();
        for v6 in [false, true] {
            if (v6 && !policy.v6) || (!v6 && !policy.v4) {
                continue;
            }
            plan.rule(
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
            plan.rule(
                v6,
                &["rule", "add", "table", "main", "suppress_prefixlength", "0"],
            );
        }
    }
    for prefix in &routes {
        let route_table = match &policy {
            Some(policy) if prefix.as_ipnet().prefix_len() == 0 => policy.table.as_str(),
            _ => table,
        };
        plan.route(interface, prefix, route_table);
    }
    Ok(plan)
}

/// Install the routes, and policy rules if a default route is among them.
fn apply_routes(
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
fn teardown_plan(
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
        let mark = policy.mark.to_string();
        for v6 in [false, true] {
            if (v6 && !policy.v6) || (!v6 && !policy.v4) {
                continue;
            }
            plan.rule(
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
            plan.rule(
                v6,
                &["rule", "add", "table", "main", "suppress_prefixlength", "0"],
            );
        }
    }
    for prefix in &routes {
        if prefix.as_ipnet().prefix_len() != 0 {
            plan.route(interface, prefix, table);
        }
    }
    plan.reversed()
}

/// Undo [`apply_routes`] — what was installed, not what the config now implies.
fn remove_routes(config: &Config, interface: &str, table: &str, dry_run: bool) {
    if table == "off" {
        return;
    }
    let path = state_path(interface);
    let recorded = read_plan(&path);
    let plan = teardown_plan(recorded.as_ref(), config, interface, table, dry_run);
    plan.run_lenient(dry_run);
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
fn covers(outer: &ipnet::IpNet, inner: &Prefix) -> bool {
    let inner = inner.as_ipnet();
    outer.addr().is_ipv4() == inner.addr().is_ipv4()
        && outer.prefix_len() <= inner.prefix_len()
        && outer.contains(&inner.addr())
}

fn save(
    config_path: &Path,
    output: Option<&Path>,
    include_secrets: bool,
    in_place: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if in_place && output.is_some() {
        return Err("--in-place and --output are mutually exclusive".into());
    }
    if in_place && !include_secrets {
        return Err(
            "--in-place needs --include-secrets: without it the export would drop the \
             private-key path and every PSK"
                .into(),
        );
    }
    if !in_place && output.is_some_and(|out| out == config_path) {
        return Err(
            "refusing to overwrite the config; use --in-place, or a different --output".into(),
        );
    }
    let binary = std::env::var("VALLUM_BIN").unwrap_or_else(|_| "vallum".to_owned());
    let mut command = Command::new(&binary);
    command.args(["showconf", "--config"]).arg(config_path);
    if include_secrets {
        command.arg("--include-secrets");
    }
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!(
            "`{binary} showconf` failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        )
        .into());
    }
    if in_place {
        let new = PathBuf::from(format!("{}.new", config_path.display()));
        let backup = PathBuf::from(format!("{}.bak", config_path.display()));
        fs::write(&new, &result.stdout)?;
        fs::copy(config_path, &backup)?;
        fs::rename(&new, config_path)?;
        println!(
            "wrote {} (backup {})",
            config_path.display(),
            backup.display()
        );
    } else {
        match output {
            Some(path) => fs::write(path, &result.stdout)?,
            None => print!("{}", String::from_utf8_lossy(&result.stdout)),
        }
    }
    Ok(())
}

/// The daemon-facing form of a config: everything except `[quick]`.
fn strip_quick(text: &str) -> String {
    let mut out = String::new();
    let mut in_quick = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_quick = trimmed == "[quick]";
        }
        if !in_quick {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn strip(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let text = fs::read_to_string(config_path)?;
    print!("{}", strip_quick(&text));
    Ok(())
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

/// Which DNS mechanism this host actually has.
///
/// `resolvectl` is preferred when `systemd-resolved` is *running*, not merely
/// installed: the binary exists on hosts where resolved is disabled, and
/// calling it then fails. `resolvconf` is the fallback, and on Ubuntu 24.04 it
/// may be resolved's compatibility shim — which is why the running check comes
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsBackend {
    ResolveCtl,
    ResolvConf,
    None,
}

fn dns_backend_from(present: impl Fn(&str) -> bool, resolved_running: bool) -> DnsBackend {
    if present("resolvectl") && resolved_running {
        DnsBackend::ResolveCtl
    } else if present("resolvconf") {
        DnsBackend::ResolvConf
    } else {
        DnsBackend::None
    }
}

fn dns_backend() -> DnsBackend {
    dns_backend_from(
        |program| which(program).is_some(),
        Path::new("/run/systemd/resolve").exists(),
    )
}

/// The routing domain to claim, if the interface should own name resolution.
///
/// `~.` is what stops a full tunnel from leaking queries to the local resolver.
/// A split tunnel wants no domain, so nothing is claimed unless the operator
/// asked for one or the config routes everything.
fn dns_domain(config: &Config) -> Option<String> {
    if let Some(domain) = &config.quick.dns_domain {
        return Some(domain.clone());
    }
    let full_tunnel = config
        .peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.iter())
        .any(|prefix| {
            prefix
                .parse::<Prefix>()
                .is_ok_and(|prefix| prefix.as_ipnet().prefix_len() == 0)
        });
    full_tunnel.then(|| "~.".to_owned())
}

fn set_dns(
    interface: &str,
    servers: &[String],
    domain: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match dns_backend() {
        DnsBackend::ResolveCtl => {
            let mut args = vec!["dns".to_owned(), interface.to_owned()];
            args.extend(servers.iter().cloned());
            if dry_run {
                println!("resolvectl {}", args.join(" "));
            } else {
                let status = Command::new("resolvectl").args(&args).status()?;
                if !status.success() {
                    return Err("resolvectl dns failed".into());
                }
            }
            if let Some(domain) = domain {
                if dry_run {
                    println!("resolvectl domain {interface} {domain}");
                } else {
                    let status = Command::new("resolvectl")
                        .args(["domain", interface, domain])
                        .status()?;
                    if !status.success() {
                        return Err("resolvectl domain failed".into());
                    }
                }
            }
            Ok(())
        }
        DnsBackend::ResolvConf => {
            let body: String = servers
                .iter()
                .map(|server| format!("nameserver {server}\n"))
                .collect();
            if dry_run {
                println!("resolvconf -a {interface} <<EOF\n{body}EOF");
                return Ok(());
            }
            let mut child = Command::new("resolvconf")
                .arg("-a")
                .arg(interface)
                .stdin(Stdio::piped())
                .spawn()?;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(body.as_bytes())?;
            }
            let status = child.wait()?;
            if !status.success() {
                return Err("resolvconf -a failed".into());
            }
            Ok(())
        }
        DnsBackend::None => {
            eprintln!(
                "vallum-quick: neither resolvectl nor resolvconf found; DNS left to the host"
            );
            Ok(())
        }
    }
}

fn unset_dns(interface: &str, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    match dns_backend() {
        DnsBackend::ResolveCtl => {
            if dry_run {
                println!("resolvectl revert {interface}");
                return Ok(());
            }
            let _ = Command::new("resolvectl")
                .args(["revert", interface])
                .status();
            Ok(())
        }
        DnsBackend::ResolvConf => {
            if dry_run {
                println!("resolvconf -d {interface}");
                return Ok(());
            }
            let _ = Command::new("resolvconf").arg("-d").arg(interface).status();
            Ok(())
        }
        DnsBackend::None => Ok(()),
    }
}

/// Refuse to run hooks from a config another user can edit.
///
/// `pre_up`/`post_up`/`pre_down`/`post_down` are `sh -c` strings executed as
/// root, so the config file is a privilege boundary, not just settings. The
/// installed path (`/etc/vallum/<iface>.toml`) is root-owned and `0600`; a
/// config anywhere else, or one that is group/world-writable, is refused rather
/// than silently becoming root execution. `wg-quick` has the same shape and the
/// same warning; this one fails closed.
fn check_config_ownership(
    config_path: &Path,
    config: &Config,
    allow_insecure: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    check_config_ownership_as(config_path, config, effective_uid_is_root(), allow_insecure)
        .map_err(Into::into)
}

/// Whether a config asks for any shell hooks at all.
fn has_hooks(config: &Config) -> bool {
    !(config.quick.pre_up.is_empty()
        && config.quick.post_up.is_empty()
        && config.quick.pre_down.is_empty()
        && config.quick.post_down.is_empty())
}

/// Whether this process runs as root, read without a libc dependency.
///
/// `/proc/self/status` lists real, effective, saved and filesystem uids; the
/// second is the effective one, which is what decides whether hooks escalate.
fn effective_uid_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|rest| rest.split_whitespace().nth(1).map(|uid| uid == "0"))
        })
        .unwrap_or(false)
}

fn check_config_ownership_as(
    config_path: &Path,
    config: &Config,
    is_root: bool,
    allow_insecure: bool,
) -> Result<(), String> {
    if !is_root || !has_hooks(config) {
        // Nothing escalates: either the caller keeps their own privileges, or
        // there is no hook to run as root. Routes and DNS from a user's own
        // config are not a privilege boundary.
        return Ok(());
    }
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::metadata(config_path)
        .map_err(|error| format!("read {}: {error}", config_path.display()))?;
    let owner = metadata.uid();
    let writable_by_others = metadata.permissions().mode() & 0o022 != 0;
    if owner == 0 && !writable_by_others {
        return Ok(());
    }
    if allow_insecure {
        eprintln!(
            "vallum-quick: warning: {} is owned by uid {owner} or writable by others; \
             its hooks run as root",
            config_path.display()
        );
        return Ok(());
    }
    Err(format!(
        "{} is owned by uid {owner}{} — its hooks (pre_up, post_up, …) would run as \
         root from a file another user can change.\n\
         Move it to /etc/vallum and chown root:root, or pass \
         --allow-insecure-config if you trust every writer of that path.",
        config_path.display(),
        if writable_by_others {
            " and is writable by others"
        } else {
            ""
        }
    ))
}

fn run_hook(hook: &str, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if dry_run {
        println!("sh -c {hook:?}");
        return Ok(());
    }
    let status = Command::new("sh").arg("-c").arg(hook).status()?;
    if !status.success() {
        return Err(format!("hook failed: {hook}").into());
    }
    Ok(())
}

/// Long enough for several handshake retries before a dead server is
/// declared; short enough that a failed unit reports promptly.
const SESSION_WAIT: Duration = Duration::from_secs(20);

/// Readiness is a handshake, not an interface. A full tunnel attaches by
/// policy-routing every packet through the peer — if that peer never
/// completes a handshake the host's entire egress blackholes while the
/// unit reports success. Gate route installation on a real session: poll
/// the control socket until a peer reports a handshake, then route. Split
/// tunnels skip this — a dead /24 hurts only that subnet.
fn wait_for_session(
    config: &Config,
    config_path: &Path,
    interface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let full_tunnel = config.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|ip| ip == "0.0.0.0/0" || ip == "::/0")
    });
    if !full_tunnel {
        return Ok(());
    }
    let socket = config
        .interface
        .control
        .clone()
        .map(|path| {
            if path.is_relative() {
                config_path
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .join(path)
            } else {
                path
            }
        })
        .unwrap_or_else(|| PathBuf::from(format!("/run/vallum/{interface}.sock")));
    let deadline = std::time::Instant::now() + SESSION_WAIT;
    while std::time::Instant::now() < deadline {
        if let Ok(reply) = uapi_get(&socket) {
            let established = reply
                .lines()
                .any(|line| line.starts_with("last_handshake_time_sec=") && !line.ends_with("=0"));
            if established {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(200));
    }
    Err(format!(
        "no peer completed a handshake within {}s — the tunnel is up but the \
         server is not answering, and routing the host's traffic into it \
         would blackhole this machine; fix the server and retry",
        SESSION_WAIT.as_secs()
    )
    .into())
}

fn uapi_get(socket: &Path) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"get=1\n\n")?;
    stream.shutdown(Shutdown::Write)?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    Ok(reply)
}

fn wait_for_interface(interface: &str) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..50 {
        let status = Command::new("ip")
            .args(["link", "show", interface])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            return Ok(());
        }
        sleep(Duration::from_millis(100));
    }
    Err(format!("interface `{interface}` did not come up").into())
}

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    #[test]
    fn a_prefix_is_covered_by_the_interface_address_that_contains_it() {
        let subnet: ipnet::IpNet = "10.7.0.1/24".parse().unwrap();
        assert!(covers(&subnet, &prefix("10.7.0.2/32")));
        assert!(covers(&subnet, &prefix("10.7.0.0/24")));
        assert!(!covers(&subnet, &prefix("10.8.0.0/24")));
        assert!(!covers(&subnet, &prefix("0.0.0.0/0")));
    }

    #[test]
    fn a_default_route_is_never_covered_by_an_interface_address() {
        // The client case: `allowed_ips = ["0.0.0.0/0", "::/0"]` must always be
        // routed, or the tunnel carries nothing.
        let v4: ipnet::IpNet = "10.7.0.2/32".parse().unwrap();
        let v6: ipnet::IpNet = "fd00:7::2/128".parse().unwrap();
        assert!(!covers(&v4, &prefix("0.0.0.0/0")));
        assert!(!covers(&v6, &prefix("::/0")));
    }

    #[test]
    fn families_do_not_cover_each_other() {
        let v4: ipnet::IpNet = "10.7.0.1/24".parse().unwrap();
        let v6: ipnet::IpNet = "fd00:7::1/64".parse().unwrap();
        assert!(!covers(&v4, &prefix("fd00:7::2/128")));
        assert!(!covers(&v6, &prefix("10.7.0.2/32")));
        assert!(covers(&v6, &prefix("fd00:7::2/128")));
    }

    #[test]
    fn managed_routes_is_empty_when_the_table_is_off() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-routes-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[quick]\ntable = \"off\"\n\n\
             [[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"10.7.0.2/32\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let routes = managed_routes(&config, "v0", "off", true).unwrap();
        assert!(routes.is_empty());
    }

    #[test]
    fn strip_removes_the_quick_table_only() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[quick]\ndns = [\"1.1.1.1\"]\n\n[[peer]]\nname = \"p\"\n",
        )
        .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let out = strip_quick(&text);
        assert!(!out.contains("[quick]"));
        assert!(!out.contains("dns ="));
        assert!(out.contains("[[peer]]"));
    }

    #[test]
    fn save_writes_the_export_and_refuses_the_config_itself() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-save-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("v.toml");
        let out = dir.join("out.toml");
        fs::write(&config, "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n").unwrap();
        std::env::set_var("VALLUM_BIN", "/bin/echo");
        save(&config, Some(&out), false, false).unwrap();
        assert!(fs::read_to_string(&out).unwrap().contains("showconf"));
        assert!(save(&config, Some(&config), false, false).is_err());
        assert!(save(&config, None, false, true).is_err());
        save(&config, None, true, true).unwrap();
        assert!(fs::read_to_string(&config).unwrap().contains("showconf"));
        assert!(config.with_extension("toml.bak").exists());
        std::env::remove_var("VALLUM_BIN");
    }

    #[test]
    fn hooks_are_refused_from_a_config_another_user_can_edit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vallum-quick-own-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(&path, "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n").unwrap();

        let hooks = Config::load(&{
            let hooked = dir.join("hooks.toml");
            fs::write(
                &hooked,
                "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[quick]\npre_up = [\"true\"]\n",
            )
            .unwrap();
            hooked
        })
        .unwrap();
        let plain = Config::load(&path).unwrap();

        // No hooks: a user-owned config is fine even as root.
        assert!(check_config_ownership_as(&path, &plain, true, false).is_ok());
        // Not root: the caller's own config, hooks run with their privileges.
        assert!(check_config_ownership_as(&path, &hooks, false, false).is_ok());

        // Root, and the file belongs to someone else (the test user).
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_config_ownership_as(&path, &hooks, true, false).is_err());
        // …unless the operator says so explicitly.
        assert!(check_config_ownership_as(&path, &hooks, true, true).is_ok());

        // Root-owned but world-writable is just as bad.
        use std::os::unix::fs::MetadataExt as _;
        if std::fs::metadata(&path).unwrap().uid() == 0 {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
            assert!(check_config_ownership_as(&path, &hooks, true, false).is_err());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_default_route_requires_a_fwmark() {
        // Without a mark the daemon's own packets would be policy-routed into
        // the tunnel — the failure that blackholed the host's internet.
        let dir = std::env::temp_dir().join(format!("vallum-quick-fm-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let routes: Vec<Prefix> = vec!["0.0.0.0/0".parse().unwrap()];
        let error = policy_for(&config, &routes, "auto").unwrap_err();
        assert!(error.to_string().contains("fwmark"), "{error}");
    }

    #[test]
    fn a_stale_full_tunnel_gains_the_mark_in_memory_and_writes_it_only_for_real() {
        // Configs minted before fwmark existed must still attach after an
        // upgrade: the entry points complete the local mark in memory, and
        // persist it only on a real run. A `--dry-run` that rewrote the file
        // it had just read was a bug, not a feature.
        let dir = std::env::temp_dir().join(format!("vallum-quick-heal-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        let original = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\nallowed_ips = [\"0.0.0.0/0\"]\n";
        fs::write(&path, original).unwrap();

        let config = load_normalized(&path).unwrap();
        assert_eq!(config.interface.fwmark, Some(51820));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            original,
            "loading a config must not rewrite it"
        );

        heal_config_on_disk(&path, true);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            original,
            "a dry run must not rewrite the config it read"
        );

        heal_config_on_disk(&path, false);
        let rewritten = fs::read_to_string(&path).unwrap();
        assert!(rewritten.contains("fwmark = 51820"), "{rewritten}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_default_route_plans_a_policy_table_not_the_main_table() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-pl-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\nfwmark = 51820\n\n[[peer]]\nname = \"p\"\nallowed_ips = [\"0.0.0.0/0\", \"::/0\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let routes: Vec<Prefix> = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
        let policy = policy_for(&config, &routes, "auto").unwrap().unwrap();
        assert_eq!(policy.table, POLICY_TABLE);
        assert_eq!(policy.mark, 51820);
        assert!(policy.v4 && policy.v6);
    }

    #[test]
    fn an_attach_records_a_plan_that_teardown_reverses_exactly() {
        // The regression that took a host's internet away: teardown re-derived
        // the plan from the config, so an edit between attach and detach made
        // it compute nothing and strand the policy rules — including the one
        // that suppresses the main table's default route.
        let dir = std::env::temp_dir().join(format!("vallum-quick-plan-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\nfwmark = 51820\n\n\
             [[peer]]\nname = \"p\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let plan = plan_routes(&config, "v0", "auto", true).unwrap();

        assert_eq!(
            plan.render(),
            "rule add not fwmark 51820 table 51820\n\
             rule add table main suppress_prefixlength 0\n\
             route add 0.0.0.0/0 dev v0 table 51820\n"
        );
        // Reverse order, verbs swapped: teardown undoes installation.
        assert_eq!(
            plan.reversed().render(),
            "route del 0.0.0.0/0 dev v0 table 51820\n\
             rule del table main suppress_prefixlength 0\n\
             rule del not fwmark 51820 table 51820\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_config_edited_after_attach_still_tears_down_what_was_installed() {
        // The incident: attach a full tunnel, then narrow the config. Teardown
        // re-derived from the narrowed config, computed no policy, and left
        // `table main suppress_prefixlength 0` behind — so the host kept its
        // gateway and lost the internet until it was rebooted.
        let dir = std::env::temp_dir().join(format!("vallum-quick-edit-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let full = dir.join("full.toml");
        fs::write(
            &full,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\nfwmark = 51820\n\n\
             [[peer]]\nname = \"p\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        let narrowed_path = dir.join("narrowed.toml");
        fs::write(
            &narrowed_path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\nfwmark = 51820\n\n\
             [[peer]]\nname = \"p\"\nallowed_ips = [\"10.9.0.0/24\"]\n",
        )
        .unwrap();

        let attached = plan_routes(&Config::load(&full).unwrap(), "v0", "auto", true).unwrap();
        let narrowed = Config::load(&narrowed_path).unwrap();

        // Re-deriving from the edited config finds nothing to undo. This is
        // the old behaviour, asserted so the regression cannot come back.
        let derived = teardown_plan(None, &narrowed, "v0", "auto", true);
        assert!(
            !derived.render().contains("suppress_prefixlength"),
            "the config-derived path is expected to miss the rules: {}",
            derived.render()
        );

        // The record wins, so teardown still removes every policy rule.
        let teardown = teardown_plan(Some(&attached), &narrowed, "v0", "auto", true);
        assert_eq!(teardown.render(), attached.reversed().render());
        assert!(
            teardown
                .render()
                .contains("rule del table main suppress_prefixlength 0"),
            "{}",
            teardown.render()
        );
        assert!(
            teardown
                .render()
                .contains("rule del not fwmark 51820 table 51820"),
            "{}",
            teardown.render()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_recorded_plan_survives_being_written_and_read_back() {
        let plan = RoutePlan {
            commands: vec![
                vec![
                    "rule".to_owned(),
                    "add".to_owned(),
                    "table".to_owned(),
                    "main".to_owned(),
                ],
                vec!["route".to_owned(), "add".to_owned(), "0.0.0.0/0".to_owned()],
            ],
        };
        assert_eq!(RoutePlan::parse(&plan.render()), plan);
    }

    #[test]
    fn a_split_tunnel_records_no_policy_rules() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-split-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n\
             [[peer]]\nname = \"p\"\nallowed_ips = [\"10.9.0.0/24\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let plan = plan_routes(&config, "v0", "auto", true).unwrap();
        assert_eq!(plan.render(), "route add 10.9.0.0/24 dev v0\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_split_tunnel_needs_no_policy() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-sp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(&path, "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n").unwrap();
        let config = Config::load(&path).unwrap();
        let routes: Vec<Prefix> = vec!["10.7.0.0/24".parse().unwrap()];
        assert!(policy_for(&config, &routes, "auto").unwrap().is_none());
    }

    #[test]
    fn a_default_route_with_table_off_is_refused() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-off-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\nfwmark = 1\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let routes: Vec<Prefix> = vec!["0.0.0.0/0".parse().unwrap()];
        assert!(policy_for(&config, &routes, "off").is_err());
    }

    #[test]
    fn a_v6_route_uses_ip_dash_six() {
        let prefix: Prefix = "fd00:7::2/128".parse().unwrap();
        assert!(matches!(prefix.as_ipnet(), ipnet::IpNet::V6(_)));
    }

    #[test]
    fn resolvectl_wins_when_resolved_is_running() {
        let backend = dns_backend_from(
            |program| program == "resolvectl" || program == "resolvconf",
            true,
        );
        assert_eq!(backend, DnsBackend::ResolveCtl);
    }

    #[test]
    fn an_installed_but_stopped_resolved_falls_back_to_resolvconf() {
        // `resolvectl` exists on hosts where resolved is disabled; calling it
        // there fails, so the running check decides.
        let backend = dns_backend_from(
            |program| program == "resolvectl" || program == "resolvconf",
            false,
        );
        assert_eq!(backend, DnsBackend::ResolvConf);
    }

    #[test]
    fn no_dns_tool_is_reported_as_none() {
        assert_eq!(dns_backend_from(|_| false, true), DnsBackend::None);
        assert_eq!(dns_backend_from(|_| false, false), DnsBackend::None);
    }

    fn config_with(name: &str, body: &str) -> Config {
        let dir =
            std::env::temp_dir().join(format!("vallum-quick-dns-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            format!("[interface]\nname = \"v0\"\nprivate_key = \"k\"\n{body}"),
        )
        .unwrap();
        Config::load(&path).unwrap()
    }

    #[test]
    fn a_full_tunnel_claims_every_name() {
        let config = config_with(
            "full",
            "\n[[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\", \"::/0\"]\n",
        );
        assert_eq!(dns_domain(&config).as_deref(), Some("~."));
    }

    #[test]
    fn a_split_tunnel_claims_no_domain() {
        let config = config_with(
            "split",
            "\n[[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"10.7.0.0/24\"]\n",
        );
        assert!(dns_domain(&config).is_none());
    }

    #[test]
    fn an_explicit_domain_wins_over_the_default() {
        let config = config_with(
            "explicit",
            "\n[quick]\ndns_domain = \"corp.example\"\n\n[[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        );
        assert_eq!(dns_domain(&config).as_deref(), Some("corp.example"));
    }
}
