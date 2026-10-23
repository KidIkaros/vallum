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
use std::time::{Duration, Instant};

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
    /// Hold the routes only while the session is alive.
    ///
    /// `attach` refuses to install a full tunnel without a handshake. This is
    /// the other half: it takes the routes back out when the peer stops
    /// answering, because a dead server behind a live interface is a host with
    /// no internet.
    Watch {
        /// The configuration file.
        config: PathBuf,
        /// Report each tick instead of changing anything.
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
        Action::Watch {
            config,
            dry_run,
            allow_insecure_config,
        } => watch(config, *dry_run, *allow_insecure_config),
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
        if let Err(error) = set_dns(
            interface,
            &config.quick.dns,
            dns_domain(config).as_deref(),
            dry_run,
        ) {
            rollback(config, config_path, interface, table, dry_run);
            return Err(format!(
                "DNS configuration failed for `{interface}`: {error}; refusing to attach to prevent DNS leaks \
                 (set `[quick] dns = []` if you manage DNS manually)"
            )
            .into());
        }
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
        wait_for_interface(&interface).map_err(|_| {
            interface_missing(
                &interface,
                config.quick.pre_up.len(),
                config_path.file_stem().and_then(|stem| stem.to_str()),
            )
        })?;
        wait_for_session(&config, config_path, &interface)?;
    }

    apply_routes(&config, &interface, table, dry_run)?;

    if !config.quick.dns.is_empty() {
        if let Err(error) = set_dns(
            &interface,
            &config.quick.dns,
            dns_domain(&config).as_deref(),
            dry_run,
        ) {
            remove_routes(&config, &interface, table, dry_run);
            return Err(format!(
                "DNS configuration failed for `{interface}`: {error}; refusing to attach to prevent DNS leaks \
                 (set `[quick] dns = []` if you manage DNS manually)"
            )
            .into());
        }
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
    fn reversed(&self) -> Self {
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
    ///
    /// The one exception is a route that already points where this one would.
    /// A restarted unit, or a host that already owns the prefix on the same
    /// interface, should be a no-op rather than `RTNETLINK answers: File
    /// exists` and a failed unit. A prefix routed via *anything else* keeps
    /// failing, because that is a real conflict.
    fn run(&self, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    fn run_lenient(&self, dry_run: bool) {
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
fn route_query(command: &[String]) -> Option<Vec<String>> {
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

fn dev_of(command: &[String]) -> Option<&str> {
    let index = command.iter().position(|arg| arg == "dev")?;
    command.get(index + 1).map(String::as_str)
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

/// Blackhole routes installed on session failure (fail-closed).
fn plan_blackhole_routes(
    config: &Config,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> Result<RoutePlan, Box<dyn std::error::Error>> {
    let routes = managed_routes(config, interface, table, dry_run)?;
    let policy = policy_for(config, &routes, table)?;
    let mut plan = RoutePlan::default();
    for prefix in &routes {
        let route_table = match &policy {
            Some(policy) if prefix.as_ipnet().prefix_len() == 0 => policy.table.as_str(),
            _ => table,
        };
        plan.blackhole(prefix, route_table);
    }
    Ok(plan)
}

fn apply_blackhole_routes(config: &Config, interface: &str, table: &str, dry_run: bool) {
    if table == "off" {
        return;
    }
    if let Ok(plan) = plan_blackhole_routes(config, interface, table, dry_run) {
        let _ = plan.run(dry_run);
    }
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
/// calling it then fails. `resolvconf` is the second fallback. When neither is
/// usable, `/etc/resolv.conf` is updated directly (`ResolvFile`) with a state
/// backup in `/run/vallum` to restore on detach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsBackend {
    ResolveCtl,
    ResolvConf,
    ResolvFile,
    None,
}

fn dns_backend_from(
    present: impl Fn(&str) -> bool,
    resolved_running: bool,
    resolv_conf_writable: bool,
) -> DnsBackend {
    if present("resolvectl") && resolved_running {
        DnsBackend::ResolveCtl
    } else if present("resolvconf") {
        DnsBackend::ResolvConf
    } else if resolv_conf_writable {
        DnsBackend::ResolvFile
    } else {
        DnsBackend::None
    }
}

fn is_resolv_conf_writable() -> bool {
    let path = Path::new("/etc/resolv.conf");
    if path.exists() {
        fs::OpenOptions::new().write(true).open(path).is_ok()
    } else {
        path.parent()
            .map(|p| {
                fs::metadata(p)
                    .map(|m| !m.permissions().readonly())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}

fn dns_backend(dry_run: bool) -> DnsBackend {
    dns_backend_from(
        |program| which(program).is_some(),
        Path::new("/run/systemd/resolve").exists(),
        dry_run || is_resolv_conf_writable(),
    )
}

fn resolv_bak_path(interface: &str) -> PathBuf {
    PathBuf::from("/run/vallum").join(format!("{interface}.resolv.conf.bak"))
}

fn backup_and_write_resolv_conf_at(
    resolv_path: &Path,
    bak_path: &Path,
    interface: &str,
    servers: &[String],
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if dry_run {
        println!(
            "would backup {} to {} and write {} nameservers",
            resolv_path.display(),
            bak_path.display(),
            servers.len()
        );
        return Ok(());
    }
    if let Some(parent) = bak_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(meta) = fs::symlink_metadata(resolv_path) {
        if meta.file_type().is_symlink() {
            if let Ok(target) = fs::read_link(resolv_path) {
                let _ = fs::write(bak_path, format!("symlink:{}", target.display()));
            }
            let _ = fs::remove_file(resolv_path);
        } else {
            let _ = fs::copy(resolv_path, bak_path);
        }
    }
    let mut content = format!("# Generated by vallum-quick for {interface}\n");
    for s in servers {
        content.push_str(&format!("nameserver {s}\n"));
    }
    fs::write(resolv_path, content)?;
    Ok(())
}

fn restore_resolv_conf_at(
    resolv_path: &Path,
    bak_path: &Path,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !bak_path.exists() {
        return Ok(());
    }
    if dry_run {
        println!(
            "would restore {} from {}",
            resolv_path.display(),
            bak_path.display()
        );
        return Ok(());
    }
    if let Ok(content) = fs::read_to_string(bak_path) {
        if let Some(target) = content.strip_prefix("symlink:") {
            let _ = fs::remove_file(resolv_path);
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(target.trim(), resolv_path);
        } else {
            let _ = fs::copy(bak_path, resolv_path);
        }
    }
    let _ = fs::remove_file(bak_path);
    Ok(())
}

fn backup_and_write_resolv_conf(
    interface: &str,
    servers: &[String],
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    backup_and_write_resolv_conf_at(
        Path::new("/etc/resolv.conf"),
        &resolv_bak_path(interface),
        interface,
        servers,
        dry_run,
    )
}

fn restore_resolv_conf(interface: &str, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    restore_resolv_conf_at(
        Path::new("/etc/resolv.conf"),
        &resolv_bak_path(interface),
        dry_run,
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

/// Configure DNS for the interface.
///
/// Refuses to attach if DNS cannot be configured when servers are specified:
/// a tunnel with unmanaged DNS leaks queries to the local host resolver outside
/// the tunnel. If an operator manages DNS manually, they must set `dns = []`.
fn set_dns(
    interface: &str,
    servers: &[String],
    domain: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if servers.is_empty() {
        return Ok(());
    }
    apply_dns(interface, servers, domain, dry_run)
}

fn apply_dns(
    interface: &str,
    servers: &[String],
    domain: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match dns_backend(dry_run) {
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
        DnsBackend::ResolvFile => backup_and_write_resolv_conf(interface, servers, dry_run),
        DnsBackend::None => Err(
            "no working DNS manager (resolvectl, resolvconf) and /etc/resolv.conf \
                 cannot be updated; refusing to attach to prevent DNS leaks"
                .into(),
        ),
    }
}

fn unset_dns(interface: &str, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    match dns_backend(dry_run) {
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
        DnsBackend::ResolvFile => restore_resolv_conf(interface, dry_run),
        DnsBackend::None => {
            let _ = restore_resolv_conf(interface, dry_run);
            Ok(())
        }
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
    let socket = control_socket(config, config_path, interface);
    let started = std::time::Instant::now();
    let deadline = started + SESSION_WAIT;
    let mut reported = 0u64;
    while std::time::Instant::now() < deadline {
        if let Ok(reply) = uapi_get(&socket) {
            let established = reply
                .lines()
                .any(|line| line.starts_with("last_handshake_time_sec=") && !line.ends_with("=0"));
            if established {
                return Ok(());
            }
        }
        // A silent wait is indistinguishable from a hang, and this one can last
        // twenty seconds. Say we are still waiting, and for how long, so the
        // user can tell "working" from "wedged" without watching a clock.
        let elapsed = started.elapsed().as_secs();
        if elapsed >= 2 && elapsed - reported >= 2 {
            reported = elapsed;
            eprintln!(
                "vallum-quick: waiting for a handshake… ({elapsed}s of {}s)",
                SESSION_WAIT.as_secs()
            );
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

/// The control socket a config's daemon listens on.
fn control_socket(config: &Config, config_path: &Path, interface: &str) -> PathBuf {
    config
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
        .unwrap_or_else(|| vallum_config::socket_path(interface))
}

/// What the watchdog should do with the routes on one tick.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    Hold,
    Withdraw(WithdrawReason),
    Restore,
}

/// Why routes were withdrawn by the watchdog.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum WithdrawReason {
    NoHandshake,
    DeliveryDegraded,
}

/// What happens when the tunnel session fails: `block` (fail-closed) or `restore` (fail-open).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum FailurePolicy {
    /// Install blackhole routes for the tunnel's prefixes so traffic cannot escape.
    Block,
    /// Withdraw the tunnel routes so traffic returns to the host's physical gateway.
    Restore,
}

impl FailurePolicy {
    fn from_config(config: &Config) -> Self {
        if let Ok(val) = std::env::var("VALLUM_FAILURE_POLICY") {
            if let Some(policy) = Self::parse(&val) {
                return policy;
            }
        }
        config
            .quick
            .failure_policy
            .as_deref()
            .and_then(Self::parse)
            .unwrap_or(Self::Block)
    }

    fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "block" | "block-on-failure" | "closed" | "fail-closed" => Some(Self::Block),
            "restore" | "open" | "fail-open" => Some(Self::Restore),
            _ => None,
        }
    }
}

/// Datagrams below which a delivery ratio is not worth judging.
///
/// Three keepalives and a stray packet are not evidence of anything.
const DELIVERY_MIN_SAMPLE: u64 = 100;

/// Delivery below this is not carrying.
///
/// A ratio under 0.1 indicates the tunnel is sending into a void (e.g. far-side
/// dropped session or routing blackhole).
const DELIVERY_FLOOR: f64 = 0.1;

/// How long delivery must stay below threshold before routes are withdrawn.
///
/// Defaults to the protocol's rekey interval (120 s). A momentary dip or transient
/// loss must not flap the routes; but once a full rekey cycle elapses with no
/// traffic carrying, the tunnel is sending into a void.
const DEGRADED_AFTER: Duration = Duration::from_secs(120);

fn degraded_after() -> Duration {
    std::env::var("VALLUM_DEGRADED_AFTER_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEGRADED_AFTER)
}

/// Decide from the session's age and whether the routes are currently in (legacy handshake-only check).
#[cfg(test)]
fn verdict(attached: bool, session_age: Option<Duration>, dead_after: Duration) -> Verdict {
    verdict_carrying(
        attached,
        session_age,
        dead_after,
        None,
        Duration::ZERO,
        DEGRADED_AFTER,
    )
}

/// Decide route status from handshake age, delivery ratio, and degraded duration.
///
/// Pure, so the rule "a full tunnel with a dead session or non-carrying delivery
/// must not own the host's default route" is testable without a kernel, a socket or a clock.
fn verdict_carrying(
    attached: bool,
    session_age: Option<Duration>,
    dead_after: Duration,
    worst_delivery: Option<f64>,
    degraded_for: Duration,
    degraded_after: Duration,
) -> Verdict {
    let handshake_live = session_age.is_some_and(|age| age < dead_after);
    if !handshake_live {
        return match attached {
            true => Verdict::Withdraw(WithdrawReason::NoHandshake),
            false => Verdict::Hold,
        };
    }

    let delivery_degraded = worst_delivery.is_some_and(|ratio| ratio < DELIVERY_FLOOR);
    if delivery_degraded && degraded_for >= degraded_after {
        return match attached {
            true => Verdict::Withdraw(WithdrawReason::DeliveryDegraded),
            false => Verdict::Hold,
        };
    }

    if delivery_degraded {
        return Verdict::Hold;
    }

    match attached {
        true => Verdict::Hold,
        false => Verdict::Restore,
    }
}

/// How stale the newest handshake may be before the tunnel counts as dead.
///
/// This must be **longer than the protocol's own expiry**. `REJECT_AFTER_TIME_MS`
/// in `vallum-core` is 180 s: until that point the daemon still considers the
/// session valid and will accept data on it, so a shorter window withdraws the
/// routes from a tunnel that is working.
///
/// Measured on a real deployment with the previous 90 s value: an idle full
/// tunnel flapped every ~125 s — routes withdrawn, then restored ~35 s later
/// when the next rekey landed — costing about a third of all connectivity in a
/// steady state that looked perfectly healthy. The old comment justified 90 s as
/// "three keepalive periods plus slack", which only holds if the peer sends
/// keepalives; a client that does not sends nothing at all while idle.
///
/// 180 s plus 30 s of slack, so a rekey that lands late is not a withdrawal.
const DEAD_AFTER: Duration = Duration::from_secs(210);

/// How often the watchdog asks the daemon whether the session is alive.
const WATCH_POLL: Duration = Duration::from_secs(5);

fn dead_after() -> Duration {
    let configured = std::env::var("VALLUM_DEAD_AFTER_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEAD_AFTER);
    clamp_dead_after(configured)
}

#[cfg(test)]
mod dead_after_tests {
    use super::*;

    /// The watchdog must outlive the protocol's own expiry. `REJECT_AFTER_TIME_MS`
    /// lives in `vallum-core` (180 s); this crate does not depend on it, so the
    /// number is asserted here rather than imported. If either moves, this fails.
    #[test]
    fn the_watchdog_window_outlives_the_protocol_expiry() {
        assert!(
            DEAD_AFTER.as_secs() > 180,
            "DEAD_AFTER must exceed REJECT_AFTER_TIME_MS (180 s) or the watchdog \
             withdraws routes from a live tunnel"
        );
    }
}

/// A window no longer than the poll interval can never be observed: every
/// sample would land after it closed, so the routes would be withdrawn and
/// never restored. Two intervals guarantees a live session is seen.
fn clamp_dead_after(configured: Duration) -> Duration {
    configured.max(WATCH_POLL * 2)
}

/// Health metrics parsed from the daemon's UAPI reply.
#[derive(Debug, Clone, Copy, PartialEq)]
struct SessionHealth {
    age: Option<Duration>,
    worst_delivery: Option<f64>,
}

fn parse_session_health(reply: &str) -> SessionHealth {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
        .unwrap_or(0);
    parse_session_health_at(reply, now)
}

fn parse_session_health_at(reply: &str, now_unix_secs: u64) -> SessionHealth {
    let mut newest_handshake: Option<u64> = None;
    let mut worst_ratio: Option<f64> = None;

    for block in reply.split("\n\n") {
        for line in block.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("last_handshake_time_sec=") {
                if let Ok(secs) = rest.trim().parse::<u64>() {
                    if secs > 0 {
                        newest_handshake = Some(newest_handshake.map_or(secs, |e| e.max(secs)));
                    }
                }
            }
        }

        let sent = block
            .lines()
            .find_map(|l| l.trim().strip_prefix("vallum_window_sent="))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);

        if sent >= DELIVERY_MIN_SAMPLE {
            let received = block
                .lines()
                .find_map(|l| l.trim().strip_prefix("vallum_window_received="))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0);
            let ratio = received as f64 / sent as f64;
            worst_ratio = Some(worst_ratio.map_or(ratio, |e| e.min(ratio)));
        }
    }

    let age = newest_handshake.map(|secs| Duration::from_secs(now_unix_secs.saturating_sub(secs)));
    SessionHealth {
        age,
        worst_delivery: worst_ratio,
    }
}

fn session_health(socket: &Path) -> Option<SessionHealth> {
    let reply = uapi_get(socket).ok()?;
    Some(parse_session_health(&reply))
}

/// Hold the routes only while the session is alive and carrying.
///
/// `attach` gates installation on a handshake, but nothing took the routes back
/// out when the peer stopped answering: the daemon stays up, the interface
/// stays up, and a full tunnel keeps the host's traffic pointed at a peer that
/// is not there. A dead server then costs the host its internet until someone
/// reboots it. This is the other half of that gate.
fn watch(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_normalized(config_path)?;
    check_config_ownership(config_path, &config, allow_insecure_config)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    let socket = control_socket(&config, config_path, &interface);
    let dead_after = dead_after();
    let degraded_after = degraded_after();
    let failure_policy = FailurePolicy::from_config(&config);
    // Guard exactly what attach installed. A config whose routes are all covered
    // by its own interface installs nothing, so there is nothing to withdraw —
    // but the process stays resident so the unit has one lifecycle either way.
    let guarded = !plan_routes(&config, &interface, table, dry_run)?
        .commands
        .is_empty();
    if !guarded {
        eprintln!("vallum-quick: {interface}: no routes of its own to guard");
    }
    let mut attached = read_plan(&state_path(&interface)).is_some();
    let mut degraded_since: Option<Instant> = None;

    loop {
        if guarded {
            let health = session_health(&socket);
            let age = health.as_ref().and_then(|h| h.age);
            let delivery = health.as_ref().and_then(|h| h.worst_delivery);

            let is_degraded = delivery.is_some_and(|ratio| ratio < DELIVERY_FLOOR);
            let degraded_for = if is_degraded {
                let start = degraded_since.get_or_insert_with(Instant::now);
                start.elapsed()
            } else {
                degraded_since = None;
                Duration::ZERO
            };

            match verdict_carrying(
                attached,
                age,
                dead_after,
                delivery,
                degraded_for,
                degraded_after,
            ) {
                Verdict::Withdraw(reason) => {
                    let msg = match reason {
                        WithdrawReason::NoHandshake => {
                            format!("no handshake within {}s", dead_after.as_secs())
                        }
                        WithdrawReason::DeliveryDegraded => {
                            format!(
                                "delivery below threshold (10%) for {}s",
                                degraded_after.as_secs()
                            )
                        }
                    };
                    match failure_policy {
                        FailurePolicy::Block => {
                            if dry_run {
                                println!("would block {interface}: {msg} (fail-closed blackhole)");
                            } else {
                                apply_blackhole_routes(&config, &interface, table, false);
                                eprintln!(
                                    "vallum-quick: {interface}: {msg} — blackhole routes installed (fail-closed), \
                                     traffic blocked"
                                );
                            }
                        }
                        FailurePolicy::Restore => {
                            if dry_run {
                                println!("would withdraw {interface}: {msg}");
                            } else {
                                remove_routes(&config, &interface, table, false);
                                eprintln!(
                                    "vallum-quick: {interface}: {msg} — routes withdrawn, \
                                     this host keeps its own gateway"
                                );
                            }
                        }
                    }
                    attached = false;
                }
                Verdict::Restore => {
                    degraded_since = None;
                    if dry_run {
                        println!("would restore {interface}: the session is back and carrying");
                    } else {
                        match apply_routes(&config, &interface, table, false) {
                            Ok(()) => {
                                attached = true;
                                eprintln!(
                                    "vallum-quick: {interface}: session is back and carrying — routes restored"
                                );
                            }
                            Err(error) => {
                                eprintln!("vallum-quick: {interface}: could not restore: {error}");
                            }
                        }
                    }
                }
                Verdict::Hold => {}
            }
        }
        std::thread::sleep(WATCH_POLL);
    }
}

/// How long `attach` waits for a `pre_up` hook to create the interface.
///
/// The timeout is one constant because the failure message quotes it: two
/// copies of "5 seconds" would drift, and the message would then describe a
/// wait that no longer happens.
const INTERFACE_WAIT: Duration = Duration::from_secs(5);

/// How often to look, while waiting.
const INTERFACE_POLL: Duration = Duration::from_millis(100);

/// Wait for an interface that something else is expected to create.
///
/// This function never creates one. `attach` runs the config's `pre_up` hooks
/// and calls this to wait for their result, so a timeout means the hooks did
/// not do their job — which is why the caller explains it rather than this
/// function guessing.
fn wait_for_interface(interface: &str) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + INTERFACE_WAIT;
    while Instant::now() < deadline {
        let status = Command::new("ip")
            .args(["link", "show", interface])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            return Ok(());
        }
        sleep(INTERFACE_POLL);
    }
    Err(format!("interface `{interface}` did not come up").into())
}

/// Explain an interface that never appeared, in terms the operator can act on.
///
/// Takes the facts it needs rather than the config, so the two remedies stay
/// distinguishable without this function knowing anything about `Config`.
fn interface_missing(
    interface: &str,
    pre_up_count: usize,
    unit: Option<&str>,
) -> Box<dyn std::error::Error> {
    let waited = INTERFACE_WAIT.as_secs();
    if pre_up_count == 0 {
        // No unit name means the config's stem could not be read, and naming a
        // guessed `vallum@` instance would send the operator to a unit that
        // does not exist.
        return match unit {
            Some(unit) => format!(
                "interface `{interface}` did not appear within {waited}s, and no `pre_up` \
                 hook is configured, so nothing started the daemon. Start it first \
                 (`systemctl start vallum@{unit}`), or add a `pre_up` hook to [quick]."
            )
            .into(),
            None => format!(
                "interface `{interface}` did not appear within {waited}s, and no `pre_up` \
                 hook is configured, so nothing started the daemon. Start it first, or \
                 add a `pre_up` hook to [quick]."
            )
            .into(),
        };
    }
    format!(
        "interface `{interface}` did not appear within {waited}s of running {pre_up_count} \
         `pre_up` hook(s); check the daemon's log for why it exited"
    )
    .into()
}

#[cfg(test)]
mod interface_missing_tests {
    use super::{interface_missing, INTERFACE_WAIT};

    #[test]
    fn no_hooks_names_the_unit_to_start() {
        let message = interface_missing("vallum-laptop", 0, Some("laptop")).to_string();
        assert!(
            message.contains("systemctl start vallum@laptop"),
            "{message}"
        );
        assert!(message.contains("no `pre_up` hook"), "{message}");
    }

    #[test]
    fn an_unknown_unit_is_never_guessed() {
        // The config's stem was unreadable, so there is no unit name to give.
        // Suggesting `vallum@vallum0` would send the operator to a unit that
        // does not exist, which is worse than saying nothing.
        let message = interface_missing("vallum-laptop", 0, None).to_string();
        assert!(!message.contains("systemctl start vallum@"), "{message}");
        assert!(message.contains("Start it first"), "{message}");
    }

    #[test]
    fn hooks_are_blamed_rather_than_missing_configuration() {
        let message = interface_missing("vallum-laptop", 2, Some("laptop")).to_string();
        assert!(message.contains("2 `pre_up` hook(s)"), "{message}");
        assert!(!message.contains("no `pre_up` hook"), "{message}");
    }

    #[test]
    fn the_quoted_wait_is_the_constant() {
        // The whole point of INTERFACE_WAIT is that the message cannot drift
        // from the behaviour; this fails the moment someone changes one only.
        let message = interface_missing("v", 1, None).to_string();
        assert!(
            message.contains(&format!("{}s", INTERFACE_WAIT.as_secs())),
            "{message}"
        );
    }
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
    fn only_a_route_add_is_ever_treated_as_already_applied() {
        // A failed rule add is never idempotent; a route add may be, but only
        // the route add itself can be asked about.
        let rule = vec![
            "rule".to_owned(),
            "add".to_owned(),
            "not".to_owned(),
            "fwmark".to_owned(),
            "51820".to_owned(),
            "table".to_owned(),
            "51820".to_owned(),
        ];
        assert!(route_query(&rule).is_none());

        let route = vec![
            "route".to_owned(),
            "add".to_owned(),
            "10.7.0.0/24".to_owned(),
            "dev".to_owned(),
            "vcli".to_owned(),
        ];
        assert_eq!(
            route_query(&route).unwrap(),
            vec!["-o", "route", "show", "10.7.0.0/24"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
        assert_eq!(dev_of(&route), Some("vcli"));

        // A policy-table route is asked about in its own table, or the answer
        // would be about the main table and wrong.
        let policy = vec![
            "route".to_owned(),
            "add".to_owned(),
            "0.0.0.0/0".to_owned(),
            "dev".to_owned(),
            "vcli".to_owned(),
            "table".to_owned(),
            "51820".to_owned(),
        ];
        assert_eq!(
            route_query(&policy).unwrap(),
            vec!["-o", "route", "show", "0.0.0.0/0", "table", "51820"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );

        let v6 = vec![
            "-6".to_owned(),
            "route".to_owned(),
            "add".to_owned(),
            "::/0".to_owned(),
            "dev".to_owned(),
            "vcli".to_owned(),
        ];
        assert_eq!(route_query(&v6).unwrap()[0], "-6");
    }

    #[test]
    fn a_window_shorter_than_the_poll_is_widened_so_a_live_session_is_seen() {
        // The bug this prevents: with a 3s window and a 5s poll the loop can
        // sample only after the window closed, so routes went out and never
        // came back. Observed exactly that in a two-namespace run.
        assert_eq!(clamp_dead_after(Duration::from_secs(3)), WATCH_POLL * 2);
        assert_eq!(clamp_dead_after(Duration::ZERO), WATCH_POLL * 2);
        // A window that can be observed is left alone.
        assert_eq!(clamp_dead_after(DEAD_AFTER), DEAD_AFTER);
    }

    #[test]
    fn a_dead_session_withdraws_the_routes_and_a_live_one_restores_them() {
        // The loop that was missing: `attach` gated on a handshake going in,
        // and nothing took the routes back out when the peer stopped
        // answering. A full tunnel then owned the host's default route with
        // nothing behind it.
        let dead_after = Duration::from_secs(90);

        // A fresh session holds.
        assert_eq!(
            verdict(true, Some(Duration::from_secs(5)), dead_after),
            Verdict::Hold
        );
        // The server stopped answering: withdraw, so the host keeps its gateway.
        assert_eq!(
            verdict(true, Some(Duration::from_secs(91)), dead_after),
            Verdict::Withdraw(WithdrawReason::NoHandshake)
        );
        // Never handshaked at all is not a live session.
        assert_eq!(
            verdict(true, None, dead_after),
            Verdict::Withdraw(WithdrawReason::NoHandshake)
        );
        // The session came back: restore.
        assert_eq!(
            verdict(false, Some(Duration::from_secs(2)), dead_after),
            Verdict::Restore
        );
        // Withdrawn and still dead: nothing to do.
        assert_eq!(verdict(false, None, dead_after), Verdict::Hold);
    }

    #[test]
    fn a_degraded_session_withdraws_routes_after_the_rekey_interval() {
        let dead_after = Duration::from_secs(210);
        let degraded_after = Duration::from_secs(120);
        let fresh_handshake = Some(Duration::from_secs(10));
        let bad_ratio = Some(0.013); // 13 back against 1000 sent

        // Attached, fresh handshake, degraded delivery, but only degraded for 30s:
        // do not flap yet; hold the routes.
        assert_eq!(
            verdict_carrying(
                true,
                fresh_handshake,
                dead_after,
                bad_ratio,
                Duration::from_secs(30),
                degraded_after,
            ),
            Verdict::Hold
        );

        // Degraded for 120s (full rekey interval): withdraw routes!
        assert_eq!(
            verdict_carrying(
                true,
                fresh_handshake,
                dead_after,
                bad_ratio,
                Duration::from_secs(120),
                degraded_after,
            ),
            Verdict::Withdraw(WithdrawReason::DeliveryDegraded)
        );

        // While withdrawn and still degraded: hold withdrawn.
        assert_eq!(
            verdict_carrying(
                false,
                fresh_handshake,
                dead_after,
                bad_ratio,
                Duration::from_secs(130),
                degraded_after,
            ),
            Verdict::Hold
        );

        // Delivery recovers (healthy ratio 0.90): restore routes!
        assert_eq!(
            verdict_carrying(
                false,
                fresh_handshake,
                dead_after,
                Some(0.90),
                Duration::ZERO,
                degraded_after,
            ),
            Verdict::Restore
        );
    }

    #[test]
    fn an_idle_session_does_not_withdraw_routes_on_delivery() {
        let dead_after = Duration::from_secs(210);
        let degraded_after = Duration::from_secs(120);
        let fresh_handshake = Some(Duration::from_secs(10));

        // Idle session has no ratio (sample < 100 or 0 sent): must hold.
        assert_eq!(
            verdict_carrying(
                true,
                fresh_handshake,
                dead_after,
                None,
                Duration::from_secs(300),
                degraded_after,
            ),
            Verdict::Hold
        );
    }

    #[test]
    fn session_health_parses_delivery_and_handshake() {
        let now = 1792678500;
        let reply = "last_handshake_time_sec=1792678450\n\
                     vallum_window_sent=1000\n\
                     vallum_window_received=50\n";
        let health = parse_session_health_at(reply, now);
        assert_eq!(health.age, Some(Duration::from_secs(50)));
        assert_eq!(health.worst_delivery, Some(0.05));

        // Insufficient sample (< 100 sent): ratio is None.
        let idle_reply = "last_handshake_time_sec=1792678450\n\
                          vallum_window_sent=20\n\
                          vallum_window_received=0\n";
        let idle_health = parse_session_health_at(idle_reply, now);
        assert_eq!(idle_health.age, Some(Duration::from_secs(50)));
        assert_eq!(idle_health.worst_delivery, None);
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
            true,
        );
        assert_eq!(backend, DnsBackend::ResolvConf);
    }

    #[test]
    fn direct_file_is_used_when_no_tool_is_installed() {
        let backend = dns_backend_from(|_| false, false, true);
        assert_eq!(backend, DnsBackend::ResolvFile);
    }

    #[test]
    fn no_dns_tool_and_unwritable_resolv_is_reported_as_none() {
        assert_eq!(dns_backend_from(|_| false, true, false), DnsBackend::None);
        assert_eq!(dns_backend_from(|_| false, false, false), DnsBackend::None);
    }

    #[test]
    fn backup_and_restore_resolv_conf_regular_file() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-resolv-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("resolv.conf");
        let bak = dir.join("resolv.conf.bak");
        fs::write(&resolv, "nameserver 192.168.1.1\n").unwrap();

        let servers = vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()];
        backup_and_write_resolv_conf_at(&resolv, &bak, "v0", &servers, false).unwrap();

        let current = fs::read_to_string(&resolv).unwrap();
        assert!(current.contains("nameserver 1.1.1.1"));
        assert!(current.contains("nameserver 8.8.8.8"));
        assert!(bak.exists());

        restore_resolv_conf_at(&resolv, &bak, false).unwrap();
        let restored = fs::read_to_string(&resolv).unwrap();
        assert_eq!(restored, "nameserver 192.168.1.1\n");
        assert!(!bak.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_and_restore_resolv_conf_symlink() {
        let dir =
            std::env::temp_dir().join(format!("vallum-quick-resolv-sym-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("stub-resolv.conf");
        let resolv = dir.join("resolv.conf");
        let bak = dir.join("resolv.conf.bak");
        fs::write(&target, "nameserver 127.0.0.53\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &resolv).unwrap();

        let servers = vec!["1.1.1.1".to_owned()];
        backup_and_write_resolv_conf_at(&resolv, &bak, "v0", &servers, false).unwrap();

        let current = fs::read_to_string(&resolv).unwrap();
        assert!(current.contains("nameserver 1.1.1.1"));
        let meta = fs::symlink_metadata(&resolv).unwrap();
        assert!(!meta.file_type().is_symlink());

        restore_resolv_conf_at(&resolv, &bak, false).unwrap();
        let meta_restored = fs::symlink_metadata(&resolv).unwrap();
        assert!(meta_restored.file_type().is_symlink());
        #[cfg(unix)]
        assert_eq!(fs::read_link(&resolv).unwrap(), target);

        let _ = fs::remove_dir_all(&dir);
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

    #[test]
    fn failure_policy_defaults_to_block() {
        let config = config_with("fp-def", "");
        assert_eq!(FailurePolicy::from_config(&config), FailurePolicy::Block);
    }

    #[test]
    fn failure_policy_parses_options() {
        assert_eq!(FailurePolicy::parse("block"), Some(FailurePolicy::Block));
        assert_eq!(
            FailurePolicy::parse("block-on-failure"),
            Some(FailurePolicy::Block)
        );
        assert_eq!(
            FailurePolicy::parse("fail-closed"),
            Some(FailurePolicy::Block)
        );
        assert_eq!(
            FailurePolicy::parse("restore"),
            Some(FailurePolicy::Restore)
        );
        assert_eq!(
            FailurePolicy::parse("fail-open"),
            Some(FailurePolicy::Restore)
        );
        assert_eq!(FailurePolicy::parse("invalid"), None);
    }

    #[test]
    fn a_dead_session_with_block_policy_plans_blackhole_routes() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-bh-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\nfwmark = 51820\n\n\
             [[peer]]\nname = \"p\"\nallowed_ips = [\"0.0.0.0/0\", \"::/0\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let plan = plan_blackhole_routes(&config, "v0", "auto", true).unwrap();
        assert_eq!(
            plan.render(),
            "route replace blackhole 0.0.0.0/0 table 51820\n\
             -6 route replace blackhole ::/0 table 51820\n"
        );
        let reversed = plan.reversed();
        assert_eq!(
            reversed.render(),
            "-6 route del blackhole ::/0 table 51820\n\
             route del blackhole 0.0.0.0/0 table 51820\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_split_tunnel_blackholes_only_its_prefixes() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-bh-sp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n\
             [[peer]]\nname = \"p\"\nallowed_ips = [\"10.9.0.0/24\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let plan = plan_blackhole_routes(&config, "v0", "auto", true).unwrap();
        assert_eq!(plan.render(), "route replace blackhole 10.9.0.0/24\n");
        let _ = fs::remove_dir_all(&dir);
    }
}
