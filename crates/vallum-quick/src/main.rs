// SPDX-License-Identifier: Apache-2.0

//! `vallum-quick`: the OS-level helper.
//!
//! The daemon owns the tunnel and nothing else. This tool owns the parts that
//! are inherently distribution- and host-specific: routes, DNS, firewall/NAT,
//! and the operator's hooks. It reads the same TOML, including a `[quick]`
//! table the daemon ignores.
//!
//! The concerns this crate drives live in:
//!
//! * [`routes`] — derive, plan, record and reverse the `ip` invocations.
//! * [`dns`] — pick a DNS mechanism, apply and revert it per interface.
//! * [`hooks`] — the config-ownership privilege boundary and `sh -c`.
//! * [`session`] — readiness: the interface wait and the handshake gate.
//! * [`watch`] — the watchdog that holds routes only while the session lives.
//!
//! `main.rs` keeps the clap surface, the dispatch, and the glue every command
//! shares: config loading, the local-fwmark heal, `save`, and `strip`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use vallum_config::{Config, ConfigError};

mod dns;
mod hooks;
mod leak_check;
mod member;
mod routes;
mod session;
mod watch;

use crate::dns::{dns_domain, set_dns, unset_dns};
use crate::hooks::{check_config_ownership, run_hook};
use crate::routes::{apply_routes, remove_routes};
use crate::session::{interface_missing, wait_for_interface, wait_for_session};
use crate::watch::watch;

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
    /// Launch a process inside the tunnel's member namespace (ADR-0023).
    App {
        /// The configuration file, for its interface name.
        config: PathBuf,
        /// The member name, used in messages and the state directory only.
        name: String,
        /// The command and its arguments, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
        cmd: Vec<String>,
        /// Report the launch instead of performing it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the config without its `[quick]` table.
    Strip {
        /// The configuration file.
        config: PathBuf,
    },
    /// Run a bounded-concurrency local loopback DNS forwarder with RFC1918 LAN
    /// split, IPv4-only AAAA suppression, and optional captive-portal spoofing.
    DnsProxy {
        /// The configuration file.
        config: PathBuf,
        /// Socket address to bind the loopback DNS forwarder on.
        #[arg(long, default_value = "127.0.0.1:53")]
        listen: std::net::SocketAddr,
        /// Spoof captive-portal A queries to `198.51.100.1` (for Blocked/Lockdown state).
        #[arg(long)]
        captive_spoof: bool,
        /// Daemon control socket to poll: toggle captive-spoofing with the
        /// session's liveness (attach uses this; the CLI sets it statically).
        #[arg(long)]
        follow_session: Option<PathBuf>,
        /// Print the proxy plan without binding the socket.
        #[arg(long)]
        dry_run: bool,
    },
    /// Run an active non-tunnel TTL=1 leak probe across physical default-route interfaces.
    LeakCheck {
        /// The configuration file.
        config: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Print the probe plan without sending packets.
        #[arg(long)]
        dry_run: bool,
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
        Action::App {
            config,
            name,
            cmd,
            dry_run,
        } => member::app_run(config, name, cmd, *dry_run),
        Action::Watch {
            config,
            dry_run,
            allow_insecure_config,
        } => watch(config, *dry_run, *allow_insecure_config),
        Action::Strip { config } => strip(config),
        Action::DnsProxy {
            config,
            listen,
            captive_spoof,
            follow_session,
            dry_run,
        } => load_normalized(config)
            .map_err(Box::<dyn std::error::Error>::from)
            .and_then(|loaded| {
                dns::run_dns_proxy(
                    &loaded,
                    *listen,
                    *captive_spoof,
                    follow_session.clone(),
                    *dry_run,
                )
            }),
        Action::LeakCheck {
            config,
            json,
            dry_run,
        } => leak_check::leak_check_cmd(config, *json, *dry_run),
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
pub(crate) fn load_normalized(config_path: &Path) -> Result<Config, ConfigError> {
    Config::load_normalized(config_path)
}

/// Persist the completed local routing mark so every later tool — `down`,
/// `detach`, `vallum uninstall` — computes the same one this attach used.
pub(crate) fn heal_config_on_disk(config_path: &Path, dry_run: bool) {
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

/// Load the config, gate its hooks on the privilege boundary, persist the
/// healed local mark, and derive the interface and table every command works
/// against. This is the shared prologue of `up`, `down`, `attach` and `detach`.
fn materialize(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(Config, String, String), Box<dyn std::error::Error>> {
    let config = load_normalized(config_path)?;
    check_config_ownership(config_path, &config, allow_insecure_config)?;
    heal_config_on_disk(config_path, dry_run);
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto").to_owned();
    Ok((config, interface, table))
}

/// Start the daemon, and record its pid so [`down`] and [`rollback`] can stop
/// it by number rather than by search.
fn spawn_daemon(binary: &str, config_path: &Path) -> Result<Child, Box<dyn std::error::Error>> {
    let child = Command::new(binary)
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
    Ok(child)
}

/// Whether a `vallum` command line is a `run --config <path>` for this config.
///
/// The pidfile holds a number, and numbers are reused; a stale one must be a
/// no-op rather than a stray kill of whatever now owns the pid.
fn names_this_daemon(args: &[String], config_path: &Path) -> bool {
    if !args.iter().any(|arg| arg == "run") {
        return false;
    }
    let declared = args
        .iter()
        .position(|arg| arg == "--config")
        .and_then(|at| args.get(at + 1));
    let Some(declared) = declared else {
        return false;
    };
    let declared = Path::new(declared);
    if declared == config_path {
        return true;
    }
    // `up` may have been given a relative path and `down` an absolute one.
    match (declared.canonicalize(), config_path.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn daemon_is_ours(pid: &str, config_path: &Path) -> bool {
    let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<String> = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    names_this_daemon(&args, config_path)
}

/// How long a daemon gets to exit after SIGTERM.
///
/// A restart that starts the replacement before the old one let go of the
/// control socket fails on the socket, which is a confusing way to learn that the
/// two overlapped.
const DAEMON_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

fn wait_for_exit(pid: &str) -> bool {
    let entry = format!("/proc/{pid}");
    let deadline = Instant::now() + DAEMON_EXIT_TIMEOUT;
    while Path::new(&entry).exists() && Instant::now() < deadline {
        sleep(Duration::from_millis(50));
    }
    !Path::new(&entry).exists()
}

/// Stop the daemon recorded in the config's pidfile, if it is still that daemon,
/// and wait for it to go.
///
/// Returns an error only when a daemon that was signalled is still there: `up`
/// must not start a second one over it, while `down` and `rollback` have nothing
/// better to do than report and carry on.
fn stop_daemon(config_path: &Path, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let pidfile = config_path.with_extension("pid");
    let Ok(text) = fs::read_to_string(&pidfile) else {
        return Ok(());
    };
    let pid = text.trim();
    if !daemon_is_ours(pid, config_path) {
        return Ok(());
    }
    if dry_run {
        println!("kill -TERM {pid}");
        return Ok(());
    }
    let _ = Command::new("kill").arg("-TERM").arg(pid).status();
    let _ = fs::remove_file(&pidfile);
    if wait_for_exit(pid) {
        Ok(())
    } else {
        Err(
            format!("daemon {pid} did not exit after SIGTERM; refusing to start a second one")
                .into(),
        )
    }
}

struct ForwardingNatPlan {
    has_v4: bool,
    has_v6: bool,
    sysctl_text: String,
    nft_script: String,
}

/// Derive the persistent sysctl and `inet vallum` NAT masquerade script when
/// `[interface] forward = true` is active on a gateway/exit config.
fn plan_forwarding_nat(
    config: &Config,
) -> Result<Option<ForwardingNatPlan>, Box<dyn std::error::Error>> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for raw in member::addresses(config) {
        let net = raw.parse::<ipnet::IpNet>()?.trunc();
        match net {
            ipnet::IpNet::V4(_) => v4.push(net),
            ipnet::IpNet::V6(_) => v6.push(net),
        }
    }
    if v4.is_empty() && v6.is_empty() {
        return Ok(None);
    }

    let mut sysctl_text = String::from("# Written by vallum-quick (forward = true).\n");
    if !v4.is_empty() {
        sysctl_text.push_str("net.ipv4.ip_forward = 1\n");
    }
    if !v6.is_empty() {
        sysctl_text.push_str("net.ipv6.conf.all.forwarding = 1\n");
    }

    let mut nft_script = String::from(
        "table inet vallum {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n",
    );
    for subnet in &v4 {
        nft_script.push_str(&format!("    ip saddr {subnet} masquerade\n"));
    }
    for subnet in &v6 {
        nft_script.push_str(&format!("    ip6 saddr {subnet} masquerade\n"));
    }
    nft_script.push_str("  }\n}\n");

    Ok(Some(ForwardingNatPlan {
        has_v4: !v4.is_empty(),
        has_v6: !v6.is_empty(),
        sysctl_text,
        nft_script,
    }))
}

/// Reconcile kernel IP forwarding and the `inet vallum` NAT masquerade table so
/// gateway routing survives host reboots cleanly.
fn ensure_forwarding_and_nat(
    config: &Config,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(plan) = plan_forwarding_nat(config)? else {
        return Ok(());
    };
    if dry_run {
        if plan.has_v4 {
            println!("sysctl -w net.ipv4.ip_forward=1");
        }
        if plan.has_v6 {
            println!("sysctl -w net.ipv6.conf.all.forwarding=1");
        }
        println!("nft -f - (table inet vallum masquerade)");
        return Ok(());
    }

    let _ = fs::write("/etc/sysctl.d/90-vallum.conf", &plan.sysctl_text);
    if plan.has_v4 {
        fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")?;
    }
    if plan.has_v6 {
        fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1\n")?;
    }

    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "vallum"])
        .output();
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        std::io::Write::write_all(&mut stdin, plan.nft_script.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nft masquerade setup failed: {}", stderr.trim()).into());
    }
    Ok(())
}

/// Everything after the daemon side of an attach: routes, DNS, then the post
/// hooks. A DNS failure takes the routes back out — a full tunnel must not
/// take the host's traffic while its resolver is unmanaged — and the caller's
/// `undo` says what that means for it (`up` also stops the daemon).
///
/// `unit` is the systemd instance name the config's stem implies, used only in
/// messages: a recovery instruction that names the wrong unit is worse than one
/// that names none, so callers pass `None` when the stem is unreadable.
fn attach_host_side(
    config: &Config,
    config_path: &Path,
    interface: &str,
    table: &str,
    unit: Option<&str>,
    dry_run: bool,
    undo: impl FnOnce(&Config, &str, &str, bool),
) -> Result<(), Box<dyn std::error::Error>> {
    // Per-app means the host is not a tunnel client: the device moves into the
    // member namespace and the host keeps its own routes and resolver. Nothing
    // is applied here for the host, so nothing here can leak.
    if config.quick.app_class {
        if config.quick.dns_proxy {
            return Err(
                "`app_class = true` tunnels only the member namespace, whose private \
                 resolv.conf already names the tunnel's servers: `[quick] dns_proxy` \
                 has no host resolver to take over there. Set one or the other"
                    .into(),
            );
        }
        if let Err(error) = member::attach(config, interface, unit, dry_run) {
            undo(config, interface, table, dry_run);
            return Err(error);
        }
        for hook in &config.quick.post_up {
            run_hook(hook, dry_run)?;
        }
        return Ok(());
    }

    if config.interface.forward == Some(true) {
        ensure_forwarding_and_nat(config, dry_run)?;
    }

    apply_routes(config, interface, table, dry_run)?;

    let effective_dns = config.quick.effective_dns_servers();
    if !effective_dns.is_empty() {
        // Proxy mode: the loopback forwarder is the resolver. It must own the
        // port before the resolver points at it — a bind failure here is a
        // plain DNS-configuration failure and takes the routes back out, so
        // the host is never left resolving into a proxy that is not there.
        let dns_result = (|| -> Result<(), String> {
            if config.quick.dns_proxy {
                let control = session::control_socket(config, config_path, interface);
                dns::spawn_for_attach(config_path, interface, &control, dry_run)
                    .map_err(|error| error.to_string())?;
            }
            let proxy_servers = if config.quick.dns_proxy {
                vec!["127.0.0.1".to_owned()]
            } else {
                effective_dns.clone()
            };
            set_dns(
                interface,
                &proxy_servers,
                dns_domain(config).as_deref(),
                dry_run,
            )
            .map_err(|error| {
                format!(
                    "DNS configuration failed for `{interface}`: {error}; refusing to attach \
                     to prevent DNS leaks (set `[quick] dns = []` if you manage DNS manually)"
                )
            })
        })();
        if let Err(error) = dns_result {
            undo(config, interface, table, dry_run);
            return Err(error.into());
        }
    }

    for hook in &config.quick.post_up {
        run_hook(hook, dry_run)?;
    }
    Ok(())
}

/// The host-level half of teardown: down hooks, routes, DNS, then the caller's
/// daemon work, then post hooks. `down` stops the daemon in between;
/// `detach` has nothing to stop.
fn withdraw_host_side(
    config: &Config,
    interface: &str,
    table: &str,
    dry_run: bool,
    between: impl FnOnce(),
) -> Result<(), Box<dyn std::error::Error>> {
    for hook in &config.quick.pre_down {
        run_hook(hook, dry_run)?;
    }

    // Per-app: the device goes back to this namespace and the holder stops.
    // The host never had routes or DNS of the tunnel's to take back.
    if config.quick.app_class {
        member::detach(interface, dry_run);
        between();
        for hook in &config.quick.post_down {
            run_hook(hook, dry_run)?;
        }
        return Ok(());
    }

    remove_routes(config, interface, table, dry_run);
    leak_check::remove_state(interface, dry_run);
    if config.quick.dns_proxy {
        dns::stop_for_detach(interface, dry_run);
    }
    if !config.quick.effective_dns_servers().is_empty() {
        unset_dns(interface, dry_run)?;
    }

    between();

    for hook in &config.quick.post_down {
        run_hook(hook, dry_run)?;
    }
    Ok(())
}

pub(crate) fn up(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config, interface, table) = materialize(config_path, dry_run, allow_insecure_config)?;
    let entry_path = resolve_via_entry(config_path, &config, dry_run, allow_insecure_config)?;
    if let Some(ref entry) = entry_path {
        up(entry, dry_run, allow_insecure_config)?;
    }

    for hook in &config.quick.pre_up {
        run_hook(hook, dry_run)?;
    }

    let result = up_after_pre(&config, config_path, &interface, &table, dry_run);
    if result.is_err() {
        // A partially applied `up` must not leave a daemon or routes behind.
        rollback(&config, config_path, &interface, &table, dry_run);
        if let Some(ref entry) = entry_path {
            let _ = down(entry, dry_run, allow_insecure_config);
        }
    }
    result
}

fn resolve_via_entry(
    config_path: &Path,
    config: &Config,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let Some(ref via) = config.quick.via else {
        return Ok(None);
    };
    let entry_path = vallum_config::resolve_via_path(config_path, via);
    if entry_path == config_path {
        return Err("[quick] via cannot point to itself".into());
    }
    let entry_cfg = load_normalized(&entry_path)?;
    check_config_ownership(&entry_path, &entry_cfg, allow_insecure_config)?;
    if entry_cfg.quick.via.is_some() {
        return Err("chained [quick] via beyond 2 hops is not supported".into());
    }
    if !dry_run && config.interface.outer_mtu.unwrap_or(1500) > 1380 {
        eprintln!(
            "vallum-quick: multihop exit config has outer_mtu > 1380; consider setting \
             outer_mtu = 1380 to avoid inner-in-outer fragmentation"
        );
    }
    Ok(Some(entry_path))
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

    // A per-app crash leaves the previous daemon without an interface (the
    // member namespace took the device with it), and only a new daemon can
    // create another — the old one would also hold the UDP port. `up` owns the
    // daemon it spawned, so it can be the whole recovery: with no tunnel device
    // here, whatever the pidfile records is not serving this config, so stop it
    // (never a process that is not that daemon — see `stop_daemon`) and start a
    // fresh one. The attach below then installs a namespace around the new
    // device.
    if config.quick.app_class && !member::device_present(interface) {
        stop_daemon(config_path, dry_run)?;
    }

    let mut child = if dry_run {
        println!("{binary} run --config {}", config_path.display());
        None
    } else {
        Some(spawn_daemon(&binary, config_path)?)
    };

    if !dry_run {
        wait_for_interface(interface)?;
        wait_for_session(config, config_path, interface)?;
    }

    attach_host_side(
        config,
        config_path,
        interface,
        table,
        config_path.file_stem().and_then(|stem| stem.to_str()),
        dry_run,
        |c, i, t, d| rollback(c, config_path, i, t, d),
    )?;

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
    // A failed attach may have moved the device or created the holder; both are
    // the namespace's to undo, and detach is a no-op without a record.
    member::detach(interface, dry_run);
    if !config.quick.app_class {
        remove_routes(config, interface, table, dry_run);
        if config.quick.dns_proxy {
            dns::stop_for_detach(interface, dry_run);
        }
        if !config.quick.effective_dns_servers().is_empty() {
            let _ = unset_dns(interface, dry_run);
        }
    }
    let _ = stop_daemon(config_path, dry_run);
}

pub(crate) fn down(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config, interface, table) = materialize(config_path, dry_run, allow_insecure_config)?;
    let entry_path = resolve_via_entry(config_path, &config, dry_run, allow_insecure_config)?;
    let res = withdraw_host_side(&config, &interface, &table, dry_run, || {
        let _ = stop_daemon(config_path, dry_run);
    });
    if let Some(ref entry) = entry_path {
        down(entry, dry_run, allow_insecure_config)?;
    }
    res
}

/// Apply the config's host-level work to an interface someone else started.
///
/// `vallum@.service` owns the daemon and `vallum-quick@.service` runs this, so
/// routes and DNS are applied without spawning a second daemon and without
/// widening the daemon's sandbox to let it write `/etc/resolv.conf`.
pub(crate) fn attach(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config, interface, table) = materialize(config_path, dry_run, allow_insecure_config)?;
    let entry_path = resolve_via_entry(config_path, &config, dry_run, allow_insecure_config)?;
    if let Some(ref entry) = entry_path {
        attach(entry, dry_run, allow_insecure_config)?;
    }

    for hook in &config.quick.pre_up {
        run_hook(hook, dry_run)?;
    }

    let unit = config_path.file_stem().and_then(|stem| stem.to_str());
    if !dry_run {
        // The crash case has a better answer than "nothing started the daemon":
        // the namespace took the device, and the daemon that lost it has to be
        // restarted before any wait can succeed. `attach` does not own that
        // daemon (systemd does), so it names the unit instead of restarting it.
        if config.quick.app_class {
            member::refuse_if_device_lost(&interface, unit)?;
        }
        if let Err(err) = wait_for_interface(&interface)
            .map_err(|_| interface_missing(&interface, config.quick.pre_up.len(), unit))
            .and_then(|()| wait_for_session(&config, config_path, &interface))
        {
            if let Some(ref entry) = entry_path {
                let _ = detach(entry, dry_run, allow_insecure_config);
            }
            return Err(err);
        }
    }

    let res = attach_host_side(
        &config,
        config_path,
        &interface,
        &table,
        unit,
        dry_run,
        remove_routes,
    );
    if res.is_err() {
        if let Some(ref entry) = entry_path {
            let _ = detach(entry, dry_run, allow_insecure_config);
        }
    }
    res
}

/// Remove what [`attach`] applied, leaving the daemon running.
pub(crate) fn detach(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config, interface, table) = materialize(config_path, dry_run, allow_insecure_config)?;
    let entry_path = resolve_via_entry(config_path, &config, dry_run, allow_insecure_config)?;
    let res = withdraw_host_side(&config, &interface, &table, dry_run, || ());
    if let Some(ref entry) = entry_path {
        detach(entry, dry_run, allow_insecure_config)?;
    }
    res
}

pub(crate) fn save(
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
pub(crate) fn strip_quick(text: &str) -> String {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::dns::{
        backup_and_write_resolv_conf_at, dns_backend_from, dns_domain, restore_resolv_conf_at,
        DnsBackend,
    };
    use crate::hooks::check_config_ownership_as;
    use crate::routes::{
        covers, dev_of, managed_routes, plan_blackhole_routes, plan_routes, policy_for, read_plan,
        route_query, state_path, teardown_plan, Prefix, RoutePlan, POLICY_TABLE,
    };
    use crate::watch::{
        clamp_dead_after, parse_session_health_at, verdict, verdict_carrying, withdraw_for_failure,
        FailurePolicy, Verdict, WithdrawReason, DEAD_AFTER, WATCH_POLL,
    };

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
    fn only_a_run_of_this_config_is_the_daemon_to_stop() {
        let args = |line: &str| -> Vec<String> { line.split(' ').map(str::to_owned).collect() };
        let path = Path::new("/etc/vallum/vallum0.toml");

        assert!(names_this_daemon(
            &args("/usr/bin/vallum run --config /etc/vallum/vallum0.toml"),
            path
        ));
        // A reused pid running something else must never be signalled.
        assert!(!names_this_daemon(
            &args("/usr/bin/nginx -g daemon off;"),
            path
        ));
        // Same binary, different config: not ours.
        assert!(!names_this_daemon(
            &args("/usr/bin/vallum run --config /etc/vallum/laptop.toml"),
            path
        ));
        // `vallum show` on our config is not the daemon either.
        assert!(!names_this_daemon(
            &args("/usr/bin/vallum show --config /etc/vallum/vallum0.toml"),
            path
        ));
        assert!(!names_this_daemon(&args("/usr/bin/vallum run"), path));
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
    fn a_failed_backup_never_touches_resolv_conf() {
        // The hazard the fix closes: the backup is the only way back, so a
        // backup that cannot be written must stop everything before the
        // resolver file is deleted or overwritten.
        let dir =
            std::env::temp_dir().join(format!("vallum-quick-resolv-fail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("resolv.conf");
        fs::write(&resolv, "nameserver 192.168.1.1\n").unwrap();
        // A path that cannot be turned into the backup's parent directory.
        let blocker = dir.join("blocker");
        fs::write(&blocker, "not a directory").unwrap();
        let bak = blocker.join("resolv.conf.bak");

        let servers = vec!["1.1.1.1".to_owned()];
        assert!(backup_and_write_resolv_conf_at(&resolv, &bak, "v0", &servers, false).is_err());
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "nameserver 192.168.1.1\n"
        );

        let _ = fs::remove_dir_all(&dir);
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
    fn failure_policy_honors_the_config_and_the_edge_supplies_the_environment() {
        // `from_config` is the pure projection now: the environment is read at
        // the `watch` edge, with the precedence env → config → block spelled
        // out there. This pins the pure half.
        let restore = config_with("fp-restore", "\n[quick]\nfailure_policy = \"restore\"\n");
        assert_eq!(FailurePolicy::from_config(&restore), FailurePolicy::Restore);
        let bogus = config_with(
            "fp-bogus",
            "\n[quick]\nfailure_policy = \"patch-everything\"\n",
        );
        assert_eq!(FailurePolicy::from_config(&bogus), FailurePolicy::Block);
    }

    #[test]
    fn a_fail_closed_withdraw_releases_the_record_so_a_restart_is_not_stuck() {
        // The bug this closes: a blackhole withdraw overwrote the tunnel
        // routes but left the plan record, so a restarted watchdog re-derived
        // `attached` as true and, with the session live, held forever — a
        // recovered host stayed blackholed until someone intervened.
        let dir = std::env::temp_dir().join(format!("vallum-quick-block-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\nfwmark = 51820\n\n\
             [[peer]]\nname = \"p\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        std::env::set_var("VALLUM_STATE_DIR", &dir);
        let state = state_path("v0");
        fs::write(
            &state,
            "rule add not fwmark 51820 table 51820\n\
             rule add table main suppress_prefixlength 0\n\
             route add 0.0.0.0/0 dev v0 table 51820\n",
        )
        .unwrap();

        assert!(read_plan(&state).is_some());

        // Fail closed: the blackhole replaces the tunnel routes, so the
        // record must not claim they are still installed.
        withdraw_for_failure(
            &Config::load(&path).unwrap(),
            "v0",
            "auto",
            FailurePolicy::Block,
            false,
            "no handshake",
        );
        assert!(
            !state.exists(),
            "the record outlived the routes it described"
        );

        // A restarted watchdog re-derives `attached = false` — and a live
        // session then reaches the Restore arm instead of holding forever.
        assert!(read_plan(&state).is_none());

        std::env::remove_var("VALLUM_STATE_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_record_line_is_never_a_command() {
        // The boundary contract: the record is parsed by whatever reads the
        // state file, so only lines this crate could have written become
        // commands; anything else is named and skipped, never handed to `ip`.
        let plan = RoutePlan::parse(
            "route add 10.9.0.0/24 dev v0\n\
             echo hello && rm -rf /\n\
             addr add 1.2.3.4 dev lo\n",
        );
        assert_eq!(plan.render(), "route add 10.9.0.0/24 dev v0\n");
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

    #[test]
    fn forward_true_plans_sysctl_and_nft_masquerade_and_dry_run_succeeds() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-fwd-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"vallum0\"\nprivate_key = \"k\"\n\
             address = \"10.7.0.1/24\"\nforward = true\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let plan = plan_forwarding_nat(&config)
            .unwrap()
            .expect("gateway config with address plans forwarding/NAT");
        assert!(plan.has_v4);
        assert!(!plan.has_v6);
        assert!(plan.sysctl_text.contains("net.ipv4.ip_forward = 1"));
        assert!(plan.nft_script.contains("ip saddr 10.7.0.0/24 masquerade"));
        ensure_forwarding_and_nat(&config, true).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn content_blockers_prepend_magic_resolver_to_effective_dns() {
        let config = config_with(
            "content-blockers",
            "\n[quick]\ndns = [\"9.9.9.9\"]\ncontent_blockers = [\"ads\", \"trackers\", \"malware\"]\n\n\
             [[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        );
        assert_eq!(
            config.quick.effective_dns_servers(),
            vec!["100.64.0.7".to_owned(), "9.9.9.9".to_owned()]
        );
    }

    #[test]
    fn multihop_via_plans_entry_and_exit_and_refuses_chained_or_self_via() {
        let dir =
            std::env::temp_dir().join(format!("vallum-quick-multihop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let entry_path = dir.join("entry.toml");
        fs::write(
            &entry_path,
            "[interface]\nname = \"vallum-entry\"\nprivate_key = \"k1\"\naddress = \"10.8.0.2/24\"\n\n\
             [[peer]]\nname = \"entry\"\npublic_key = \"k2\"\nendpoint = \"203.0.113.10:51820\"\n\
             allowed_ips = [\"198.51.100.20/32\"]\n",
        )
        .unwrap();

        let exit_path = dir.join("exit.toml");
        fs::write(
            &exit_path,
            "[interface]\nname = \"vallum-exit\"\nprivate_key = \"k3\"\naddress = \"10.9.0.2/24\"\n\n\
             [quick]\nvia = \"entry.toml\"\n\n\
             [[peer]]\nname = \"exit\"\npublic_key = \"k4\"\nendpoint = \"198.51.100.20:51820\"\n\
             allowed_ips = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();

        up(&exit_path, true, true).unwrap();
        down(&exit_path, true, true).unwrap();

        let chained_path = dir.join("chained.toml");
        fs::write(
            &chained_path,
            "[interface]\nname = \"vallum-chain\"\nprivate_key = \"k5\"\naddress = \"10.10.0.2/24\"\n\n\
             [quick]\nvia = \"exit.toml\"\n\n\
             [[peer]]\nname = \"chain\"\npublic_key = \"k6\"\nendpoint = \"198.51.100.21:51820\"\n\
             allowed_ips = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        assert!(up(&chained_path, true, true).is_err());

        let self_path = dir.join("self_via.toml");
        fs::write(
            &self_path,
            "[interface]\nname = \"vallum-self\"\nprivate_key = \"k7\"\naddress = \"10.11.0.2/24\"\n\n\
             [quick]\nvia = \"self_via.toml\"\n\n\
             [[peer]]\nname = \"self\"\npublic_key = \"k8\"\nendpoint = \"198.51.100.22:51820\"\n\
             allowed_ips = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        assert!(up(&self_path, true, true).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
