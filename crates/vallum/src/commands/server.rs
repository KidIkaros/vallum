// SPDX-License-Identifier: Apache-2.0

//! `vallum server`: prepare a host to be a tunnel server.
//!
//! One command does what the WireGuard walkthrough does by hand: generate the
//! server key, write `/etc/vallum/<name>.toml`, enable forwarding, open the UDP
//! port, install the masquerade rule, and start the unit. Every step is
//! idempotent, so re-running it converges instead of duplicating, and
//! `--dry-run` prints the whole plan without touching the host.

use crate::say;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use ipnet::IpNet;
use serde::Serialize;
use vallum_crypto_sdk::SdkSuite;

use crate::config::Config;
use crate::{control, entropy, hostnet, keys, Error};

/// The two units a server needs: the daemon, and the host-networking one-shot.
const DAEMON_UNIT: &str = include_str!("../../../../packaging/vallum@.service");
const QUICK_UNIT: &str = include_str!("../../../../packaging/vallum-quick@.service");
const WATCH_UNIT: &str = include_str!("../../../../packaging/vallum-quick-watch@.service");
const ENROLL_UNIT: &str = include_str!("../../../../packaging/vallum-enroll@.service");
/// `/run/vallum` holds every control socket on the machine. The units only get
/// a writable window into it when it exists, so it must be created before the
/// first unit starts — and by something that is not a unit, or it disappears
/// when that unit stops. See ADR-0017.
const TMPFILES: &str = include_str!("../../../../packaging/vallum-tmpfiles.conf");

#[derive(Debug, Args)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub command: ServerCommand,
}

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Generate the key, write the config, and start the service.
    Init(InitArgs),
    /// Turn one-time token enrolment on or off, with its service and port.
    Enroll(EnrollArgs),
    /// Undo the host changes `server init` made (units, NAT, firewall, sysctl).
    Teardown(TeardownArgs),
}

#[derive(Debug, Args)]
pub struct TeardownArgs {
    /// The server configuration file to tear down.
    #[arg(long, value_name = "FILE", default_value = crate::host::paths::DEFAULT_CONFIG)]
    pub config: PathBuf,

    /// Also delete the config file and keys in `/etc/vallum`. Without this,
    /// they stay in place so `server init` can bring the same server back up.
    #[arg(long)]
    pub purge: bool,

    /// Show what would be removed, without changing the host.
    #[arg(long)]
    pub dry_run: bool,
}

/// Reverse the host changes `server init` installed.
///
/// A system with an inflow (`server init`) and no outflow forces operators to
/// copy-paste an eight-line shell block to undo a trial server install.
pub fn teardown(args: &TeardownArgs) -> Result<(), Error> {
    if !args.dry_run && !nix::unistd::geteuid().is_root() {
        return Err(Error::Precondition(
            "`vallum server teardown` removes systemd units and firewall rules; \
             run it as root, or pass --dry-run to see the plan"
                .to_owned(),
        ));
    }
    let config = vallum_config::Config::load(&args.config).ok();
    let instance = args
        .config
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
        .to_owned();
    let interface = config
        .as_ref()
        .and_then(|cfg| cfg.interface.name.clone())
        .unwrap_or_else(|| instance.clone());
    let listen = config
        .as_ref()
        .and_then(|cfg| cfg.interface.listen.as_deref())
        .and_then(|listen| listen_port(listen).ok())
        .unwrap_or(51820);
    let enroll_port = config
        .as_ref()
        .and_then(|cfg| cfg.enroll.port)
        .unwrap_or_else(|| listen.saturating_add(1));
    let ports = [listen, enroll_port];

    for unit in [
        format!("vallum-enroll@{instance}"),
        format!("vallum-quick@{instance}"),
        format!("vallum@{instance}"),
    ] {
        if args.dry_run {
            say!("   would disable --now {unit}");
        } else {
            let _ = systemctl(&["disable", "--now", &unit]);
        }
    }

    let steps = hostnet::plan_teardown(&hostnet::inspect(), &ports, &interface);
    let _ = hostnet::apply(&steps, args.dry_run)?;

    let sysctl = Path::new("/etc/sysctl.d/90-vallum.conf");
    if sysctl.exists() || args.dry_run {
        if args.dry_run {
            say!("   would remove {}", sysctl.display());
        } else {
            let _ = std::fs::remove_file(sysctl);
            say!("   ok    remove {}", sysctl.display());
        }
    }

    if args.purge {
        if args.dry_run {
            say!(
                "   would remove {} and its keys (--purge)",
                args.config.display()
            );
        } else {
            if let Some(cfg) = &config {
                let key = crate::config::resolve_key_path(&args.config, &cfg.interface.private_key);
                let _ = std::fs::remove_file(key);
            }
            let _ = std::fs::remove_file(&args.config);
            say!("   ok    removed {}", args.config.display());
        }
    } else {
        say!(
            "   kept  {} (pass --purge to delete the config and key too)",
            args.config.display()
        );
    }
    say!("torn down: server `{instance}`");
    Ok(())
}

#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// The configuration file to change.
    #[arg(long, value_name = "FILE", default_value = crate::host::paths::DEFAULT_CONFIG)]
    pub config: PathBuf,

    /// Allow devices to enrol with a one-time token.
    #[arg(long, conflicts_with = "disable")]
    pub enable: bool,

    /// Stop answering enrolment requests, and try to close the port.
    #[arg(long)]
    pub disable: bool,

    /// Show what would change, without changing it.
    #[arg(long)]
    pub dry_run: bool,
}

/// Flip `[enroll] enabled` and keep the unit and firewall in step with it.
///
/// Without this an operator has to know to edit the config, install the unit,
/// and open a second UDP port — which is how a feature ends up documented but
/// unused.
pub fn enroll(args: &EnrollArgs) -> Result<(), Error> {
    if !args.enable && !args.disable {
        return Err(Error::Usage(
            "say which: `--enable` or `--disable`".to_owned(),
        ));
    }
    let text = std::fs::read_to_string(&args.config).map_err(|source| Error::IoPath {
        action: "read the config",
        path: args.config.clone(),
        source,
    })?;
    let config = vallum_config::Config::load(&args.config)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    // The responder's port must exist before the flag flips: enabling with an
    // unbindable port writes `enabled = true`, crash-loops the unit, and mints
    // invites that name a port nothing serves. Disabling never needs it —
    // closing the firewall is best-effort anyway.
    let port = match enroll_port(&config) {
        Ok(port) => Some(port),
        Err(error) => {
            if args.enable {
                return Err(error);
            }
            None
        }
    };

    let updated = set_enroll_flag(&text, args.enable);
    if args.dry_run {
        say!(
            "   would set [enroll] enabled = {} in {}",
            args.enable,
            args.config.display()
        );
        say!(
            "   would {} vallum-enroll@{interface}",
            if args.enable { "start" } else { "stop" }
        );
        match port {
            Some(port) => say!(
                "   would {} UDP {port}",
                if args.enable { "open" } else { "try to close" }
            ),
            None => say!("   would try to close the enrolment port"),
        }
        return Ok(());
    }
    write_atomic(&args.config, &updated, 0o600)?;
    // Parse it back: a config that no longer loads is worse than the toggle.
    vallum_config::Config::load(&args.config)?;

    if args.enable {
        // Already proven derivable above; re-derived rather than assumed.
        let port = enroll_port(&config)?;
        if Path::new("/etc/systemd/system/vallum@.service").exists()
            && Path::new("/etc/systemd/system/vallum-enroll@.service").exists()
        {
            // The tunnel's units already run: opening the enrolment window
            // must not bounce the tunnel it serves, so `start` the responder
            // rather than the full install — which restarts vallum@ to pick
            // up re-init state that did not change. Started, not enabled:
            // ADR-0034.
            systemctl(&["start", &format!("vallum-enroll@{interface}")])?;
        } else {
            install_service(&interface, false)?;
        }
        let steps = hostnet::plan_port(&hostnet::inspect(), port);
        let _ = hostnet::apply(&steps, false)?;
        say!("token enrolment on for {interface}: UDP {port}");
        say!("   invite a device with `vallum peer invite <name>`");
        return Ok(());
    }

    let _ = systemctl(&["disable", "--now", &format!("vallum-enroll@{interface}")]);
    // Closing the port is best effort across three backends; say what ran.
    // A config whose port cannot be derived (a client shape) never opened one.
    if let Some(port) = port {
        let attempts: [(&str, Vec<&str>); 3] = [
            ("ufw", vec!["delete", "allow", "PORT/udp"]),
            (
                "iptables",
                vec![
                    "-D", "INPUT", "-p", "udp", "--dport", "PORT", "-j", "ACCEPT",
                ],
            ),
            (
                "firewall-cmd",
                vec!["--permanent", "--remove-port=PORT/udp"],
            ),
        ];
        let mut closed = Vec::new();
        for (program, args) in attempts {
            let port_text = port.to_string();
            let rendered: Vec<String> = args
                .iter()
                .map(|arg| {
                    arg.replace("PORT/udp", &format!("{port}/udp"))
                        .replace("PORT", &port_text)
                })
                .collect();
            if Command::new(program)
                .args(&rendered)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
            {
                closed.push(program);
            }
        }
        say!("token enrolment off for {interface}");
        if closed.is_empty() {
            say!("   the port rule was not found by ufw, iptables, or firewalld —");
            say!("   check that UDP {port} is closed if you no longer want it open");
        } else {
            say!("   closed UDP {port} through {}", closed.join(", "));
        }
    } else {
        say!("token enrolment off for {interface}");
    }
    Ok(())
}

/// Set `[enroll] enabled` in a config's text, adding the table if absent.
fn set_enroll_flag(text: &str, enabled: bool) -> String {
    let flag = format!("enabled = {enabled}");
    let mut out: Vec<String> = Vec::new();
    let mut in_enroll = false;
    let mut seen_enroll = false;
    let mut wrote_flag = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if in_enroll && !wrote_flag {
                out.push(flag.clone());
                wrote_flag = true;
            }
            in_enroll = trimmed == "[enroll]";
            seen_enroll |= in_enroll;
            out.push(line.to_owned());
            continue;
        }
        if in_enroll && trimmed.starts_with("enabled") {
            out.push(flag.clone());
            wrote_flag = true;
            continue;
        }
        out.push(line.to_owned());
    }
    if in_enroll && !wrote_flag {
        out.push(flag.clone());
    }
    if !seen_enroll {
        out.push(String::new());
        out.push("[enroll]".to_owned());
        out.push(flag);
    }
    let mut joined = out.join("\n");
    joined.push('\n');
    joined
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// The configuration file to write.
    #[arg(long, value_name = "FILE", default_value = crate::host::paths::DEFAULT_CONFIG)]
    pub config: PathBuf,

    /// The kernel interface name. Defaults to the config file's stem.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// The address and prefix for the interface. Repeat for dual-stack.
    #[arg(long = "address", value_name = "CIDR")]
    pub addresses: Vec<String>,

    /// The UDP address to listen on.
    #[arg(long, value_name = "ADDR:PORT", default_value = "0.0.0.0:51820")]
    pub listen: String,

    /// The address clients dial, printed in their bundles. Detected if absent.
    #[arg(long, value_name = "HOST:PORT")]
    pub endpoint: Option<String>,

    /// The control socket path. Defaults to `/run/vallum/<name>.sock`.
    #[arg(long, value_name = "PATH")]
    pub control: Option<PathBuf>,

    /// Allow devices to enrol with a one-time token, which opens UDP
    /// `listen + 1` and enables the `vallum-enroll@` unit.
    #[arg(long)]
    pub enroll: bool,

    /// A DNS server to push to clients through `[quick]`. Repeatable.
    #[arg(long, value_name = "ADDR")]
    pub dns: Vec<String>,

    /// The user to drop to after the interface and socket are open.
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,

    /// Do not install the masquerade rule.
    #[arg(long)]
    pub no_nat: bool,

    /// Do not open the UDP port in the host firewall.
    #[arg(long)]
    pub no_firewall: bool,

    /// Do not enable IP forwarding.
    #[arg(long)]
    pub no_forward: bool,

    /// Do not install or start the systemd units.
    #[arg(long)]
    pub no_service: bool,

    /// Do not change the host's network configuration: no NAT, no firewall
    /// rule, no `ip_forward` (implies the three `--no-*` above). The systemd
    /// units are still installed unless `--no-service` is also passed.
    #[arg(long)]
    pub no_host: bool,

    /// Print every step and change nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// Rewrite an existing config (the key is never regenerated).
    #[arg(long)]
    pub force: bool,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct Report {
    config: PathBuf,
    key: PathBuf,
    interface: String,
    addresses: Vec<String>,
    listen: String,
    endpoint: Option<String>,
    public_key: String,
    firewall: &'static str,
    host_steps: Vec<String>,
    service: String,
    control: Option<String>,
    next: String,
}

/// `vallum server init`.
///
/// # Errors
///
/// A precondition that cannot be met (not root, no `/etc/vallum`), or a host
/// step that failed — named with what it was trying to do.
pub fn server(args: &ServerArgs) -> Result<(), Error> {
    match &args.command {
        ServerCommand::Init(init) => self::init(init),
        ServerCommand::Enroll(args) => enroll(args),
        ServerCommand::Teardown(args) => teardown(args),
    }
}

/// The inner address plan a server gets unless it is told otherwise.
///
/// A `/24` holds 253 peer addresses, eight times below the 2,000-peer target in
/// `docs/requirements.md` — a gap that stayed invisible until someone enrolled
/// their 254th device and read "the tunnel has no free address left". The
/// address plan is the first capacity ceiling, so the default clears the target
/// with room: `/20` is 4,094 devices. The IPv6 prefix is a unique-local /64 and
/// is not a constraint.
pub const DEFAULT_ADDRESSES: [&str; 2] = ["10.7.0.1/20", "fd00:7::1/64"];

pub(crate) fn init(args: &InitArgs) -> Result<(), Error> {
    let root = nix::unistd::geteuid().is_root();
    let needs_service = !args.no_service && Path::new("/run/systemd/system").exists();
    if !args.dry_run && (!args.no_host || needs_service) && !root {
        return Err(Error::Precondition(
            "server setup changes the host firewall, forwarding, and systemd units; \
             run it as root (or pass --no-host --no-service, or --dry-run to see the plan)"
                .to_owned(),
        ));
    }

    let interface = args.name.clone().unwrap_or_else(|| {
        args.config
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("vallum0")
            .to_owned()
    });
    let directory = args
        .config
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    if !args.dry_run && !directory_writable(&directory) {
        return Err(Error::Precondition(format!(
            "{} is not writable; run as root, or choose another --config path",
            directory.display()
        )));
    }
    let key_path = key_path_for(&args.config, &directory);
    let control_path = args
        .control
        .clone()
        .unwrap_or_else(|| vallum_config::socket_path(&interface));

    let addresses = if args.addresses.is_empty() {
        // Both families by default. A v4-only server gives every peer a v4
        // address and nothing to route v6 through, so a client that claims
        // `::/0` sends v6 around the tunnel instead of through it — which is
        // how the IPv6 leak happened. A unique-local v6 prefix is routed, not
        // NATed: the server already forwards, and no translation is involved.
        DEFAULT_ADDRESSES.iter().map(ToString::to_string).collect()
    } else {
        args.addresses.clone()
    };
    let networks = parse_networks(&addresses)?;
    let port = listen_port(&args.listen)?;

    // The endpoint is computed before the config is written so `write_config`
    // can persist it as `public_endpoint`: every `peer add --bundle-out` then
    // reuses the address the operator chose instead of re-detecting it.
    let endpoint = args
        .endpoint
        .clone()
        .or_else(|| detected_endpoint(port))
        .map(|endpoint| normalise_endpoint(&endpoint, port));

    let (public_key, key_created) = ensure_key(&key_path, args.dry_run)?;
    let config_created = write_config(
        args,
        &interface,
        &addresses,
        &control_path,
        &key_path,
        key_created,
        endpoint.as_deref(),
    )?;

    let host = hostnet::inspect();
    let mut steps: Vec<hostnet::HostStep> = Vec::new();
    if !args.no_host {
        let v4: Vec<IpNet> = networks
            .iter()
            .copied()
            .filter(|network| network.addr().is_ipv4())
            .collect();
        let v6: Vec<IpNet> = networks
            .iter()
            .copied()
            .filter(|network| network.addr().is_ipv6())
            .collect();
        if !args.no_forward {
            steps.extend(hostnet::plan_forwarding(
                &host,
                !v4.is_empty(),
                !v6.is_empty(),
            ));
        }
        if !args.no_firewall {
            steps.extend(hostnet::plan_firewall(&host, port, &interface));
            if args.enroll {
                // The responder listens on the next port up; open it too, or the
                // feature exists but nothing can reach it.
                steps.extend(hostnet::plan_port(&host, port.saturating_add(1)));
            }
        }
        if !args.no_nat {
            steps.extend(hostnet::plan_nat(&v4, &v6));
        }
    }
    let host_steps = hostnet::apply(&steps, args.dry_run)?;

    let service = if args.no_service {
        "skipped (--no-service)".to_owned()
    } else {
        install_service(&interface, args.dry_run)?
    };

    let reachable = if args.dry_run || args.no_service {
        None
    } else {
        wait_for_socket(&control_path)
    };

    // The modern paths first: a bundle needs `--ship-key`, because it carries
    // a private key the server generated.
    let next = format!(
        "on the client: sudo vallum setup --remote you@<this-host>\n\
         \x20  or here:       sudo vallum peer invite laptop   (one-time token)\n\
         \x20  a bundle:      vallum peer add laptop --config {} --ship-key \
         --bundle-out laptop.vallum-bundle",
        args.config.display()
    );

    if args.json {
        let report = Report {
            config: args.config.clone(),
            key: key_path,
            interface,
            addresses,
            listen: args.listen.clone(),
            endpoint,
            public_key,
            firewall: host.firewall.as_str(),
            host_steps,
            service: service.clone(),
            control: reachable.map(|_| control_path.display().to_string()),
            next,
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }

    say!();
    say!(
        "{} server `{}`",
        if args.dry_run { "plan for" } else { "ready:" },
        interface
    );
    say!("   config    {}", args.config.display());
    say!(
        "   key       {}{}",
        key_path.display(),
        if key_created { " (new)" } else { " (existing)" }
    );
    if !config_created {
        say!("   config    kept as written (pass --force to rewrite)");
    }
    say!("   listen    {}", args.listen);
    if let Some(endpoint) = &endpoint {
        say!("   endpoint  {endpoint}");
    } else {
        say!("   endpoint  unknown — pass --endpoint <host:port> for client bundles");
    }
    say!("   address   {}", addresses.join(", "));
    say!("   firewall  {}", host.firewall.as_str());
    say!("   service   {service}");
    say!();
    say!("add a client:");
    say!("   {next}");
    Ok(())
}

fn parse_networks(addresses: &[String]) -> Result<Vec<IpNet>, Error> {
    addresses
        .iter()
        .map(|address| {
            address.parse::<IpNet>().map_err(|error| {
                Error::Usage(format!(
                    "`{address}` is not an address with a prefix (e.g. 10.7.0.1/24): {error}"
                ))
            })
        })
        .collect()
}

pub(crate) fn listen_port(listen: &str) -> Result<u16, Error> {
    listen
        .rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .ok_or_else(|| {
            Error::Usage(format!(
                "`{listen}` is not an address and port (e.g. 0.0.0.0:51820)"
            ))
        })
}

/// The UDP port `vallum-enroll@` binds: `[enroll] port` when the config names
/// one, else one above `interface.listen`.
///
/// Two inputs are refused rather than served, because both mint invitations
/// that can never be answered:
///
/// - a port below 1024 — the responder runs without `CAP_NET_BIND_SERVICE`,
///   so the unit crash-loops on bind; and
/// - an ephemeral `interface.listen` (`:0`, the shape of a client config),
///   where `listen + 1` is not a port the responder owns but port 1.
pub(crate) fn enroll_port(config: &vallum_config::Config) -> Result<u16, Error> {
    let port = match config.enroll.port {
        Some(port) => port,
        None => {
            let listen = config
                .interface
                .listen
                .as_deref()
                .map(listen_port)
                .transpose()?
                .unwrap_or(51820);
            if listen == 0 {
                return Err(Error::Usage(
                    "cannot derive the enrolment port: `interface.listen` is ephemeral \
                     (`:0`), so `listen + 1` names nothing. That is the shape of a client \
                     config — enrolment is a server feature; if this config really does \
                     serve, set `enroll.port` (and `interface.public_endpoint`) explicitly"
                        .to_owned(),
                ));
            }
            listen.saturating_add(1)
        }
    };
    if port < 1024 {
        return Err(Error::Usage(format!(
            "the enrolment port is {port}, below 1024 — vallum-enroll runs without \
             CAP_NET_BIND_SERVICE and cannot bind it; choose a port ≥ 1024"
        )));
    }
    Ok(port)
}

/// Read the key if it exists, or make one.
///
/// The key is never regenerated: re-running setup on a live server must not
/// invalidate every client's configuration.
fn ensure_key(path: &Path, dry_run: bool) -> Result<(String, bool), Error> {
    let suite = SdkSuite::from_id(3).map_err(|error| Error::Suite(error.to_string()))?;
    if path.exists() {
        let file = keys::load_secret(path)?;
        let identity = keys::identity(&suite, &file)?;
        return Ok((keys::encode_public(file.suite, &identity.to_peer()), false));
    }
    if dry_run {
        return Ok(("(would generate a key)".to_owned(), true));
    }
    let file = keys::new_secret(3, false, entropy::seed());
    keys::save_secret(path, &file)?;
    let identity = keys::identity(&suite, &file)?;
    Ok((keys::encode_public(file.suite, &identity.to_peer()), true))
}

/// Where the key lives: the path an existing config already names, or a name
/// derived from this config's own stem.
///
/// The stem matters because a fixed `server.key` made every config in one
/// directory share a single identity — `--name beta` said "a separate tunnel"
/// and the key silently disagreed. Honouring an existing config's declared path
/// is what keeps hosts set up before that change working, including under
/// `--force`, where a fresh name would orphan the key their peers already know.
fn key_path_for(config: &Path, directory: &Path) -> PathBuf {
    if config.exists() {
        if let Ok(loaded) = Config::load(config) {
            return crate::config::resolve_key_path(config, &loaded.interface.private_key);
        }
    }
    let stem = config
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("server");
    directory.join(format!("{stem}.key"))
}

fn write_config(
    args: &InitArgs,
    interface: &str,
    addresses: &[String],
    control: &Path,
    key_path: &Path,
    key_created: bool,
    public_endpoint: Option<&str>,
) -> Result<bool, Error> {
    if args.config.exists() && !args.force {
        // Re-running setup must not rewrite an operator's file. The key it names
        // is still checked, so a broken config is caught here rather than at
        // service start.
        let config = Config::load(&args.config)?;
        let declared = config.interface.private_key.clone();
        let resolved = crate::config::resolve_key_path(&args.config, &declared);
        if resolved != key_path && !resolved.exists() {
            return Err(Error::Invalid {
                path: args.config.clone(),
                what: format!(
                    "the existing config names `{}`, which does not exist",
                    declared.display()
                ),
            });
        }
        return Ok(false);
    }

    let key_name = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("server.key");
    let mut body = String::new();
    body.push_str("[interface]\n");
    body.push_str(&format!("name = \"{interface}\"\n"));
    body.push_str(&format!("private_key = \"{key_name}\"\n"));
    if addresses.len() == 1 {
        body.push_str(&format!("address = \"{}\"\n", addresses[0]));
    } else {
        let list = addresses
            .iter()
            .map(|address| format!("\"{address}\""))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!("addresses = [{list}]\n"));
    }
    body.push_str(&format!("listen = \"{}\"\n", args.listen));
    // A server that runs `server init` exists to forward for its peers: its
    // host steps install the forwarding rules and NAT, and every relayed
    // reply re-enters the tunnel with a source that is not this interface's.
    // The flag says so, or the egress source check eats those replies (the
    // failure `verify-remote.sh` caught live). See ADR-0020.
    body.push_str("forward = true\n");
    if let Some(endpoint) = public_endpoint {
        body.push_str(&format!("public_endpoint = \"{endpoint}\"\n"));
    }
    body.push_str(&format!("control = \"{}\"\n", control.display()));
    body.push_str("fwmark = 4660\n");
    if let Some(user) = &args.user {
        body.push_str(&format!("user = \"{user}\"\n"));
    }
    body.push_str("\n[log]\nlevel = \"info\"\n");
    body.push_str("\n[quick]\n");
    if !args.dns.is_empty() {
        let list = args
            .dns
            .iter()
            .map(|server| format!("\"{server}\""))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!("dns = [{list}]\n"));
    }
    body.push_str("table = \"auto\"\n");
    if args.enroll {
        body.push_str("\n[enroll]\nenabled = true\n");
    }

    if args.dry_run {
        say!("   would write {} (0600):", args.config.display());
        for line in body.lines() {
            say!("      {line}");
        }
        if key_created {
            say!("   would generate {}", key_path.display());
        }
        return Ok(true);
    }

    write_atomic(&args.config, &body, 0o600)?;
    Ok(true)
}

fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| Error::IoPath {
                action: "create",
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    if path.exists() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let backup = PathBuf::from(format!("{}.bak.{stamp}", path.display()));
        std::fs::copy(path, &backup).map_err(|source| Error::IoPath {
            action: "back up",
            path: path.to_path_buf(),
            source,
        })?;
        crate::config_edit::prune_backups(path, 1);
    }
    let temporary = PathBuf::from(format!("{}.new", path.display()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(mode);
    let mut file = options.open(&temporary).map_err(|source| Error::IoPath {
        action: "write",
        path: temporary.clone(),
        source,
    })?;
    file.write_all(contents.as_bytes())
        .map_err(|source| Error::IoPath {
            action: "write",
            path: temporary.clone(),
            source,
        })?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(|source| Error::IoPath {
        action: "rename",
        path: path.to_path_buf(),
        source,
    })
}

fn directory_writable(directory: &Path) -> bool {
    if std::fs::create_dir_all(directory).is_err() {
        return false;
    }
    let probe = directory.join(".vallum-init-probe");
    let writable = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    writable
}

pub(crate) fn detected_endpoint(port: u16) -> Option<String> {
    // The source address the kernel would use to reach the internet, not the
    // first address `hostname -I` happens to print (which may be a container
    // bridge or a link-local address).
    let output = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();
    let index = fields.iter().position(|field| *field == "src")?;
    let address: IpAddr = fields.get(index + 1)?.parse().ok()?;
    Some(format_endpoint(address, port))
}

fn format_endpoint(address: IpAddr, port: u16) -> String {
    match address {
        IpAddr::V4(address) => format!("{address}:{port}"),
        IpAddr::V6(address) => format!("[{address}]:{port}"),
    }
}

pub(crate) fn normalise_endpoint(endpoint: &str, port: u16) -> String {
    let endpoint = endpoint.trim();
    // A bare address has no port; an IPv6 address contains colons, so it is
    // parsed before anything looks for one.
    if let Ok(address) = endpoint.parse::<IpAddr>() {
        return format_endpoint(address, port);
    }
    if endpoint.parse::<std::net::SocketAddr>().is_ok() {
        return endpoint.to_owned();
    }
    if let Some(inner) = endpoint
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        if let Ok(address) = inner.parse::<IpAddr>() {
            return format_endpoint(address, port);
        }
    }
    if endpoint.contains(':') {
        return endpoint.to_owned();
    }
    format!("{endpoint}:{port}")
}

/// Refuse to install a unit that could never start.
///
/// The units exec `/usr/bin/vallum{,-quick}`. Running from a checkout — which
/// is exactly what a first-time user does — leaves those paths empty, and the
/// unit then fails with `203/EXEC` after the operator has been told setup
/// succeeded.
pub(crate) fn require_installed_binaries() -> Result<(), Error> {
    let missing: Vec<&str> = ["/usr/bin/vallum", "/usr/bin/vallum-quick"]
        .into_iter()
        .filter(|path| !Path::new(path).exists())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(Error::Precondition(format!(
        "the systemd units run {}, which {} not installed. Install first          (`sudo ./scripts/install.sh --local`, or a release with --from-release),          or pass --no-service to write the config and run it with `vallum run`",
        missing.join(" and "),
        if missing.len() == 1 { "is" } else { "are" }
    )))
}

pub(crate) fn install_service(instance: &str, dry_run: bool) -> Result<String, Error> {
    if !Path::new("/run/systemd/system").exists() {
        return Ok(format!(
            "no systemd on this host; start it with `vallum run --config /etc/vallum/{instance}.toml`"
        ));
    }
    require_installed_binaries()?;
    let unit_dir = Path::new("/etc/systemd/system");
    let daemon_unit = unit_dir.join("vallum@.service");
    let quick_unit = unit_dir.join("vallum-quick@.service");
    let watch_unit = unit_dir.join("vallum-quick-watch@.service");
    if dry_run {
        say!("   would install /etc/tmpfiles.d/vallum.conf and create /run/vallum");
        say!("   would install {}", daemon_unit.display());
        say!("   would install {}", quick_unit.display());
        say!("   would install {}", watch_unit.display());
        say!(
            "   would enable --now vallum@{instance} vallum-quick@{instance} \
             vallum-quick-watch@{instance}"
        );
        return Ok("would install and start".to_owned());
    }
    // Before the units: `/run/vallum` must exist or every daemon fails with
    // EROFS under `ProtectSystem=strict`, because `ReadWritePaths=-` grants a
    // window into a path it does not create. The package gets this from its
    // tmpfiles.d entry; a host that installed the binary directly gets it here.
    let tmpfiles = Path::new("/etc/tmpfiles.d/vallum.conf");
    write_atomic(tmpfiles, TMPFILES, 0o644)?;
    let created = Command::new("systemd-tmpfiles")
        .args(["--create", "/etc/tmpfiles.d/vallum.conf"])
        .status()
        .map_err(|source| Error::IoPath {
            action: "run",
            path: PathBuf::from("systemd-tmpfiles"),
            source,
        })?;
    if !created.success() {
        return Err(Error::Usage(
            "systemd-tmpfiles could not create /run/vallum; the daemon would fail to \
             open its control socket"
                .to_owned(),
        ));
    }
    write_atomic(&daemon_unit, DAEMON_UNIT, 0o644)?;
    write_atomic(&quick_unit, QUICK_UNIT, 0o644)?;
    write_atomic(&watch_unit, WATCH_UNIT, 0o644)?;
    let enroll_unit = unit_dir.join("vallum-enroll@.service");
    write_atomic(&enroll_unit, ENROLL_UNIT, 0o644)?;
    systemctl(&["daemon-reload"])?;
    // Enable for boot, then restart: `enable --now` is a no-op when the unit is
    // already active, which leaves an older daemon running with a stale key or
    // an unlinked control socket after a re-init.
    for unit in [
        format!("vallum@{instance}"),
        format!("vallum-quick@{instance}"),
        format!("vallum-quick-watch@{instance}"),
    ] {
        systemctl(&["enable", &unit])?;
        systemctl(&["restart", &unit])?;
    }
    let enroll_enabled = vallum_config::Config::load(
        &crate::host::paths::config_dir().join(format!("{instance}.toml")),
    )
    .map(|config| config.enroll.enabled)
    .unwrap_or(false);
    if enroll_enabled {
        // The responder is started, not armed. `[enroll] enabled = true` says
        // "the responder may serve" - it does not say "the responder should be
        // listening to the world on every boot". ADR-0034: the enrolment port
        // is opened for the enrolment, not for the lifetime of the server.
        let unit = format!("vallum-enroll@{instance}");
        systemctl(&["start", &unit])?;
    }
    Ok("installed and started".to_owned())
}

pub(crate) fn systemctl(args: &[&str]) -> Result<(), Error> {
    let status = Command::new("systemctl")
        .arg("--no-ask-password")
        .args(args)
        .status()
        .map_err(|source| Error::IoPath {
            action: "run",
            path: PathBuf::from("systemctl"),
            source,
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Partial(format!(
            "`systemctl {}` failed; the config and key are in place, so fix the \
             service and run `systemctl start vallum@…`",
            args.join(" ")
        )))
    }
}

fn wait_for_socket(path: &Path) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if control::request(path, "get=1\n").is_ok() {
            return Some(path.display().to_string());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_enroll_toggle_adds_and_flips_the_table() {
        let plain = "[interface]\nname = \"v0\"\n";
        let added = set_enroll_flag(plain, true);
        assert!(added.contains("[enroll]\nenabled = true"), "{added}");

        let off = "[interface]\nname = \"v0\"\n\n[enroll]\nenabled = false\n";
        let on = set_enroll_flag(off, true);
        assert!(on.contains("enabled = true"), "{on}");
        assert!(!on.contains("enabled = false"), "{on}");
        assert!(set_enroll_flag(&on, false).contains("enabled = false"));

        // A table that exists without the flag gets it, and the next table
        // is not disturbed.
        let partial = "[enroll]\nport = 51821\n\n[log]\nlevel = \"info\"\n";
        let fixed = set_enroll_flag(partial, true);
        assert!(fixed.contains("enabled = true"), "{fixed}");
        assert!(fixed.contains("port = 51821"), "{fixed}");
        assert!(fixed.contains("[log]"), "{fixed}");
    }

    #[test]
    fn a_listen_address_must_name_a_port() {
        assert_eq!(listen_port("0.0.0.0:51820").unwrap(), 51820);
        assert_eq!(listen_port("[::]:51820").unwrap(), 51820);
        assert!(listen_port("0.0.0.0").is_err());
        assert!(listen_port("0.0.0.0:99999").is_err());
    }

    #[test]
    fn the_enrolment_port_defaults_to_listen_plus_one() {
        let config: vallum_config::Config = toml::from_str(
            "[interface]\nname = \"vallum0\"\nprivate_key = \"k\"\nlisten = \"0.0.0.0:51820\"\n",
        )
        .unwrap();
        assert_eq!(enroll_port(&config).unwrap(), 51821);
    }

    #[test]
    fn the_enrolment_port_refuses_an_ephemeral_listen() {
        // A client config binds `listen = "0.0.0.0:0"`; `listen + 1` on it
        // minted invites and firewall holes for UDP 1 — a port the responder
        // cannot bind and nobody could reach.
        let config: vallum_config::Config = toml::from_str(
            "[interface]\nname = \"vallum0\"\nprivate_key = \"k\"\nlisten = \"0.0.0.0:0\"\n",
        )
        .unwrap();
        let error = enroll_port(&config).unwrap_err().to_string();
        assert!(error.contains("ephemeral"), "{error}");
    }

    #[test]
    fn the_enrolment_port_refuses_a_privileged_port() {
        // The responder runs without CAP_NET_BIND_SERVICE: an explicit port
        // below 1024 is a crash-loop, not a choice.
        let config: vallum_config::Config = toml::from_str(
            "[interface]\nname = \"vallum0\"\nprivate_key = \"k\"\nlisten = \"0.0.0.0:51820\"\n\
             [enroll]\nport = 443\n",
        )
        .unwrap();
        let error = enroll_port(&config).unwrap_err().to_string();
        assert!(error.contains("below 1024"), "{error}");
    }

    #[test]
    fn the_default_address_plan_clears_the_peer_target() {
        // docs/requirements.md promises 2,000 peers. A /24 holds 253 and nothing
        // failed until a real enrolment reached 254, because the allocator only
        // complains when it runs dry. Keep the default above the claim so the
        // two cannot drift apart again without a test saying so.
        let v4 = DEFAULT_ADDRESSES
            .iter()
            .find(|address| !address.contains(':'))
            .expect("a v4 default");
        let prefix: u32 = v4
            .rsplit('/')
            .next()
            .expect("a prefix")
            .parse()
            .expect("a number");
        let hosts = 2u64.pow(32 - prefix) - 2;
        assert!(
            hosts >= 2_000,
            "the default {v4} holds {hosts} peers, below the stated 2,000 target"
        );
    }

    #[test]
    fn addresses_must_carry_a_prefix() {
        assert_eq!(
            parse_networks(&["10.7.0.1/24".to_owned()]).unwrap().len(),
            1
        );
        assert!(parse_networks(&["10.7.0.1".to_owned()]).is_err());
        assert!(parse_networks(&["not-an-address/24".to_owned()]).is_err());
    }

    #[test]
    fn an_endpoint_gains_the_listening_port() {
        assert_eq!(
            normalise_endpoint("vpn.example.com", 51820),
            "vpn.example.com:51820"
        );
        assert_eq!(
            normalise_endpoint("203.0.113.5", 51820),
            "203.0.113.5:51820"
        );
        assert_eq!(
            normalise_endpoint("203.0.113.5:1234", 51820),
            "203.0.113.5:1234"
        );
        assert_eq!(
            normalise_endpoint("2001:db8::1", 51820),
            "[2001:db8::1]:51820"
        );
        assert_eq!(
            normalise_endpoint("[2001:db8::1]:1234", 51820),
            "[2001:db8::1]:1234"
        );
    }

    #[test]
    fn teardown_dry_run_succeeds_without_root() {
        let dir = std::env::temp_dir().join(format!("vallum-teardown-dry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("vallum0.toml");
        std::fs::write(
            &config,
            "[interface]\nname = \"vallum0\"\nprivate_key = \"server.key\"\nlisten = \"0.0.0.0:51820\"\n",
        )
        .unwrap();
        teardown(&TeardownArgs {
            config: config.clone(),
            purge: true,
            dry_run: true,
        })
        .unwrap();
        assert!(config.exists(), "dry-run must not delete the config");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dry_run_writes_no_config() {
        let dir = std::env::temp_dir().join(format!("vallum-server-dry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = dir.join("vallum0.toml");
        let args = InitArgs {
            enroll: false,
            config: config.clone(),
            name: None,
            addresses: vec!["10.7.0.1/24".to_owned()],
            listen: "0.0.0.0:51820".to_owned(),
            endpoint: Some("vpn.example.com:51820".to_owned()),
            control: None,
            dns: Vec::new(),
            user: None,
            no_nat: true,
            no_firewall: true,
            no_forward: true,
            no_service: true,
            no_host: true,
            dry_run: true,
            force: false,
            json: false,
        };
        self::init(&args).unwrap();
        assert!(!config.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_writes_a_config_a_daemon_can_load() {
        let dir = std::env::temp_dir().join(format!("vallum-server-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("vallum0.toml");
        let args = InitArgs {
            enroll: false,
            config: config.clone(),
            name: Some("vallum9".to_owned()),
            addresses: vec!["10.7.0.1/24".to_owned(), "fd00:7::1/64".to_owned()],
            listen: "0.0.0.0:51820".to_owned(),
            endpoint: Some("vpn.example.com".to_owned()),
            control: None,
            dns: vec!["1.1.1.1".to_owned()],
            user: None,
            no_nat: true,
            no_firewall: true,
            no_forward: true,
            no_service: true,
            no_host: true,
            dry_run: false,
            force: false,
            json: false,
        };
        self::init(&args).unwrap();
        let loaded = Config::load(&config).unwrap();
        assert_eq!(loaded.interface.name.as_deref(), Some("vallum9"));
        assert_eq!(loaded.interface.listen.as_deref(), Some("0.0.0.0:51820"));
        assert_eq!(loaded.interface.addresses.len(), 2);
        assert_eq!(loaded.quick.dns, vec!["1.1.1.1".to_owned()]);

        // The key is 0600 and the config names it relatively.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("vallum0.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(loaded.interface.private_key, PathBuf::from("vallum0.key"));

        // Re-running keeps the key: a second init must not invalidate clients.
        let before = std::fs::read(dir.join("vallum0.key")).unwrap();
        self::init(&args).unwrap();
        let after = std::fs::read(dir.join("vallum0.key")).unwrap();
        assert_eq!(before, after);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two configs in one directory must not share a key.
    ///
    /// A fixed `server.key` gave every config in a directory one identity:
    /// `--name beta` said "a separate tunnel" and the key silently disagreed.
    #[test]
    fn a_second_config_gets_its_own_key() {
        let dir = std::path::PathBuf::from("/tmp/vallum-key-test");
        assert_eq!(
            key_path_for(&dir.join("alpha.toml"), &dir),
            dir.join("alpha.key")
        );
        assert_eq!(
            key_path_for(&dir.join("beta.toml"), &dir),
            dir.join("beta.key")
        );
    }

    /// A config that already names a key keeps it, so a later `--force` cannot
    /// orphan the key a peer already knows.
    #[test]
    fn an_existing_config_keeps_the_key_it_names() {
        let dir = std::env::temp_dir().join(format!("vallum-key-decl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("vallum0.toml");
        std::fs::write(
            &config,
            "[interface]\nname = \"vallum0\"\nprivate_key = \"server.key\"\n\
             listen = \"0.0.0.0:51820\"\n",
        )
        .unwrap();
        assert_eq!(key_path_for(&config, &dir), dir.join("server.key"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
