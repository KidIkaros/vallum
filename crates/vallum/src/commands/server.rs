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
const ENROLL_UNIT: &str = include_str!("../../../../packaging/vallum-enroll@.service");

#[derive(Debug, Args)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub command: ServerCommand,
}

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Generate the key, write the config, and start the service.
    Init(InitArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// The configuration file to write.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
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

    /// The control socket path. Defaults to /run/vallum/<name>.sock.
    #[arg(long, value_name = "PATH")]
    pub control: Option<PathBuf>,

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

    /// Do not change anything about the host (implies the three `--no-*` above).
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
    }
}

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
    let key_path = directory.join("server.key");
    let control_path = args
        .control
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("/run/vallum/{interface}.sock")));

    let addresses = if args.addresses.is_empty() {
        vec!["10.7.0.1/24".to_owned()]
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

    let next = format!(
        "vallum peer add laptop --config {} --bundle-out laptop.vallum-bundle",
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
    if dry_run {
        say!("   would install {}", daemon_unit.display());
        say!("   would install {}", quick_unit.display());
        say!("   would enable --now vallum@{instance} vallum-quick@{instance}");
        return Ok("would install and start".to_owned());
    }
    write_atomic(&daemon_unit, DAEMON_UNIT, 0o644)?;
    write_atomic(&quick_unit, QUICK_UNIT, 0o644)?;
    let enroll_unit = unit_dir.join("vallum-enroll@.service");
    write_atomic(&enroll_unit, ENROLL_UNIT, 0o644)?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", &format!("vallum@{instance}")])?;
    // The host-networking unit depends on the daemon; enabling it explicitly
    // makes `systemctl stop vallum@x` also undo the routes, via `PartOf=`.
    systemctl(&["enable", "--now", &format!("vallum-quick@{instance}")])?;
    // The enrolment responder only runs where it was asked for.
    let enroll_enabled =
        vallum_config::Config::load(&PathBuf::from(format!("/etc/vallum/{instance}.toml")))
            .map(|config| config.enroll.enabled)
            .unwrap_or(false);
    if enroll_enabled {
        systemctl(&["enable", "--now", &format!("vallum-enroll@{instance}")])?;
    }
    Ok("installed and started".to_owned())
}

fn systemctl(args: &[&str]) -> Result<(), Error> {
    let status = Command::new("systemctl")
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
    fn a_listen_address_must_name_a_port() {
        assert_eq!(listen_port("0.0.0.0:51820").unwrap(), 51820);
        assert_eq!(listen_port("[::]:51820").unwrap(), 51820);
        assert!(listen_port("0.0.0.0").is_err());
        assert!(listen_port("0.0.0.0:99999").is_err());
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
    fn a_dry_run_writes_no_config() {
        let dir = std::env::temp_dir().join(format!("vallum-server-dry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = dir.join("vallum0.toml");
        let args = InitArgs {
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
        let mode = std::fs::metadata(dir.join("server.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(loaded.interface.private_key, PathBuf::from("server.key"));

        // Re-running keeps the key: a second init must not invalidate clients.
        let before = std::fs::read(dir.join("server.key")).unwrap();
        self::init(&args).unwrap();
        let after = std::fs::read(dir.join("server.key")).unwrap();
        assert_eq!(before, after);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
