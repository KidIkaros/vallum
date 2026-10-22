// SPDX-License-Identifier: Apache-2.0

//! `show`, `showconf`, `setconf`, `addconf`, and `syncconf`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use vallum_crypto::SharedSecret;
use vallum_crypto_sdk::SdkSuite;

use crate::config::{self, Config, ResolveConfig};
use crate::control;
use crate::keys;
use crate::uapi::{errno, field as uapi_field};
use crate::Error;
use serde::Serialize;

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// The configuration file, for its `control` path.
    #[arg(long, short, value_name = "FILE")]
    config: Option<PathBuf>,

    /// The control socket path, instead of a config.
    #[arg(long, value_name = "SOCKET")]
    control: Option<PathBuf>,

    /// Print the raw UAPI response.
    #[arg(long)]
    dump: bool,

    /// Emit the secret-free JSON view.
    #[arg(long)]
    json: bool,

    /// Refresh the view until Ctrl-C.
    #[arg(long)]
    watch: bool,

    /// Refresh interval for `--watch`, in milliseconds.
    #[arg(long, default_value = "1000", value_name = "MS")]
    interval: u64,

    /// Print only one field (endpoints, allowed-ips, transfer, ...).
    #[arg(long, value_name = "FIELD")]
    field: Option<String>,
}

#[derive(Debug, Args)]
pub struct ShowconfArgs {
    /// The configuration file, for its `control` path.
    #[arg(long, short, value_name = "FILE")]
    config: Option<PathBuf>,

    /// The control socket path, instead of a config.
    #[arg(long, value_name = "SOCKET")]
    control: Option<PathBuf>,

    /// Include the private-key path and preshared keys in the export.
    #[arg(long)]
    include_secrets: bool,
}

#[derive(Debug, Args)]
pub struct SetconfArgs {
    /// The configuration file to apply.
    #[arg(value_name = "FILE")]
    config: PathBuf,

    /// The control socket path, instead of the config's `control` field.
    #[arg(long, value_name = "SOCKET")]
    control: Option<PathBuf>,
}

/// The control socket: the explicit path, or the config's `control` field.
fn control_path(config: Option<&Path>, explicit: Option<&Path>) -> Result<PathBuf, Error> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let Some(config_path) = config else {
        // Nothing was attempted and retrying cannot help: the documented
        // automation contract calls that a precondition (exit 2), and `metrics`
        // already reports this same condition that way.
        return Err(Error::Precondition(
            "give --control <socket>, or --config <file> with a `control` field".to_owned(),
        ));
    };
    let config = Config::load(config_path)?;
    config
        .interface
        .control
        .as_ref()
        .map(|declared| config::resolve_key_path(config_path, declared))
        .ok_or_else(|| Error::Invalid {
            path: config_path.to_path_buf(),
            what: "interface.control is not set, so there is no socket to query".to_owned(),
        })
}

// A config-derived device view, used when no daemon is reachable.
// This is the Gulf of execution fix for finding A: ` Vallum show` does the
// prerequisite (reading the config) itself, rather than dying with
// "no daemon". See docs/proof/pre-release-dogfood-assess.md.
#[derive(Debug, Clone, Serialize)]
struct ConfigDevice {
    config: PathBuf,
    interface: String,
    listen: String,
    addresses: Vec<String>,
    fwmark: u32,
    peers: Vec<PeerRow>,
    next: String,
}

#[derive(Debug, Clone, Serialize)]
struct PeerRow {
    name: String,
    endpoint: String,
    allowed_ips: Vec<String>,
    preshared_key: bool,
}

impl ConfigDevice {
    fn from_resolved(resolved: &config::Resolved, config_path: &Path) -> Self {
        let peers = resolved
            .peers
            .iter()
            .map(|peer| PeerRow {
                name: peer.name().to_owned(),
                endpoint: peer.endpoint().map(|s| s.to_string()).unwrap_or_default(),
                allowed_ips: peer
                    .allowed_ips()
                    .nets()
                    .iter()
                    .map(|n| n.to_string())
                    .collect(),
                preshared_key: peer.preshared_key().is_some(),
            })
            .collect();
        ConfigDevice {
            config: config_path.to_path_buf(),
            interface: resolved
                .interface_name
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            listen: resolved.listen.to_string(),
            addresses: resolved.addresses.iter().map(|p| p.to_string()).collect(),
            fwmark: resolved.fwmark,
            peers,
            next: format!("vallum run --config {}", config_path.display()),
        }
    }
}

impl std::fmt::Display for ConfigDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "config: {}", self.config.display())?;
        writeln!(f, "interface: {}", self.interface)?;
        writeln!(f, "listen: {}", self.listen)?;
        writeln!(f, "addresses: {}", self.addresses.join(", "))?;
        writeln!(f, "fwmark: {}", self.fwmark)?;
        writeln!(f, "peers: {}", self.peers.len())?;
        for peer in &self.peers {
            let endpoint = if peer.endpoint.is_empty() {
                "roaming".to_owned()
            } else {
                peer.endpoint.clone()
            };
            writeln!(
                f,
                "  {} — {} via {}",
                peer.name,
                peer.allowed_ips.join(", "),
                endpoint
            )?;
        }
        writeln!(f, "next: {}", self.next)
    }
}

pub fn show(args: &ShowArgs) -> Result<(), Error> {
    if args.json && args.watch {
        return Err(Error::Usage(
            "`--json` and `--watch` are different modes; choose one".to_owned(),
        ));
    }
    // An explicit --control wins; otherwise the socket comes from the config's
    // `control` field. The config itself is also loaded so an unreachable
    // daemon can still yield the configured-device view (finding A in
    // docs/proof/pre-release-dogfood-assess.md).
    let config_path = args.config.as_deref();
    let cfg = match config_path {
        Some(path) => Some(Config::load(path)?),
        None => None,
    };
    let socket_path = match (args.control.as_deref(), config_path) {
        (Some(socket), _) => Some(socket.to_path_buf()),
        (None, Some(path)) => cfg
            .as_ref()
            .and_then(|config| config.interface.control.as_ref())
            .map(|declared| config::resolve_key_path(path, declared)),
        (None, None) => None,
    };

    if args.watch {
        let socket = match (socket_path, config_path) {
            (Some(socket), _) => socket,
            (None, Some(path)) => {
                return Err(Error::Invalid {
                    path: path.to_path_buf(),
                    what: "interface.control is not set, so there is no socket to query".to_owned(),
                })
            }
            (None, None) => {
                return Err(Error::Precondition(
                    "give --control <socket>, or --config <file> with a `control` field".to_owned(),
                ))
            }
        };
        return watch(&socket, args);
    }

    let reply = socket_path
        .as_deref()
        .map(|socket| control::request(socket, "get=1\n"));

    if let Some(Ok(reply)) = reply {
        if args.dump {
            print!("{reply}");
            return Ok(());
        }
        if args.json {
            let response = crate::uapi::parse_response(&reply);
            let value = crate::uapi::response_json(&response);
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|e| Error::Usage(e.to_string()))?
            );
            return Ok(());
        }
        if let Some(field) = args.field.as_deref() {
            print_field(&reply, field);
            return Ok(());
        }
        print!(
            "{}",
            crate::uapi::render_human(&crate::uapi::parse_response(&reply))
        );
        return Ok(());
    }

    // The daemon is unreachable — or no socket was configured. With a config,
    // show the configured device; without one, report the original failure.
    let (Some(cfg), Some(config_path)) = (cfg.as_ref(), config_path) else {
        return match reply {
            Some(Err(error)) => Err(error),
            _ => Err(Error::Precondition(
                "give --control <socket>, or --config <file> with a `control` field".to_owned(),
            )),
        };
    };
    let suite =
        SdkSuite::from_id(cfg.suite_id(config_path).map_err(|e| {
            Error::Suite(format!("key file names a suite this build cannot use: {e}"))
        })?)
        .map_err(|e| Error::Suite(format!("key file names a suite this build cannot use: {e}")))?;
    let resolved = cfg
        .resolve(config_path, &suite)
        .map_err(|e| Error::Usage(e.to_string()))?;
    let device = ConfigDevice::from_resolved(&resolved, config_path);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&device).map_err(|e| Error::Usage(e.to_string()))?
        );
    } else {
        println!("{device}");
    }
    eprintln!(
        "note: no daemon connected; showing the configured device from {}",
        device.config.display()
    );
    Ok(())
}

fn watch(path: &Path, args: &ShowArgs) -> Result<(), Error> {
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))
        .map_err(Error::Io)?;
    let interval = Duration::from_millis(args.interval.max(100));
    while !stop.load(Ordering::Relaxed) {
        let reply = control::request(path, "get=1\n")?;
        print!("\x1b[2J\x1b[H");
        if let Some(field) = args.field.as_deref() {
            print_field(&reply, field);
        } else {
            print!(
                "{}",
                crate::uapi::render_human(&crate::uapi::parse_response(&reply))
            );
        }
        std::io::stdout().flush().map_err(Error::Io)?;
        std::thread::sleep(interval);
    }
    Ok(())
}

pub fn showconf(args: &ShowconfArgs) -> Result<(), Error> {
    let path = control_path(args.config.as_deref(), args.control.as_deref())?;
    let reply = control::request(&path, "get=1\n")?;
    print!(
        "{}",
        crate::uapi::render_config(&crate::uapi::parse_response(&reply), args.include_secrets,)
    );
    Ok(())
}

fn print_field(reply: &str, name: &str) {
    let key = match name {
        "endpoints" => uapi_field::ENDPOINT,
        "allowed-ips" => uapi_field::ALLOWED_IP,
        "latest-handshakes" => uapi_field::LAST_HANDSHAKE_TIME_SEC,
        "transfer" => uapi_field::TX_BYTES,
        "persistent-keepalive" => uapi_field::PERSISTENT_KEEPALIVE_INTERVAL,
        "preshared-keys" => uapi_field::PRESHARED_KEY,
        "public-key" | "peers" => uapi_field::PUBLIC_KEY,
        "private-key" => uapi_field::PRIVATE_KEY,
        "listen-port" => uapi_field::LISTEN_PORT,
        "fwmark" => uapi_field::FWMARK,
        "dump" => {
            print!("{reply}");
            return;
        }
        other => other,
    };
    let prefix = format!("{key}=");
    for line in reply.lines() {
        if let Some(value) = line.strip_prefix(&prefix) {
            println!("{value}");
        }
    }
}

/// The peer lines of a `set=1` body.
fn peer_lines(peer: &vallum_tunnel::PeerConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "public_key={}\n",
        keys::hex_encode(peer.identity().kem().as_bytes())
    ));
    // The name is the only human handle on a peer, and every surface that
    // reports traffic — `show`, the metrics exporter, the TUI — reads it from
    // the running daemon rather than from the config. Omitting it here made the
    // daemon fall back to `peer-<key prefix>`, so per-peer telemetry identified
    // traffic by an opaque hash and could not be mapped to a device.
    out.push_str(&format!(
        "{}={}\n",
        crate::uapi::field::VALLUM_NAME,
        peer.name()
    ));
    if let Some(psk) = peer.preshared_key() {
        out.push_str(&format!(
            "preshared_key={}\n",
            keys::hex_encode(psk.as_bytes())
        ));
    }
    if let Some(endpoint) = peer.endpoint() {
        out.push_str(&format!("endpoint={endpoint}\n"));
    }
    if let Some(keepalive) = peer.persistent_keepalive() {
        out.push_str(&format!(
            "persistent_keepalive_interval={}\n",
            keepalive.as_secs()
        ));
    }
    for prefix in peer.allowed_ips().nets() {
        out.push_str(&format!("allowed_ip={prefix}\n"));
    }
    out
}

fn resolve_config(config_path: &Path) -> Result<crate::config::Resolved, Error> {
    let config = Config::load(config_path)?;
    let suite = SdkSuite::from_id(config.suite_id(config_path)?)
        .map_err(|e| Error::Suite(format!("key file names a suite this build cannot use: {e}")))?;
    config.resolve(config_path, &suite)
}

/// The device fields that differ from the running daemon.
///
/// A `listen_port` of 0 in the config means "any"; a running daemon already has
/// one, so it is not a requested change. `fwmark = 0` means unset.
fn device_lines(desired: &crate::config::Resolved, seed: &SharedSecret, current: &str) -> String {
    let response = crate::uapi::parse_response(current);
    let mut out = String::new();
    let seed_hex = keys::hex_encode(seed.as_bytes());
    if response.field(uapi_field::PRIVATE_KEY) != Some(seed_hex.as_str()) {
        out.push_str(&format!("private_key={seed_hex}\n"));
    }
    let current_port = response
        .field(uapi_field::LISTEN_PORT)
        .and_then(|value| value.parse::<u16>().ok());
    if desired.listen.port() != 0 && current_port != Some(desired.listen.port()) {
        out.push_str(&format!("listen_port={}\n", desired.listen.port()));
    }
    let current_mark = response
        .field(uapi_field::FWMARK)
        .and_then(|value| value.parse::<u32>().ok());
    if desired.fwmark != 0 && current_mark != Some(desired.fwmark) {
        out.push_str(&format!("fwmark={}\n", desired.fwmark));
    }
    out
}

pub fn setconf(args: &SetconfArgs, replace: bool) -> Result<(), Error> {
    let path = control_path(Some(args.config.as_path()), args.control.as_deref())?;
    let resolved = resolve_config(args.config.as_path())?;
    let mut body = String::from("set=1\n");
    if replace {
        let current = control::request(&path, "get=1\n")?;
        body.push_str(&device_lines(&resolved, &resolved.seed, &current));
        body.push_str("replace_peers=true\n");
    }
    for peer in &resolved.peers {
        body.push_str(&peer_lines(peer));
    }
    let reply = control::request(&path, &body)?;
    expect_ok(path.as_path(), &reply)
}

fn peer_entry_field<'a>(peer: &'a [(String, String)], name: &str) -> Option<&'a str> {
    peer.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn peer_differs(peer: &vallum_tunnel::PeerConfig, current: &[(String, String)]) -> bool {
    let current_name = peer_entry_field(current, uapi_field::VALLUM_NAME).unwrap_or("");
    if peer.name() != current_name {
        return true;
    }
    let current_endpoint = peer_entry_field(current, uapi_field::ENDPOINT);
    let desired_endpoint = peer.endpoint().map(|e| e.to_string());
    if desired_endpoint.as_deref() != current_endpoint && current_endpoint != Some("(none)") {
        return true;
    }
    if desired_endpoint.is_some() && current_endpoint == Some("(none)") {
        return true;
    }
    let current_psk = peer_entry_field(current, uapi_field::PRESHARED_KEY);
    let desired_psk = peer.preshared_key().map(|p| keys::hex_encode(p.as_bytes()));
    if desired_psk.as_deref() != current_psk {
        return true;
    }
    let current_keepalive = peer_entry_field(current, uapi_field::PERSISTENT_KEEPALIVE_INTERVAL)
        .and_then(|v| v.parse::<u64>().ok());
    let desired_keepalive = peer.persistent_keepalive().map(|d| d.as_secs());
    if desired_keepalive != current_keepalive {
        return true;
    }
    let current_ips: Vec<&str> = current
        .iter()
        .filter(|(k, _)| k == uapi_field::ALLOWED_IP)
        .map(|(_, v)| v.as_str())
        .collect();
    let desired_ips: Vec<String> = peer
        .allowed_ips()
        .nets()
        .iter()
        .map(|p| p.to_string())
        .collect();
    if current_ips.len() != desired_ips.len()
        || !desired_ips
            .iter()
            .all(|ip| current_ips.contains(&ip.as_str()))
    {
        return true;
    }
    false
}

/// The outcome of applying configuration differences to the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncReport {
    /// Peers in the config that were not yet in the daemon.
    pub added_peers: usize,
    /// Existing peers whose attributes differed and were refreshed.
    pub updated_peers: usize,
    /// Peers running in the daemon that were absent from the config.
    pub removed_peers: usize,
    /// Whether interface-level attributes (listen port, mark, key) changed.
    pub device_changed: bool,
}

impl SyncReport {
    /// Whether the config matches the running daemon exactly.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !self.device_changed
            && self.added_peers == 0
            && self.updated_peers == 0
            && self.removed_peers == 0
    }
}

pub fn syncconf(args: &SetconfArgs) -> Result<SyncReport, Error> {
    let path = control_path(Some(args.config.as_path()), args.control.as_deref())?;
    let resolved = resolve_config(args.config.as_path())?;
    let current = control::request(&path, "get=1\n")?;
    let parsed_current = crate::uapi::parse_response(&current);

    // The first `public_key` is the device's; every later one is a peer.
    let mut current_peers = Vec::new();
    let mut first = true;
    for line in current.lines() {
        if let Some(key) = line.strip_prefix("public_key=") {
            if first {
                first = false;
            } else {
                current_peers.push(key.to_owned());
            }
        }
    }
    let desired: Vec<String> = resolved
        .peers
        .iter()
        .map(|peer| keys::hex_encode(peer.identity().kem().as_bytes()))
        .collect();

    let mut body = String::from("set=1\n");
    let dev_diff = device_lines(&resolved, &resolved.seed, &current);
    let device_changed = !dev_diff.is_empty();
    body.push_str(&dev_diff);

    let mut removed_peers = 0;
    for key in &current_peers {
        if !desired.contains(key) {
            body.push_str(&format!("public_key={key}\nremove=true\n"));
            removed_peers += 1;
        }
    }

    let mut added_peers = 0;
    let mut updated_peers = 0;
    for peer in &resolved.peers {
        let key_hex = keys::hex_encode(peer.identity().kem().as_bytes());
        if let Some(curr) = parsed_current.peers.iter().find(|p| {
            p.iter()
                .any(|(k, v)| k == uapi_field::PUBLIC_KEY && v == &key_hex)
        }) {
            if peer_differs(peer, curr) {
                updated_peers += 1;
            }
        } else {
            added_peers += 1;
        }
        body.push_str(&peer_lines(peer));
        body.push_str("replace_allowed_ips=true\n");
    }
    let reply = control::request(&path, &body)?;
    expect_ok(path.as_path(), &reply)?;
    Ok(SyncReport {
        added_peers,
        updated_peers,
        removed_peers,
        device_changed,
    })
}

/// What an attempt to push a config to the running daemon did, and if it did
/// nothing, why.
///
/// The distinction is the point: a missing socket has at least three causes —
/// the daemon is down, it is up and its socket was removed, or it is up in a
/// mount namespace this process cannot see — and the caller must not pick one.
/// See ADR-0017.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The running daemon accepted the configuration.
    Applied,
    /// `--no-apply`: the config was written and nothing was pushed.
    Skipped,
    /// The config declares no `control` path, so there is nothing to reach.
    NoControlDeclared,
    /// A `control` path is declared but no socket exists there.
    NoControlSocket(PathBuf),
}

impl ApplyOutcome {
    /// Whether the running daemon accepted the configuration.
    #[must_use]
    pub fn applied(&self) -> bool {
        matches!(self, Self::Applied)
    }

    /// The text to print after `applied`: what was observed, not what it is
    /// assumed to mean.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Applied => "yes".to_owned(),
            Self::Skipped => "no — --no-apply was given".to_owned(),
            Self::NoControlDeclared => "no — the config declares no control socket".to_owned(),
            Self::NoControlSocket(path) => {
                format!("no — no control socket at {}", path.display())
            }
        }
    }
}

/// Apply a config to the daemon its own `control` field names.
///
/// This is the `vallum peer` path: the config was just edited, and the running
/// daemon should learn about it without a restart. A socket that is not there
/// is not an error — the config is written, and the service will read it when it
/// starts. The returned outcome says which of those happened, so the caller can
/// report it without inventing a cause.
pub fn syncconf_running(config: &Path) -> Result<ApplyOutcome, Error> {
    let loaded = Config::load(config)?;
    let Some(declared) = loaded.interface.control.as_ref() else {
        return Ok(ApplyOutcome::NoControlDeclared);
    };
    let socket = config::resolve_key_path(config, declared);
    if !socket.exists() {
        return Ok(ApplyOutcome::NoControlSocket(socket));
    }
    syncconf(&SetconfArgs {
        config: config.to_path_buf(),
        control: Some(socket),
    })?;
    Ok(ApplyOutcome::Applied)
}

fn expect_ok(path: &Path, reply: &str) -> Result<(), Error> {
    if reply.lines().any(|line| line == "errno=0") {
        return Ok(());
    }
    let errno = reply
        .lines()
        .find_map(|line| line.strip_prefix("errno="))
        .and_then(|value| value.parse::<i32>().ok());
    let what = match errno {
        Some(errno::EPERM) => "the daemon could not rebind the socket: it needs \
                               CAP_NET_ADMIN, and permission for the port"
            .to_owned(),
        Some(errno::EADDRINUSE) => "the requested listen port is already in use".to_owned(),
        Some(errno::EADDRNOTAVAIL) => {
            "the requested listen address is not available on this host".to_owned()
        }
        Some(errno::ENOENT) => "update_only named a peer that is not configured".to_owned(),
        Some(errno::EINVAL) => {
            "the request was malformed, or two peers claim the same prefix".to_owned()
        }
        Some(errno::EEXIST) => "the peer already exists".to_owned(),
        _ => format!("control request failed: {}", reply.trim()),
    };
    Err(Error::Invalid {
        path: path.to_path_buf(),
        what,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn show_args(config: Option<PathBuf>, control: Option<PathBuf>) -> ShowArgs {
        ShowArgs {
            config,
            control,
            dump: false,
            json: false,
            watch: false,
            interval: 1000,
            field: None,
        }
    }

    #[test]
    fn a_dead_control_socket_is_an_error_not_a_panic() {
        // Regression: the config-fallback path used to panic when --control
        // was given without --config and the daemon was unreachable.
        let result = show(&show_args(
            None,
            Some(PathBuf::from("/nonexistent/vallum-dead.sock")),
        ));
        assert!(result.is_err());
    }

    #[test]
    fn config_and_control_together_are_accepted() {
        // --control overrides the socket but must not be rejected.
        let result = show(&show_args(
            Some(PathBuf::from("/nonexistent/missing-config.toml")),
            Some(PathBuf::from("/nonexistent/dead.sock")),
        ));
        // It fails on the missing config file, not on argument validation.
        assert!(result.is_err());
        let message = result.unwrap_err().to_string();
        assert!(!message.contains("give --control"));
    }
}
