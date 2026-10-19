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
        return Err(Error::Usage(
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

pub fn show(args: &ShowArgs) -> Result<(), Error> {
    if args.json && args.watch {
        return Err(Error::Usage(
            "`--json` and `--watch` are different modes; choose one".to_owned(),
        ));
    }
    let path = control_path(args.config.as_deref(), args.control.as_deref())?;
    if args.watch {
        return watch(&path, args);
    }
    let reply = control::request(&path, "get=1\n")?;
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

pub fn syncconf(args: &SetconfArgs) -> Result<(), Error> {
    let path = control_path(Some(args.config.as_path()), args.control.as_deref())?;
    let resolved = resolve_config(args.config.as_path())?;
    let current = control::request(&path, "get=1\n")?;

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
    body.push_str(&device_lines(&resolved, &resolved.seed, &current));
    for key in &current_peers {
        if !desired.contains(key) {
            body.push_str(&format!("public_key={key}\nremove=true\n"));
        }
    }
    for peer in &resolved.peers {
        body.push_str(&peer_lines(peer));
        body.push_str("replace_allowed_ips=true\n");
    }
    let reply = control::request(&path, &body)?;
    expect_ok(path.as_path(), &reply)
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
