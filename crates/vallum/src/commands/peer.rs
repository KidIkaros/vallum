// SPDX-License-Identifier: Apache-2.0

//! `vallum peer`: enrol, list, inspect, and remove peers.
//!
//! This is the server side of provisioning. A peer is a public line plus the
//! prefixes routed to it; the command allocates an address, refuses an overlap,
//! writes the file without reformatting it, and tells a running daemon about the
//! change. Two custody models are supported:
//!
//! - `--public-key` — the device generated its own key and only its public line
//!   travels. This is the WireGuard model and the one the docs recommend.
//! - `--bundle-out` — the server generates the keypair and hands over a bundle.
//!   One step, but the server has seen the client's private key; `--forget-key`
//!   deletes its copy immediately.

use crate::say;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use ipnet::IpNet;
use serde::Serialize;
use vallum_core::identity::{IdentityDocument, Validity};
use vallum_core::PeerIdentity;
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;
use vallum_tunnel::Prefix;

use crate::bundle::Bundle;
use crate::commands::control::{syncconf_running, ApplyOutcome};
use crate::commands::server::{detected_endpoint, listen_port, normalise_endpoint};
use crate::config::{self, Config};
use crate::config_edit::{self, ConfigFile, IdentityFields, PeerRecord};
use crate::{entropy, keys, Error};

#[derive(Debug, Args)]
pub struct PeerArgs {
    #[command(subcommand)]
    pub command: PeerCommand,
}

#[derive(Debug, Subcommand)]
pub enum PeerCommand {
    /// Enrol a peer and optionally write its client bundle.
    Add(AddArgs),
    /// List the configured peers.
    List(ListArgs),
    /// Show one peer.
    Show(ShowArgs),
    /// Remove a peer.
    Remove(RemoveArgs),
    /// Enrol a device that generated its own key, and hand back its config.
    Enroll(EnrollArgs),
    /// Mint a single-use token so a device can enrol without SSH access.
    Invite(InviteArgs),
    /// List live one-time invites and their remaining TTL (pruning expired ones).
    Invites(InvitesArgs),
    /// Install a new identity while the old one keeps working.
    Rotate(RotateArgs),
    /// Retire the previous identity a rotation kept.
    Finalize(FinalizeArgs),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// The peer's name, as it appears in logs and in the file.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The configuration file to edit.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// The peer's public line (the device generated its own key).
    #[arg(long, value_name = "LINE", conflicts_with_all = ["public_key_file", "bundle_out"])]
    pub public_key: Option<String>,

    /// A file holding the peer's public line.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["public_key", "bundle_out"])]
    pub public_key_file: Option<PathBuf>,

    /// Generate the keypair here and write the client's bundle to this path.
    ///
    /// A bundle carries a *private* key, so it needs `--ship-key`: a server
    /// that generates a client's key means a server compromise is a client
    /// compromise. Prefer `--public-key`, `peer invite`, or `setup --remote`.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["public_key", "public_key_file"],
        requires = "ship_key"
    )]
    pub bundle_out: Option<PathBuf>,

    /// Confirm that this server should generate the device's key and hand it
    /// over. Only for devices that cannot generate their own.
    #[arg(long)]
    pub ship_key: bool,

    /// Write the client's config to this path (no private key: the device has
    /// its own). Use with `--public-key`.
    #[arg(long, value_name = "FILE", conflicts_with = "bundle_out")]
    pub client_config_out: Option<PathBuf>,

    /// Enrol a peer by its identity document instead of a public line.
    ///
    /// The document is verified against `[interface] identity_issuer` (or its
    /// own signature when no issuer is configured) and its window is checked.
    /// It is copied to `clients/<name>.identity`.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["public_key", "public_key_file", "bundle_out"])]
    pub identity: Option<PathBuf>,

    /// The address to route to the peer. Allocated if absent.
    #[arg(long, value_name = "CIDR")]
    pub address: Option<String>,

    /// The prefixes routed to the peer. Defaults to the peer's address.
    #[arg(long, value_name = "LIST")]
    pub allowed_ips: Option<String>,

    /// The address the client dials. Detected for a bundle if absent.
    #[arg(long, value_name = "HOST:PORT")]
    pub endpoint: Option<String>,

    /// Send a keepalive every this many seconds.
    #[arg(long, value_name = "SECS")]
    pub keepalive: Option<u16>,

    /// Refuse handshakes from any address other than `--endpoint`.
    #[arg(long)]
    pub pin_endpoint: bool,

    /// Generate a preshared key and store it next to the config.
    #[arg(long)]
    pub psk: bool,

    /// A DNS server to push to the client bundle. Repeatable.
    #[arg(long, value_name = "ADDR")]
    pub dns: Vec<String>,

    /// Delete the server's copy of the client key after writing the bundle.
    #[arg(long)]
    pub forget_key: bool,

    /// Write the config but do not tell a running daemon.
    #[arg(long)]
    pub no_apply: bool,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,

    /// Include the full public line in JSON output.
    #[arg(long)]
    pub full: bool,

    /// Suppress the report. Used by `peer enroll`, which prints its own.
    #[arg(long, hide = true)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    /// The peer to rotate.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The configuration file to edit.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// The peer's new public line.
    #[arg(long, value_name = "LINE", conflicts_with_all = ["public_key_file", "bundle_out", "identity"])]
    pub public_key: Option<String>,

    /// A file holding the new public line.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["public_key", "bundle_out", "identity"])]
    pub public_key_file: Option<PathBuf>,

    /// Generate the new keypair here and write the client's bundle.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["public_key", "public_key_file", "identity"],
        requires = "ship_key"
    )]
    pub bundle_out: Option<PathBuf>,

    /// Confirm that this server should generate the replacement key.
    #[arg(long)]
    pub ship_key: bool,

    /// The peer's new identity document.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["public_key", "public_key_file", "bundle_out"])]
    pub identity: Option<PathBuf>,

    /// The address the client dials, for the bundle. Detected if absent.
    #[arg(long, value_name = "HOST:PORT")]
    pub endpoint: Option<String>,

    /// A DNS server to push to the client bundle. Repeatable.
    #[arg(long, value_name = "ADDR")]
    pub dns: Vec<String>,

    /// Delete the server's copy of the generated key after writing the bundle.
    #[arg(long)]
    pub forget_key: bool,

    /// Write the config but do not tell a running daemon.
    #[arg(long)]
    pub no_apply: bool,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct FinalizeArgs {
    /// The peer whose previous identity should be retired.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The configuration file to edit.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// Write the config but do not tell a running daemon.
    #[arg(long)]
    pub no_apply: bool,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// The configuration file to read.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// Include the full public line, not just its fingerprint.
    #[arg(long)]
    pub full: bool,

    /// Emit JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// The peer's name.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The configuration file to read.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// Print the full public line.
    #[arg(long)]
    pub full: bool,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// The peer's name.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The configuration file to edit.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// Write the config but do not tell a running daemon.
    #[arg(long)]
    pub no_apply: bool,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

/// The server's own key, as provisioning needs it.
struct Server {
    suite: SdkSuite,
    suite_id: u16,
    public_line: String,
    /// The CA key every document must verify against, if one is configured.
    issuer: Option<vallum_crypto::SignPublicKey>,
    /// `interface.public_endpoint`: the address `server init` remembered, which
    /// client bundles should dial before falling back to source-route detection.
    public_endpoint: Option<String>,
}

/// `vallum peer`.
///
/// # Errors
///
/// A config that does not exist or does not parse, a public line for the wrong
/// suite, a duplicate name, an overlapping prefix, or a failed write.
pub fn peer(args: &PeerArgs) -> Result<(), Error> {
    match &args.command {
        PeerCommand::Add(args) => add(args),
        PeerCommand::List(args) => list(args),
        PeerCommand::Show(args) => show(args),
        PeerCommand::Remove(args) => remove(args),
        PeerCommand::Enroll(args) => enroll(args),
        PeerCommand::Invite(args) => invite(args),
        PeerCommand::Invites(args) => invites(args),
        PeerCommand::Rotate(args) => rotate(args),
        PeerCommand::Finalize(args) => finalize(args),
    }
}

/// A resolved identity for a new or rotated peer.
struct NewIdentity {
    identity: PeerIdentity,
    public_line: String,
    text: Option<String>,
    file: Option<String>,
    validity: Option<Validity>,
    generated: Option<keys::SecretFile>,
    key_path: Option<PathBuf>,
}

/// Resolve a peer's identity from a public line, a document, or a key made here.
///
/// `fresh_key` names the generated key with a timestamp, so a rotation never
/// overwrites the key file the previous bundle referred to.
#[allow(clippy::too_many_arguments)]
fn build_identity(
    server: &Server,
    directory: &Path,
    name: &str,
    public_key: Option<&str>,
    public_key_file: Option<&Path>,
    bundle_out: Option<&Path>,
    identity_path: Option<&Path>,
    fresh_key: bool,
) -> Result<NewIdentity, Error> {
    match (public_key, public_key_file, bundle_out, identity_path) {
        (Some(line), None, None, None) => {
            let identity = validate_public_line(server, line)?;
            Ok(NewIdentity {
                public_line: keys::encode_public(server.suite_id, &identity),
                identity,
                text: None,
                file: None,
                validity: None,
                generated: None,
                key_path: None,
            })
        }
        (None, Some(path), None, None) => {
            let text = std::fs::read_to_string(path).map_err(|source| Error::IoPath {
                action: "read public line",
                path: path.to_path_buf(),
                source,
            })?;
            let identity = validate_public_line(server, &text)?;
            Ok(NewIdentity {
                public_line: keys::encode_public(server.suite_id, &identity),
                identity,
                text: None,
                file: None,
                validity: None,
                generated: None,
                key_path: None,
            })
        }
        (None, None, Some(_), None) => {
            let clients = directory.join("clients");
            std::fs::create_dir_all(&clients).map_err(|source| Error::IoPath {
                action: "create",
                path: clients.clone(),
                source,
            })?;
            let key_name = if fresh_key {
                format!("{name}-{}.key", now_unix())
            } else {
                format!("{name}.key")
            };
            let key_path = clients.join(&key_name);
            let secret = keys::new_secret(server.suite_id, false, entropy::seed());
            keys::save_secret(&key_path, &secret)?;
            let identity = keys::identity(&server.suite, &secret)?;
            Ok(NewIdentity {
                public_line: keys::encode_public(server.suite_id, &identity.to_peer()),
                identity: identity.to_peer(),
                text: None,
                file: None,
                validity: None,
                generated: Some(secret),
                key_path: Some(key_path),
            })
        }
        (None, None, None, Some(path)) => {
            let text = std::fs::read_to_string(path).map_err(|source| Error::IoPath {
                action: "read identity document",
                path: path.to_path_buf(),
                source,
            })?;
            let text = text.trim().to_owned();
            let bytes = keys::hex_decode(&text).map_err(|why| {
                Error::Usage(format!("{}: identity document: {why}", path.display()))
            })?;
            let document = IdentityDocument::decode(&bytes)
                .map_err(|why| Error::Usage(format!("{}: {why}", path.display())))?;
            let now = now_unix();
            let window = document.validity();
            let identity = match &server.issuer {
                Some(issuer) => document.to_peer(&server.suite, issuer, now),
                None => {
                    if !document.is_self_signed(&server.suite) {
                        return Err(Error::Usage(format!(
                            "{}: the document is not self-signed, and interface.identity_issuer \
                             is not set",
                            path.display()
                        )));
                    }
                    document.to_peer(&server.suite, document.signing(), now)
                }
            }
            .map_err(|why| {
                Error::Usage(format!(
                    "{}: {why} (window {}..{})",
                    path.display(),
                    window.not_before,
                    window.not_after
                ))
            })?;

            // Keep a copy beside the config so the peer survives the source
            // file being moved, and so `peer list` can read the window.
            let clients = directory.join("clients");
            std::fs::create_dir_all(&clients).map_err(|source| Error::IoPath {
                action: "create",
                path: clients.clone(),
                source,
            })?;
            let relative = PathBuf::from("clients").join(format!("{}.identity", name));
            write_private(&directory.join(&relative), text.as_bytes())?;
            Ok(NewIdentity {
                public_line: keys::encode_public(server.suite_id, &identity),
                identity,
                text: Some(text),
                file: Some(relative.to_string_lossy().into_owned()),
                validity: Some(window),
                generated: None,
                key_path: None,
            })
        }
        _ => Err(Error::Usage(
            "give exactly one of --public-key, --public-key-file, --identity, or --bundle-out:\n  \
             --public-key LINE       the device generated its own key (recommended)\n  \
             --identity FILE         a CA-issued or self-signed document\n  \
             --bundle-out FILE       generate the keypair here and hand over a bundle"
                .to_owned(),
        )),
    }
}

/// `peer add` as `vallum setup` needs it: a name, a bundle, defaults elsewhere.
pub(crate) fn add_for_setup(config: &Path, name: &str, bundle_out: &Path) -> Result<(), Error> {
    add(&AddArgs {
        name: name.to_owned(),
        config: config.to_path_buf(),
        public_key: None,
        public_key_file: None,
        bundle_out: Some(bundle_out.to_path_buf()),
        ship_key: true,
        client_config_out: None,
        identity: None,
        address: None,
        allowed_ips: None,
        endpoint: None,
        keepalive: None,
        pin_endpoint: false,
        psk: false,
        dns: Vec::new(),
        forget_key: false,
        no_apply: false,
        json: false,
        full: false,
        quiet: false,
    })
}

#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// The name this device will have on the server.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The configuration file to edit.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// The device's public line, generated on the device itself.
    #[arg(long, value_name = "LINE", conflicts_with = "public_key_file")]
    pub public_key: Option<String>,

    /// A file holding the device's public line.
    #[arg(long, value_name = "FILE")]
    pub public_key_file: Option<PathBuf>,

    /// The address to route to the device. Allocated if absent.
    #[arg(long, value_name = "CIDR")]
    pub address: Option<String>,

    /// Send a keepalive every this many seconds.
    #[arg(long, value_name = "SECS")]
    pub keepalive: Option<u16>,

    /// Write the config but do not tell a running daemon.
    #[arg(long)]
    pub no_apply: bool,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

/// Enrol a device that generated its own key.
///
/// This is the primitive both enrolment transports call: SSH hands it a public
/// line, and the token transport will do the same. The private key is never
/// here — only the public line arrives, and only non-secret material leaves.
///
/// Idempotent on retry: the same line returns the same config, so a client that
/// lost its answer can simply ask again.
fn enroll(args: &EnrollArgs) -> Result<(), Error> {
    let report = enroll_report(args)?;
    if args.json {
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }
    say!("enrolled `{}`", report.name);
    say!("   address    {}", report.address);
    say!("   endpoint   {}", report.endpoint);
    say!("   fingerprint {}", report.fingerprint);
    say!();
    say!("the device's config:");
    for line in report.config.lines() {
        say!("   {line}");
    }
    Ok(())
}

/// Do the enrolment and return the report, without printing it.
///
/// The responder calls this in-process: a root service that shells out to
/// itself is another surface, and this way the validation is the same code.
pub(crate) fn enroll_report(args: &EnrollArgs) -> Result<Enrolled, Error> {
    require_config(&args.config)?;
    let server = load_server(&args.config)?;
    let line = match (&args.public_key, &args.public_key_file) {
        (Some(line), None) => line.trim().to_owned(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|source| Error::IoPath {
                action: "read the device's public line",
                path: path.clone(),
                source,
            })?
            .trim()
            .to_owned(),
        _ => {
            return Err(Error::Usage(
                "give the device's public line: --public-key LINE, or --public-key-file FILE"
                    .to_owned(),
            ))
        }
    };
    let identity = validate_public_line(&server, &line)?;
    let canonical = keys::encode_public(server.suite_id, &identity);

    let mut file = ConfigFile::load(&args.config)?;
    let existing = file.peers().into_iter().find(|peer| peer.name == args.name);
    let address = match &existing {
        Some(peer) => {
            let same = peer.public_key == canonical
                || peer.identity.as_deref() == Some(canonical.as_str());
            if !same {
                return Err(Error::Usage(format!(
                    "`{}` is already enrolled with a different key; `vallum peer rotate {}` \
                     replaces it deliberately",
                    args.name, args.name
                )));
            }
            peer.allowed_ips.first().cloned().ok_or_else(|| {
                Error::Usage(format!("`{}` has no address to hand back", args.name))
            })?
        }
        None => {
            add(&AddArgs {
                name: args.name.clone(),
                config: args.config.clone(),
                public_key: Some(canonical.clone()),
                public_key_file: None,
                bundle_out: None,
                ship_key: false,
                client_config_out: None,
                identity: None,
                address: args.address.clone(),
                allowed_ips: None,
                endpoint: None,
                keepalive: args.keepalive,
                pin_endpoint: false,
                psk: false,
                dns: Vec::new(),
                forget_key: false,
                no_apply: args.no_apply,
                json: false,
                full: false,
                quiet: true,
            })?;
            // `add` allocated the address; read it back rather than guessing.
            file = ConfigFile::load(&args.config)?;
            file.peers()
                .into_iter()
                .find(|peer| peer.name == args.name)
                .and_then(|peer| peer.allowed_ips.first().cloned())
                .ok_or_else(|| {
                    Error::Usage(format!("`{}` was added but has no address", args.name))
                })?
        }
    };

    let (endpoint, source) = bundle_endpoint(None, &server, &args.config)?;
    let config_text = client_config(
        &args.name,
        &address,
        &server.public_line,
        &endpoint,
        &[],
        None,
    );

    let _ = source;
    Ok(Enrolled {
        name: args.name.clone(),
        address,
        endpoint,
        server_address: file
            .interface_addresses()
            .first()
            .map(|network| network.addr().to_string()),
        fingerprint: fingerprint(&canonical),
        config: config_text,
    })
}

#[derive(Debug, Args)]
pub struct InviteArgs {
    /// The name the device will enrol under.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The configuration file this invite is for.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// Bind the invite to the device's public line: a stolen token then
    /// enrols nothing, because the attacker has no matching private key.
    #[arg(long, value_name = "LINE", conflicts_with = "public_key_file")]
    pub public_key: Option<String>,

    /// A file holding the device's public line.
    #[arg(long, value_name = "FILE")]
    pub public_key_file: Option<PathBuf>,

    /// How long the invite lives, in minutes.
    #[arg(long, value_name = "MINUTES", default_value = "15")]
    pub ttl: u64,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

/// Mint a single-use enrolment token for a machine that cannot SSH in.
///
/// The token is the only secret here, and it is small and short-lived on
/// purpose: single use, fifteen minutes, stored hashed nowhere because the
/// whole point is that it can be read aloud — typed into the client once.
fn invite(args: &InviteArgs) -> Result<(), Error> {
    require_config(&args.config)?;
    let file = ConfigFile::load(&args.config)?;
    let interface = vallum_config::Config::load(&args.config)
        .ok()
        .and_then(|config| config.interface.name)
        .unwrap_or_else(|| "vallum0".to_owned());
    if file.peers().into_iter().any(|peer| peer.name == args.name) {
        return Err(Error::Usage(format!(
            "`{}` is already a peer; `vallum peer remove {}` first, or choose another name",
            args.name, args.name
        )));
    }
    // A pinned invite names the key it will accept, which turns the token from
    // a bearer credential into a registration for a key the client already has.
    let expect =
        match (&args.public_key, &args.public_key_file) {
            (Some(line), None) => Some(line.trim().to_owned()),
            (None, Some(path)) => Some(
                std::fs::read_to_string(path)
                    .map_err(|source| Error::IoPath {
                        action: "read the device's public line",
                        path: path.clone(),
                        source,
                    })?
                    .trim()
                    .to_owned(),
            ),
            (None, None) => None,
            _ => return Err(Error::Usage(
                "give the device's public line once: --public-key LINE or --public-key-file FILE"
                    .to_owned(),
            )),
        };
    let server = load_server(&args.config)?;
    if let Some(line) = &expect {
        validate_public_line(&server, line)?;
    }
    let (token, id, path) =
        crate::enroll::issue_invite(&interface, &args.name, args.ttl * 60, expect)?;
    let server_fingerprint = fingerprint(&server.public_line);
    let endpoint = bundle_endpoint(None, &server, &args.config)?.0;
    // The responder's port is `[enroll].port`, defaulting to `listen + 1` —
    // not necessarily the endpoint's port + 1 (the endpoint can name a
    // different port than the one bound, e.g. behind NAT).
    let config = vallum_config::Config::load(&args.config).ok();
    let port = config
        .as_ref()
        .and_then(|cfg| cfg.enroll.port)
        .or_else(|| {
            endpoint
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .map(|port| port.saturating_add(1))
        })
        .unwrap_or(51821);
    let host = endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or("?");

    let ticket = crate::enroll::JoinTicket {
        server: format!("{host}:{port}"),
        name: args.name.clone(),
        invite_id: id.clone(),
        token: token.clone(),
        fingerprint: server_fingerprint.clone(),
    }
    .encode();

    if args.json {
        say!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "name": args.name,
                "id": id,
                "token": token.display(),
                "fingerprint": server_fingerprint,
                "expires_in_secs": args.ttl * 60,
                "join": format!("{host}:{port}"),
                "ticket": ticket,
            }))
            .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }

    // An invite that cannot be answered is dead code. When this operator is
    // root on a systemd host, the invite starts its own responder rather than
    // printing homework.
    let enroll_enabled = config
        .as_ref()
        .map(|config| config.enroll.enabled)
        .unwrap_or(false);
    let systemd = Path::new("/run/systemd/system").exists();
    let root = nix::unistd::geteuid().is_root();
    if root && systemd && !enroll_enabled {
        crate::commands::server::enroll(&crate::commands::server::EnrollArgs {
            config: args.config.clone(),
            enable: true,
            disable: false,
            dry_run: false,
        })?;
    } else if root && systemd {
        let active = std::process::Command::new("systemctl")
            .args([
                "--no-ask-password",
                "is-active",
                "--quiet",
                &format!("vallum-enroll@{interface}"),
            ])
            .status()
            .is_ok_and(|status| status.success());
        if !active {
            let _ = std::process::Command::new("systemctl")
                .args([
                    "--no-ask-password",
                    "enable",
                    "--now",
                    &format!("vallum-enroll@{interface}"),
                ])
                .status();
        }
    }

    say!(
        "invite for `{}` — single use, expires in {} minutes",
        args.name,
        args.ttl
    );
    say!();
    say!("   on the client:");
    say!("      sudo vallum join {ticket}");
    say!();
    say!(
        "   the token lives in {} (0600) and is never logged;",
        path.display()
    );
    say!("   it is the only secret in this exchange — the client's private key");
    say!("   is generated on the client and never leaves it.");
    if !(root && systemd) {
        say!();
        if enroll_enabled {
            say!("   [enroll] is enabled; if the responder is not running yet:");
            say!(
                "      sudo systemctl enable --now vallum-enroll@{}",
                interface
            );
        } else {
            say!(
                "   this needs `[enroll] enabled = true` in {} and then",
                args.config.display()
            );
            say!(
                "   `sudo systemctl enable --now vallum-enroll@{}`.",
                interface
            );
        }
    }
    Ok(())
}

#[derive(Debug, Args)]
pub struct InvitesArgs {
    /// The configuration file whose interface to inspect.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    pub config: PathBuf,

    /// Emit JSON instead of a table (tokens are never printed here).
    #[arg(long)]
    pub json: bool,
}

fn invites(args: &InvitesArgs) -> Result<(), Error> {
    let interface = vallum_config::Config::load(&args.config)
        .ok()
        .and_then(|config| config.interface.name)
        .unwrap_or_else(|| "vallum0".to_owned());
    let live = crate::enroll::list_invites(&interface);
    let now = now_unix();
    if args.json {
        let rows: Vec<serde_json::Value> = live
            .iter()
            .map(|inv| {
                serde_json::json!({
                    "name": inv.name,
                    "id": inv.id,
                    "pinned": inv.expect_public_line.is_some(),
                    "spent": inv.public_line.is_some(),
                    "expires_in_secs": inv.expires.saturating_sub(now),
                })
            })
            .collect();
        say!(
            "{}",
            serde_json::to_string_pretty(&rows)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }
    if live.is_empty() {
        say!("no live invites for `{interface}`");
        return Ok(());
    }
    say!(
        "{}",
        crate::style::table_header(&format!(
            "{:<16} {:<32} {:<8} {:<8} EXPIRES IN",
            "NAME", "ID", "PINNED", "STATUS"
        ))
    );
    for inv in &live {
        let remaining = inv.expires.saturating_sub(now);
        let status = if inv.public_line.is_some() {
            "spent"
        } else {
            "open"
        };
        let pinned = if inv.expect_public_line.is_some() {
            "yes"
        } else {
            "no"
        };
        say!(
            "{:<16} {:<32} {:<8} {:<8} {}s",
            inv.name,
            inv.id,
            pinned,
            status,
            remaining
        );
    }
    Ok(())
}

fn add(args: &AddArgs) -> Result<(), Error> {
    // The default must not be "the server makes the key": that is the custody
    // finding this command used to embody. A device that can run `vallum
    // keygen` should send its public line; one that cannot must be named.
    if args.public_key.is_none()
        && args.public_key_file.is_none()
        && args.identity.is_none()
        && !args.ship_key
    {
        return Err(Error::Usage(format!(
            "give `{}`'s public line with --public-key or --public-key-file — it \
             generates its own key with `vallum keygen`.\n\
             If the device cannot do that (a phone, an appliance), pass --ship-key \
             to have this server generate the key and hand it over in a bundle.",
            args.name
        )));
    }
    if args.ship_key && args.bundle_out.is_none() && args.client_config_out.is_none() {
        return Err(Error::Usage(
            "--ship-key generates a key; say where it goes with --bundle-out or \
             --client-config-out, or drop --ship-key"
                .to_owned(),
        ));
    }
    if args.ship_key {
        say!(
            "warning: this server is generating `{}`'s private key.",
            args.name
        );
        say!("         a compromise here is a compromise of that device. The key");
        say!("         leaves in the bundle and stays on the server until --forget-key.");
    }

    require_config(&args.config)?;
    let mut file = ConfigFile::load(&args.config)?;
    if file.has_peer(&args.name) {
        return Err(Error::Usage(format!(
            "a peer named `{}` already exists; remove it first, or choose another name",
            args.name
        )));
    }
    let server = load_server(&args.config)?;

    // 1. The peer's identity: a public line, a document, or a key generated here.
    let built = build_identity(
        &server,
        &file.directory(),
        &args.name,
        args.public_key.as_deref(),
        args.public_key_file.as_deref(),
        args.bundle_out.as_deref(),
        args.identity.as_deref(),
        false,
    )?;
    let peer_identity = built.identity.clone();
    let identity_text = built.text.clone();
    let identity_file = built.file.clone();
    let validity = built.validity;
    let generated = built.generated.clone();
    let public_line = keys::encode_public(server.suite_id, &peer_identity);

    // 2. The address, allocated from the tunnel's own subnets if not given.
    let address = match &args.address {
        Some(text) => parse_host_prefix(text)?,
        None => {
            let networks = file.interface_addresses();
            let own = file.own_addresses();
            let taken: Vec<IpNet> = file
                .peers()
                .iter()
                .flat_map(|peer| peer.allowed_ips.iter())
                .filter_map(|prefix| prefix.parse().ok())
                .collect();
            config_edit::next_host_address(&networks, &taken, &own).ok_or_else(|| {
                Error::Usage(
                    "the tunnel has no free address left; pass --address with one from the \
                     tunnel's subnet, or widen the interface address"
                        .to_owned(),
                )
            })?
        }
    };

    // 3. What is routed to it.
    let allowed = match &args.allowed_ips {
        Some(list) => config_edit::parse_prefixes(list)?,
        None => vec![address.to_string()],
    };
    ensure_no_overlap(&file, &args.name, &allowed)?;

    // 4. A preshared key, if asked for. Written as a file so it is not in the
    //    config body, which is the form the config docs recommend.
    let mut psk_hex = None;
    let mut psk_file = None;
    if args.psk {
        let bytes = entropy::seed();
        let hex = keys::hex_encode(&bytes);
        let relative = PathBuf::from("clients").join(format!("{}.psk", args.name));
        let path = file.directory().join(&relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| Error::IoPath {
                action: "create",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        write_private(&path, hex.as_bytes())?;
        psk_file = Some(relative.to_string_lossy().into_owned());
        psk_hex = Some(hex);
    }

    if args.pin_endpoint && args.endpoint.is_none() {
        return Err(Error::Usage(
            "--pin-endpoint needs --endpoint: a peer with no address has nothing to pin to"
                .to_owned(),
        ));
    }
    let endpoint = match &args.endpoint {
        Some(text) => Some(endpoint_with_port(text, &args.config)?),
        None => None,
    };
    let record = PeerRecord {
        name: args.name.clone(),
        // A document names the key; writing both would be a config that says
        // two different things about the same peer.
        public_key: if identity_file.is_some() {
            String::new()
        } else {
            public_line.clone()
        },
        allowed_ips: allowed.clone(),
        endpoint: endpoint.clone(),
        keepalive: args.keepalive,
        identity: identity_text.clone(),
        identity_file,
        validity,
        preshared_key_file: psk_file,
        has_psk: args.psk,
        pin_endpoint: args.pin_endpoint,
        rotating: false,
    };
    file.add_peer(&record)?;
    file.validate()?;
    let backup = file.save()?;

    // 5. The bundle, when the server generated the key.
    let mut bundle_path = None;
    let mut bundle_endpoint_result = None;
    if let Some(path) = &args.bundle_out {
        let secret = generated.as_ref().ok_or_else(|| {
            Error::Usage("--bundle-out needs a key this command generated".to_owned())
        })?;
        let (endpoint, source) = bundle_endpoint(args.endpoint.as_deref(), &server, &args.config)?;
        let config_text = client_config(
            &args.name,
            &address.to_string(),
            &server.public_line,
            &endpoint,
            &args.dns,
            psk_hex.as_deref(),
        );
        let bundle = Bundle {
            version: 1,
            name: args.name.clone(),
            config: config_text,
            key: keys::render_secret(secret),
        };
        write_private(
            path,
            serde_json::to_string_pretty(&bundle)
                .map_err(|error| Error::Usage(format!("bundle: {error}")))?
                .as_bytes(),
        )?;
        if args.forget_key {
            let key_path = file
                .directory()
                .join("clients")
                .join(format!("{}.key", args.name));
            let _ = std::fs::remove_file(key_path);
        }
        bundle_path = Some(path.clone());
        bundle_endpoint_result = Some((endpoint, source));
    }

    let mut client_config_path = None;
    if let Some(path) = &args.client_config_out {
        let (endpoint, source) = bundle_endpoint(args.endpoint.as_deref(), &server, &args.config)?;
        let text = client_config(
            &args.name,
            &address.to_string(),
            &server.public_line,
            &endpoint,
            &args.dns,
            psk_hex.as_deref(),
        );
        write_private(path, text.as_bytes())?;
        client_config_path = Some(path.clone());
        bundle_endpoint_result = Some((endpoint, source));
    }

    let apply = if args.no_apply {
        ApplyOutcome::Skipped
    } else {
        syncconf_running(&args.config)?
    };

    if args.json {
        let report = Added {
            name: args.name.clone(),
            address: address.to_string(),
            allowed_ips: allowed,
            public_key: args.full.then(|| public_line.clone()),
            fingerprint: fingerprint(identity_text.as_deref().unwrap_or(&public_line)),
            endpoint: endpoint.clone(),
            keepalive: args.keepalive,
            psk: args.psk,
            pin_endpoint: args.pin_endpoint,
            validity: validity_label(validity, now_unix()),
            bundle: bundle_path.clone(),
            bundle_endpoint: bundle_endpoint_result
                .as_ref()
                .map(|(endpoint, _)| endpoint.clone()),
            client_config: client_config_path.clone(),
            config: args.config.clone(),
            backup,
            applied: apply.applied(),
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }

    if args.quiet {
        return Ok(());
    }
    say!("added peer `{}`", args.name);
    say!("   address    {}", address);
    say!("   allowed    {}", allowed.join(", "));
    say!(
        "   fingerprint {}",
        fingerprint(identity_text.as_deref().unwrap_or(&public_line))
    );
    if validity.is_some() {
        say!("   identity    {}", validity_label(validity, now_unix()));
    }
    if let Some(endpoint) = &endpoint {
        say!("   endpoint   {endpoint}");
    }
    say!(
        "   config     {} (backup {})",
        args.config.display(),
        backup.display()
    );
    say!("   applied    {}", apply.describe());
    if let Some(path) = &client_config_path {
        say!("   client     {}", path.display());
        if let Some((endpoint, source)) = &bundle_endpoint_result {
            say_bundle_endpoint(endpoint, *source);
        }
        say!(
            "              copy it to the device, with its key file named `{}.key`",
            args.name
        );
    }
    if let Some(path) = &bundle_path {
        say!("   bundle     {}", path.display());
        if let Some((endpoint, source)) = &bundle_endpoint_result {
            say_bundle_endpoint(endpoint, *source);
        }
        if args.forget_key {
            say!("   key        deleted from the server (--forget-key)");
        } else {
            say!(
                "   key        {} — the server still holds this client's key",
                file.directory()
                    .join("clients")
                    .join(format!("{}.key", args.name))
                    .display()
            );
        }
        say!();
        say!("on the client:");
        say!("   vallum import-bundle {} --install", path.display());
    }
    Ok(())
}

fn rotate(args: &RotateArgs) -> Result<(), Error> {
    require_config(&args.config)?;
    let mut file = ConfigFile::load(&args.config)?;
    if !file.has_peer(&args.name) {
        return Err(Error::Usage(format!(
            "no peer named `{}`; `peer add` creates one",
            args.name
        )));
    }
    let server = load_server(&args.config)?;
    let built = build_identity(
        &server,
        &file.directory(),
        &args.name,
        args.public_key.as_deref(),
        args.public_key_file.as_deref(),
        args.bundle_out.as_deref(),
        args.identity.as_deref(),
        true,
    )?;

    let fields = IdentityFields {
        public_key: if built.file.is_some() {
            None
        } else {
            Some(built.public_line.clone())
        },
        identity: built.text.clone(),
        identity_file: built.file.clone(),
    };
    file.rotate_peer(&args.name, &fields)?;
    file.validate()?;
    let backup = file.save()?;

    // The bundle, when the server generated the new key.
    let mut bundle_path = None;
    let mut bundle_endpoint_result = None;
    if let Some(path) = &args.bundle_out {
        let secret = built.generated.as_ref().ok_or_else(|| {
            Error::Usage("--bundle-out needs a key this command generated".to_owned())
        })?;
        let peer = file
            .peers()
            .into_iter()
            .find(|peer| peer.name == args.name)
            .ok_or_else(|| Error::Usage(format!("no peer named `{}`", args.name)))?;
        let address = peer
            .allowed_ips
            .first()
            .ok_or_else(|| Error::Usage("the peer has no address to put in a bundle".to_owned()))?;
        let (endpoint, source) = bundle_endpoint(args.endpoint.as_deref(), &server, &args.config)?;
        bundle_endpoint_result = Some((endpoint.clone(), source));
        let psk = read_psk(&peer, &file.directory())?;
        let config_text = client_config(
            &args.name,
            address,
            &server.public_line,
            &endpoint,
            &args.dns,
            psk.as_deref(),
        );
        let bundle = Bundle {
            version: 1,
            name: args.name.clone(),
            config: config_text,
            key: keys::render_secret(secret),
        };
        write_private(
            path,
            serde_json::to_string_pretty(&bundle)
                .map_err(|error| Error::Usage(format!("bundle: {error}")))?
                .as_bytes(),
        )?;
        if args.forget_key {
            if let Some(key_path) = &built.key_path {
                let _ = std::fs::remove_file(key_path);
            }
        }
        bundle_path = Some(path.clone());
    }

    let apply = if args.no_apply {
        ApplyOutcome::Skipped
    } else {
        syncconf_running(&args.config)?
    };

    if args.json {
        let report = Rotated {
            name: args.name.clone(),
            fingerprint: fingerprint(built.text.as_deref().unwrap_or(&built.public_line)),
            bundle: bundle_path.clone(),
            bundle_endpoint: bundle_endpoint_result
                .as_ref()
                .map(|(endpoint, _)| endpoint.clone()),
            config: args.config.clone(),
            backup,
            applied: apply.applied(),
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }

    say!("rotated peer `{}`", args.name);
    say!(
        "   new key    {}",
        fingerprint(built.text.as_deref().unwrap_or(&built.public_line))
    );
    say!(
        "   old key    kept as previous until `peer finalize {}`",
        args.name
    );
    if let Some(path) = &bundle_path {
        say!("   bundle     {}", path.display());
        if let Some((endpoint, source)) = &bundle_endpoint_result {
            say_bundle_endpoint(endpoint, *source);
        }
        say!();
        say!("on the client:");
        say!("   vallum import-bundle {} --install", path.display());
    }
    say!(
        "   config     {} (backup {})",
        args.config.display(),
        backup.display()
    );
    say!("   applied    {}", apply.describe());
    Ok(())
}

fn finalize(args: &FinalizeArgs) -> Result<(), Error> {
    require_config(&args.config)?;
    let mut file = ConfigFile::load(&args.config)?;
    let retired = file.finalize_peer(&args.name)?;
    file.validate()?;
    let backup = file.save()?;
    let apply = if args.no_apply {
        ApplyOutcome::Skipped
    } else {
        syncconf_running(&args.config)?
    };

    if args.json {
        let report = Finalized {
            name: args.name.clone(),
            retired,
            config: args.config.clone(),
            backup,
            applied: apply.applied(),
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }

    if retired {
        say!("finalized peer `{}`", args.name);
        say!("   the previous identity is no longer accepted");
    } else {
        say!(
            "peer `{}` has no previous identity; nothing to retire",
            args.name
        );
    }
    say!(
        "   config     {} (backup {})",
        args.config.display(),
        backup.display()
    );
    say!("   applied    {}", apply.describe());
    Ok(())
}

fn read_psk(peer: &PeerRecord, directory: &Path) -> Result<Option<String>, Error> {
    let Some(file) = &peer.preshared_key_file else {
        return Ok(None);
    };
    let path = directory.join(file);
    Ok(Some(
        std::fs::read_to_string(&path)
            .map_err(|source| Error::IoPath {
                action: "read preshared key",
                path,
                source,
            })?
            .trim()
            .to_owned(),
    ))
}

fn list(args: &ListArgs) -> Result<(), Error> {
    require_config(&args.config)?;
    let file = ConfigFile::load(&args.config)?;
    let peers = file.peers();
    if args.json {
        let rows: Vec<Listed> = peers
            .iter()
            .map(|peer| Listed {
                name: peer.name.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                endpoint: peer.endpoint.clone(),
                keepalive: peer.keepalive,
                psk: peer.has_psk,
                pin_endpoint: peer.pin_endpoint,
                validity: validity_label(peer.validity, now_unix()),
                rotating: peer.rotating,
                fingerprint: peer
                    .fingerprint_source()
                    .map_or_else(|| "-".to_owned(), fingerprint),
                public_key: args.full.then(|| peer.public_key.clone()),
            })
            .collect();
        say!(
            "{}",
            serde_json::to_string_pretty(&rows)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }
    if peers.is_empty() {
        say!("no peers in {}", args.config.display());
        say!("add one:  vallum peer add laptop --bundle-out laptop.vallum-bundle");
        return Ok(());
    }
    say!(
        "{:<16} {:<28} {:<26} {:>9} {:>4} {:>4} {:<9} {:>3}  FINGERPRINT",
        "NAME",
        "ALLOWED IPS",
        "ENDPOINT",
        "KEEPALIVE",
        "PSK",
        "PIN",
        "VALIDITY",
        "ROT"
    );
    for peer in &peers {
        let allowed = peer.allowed_ips.join(",");
        let allowed = elide(&allowed, 28);
        let endpoint = peer
            .endpoint
            .clone()
            .unwrap_or_else(|| "(roaming)".to_owned());
        say!(
            "{:<16} {:<28} {:<26} {:>9} {:>4} {:>4} {:<9} {:>3}  {}",
            elide(&peer.name, 16),
            allowed,
            elide(&endpoint, 26),
            peer.keepalive
                .map_or_else(|| "-".to_owned(), |value| format!("{value}s")),
            if peer.has_psk { "yes" } else { "no" },
            if peer.pin_endpoint { "yes" } else { "no" },
            validity_label(peer.validity, now_unix()),
            if peer.rotating { "yes" } else { "-" },
            peer.fingerprint_source()
                .map_or_else(|| "-".to_owned(), fingerprint),
        );
        if args.full {
            if let Some(line) = peer.fingerprint_source() {
                say!("                 {line}");
            }
        }
    }
    Ok(())
}

fn show(args: &ShowArgs) -> Result<(), Error> {
    require_config(&args.config)?;
    let file = ConfigFile::load(&args.config)?;
    let peer = file
        .peers()
        .into_iter()
        .find(|peer| peer.name == args.name)
        .ok_or_else(|| Error::Usage(format!("no peer named `{}`", args.name)))?;
    if args.json {
        let report = Listed {
            name: peer.name.clone(),
            allowed_ips: peer.allowed_ips.clone(),
            endpoint: peer.endpoint.clone(),
            keepalive: peer.keepalive,
            psk: peer.has_psk,
            pin_endpoint: peer.pin_endpoint,
            validity: validity_label(peer.validity, now_unix()),
            rotating: peer.rotating,
            fingerprint: peer
                .fingerprint_source()
                .map_or_else(|| "-".to_owned(), fingerprint),
            public_key: Some(peer.public_key.clone()),
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }
    say!("peer `{}`", peer.name);
    say!("   allowed ips   {}", peer.allowed_ips.join(", "));
    say!(
        "   endpoint      {}",
        peer.endpoint
            .clone()
            .unwrap_or_else(|| "(roaming)".to_owned())
    );
    say!(
        "   keepalive     {}",
        peer.keepalive
            .map_or_else(|| "off".to_owned(), |value| format!("{value}s"))
    );
    say!(
        "   preshared key {}",
        if peer.has_psk { "set" } else { "none" }
    );
    say!(
        "   endpoint pin  {}",
        if peer.pin_endpoint {
            "pinned (no roaming)"
        } else {
            "roaming"
        }
    );
    say!(
        "   identity      {}",
        validity_label(peer.validity, now_unix())
    );
    if peer.rotating {
        say!("   rotation      in progress; `peer finalize` retires the old key");
    }
    say!(
        "   fingerprint   {}",
        peer.fingerprint_source()
            .map_or_else(|| "-".to_owned(), fingerprint)
    );
    if peer.public_key.is_empty() {
        say!("   public line   (none: this peer is named by an identity document)");
    } else if args.full {
        say!("   public line   {}", peer.public_key);
    } else {
        say!(
            "   public line   (pass --full to print all {} bytes)",
            peer.public_key.len()
        );
    }
    Ok(())
}

fn remove(args: &RemoveArgs) -> Result<(), Error> {
    require_config(&args.config)?;
    let interface = vallum_config::Config::load(&args.config)
        .ok()
        .and_then(|config| config.interface.name)
        .unwrap_or_else(|| "vallum0".to_owned());
    // Revoke any live invite first: if the operator is cancelling an unspent
    // invite before the device ever enrolled, that alone is a valid removal.
    let revoked = crate::enroll::revoke_invite(&interface, &args.name);
    let mut file = ConfigFile::load(&args.config)?;
    if !file.has_peer(&args.name) && revoked > 0 {
        if args.json {
            say!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": args.name,
                    "revoked_invites": revoked,
                }))
                .map_err(|error| Error::Usage(format!("json: {error}")))?
            );
        } else {
            say!("revoked pending invite for `{}`", args.name);
        }
        return Ok(());
    }
    let removed = file.remove_peer(&args.name)?;
    file.validate()?;
    let backup = file.save()?;
    let apply = if args.no_apply {
        ApplyOutcome::Skipped
    } else {
        syncconf_running(&args.config)?
    };
    if args.json {
        let report = Removed {
            name: removed.name,
            allowed_ips: removed.allowed_ips,
            config: args.config.clone(),
            backup,
            applied: apply.applied(),
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }
    say!("removed peer `{}`", args.name);
    say!(
        "   config   {} (backup {})",
        args.config.display(),
        backup.display()
    );
    say!("   applied  {}", apply.describe());
    say!("   client key files are left in place; delete them by hand if the device is gone");
    Ok(())
}

#[derive(Debug, Serialize)]
pub(crate) struct Enrolled {
    pub(crate) name: String,
    pub(crate) address: String,
    pub(crate) endpoint: String,
    /// The server's own tunnel address, so the client can prove the tunnel by
    /// pinging it straight after enrolling.
    pub(crate) server_address: Option<String>,
    pub(crate) fingerprint: String,
    pub(crate) config: String,
}

#[derive(Debug, Serialize)]
struct Added {
    name: String,
    address: String,
    allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    fingerprint: String,
    endpoint: Option<String>,
    keepalive: Option<u16>,
    psk: bool,
    pin_endpoint: bool,
    validity: String,
    bundle: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_config: Option<PathBuf>,
    config: PathBuf,
    backup: PathBuf,
    applied: bool,
}

#[derive(Debug, Serialize)]
struct Listed {
    name: String,
    allowed_ips: Vec<String>,
    endpoint: Option<String>,
    keepalive: Option<u16>,
    psk: bool,
    pin_endpoint: bool,
    validity: String,
    rotating: bool,
    fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct Rotated {
    name: String,
    fingerprint: String,
    bundle: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_endpoint: Option<String>,
    config: PathBuf,
    backup: PathBuf,
    applied: bool,
}

#[derive(Debug, Serialize)]
struct Finalized {
    name: String,
    retired: bool,
    config: PathBuf,
    backup: PathBuf,
    applied: bool,
}

#[derive(Debug, Serialize)]
struct Removed {
    name: String,
    allowed_ips: Vec<String>,
    config: PathBuf,
    backup: PathBuf,
    applied: bool,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn require_config(path: &Path) -> Result<(), Error> {
    if path.exists() {
        Ok(())
    } else {
        Err(Error::Precondition(format!(
            "{} does not exist; run `vallum server init --config {}` first",
            path.display(),
            path.display()
        )))
    }
}

fn load_server(config_path: &Path) -> Result<Server, Error> {
    let config = Config::load(config_path)?;
    let key_path = config::resolve_key_path(config_path, &config.interface.private_key);
    let file = keys::load_secret(&key_path)?;
    let suite = SdkSuite::from_id(file.suite).map_err(|error| Error::Suite(error.to_string()))?;
    let identity = keys::identity(&suite, &file)?;
    let public_line = keys::encode_public(file.suite, &identity.to_peer());
    let issuer = match config.interface.identity_issuer.as_deref() {
        Some(text) => Some(
            keys::issuer_signing_key(suite.suite_id(), suite.sizes().sign_pk_max, text)
                .map_err(|why| Error::Usage(format!("interface.identity_issuer: {why}")))?,
        ),
        None => None,
    };
    Ok(Server {
        suite,
        suite_id: file.suite,
        public_line,
        issuer,
        public_endpoint: config.interface.public_endpoint.clone(),
    })
}

fn validate_public_line(server: &Server, line: &str) -> Result<vallum_core::PeerIdentity, Error> {
    let (suite, identity) = keys::decode_public(line)?;
    if suite != server.suite_id {
        return Err(Error::Usage(format!(
            "the peer's public line is for suite 0x{suite:04x} ({}), but this server speaks \
             0x{:04x} ({}); generate the key with `vallum keygen --suite {}`",
            keys::describe_suite(suite),
            server.suite_id,
            keys::describe_suite(server.suite_id),
            server.suite_id,
        )));
    }
    let expected = server.suite.sizes().kem_pk;
    if identity.kem().len() != expected {
        return Err(Error::Usage(format!(
            "the peer's KEM public key is {} bytes, but suite 0x{:04x} uses {expected}",
            identity.kem().len(),
            server.suite_id
        )));
    }
    Ok(identity)
}

fn parse_host_prefix(text: &str) -> Result<IpNet, Error> {
    if let Ok(network) = text.parse::<IpNet>() {
        return Ok(network);
    }
    let address: IpAddr = text
        .parse()
        .map_err(|error| Error::Usage(format!("`{text}` is not an address: {error}")))?;
    let prefix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    IpNet::new(address, prefix)
        .map_err(|error| Error::Usage(format!("`{text}` is not an address: {error}")))
}

fn ensure_no_overlap(file: &ConfigFile, name: &str, allowed: &[String]) -> Result<(), Error> {
    let candidate: Vec<Prefix> = allowed
        .iter()
        .map(|prefix| {
            prefix
                .parse::<Prefix>()
                .map_err(|error| Error::Usage(format!("`{prefix}`: {error}")))
        })
        .collect::<Result<_, _>>()?;
    for peer in file.peers() {
        for existing in &peer.allowed_ips {
            let existing: Prefix = existing
                .parse()
                .map_err(|error| Error::Usage(format!("peer `{}`: {error}", peer.name)))?;
            for prefix in &candidate {
                if existing.overlaps(prefix).is_some() {
                    return Err(Error::Usage(format!(
                        "`{}` for `{name}` overlaps `{existing}` routed to peer `{}`; \
                         two peers cannot claim the same addresses",
                        prefix, peer.name
                    )));
                }
            }
        }
    }
    Ok(())
}

fn listen_port_of(config_path: &Path) -> Result<u16, Error> {
    let config = Config::load(config_path)?;
    let listen = config
        .interface
        .listen
        .clone()
        .unwrap_or_else(|| "0.0.0.0:51820".to_owned());
    listen_port(&listen)
}

/// An endpoint as the config stores it: always with the port the server binds,
/// because a bare host is not a dialable endpoint and the daemon refuses it.
fn endpoint_with_port(text: &str, config_path: &Path) -> Result<String, Error> {
    Ok(normalise_endpoint(text, listen_port_of(config_path)?))
}

/// Where the bundle's endpoint came from, so the report can say so honestly: an
/// explicit flag and a remembered `public_endpoint` are choices; a detected
/// source route is a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointSource {
    Explicit,
    Configured,
    Detected,
}

fn bundle_endpoint(
    explicit: Option<&str>,
    server: &Server,
    config_path: &Path,
) -> Result<(String, EndpointSource), Error> {
    let port = listen_port_of(config_path)?;
    if let Some(text) = explicit {
        return Ok((normalise_endpoint(text, port), EndpointSource::Explicit));
    }
    if let Some(text) = server.public_endpoint.as_deref() {
        return Ok((normalise_endpoint(text, port), EndpointSource::Configured));
    }
    detected_endpoint(port)
        .map(|endpoint| (endpoint, EndpointSource::Detected))
        .ok_or_else(|| {
            Error::Usage(
                "the client bundle needs a reachable endpoint; pass --endpoint <host:port> \
                 (the address the client should dial)"
                    .to_owned(),
            )
        })
}

fn say_bundle_endpoint(endpoint: &str, source: EndpointSource) {
    match source {
        EndpointSource::Explicit | EndpointSource::Configured => {
            say!("              → {endpoint}")
        }
        EndpointSource::Detected => say!(
            "              → {endpoint} (guessed from the source route; pass --endpoint if clients \
             should dial something else)"
        ),
    }
}

/// The interface name a client config uses: `vallum-<peer>`, at most 15 bytes.
///
/// The name is local to this machine, and it must not be `vallum0`, which is
/// what a server calls its own interface: a host that is both a server and a
/// client would otherwise have two daemons fighting over one interface.
///
/// Returns whether the name had to be shortened. A shortened name is not
/// unique: `vpsclient-a` and `vpsclient-b` both become `vallum-vpsclien`, and
/// two configs on one machine would then fight over one interface. The caller
/// says so out loud rather than letting the collision surface later.
fn client_interface_name(peer: &str) -> (String, bool) {
    let mut name = String::from("vallum-");
    let mut shortened = false;
    for ch in peer.chars() {
        if name.len() >= 15 {
            shortened = true;
            break;
        }
        name.push(if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            ch
        } else {
            '-'
        });
    }
    while name.len() > 7 && name.ends_with(['-', '_']) {
        name.pop();
    }
    (name, shortened)
}

fn client_config(
    name: &str,
    address: &str,
    server_line: &str,
    endpoint: &str,
    dns: &[String],
    psk: Option<&str>,
) -> String {
    let mut body = String::new();
    body.push_str("[interface]\n");
    // Named after the peer, not `vallum0`: a machine that is already a server
    // has a `vallum0`, and two daemons cannot own one interface. 15 characters
    // is the kernel's IFNAMSIZ limit minus the terminator.
    let (interface, shortened) = client_interface_name(name);
    if shortened {
        eprintln!(
            "vallum: peer name `{name}` is longer than the kernel's 15-character \
             interface name allows, so this config uses `{interface}`. Two peers whose \
             names share that prefix would collide on one machine — give them names \
             that differ early."
        );
    }
    body.push_str(&format!("name = \"{interface}\"\n"));
    body.push_str(&format!("private_key = \"{name}.key\"\n"));
    body.push_str(&format!("addresses = [\"{address}\"]\n"));
    body.push_str("listen = \"0.0.0.0:0\"\n");
    body.push_str(&format!(
        "control = \"{}/{interface}.sock\"\n",
        vallum_config::RUNTIME_DIR
    ));
    // This is a full-tunnel config (allowed_ips is 0.0.0.0/0 below), so the
    // default route moves to a policy table. The mark is what lets the daemon's
    // own packets escape to the real gateway; without it `vallum-quick` refuses
    // the config, and with a wrong one the tunnel would carry itself.
    body.push_str("fwmark = 51820\n");
    body.push_str("\n[log]\nlevel = \"info\"\n");
    body.push_str("\n[quick]\n");
    if !dns.is_empty() {
        let list = dns
            .iter()
            .map(|server| format!("\"{server}\""))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!("dns = [{list}]\n"));
    }
    body.push_str("table = \"auto\"\n");
    body.push_str("\n[[peer]]\n");
    body.push_str("name = \"server\"\n");
    body.push_str(&format!("public_key = \"{server_line}\"\n"));
    body.push_str(&format!("endpoint = \"{endpoint}\"\n"));
    // Claim only the families the tunnel carries. `::/0` on a tunnel with no
    // IPv6 does not create a v6 route — it asserts that v6 belongs to the
    // tunnel, and when that route cannot be installed the traffic falls through
    // to the real default route and escapes outside the tunnel. That is the leak
    // `verify-remote.sh` reports. The address this peer was given is the
    // authority on what the tunnel carries; when allocation learns to hand out a
    // v6 address as well, this must take the whole set rather than the first.
    let allowed = if address.contains(':') {
        "[\"::/0\"]"
    } else {
        "[\"0.0.0.0/0\"]"
    };
    body.push_str(&format!("allowed_ips = {allowed}\n"));
    body.push_str("persistent_keepalive = 25\n");
    if let Some(psk) = psk {
        body.push_str(&format!("preshared_key = \"{psk}\"\n"));
    }
    body
}

use crate::keys::fingerprint;

pub(crate) use crate::keys::write_private;

fn validity_label(validity: Option<Validity>, now: u64) -> String {
    match validity {
        None => "-".to_owned(),
        Some(window) if now >= window.not_after => "EXPIRED".to_owned(),
        Some(window) if now < window.not_before => "NOT YET".to_owned(),
        Some(window) => format!("{}d", (window.not_after - now).div_ceil(86_400)),
    }
}

fn elide(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_address_becomes_a_host_prefix() {
        assert_eq!(
            parse_host_prefix("10.7.0.3").unwrap().to_string(),
            "10.7.0.3/32"
        );
        assert_eq!(
            parse_host_prefix("fd00:7::3").unwrap().to_string(),
            "fd00:7::3/128"
        );
        assert_eq!(
            parse_host_prefix("10.7.0.0/24").unwrap().to_string(),
            "10.7.0.0/24"
        );
        assert!(parse_host_prefix("nope").is_err());
    }

    #[test]
    fn a_long_peer_name_is_shortened_and_reported() {
        // IFNAMSIZ is 16 including the terminator, so 15 bytes is the ceiling.
        // A name that fits is used whole, and nothing is reported.
        assert_eq!(
            client_interface_name("laptop"),
            ("vallum-laptop".to_owned(), false)
        );
        // One that does not is shortened — and says so, because the shortened
        // name is not unique: these two are the same interface.
        let (a, cut_a) = client_interface_name("vpsclient-a");
        let (b, cut_b) = client_interface_name("vpsclient-b");
        assert_eq!(a, "vallum-vpsclien");
        assert_eq!(a, b);
        assert!(cut_a && cut_b, "both were shortened and must be reported");
        assert!(a.len() <= 15);
    }

    /// A tunnel that carries IPv6 claims the v6 default route — and only that,
    /// for the same reason in reverse: a v6 tunnel that claims `0.0.0.0/0`
    /// would send v4 traffic somewhere it cannot go.
    #[test]
    fn a_v6_tunnel_claims_the_v6_default_route() {
        let text = client_config(
            "laptop",
            "fd00:8::2/128",
            "vallum1:0003:aa:-",
            "vpn.example.com:51820",
            &[],
            None,
        );
        assert!(text.contains("allowed_ips = [\"::/0\"]"));
        assert!(
            !text.contains("0.0.0.0/0"),
            "a v6-only tunnel must not claim the v4 default route"
        );
    }

    #[test]
    fn the_client_config_names_the_server_and_routes_everything() {
        let text = client_config(
            "laptop",
            "10.7.0.3/32",
            "vallum1:0003:aa:-",
            "vpn.example.com:51820",
            &["1.1.1.1".to_owned()],
            Some("0011"),
        );
        assert!(text.contains("private_key = \"laptop.key\""));
        assert!(text.contains("public_key = \"vallum1:0003:aa:-\""));
        assert!(text.contains("endpoint = \"vpn.example.com:51820\""));
        assert!(text.contains("allowed_ips = [\"0.0.0.0/0\"]"));
        // A v4 tunnel must not claim the v6 default route. Claiming it does not
        // create a v6 route; it makes v6 traffic fall through to the real
        // default route and escape outside the tunnel.
        assert!(
            !text.contains("::/0"),
            "a v4-only tunnel must not claim ::/0"
        );
        assert!(text.contains("preshared_key = \"0011\""));
        // A full tunnel needs a socket mark, or `vallum-quick` refuses to
        // install the default route and the daemon's own packets would be
        // routed into the tunnel it is trying to establish.
        assert!(
            text.contains("fwmark = 51820"),
            "a full-tunnel client config must carry a fwmark"
        );
        // It must parse as a config the daemon accepts.
        let parsed: vallum_config::Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.interface.private_key, PathBuf::from("laptop.key"));
    }

    #[test]
    fn an_overlap_with_an_existing_peer_is_refused() {
        let dir = std::env::temp_dir().join(format!("vallum-peer-overlap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vallum0.toml");
        std::fs::write(
            &path,
            "[interface]\nname = \"vallum0\"\nprivate_key = \"server.key\"\n\
             address = \"10.7.0.1/24\"\n\n[[peer]]\nname = \"phone\"\n\
             public_key = \"vallum1:0003:aa:-\"\nallowed_ips = [\"10.7.0.2/32\"]\n",
        )
        .unwrap();
        let file = ConfigFile::load(&path).unwrap();
        let error = ensure_no_overlap(&file, "laptop", &["10.7.0.2/32".to_owned()]).unwrap_err();
        assert!(error.to_string().contains("overlaps"));
        ensure_no_overlap(&file, "laptop", &["10.7.0.3/32".to_owned()]).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fingerprint_is_short_and_stable() {
        let one = fingerprint("vallum1:0003:aa:-");
        assert_eq!(one, fingerprint("vallum1:0003:aa:-"));
        assert_eq!(one.len(), 12);
        assert_ne!(one, fingerprint("vallum1:0003:bb:-"));
    }
}
