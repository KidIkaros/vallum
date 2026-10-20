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
use crate::commands::control::syncconf_running;
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
    #[arg(long, value_name = "FILE", conflicts_with_all = ["public_key", "public_key_file"])]
    pub bundle_out: Option<PathBuf>,

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
    #[arg(long, value_name = "FILE", conflicts_with_all = ["public_key", "public_key_file", "identity"])]
    pub bundle_out: Option<PathBuf>,

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

fn add(args: &AddArgs) -> Result<(), Error> {
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

    let applied = if args.no_apply {
        false
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
            applied,
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
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
    say!(
        "   applied    {}",
        if applied {
            "yes"
        } else {
            "no — the daemon is not running; start it to apply"
        }
    );
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

    let applied = if args.no_apply {
        false
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
            applied,
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
    say!(
        "   applied    {}",
        if applied {
            "yes"
        } else {
            "no — the daemon is not running; start it to apply"
        }
    );
    Ok(())
}

fn finalize(args: &FinalizeArgs) -> Result<(), Error> {
    require_config(&args.config)?;
    let mut file = ConfigFile::load(&args.config)?;
    let retired = file.finalize_peer(&args.name)?;
    file.validate()?;
    let backup = file.save()?;
    let applied = if args.no_apply {
        false
    } else {
        syncconf_running(&args.config)?
    };

    if args.json {
        let report = Finalized {
            name: args.name.clone(),
            retired,
            config: args.config.clone(),
            backup,
            applied,
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
    say!(
        "   applied    {}",
        if applied {
            "yes"
        } else {
            "no — the daemon is not running; start it to apply"
        }
    );
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
    let mut file = ConfigFile::load(&args.config)?;
    let removed = file.remove_peer(&args.name)?;
    file.validate()?;
    let backup = file.save()?;
    let applied = if args.no_apply {
        false
    } else {
        syncconf_running(&args.config)?
    };
    if args.json {
        let report = Removed {
            name: removed.name,
            allowed_ips: removed.allowed_ips,
            config: args.config.clone(),
            backup,
            applied,
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
    say!(
        "   applied  {}",
        if applied {
            "yes"
        } else {
            "no — the daemon is not running; start it to apply"
        }
    );
    say!("   client key files are left in place; delete them by hand if the device is gone");
    Ok(())
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
    body.push_str("name = \"vallum0\"\n");
    body.push_str(&format!("private_key = \"{name}.key\"\n"));
    body.push_str(&format!("addresses = [\"{address}\"]\n"));
    body.push_str("listen = \"0.0.0.0:0\"\n");
    body.push_str("control = \"/run/vallum/vallum0.sock\"\n");
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
    body.push_str("allowed_ips = [\"0.0.0.0/0\", \"::/0\"]\n");
    body.push_str("persistent_keepalive = 25\n");
    if let Some(psk) = psk {
        body.push_str(&format!("preshared_key = \"{psk}\"\n"));
    }
    body
}

fn fingerprint(public_line: &str) -> String {
    let suite = SdkSuite::tri_hybrid();
    let hash = suite.hash(b"vallum/peer/fingerprint/v1", public_line.as_bytes());
    keys::hex_encode(&hash[..6])
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = options.open(path).map_err(|source| Error::IoPath {
        action: "write",
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| Error::IoPath {
        action: "write",
        path: path.to_path_buf(),
        source,
    })
}

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
        assert!(text.contains("allowed_ips = [\"0.0.0.0/0\", \"::/0\"]"));
        assert!(text.contains("preshared_key = \"0011\""));
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
