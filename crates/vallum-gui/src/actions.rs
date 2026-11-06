// SPDX-License-Identifier: Apache-2.0

//! Phase 2: the writes.
//!
//! Every mutation leaves as a transaction rendered by
//! [`vallum::uapi::render_set`] and read by the daemon's own parser, so the
//! console sends the bytes the TUI sends. Field parsing is
//! [`vallum::form`]'s, shared with the TUI, for the same reason.
//!
//! Two kinds of write exist here, and they are not interchangeable:
//!
//! * Runtime state — add, edit, remove, listen port and fwmark — is a `set=1`
//!   transaction against the running daemon, which is exactly what the TUI's
//!   `apply` does.
//! * Identity rotation and finalise are *config* edits followed by `syncconf`,
//!   because a rotation applied only to the running daemon is undone by the
//!   next `syncconf` or restart. Losing a rotation quietly is worse than
//!   refusing it, so these write the file the daemon will start from, then ask
//!   it to adopt the change.
//!
//! Neither path makes a privileged decision for the operator: when the config
//! or the invite directory is not writable, the error names the command that
//! does the same thing.

use std::path::Path;

use serde::Deserialize;
use vallum::config::Config;
use vallum::config_edit::{ConfigFile, IdentityFields};
use vallum::enroll;
use vallum::form;
use vallum::keys;
use vallum::uapi::{self, Peer, Set};

use crate::snapshot;

/// The fields of the invite form, as typed.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct InviteFields {
    pub name: String,
    pub ttl_minutes: String,
    pub pinned: String,
}

/// The fields of the peer form, as typed.
///
/// `#[serde(default)]` throughout: an edit form sends the fields it has and
/// leaves the rest blank, which the parsers read as "not set".
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PeerFields {
    pub public_line: String,
    pub name: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub keepalive: String,
    pub preshared_key: String,
}

/// What a write answers on success.
#[derive(Debug, serde::Serialize)]
pub struct Done {
    pub message: String,
    /// A command to run when the console could not finish the work itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

impl Done {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            command: None,
        }
    }
}

/// Add a peer to the running device.
///
/// # Errors
///
/// A form error naming the field, a suite mismatch, or the daemon's refusal.
pub fn add(path: &Path, fields: &PeerFields) -> Result<Done, String> {
    let device = snapshot::fetch(path)?;
    let peer = build(fields, device.suite_id(), false)?;
    submit(
        path,
        &Set {
            peers: vec![peer],
            ..Set::default()
        },
    )?;
    Ok(Done::message(format!("added {}", label(fields))))
}

/// Update a peer that already exists.
///
/// # Errors
///
/// As [`add`], plus the daemon's `ENOENT` when the peer has gone.
pub fn edit(path: &Path, fields: &PeerFields) -> Result<Done, String> {
    let device = snapshot::fetch(path)?;
    let peer = build(fields, device.suite_id(), true)?;
    submit(
        path,
        &Set {
            peers: vec![peer],
            ..Set::default()
        },
    )?;
    Ok(Done::message(format!("updated {}", label(fields))))
}

/// Remove a peer, addressed by its public line.
///
/// Nothing else identifies a peer in the runtime table, and using the key rather
/// than a row number means a snapshot that moved under the pointer cannot delete
/// the wrong peer.
///
/// # Errors
///
/// If the public line cannot be decoded or the daemon refuses.
pub fn remove(path: &Path, public_line: &str) -> Result<Done, String> {
    let (_, identity) = keys::decode_public(public_line).map_err(|error| error.to_string())?;
    let peer = Peer {
        public_key: Some(identity.kem().as_bytes().to_vec()),
        remove: true,
        ..Peer::default()
    };
    submit(
        path,
        &Set {
            peers: vec![peer],
            ..Set::default()
        },
    )?;
    Ok(Done::message("peer removed"))
}

/// Set the runtime listen port and fwmark.
///
/// Empty fields are left alone rather than defaulted: a form saved with the
/// fwmark box clear must not reset the mark to zero.
///
/// # Errors
///
/// A parse error or the daemon's refusal.
pub fn apply_device(path: &Path, listen_port: &str, fwmark: &str) -> Result<Done, String> {
    let listen_port = match listen_port.trim() {
        "" => None,
        text => Some(
            text.parse::<u16>()
                .map_err(|_| "listen port is not a number".to_owned())?,
        ),
    };
    let fwmark = match fwmark.trim() {
        "" => None,
        text => Some(
            text.parse::<u32>()
                .map_err(|_| "fwmark is not a number".to_owned())?,
        ),
    };
    if listen_port.is_none() && fwmark.is_none() {
        return Err("nothing to apply".to_owned());
    }
    submit(
        path,
        &Set {
            listen_port,
            fwmark,
            ..Set::default()
        },
    )?;
    Ok(Done::message("runtime device updated"))
}

/// Rotate a peer's identity: the new key takes over, the old one stays accepted.
///
/// # Errors
///
/// A suite mismatch, an unreadable or unwritable config (with the command that
/// does the same thing), or a validation failure.
pub fn rotate(
    config: &Path,
    name: &str,
    new_line: &str,
    device_suite: Option<u16>,
) -> Result<Done, String> {
    let (suite, identity) = keys::decode_public(new_line).map_err(|error| error.to_string())?;
    if let Some(device) = device_suite {
        if suite != device {
            return Err(format!(
                "suite 0x{suite:04x} does not match device 0x{device:04x}"
            ));
        }
    }
    let canonical = keys::encode_public(suite, &identity);
    let mut file = ConfigFile::load(config).map_err(|error| privileged(config, "rotate", error))?;
    file.rotate_peer(
        name,
        &IdentityFields {
            public_key: Some(canonical),
            identity: None,
            identity_file: None,
        },
    )
    .map_err(|error| error.to_string())?;
    file.validate().map_err(|error| error.to_string())?;
    file.save()
        .map_err(|error| privileged(config, "rotate", error))?;
    let _ = vallum::commands::control::syncconf_running(config);
    Ok(Done::message(format!(
        "rotated `{name}` — the old key is accepted until you finalise"
    )))
}

/// Retire a rotated peer's previous identity.
///
/// # Errors
///
/// An unreadable or unwritable config (with the command that does the same
/// thing), or a validation failure.
pub fn finalize(config: &Path, name: &str) -> Result<Done, String> {
    let mut file =
        ConfigFile::load(config).map_err(|error| privileged(config, "finalize", error))?;
    file.finalize_peer(name)
        .map_err(|error| error.to_string())?;
    file.validate().map_err(|error| error.to_string())?;
    file.save()
        .map_err(|error| privileged(config, "finalize", error))?;
    let _ = vallum::commands::control::syncconf_running(config);
    Ok(Done::message(format!(
        "finalised `{name}` — previous key retired"
    )))
}

/// Mint a one-time invite and hand back the command the new peer runs.
///
/// # Errors
///
/// A bad name or TTL, a pinned line that does not decode, or a runtime
/// directory the console cannot write (with the command that does the same
/// thing).
pub fn invite(
    interface: &str,
    config: Option<&Path>,
    listen: Option<&str>,
    public_line: &str,
    fields: &InviteFields,
) -> Result<Done, String> {
    let name = fields.name.trim();
    if name.is_empty() {
        return Err("peer name is required".to_owned());
    }
    let minutes: u64 = fields
        .ttl_minutes
        .trim()
        .parse()
        .map_err(|_| "TTL must be a positive number of minutes".to_owned())?;
    if minutes == 0 {
        return Err("TTL must be at least 1 minute".to_owned());
    }
    let pinned = match fields.pinned.trim() {
        "" => None,
        text => {
            keys::decode_public(text).map_err(|error| format!("pinned public line: {error}"))?;
            Some(text.to_owned())
        }
    };
    let (token, id, path) =
        enroll::issue_invite(interface, name, minutes * 60, pinned).map_err(invite_privileged)?;
    let loaded = config.and_then(|path| Config::load(path).ok());
    let target = enroll::join_target(loaded.as_ref(), listen);
    let ticket = enroll::JoinTicket {
        server: target,
        name: name.to_owned(),
        invite_id: id,
        token,
        fingerprint: keys::fingerprint(public_line),
    }
    .encode();
    Ok(Done {
        message: format!("invite minted for `{name}` — {}", path.display()),
        command: Some(format!("sudo vallum join {ticket}")),
    })
}

/// The config file that owns a control socket, if this process can read it.
///
/// Discovery mirrors the TUI: every `*.toml` in the config directory, resolved
/// the way the daemon resolves a relative `control` path. A file this process
/// cannot read is simply not a candidate — the caller then offers the command
/// instead of pretending the config is absent by choice.
#[must_use]
pub fn config_for(socket: &Path, config_dir: &Path) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(config_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
            continue;
        }
        let Ok(config) = Config::load(&path) else {
            continue;
        };
        let Some(declared) = config.interface.control.as_ref() else {
            continue;
        };
        let candidate = vallum::config::resolve_key_path(&path, declared);
        if candidate == socket {
            return Some(path);
        }
    }
    None
}

fn build(fields: &PeerFields, suite: u16, update_only: bool) -> Result<Peer, String> {
    let (peer_suite, identity) =
        keys::decode_public(&fields.public_line).map_err(|error| error.to_string())?;
    if peer_suite != suite {
        return Err(format!(
            "peer suite 0x{peer_suite:04x} does not match device 0x{suite:04x}"
        ));
    }
    let allowed_ips = form::parse_prefixes(&fields.allowed_ips)
        .map_err(|error| format!("allowed IPs: {error}"))?;
    if allowed_ips.is_empty() {
        return Err("allowed IPs is empty".to_owned());
    }
    let endpoint = form::parse_endpoint(&fields.endpoint)?;
    let keepalive = form::parse_keepalive(&fields.keepalive)?;
    let preshared_key = form::parse_psk(&fields.preshared_key)?;
    let name = fields.name.trim();
    Ok(Peer {
        public_key: Some(identity.kem().as_bytes().to_vec()),
        name: (!name.is_empty()).then(|| name.to_owned()),
        preshared_key: preshared_key.map(Some),
        endpoint: endpoint.map(Some),
        keepalive,
        allowed_ips,
        remove: false,
        update_only,
        replace_allowed_ips: true,
        previous_public_key: None,
    })
}

fn submit(path: &Path, set: &Set) -> Result<(), String> {
    let body = uapi::render_set(set);
    let reply = vallum::control::request(path, &body).map_err(|error| error.to_string())?;
    let errno = reply
        .lines()
        .find_map(|line| line.strip_prefix("errno="))
        .and_then(|value| value.trim().parse::<i32>().ok())
        .ok_or_else(|| format!("the daemon's reply carried no errno: {}", reply.trim()))?;
    if errno == 0 {
        Ok(())
    } else {
        Err(describe(errno))
    }
}

/// Say what the daemon refused, rather than a bare number.
fn describe(errno: i32) -> String {
    let reason = match errno {
        1 => "the daemon refused: not permitted",
        2 => "no such peer",
        7 => "the request is larger than the control socket accepts",
        22 => "the daemon rejected one of the values",
        95 => "the running daemon does not support that",
        _ => "the daemon returned an error",
    };
    format!("{reason} (errno {errno})")
}

fn label(fields: &PeerFields) -> String {
    let name = fields.name.trim();
    if name.is_empty() {
        format!("`{}`", keys::fingerprint(&fields.public_line))
    } else {
        format!("`{name}`")
    }
}

/// The config could not be read or written: say which file, and how to finish
/// the same change as root. Naming the verb but not inventing its flags: the
/// man page owns those, and a wrong command in an error message is worse than a
/// short one.
fn privileged(config: &Path, verb: &str, error: impl std::fmt::Display) -> String {
    format!(
        "{error}\n\nThe config is {}, which this console could not change. Run the console as root, or run `sudo vallum peer {verb} --help` for the same change from a terminal.",
        config.display()
    )
}

fn invite_privileged(error: impl std::fmt::Display) -> String {
    format!(
        "{error}\n\nThe invite file lives in the daemon's runtime directory, which this console cannot write. Run the console as root, or run `sudo vallum peer invite --help` for the same change from a terminal."
    )
}
