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

use crate::hostfacts::write_gate;
use crate::snapshot;

/// The fields of the invite form, as typed.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct InviteFields {
    pub name: String,
    pub ttl_minutes: String,
    pub pinned: String,
    pub ssh_target: String,
}

/// The fields of the client network join form (ticket or SSH enrolment).
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
#[serde(default)]
pub struct JoinFields {
    pub mode: String,
    pub ticket: String,
    pub ssh_target: String,
    pub name: String,
}

/// The fields of the server initialization wizard.
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ServerSetupFields {
    pub address: String,
    pub listen: String,
    pub public_endpoint: String,
}

/// The fields of the interface config form, as typed.
///
/// Mirrors the TUI's `FormKind::Interface`: `[interface]` (`listen`, `carrier`,
/// `mtu`, `fwmark`, `addresses`) and `[quick]` (`dns`, `table`, `policy`,
/// `content_blockers`).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct InterfaceFields {
    pub listen: String,
    pub carrier: String,
    pub tcp_upgrade: String,
    pub ss_psk: String,
    pub tls_sni: String,
    pub mtu: String,
    pub fwmark: String,
    pub addresses: String,
    pub dns: String,
    pub table: String,
    pub policy: String,
    pub content_blockers: String,
    pub via: String,
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

/// Validate a peer name before sending it to the daemon or minting an invite.
///
/// Linux network interface names (`vallum-<name>`) cap at 15 characters and
/// enrollment configs only permit `[A-Za-z0-9._-]` starting with an alphanumeric
/// character, so rejecting spaces, slashes, leading dots/hyphens, and
/// over-long names here catches bugs identically across Tauri and HTTP.
pub(crate) fn validate_peer_name(raw: &str) -> Result<&str, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("peer name is required".to_owned());
    }
    if name.len() > 15 {
        return Err(format!(
            "peer name must be 15 characters or fewer (got {}) — Linux interface names cap at 15 chars",
            name.len()
        ));
    }
    let mut chars = name.chars();
    let valid_first = chars.next().is_some_and(|ch| ch.is_ascii_alphanumeric());
    let valid_rest = chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'));
    if !valid_first || !valid_rest {
        return Err(
            "peer name may only contain letters, digits, '.', '_', or '-', and must start with a letter or digit"
                .to_owned(),
        );
    }
    Ok(name)
}

/// Validate an SSH destination (`user@host`, hostname, or `~/.ssh/config` alias)
/// so it cannot inject flags (`-oProxyCommand=...`) into `ssh`.
pub(crate) fn validate_ssh_target(raw: &str) -> Result<&str, String> {
    let target = raw.trim();
    if target.is_empty() {
        return Err(
            "SSH host is required (e.g. user@vpn.example.com or an ~/.ssh/config alias)".to_owned(),
        );
    }
    if target.starts_with('-') {
        return Err("SSH host must not start with `-`".to_owned());
    }
    if !target
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '@' | ':'))
    {
        return Err(
            "SSH host may only contain letters, digits, '.', '_', '-', '@', or ':'".to_owned(),
        );
    }
    Ok(target)
}

/// Extract and validate a `vallum1-join:...` ticket from raw user input
/// (tolerating a pasted `sudo vallum join vallum1-join:...` command).
pub(crate) fn extract_join_ticket(raw: &str) -> Result<&str, String> {
    let ticket = raw
        .split_whitespace()
        .find(|token| token.starts_with("vallum1-join:"))
        .unwrap_or_else(|| raw.trim());
    if ticket.is_empty() {
        return Err("paste a `vallum1-join:...` invite ticket".to_owned());
    }
    if !ticket.starts_with("vallum1-join:") {
        return Err("ticket must start with `vallum1-join:`".to_owned());
    }
    if ticket
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err("ticket must not contain spaces or control characters".to_owned());
    }
    let body = &ticket["vallum1-join:".len()..];
    if body.split('/').count() < 5 {
        return Err(
            "incomplete invite ticket — expected `vallum1-join:<host>:<port>/<name>/<id>/<token>/<fp>`"
                .to_owned(),
        );
    }
    Ok(ticket)
}

/// Validate `ServerSetupFields` before invoking `vallum setup --server`.
pub(crate) fn validate_server_setup_fields(fields: &ServerSetupFields) -> Result<(), String> {
    let addr = fields.address.trim();
    if addr.is_empty() {
        return Err("server tunnel CIDR is required (e.g. 10.7.0.1/20)".to_owned());
    }
    for part in addr.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if !part.contains('/') {
            return Err(format!(
                "address `{part}` must include a prefix length (e.g. 10.7.0.1/20)"
            ));
        }
        form::parse_prefixes(part).map_err(|error| format!("address: {error}"))?;
    }
    let listen = fields.listen.trim();
    if !listen.is_empty() {
        listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "listen address must be IP:port (e.g. 0.0.0.0:51820)".to_owned())?;
    }
    let endpoint = fields.public_endpoint.trim();
    if !endpoint.is_empty() {
        let Some((host, port_str)) = endpoint.rsplit_once(':') else {
            return Err("public endpoint must be host:port (e.g. 203.0.113.5:51820)".to_owned());
        };
        if host.trim().is_empty() || port_str.parse::<u16>().is_err() {
            return Err("public endpoint must be host:port (e.g. 203.0.113.5:51820)".to_owned());
        }
    }
    Ok(())
}

/// Mint an invite on a remote server over SSH (`sudo -n /usr/bin/vallum peer invite <name>`)
/// so an operator running the console on a client laptop can onboard colleagues
/// without opening a terminal.
pub fn invite_remote(fields: &InviteFields) -> Result<Done, String> {
    let target = validate_ssh_target(&fields.ssh_target)?;
    let name = validate_peer_name(&fields.name)?;
    const DEFAULT_TTL_MINUTES: u64 = 60;
    let minutes: u64 = if fields.ttl_minutes.trim().is_empty() {
        DEFAULT_TTL_MINUTES
    } else {
        fields
            .ttl_minutes
            .trim()
            .parse()
            .map_err(|_| "TTL must be a whole number of minutes".to_owned())?
    };
    if !(1..=10_080).contains(&minutes) {
        return Err("TTL must be between 1 and 10080 minutes (7 days)".to_owned());
    }
    let pinned = match fields.pinned.trim() {
        "" => None,
        text => {
            keys::decode_public(text).map_err(|error| format!("pinned public line: {error}"))?;
            Some(text.to_owned())
        }
    };
    let mut remote_cmd = format!("sudo -n /usr/bin/vallum peer invite '{name}' --ttl {minutes}");
    if let Some(pin) = &pinned {
        if !pin
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '+' | '/' | '='))
        {
            return Err("invalid characters in pinned public key".to_owned());
        }
        remote_cmd.push_str(&format!(" --public-key '{pin}'"));
    }
    let output = std::process::Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            target,
            &remote_cmd,
        ])
        .output()
        .map_err(|error| format!("cannot run ssh to {target}: {error}"))?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!(
            "remote invite on `{target}` failed: {}",
            combined.trim()
        ));
    }
    let ticket = combined
        .split_whitespace()
        .find(|token| token.starts_with("vallum1-join:") && token.len() > 40)
        .ok_or_else(|| {
            format!(
                "remote server `{target}` did not return a `vallum1-join:` ticket: {}",
                combined.trim()
            )
        })?;
    Ok(Done {
        message: format!(
            "invite minted for `{name}` on `{target}` (UDP 51821 responder started on server)"
        ),
        command: Some(format!("sudo vallum join {ticket}")),
    })
}

/// Add a peer to the running device.
///
/// # Errors
///
/// A form error naming the field, a suite mismatch, or the daemon's refusal.
pub fn add(path: &Path, fields: &PeerFields) -> Result<Done, String> {
    // Both transports pass here; the gate lives with the write, not the route.
    write_gate(path)?;
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
    // Both transports pass here; the gate lives with the write, not the route.
    write_gate(path)?;
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
    // Both transports pass here; the gate lives with the write, not the route.
    write_gate(path)?;
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
    // Both transports pass here; the gate lives with the write, not the route.
    write_gate(path)?;
    let listen_port = match listen_port.trim() {
        "" => None,
        text => Some(
            text.parse::<u16>()
                .map_err(|_| "listen port is not a number".to_owned())?,
        ),
    };
    let fwmark = match fwmark.trim() {
        "" => None,
        text if text.eq_ignore_ascii_case("off") => Some(0),
        text => {
            let parsed =
                if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    u32::from_str_radix(hex, 16)
                } else {
                    text.parse::<u32>()
                };
            Some(
                parsed.map_err(|_| {
                    "fwmark must be 'off', decimal, or hex (e.g. 0xca6c)".to_owned()
                })?,
            )
        }
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
    let name = validate_peer_name(&fields.name)?;
    // A blank TTL is the common case — the operator wants "an invite, now".
    // The field says blank means the default, so blank must mean the default.
    const DEFAULT_TTL_MINUTES: u64 = 60;
    let minutes: u64 = if fields.ttl_minutes.trim().is_empty() {
        DEFAULT_TTL_MINUTES
    } else {
        fields
            .ttl_minutes
            .trim()
            .parse()
            .map_err(|_| "TTL must be a whole number of minutes".to_owned())?
    };
    if !(1..=10_080).contains(&minutes) {
        return Err("TTL must be between 1 and 10080 minutes (7 days)".to_owned());
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
    // A ticket that says `<server>` cannot be redeemed. Refusing here costs one
    // click; handing it over costs a support conversation on the other device.
    if target.starts_with("<server>") {
        return Err(
            "this config has no `[interface] public_endpoint`, so the ticket would \
             say `<server>`. Set it to the address peers dial (host:port) and mint again."
                .to_owned(),
        );
    }
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
    let wanted = socket.file_stem().and_then(|stem| stem.to_str());
    let mut by_name: Option<std::path::PathBuf> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
            continue;
        }
        let Ok(config) = Config::load(&path) else {
            continue;
        };
        // Exact match first: the config names the socket this console is using.
        if let Some(declared) = config.interface.control.as_ref() {
            if vallum::config::resolve_key_path(&path, declared) == socket {
                return Some(path);
            }
        }
        // Then by interface name: a lab or a container sees the socket through a
        // different path than the config declares, and refusing to find the
        // config over that difference helps nobody.
        if by_name.is_none() && config.interface.name.as_deref() == wanted {
            by_name = Some(path);
        }
    }
    by_name
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
    let name = if fields.name.trim().is_empty() {
        None
    } else {
        Some(validate_peer_name(&fields.name)?.to_owned())
    };
    Ok(Peer {
        public_key: Some(identity.kem().as_bytes().to_vec()),
        name,
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
        17 => "a peer with that public key already exists",
        22 => "the daemon rejected a value — a duplicate public key, or an allowed IP that overlaps the interface",
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

/// What an export answers: the bundle as JSON text plus the file name the
/// front-end saves it under. The key is minted in memory and never written to
/// disk — the downloaded bundle file is its only copy, and the dialog says so.
#[derive(Debug, serde::Serialize)]
pub struct BundleOut {
    pub filename: String,
    pub json: String,
    pub message: String,
}

/// A minted key: text plus a suggested file name. In-memory only — the TUI
/// writes its key next to the config directory, the GUI hands the text to the
/// browser as a download. Same `new_secret` both sides, so the files match.
#[derive(Debug, serde::Serialize)]
pub struct KeyOut {
    pub filename: String,
    pub text: String,
    pub message: String,
}

/// Mint a fresh identity in the device's suite. Read-only against the daemon
/// plus local randomness: no write gate, no privilege question. With no daemon
/// to ask (a fresh client before first join), the key is minted in the shipping
/// suite `0x0003` — the only suite `vallum join` negotiates today.
///
/// # Errors
///
/// If the daemon cannot be read for its suite.
pub fn generate_key(path: Option<&Path>) -> Result<KeyOut, String> {
    let (suite_id, suite, interface) = match path {
        Some(path) => {
            let snap = snapshot::fetch(path)?;
            (snap.suite_id(), snap.suite.clone(), snap.interface.clone())
        }
        None => (
            0x0003,
            "x25519+sntrup761+ml-kem-768".to_owned(),
            "vallum0".to_owned(),
        ),
    };
    let secret = vallum::keys::new_secret(suite_id, false, vallum::entropy::seed());
    Ok(KeyOut {
        filename: format!("{interface}-client.key"),
        text: vallum::keys::render_secret(&secret),
        message: format!(
            "fresh {suite} key minted — it exists only in this download until it is added to a peer"
        ),
    })
}

/// Read the on-disk config behind a socket for the editor. Reading another
/// user's file fails honestly; the dialog then says so instead of showing a
/// blank form that would clobber on save.
///
/// # Errors
///
/// No readable config names this socket, or it cannot be read.
pub fn read_config(config: &Path) -> Result<String, String> {
    std::fs::read_to_string(config).map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "permission denied reading {} (mode 0600 root) — edit from a root shell or run: sudo vallum tui",
                config.display()
            )
        } else {
            format!("read {}: {error}", config.display())
        }
    })
}

/// Write edited config text back, validated before it lands. The current file
/// is backed up first; text that does not parse restores the backup instead
/// of stranding the daemon on an invalid config — the one deliberate
/// difference from the TUI's `$EDITOR` flow, where the editor is still open
/// to fix the mistake and the backup path is reported.
///
/// # Errors
///
/// Unparseable text (backup restored), or an unwritable file with the
/// command that finishes the same edit as root.
pub fn write_config(config: &Path, text: &str) -> Result<Done, String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let backup = config.with_extension(format!("toml.bak.{stamp}"));
    std::fs::copy(config, &backup).map_err(|error| privileged(config, "edit", error))?;
    std::fs::write(config, text).map_err(|error| privileged(config, "edit", error))?;
    if let Err(error) = vallum_config::Config::load(config) {
        let _ = std::fs::copy(&backup, config);
        return Err(format!(
            "not saved: the edited config does not parse ({error}); previous file restored"
        ));
    }
    Ok(Done::message(format!(
        "config saved; backup {}",
        backup.display()
    )))
}

/// Mint a client bundle for the peer with this fingerprint: its allowed
/// address becomes the client's address, the server's public line becomes the
/// client's `server` peer, and a fresh key is minted in memory.
///
/// Read-only against the daemon plus local randomness: no write gate, no
/// privilege question. The endpoint is the address the client dials, so a
/// bundle that says `<server>` is refused the way a ticket is.
///
/// # Errors
///
/// No such peer, no allowed address on it, or a bad endpoint.
pub fn export_bundle(path: &Path, fingerprint: &str, endpoint: &str) -> Result<BundleOut, String> {
    let snap = snapshot::fetch(path)?;
    let peer = snap
        .peers
        .iter()
        .find(|peer| peer.fingerprint == fingerprint)
        .ok_or_else(|| {
            "select a peer first — the export carries that peer's allowed address".to_owned()
        })?;
    let address = peer.allowed_ips.first().ok_or_else(|| {
        format!(
            "`{}` has no allowed address to use as the client address",
            peer.name
        )
    })?;
    let secret = vallum::keys::new_secret(snap.suite_id(), false, vallum::entropy::seed());
    let key_name = format!("{}-client.key", snap.interface);
    let bundle = vallum::bundle::build(
        &snap.public_line,
        &snap.interface,
        address,
        &vallum::keys::render_secret(&secret),
        &key_name,
        endpoint,
    )?;
    let json = serde_json::to_string_pretty(&bundle).map_err(|error| error.to_string())?;
    Ok(BundleOut {
        filename: format!("{}.vallum-bundle", bundle.name),
        json,
        message: format!(
            "bundle minted for `{}` — the key exists only in this file; whoever holds it joins as this peer",
            peer.name
        ),
    })
}

/// One frame of an animated QR: its position in the set, the set's integrity
/// prefix, and the module grid the front-end draws — dark flags in row-major
/// order, no quiet zone (the canvas adds the plate, the way the TUI's
/// two-module plate does). The text is whatever the caller already has: an
/// exported bundle's JSON, or an invite's `vallum join` command. This never
/// mints, so the code carries exactly what the other view showed.
#[derive(Debug, serde::Serialize)]
pub struct QrFrame {
    pub index: usize,
    pub total: usize,
    pub hash: String,
    pub size: u32,
    pub modules: Vec<u8>,
}

/// Render frame `index` of the `VALLUM1` animation for `text`.
/// Read-only against the daemon plus the encoder: no gate, no privilege
/// question — but a bundle frame carries the private key and an invite frame
/// carries the one-time token, so the dialog clears it on close and never
/// logs it.
///
/// # Errors
///
/// Text that will not fit the bounded frame set, or an index past the last
/// frame.
pub fn qr_frame(text: &str, index: usize) -> Result<QrFrame, String> {
    let frames = vallum::qr_frames::encode(text)?;
    let total = frames.frames.len();
    let frame = frames.frames.get(index).ok_or_else(|| {
        format!("frame {index} is past the last of {total} — restart the animation")
    })?;
    let grid = vallum::qr_frames::grid(frame)?;
    Ok(QrFrame {
        index,
        total,
        hash: frames.hash,
        size: grid.size,
        modules: grid.modules,
    })
}

/// Import a `.vallum-bundle` file into a directory.
///
/// The directory default is the caller's decision (the selected interface's
/// config directory, else the daemon's). When the write fails the error names
/// the CLI that does the same thing, the way config writes do.
///
/// # Errors
///
/// An unreadable or invalid bundle, or a directory this console cannot write.
pub fn import_bundle(bundle_path: &str, out_dir: &str) -> Result<Done, String> {
    let bundle =
        vallum::bundle::read(Path::new(bundle_path.trim())).map_err(|error| error.to_string())?;
    // The operator explicitly invoked bundle import from the GUI (the one flow
    // where a `.vallum-bundle` carries a shipped client key); keep hooks refused.
    match vallum::bundle::import_with_policy(&bundle, Path::new(out_dir), false, false, false, true)
    {
        Ok(imported) => Ok(Done::message(format!(
            "imported `{}`: config {} (key {}) — note: this key travelled in the bundle",
            bundle.name,
            imported.config.display(),
            imported.key.display()
        ))),
        Err(error) => Err(format!(
            "{error}\n\nThis console could not write there. Run `sudo vallum import-bundle --allow-shipped-key \"{bundle_path}\"` from a terminal for the same import."
        )),
    }
}

fn invite_privileged(error: impl std::fmt::Display) -> String {
    format!(
        "{error}\n\nThe invite file lives in the daemon's runtime directory, which this console cannot write. Run the console as root, or run `sudo vallum peer invite --help` for the same change from a terminal."
    )
}

/// Read `[interface]` and `[quick]` fields from an interface config file for
/// the structured interface form (matching TUI `Action::InterfaceForm`).
///
/// # Errors
///
/// If the config cannot be read or does not parse as TOML.
pub fn read_interface_fields(config: &Path) -> Result<InterfaceFields, String> {
    let text = read_config(config)?;
    let doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|error| format!("parse {}: {error}", config.display()))?;
    let table_string = |table_name: &str, key: &str| {
        doc.get(table_name)
            .and_then(|item| item.get(key))
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned()
    };
    let integer = |key: &str| {
        doc.get("interface")
            .and_then(|item| item.get(key))
            .and_then(|item| item.as_integer())
            .map_or_else(String::new, |value| value.to_string())
    };
    let list = |table_name: &str, key: &str| {
        doc.get(table_name)
            .and_then(|item| item.get(key))
            .and_then(|item| item.as_array())
            .map(|array| {
                array
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    };
    Ok(InterfaceFields {
        listen: table_string("interface", "listen"),
        carrier: table_string("interface", "carrier"),
        tcp_upgrade: table_string("interface", "tcp_upgrade"),
        ss_psk: table_string("interface", "ss_psk"),
        tls_sni: table_string("interface", "tls_sni"),
        mtu: integer("mtu"),
        fwmark: integer("fwmark"),
        addresses: list("interface", "addresses"),
        dns: list("quick", "dns"),
        table: table_string("quick", "table"),
        policy: table_string("quick", "policy"),
        content_blockers: list("quick", "content_blockers"),
        via: table_string("quick", "via"),
    })
}

fn validate_interface_fields(fields: &InterfaceFields) -> Result<(), String> {
    let listen = fields.listen.trim();
    if !listen.is_empty() {
        listen.parse::<std::net::SocketAddr>().map_err(|_| {
            "listen must be an IP:port (e.g. 0.0.0.0:51820 or [::]:51820)".to_owned()
        })?;
    }
    let mtu = fields.mtu.trim();
    if !mtu.is_empty() {
        let parsed: u16 = mtu
            .parse()
            .map_err(|_| "mtu must be 576–65535 (or 0 for auto)".to_owned())?;
        if parsed != 0 && parsed < 576 {
            return Err("mtu must be 576–65535 (or 0 for auto)".to_owned());
        }
    }
    let fwmark = fields.fwmark.trim();
    if !fwmark.is_empty() {
        let valid = if let Some(hex) = fwmark
            .strip_prefix("0x")
            .or_else(|| fwmark.strip_prefix("0X"))
        {
            u32::from_str_radix(hex, 16).is_ok()
        } else {
            fwmark.parse::<u32>().is_ok()
        };
        if !valid {
            return Err("fwmark must be a decimal integer or 0x hex".to_owned());
        }
    }
    let addresses = fields.addresses.trim();
    if !addresses.is_empty() {
        for raw in addresses
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !raw.contains('/') {
                return Err(format!(
                    "address `{raw}` must use CIDR notation (e.g. 10.7.0.1/24)"
                ));
            }
            form::parse_prefixes(raw).map_err(|error| format!("addresses: {error}"))?;
        }
    }
    let dns = fields.dns.trim();
    if !dns.is_empty() {
        for raw in dns.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            raw.parse::<std::net::IpAddr>()
                .map_err(|_| format!("DNS entry `{raw}` is not a valid IP address"))?;
        }
    }
    let table = fields.table.trim();
    if !table.is_empty() && !matches!(table, "auto" | "off") && table.parse::<u32>().is_err() {
        return Err("table must be `auto`, `off`, or a routing table number".to_owned());
    }
    let carrier = fields.carrier.trim();
    if !carrier.is_empty()
        && !matches!(
            carrier,
            "udp" | "lwo" | "auto" | "tcp" | "ss" | "tls" | "quic"
        )
    {
        return Err(
            "carrier must be `udp`, `lwo`, `auto`, `tcp`, `ss`, `tls`, or `quic`".to_owned(),
        );
    }
    let tcp_upgrade = fields.tcp_upgrade.trim();
    if !tcp_upgrade.is_empty() {
        vallum_config::validate_tcp_upgrade_host(tcp_upgrade)?;
    }
    let tls_sni = fields.tls_sni.trim();
    if !tls_sni.is_empty() {
        vallum_config::validate_tls_sni(tls_sni)?;
    }
    let policy = fields.policy.trim();
    if !policy.is_empty() && !matches!(policy, "off" | "auto" | "on" | "lockdown") {
        return Err("policy must be `auto`, `on`, `lockdown`, or `off`".to_owned());
    }
    let content_blockers = fields.content_blockers.trim();
    if !content_blockers.is_empty() {
        for raw in content_blockers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if vallum_config::content_blocker_bit(raw).is_none() {
                return Err(format!(
                    "content blocker `{raw}` must be ads, trackers, malware, adult, gambling, or social"
                ));
            }
        }
    }
    Ok(())
}

/// Apply structured `[interface]` and `[quick]` settings to the config file
/// with backup + parser validation (matching TUI `apply_interface_form`).
///
/// # Errors
///
/// Validation error, unreadable/unwritable config, or invalid resulting TOML.
pub fn apply_interface(config: &Path, fields: &InterfaceFields) -> Result<Done, String> {
    validate_interface_fields(fields)?;
    let text = read_config(config)?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|error| format!("parse {}: {error}", config.display()))?;
    if doc.get("interface").is_none() {
        doc["interface"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    let interface = doc["interface"]
        .as_table_mut()
        .ok_or_else(|| "config `[interface]` is not a TOML table".to_owned())?;

    let set_string = |table: &mut toml_edit::Table, key: &str, value: &str| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            table.remove(key);
        } else {
            table[key] = toml_edit::value(trimmed);
        }
    };
    set_string(interface, "listen", &fields.listen);
    set_string(interface, "carrier", &fields.carrier);
    set_string(interface, "tcp_upgrade", &fields.tcp_upgrade);
    set_string(interface, "ss_psk", &fields.ss_psk);
    set_string(interface, "tls_sni", &fields.tls_sni);

    let mtu = fields.mtu.trim();
    if mtu.is_empty() {
        interface.remove("mtu");
    } else {
        let parsed: i64 = mtu.parse().map_err(|_| "mtu is not a number".to_owned())?;
        interface["mtu"] = toml_edit::value(parsed);
    }

    let fwmark = fields.fwmark.trim();
    if fwmark.is_empty() {
        interface.remove("fwmark");
    } else {
        let parsed = if let Some(hex) = fwmark
            .strip_prefix("0x")
            .or_else(|| fwmark.strip_prefix("0X"))
        {
            u32::from_str_radix(hex, 16).map_err(|_| "fwmark is not valid hex".to_owned())?
        } else {
            fwmark
                .parse::<u32>()
                .map_err(|_| "fwmark is not a number".to_owned())?
        };
        interface["fwmark"] = toml_edit::value(i64::from(parsed));
    }

    for (table_name, key, raw) in [
        ("interface", "addresses", fields.addresses.as_str()),
        ("quick", "dns", fields.dns.as_str()),
        (
            "quick",
            "content_blockers",
            fields.content_blockers.as_str(),
        ),
    ] {
        let entries: Vec<&str> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if doc.get(table_name).is_none() {
            if entries.is_empty() {
                continue;
            }
            doc[table_name] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let table = doc[table_name]
            .as_table_mut()
            .ok_or_else(|| format!("config `[{table_name}]` is not a TOML table"))?;
        if entries.is_empty() {
            table.remove(key);
        } else {
            let mut array = toml_edit::Array::new();
            for entry in entries {
                array.push(entry);
            }
            table[key] = toml_edit::Item::Value(toml_edit::Value::Array(array));
        }
    }

    if !fields.table.trim().is_empty()
        || !fields.policy.trim().is_empty()
        || !fields.via.trim().is_empty()
        || doc.get("quick").is_some()
    {
        if doc.get("quick").is_none() {
            doc["quick"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        if let Some(table) = doc["quick"].as_table_mut() {
            set_string(table, "table", &fields.table);
            set_string(table, "policy", &fields.policy);
            set_string(table, "via", &fields.via);
        }
    }

    let done = write_config(config, &doc.to_string())?;
    Ok(Done::message(format!(
        "interface config updated — {}",
        done.message
    )))
}

/// Snapshot the running daemon's peer table and persist it back to the
/// interface's TOML config file (matching TUI `Action::SaveRuntime`).
///
/// # Errors
///
/// If the daemon socket cannot be read, or the config cannot be read/validated/written.
pub fn save_runtime(path: &Path, config: &Path) -> Result<Done, String> {
    let snap = snapshot::fetch(path)?;
    let text = read_config(config)?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|error| format!("parse {}: {error}", config.display()))?;

    let mut peers_array = toml_edit::ArrayOfTables::new();
    for peer in &snap.peers {
        let mut table = toml_edit::Table::new();
        if !peer.name.is_empty() {
            table.insert(
                "name",
                toml_edit::Item::Value(toml_edit::Value::from(peer.name.as_str())),
            );
        }
        if !peer.public_line.is_empty() {
            table.insert(
                "public_key",
                toml_edit::Item::Value(toml_edit::Value::from(peer.public_line.as_str())),
            );
        }
        if !peer.endpoint.is_empty() && peer.endpoint != "(none)" {
            table.insert(
                "endpoint",
                toml_edit::Item::Value(toml_edit::Value::from(peer.endpoint.as_str())),
            );
        }
        if !peer.allowed_ips.is_empty() {
            let mut allowed_array = toml_edit::Array::new();
            for ip in &peer.allowed_ips {
                allowed_array.push(ip.as_str());
            }
            table.insert(
                "allowed_ips",
                toml_edit::Item::Value(toml_edit::Value::Array(allowed_array)),
            );
        }
        if let Some(keepalive) = peer.keepalive {
            if keepalive > 0 {
                table.insert(
                    "persistent_keepalive",
                    toml_edit::Item::Value(toml_edit::Value::from(i64::from(keepalive))),
                );
            }
        }
        peers_array.push(table);
    }
    doc["peer"] = toml_edit::Item::ArrayOfTables(peers_array);

    let done = write_config(config, &doc.to_string())?;
    Ok(Done::message(format!(
        "saved runtime configuration to {} ({} peers) — {}",
        config.display(),
        snap.peers.len(),
        done.message
    )))
}

/// Result of an active path MTU + live UAPI fragmentation sweep from the GUI.
#[derive(Debug, serde::Serialize)]
pub struct MtuTuneOut {
    pub host: String,
    pub ceiling_outer_mtu: u16,
    pub recommended_inner_mtu: u16,
    pub recommended_outer_mtu: u16,
    pub ipv4_tcp_mss: u16,
    pub ipv6_tcp_mss: u16,
    pub profile: String,
    pub rationale: String,
}

/// Run a live path MTU + fragmentation telemetry sweep against the first
/// configured peer endpoint on `socket`.
///
/// # Errors
///
/// If the socket cannot be read, no peer has an endpoint, or ICMP probes fail.
pub fn tune_mtu(socket: &Path) -> Result<MtuTuneOut, String> {
    let snap = snapshot::fetch(socket)?;
    let endpoint = snap
        .peers
        .iter()
        .map(|peer| peer.endpoint.trim())
        .find(|ep| !ep.is_empty() && *ep != "(none)")
        .ok_or_else(|| "no peer endpoint configured to probe".to_owned())?;
    let c = &snap.counters;
    let rec = vallum::net::tune_path_mtu_host_with_counters(
        endpoint,
        c.fragments_dropped,
        c.reassembled,
        c.packets_delivered,
    )
    .ok_or_else(|| {
        format!("path MTU probe to {endpoint} inconclusive (ICMP blocked or unreachable)")
    })?;
    Ok(MtuTuneOut {
        host: endpoint.to_owned(),
        ceiling_outer_mtu: rec.ceiling_outer_mtu,
        recommended_inner_mtu: rec.recommended_inner_mtu,
        recommended_outer_mtu: rec.recommended_outer_mtu,
        ipv4_tcp_mss: rec.ipv4_tcp_mss,
        ipv6_tcp_mss: rec.ipv6_tcp_mss,
        profile: rec.profile.as_str().to_owned(),
        rationale: rec.rationale,
    })
}

// ---------------------------------------------------------------------------
// Guidance: the machine says what it needs next
// ---------------------------------------------------------------------------

/// The machine's next steps per `vallum::guidance`, as this surface sees them.
///
/// `socket` is optional: on a bare machine there is no daemon to ask, and the
/// unenrolled suggestions are exactly what the console should show. Facts that
/// need systemd are read unprivileged; the one privileged probe (`sync
/// --check`) is cached for five minutes so a polling console does not meter
/// sudo calls.
pub(crate) fn suggestions(socket: Option<&Path>) -> serde_json::Value {
    use vallum::guidance::{self, Facts, PeerFact};

    let snap = socket.and_then(|path| snapshot::fetch(path).ok());
    let stem = snap.as_ref().map(|s| s.interface.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let peers: Vec<PeerFact> = snap
        .as_ref()
        .map(|s| {
            s.peers
                .iter()
                .map(|p| {
                    PeerFact::from_observation(
                        &p.name,
                        &p.fingerprint,
                        &p.endpoint,
                        (p.last_handshake_sec > 0)
                            .then(|| now.saturating_sub(p.last_handshake_sec)),
                        p.rotating,
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let facts = Facts {
        config_present: crate::hostfacts::any_config_present().unwrap_or_else(|| snap.is_some()),
        role: vallum::host::paths::config_path(stem.as_deref())
            .and_then(|p| guidance::role_from_config(&p))
            .unwrap_or_else(|| guidance::infer_role(&peers)),
        unit_active: vallum::host::probes::any_unit_active("vallum@*"),
        unit_enabled: stem.as_deref().and_then(vallum::host::probes::unit_enabled),
        daemon_reachable: Some(snap.is_some()),
        interface_present: Some(snap.is_some()),
        peers,
        enrolment_open: vallum::host::probes::any_unit_active("vallum-enroll@*"),
        trial_armed: vallum::host::probes::any_unit_active("vallum-guard@*"),
        unit_restarts: stem
            .as_deref()
            .and_then(vallum::host::probes::unit_restarts),
        sync_stale: sync_stale_cached(),
        ssh_hosts: vallum::host::probes::ssh_host_count(),
    };

    serde_json::json!({ "suggestions": guidance::suggest(&facts) })
}

/// `vallum-ops sync --check`, cached: the verdict changes only when the tree or
/// the install does, so polling it is a sudo call for nothing. A failed check
/// answers `None` — a host without a trusted tree simply has no sync story.
fn sync_stale_cached() -> Option<bool> {
    if let Ok(mut cache) = SYNC_CHECK_CACHE.lock() {
        if let Some((at, stale)) = *cache {
            if at.elapsed() < std::time::Duration::from_secs(300) {
                return Some(stale);
            }
        }
        let result = crate::run_ops_with_stdin(&["sync", "--check"], None)
            .ok()
            .map(|text| text.contains("stale files found"));
        if let Some(stale) = result {
            *cache = Some((std::time::Instant::now(), stale));
        }
        result
    } else {
        crate::run_ops_with_stdin(&["sync", "--check"], None)
            .ok()
            .map(|text| text.contains("stale files found"))
    }
}

/// The five-minute `sync --check` verdict, shared with `sync_host`.
static SYNC_CHECK_CACHE: std::sync::Mutex<Option<(std::time::Instant, bool)>> =
    std::sync::Mutex::new(None);

/// `vallum-ops sync`: make the host match the build under test.
pub(crate) fn sync_host() -> Result<Done, String> {
    let text = crate::run_ops_with_stdin(&["sync"], None)?;
    // A successful sync IS a check: the host now matches the tree.
    if let Ok(mut cache) = SYNC_CHECK_CACHE.lock() {
        *cache = Some((std::time::Instant::now(), false));
    }
    Ok(Done::message(vallum::host::probes::sync_verdict(&text)))
}

/// `vallum-ops sync --check` on demand — the "check for updates" button, not
/// the cached value the suggestion strip uses.
pub(crate) fn sync_check() -> Result<Done, String> {
    let text = crate::run_ops_with_stdin(&["sync", "--check"], None)?;
    Ok(Done::message(vallum::host::probes::sync_verdict(&text)))
}

/// `vallum-ops enable|disable <stem>` — boot persistence for the unit set.
pub(crate) fn units_enabled_set(stem: &str, enabled: bool) -> Result<Done, String> {
    let verb = if enabled { "enable" } else { "disable" };
    crate::run_ops_with_stdin(&[verb, stem], None)?;
    Ok(Done::message(if enabled {
        format!("`{stem}` starts at boot")
    } else {
        format!("units for `{stem}` disabled — the tunnel stays off after reboot")
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod config_tests {
    use super::*;

    fn config_file(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(
            &path,
            "[interface]\nname = \"vallum0\"\nprivate_key = \"vallum0.key\"\naddresses = [\"10.7.0.1/32\"]\n",
        )
        .expect("fixture config");
        path
    }

    #[test]
    fn a_valid_edit_saves_and_keeps_a_backup() {
        let dir = std::env::temp_dir().join(format!("vallum-gui-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let path = config_file(&dir, "vallum0.toml");
        let edited =
            std::fs::read_to_string(&path).expect("fixture read") + "\n[log]\nlevel = \"debug\"\n";
        let done = write_config(&path, &edited).expect("valid edit saves");
        assert!(done.message.contains("backup"));
        assert!(std::fs::read_to_string(&path)
            .expect("read back")
            .contains("debug"));
        let backups = std::fs::read_dir(&dir)
            .expect("list dir")
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".bak."))
            })
            .count();
        assert_eq!(backups, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_invalid_edit_restores_the_previous_file() {
        let dir =
            std::env::temp_dir().join(format!("vallum-gui-config-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let path = config_file(&dir, "vallum0.toml");
        let before = std::fs::read_to_string(&path).expect("fixture read");
        let error = write_config(&path, "[interface\nthis is not toml = =").expect_err("bad edit");
        assert!(error.contains("restored"));
        assert_eq!(std::fs::read_to_string(&path).expect("read back"), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The dialogs' animation walks the same `VALLUM1` set the TUI animates:
    /// frame 0 is the first of the total, the grid is square, and an index
    /// past the end is an error the dialog can show rather than a blank
    /// canvas.
    #[test]
    fn the_qr_steps_through_the_frames() {
        let json = "{\"name\":\"phone\",\"config\":\"x\"}";
        let frame = qr_frame(json, 0).expect("frame 0 renders");
        assert_eq!(frame.index, 0);
        assert_eq!(frame.total, 1);
        assert_eq!(frame.hash.len(), 16);
        assert_eq!(frame.modules.len(), (frame.size * frame.size) as usize);
        assert!(frame.modules.contains(&1));
        let past = qr_frame(json, 1).expect_err("past the last frame");
        assert!(past.contains("frame 1"), "{past}");
    }

    #[test]
    fn peer_name_validation_rejects_bad_names_and_allows_good_ones() {
        for good in ["laptop", "node-01.wg", "a", "a_b-c.1", "123456789012345"] {
            assert_eq!(validate_peer_name(good).unwrap(), good);
        }
        assert_eq!(validate_peer_name("  phone  ").unwrap(), "phone");
        for bad in [
            "",
            "   ",
            "-bad",
            ".bad",
            "../etc",
            "my laptop",
            "1234567890123456",
            "node/1",
        ] {
            assert!(
                validate_peer_name(bad).is_err(),
                "{bad:?} must be rejected as an invalid peer name"
            );
        }
    }

    #[test]
    fn invite_rejects_bad_peer_names_and_out_of_range_ttl() {
        let bad_name = InviteFields {
            name: "../bad name".to_owned(),
            ttl_minutes: "15".to_owned(),
            pinned: String::new(),
            ssh_target: String::new(),
        };
        let err = invite("vallum0", None, None, "", &bad_name).expect_err("bad name rejected");
        assert!(err.contains("peer name"), "{err}");

        for bad_ttl in ["0", "10081", "abc"] {
            let bad = InviteFields {
                name: "phone".to_owned(),
                ttl_minutes: bad_ttl.to_owned(),
                pinned: String::new(),
                ssh_target: String::new(),
            };
            assert!(
                invite("vallum0", None, None, "", &bad).is_err(),
                "ttl {bad_ttl:?} must be rejected"
            );
        }
    }

    #[test]
    fn join_and_server_setup_validation_rejects_bad_inputs() {
        assert!(extract_join_ticket("").is_err());
        assert!(extract_join_ticket("not-a-ticket").is_err());
        assert!(extract_join_ticket("vallum1-join:short/a").is_err());
        let valid_ticket = "vallum1-join:203.0.113.5:51821/alice/id123/tok456/fp789";
        assert_eq!(
            extract_join_ticket(&format!("sudo vallum join {valid_ticket}")).unwrap(),
            valid_ticket
        );

        assert!(validate_ssh_target("").is_err());
        assert!(validate_ssh_target("-oProxyCommand=evil").is_err());
        assert!(validate_ssh_target("user@host;id").is_err());
        assert_eq!(
            validate_ssh_target("buffy@203.0.113.5").unwrap(),
            "buffy@203.0.113.5"
        );
        assert_eq!(validate_ssh_target("wingman-vps").unwrap(), "wingman-vps");

        assert!(validate_server_setup_fields(&ServerSetupFields::default()).is_err());
        assert!(validate_server_setup_fields(&ServerSetupFields {
            address: "10.7.0.1".to_owned(),
            listen: String::new(),
            public_endpoint: String::new(),
        })
        .is_err());
        assert!(validate_server_setup_fields(&ServerSetupFields {
            address: "10.7.0.1/20".to_owned(),
            listen: "0.0.0.0:51820".to_owned(),
            public_endpoint: "vpn.example.com:51820".to_owned(),
        })
        .is_ok());
    }

    #[test]
    fn interface_fields_round_trip_and_validate() {
        let dir = std::env::temp_dir().join(format!("vallum-gui-iface-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let path = config_file(&dir, "vallum0.toml");

        let fields = read_interface_fields(&path).expect("read initial fields");
        assert_eq!(fields.addresses, "10.7.0.1/32");
        assert_eq!(fields.listen, "");
        assert_eq!(fields.tcp_upgrade, "");

        let updated = InterfaceFields {
            listen: "0.0.0.0:51820".to_owned(),
            carrier: "auto".to_owned(),
            tcp_upgrade: "edge.wingman.gold:443".to_owned(),
            ss_psk: String::new(),
            tls_sni: "cdn.example.com".to_owned(),
            mtu: "1420".to_owned(),
            fwmark: "0xca6c".to_owned(),
            addresses: "10.7.0.1/24, fd00:7::1/64".to_owned(),
            dns: "1.1.1.1, 9.9.9.9".to_owned(),
            table: "auto".to_owned(),
            policy: "lockdown".to_owned(),
            content_blockers: "ads, trackers, malware".to_owned(),
            via: "entry.toml".to_owned(),
        };
        apply_interface(&path, &updated).expect("apply valid interface fields");

        let reread = read_interface_fields(&path).expect("re-read updated fields");
        assert_eq!(reread.listen, "0.0.0.0:51820");
        assert_eq!(reread.carrier, "auto");
        assert_eq!(reread.tcp_upgrade, "edge.wingman.gold:443");
        assert_eq!(reread.mtu, "1420");
        assert_eq!(reread.fwmark, "51820");
        assert_eq!(reread.addresses, "10.7.0.1/24, fd00:7::1/64");
        assert_eq!(reread.dns, "1.1.1.1, 9.9.9.9");
        assert_eq!(reread.table, "auto");
        assert_eq!(reread.policy, "lockdown");
        assert_eq!(reread.content_blockers, "ads, trackers, malware");

        let invalid = InterfaceFields {
            mtu: "100".to_owned(),
            ..updated.clone()
        };
        assert!(apply_interface(&path, &invalid).is_err());

        let invalid_carrier = InterfaceFields {
            carrier: "wireguard".to_owned(),
            ..updated.clone()
        };
        assert!(apply_interface(&path, &invalid_carrier).is_err());

        let invalid_tcp_upgrade = InterfaceFields {
            tcp_upgrade: "edge.wingman.gold\r\nX-Inject: 1".to_owned(),
            ..updated.clone()
        };
        assert!(apply_interface(&path, &invalid_tcp_upgrade).is_err());

        let invalid_policy = InterfaceFields {
            policy: "permissive".to_owned(),
            ..updated.clone()
        };
        assert!(apply_interface(&path, &invalid_policy).is_err());

        let invalid_blocker = InterfaceFields {
            content_blockers: "ads, nonexistent".to_owned(),
            ..updated
        };
        assert!(apply_interface(&path, &invalid_blocker).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_runtime_persists_live_peers_and_keeps_backup() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("vallum-gui-save-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let sock_path = dir.join("vallum0.sock");
        let cfg_path = config_file(&dir, "vallum0.toml");

        let listener = UnixListener::bind(&sock_path).expect("bind fake socket");
        let peer_line = "vallum1:0003:aabbccdd:-";

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let reply = format!(
                "vallum_interface=vallum0\nvallum_suite=0x0003\nerrno=0\n\n\
                 public_key=aabbccdd\nvallum_name=phone\nvallum_public_line={peer_line}\n\
                 endpoint=203.0.113.5:51820\nallowed_ip=10.7.0.2/32\npersistent_keepalive_interval=25\nerrno=0\n"
            );
            stream.write_all(reply.as_bytes()).expect("write reply");
        });

        let done = save_runtime(&sock_path, &cfg_path).expect("save runtime");
        server.join().expect("server thread");
        assert!(done.message.contains("1 peers"), "{}", done.message);
        let written = std::fs::read_to_string(&cfg_path).expect("read config");
        assert!(written.contains("name = \"phone\""), "{written}");
        assert!(written.contains("10.7.0.2/32"), "{written}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
