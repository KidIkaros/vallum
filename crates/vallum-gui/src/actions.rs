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
/// plus local randomness: no write gate, no privilege question.
///
/// # Errors
///
/// If the daemon cannot be read for its suite.
pub fn generate_key(path: &Path) -> Result<KeyOut, String> {
    let snap = snapshot::fetch(path)?;
    let secret = vallum::keys::new_secret(snap.suite_id(), false, vallum::entropy::seed());
    Ok(KeyOut {
        filename: format!("{}-client.key", snap.interface),
        text: vallum::keys::render_secret(&secret),
        message: format!(
            "fresh {} key minted — it exists only in this download until it is added to a peer",
            snap.suite
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
    std::fs::read_to_string(config).map_err(|error| format!("read {}: {error}", config.display()))
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
    match vallum::bundle::import(&bundle, Path::new(out_dir), false) {
        Ok(imported) => Ok(Done::message(format!(
            "imported `{}`: config {} (key {})",
            bundle.name,
            imported.config.display(),
            imported.key.display()
        ))),
        Err(error) => Err(format!(
            "{error}\n\nThis console could not write there. Run `sudo vallum import-bundle \"{bundle_path}\"` from a terminal for the same import."
        )),
    }
}

fn invite_privileged(error: impl std::fmt::Display) -> String {
    format!(
        "{error}\n\nThe invite file lives in the daemon's runtime directory, which this console cannot write. Run the console as root, or run `sudo vallum peer invite --help` for the same change from a terminal."
    )
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
}
