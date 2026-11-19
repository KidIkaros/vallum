// SPDX-License-Identifier: Apache-2.0

//! Side effects: UAPI writes, key generation, service control, logs.

use std::io::Write;

use std::path::PathBuf;
use std::process::Command;

use crate::control;
use crate::entropy;
use crate::host::probes::unit_state;
use crate::keys;
use crate::uapi::{self, Peer, Set};

use super::app::{App, ConfirmAction, FormError, FormKind, ServiceState, View};
use super::bundle;
use super::client;
use super::qr;

pub fn refresh(app: &mut App) {
    for interface in &mut app.interfaces {
        match client::fetch(&interface.control_path) {
            Ok(device) => interface.set_device(device),
            Err(error) => interface.set_error(error),
        }
        if interface.should_check_service(std::time::Instant::now()) {
            // Socket-discovered interfaces carry no config path; their socket
            // stem is the unit's instance name either way.
            let state = interface
                .config_path
                .as_deref()
                .and_then(systemd_service_state)
                .or_else(|| unit_state(&interface.name, "vallum@"));
            interface.set_service_state(state);
            // The unit name needs only the interface name: the config may be
            // root-only and unreadable to the operator, but the guard's state
            // is not a secret.
            let guard = unit_state(&interface.name, "vallum-guard@");
            interface.set_guard_state(guard);
        }
    }
    app.last_refresh = std::time::Instant::now();
    app.now = super::app::wall_now();
    recompute_suggestions(app);
}

fn systemd_service_state(config: &std::path::Path) -> Option<ServiceState> {
    unit_state(config.file_stem()?.to_str()?, "vallum@")
}

fn refresh_service_state(app: &mut App) {
    if let Some(interface) = app.current_mut() {
        interface.invalidate_service_state();
    }
}

pub fn submit_form(app: &mut App) {
    let Some(form) = app.form.clone() else {
        return;
    };
    let result = match form.kind {
        FormKind::AddPeer => add_peer(app, &form),
        FormKind::InvitePeer => invite_peer(app, &form),
        FormKind::EditPeer(index) => edit_peer(app, &form, index),
        FormKind::RotatePeer(index) => rotate_peer(app, &form, index),
        FormKind::Device => apply_device(app, &form),
        FormKind::ExportBundle => finish_export(app, &form),
        FormKind::ImportBundle => finish_import_bundle(app, &form),
        FormKind::Interface => apply_interface_form(app, &form),
        FormKind::JoinNetwork => join_network(app, &form),
        FormKind::SetupServer => setup_server(app, &form),
    };
    match result {
        Ok(message) => {
            app.form = None;
            app.notify(message);
            refresh(app);
        }
        Err(error) => {
            let mut form = form;
            form.error = Some(error);
            app.form = Some(form);
            app.toast = None;
        }
    }
}

type FormResult = Result<String, FormError>;

fn form_error(field: Option<&'static str>, message: impl Into<String>) -> FormError {
    FormError {
        field,
        message: message.into(),
    }
}

fn field_error(field: &'static str, message: impl Into<String>) -> FormError {
    form_error(Some(field), message)
}

fn invite_peer(app: &mut App, form: &super::app::Form) -> FormResult {
    let name = form.field("name").trim();
    if name.is_empty() {
        return Err(field_error("name", "peer name is required"));
    }
    let ttl_mins: u64 =
        form.field("TTL (minutes)").trim().parse().map_err(|_| {
            field_error("TTL (minutes)", "TTL must be a positive number of minutes")
        })?;
    if ttl_mins == 0 {
        return Err(field_error(
            "TTL (minutes)",
            "TTL must be at least 1 minute",
        ));
    }
    let pinned_raw = form.field("pinned public line").trim();
    let pinned = if pinned_raw.is_empty() {
        None
    } else {
        let (_, _) = keys::decode_public(pinned_raw)
            .map_err(|e| field_error("pinned public line", e.to_string()))?;
        Some(pinned_raw.to_owned())
    };
    let ssh_target = form.field("remote SSH (optional)").trim();
    if !ssh_target.is_empty() {
        return invite_via_ssh(app, ssh_target, name, ttl_mins, pinned.as_deref());
    }
    let interface_name = app
        .current()
        .map_or_else(|| "vallum0".to_owned(), |iface| iface.name.clone());
    let stem = app
        .current()
        .and_then(|iface| {
            iface
                .config_path
                .as_ref()
                .and_then(|p| p.file_stem())
                .and_then(|s| s.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| interface_name.clone());
    let (token, id, path) = match crate::enroll::issue_invite(
        &interface_name,
        name,
        ttl_mins * 60,
        pinned.clone(),
        false,
        None,
    ) {
        Ok(ok) => ok,
        Err(error) => {
            // The console cannot write the root-owned runtime dir or read the
            // 0600 config: mint through the privileged dispatcher instead, which
            // also starts the UDP 51821 responder and its firewall rule.
            let ttl = ttl_mins.to_string();
            let mut args = vec!["invite", name, ttl.as_str(), stem.as_str()];
            if let Some(pin) = pinned.as_deref() {
                args.push(pin);
            }
            let output = run_privileged(&args, None)
                .map_err(|ops_error| form_error(None, format!("{error}\n{ops_error}")))?;
            let Some(ticket) = output
                .split_whitespace()
                .find(|token| token.starts_with("vallum1-join:") && token.len() > 40)
            else {
                return Err(form_error(None, error.to_string()));
            };
            return show_invite(app, name, ticket, &stem);
        }
    };
    let (host_port, fp) = if let Some(device) = app.current_device() {
        let config = app
            .current()
            .and_then(|iface| iface.config_path.as_deref())
            .and_then(|cfg| crate::config::Config::load(cfg).ok());
        if let Some(cfg) = &config {
            // The same refusal the privileged `peer invite` path gives: an
            // enrolment port that cannot be bound mints a dead ticket.
            crate::commands::server::enroll_port(cfg)
                .map_err(|e| form_error(None, e.to_string()))?;
        }
        (
            crate::enroll::join_target(config.as_ref(), Some(&device.listen)),
            keys::fingerprint(&device.public_line),
        )
    } else {
        (crate::enroll::join_target(None, None), "?".to_owned())
    };
    // A ticket that says `<server>` cannot be redeemed — the config does not
    // name the address peers dial, so invite on the server instead.
    if host_port.starts_with("<server>") {
        return Err(form_error(
            None,
            "this config has no `[interface] public_endpoint`, so the ticket would \
             say `<server>` — mint the invite on the server (or set the endpoint first)"
                .to_owned(),
        ));
    }
    let ticket = crate::enroll::JoinTicket {
        server: host_port,
        name: name.to_owned(),
        invite_id: id,
        token,
        fingerprint: fp,
    }
    .encode();
    let join_cmd = format!("sudo vallum join {ticket}");
    let _ = copy_to_clipboard(&join_cmd);
    if let Ok(qr_state) = qr::encode_invite(&join_cmd, &path.display().to_string()) {
        app.qr = Some(qr_state);
    }
    Ok(format!(
        "invite minted for `{name}` (copied the join ticket)"
    ))
}

fn rotate_peer(app: &mut App, form: &super::app::Form, index: usize) -> FormResult {
    let config_path = app
        .current()
        .and_then(|iface| iface.config_path.clone())
        .ok_or_else(|| form_error(None, "no config file attached to this interface"))?;
    let device = app
        .current_device()
        .ok_or_else(|| form_error(None, "no device"))?;
    let peer = device
        .peers
        .get(index)
        .ok_or_else(|| form_error(None, "peer not found"))?;
    if peer.name.is_empty() {
        return Err(form_error(None, "peer has no name in config"));
    }
    let peer_name = peer.name.clone();
    let new_line = form.field("new public line").trim();
    if new_line.is_empty() {
        return Err(field_error(
            "new public line",
            "replacement public line is required",
        ));
    }
    let (suite, identity) =
        keys::decode_public(new_line).map_err(|e| field_error("new public line", e.to_string()))?;
    if suite != device.suite_id {
        return Err(field_error(
            "new public line",
            format!(
                "suite 0x{suite:04x} does not match device 0x{:04x}",
                device.suite_id
            ),
        ));
    }
    let canonical = keys::encode_public(suite, &identity);
    let mut file = crate::config_edit::ConfigFile::load(&config_path)
        .map_err(|e| form_error(None, e.to_string()))?;
    file.rotate_peer(
        &peer_name,
        &crate::config_edit::IdentityFields {
            public_key: Some(canonical),
            identity: None,
            identity_file: None,
        },
    )
    .map_err(|e| form_error(None, e.to_string()))?;
    file.validate()
        .map_err(|e| form_error(None, e.to_string()))?;
    file.save().map_err(|e| form_error(None, e.to_string()))?;
    let _ = crate::commands::control::syncconf_running(&config_path);
    Ok(format!(
        "rotated `{peer_name}` — old key kept until finalize (press f)"
    ))
}

fn finalize_peer_rotation(app: &mut App, name: &str) -> Result<String, String> {
    let config_path = app
        .current()
        .and_then(|iface| iface.config_path.clone())
        .ok_or_else(|| "no config file attached to this interface".to_owned())?;
    let mut file = crate::config_edit::ConfigFile::load(&config_path).map_err(|e| e.to_string())?;
    file.finalize_peer(name).map_err(|e| e.to_string())?;
    file.validate().map_err(|e| e.to_string())?;
    file.save().map_err(|e| e.to_string())?;
    let _ = crate::commands::control::syncconf_running(&config_path);
    Ok(format!("finalized `{name}` — previous key retired"))
}

fn add_peer(app: &mut App, form: &super::app::Form) -> FormResult {
    let device = app
        .current_device()
        .ok_or_else(|| form_error(None, "no device"))?;
    let (suite, identity) = keys::decode_public(form.field("public line"))
        .map_err(|error| field_error("public line", error.to_string()))?;
    if suite != device.suite_id {
        return Err(field_error(
            "public line",
            format!(
                "peer suite 0x{suite:04x} does not match device 0x{:04x}",
                device.suite_id
            ),
        ));
    }
    let endpoint =
        parse_endpoint(form.field("endpoint")).map_err(|error| field_error("endpoint", error))?;
    let allowed = parse_prefixes(form.field("allowed IPs"))
        .map_err(|error| field_error("allowed IPs", error))?;
    if allowed.is_empty() {
        return Err(field_error("allowed IPs", "allowed IPs is empty"));
    }
    let keepalive = parse_keepalive(form.field("keepalive"))
        .map_err(|error| field_error("keepalive", error))?;
    let psk = parse_psk(form.field("PSK (hex, optional)"))
        .map_err(|error| field_error("PSK (hex, optional)", error))?;
    let peer = Peer {
        public_key: Some(identity.kem().as_bytes().to_vec()),
        name: optional_name(form.field("name")),
        preshared_key: psk.map(Some),
        endpoint: endpoint.map(Some),
        keepalive,
        allowed_ips: allowed,
        remove: false,
        update_only: false,
        replace_allowed_ips: true,
        previous_public_key: None,
    };
    let set = Set {
        private_key: None,
        listen_port: None,
        fwmark: None,
        replace_peers: false,
        peers: vec![peer],
    };
    apply(app, &set).map_err(|error| form_error(None, error))?;
    Ok("peer added".to_owned())
}

fn apply_device(app: &mut App, form: &super::app::Form) -> FormResult {
    let port: u16 = form
        .field("listen port")
        .trim()
        .parse()
        .map_err(|_| field_error("listen port", "listen port is not a number"))?;
    let mark: u32 = form
        .field("fwmark")
        .trim()
        .parse()
        .map_err(|_| field_error("fwmark", "fwmark is not a number"))?;
    let set = Set {
        private_key: None,
        listen_port: Some(port),
        fwmark: Some(mark),
        replace_peers: false,
        peers: Vec::new(),
    };
    apply(app, &set).map_err(|error| form_error(None, error))?;
    Ok("runtime device updated".to_owned())
}

fn edit_peer(app: &mut App, form: &super::app::Form, index: usize) -> FormResult {
    let peer = app
        .current_device()
        .and_then(|device| device.peers.get(index))
        .cloned()
        .ok_or_else(|| form_error(None, "peer disappeared"))?;
    let (suite, identity) = keys::decode_public(&peer.public_line)
        .map_err(|error| form_error(None, error.to_string()))?;
    let device = app
        .current_device()
        .ok_or_else(|| form_error(None, "no device"))?;
    if suite != device.suite_id {
        return Err(form_error(None, "peer suite does not match device"));
    }
    let endpoint =
        parse_endpoint(form.field("endpoint")).map_err(|error| field_error("endpoint", error))?;
    let allowed = parse_prefixes(form.field("allowed IPs"))
        .map_err(|error| field_error("allowed IPs", error))?;
    if allowed.is_empty() {
        return Err(field_error("allowed IPs", "allowed IPs is empty"));
    }
    let keepalive = parse_keepalive(form.field("keepalive"))
        .map_err(|error| field_error("keepalive", error))?;
    let psk = parse_psk(form.field("PSK (hex, blank = keep)"))
        .map_err(|error| field_error("PSK (hex, blank = keep)", error))?;
    let peer = Peer {
        public_key: Some(identity.kem().as_bytes().to_vec()),
        name: optional_name(form.field("name")),
        preshared_key: psk.map(Some),
        endpoint: endpoint.map(Some),
        keepalive,
        allowed_ips: allowed,
        remove: false,
        update_only: true,
        replace_allowed_ips: true,
        previous_public_key: None,
    };
    let set = Set {
        private_key: None,
        listen_port: None,
        fwmark: None,
        replace_peers: false,
        peers: vec![peer],
    };
    apply(app, &set).map_err(|error| form_error(None, error))?;
    Ok("peer updated".to_owned())
}

pub fn confirm(app: &mut App) {
    let Some(confirm) = app.confirm.take() else {
        return;
    };

    match confirm.action {
        ConfirmAction::RemovePeer { index, .. } => {
            let Some(peer) = app
                .current_device()
                .and_then(|device| device.peers.get(index))
                .cloned()
            else {
                return;
            };
            let Ok((_, identity)) = keys::decode_public(&peer.public_line) else {
                app.notify("peer public line is not decodable");
                return;
            };
            let set = Set {
                private_key: None,
                listen_port: None,
                fwmark: None,
                replace_peers: false,
                peers: vec![Peer {
                    public_key: Some(identity.kem().as_bytes().to_vec()),
                    name: None,
                    preshared_key: None,
                    endpoint: None,
                    keepalive: None,
                    allowed_ips: Vec::new(),
                    remove: true,
                    update_only: false,
                    replace_allowed_ips: false,
                    previous_public_key: None,
                }],
            };
            match apply(app, &set) {
                Ok(()) => {
                    app.notify("peer removed");
                    app.peer_selected = app.peer_selected.saturating_sub(1);
                    refresh(app);
                }
                Err(error) => app.notify(error),
            }
        }
        ConfirmAction::FinalizePeer { name } => match finalize_peer_rotation(app, &name) {
            Ok(msg) => {
                app.notify(msg);
                refresh(app);
            }
            Err(err) => app.notify(err),
        },
        ConfirmAction::ApplyConfig => {
            let Some(path) = app
                .current()
                .and_then(|interface| interface.config_path.clone())
            else {
                app.notify("no config path available");
                return;
            };
            // Same discipline as the `E` flow: write to a sibling file,
            // validate, back up the original, then rename and restart.
            let candidate = path.with_extension("toml.new");
            if let Err(error) = std::fs::write(&candidate, &confirm.config) {
                app.notify(format!("write config: {error}"));
                return;
            }
            if let Err(error) = crate::config::Config::load(&candidate) {
                let _ = std::fs::remove_file(&candidate);
                app.notify(format!("invalid config: {error}"));
                return;
            }
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            let backup = path.with_extension(format!("toml.bak.{stamp}"));
            if let Err(error) = std::fs::copy(&path, &backup) {
                let _ = std::fs::remove_file(&candidate);
                app.notify(format!("backup failed: {error}"));
                return;
            }
            if let Err(error) = std::fs::rename(&candidate, &path) {
                app.notify(format!("apply config: {error}"));
                return;
            }
            app.notify(format!("config applied · backup {}", backup.display()));
            restart_service(app);
            refresh(app);
        }
        ConfirmAction::DisableUnits { stem } => match run_privileged(&["disable", &stem], None) {
            Ok(_) => {
                app.notify(format!(
                    "units for `{stem}` disabled — the tunnel stays off after reboot"
                ));
                refresh(app);
            }
            Err(error) => app.notify(format!("disable: {error}")),
        },
    }
}

pub fn keygen(app: &mut App) {
    let Some(device) = app.current_device() else {
        app.notify("no device to take a suite from");
        return;
    };
    let suite = device.suite_id;
    let interface = device.interface.clone();
    let preferred = app
        .current()
        .and_then(|current| current.config_path.as_ref())
        .and_then(|path| path.parent())
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let directory = writable_directory(preferred);
    let mut path = directory.join(format!("{interface}.key"));
    let mut counter = 1;
    while path.exists() {
        path = directory.join(format!("{interface}-{counter}.key"));
        counter += 1;
    }
    let file = keys::new_secret(suite, false, entropy::seed());
    if let Err(error) = keys::save_secret(&path, &file) {
        app.notify(error.to_string());
        return;
    }
    match keys::identity(
        &vallum_crypto_sdk::SdkSuite::from_id(suite)
            .unwrap_or_else(|_| vallum_crypto_sdk::SdkSuite::tri_hybrid()),
        &file,
    ) {
        Ok(identity) => {
            let line = keys::encode_public(suite, &identity.to_peer());
            app.pending_key = Some(path.clone());
            app.notify(format!(
                "wrote {} (public line copied to add form)",
                path.display()
            ));
            let mut form = super::app::Form::add_peer();
            if let Some(field) = form
                .fields
                .iter_mut()
                .find(|field| field.label == "public line")
            {
                field.value = line;
            }
            app.form = Some(form);
        }
        Err(error) => app.notify(error.to_string()),
    }
}

pub fn edit_config(app: &mut App) {
    let Some(path) = app
        .current()
        .and_then(|interface| interface.config_path.clone())
    else {
        app.notify("no config path; start the daemon from a config file");
        return;
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let backup = path.with_extension(format!("toml.bak.{stamp}"));
    if let Err(error) = std::fs::copy(&path, &backup) {
        app.notify(format!("cannot back up config: {error}"));
        return;
    }
    app.editor_backup = Some(backup);
    app.editor = Some(path);
}

pub fn finish_edit_config(app: &mut App, path: &std::path::Path) {
    let backup = app.editor_backup.take();
    let backup_note = backup
        .as_ref()
        .map_or_else(String::new, |path| format!("; backup {}", path.display()));
    if let Err(error) = crate::config::Config::load(path) {
        app.notify(format!("invalid config: {error}{backup_note}"));
        return;
    }
    let Some(backup) = backup else {
        app.notify("config parsed; no backup to diff");
        return;
    };
    let old = std::fs::read_to_string(&backup).unwrap_or_default();
    let new = std::fs::read_to_string(path).unwrap_or_default();
    if old == new {
        app.notify(format!("config parsed; no changes{backup_note}"));
        return;
    }
    app.diff = Some(super::app::DiffView {
        rows: build_diff(&old, &new),
        backup,
    });
    app.view = super::app::View::Diff;
}

fn build_diff(old: &str, new: &str) -> Vec<super::app::DiffRow> {
    use similar::{DiffOp, TextDiff};
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let diff = TextDiff::from_lines(old, new);
    let mut rows = Vec::new();
    for op in diff.ops() {
        match *op {
            DiffOp::Equal {
                old_index,
                new_index,
                len,
            } => {
                for offset in 0..len {
                    rows.push(super::app::DiffRow {
                        left: Some(old_lines[old_index + offset].to_owned()),
                        right: Some(new_lines[new_index + offset].to_owned()),
                        kind: super::app::DiffKind::Equal,
                    });
                }
            }
            DiffOp::Delete {
                old_index, old_len, ..
            } => {
                for offset in 0..old_len {
                    rows.push(super::app::DiffRow {
                        left: Some(old_lines[old_index + offset].to_owned()),
                        right: None,
                        kind: super::app::DiffKind::Delete,
                    });
                }
            }
            DiffOp::Insert {
                new_index, new_len, ..
            } => {
                for offset in 0..new_len {
                    rows.push(super::app::DiffRow {
                        left: None,
                        right: Some(new_lines[new_index + offset].to_owned()),
                        kind: super::app::DiffKind::Insert,
                    });
                }
            }
            DiffOp::Replace {
                old_index,
                old_len,
                new_index,
                new_len,
            } => {
                for offset in 0..old_len.max(new_len) {
                    rows.push(super::app::DiffRow {
                        left: (offset < old_len).then(|| old_lines[old_index + offset].to_owned()),
                        right: (offset < new_len).then(|| new_lines[new_index + offset].to_owned()),
                        kind: super::app::DiffKind::Replace,
                    });
                }
            }
        }
        if rows.len() > 1_000 {
            rows.truncate(1_000);
            rows.push(super::app::DiffRow {
                left: Some("… diff truncated".to_owned()),
                right: None,
                kind: super::app::DiffKind::Delete,
            });
            break;
        }
    }
    rows
}

pub fn apply_config(app: &mut App) {
    app.diff = None;
    app.view = super::app::View::Dashboard;
    restart_service_inner(app);
}

fn restart_service_inner(app: &mut App) {
    let Some(interface) = app.current() else {
        return;
    };
    let Some(config) = &interface.config_path else {
        app.notify("no config path to restart");
        return;
    };
    let unit = format!("vallum@{}.service", crate::host::paths::config_stem(config));
    if Command::new("systemctl")
        .args(["--no-ask-password", "cat", &unit])
        .status()
        .is_ok_and(|status| status.success())
    {
        // A normal user cannot restart a system unit, and trying raises a
        // polkit dialog in the middle of the dashboard — the same reason
        // `service_plan` hands over the command instead of running it. The
        // check has to come *before* the attempt: `systemctl` only fails once
        // the operator has dismissed the dialog, which is the wrong moment to
        // find out.
        if !nix::unistd::geteuid().is_root() {
            app.notify(format!("sudo systemctl restart {unit}"));
            return;
        }
        match Command::new("systemctl")
            .args(["--no-ask-password", "restart", &unit])
            .status()
        {
            Ok(status) if status.success() => {
                app.notify(format!("systemctl restart {unit}"));
                refresh_service_state(app);
                refresh(app);
                return;
            }
            _ => {}
        }
    }
    if nix::unistd::geteuid().is_root() {
        let down = Command::new("vallum-quick")
            .arg("down")
            .arg(config)
            .status();
        let up = Command::new("vallum-quick").arg("up").arg(config).status();
        if down.is_ok_and(|status| status.success()) && up.is_ok_and(|status| status.success()) {
            app.notify("vallum-quick down && up");
            refresh(app);
            return;
        }
    }
    app.notify(format!(
        "sudo vallum-quick down {} && sudo vallum-quick up {}",
        config.display(),
        config.display()
    ));
}

fn writable_directory(preferred: PathBuf) -> PathBuf {
    if is_writable(&preferred) {
        return preferred;
    }
    let fallback = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(std::env::temp_dir)
        .join("vallum");
    let _ = std::fs::create_dir_all(&fallback);
    fallback
}

fn is_writable(directory: &std::path::Path) -> bool {
    let probe = directory.join(format!(".vallum-write-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

pub fn interface_form(app: &mut App) {
    let Some(path) = app
        .current()
        .and_then(|interface| interface.config_path.clone())
    else {
        app.notify("no config path to edit");
        return;
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            app.notify(format!("read config: {error}"));
            return;
        }
    };
    let doc: toml_edit::DocumentMut = match text.parse() {
        Ok(doc) => doc,
        Err(error) => {
            app.notify(format!("parse config: {error}"));
            return;
        }
    };
    let string = |table: &toml_edit::DocumentMut, key: &str| {
        table
            .get("interface")
            .and_then(|item| item.get(key))
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned()
    };
    let integer = |table: &toml_edit::DocumentMut, key: &str| {
        table
            .get("interface")
            .and_then(|item| item.get(key))
            .and_then(|item| item.as_integer())
            .map_or_else(String::new, |value| value.to_string())
    };
    let list = |table: &toml_edit::DocumentMut, table_name: &str, key: &str| {
        table
            .get(table_name)
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
    let values = [
        string(&doc, "listen"),
        string(&doc, "carrier"),
        integer(&doc, "mtu"),
        integer(&doc, "fwmark"),
        list(&doc, "interface", "addresses"),
        list(&doc, "quick", "dns"),
        doc.get("quick")
            .and_then(|item| item.get("table"))
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned(),
    ];
    app.form = Some(super::app::Form::interface(values));
}

fn apply_interface_form(app: &mut App, form: &super::app::Form) -> FormResult {
    let values: Vec<String> = form
        .fields
        .iter()
        .map(|field| field.value.clone())
        .collect();
    super::app::Form::validate_interface(&values)?;
    let path = app
        .current()
        .and_then(|interface| interface.config_path.clone())
        .ok_or_else(|| form_error(None, "no config path"))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|error| form_error(None, format!("read config: {error}")))?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|error| form_error(None, format!("parse config: {error}")))?;
    if doc.get("interface").is_none() {
        doc["interface"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    let interface = doc["interface"]
        .as_table_mut()
        .ok_or_else(|| form_error(None, "interface is not a table"))?;
    let set_string = |table: &mut toml_edit::Table, key: &str, value: &str| {
        let value = value.trim();
        if value.is_empty() {
            table.remove(key);
        } else {
            table[key] = toml_edit::value(value);
        }
    };
    set_string(interface, "listen", form.field("listen"));
    set_string(interface, "carrier", form.field("carrier"));
    for (key, label) in [("mtu", "mtu"), ("fwmark", "fwmark")] {
        let value = form.field(label).trim();
        if value.is_empty() {
            interface.remove(key);
        } else {
            let parsed: i64 = value
                .parse()
                .map_err(|_| field_error(label, format!("{label} is not a number")))?;
            interface[key] = toml_edit::value(parsed);
        }
    }
    for (table_name, key, label) in [
        ("interface", "addresses", "addresses (comma)"),
        ("quick", "dns", "dns (comma)"),
    ] {
        let entries: Vec<&str> = form
            .field(label)
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect();
        // Don't create a table that stays empty just to delete a missing key.
        if doc.get(table_name).is_none() {
            if entries.is_empty() {
                continue;
            }
            doc[table_name] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let table = doc[table_name]
            .as_table_mut()
            .ok_or_else(|| form_error(None, format!("{table_name} is not a table")))?;
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
    if !form.field("table").trim().is_empty() || doc.get("quick").is_some() {
        if doc.get("quick").is_none() {
            doc["quick"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        if let Some(table) = doc["quick"].as_table_mut() {
            set_string(table, "table", form.field("table"));
        }
    }

    // Ask for confirmation before applying config changes
    // Store the config in the confirm struct so it can be applied later
    app.confirm = Some(super::app::Confirm {
        action: ConfirmAction::ApplyConfig,
        config: doc.to_string(),
    });
    Ok("Press Enter to apply config changes".to_string())
}

pub fn export_bundle(app: &mut App) {
    let Some(device) = app.current_device().cloned() else {
        app.notify("no device to export");
        return;
    };
    if app.current_peer().is_none() {
        app.notify("select a peer first");
        return;
    }
    if app.pending_key.is_none() {
        app.notify("generate a key first (g), then add the peer");
        return;
    }
    app.form = Some(super::app::Form::export_bundle(&device));
}

fn finish_export(app: &mut App, form: &super::app::Form) -> FormResult {
    let device = app
        .current_device()
        .cloned()
        .ok_or_else(|| form_error(None, "no device"))?;
    let peer = app
        .current_peer()
        .cloned()
        .ok_or_else(|| form_error(None, "no peer"))?;
    let key_path = app
        .pending_key
        .clone()
        .ok_or_else(|| form_error(None, "no generated key"))?;
    let (bundle, path) = bundle::build(&device, &peer, &key_path, form.field("server endpoint"))
        .map_err(|error| {
            if error.starts_with("server endpoint") {
                field_error("server endpoint", error)
            } else {
                form_error(None, error)
            }
        })?;
    let json = serde_json::to_string_pretty(&bundle)
        .map_err(|error| form_error(None, error.to_string()))?;
    let state =
        qr::encode(&json, &path.display().to_string()).map_err(|error| form_error(None, error))?;
    app.qr = Some(state);
    Ok(format!("bundle written to {}", path.display()))
}

pub fn import_bundle(app: &mut App) {
    let default_dir = app
        .current()
        .and_then(|i| i.config_path.as_ref())
        .and_then(|p| p.parent())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| crate::host::paths::config_dir().display().to_string());
    app.form = Some(super::app::Form::import_bundle(&default_dir));
}

fn finish_import_bundle(app: &mut App, form: &super::app::Form) -> FormResult {
    let bundle_path_str = form.field("bundle file").trim();
    if bundle_path_str.is_empty() {
        return Err(field_error("bundle file", "bundle file path is empty"));
    }
    let bundle_path = std::path::Path::new(bundle_path_str);
    if !bundle_path.exists() {
        return Err(field_error("bundle file", "file does not exist"));
    }
    let bundle = crate::bundle::read(bundle_path)
        .map_err(|err| field_error("bundle file", format!("cannot load bundle: {err}")))?;

    let out_dir_str = form.field("output dir").trim();
    let out_dir = if out_dir_str.is_empty() {
        crate::host::paths::config_dir()
    } else {
        std::path::Path::new(out_dir_str)
    };

    let imported = crate::bundle::import(&bundle, out_dir, false)
        .map_err(|err| form_error(None, format!("import failed: {err}")))?;

    let stem = imported
        .config
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("vallum0");
    let control_path = out_dir.join(format!("{stem}.control.sock"));
    let new_iface =
        super::app::Interface::new(stem.to_owned(), Some(imported.config.clone()), control_path);
    app.interfaces.push(new_iface);
    app.selected = app.interfaces.len().saturating_sub(1);

    Ok(format!(
        "bundle imported: config {} (key {})",
        imported.config.display(),
        imported.key.display()
    ))
}

pub fn save_runtime_config(app: &mut App) {
    let Some(interface) = app.current() else {
        app.notify("no interface selected");
        return;
    };
    let Some(config_path) = interface.config_path.clone() else {
        app.notify("no config file associated with this interface; cannot save");
        return;
    };
    let Some(device) = interface.device.clone() else {
        app.notify("no runtime device snapshot to save");
        return;
    };

    let text = match std::fs::read_to_string(&config_path) {
        Ok(t) => t,
        Err(e) => {
            app.notify(format!("cannot read {}: {e}", config_path.display()));
            return;
        }
    };
    let mut doc: toml_edit::DocumentMut = match text.parse() {
        Ok(d) => d,
        Err(e) => {
            app.notify(format!("cannot parse config: {e}"));
            return;
        }
    };

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let backup = config_path.with_extension(format!("toml.bak.{stamp}"));
    if let Err(e) = std::fs::copy(&config_path, &backup) {
        app.notify(format!("backup failed: {e}"));
        return;
    }

    let mut peers_array = toml_edit::ArrayOfTables::new();
    for peer in &device.peers {
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

    if let Err(e) = std::fs::write(&config_path, doc.to_string()) {
        app.notify(format!("cannot write config: {e}"));
        return;
    }

    app.notify(format!(
        "saved runtime configuration to {} ({} peers)",
        config_path.display(),
        device.peers.len()
    ));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicePlan {
    Systemd {
        unit: String,
        action: &'static str,
    },
    Quick {
        action: &'static str,
        config: PathBuf,
    },
    Command(String),
}

pub fn service_plan(
    config: &std::path::Path,
    running: bool,
    systemd: bool,
    root: bool,
) -> ServicePlan {
    let unit = format!("vallum@{}.service", crate::host::paths::config_stem(config));
    let action = if running { "stop" } else { "start" };
    let quick = if running { "down" } else { "up" };
    if systemd && root {
        ServicePlan::Systemd { unit, action }
    } else if systemd {
        // A normal user cannot start a system unit, and trying raises a polkit
        // dialog in the middle of the dashboard. Hand over the command instead.
        ServicePlan::Command(format!("sudo systemctl {action} {unit}"))
    } else if root {
        ServicePlan::Quick {
            action: quick,
            config: config.to_path_buf(),
        }
    } else {
        ServicePlan::Command(format!("sudo vallum-quick {quick} {}", config.display()))
    }
}

trait ServiceRunner {
    fn is_root(&self) -> bool;
    fn run(&self, program: &str, args: &[String]) -> Result<(), String>;
}

struct SystemRunner;

impl ServiceRunner for SystemRunner {
    fn is_root(&self) -> bool {
        nix::unistd::geteuid().is_root()
    }

    fn run(&self, program: &str, args: &[String]) -> Result<(), String> {
        match Command::new(program).args(args).status() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("{program} exited {status}")),
            Err(error) => Err(format!("{program}: {error}")),
        }
    }
}

pub fn toggle_service(app: &mut App) {
    toggle_service_with(app, &SystemRunner);
}

fn toggle_service_with(app: &mut App, runner: &impl ServiceRunner) {
    let Some(interface) = app.current() else {
        return;
    };
    let Some(config) = &interface.config_path else {
        app.notify("no config path; use systemctl or vallum-quick directly");
        return;
    };
    let unit = format!("vallum@{}.service", crate::host::paths::config_stem(config));
    // The *template* unit exists on any host that installed Vallum, so
    // `systemctl cat` succeeds for instance names that were never created. A
    // unit only ever reads /etc/vallum/<instance>.toml, so the config's own
    // location is what decides whether systemd owns this interface.
    let under_etc = config.starts_with(crate::host::paths::config_dir());
    let systemd = under_etc
        && runner
            .run("systemctl", &["cat".to_owned(), unit.clone()])
            .is_ok();
    let plan = service_plan(
        config,
        interface.device.is_some(),
        systemd,
        runner.is_root(),
    );
    match plan {
        ServicePlan::Systemd { unit, action } => {
            if runner
                .run("systemctl", &[action.to_owned(), unit.clone()])
                .is_ok()
            {
                if let Some(interface) = app.current_mut() {
                    interface.service_state = Some(match action {
                        "start" => super::app::ServiceState::Activating,
                        "stop" => super::app::ServiceState::Deactivating,
                        _ => super::app::ServiceState::Activating,
                    });
                }
                app.notify(format!("systemctl {action} {unit}"));
                refresh_service_state(app);
                refresh(app);
            } else {
                let quick = if interface.device.is_some() {
                    "down"
                } else {
                    "up"
                };
                app.notify(format!("sudo vallum-quick {quick} {}", config.display()));
            }
        }
        ServicePlan::Quick { action, config } => {
            let config_arg = config.display().to_string();
            if runner
                .run("vallum-quick", &[action.to_owned(), config_arg.clone()])
                .is_ok()
            {
                if let Some(interface) = app.current_mut() {
                    interface.service_state = Some(match action {
                        "up" => super::app::ServiceState::Activating,
                        "down" => super::app::ServiceState::Deactivating,
                        _ => super::app::ServiceState::Activating,
                    });
                }
                app.notify(format!("vallum-quick {action}"));
                refresh_service_state(app);
                refresh(app);
            } else {
                app.notify(format!("sudo vallum-quick {action} {config_arg}"));
            }
        }
        ServicePlan::Command(command) => {
            // Copy it: the operator has to run this in a terminal, and retyping
            // a unit name is how the wrong unit gets restarted.
            let channels = copy_to_clipboard(&command);
            app.notify(format!("{command} — {}", clipboard_report(&channels)));
        }
    }
}

pub fn load_logs(app: &mut App) {
    let Some(interface) = app.current() else {
        return;
    };
    let Some(config) = &interface.config_path else {
        app.notify("no config path for journald");
        return;
    };
    let unit = format!("vallum@{}.service", crate::host::paths::config_stem(config));
    match Command::new("journalctl")
        .args(["-u", &unit, "-n", "200", "--no-pager", "-o", "cat"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::to_owned)
                .collect();
            app.logs = if lines.is_empty() {
                vec![format!("journald returned no lines for {unit}")]
            } else {
                lines
            };
            app.view = View::Logs;
            app.last_logs = std::time::Instant::now();
        }
        Ok(output) => {
            let error = String::from_utf8_lossy(&output.stderr);
            app.logs = vec![format!("journal unavailable for {unit}: {}", error.trim())];
            app.view = View::Logs;
            app.last_logs = std::time::Instant::now();
        }
        Err(error) => {
            app.logs = vec![format!("journal unavailable for {unit}: {error}")];
            app.view = View::Logs;
            app.last_logs = std::time::Instant::now();
        }
    }
}

/// Refresh the cached desk account read — never on the render path.
///
/// The read is a blocking HTTPS call (up to the desk's own timeouts), so it
/// runs on a worker thread and the panel renders the last cached answer, or
/// `unknown` until the first one lands. While the panel is open the read is
/// refreshed on open, every 30 s, and whenever the selected interface's
/// config changes — the same off-render discipline as the background ping.
pub fn poll_account(app: &mut App) {
    if let Some(receiver) = app.account_pending.take() {
        match receiver.try_recv() {
            Ok(state) => {
                app.account = state;
                app.account_fetched_at = Some(std::time::Instant::now());
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => app.account_pending = Some(receiver),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                app.account = super::account::AccountState::Unreadable(
                    "account worker exited without a result".to_owned(),
                );
            }
        }
        return;
    }
    if app.view != View::Account {
        return;
    }
    let Some(path) = app.current().and_then(|iface| iface.config_path.clone()) else {
        // Socket-discovered interfaces carry no config: there is no [account]
        // to read, and saying "no desk account" would be a confident guess.
        app.account = super::account::AccountState::NoConfig;
        return;
    };
    let fresh_for = app.account_for.as_ref() == Some(&path);
    let due = app
        .account_fetched_at
        .is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(30));
    if fresh_for && !due {
        return;
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    app.account_pending = Some(receiver);
    app.account_for = Some(path.clone());
    std::thread::spawn(move || {
        let state = match vallum_config::Config::load(&path) {
            Ok(config) => super::account::AccountState::Read(Box::new(
                crate::commands::account::read_report(&config),
            )),
            Err(error) => super::account::AccountState::Unreadable(error.to_string()),
        };
        let _ = sender.send(state);
    });
}

/// Open the account panel: the desk read on top, the full-tunnel trial plan
/// below (the view's own `a`/`p` keys). The read itself lands off the render
/// path via `poll_account`; opening forces a fresh one.
pub fn account_panel(app: &mut App) {
    trial_plan(app);
}

/// The full-tunnel trial preview. Read-only: `vallum-ops status` needs no
/// privilege, so the plan renders for every operator. Arming stays behind the
/// privilege rule in `run_ops` below.
pub fn trial_plan(app: &mut App) {
    let mut lines = vec![
        "FULL-TUNNEL TRIAL — route all host traffic through the tunnel.".to_owned(),
        String::new(),
        "What arming does: default route via the tunnel, DNS via the tunnel,".to_owned(),
        "egress guard on, and a dead-man revert timer. The dispatcher's verdict".to_owned(),
        "prints verbatim after `full-tunnel` runs. `p` panics back to split.".to_owned(),
        String::new(),
        "--- host now (`vallum-ops status`) ---".to_owned(),
    ];
    match Command::new("vallum-ops").arg("status").output() {
        Ok(output) if output.status.success() => lines.extend(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::to_owned),
        ),
        Ok(output) => lines.push(format!(
            "status unavailable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(_) => {
            lines.push("vallum-ops not found — arm with: sudo vallum-ops full-tunnel".to_owned())
        }
    }
    app.trial_lines = lines;
    app.trial_scroll = 0;
    app.view = View::Account;
    // Opening (or refreshing) the panel asks the desk again on the next tick.
    app.account_fetched_at = None;
}

/// Run a privileged ops subcommand, or hand its command over. The TUI never
/// raises a privilege prompt mid-dashboard: the same rule `restart_service`
/// follows — root runs, everyone else gets the exact command to run.
fn run_ops(app: &mut App, subcommand: &str) {
    if !nix::unistd::geteuid().is_root() {
        app.notify(format!("sudo vallum-ops {subcommand}"));
        return;
    }
    match Command::new("vallum-ops").arg(subcommand).output() {
        Ok(output) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            app.trial_lines = text.lines().map(str::to_owned).collect();
            app.trial_scroll = 0;
            app.view = View::Account;
            app.notify(if output.status.success() {
                format!("vallum-ops {subcommand}: ok")
            } else {
                format!("vallum-ops {subcommand}: failed")
            });
        }
        Err(error) => app.notify(format!("cannot run vallum-ops: {error}")),
    }
}

/// Arm the full-tunnel trial from the plan view.
pub fn trial_arm(app: &mut App) {
    run_ops(app, "full-tunnel");
}

/// Panic: the documented undo, run immediately. Converges on split tunnel
/// even when no trial is active — the same end state a failed trial reaches
/// on its own, reached now instead of at the deadline.
pub fn trial_revert(app: &mut App) {
    run_ops(app, "revert");
}

/// Egress health, measured from the host. Read-only, so it renders for every
/// operator with no privilege question — the GUI's EGRESS HEALTH rows.
pub fn health_check(app: &mut App) {
    let Some(interface) = app.current() else {
        app.notify("no interface to check");
        return;
    };
    let stem = interface
        .config_path
        .as_ref()
        .and_then(|path| path.file_stem())
        .and_then(|stem| stem.to_str())
        .unwrap_or(interface.name.as_str());
    let name = if interface.name.is_empty() {
        stem.to_owned()
    } else {
        interface.name.clone()
    };
    let expected_full = app
        .current_device()
        .is_some_and(|device| device.egress == "full");
    let facts = super::health::measure(&name, &format!("vallum@{stem}"), expected_full);
    let (_, _, tone) = super::health::verdict(&facts);
    app.health_tone = tone;
    app.health_lines = super::health::lines(&facts);
    app.health_scroll = 0;
    app.view = View::Health;
}

fn apply(app: &App, set: &Set) -> Result<(), String> {
    let interface = app.current().ok_or("no interface")?;
    let body = uapi::render_set(set);
    let reply =
        control::request(&interface.control_path, &body).map_err(|error| error.to_string())?;
    if reply.lines().any(|line| line == "errno=0") {
        Ok(())
    } else {
        Err(format!("control error: {}", reply.trim()))
    }
}

fn optional_name(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

// The form-field parsers are shared with the desktop console, so they live in
// `crate::form` rather than here; the names are re-exported for the call sites
// below and for `tui::tests`.
pub(crate) use crate::form::{parse_endpoint, parse_keepalive, parse_prefixes, parse_psk};

/// Run a `vallum-ops` subcommand with privilege: directly as root, or through
/// the installer's passwordless sudoers rule (`sudo -n`). On failure the error
/// carries the exact `sudo vallum-ops …` command — the TUI never raises a
/// password prompt mid-dashboard.
fn run_privileged(ops_args: &[&str], stdin_data: Option<&str>) -> Result<String, String> {
    run_privileged_with_env(ops_args, stdin_data, &[])
}

/// `run_privileged` with extra environment for the spawned dispatcher. The
/// direct (root) path inherits it; the sudo path strips it (sudoers grants
/// the dispatcher only, no SETENV) — secrets that must cross sudo ride
/// stdin, the way the join token does.
fn run_privileged_with_env(
    ops_args: &[&str],
    stdin_data: Option<&str>,
    env: &[(&str, String)],
) -> Result<String, String> {
    use std::process::Stdio;
    let attempts: Vec<(String, Vec<String>)> = if nix::unistd::geteuid().is_root() {
        vec![
            (
                "/usr/local/sbin/vallum-ops".to_owned(),
                ops_args.iter().map(|s| s.to_string()).collect(),
            ),
            (
                "vallum-ops".to_owned(),
                ops_args.iter().map(|s| s.to_string()).collect(),
            ),
        ]
    } else {
        vec![
            (
                "sudo".to_owned(),
                std::iter::once("-n".to_owned())
                    .chain(std::iter::once("/usr/local/sbin/vallum-ops".to_owned()))
                    .chain(ops_args.iter().map(|s| s.to_string()))
                    .collect(),
            ),
            (
                "sudo".to_owned(),
                std::iter::once("-n".to_owned())
                    .chain(std::iter::once("vallum-ops".to_owned()))
                    .chain(ops_args.iter().map(|s| s.to_string()))
                    .collect(),
            ),
        ]
    };
    let mut last = String::new();
    for (program, args) in attempts {
        let mut cmd = Command::new(&program);
        cmd.args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            cmd.env(key, value);
        }
        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let Ok(mut child) = cmd.spawn() else {
            continue;
        };
        if let Some(input) = stdin_data {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = writeln!(stdin, "{input}");
            }
        }
        if let Ok(output) = child.wait_with_output() {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if output.status.success() {
                return Ok(text);
            }
            if !text.trim().is_empty() {
                last = text.trim().to_owned();
            }
            // The second attempt only relocates ops on PATH — it can help
            // when the first path was missing, never when ops ran and gave a
            // verdict or sudo refused auth. Don't run the command twice.
            if !text.contains("command not found") && !text.contains("No such file or directory") {
                break;
            }
        }
    }
    let suggested = format!("sudo vallum-ops {}", ops_args.join(" "));
    Err(if last.is_empty() {
        format!("run it elevated: {suggested}")
    } else {
        format!("{last} (or run: {suggested})")
    })
}

/// Mint the invite on a remote server over SSH — for an operator running this
/// console on a client laptop. Prints the join ticket into a QR modal.
fn invite_via_ssh(
    app: &mut App,
    ssh_target: &str,
    name: &str,
    ttl_mins: u64,
    pinned: Option<&str>,
) -> FormResult {
    if ssh_target.starts_with('-')
        || !ssh_target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':'))
    {
        return Err(field_error(
            "remote SSH (optional)",
            "SSH host may only contain letters, digits, '.', '_', '-', '@', or ':'",
        ));
    }
    let mut remote = format!("sudo -n /usr/bin/vallum peer invite '{name}' --ttl {ttl_mins}");
    if let Some(pin) = pinned {
        remote.push_str(&format!(" --public-key '{pin}'"));
    }
    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            ssh_target,
            &remote,
        ])
        .output()
        .map_err(|error| form_error(None, format!("cannot run ssh to {ssh_target}: {error}")))?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(form_error(
            None,
            format!(
                "remote invite on `{ssh_target}` failed: {}",
                combined.trim()
            ),
        ));
    }
    let Some(ticket) = combined
        .split_whitespace()
        .find(|token| token.starts_with("vallum1-join:") && token.len() > 40)
    else {
        return Err(form_error(
            None,
            format!(
                "`{ssh_target}` returned no vallum1-join ticket: {}",
                combined.trim()
            ),
        ));
    };
    show_invite(app, name, ticket, ssh_target)
}

/// Copy the join ticket and open the QR modal — shared by the local, privileged,
/// and remote-SSH invite paths.
fn show_invite(app: &mut App, name: &str, ticket: &str, responder_label: &str) -> FormResult {
    let join_cmd = format!("sudo vallum join {ticket}");
    let _ = copy_to_clipboard(&join_cmd);
    if let Ok(qr_state) = qr::encode_invite(&join_cmd, responder_label) {
        app.qr = Some(qr_state);
    }
    Ok(format!(
        "invite minted for `{name}` on {responder_label} (copied the join ticket)"
    ))
}

/// What the privileged join invocation carries (ADR-0046).
///
/// The ticket rides stdin line 1; an optional desk account token rides
/// line 2, which `vallum-ops join` re-exports as `VALLUM_ACCOUNT` for
/// `vallum join` to seal into `[account]`. The desk origin rides the
/// environment as `VALLUM_DESK_ENDPOINT` — the same channels
/// `service/vallum-uri` uses. Nothing secret sits in argv: `ps` is
/// world-readable. (The sudo path strips the environment; recording the
/// endpoint there needs a dispatcher stdin line — a packaging change.)
#[derive(Debug)]
pub(crate) struct JoinRequest {
    pub ops_args: Vec<String>,
    pub stdin: Option<String>,
    pub env: Vec<(&'static str, String)>,
}

/// Validate the join form and build the privileged invocation's channels.
pub(crate) fn join_request(form: &super::app::Form) -> Result<JoinRequest, FormError> {
    let target = form.field("ticket or user@host").trim();
    if target.is_empty() {
        return Err(field_error(
            "ticket or user@host",
            "paste a `vallum1-join:` ticket or enter user@host",
        ));
    }
    let name = form.field("device name (optional)").trim();
    if !name.is_empty()
        && !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(field_error(
            "device name (optional)",
            "letters, digits, '.', '_', '-' only",
        ));
    }
    let account = form.field("account token (optional)").trim();
    let desk = form.field("desk endpoint (optional)").trim();
    if let Some(ticket) = target
        .split_whitespace()
        .find(|token| token.starts_with("vallum1-join:"))
    {
        if !account.is_empty()
            && (account.len() != 32 || !account.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(field_error(
                "account token (optional)",
                "the account number is 32 hex characters",
            ));
        }
        if !desk.is_empty() {
            if account.is_empty() {
                return Err(field_error(
                    "account token (optional)",
                    "a desk endpoint needs an account token",
                ));
            }
            crate::commands::account::parse_desk_endpoint(desk)
                .map_err(|e| field_error("desk endpoint (optional)", e.to_string()))?;
        }
        let stdin = if account.is_empty() {
            ticket.to_owned()
        } else {
            format!("{ticket}\n{account}")
        };
        let env = if desk.is_empty() {
            Vec::new()
        } else {
            vec![("VALLUM_DESK_ENDPOINT", desk.to_owned())]
        };
        Ok(JoinRequest {
            ops_args: vec!["join".to_owned()],
            stdin: Some(stdin),
            env,
        })
    } else {
        if !account.is_empty() {
            return Err(field_error(
                "account token (optional)",
                "a desk account token rides with a vallum1-join: ticket, not an SSH target",
            ));
        }
        if target.starts_with('-')
            || !target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':'))
        {
            return Err(field_error(
                "ticket or user@host",
                "not a ticket — enter a valid SSH host (user@host or alias)",
            ));
        }
        let mut args = vec!["setup-remote".to_owned(), target.to_owned()];
        if !name.is_empty() {
            args.push(name.to_owned());
        }
        Ok(JoinRequest {
            ops_args: args,
            stdin: None,
            env: Vec::new(),
        })
    }
}

/// Join this machine to a network: a pasted `vallum1-join:` ticket goes to
/// `vallum-ops join` on stdin (never in argv); anything else is an SSH target
/// for zero-custody enrolment via `vallum-ops setup-remote`.
fn join_network(_app: &mut App, form: &super::app::Form) -> FormResult {
    let request = join_request(form)?;
    let args: Vec<&str> = request.ops_args.iter().map(String::as_str).collect();
    let output = run_privileged_with_env(&args, request.stdin.as_deref(), &request.env)
        .map_err(|e| form_error(None, e))?;
    let summary = output
        .lines()
        .find(|line| line.contains("enrolled ") || line.contains("handshake with the server"))
        .unwrap_or("joined network and started tunnel service")
        .trim()
        .to_owned();
    Ok(summary)
}

/// Initialise this machine as a server through `vallum-ops setup-server`.
fn setup_server(_app: &mut App, form: &super::app::Form) -> FormResult {
    let address = form.field("tunnel subnet").trim();
    if !address.contains('/') {
        return Err(field_error(
            "tunnel subnet",
            "needs a prefix, e.g. 10.7.0.1/20",
        ));
    }
    parse_prefixes(address).map_err(|e| field_error("tunnel subnet", e))?;
    let listen = form.field("listen").trim();
    if !listen.is_empty() && listen.parse::<std::net::SocketAddr>().is_err() {
        return Err(field_error("listen", "must be IP:port, e.g. 0.0.0.0:51820"));
    }
    let endpoint = form.field("public endpoint (optional)").trim();
    if !endpoint.is_empty() {
        let valid = endpoint
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
        if !valid {
            return Err(field_error(
                "public endpoint (optional)",
                "must be host:port, e.g. vpn.example.com:51820",
            ));
        }
    }
    let output = run_privileged(&["setup-server", address, listen, endpoint], None)
        .map_err(|e| form_error(None, e))?;
    let summary = output
        .lines()
        .find(|line| line.contains("server ready") || line.contains("vallum0"))
        .unwrap_or("server initialized and service started")
        .trim()
        .to_owned();
    Ok(summary)
}

/// Close the temporary UDP 51821 enrolment responder on the selected
/// interface — the one-click tidy-up after a device joins.
pub fn close_enrollment(app: &mut App) {
    match run_privileged(&["enroll-off", &current_stem(app)], None) {
        Ok(_) => app.notify(format!(
            "enrolment responder closed for `{}` (UDP 51821)",
            current_stem(app)
        )),
        Err(error) => app.notify(error),
    }
}

/// The config stem the privileged verbs address, e.g. `vallum0`.
fn current_stem(app: &App) -> String {
    app.current()
        .and_then(|iface| {
            iface
                .config_path
                .as_ref()
                .and_then(|p| p.file_stem())
                .and_then(|s| s.to_str())
                .map(str::to_owned)
        })
        .or_else(|| app.current().map(|iface| iface.name.clone()))
        .unwrap_or_else(|| "vallum0".to_owned())
}

// ---------------------------------------------------------------------------
// Guidance: the machine says what it needs next
// ---------------------------------------------------------------------------

/// Recompute the suggestion strip from everything the app already knows plus
/// a few cheap systemd reads. Runs on the refresh cadence — never per frame.
pub fn recompute_suggestions(app: &mut App) {
    app.suggestions = crate::guidance::suggest(&facts(app));
}

/// The facts guidance reasons over, as this surface can see them.
fn facts(app: &App) -> crate::guidance::Facts {
    use crate::guidance::{Facts, PeerFact};

    let current = app.current();
    let stem = current.map(|_| current_stem(app));

    let peers: Vec<PeerFact> = current
        .and_then(|iface| iface.device.as_ref())
        .map(|device| {
            device
                .peers
                .iter()
                .map(|peer| {
                    PeerFact::from_observation(
                        &peer.name,
                        &peer.fingerprint,
                        &peer.endpoint,
                        peer.last_handshake
                            .map(|(sec, _)| app.now.saturating_sub(sec)),
                        peer.rotating,
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let role = current
        .and_then(|iface| iface.config_path.as_deref())
        .and_then(crate::guidance::role_from_config)
        .unwrap_or_else(|| crate::guidance::infer_role(&peers));

    Facts {
        // A socket-discovered interface has no config_path, but a daemon that
        // answers the control socket is definitionally running a config —
        // saying "no config" there would offer enrolment on a configured box.
        config_present: app
            .interfaces
            .iter()
            .any(|iface| iface.config_path.is_some() || iface.device.is_some()),
        role,
        unit_active: current
            .and_then(|iface| iface.service_state)
            .map(|state| state == ServiceState::Active),
        unit_enabled: stem.as_deref().and_then(crate::host::probes::unit_enabled),
        daemon_reachable: current.map(|iface| iface.device.is_some() && iface.error.is_none()),
        interface_present: current.map(|iface| iface.device.is_some()),
        peers,
        enrolment_open: stem
            .as_deref()
            .and_then(|s| unit_state(s, "vallum-enroll@"))
            .map(|state| state == ServiceState::Active),
        trial_armed: current
            .and_then(|iface| iface.guard_state)
            .map(|state| state == ServiceState::Active),
        unit_restarts: stem.as_deref().and_then(crate::host::probes::unit_restarts),
        sync_stale: app.sync_stale,
        ssh_hosts: crate::host::probes::ssh_host_count(),
    }
}

/// `vallum-ops sync --check`: a read — reports whether the host is behind the
/// checkout without changing it. Caches the verdict for the suggestion strip.
pub fn check_updates(app: &mut App) {
    match run_privileged(&["sync", "--check"], None) {
        Ok(text) => {
            let stale = text.contains("stale files found");
            app.sync_stale = Some(stale);
            recompute_suggestions(app);
            app.notify(if stale {
                "updates available — :sync host applies them".to_owned()
            } else {
                "host matches the checkout".to_owned()
            });
        }
        Err(error) => {
            app.sync_stale = None;
            app.notify(format!("sync check: {error}"));
        }
    }
}

/// `vallum-ops sync`: make the host match the build under test.
pub fn sync_host(app: &mut App) {
    match run_privileged(&["sync"], None) {
        Ok(text) => {
            app.sync_stale = Some(false);
            app.notify(crate::host::probes::sync_verdict(&text).to_owned());
            refresh(app);
        }
        Err(error) => app.notify(format!("sync: {error}")),
    }
}

/// `vallum-ops enable <stem>`: the interface rejoins at every boot.
pub fn enable_units(app: &mut App) {
    if app.current().is_none() {
        app.notify("no interface to enable");
        return;
    }
    let stem = current_stem(app);
    match run_privileged(&["enable", &stem], None) {
        Ok(_) => {
            app.notify(format!("`{stem}` starts at boot"));
            refresh(app);
        }
        Err(error) => app.notify(format!("enable: {error}")),
    }
}

/// `vallum-ops service restart <stem>`: the daemon-silent fix — bounce the
/// unit when systemd says up but the socket says nothing. Preferring the ops
/// dispatcher means an unprivileged console escalates through the narrow
/// door instead of printing a sudo command; configs systemd does not own
/// fall back to the in-process path.
pub fn restart_service(app: &mut App) {
    if app.current().is_none() {
        app.notify("no interface to restart");
        return;
    }
    let stem = current_stem(app);
    if run_privileged(&["service", "restart", &stem], None).is_ok() {
        app.notify(format!("restarting `{stem}`"));
        refresh_service_state(app);
        refresh(app);
        return;
    }
    restart_service_inner(app);
}

/// `vallum-ops disable <stem>` retires every unit for the interface — the
/// machine keeps its config but stops running the tunnel at boot. Confirmed
/// first: it is the "stop being a VPN node" button.
pub fn disable_units(app: &mut App) {
    if app.current().is_none() {
        app.notify("no interface to disable");
        return;
    }
    app.confirm = Some(super::app::Confirm {
        action: ConfirmAction::DisableUnits {
            stem: current_stem(app),
        },
        config: String::new(),
    });
}

/// Best-effort clipboard copy. Returns the channels that accepted the text so
/// the caller can report honestly — an OSC 52 write can only be reported as
/// *sent*; whether the terminal stores it is unverifiable.
pub fn copy_to_clipboard(text: &str) -> Vec<&'static str> {
    let mut channels = Vec::new();
    // 1. ANSI OSC 52 sequence (works over SSH, tmux, and modern terminal emulators)
    let encoded = base64_encode(text.as_bytes());
    let mut out = std::io::stdout();
    if write!(out, "\x1b]52;c;{encoded}\x07")
        .and_then(|()| out.flush())
        .is_ok()
    {
        channels.push("OSC 52");
    }

    // 2. Local display server clipboard for terminals with OSC 52 disabled.
    let helper = if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        Some(("wl-copy", Vec::<&str>::new()))
    } else if std::env::var_os("DISPLAY").is_some() {
        Some(("xclip", vec!["-selection", "clipboard"]))
    } else {
        None
    };
    if let Some((program, args)) = helper {
        if let Ok(mut child) = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            let written = child
                .stdin
                .take()
                .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
            if written && child.wait().is_ok_and(|status| status.success()) {
                channels.push(program);
            }
        }
    }
    channels
}

pub(crate) fn clipboard_report(channels: &[&'static str]) -> String {
    match channels {
        [] => "no clipboard channel worked".to_owned(),
        [single] if *single == "OSC 52" => {
            "sent to the terminal clipboard (OSC 52; paste may fail if the terminal strips it)"
                .to_owned()
        }
        list => format!("copied via {}", list.join(" + ")),
    }
}

pub fn yank_public_line(app: &mut App) {
    let (target_label, line) = if let Some(peer) = app.current_peer() {
        let label = if !peer.name.is_empty() {
            format!("peer '{}'", peer.name)
        } else {
            format!("peer {}", peer.fingerprint)
        };
        (label, peer.public_line.clone())
    } else if let Some(device) = app.current_device() {
        (
            format!("device {}", device.interface),
            device.public_line.clone(),
        )
    } else if let Some(interface) = app.current() {
        if let Some(config) = &interface.config_path {
            let cmd = format!("sudo vallum-quick up {}", config.display());
            let report = clipboard_report(&copy_to_clipboard(&cmd));
            app.notify(format!("start command {report}"));
            return;
        }
        app.notify("no public identity to copy");
        return;
    } else {
        app.notify("no public identity to copy");
        return;
    };

    if line.is_empty() {
        app.notify("public line is empty");
        return;
    }

    let report = clipboard_report(&copy_to_clipboard(&line));
    app.notify(format!("{target_label} public line {report}"));
}

pub fn yank_peer_address(app: &mut App) {
    if let Some(peer) = app.current_peer() {
        let label = if !peer.name.is_empty() {
            format!("peer '{}'", peer.name)
        } else {
            format!("peer {}", peer.fingerprint)
        };
        let target = if !peer.allowed_ips.is_empty() {
            peer.allowed_ips.join(", ")
        } else if !peer.endpoint.is_empty() {
            peer.endpoint.clone()
        } else {
            app.notify(format!("{label} has no IP or endpoint"));
            return;
        };
        let report = clipboard_report(&copy_to_clipboard(&target));
        app.notify(format!("{label} address ({target}) {report}"));
    } else if let Some(device) = app.current_device() {
        let target = if !device.addresses.is_empty() {
            device.addresses.join(", ")
        } else {
            device.listen.clone()
        };
        let report = clipboard_report(&copy_to_clipboard(&target));
        app.notify(format!("device address {report}"));
    } else if let Some(interface) = app.current() {
        if let Some(config) = &interface.config_path {
            let cmd = format!("sudo vallum-quick up {}", config.display());
            let report = clipboard_report(&copy_to_clipboard(&cmd));
            app.notify(format!("start command {report}"));
        } else {
            app.notify("no address to copy");
        }
    } else {
        app.notify("no address to copy");
    }
}

pub fn ping_peer(app: &mut App) {
    let Some(peer) = app.current_peer() else {
        app.notify("no peer selected to ping");
        return;
    };
    let Some(first_allowed) = peer.allowed_ips.first() else {
        let label = if !peer.name.is_empty() {
            &peer.name
        } else {
            &peer.fingerprint
        };
        app.notify(format!("peer '{label}' has no allowed IPs to ping"));
        return;
    };
    let target_ip = first_allowed
        .split('/')
        .next()
        .unwrap_or(first_allowed)
        .trim()
        .to_owned();
    if target_ip.is_empty() {
        app.notify("invalid allowed IP to ping");
        return;
    }
    if app.pending_ping.is_some() {
        app.notify("a ping is already running");
        return;
    }

    let target = target_ip.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = match Command::new("ping")
            .args(["-c", "1", "-W", "1", &target])
            .output()
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let time_str = stdout
                    .lines()
                    .find(|l| l.contains("time="))
                    .and_then(|l| l.split("time=").nth(1))
                    .and_then(|part| part.split_whitespace().next())
                    .unwrap_or("");
                if time_str.is_empty() {
                    format!("ping {target}: reply (online)")
                } else {
                    format!("ping {target}: reply in {time_str} ms")
                }
            }
            Ok(_) => format!("ping {target}: no reply (timed out)"),
            Err(err) => format!("ping {target}: {err}"),
        };
        let _ = sender.send(result);
    });
    app.pending_ping = Some(receiver);
    app.notify(format!("pinging {target_ip}…"));
}

pub(crate) fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_config_edit_opens_the_diff_view() {
        let dir = std::env::temp_dir().join(format!("vallum-diff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vallum0.toml");
        let original =
            "[interface]\nname = \"vallum0\"\nprivate_key = \"key\"\naddress = \"10.7.0.1/24\"\n";
        std::fs::write(&path, original).unwrap();
        let backup = dir.join("vallum0.toml.bak");
        std::fs::write(&backup, original).unwrap();
        std::fs::write(&path, format!("{original}# changed\n")).unwrap();
        let mut app = App::new(vec![super::super::app::Interface::new(
            "vallum0".to_owned(),
            Some(path),
            dir.join("control.sock"),
        )]);
        app.editor_backup = Some(backup);
        finish_edit_config(&mut app, &dir.join("vallum0.toml"));
        assert_eq!(app.view, super::super::app::View::Diff);
        assert!(app.diff.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_diff_marks_changed_lines() {
        let rows = build_diff("a\nb\n", "a\nc\n");
        assert!(rows
            .iter()
            .any(|row| row.kind == super::super::app::DiffKind::Replace));
        assert_eq!(rows.first().and_then(|row| row.left.as_deref()), Some("a"));
    }

    #[test]
    fn the_interface_form_writes_and_validates() {
        let dir = std::env::temp_dir().join(format!("vallum-interface-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vallum0.toml");
        std::fs::write(
            &path,
            "[interface]\nname = \"vallum0\"\nprivate_key = \"key\"\naddress = \"10.7.0.1/24\"\nlisten = \"0.0.0.0:51820\"\n",
        )
        .unwrap();
        let mut app = App::new(vec![super::super::app::Interface::new(
            "vallum0".to_owned(),
            Some(path.clone()),
            dir.join("control.sock"),
        )]);
        let form = super::super::app::Form::interface([
            "0.0.0.0:51821".to_owned(),
            "auto".to_owned(),
            "1400".to_owned(),
            "7".to_owned(),
            "10.7.0.1/24, fd00:7::1/64".to_owned(),
            "9.9.9.9".to_owned(),
            "auto".to_owned(),
        ]);
        // apply_interface_form should NOT write the config; it should ask for confirmation
        let msg = apply_interface_form(&mut app, &form).expect("apply");
        assert_eq!(msg, "Press Enter to apply config changes");
        assert!(app.confirm.is_some());
        assert!(matches!(
            app.confirm.as_ref().unwrap().action,
            super::super::app::ConfirmAction::ApplyConfig
        ));
        // The original config should NOT be modified yet
        let text_before = std::fs::read_to_string(&path).unwrap();
        assert!(text_before.contains("listen = \"0.0.0.0:51820\""));
        assert!(!text_before.contains("listen = \"0.0.0.0:51821\""));
        // Confirm should apply the config
        super::super::actions::confirm(&mut app);
        assert!(app.confirm.is_none());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("listen = \"0.0.0.0:51821\""));
        assert!(text.contains("carrier = \"auto\""));
        assert!(text.contains("mtu = 1400"));
        assert!(text.contains("10.7.0.1/24"));
        assert!(text.contains("9.9.9.9"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct FakeRunner {
        root: bool,
        calls: std::sync::Mutex<Vec<String>>,
        results: std::sync::Mutex<Vec<Result<(), String>>>,
    }

    impl FakeRunner {
        fn new(root: bool, results: Vec<Result<(), String>>) -> Self {
            Self {
                root,
                calls: std::sync::Mutex::new(Vec::new()),
                results: std::sync::Mutex::new(results),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ServiceRunner for FakeRunner {
        fn is_root(&self) -> bool {
            self.root
        }

        fn run(&self, program: &str, args: &[String]) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            self.results.lock().unwrap().remove(0)
        }
    }

    #[test]
    fn the_tui_uses_systemd_when_the_unit_owns_the_config() {
        // Only a config in /etc/vallum is read by the unit; anywhere else the
        // template exists but the instance would start with nothing.
        let app_interface = super::super::app::Interface::new(
            "fake".to_owned(),
            Some(std::path::PathBuf::from("/etc/vallum/fake.toml")),
            std::path::PathBuf::from("/tmp/control.sock"),
        );
        let mut app = App::new(vec![app_interface]);
        let runner = FakeRunner::new(true, vec![Ok(()), Ok(())]);
        toggle_service_with(&mut app, &runner);
        assert_eq!(
            runner.calls(),
            [
                "systemctl cat vallum@fake.service",
                "systemctl start vallum@fake.service",
            ]
        );
    }

    #[test]
    fn an_unprivileged_operator_is_handed_the_command_not_a_polkit_prompt() {
        let app_interface = super::super::app::Interface::new(
            "fake".to_owned(),
            Some(std::path::PathBuf::from("/etc/vallum/fake.toml")),
            std::path::PathBuf::from("/tmp/control.sock"),
        );
        let mut app = App::new(vec![app_interface]);
        let runner = FakeRunner::new(false, vec![Ok(())]);
        toggle_service_with(&mut app, &runner);
        // It asked systemd whether it owns the unit, then stopped: no start,
        // which is what used to raise the polkit dialog.
        assert_eq!(runner.calls(), ["systemctl cat vallum@fake.service"]);
        let toast = app
            .toast
            .as_ref()
            .expect("the operator is told what to run");
        assert!(
            toast
                .message
                .contains("sudo systemctl start vallum@fake.service"),
            "{}",
            toast.message
        );
    }

    #[test]
    fn the_tui_falls_back_to_quick_for_a_config_outside_etc() {
        // A config in /tmp is not read by any unit, so systemd is never asked.
        let app_interface = super::super::app::Interface::new(
            "fake".to_owned(),
            Some(std::path::PathBuf::from("/tmp/fake.toml")),
            std::path::PathBuf::from("/tmp/control.sock"),
        );
        let mut app = App::new(vec![app_interface]);
        let runner = FakeRunner::new(true, vec![Ok(())]);
        toggle_service_with(&mut app, &runner);
        assert_eq!(runner.calls(), ["vallum-quick up /tmp/fake.toml"]);
    }

    #[test]
    fn the_tui_shows_a_sudo_command_when_unprivileged() {
        let app_interface = super::super::app::Interface::new(
            "vallum0".to_owned(),
            Some(std::path::PathBuf::from("/tmp/fake.toml")),
            std::path::PathBuf::from("/tmp/control.sock"),
        );
        let mut app = App::new(vec![app_interface]);
        let runner = FakeRunner::new(false, vec![Ok(())]);
        toggle_service_with(&mut app, &runner);
        assert_eq!(runner.calls(), Vec::<String>::new());
        assert!(app
            .toast
            .as_ref()
            .is_some_and(|toast| toast.message.contains("sudo vallum-quick")));
    }

    #[test]
    fn the_service_plan_prefers_systemd() {
        let plan = service_plan(
            std::path::Path::new("/etc/vallum/vallum0.toml"),
            true,
            true,
            true,
        );
        assert_eq!(
            plan,
            ServicePlan::Systemd {
                unit: "vallum@vallum0.service".to_owned(),
                action: "stop",
            }
        );
    }

    #[test]
    fn the_service_plan_uses_quick_as_root() {
        let plan = service_plan(
            std::path::Path::new("/etc/vallum/vallum0.toml"),
            false,
            false,
            true,
        );
        assert!(matches!(plan, ServicePlan::Quick { action: "up", .. }));
        let plan = service_plan(
            std::path::Path::new("/etc/vallum/vallum0.toml"),
            true,
            false,
            true,
        );
        assert!(matches!(plan, ServicePlan::Quick { action: "down", .. }));
    }

    #[test]
    fn the_service_plan_shows_a_sudo_command_when_unprivileged() {
        let plan = service_plan(
            std::path::Path::new("/etc/vallum/vallum0.toml"),
            false,
            false,
            false,
        );
        let ServicePlan::Command(command) = plan else {
            panic!("expected a command");
        };
        assert!(command.starts_with("sudo vallum-quick up "));
    }
}
