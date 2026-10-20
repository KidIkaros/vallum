// SPDX-License-Identifier: Apache-2.0

//! Side effects: UAPI writes, key generation, service control, logs.

use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;

use vallum_tunnel::Prefix;

use crate::control;
use crate::entropy;
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
            let state = interface
                .config_path
                .as_deref()
                .and_then(systemd_service_state);
            interface.set_service_state(state);
        }
    }
    app.last_refresh = std::time::Instant::now();
}

fn systemd_service_state(config: &std::path::Path) -> Option<ServiceState> {
    let stem = config.file_stem()?.to_str()?;
    let unit = format!("vallum@{stem}.service");
    let output = Command::new("systemctl")
        .args(["is-active", &unit])
        .output()
        .ok()?;
    ServiceState::parse(&String::from_utf8_lossy(&output.stdout))
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
        FormKind::EditPeer(index) => edit_peer(app, &form, index),
        FormKind::Device => apply_device(app, &form),
        FormKind::ExportBundle => finish_export(app, &form),
        FormKind::ImportBundle => finish_import_bundle(app, &form),
        FormKind::Interface => apply_interface_form(app, &form),
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
    restart_service(app);
}

fn restart_service(app: &mut App) {
    let Some(interface) = app.current() else {
        return;
    };
    let Some(config) = &interface.config_path else {
        app.notify("no config path to restart");
        return;
    };
    let stem = config
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0");
    let unit = format!("vallum@{stem}.service");
    if Command::new("systemctl")
        .args(["cat", &unit])
        .status()
        .is_ok_and(|status| status.success())
    {
        match Command::new("systemctl").args(["restart", &unit]).status() {
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
        .unwrap_or_else(|| "/etc/vallum".to_owned());
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
        std::path::Path::new("/etc/vallum")
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
    let stem = config
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0");
    let unit = format!("vallum@{stem}.service");
    let action = if running { "stop" } else { "start" };
    let quick = if running { "down" } else { "up" };
    if systemd {
        ServicePlan::Systemd { unit, action }
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
    let stem = config
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0");
    let unit = format!("vallum@{stem}.service");
    let systemd = runner
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
        ServicePlan::Command(command) => app.notify(command),
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
    let stem = config
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0");
    let unit = format!("vallum@{stem}.service");
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

pub(crate) fn parse_endpoint(text: &str) -> Result<Option<SocketAddr>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if let Ok(address) = text.parse() {
        return Ok(Some(address));
    }
    if !text.contains(':') || (text.starts_with('[') && !text.contains("]:")) {
        return Err(
            "endpoint must include a port (e.g. 198.51.100.1:51820 or vpn.example.com:51820)"
                .to_owned(),
        );
    }
    text.to_socket_addrs()
        .map_err(|error| format!("endpoint: {error} (check hostname and port)"))?
        .next()
        .map(Some)
        .ok_or_else(|| "endpoint resolved to nothing".to_owned())
}

pub fn copy_to_clipboard(text: &str) {
    // 1. ANSI OSC 52 sequence (works over SSH, tmux, and modern terminal emulators)
    let encoded = base64_encode(text.as_bytes());
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{encoded}\x07");
    let _ = out.flush();

    // 2. Best-effort fallback: local display server clipboard (wl-copy or xclip)
    // for Linux desktop terminals with OSC 52 disabled by default
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        if let Ok(mut child) = std::process::Command::new("wl-copy")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    } else if std::env::var_os("DISPLAY").is_some() {
        if let Ok(mut child) = std::process::Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
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
            copy_to_clipboard(&cmd);
            app.notify(format!("copied start command to clipboard: {cmd}"));
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

    copy_to_clipboard(&line);
    app.notify(format!("copied {target_label} public line to clipboard"));
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
        copy_to_clipboard(&target);
        app.notify(format!("copied {label} address ({target}) to clipboard"));
    } else if let Some(device) = app.current_device() {
        let target = if !device.addresses.is_empty() {
            device.addresses.join(", ")
        } else {
            device.listen.clone()
        };
        copy_to_clipboard(&target);
        app.notify(format!("copied device address ({target}) to clipboard"));
    } else if let Some(interface) = app.current() {
        if let Some(config) = &interface.config_path {
            let cmd = format!("sudo vallum-quick up {}", config.display());
            copy_to_clipboard(&cmd);
            app.notify(format!("copied start command to clipboard: {cmd}"));
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
        .trim();
    if target_ip.is_empty() {
        app.notify("invalid allowed IP to ping");
        return;
    }

    match Command::new("ping")
        .args(["-c", "1", "-W", "1", target_ip])
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
            if !time_str.is_empty() {
                app.notify(format!("ping {target_ip}: reply in {time_str} ms"));
            } else {
                app.notify(format!("ping {target_ip}: reply (online)"));
            }
        }
        Ok(_) => {
            app.notify(format!("ping {target_ip}: no reply (timed out)"));
        }
        Err(err) => {
            app.notify(format!("ping {target_ip}: {err}"));
        }
    }
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

pub(crate) fn parse_prefixes(text: &str) -> Result<Vec<Prefix>, String> {
    text.split([',', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let normalized = if !part.contains('/') {
                if part.parse::<std::net::Ipv4Addr>().is_ok() {
                    format!("{part}/32")
                } else if part.parse::<std::net::Ipv6Addr>().is_ok() {
                    format!("{part}/128")
                } else {
                    part.to_owned()
                }
            } else {
                part.to_owned()
            };
            normalized
                .parse::<Prefix>()
                .map_err(|error| format!("{part}: {error}"))
        })
        .collect()
}

fn parse_keepalive(text: &str) -> Result<Option<u16>, String> {
    let value = text.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let seconds: u16 = value
        .parse()
        .map_err(|_| "keepalive is not a number".to_owned())?;
    Ok((seconds > 0).then_some(seconds))
}

fn parse_psk(text: &str) -> Result<Option<[u8; 32]>, String> {
    let value = text.trim();
    if value.is_empty() {
        return Ok(None);
    }
    keys::parse_psk(value)
        .map(|psk| Some(*psk.as_bytes()))
        .map_err(|error| error.to_string())
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
    fn the_tui_uses_systemd_when_available() {
        let app_interface = super::super::app::Interface::new(
            "vallum0".to_owned(),
            Some(std::path::PathBuf::from("/tmp/fake.toml")),
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
    fn the_tui_falls_back_to_quick_as_root() {
        let app_interface = super::super::app::Interface::new(
            "vallum0".to_owned(),
            Some(std::path::PathBuf::from("/tmp/fake.toml")),
            std::path::PathBuf::from("/tmp/control.sock"),
        );
        let mut app = App::new(vec![app_interface]);
        let runner = FakeRunner::new(true, vec![Err("no unit".to_owned()), Ok(())]);
        toggle_service_with(&mut app, &runner);
        assert_eq!(
            runner.calls(),
            [
                "systemctl cat vallum@fake.service",
                "vallum-quick up /tmp/fake.toml",
            ]
        );
    }

    #[test]
    fn the_tui_shows_a_sudo_command_when_unprivileged() {
        let app_interface = super::super::app::Interface::new(
            "vallum0".to_owned(),
            Some(std::path::PathBuf::from("/tmp/fake.toml")),
            std::path::PathBuf::from("/tmp/control.sock"),
        );
        let mut app = App::new(vec![app_interface]);
        let runner = FakeRunner::new(false, vec![Err("no unit".to_owned())]);
        toggle_service_with(&mut app, &runner);
        assert_eq!(runner.calls(), ["systemctl cat vallum@fake.service"]);
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
