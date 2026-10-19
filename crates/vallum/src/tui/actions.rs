// SPDX-License-Identifier: Apache-2.0

//! Side effects: UAPI writes, key generation, service control, logs.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;

use vallum_tunnel::Prefix;

use crate::control;
use crate::entropy;
use crate::keys;
use crate::uapi::{self, Peer, Set};

use super::app::{App, ConfirmAction, FormKind, View};
use super::bundle;
use super::client;
use super::qr;

pub fn refresh(app: &mut App) {
    for interface in &mut app.interfaces {
        match client::fetch(&interface.control_path) {
            Ok(device) => interface.set_device(device),
            Err(error) => interface.set_error(error),
        }
    }
    app.last_refresh = std::time::Instant::now();
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
        FormKind::Interface => apply_interface_form(app, &form),
    };
    match result {
        Ok(message) => {
            app.form = None;
            app.notify(message);
            refresh(app);
        }
        Err(error) => app.notify(error),
    }
}

fn add_peer(app: &mut App, form: &super::app::Form) -> Result<String, String> {
    let device = app.current_device().ok_or("no device")?;
    let (suite, identity) =
        keys::decode_public(form.field("public line")).map_err(|error| error.to_string())?;
    if suite != device.suite_id {
        return Err(format!(
            "peer suite 0x{suite:04x} does not match device 0x{:04x}",
            device.suite_id
        ));
    }
    let endpoint = parse_endpoint(form.field("endpoint"))?;
    let allowed = parse_prefixes(form.field("allowed IPs"))?;
    if allowed.is_empty() {
        return Err("allowed IPs is empty".to_owned());
    }
    let keepalive = parse_keepalive(form.field("keepalive"))?;
    let psk = parse_psk(form.field("PSK (hex, optional)"))?;
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
    apply(app, &set)?;
    Ok("peer added".to_owned())
}

fn apply_device(app: &mut App, form: &super::app::Form) -> Result<String, String> {
    let port: u16 = form
        .field("listen port")
        .trim()
        .parse()
        .map_err(|_| "listen port is not a number".to_owned())?;
    let mark: u32 = form
        .field("fwmark")
        .trim()
        .parse()
        .map_err(|_| "fwmark is not a number".to_owned())?;
    let set = Set {
        private_key: None,
        listen_port: Some(port),
        fwmark: Some(mark),
        replace_peers: false,
        peers: Vec::new(),
    };
    apply(app, &set)?;
    Ok("runtime device updated".to_owned())
}

fn edit_peer(app: &mut App, form: &super::app::Form, index: usize) -> Result<String, String> {
    let peer = app
        .current_device()
        .and_then(|device| device.peers.get(index))
        .cloned()
        .ok_or("peer disappeared")?;
    let (suite, identity) =
        keys::decode_public(&peer.public_line).map_err(|error| error.to_string())?;
    let device = app.current_device().ok_or("no device")?;
    if suite != device.suite_id {
        return Err("peer suite does not match device".to_owned());
    }
    let endpoint = parse_endpoint(form.field("endpoint"))?;
    let allowed = parse_prefixes(form.field("allowed IPs"))?;
    if allowed.is_empty() {
        return Err("allowed IPs is empty".to_owned());
    }
    let keepalive = parse_keepalive(form.field("keepalive"))?;
    let psk = parse_psk(form.field("PSK (hex, blank = keep)"))?;
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
    apply(app, &set)?;
    Ok("peer updated".to_owned())
}

pub fn confirm(app: &mut App) {
    let Some(confirm) = app.confirm.take() else {
        return;
    };
    let ConfirmAction::RemovePeer(index) = confirm.action else {
        restart_service(app);
        return;
    };
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
            form.fields[0].value = line;
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

fn apply_interface_form(app: &mut App, form: &super::app::Form) -> Result<String, String> {
    let path = app
        .current()
        .and_then(|interface| interface.config_path.clone())
        .ok_or("no config path")?;
    let text = std::fs::read_to_string(&path).map_err(|error| format!("read config: {error}"))?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|error| format!("parse config: {error}"))?;
    if doc.get("interface").is_none() {
        doc["interface"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    let interface = doc["interface"]
        .as_table_mut()
        .ok_or("interface is not a table")?;
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
                .map_err(|_| format!("{label} is not a number"))?;
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
        if doc.get(table_name).is_none() {
            doc[table_name] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let table = doc[table_name]
            .as_table_mut()
            .ok_or_else(|| format!("{table_name} is not a table"))?;
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
    if doc.get("quick").is_none() {
        doc["quick"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    if let Some(table) = doc["quick"].as_table_mut() {
        set_string(table, "table", form.field("table"));
    }

    let candidate = path.with_extension("toml.new");
    std::fs::write(&candidate, doc.to_string()).map_err(|error| format!("write: {error}"))?;
    crate::config::Config::load(&candidate).map_err(|error| format!("invalid config: {error}"))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let backup = path.with_extension(format!("toml.bak.{stamp}"));
    std::fs::copy(&path, &backup).map_err(|error| format!("backup: {error}"))?;
    std::fs::rename(&candidate, &path).map_err(|error| format!("replace: {error}"))?;
    app.confirm = Some(super::app::Confirm {
        action: ConfirmAction::ApplyConfig,
    });
    Ok(format!("config written; backup {}", backup.display()))
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

fn finish_export(app: &mut App, form: &super::app::Form) -> Result<String, String> {
    let device = app.current_device().cloned().ok_or("no device")?;
    let peer = app.current_peer().cloned().ok_or("no peer")?;
    let key_path = app.pending_key.clone().ok_or("no generated key")?;
    let (bundle, path) = bundle::build(&device, &peer, &key_path, form.field("server endpoint"))?;
    let json = serde_json::to_string_pretty(&bundle).map_err(|error| error.to_string())?;
    let state = qr::encode(&json, &path.display().to_string())?;
    app.qr = Some(state);
    Ok(format!("bundle written to {}", path.display()))
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

pub fn toggle_service(app: &mut App) {
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
    let systemd = Command::new("systemctl")
        .args(["cat", &unit])
        .status()
        .is_ok_and(|status| status.success());
    let plan = service_plan(
        config,
        interface.device.is_some(),
        systemd,
        nix::unistd::geteuid().is_root(),
    );
    match plan {
        ServicePlan::Systemd { unit, action } => {
            match Command::new("systemctl").args([action, &unit]).status() {
                Ok(status) if status.success() => {
                    app.notify(format!("systemctl {action} {unit}"));
                    refresh(app);
                }
                _ => {
                    let quick = if interface.device.is_some() {
                        "down"
                    } else {
                        "up"
                    };
                    app.notify(format!("sudo vallum-quick {quick} {}", config.display()));
                }
            }
        }
        ServicePlan::Quick { action, config } => {
            match Command::new("vallum-quick")
                .arg(action)
                .arg(&config)
                .status()
            {
                Ok(status) if status.success() => {
                    app.notify(format!("vallum-quick {action}"));
                    refresh(app);
                }
                _ => app.notify(format!("sudo vallum-quick {action} {}", config.display())),
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

fn parse_endpoint(text: &str) -> Result<Option<SocketAddr>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if let Ok(address) = text.parse() {
        return Ok(Some(address));
    }
    text.to_socket_addrs()
        .map_err(|error| format!("endpoint: {error}"))?
        .next()
        .map(Some)
        .ok_or_else(|| "endpoint resolved to nothing".to_owned())
}

fn parse_prefixes(text: &str) -> Result<Vec<Prefix>, String> {
    text.split([',', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<Prefix>()
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
        apply_interface_form(&mut app, &form).expect("apply");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("listen = \"0.0.0.0:51821\""));
        assert!(text.contains("mtu = 1400"));
        assert!(text.contains("10.7.0.1/24"));
        assert!(text.contains("9.9.9.9"));
        let _ = std::fs::remove_dir_all(&dir);
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
