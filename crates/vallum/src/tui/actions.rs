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

pub fn confirm_remove(app: &mut App) {
    let Some(confirm) = app.confirm.take() else {
        return;
    };
    let ConfirmAction::RemovePeer(index) = confirm.action;
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
    let directory = app
        .current()
        .and_then(|current| current.config_path.as_ref())
        .and_then(|path| path.parent())
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
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
    app.editor = Some(path);
}

pub fn export_bundle(app: &mut App) {
    let Some(device) = app.current_device().cloned() else {
        app.notify("no device to export");
        return;
    };
    let Some(peer) = app.current_peer().cloned() else {
        app.notify("select a peer first");
        return;
    };
    let Some(key_path) = app.pending_key.clone() else {
        app.notify("generate a key first (g), then add the peer");
        return;
    };
    match bundle::build(&device, &peer, &key_path) {
        Ok((bundle, path)) => {
            let json = match serde_json::to_string_pretty(&bundle) {
                Ok(json) => json,
                Err(error) => {
                    app.notify(error.to_string());
                    return;
                }
            };
            match qr::encode(&json, &path.display().to_string()) {
                Ok(state) => {
                    app.notify(format!("bundle written to {}", path.display()));
                    app.qr = Some(state);
                }
                Err(error) => app.notify(error),
            }
        }
        Err(error) => app.notify(error),
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
    let running = interface.device.is_some();
    let action = if running { "stop" } else { "start" };
    let status = Command::new("systemctl").args([action, &unit]).status();
    match status {
        Ok(status) if status.success() => {
            app.notify(format!("systemctl {action} {unit}"));
            refresh(app);
        }
        Ok(_) | Err(_) => {
            let quick = if running { "down" } else { "up" };
            if nix::unistd::geteuid().is_root() {
                match Command::new("vallum-quick").arg(quick).arg(config).status() {
                    Ok(status) if status.success() => {
                        app.notify(format!("vallum-quick {quick}"));
                        refresh(app);
                    }
                    _ => app.notify(format!("sudo vallum-quick {quick} {}", config.display())),
                }
            } else {
                app.notify(format!("sudo vallum-quick {quick} {}", config.display()));
            }
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
            app.logs = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::to_owned)
                .collect();
            app.view = View::Logs;
        }
        _ => app.notify(format!("no journal for {unit}; see the daemon log")),
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
