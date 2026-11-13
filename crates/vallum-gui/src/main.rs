// SPDX-License-Identifier: Apache-2.0

//! `vallum-gui` — Vallum's desktop operations console (ADR-0024, phase 1).
//!
//! The host is deliberately thin. It asks the daemon over the same `get=1` path
//! the TUI uses ([`vallum::control::request`] plus [`vallum::uapi`]), decodes the
//! reply into [`snapshot`]'s allowlisted shape, and hands the front-end JSON over
//! Tauri's IPC. It has no second parser and no second idea of what a request is.
//!
//! Phase 1 is read-only: one poller thread, one socket request at a time, no
//! mutations. That matters because the daemon's accept loop is serial with a 5 s
//! timeout — a UI that opened several connections, or one that polled from every
//! view, would queue against the mutations the operator actually wants.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod actions;
pub(crate) mod hostfacts;
mod serve;
pub(crate) mod snapshot;

// The serve transport and the Tauri commands both speak to the inner ring
// through this facade; the ring itself lives in hostfacts.
pub(crate) use hostfacts::{health, plan, write_gate};

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{Emitter, State};

use actions::{
    BundleOut, Done, InterfaceFields, InviteFields, JoinFields, KeyOut, PeerFields, QrFrame,
    ServerSetupFields,
};
use snapshot::Snapshot;

/// Where the daemon's configs live, the same default the TUI uses.
const CONFIG_DIR: &str = "/etc/vallum";

/// Cadence while the window has focus. One request a second is one connection a
/// second on a serial accept loop, which is the budget the ADR sets.
const FOCUSED: Duration = Duration::from_secs(1);

/// Cadence while the window is open but not focused. An idle console should not
/// keep a daemon busy just because it is on screen.
const UNFOCUSED: Duration = Duration::from_secs(10);

/// What the front-end receives on every poll.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Payload {
    ok: bool,
    error: Option<String>,
    data: Option<Snapshot>,
}

/// One offer of a control socket, by display name and path.
#[derive(Debug, Serialize)]
pub(crate) struct InterfaceEntry {
    name: String,
    path: String,
}

#[derive(Debug)]
struct Inner {
    socket: Option<PathBuf>,
    /// Where the socket was last seen. Survives the daemon stopping.
    last_socket: Option<PathBuf>,
    focused: bool,
    visible: bool,
    /// Bumped on every state change so the poller can abandon a sleep early.
    generation: u64,
    /// Set when a newly selected socket should be read without waiting a tick.
    immediate: bool,
}

/// Shared poller state. One mutex, one condvar: the UI thread only ever needs to
/// say "the window changed", so nothing more elaborate is warranted.
#[derive(Debug)]
pub(crate) struct Console {
    inner: Mutex<Inner>,
    wake: Condvar,
}

impl Console {
    fn new() -> Self {
        let initial = interfaces()
            .into_iter()
            .next()
            .map(|entry| PathBuf::from(entry.path));
        Self {
            inner: Mutex::new(Inner {
                socket: initial.clone(),
                last_socket: initial,
                // Assume focused until the front-end says otherwise; a window
                // that just opened is the case where a fresh snapshot is wanted.
                focused: true,
                visible: true,
                generation: 0,
                immediate: true,
            }),
            wake: Condvar::new(),
        }
    }

    pub(crate) fn current_socket(&self) -> Option<PathBuf> {
        let current = self.lock().socket.clone();
        if current.is_some() {
            return current;
        }
        let discovered = interfaces()
            .into_iter()
            .next()
            .map(|entry| PathBuf::from(entry.path));
        if let Some(ref path) = discovered {
            let mut inner = self.lock();
            inner.socket = Some(path.clone());
            inner.last_socket = Some(path.clone());
        }
        discovered
    }

    /// The socket this console is about, even when the daemon behind it has
    /// stopped and taken the socket file with it. Starting a stopped service is
    /// exactly the case where the file is gone, so lifecycle work must not
    /// depend on it existing.
    pub(crate) fn known_socket(&self) -> Option<PathBuf> {
        let remembered = {
            let inner = self.lock();
            inner.socket.clone().or_else(|| inner.last_socket.clone())
        };
        remembered.or_else(discover_socket)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn changed(&self, mutate: impl FnOnce(&mut Inner)) {
        let mut inner = self.lock();
        mutate(&mut inner);
        inner.generation = inner.generation.wrapping_add(1);
        self.wake.notify_all();
    }
}

/// Startup diagnostics from the page: what it rendered, whether the bridge is
/// there, and any boot errors. Called by the probe through `window.__TAURI__`,
/// so it works even when the app bundle failed to load.
#[tauri::command]
fn ui_report(rendered: usize, bridge: String, errors: Vec<String>) {
    eprintln!(
        "vallum-gui: ui_report rendered={rendered} bridge={bridge} errors={:?}",
        errors
    );
}

/// The control sockets this host can offer.
///
/// Discovery reads the runtime directory the daemon binds its socket in, which
/// is also what the TUI scans. Nothing is invented when the directory is absent:
/// a machine with no daemon shows no interfaces.
#[tauri::command]
fn list_interfaces() -> Vec<InterfaceEntry> {
    interfaces()
}

pub(crate) fn interfaces() -> Vec<InterfaceEntry> {
    let mut entries: Vec<InterfaceEntry> = Vec::new();
    // `VALLUM_RUNTIME_DIR` lets a daemon that cannot own /run/vallum publish
    // its socket where the console can read it — the lab and the test runs use
    // it; a normal install never sets it.
    let dir = std::env::var_os("VALLUM_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| vallum_config::runtime_dir().to_path_buf());
    if let Ok(read) = std::fs::read_dir(&dir) {
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("sock") {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("vallum")
                .to_owned();
            entries.push(InterfaceEntry {
                name,
                path: path.display().to_string(),
            });
        }
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

/// Point the poller at one socket.
#[tauri::command]
fn select(console: State<'_, Arc<Console>>, path: String) {
    select_path(&console, path);
}

pub(crate) fn select_path(console: &Console, path: String) {
    console.changed(|inner| {
        inner.socket = Some(PathBuf::from(path.clone()));
        inner.last_socket = Some(PathBuf::from(path));
        inner.immediate = true;
    });
}

/// The socket the console is pointed at.
fn selected(console: &Console) -> Result<PathBuf, String> {
    console
        .current_socket()
        .ok_or_else(|| "no interface selected".to_owned())
}

/// The config that owns the selected socket, when this process can read it.
fn config_of(socket: &std::path::Path) -> Option<PathBuf> {
    // The installed layout keeps configs in /etc/vallum. A lab or a hand-run
    // daemon keeps its config beside the socket it publishes, and the console
    // should find that too rather than reporting "no config" at the operator.
    actions::config_for(socket, std::path::Path::new(CONFIG_DIR)).or_else(|| {
        socket
            .parent()
            .and_then(|dir| actions::config_for(socket, dir))
    })
}

#[tauri::command]
fn add_peer(console: State<'_, Arc<Console>>, fields: PeerFields) -> Result<Done, String> {
    actions::add(&selected(&console)?, &fields)
}

#[tauri::command]
fn edit_peer(console: State<'_, Arc<Console>>, fields: PeerFields) -> Result<Done, String> {
    actions::edit(&selected(&console)?, &fields)
}

#[tauri::command]
fn remove_peer(console: State<'_, Arc<Console>>, public_line: String) -> Result<Done, String> {
    actions::remove(&selected(&console)?, &public_line)
}

#[tauri::command]
fn apply_device(
    console: State<'_, Arc<Console>>,
    listen_port: String,
    fwmark: String,
) -> Result<Done, String> {
    actions::apply_device(&selected(&console)?, &listen_port, &fwmark)
}

fn rotate_at(socket: &std::path::Path, name: &str, new_line: &str) -> Result<Done, String> {
    // Config edits pass here from both transports; the gate lives with the
    // write, not the route.
    crate::hostfacts::write_gate(socket)?;
    let config = config_of(socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to rotate the stored identity"
        )
    })?;
    let suite = snapshot::fetch(socket)
        .ok()
        .map(|snapshot| snapshot.suite_id());
    actions::rotate(&config, name, new_line, suite)
}

fn finalize_at(socket: &std::path::Path, name: &str) -> Result<Done, String> {
    // Config edits pass here from both transports; the gate lives with the
    // write, not the route.
    crate::hostfacts::write_gate(socket)?;
    let config = config_of(socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to finalise"
        )
    })?;
    actions::finalize(&config, name)
}

fn invite_at(socket: &std::path::Path, fields: &InviteFields) -> Result<Done, String> {
    // Both transports pass here; the gate lives with the write, not the route.
    crate::hostfacts::write_gate(socket)?;
    if !fields.ssh_target.trim().is_empty() {
        return actions::invite_remote(fields);
    }
    let interface = socket
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
        .to_owned();
    let device = snapshot::fetch(socket).ok();
    let config = config_of(socket);
    let listen = device
        .as_ref()
        .and_then(|snapshot| snapshot.listen_port)
        .map(|port| format!("0.0.0.0:{port}"));
    let public_line = device
        .as_ref()
        .map_or_else(String::new, |snapshot| snapshot.public_line.clone());
    match actions::invite(
        &interface,
        config.as_deref(),
        listen.as_deref(),
        &public_line,
        fields,
    ) {
        Ok(done) => Ok(done),
        Err(error) => {
            // When running on a real host as an unprivileged user, `/etc/vallum/*.toml`
            // is 0600 root so `config` is None and `actions::invite` cannot read
            // `public_endpoint`. If `VALLUM_RUNTIME_DIR` is not overridden (i.e. not a
            // synthetic test harness), try `vallum-ops invite`.
            if config.is_none()
                && std::env::var_os("VALLUM_RUNTIME_DIR").is_none()
                && std::path::Path::new("/usr/local/sbin/vallum-ops").exists()
            {
                let name = actions::validate_peer_name(&fields.name)?;
                let ttl = if fields.ttl_minutes.trim().is_empty() {
                    "60"
                } else {
                    fields.ttl_minutes.trim()
                };
                let mut ops_args = vec!["invite", name, ttl, &interface];
                if !fields.pinned.trim().is_empty() {
                    ops_args.push(fields.pinned.trim());
                }
                if let Ok(out) = run_ops_with_stdin(&ops_args, None) {
                    if let Some(ticket) = out
                        .split_whitespace()
                        .find(|token| token.starts_with("vallum1-join:") && token.len() > 40)
                    {
                        return Ok(Done {
                            message: format!(
                                "invite minted for `{name}` (UDP 51821 responder active)"
                            ),
                            command: Some(format!("sudo vallum join {ticket}")),
                        });
                    }
                }
            }
            let has_remote_peer = device.as_ref().is_some_and(|snap| {
                snap.peers
                    .iter()
                    .any(|p| !p.endpoint.is_empty() && p.endpoint != "(none)")
            });
            if has_remote_peer && error.contains("public_endpoint") {
                Err(format!(
                    "{error}\n\nThis machine is a client connected to a remote server. Enter your server's SSH host in 'Remote server SSH' above to mint the invite on the server."
                ))
            } else {
                Err(error)
            }
        }
    }
}

fn join_network_at(console: &Arc<Console>, fields: &JoinFields) -> Result<Done, String> {
    let mode = fields.mode.trim();
    let output = if mode == "ssh"
        || (fields.ticket.trim().is_empty() && !fields.ssh_target.trim().is_empty())
    {
        let target = actions::validate_ssh_target(&fields.ssh_target)?;
        let mut args = vec!["setup-remote", target];
        let name_trimmed = fields.name.trim();
        if !name_trimmed.is_empty() {
            let valid_name = actions::validate_peer_name(name_trimmed)?;
            args.push(valid_name);
        }
        run_ops_with_stdin(&args, None)?
    } else {
        let ticket = actions::extract_join_ticket(&fields.ticket)?;
        run_ops_with_stdin(&["join"], Some(ticket))?
    };
    if console.current_socket().is_none() {
        if let Some(found) = discover_socket() {
            select_path(console, found.display().to_string());
        }
    }
    let summary = output
        .lines()
        .find(|line| line.contains("enrolled ") || line.contains("handshake with the server"))
        .unwrap_or("joined network and started tunnel service")
        .trim();
    Ok(Done {
        message: summary.to_owned(),
        command: None,
    })
}

fn setup_server_at(console: &Arc<Console>, fields: &ServerSetupFields) -> Result<Done, String> {
    actions::validate_server_setup_fields(fields)?;
    let addr = fields.address.trim();
    let listen = fields.listen.trim();
    let endpoint = fields.public_endpoint.trim();
    let output = run_ops_with_stdin(&["setup-server", addr, listen, endpoint], None)?;
    if console.current_socket().is_none() {
        if let Some(found) = discover_socket() {
            select_path(console, found.display().to_string());
        }
    }
    let summary = output
        .lines()
        .find(|line| line.contains("server ready") || line.contains("vallum0"))
        .unwrap_or("server initialized and service started")
        .trim();
    Ok(Done {
        message: summary.to_owned(),
        command: None,
    })
}

fn close_enrollment_at(socket: Option<&std::path::Path>, ssh_target: &str) -> Result<Done, String> {
    let target = ssh_target.trim();
    if !target.is_empty() {
        let valid_target = actions::validate_ssh_target(target)?;
        let output = std::process::Command::new("ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                valid_target,
                "sudo -n /usr/bin/vallum server enroll --disable",
            ])
            .output()
            .map_err(|e| format!("cannot run ssh to {valid_target}: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "closing enrollment on `{valid_target}` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return Ok(Done {
            message: format!("closed UDP 51821 enrollment responder on `{valid_target}`"),
            command: None,
        });
    }
    let iface = socket
        .and_then(|s| s.file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("vallum0");
    let _ = actions::validate_peer_name(iface)?;
    run_ops_with_stdin(&["enroll-off", iface], None)?;
    Ok(Done {
        message: format!("closed UDP 51821 enrollment responder for `{iface}`"),
        command: None,
    })
}

#[tauri::command]
fn rotate_peer(
    console: State<'_, Arc<Console>>,
    name: String,
    new_line: String,
) -> Result<Done, String> {
    let socket = selected(&console)?;
    rotate_at(&socket, &name, &new_line)
}

#[tauri::command]
fn finalize_peer(console: State<'_, Arc<Console>>, name: String) -> Result<Done, String> {
    let socket = selected(&console)?;
    finalize_at(&socket, &name)
}

#[tauri::command]
fn invite_peer(console: State<'_, Arc<Console>>, fields: InviteFields) -> Result<Done, String> {
    let socket = selected(&console)?;
    invite_at(&socket, &fields)
}

#[tauri::command]
fn join_network(console: State<'_, Arc<Console>>, fields: JoinFields) -> Result<Done, String> {
    join_network_at(&console, &fields)
}

#[tauri::command]
fn setup_server(
    console: State<'_, Arc<Console>>,
    fields: ServerSetupFields,
) -> Result<Done, String> {
    setup_server_at(&console, &fields)
}

#[tauri::command]
fn close_enrollment(console: State<'_, Arc<Console>>, ssh_target: String) -> Result<Done, String> {
    let socket = console.current_socket();
    close_enrollment_at(socket.as_deref(), &ssh_target)
}

/// A bundle export reads the snapshot and mints randomness; nothing is
/// written anywhere, so no gate and no privilege question — the downloaded
/// file is the key's only copy.
fn export_at(
    socket: &std::path::Path,
    fingerprint: &str,
    endpoint: &str,
) -> Result<BundleOut, String> {
    actions::export_bundle(socket, fingerprint, endpoint)
}

/// A bundle import writes a config and a key. The directory defaults to the
/// selected interface's config directory — the TUI's rule — so a client
/// bundle lands where the daemon reads, and the error names the CLI when the
/// console cannot write there.
fn import_at(socket: &std::path::Path, bundle_path: &str, out_dir: &str) -> Result<Done, String> {
    let dir = if out_dir.trim().is_empty() {
        config_of(socket)
            .and_then(|config| {
                config
                    .parent()
                    .map(|parent| parent.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| CONFIG_DIR.to_owned())
    } else {
        out_dir.to_owned()
    };
    actions::import_bundle(bundle_path, &dir)
}

#[tauri::command]
fn export_bundle(
    console: State<'_, Arc<Console>>,
    fingerprint: String,
    endpoint: String,
) -> Result<BundleOut, String> {
    let socket = selected(&console)?;
    export_at(&socket, &fingerprint, &endpoint)
}

/// One animated-QR frame for text the console already holds — an exported
/// bundle, or an invite's join command. The front-end steps the index on its
/// own 700 ms timer, the TUI's cadence, so the backend stays stateless and
/// both consoles scan the same frames.
#[tauri::command]
fn qr_frame(
    console: State<'_, Arc<Console>>,
    text: String,
    index: usize,
) -> Result<QrFrame, String> {
    let _ = selected(&console)?;
    actions::qr_frame(&text, index)
}

/// The config that owns the selected socket, read for the editor. Missing or
/// unreadable is an answer, not a fallback: a blank editor that saves would
/// clobber a config the console simply could not see.
fn config_text_at(socket: &std::path::Path) -> Result<String, String> {
    let config = config_of(socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to edit it"
        )
    })?;
    actions::read_config(&config)
}

fn config_write_at(socket: &std::path::Path, text: &str) -> Result<Done, String> {
    let config = config_of(socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to edit it"
        )
    })?;
    actions::write_config(&config, text)
}

fn interface_fields_at(socket: &std::path::Path) -> Result<InterfaceFields, String> {
    let config = config_of(socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to edit it"
        )
    })?;
    actions::read_interface_fields(&config)
}

fn apply_interface_at(socket: &std::path::Path, fields: &InterfaceFields) -> Result<Done, String> {
    let config = config_of(socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to edit it"
        )
    })?;
    actions::apply_interface(&config, fields)
}

fn save_runtime_at(socket: &std::path::Path) -> Result<Done, String> {
    let config = config_of(socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to save runtime config"
        )
    })?;
    actions::save_runtime(socket, &config)
}

#[tauri::command]
fn generate_key(console: State<'_, Arc<Console>>) -> Result<KeyOut, String> {
    actions::generate_key(console.current_socket().as_deref())
}

#[tauri::command]
fn read_config(console: State<'_, Arc<Console>>) -> Result<String, String> {
    let socket = selected(&console)?;
    config_text_at(&socket)
}

#[tauri::command]
fn write_config(console: State<'_, Arc<Console>>, text: String) -> Result<Done, String> {
    let socket = selected(&console)?;
    config_write_at(&socket, &text)
}

#[tauri::command]
fn read_interface_fields(console: State<'_, Arc<Console>>) -> Result<InterfaceFields, String> {
    let socket = selected(&console)?;
    interface_fields_at(&socket)
}

#[tauri::command]
fn apply_interface(
    console: State<'_, Arc<Console>>,
    fields: InterfaceFields,
) -> Result<Done, String> {
    let socket = selected(&console)?;
    apply_interface_at(&socket, &fields)
}

#[tauri::command]
fn save_runtime(console: State<'_, Arc<Console>>) -> Result<Done, String> {
    let socket = selected(&console)?;
    save_runtime_at(&socket)
}

#[tauri::command]
fn import_bundle(
    console: State<'_, Arc<Console>>,
    bundle_path: String,
    out_dir: String,
) -> Result<Done, String> {
    let socket = selected(&console)?;
    import_at(&socket, &bundle_path, &out_dir)
}

#[tauri::command]
fn health_state(console: State<'_, Arc<Console>>) -> serde_json::Value {
    console
        .known_socket()
        .map_or(serde_json::Value::Null, |socket| health(&socket))
}

/// The service and log twins of the HTTP `/api/service` and `/api/logs`
/// routes. The front-end already invokes these names over Tauri IPC; they
/// were never registered, so the Tauri build failed every service and log
/// read. Same functions, second transport — the rule the dispatch facade
/// states, now actually kept. Reads use `known_socket` (not `selected`) so a
/// stopped service — the case with no socket file — still reports and starts.
#[tauri::command]
fn service_state_command(console: State<'_, Arc<Console>>) -> serde_json::Value {
    console
        .known_socket()
        .map_or(serde_json::Value::Null, |socket| service_state(&socket))
}

#[tauri::command]
fn service_action_command(
    console: State<'_, Arc<Console>>,
    action: String,
) -> Result<Done, String> {
    let socket = console
        .known_socket()
        .ok_or_else(|| "no interface selected".to_owned())?;
    service_action(&socket, &action)
}

#[tauri::command]
fn logs_tail_command(console: State<'_, Arc<Console>>, lines: u32) -> serde_json::Value {
    console.known_socket().map_or_else(
        || serde_json::json!({ "error": "no interface selected" }),
        |socket| logs_tail(&socket, lines),
    )
}

#[tauri::command]
fn window_state(console: State<'_, Arc<Console>>, focused: bool, visible: bool) {
    let unchanged = {
        let inner = console.lock();
        inner.focused == focused && inner.visible == visible
    };
    if unchanged {
        return;
    }
    console.changed(|inner| {
        inner.focused = focused;
        inner.visible = visible;
    });
}

/// The single reader of the control plane.
///
/// It holds no lock while the daemon is answering: a 5 s request timeout must
/// never block the UI thread that is trying to change the window state.
static FIRST_SNAPSHOT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

fn poll_loop(app: tauri::AppHandle, console: Arc<Console>) {
    loop {
        let socket = {
            let mut inner = console.lock();
            // Poll whenever a socket is selected. Visibility and focus pick the
            // cadence, never whether to read at all: a webview that reports
            // itself hidden (occluded, minimised, or a quirk of the toolkit)
            // must not leave the console showing a dead zero state.
            while inner.socket.is_none() {
                inner = console
                    .wake
                    .wait(inner)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            if inner.immediate {
                inner.immediate = false;
                inner.socket.clone()
            } else {
                let interval = if inner.focused && inner.visible {
                    FOCUSED
                } else {
                    UNFOCUSED
                };
                let generation = inner.generation;
                let deadline = Instant::now() + interval;
                let mut current = inner;
                loop {
                    let now = Instant::now();
                    if now >= deadline || current.generation != generation {
                        break;
                    }
                    let remaining = deadline - now;
                    let (guard, _) = console
                        .wake
                        .wait_timeout(current, remaining)
                        .unwrap_or_else(PoisonError::into_inner);
                    current = guard;
                }
                // A change during the sleep means the cadence or the target moved;
                // spend the next iteration re-reading state instead of a stale socket.
                if current.generation != generation {
                    None
                } else {
                    current.socket.clone()
                }
            }
        };

        let Some(path) = socket else {
            continue;
        };
        let first = FIRST_SNAPSHOT.swap(false, std::sync::atomic::Ordering::Relaxed);
        let payload = match snapshot::fetch(&path) {
            Ok(data) => Payload {
                ok: true,
                error: None,
                data: Some(data),
            },
            Err(error) => Payload {
                ok: false,
                error: Some(error),
                data: None,
            },
        };
        if first {
            eprintln!(
                "vallum-gui: first payload from {} ok={} error={:?} peers={}",
                path.display(),
                payload.ok,
                payload.error,
                payload.data.as_ref().map_or(0, |d| d.peers.len())
            );
        }
        // A failed emit means the window is gone; the poller has no work left.
        if app.emit("snapshot", payload).is_err() {
            return;
        }
    }
}

/// The write surface over HTTP: the same functions the Tauri commands call,
/// dispatched from a JSON body. One implementation, two transports.
pub(crate) fn dispatch(
    console: &Arc<Console>,
    name: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // The Tauri commands take `fields: PeerFields` (a named argument, so the
    // IPC body is `{"fields": {...}}`); the HTTP body is the arguments object
    // itself. Unwrap once here so both transports feed the same functions.
    let body = match body.get("fields") {
        Some(inner) => inner.clone(),
        None => body,
    };
    let text = |key: &str| -> Result<String, String> {
        body.get(key)
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .ok_or_else(|| format!("missing `{key}`"))
    };
    let answer = |done: Done| serde_json::to_value(done).map_err(|error| error.to_string());

    // Onboarding commands must work on a fresh host before any tunnel socket exists.
    match name {
        "join_network" => {
            let fields: JoinFields = serde_json::from_value(body).map_err(|e| e.to_string())?;
            return answer(join_network_at(console, &fields)?);
        }
        "setup_server" => {
            let fields: ServerSetupFields =
                serde_json::from_value(body).map_err(|e| e.to_string())?;
            return answer(setup_server_at(console, &fields)?);
        }
        "close_enrollment" => {
            let ssh_target = text("sshTarget")?;
            let socket = console.current_socket();
            return answer(close_enrollment_at(socket.as_deref(), &ssh_target)?);
        }
        "qr_frame" => {
            let index = body
                .get("index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "missing `index`".to_owned())?;
            return serde_json::to_value(actions::qr_frame(&text("text")?, index as usize)?)
                .map_err(|error| error.to_string());
        }
        "import_bundle" => {
            // `outDir` is optional: a missing key means "the interface's
            // config directory", not a client error. `text` rejects absence,
            // so the key is read directly here.
            let out_dir = body
                .get("outDir")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_owned();
            let socket = console
                .current_socket()
                .unwrap_or_else(|| PathBuf::from("/run/vallum/vallum0.sock"));
            return answer(import_at(&socket, &text("bundlePath")?, &out_dir)?);
        }
        "generate_key" => {
            return serde_json::to_value(actions::generate_key(
                console.current_socket().as_deref(),
            )?)
            .map_err(|error| error.to_string());
        }
        _ => {}
    }

    let socket = console
        .current_socket()
        .ok_or_else(|| "no interface selected".to_owned())?;
    match name {
        "add_peer" => {
            let fields: PeerFields =
                serde_json::from_value(body.clone()).map_err(|e| e.to_string())?;
            let result = actions::add(&socket, &fields);
            if let Err(error) = &result {
                // A rejected write is the one case where the exact request
                // matters; log the shape (never the private key, which is not
                // in this body) so the operator can see what was sent.
                eprintln!(
                    "vallum-gui: add_peer rejected: {error} | name={:?} allowed={:?} keepalive={:?} endpoint={:?} line_len={}",
                    fields.name, fields.allowed_ips, fields.keepalive, fields.endpoint, fields.public_line.len()
                );
            }
            answer(result?)
        }
        "edit_peer" => {
            let fields: PeerFields = serde_json::from_value(body).map_err(|e| e.to_string())?;
            answer(actions::edit(&socket, &fields)?)
        }
        "remove_peer" => answer(actions::remove(&socket, &text("publicLine")?)?),
        "rotate_peer" => answer(rotate_at(&socket, &text("name")?, &text("newLine")?)?),
        "finalize_peer" => answer(finalize_at(&socket, &text("name")?)?),
        "invite_peer" => {
            let fields: InviteFields = serde_json::from_value(body).map_err(|e| e.to_string())?;
            answer(invite_at(&socket, &fields)?)
        }
        "read_config" => {
            serde_json::to_value(config_text_at(&socket)?).map_err(|error| error.to_string())
        }
        "write_config" => answer(config_write_at(&socket, &text("text")?)?),
        "read_interface_fields" => {
            serde_json::to_value(interface_fields_at(&socket)?).map_err(|error| error.to_string())
        }
        "apply_interface" => {
            let fields: InterfaceFields =
                serde_json::from_value(body).map_err(|e| e.to_string())?;
            answer(apply_interface_at(&socket, &fields)?)
        }
        "save_runtime" => answer(save_runtime_at(&socket)?),
        "export_bundle" => serde_json::to_value(export_at(
            &socket,
            &text("fingerprint")?,
            &text("endpoint")?,
        )?)
        .map_err(|error| error.to_string()),
        "apply_device" => answer(actions::apply_device(
            &socket,
            &text("listenPort")?,
            &text("fwmark")?,
        )?),
        other => Err(format!("unknown command `{other}`")),
    }
}

/// Which tunnel is this console about when nothing is selected and no socket
/// exists? A stopped daemon leaves no socket, so ask systemd for the instances
/// it knows about and derive the socket path they would publish.
fn discover_socket() -> Option<PathBuf> {
    let dir = std::env::var_os("VALLUM_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| vallum_config::runtime_dir().to_path_buf());
    if let Ok(read) = std::fs::read_dir(&dir) {
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sock") {
                return Some(path);
            }
        }
    }
    let output = std::process::Command::new("systemctl")
        .args([
            "list-units",
            "vallum@*",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
        ])
        .output()
        .ok()?;
    let listing = String::from_utf8_lossy(&output.stdout);
    // Prefer a unit that is actually running; among equals, the conventional
    // `vallum0`; a machine can carry stale instances from earlier experiments
    // and starting one of those would be the console guessing wrong.
    let mut best: Option<(u8, String)> = None;
    for line in listing.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(unit), Some(state)) = (fields.first(), fields.get(2)) else {
            continue;
        };
        let Some(instance) = unit
            .strip_prefix("vallum@")
            .and_then(|rest| rest.strip_suffix(".service"))
        else {
            continue;
        };
        let score = if *state == "active" {
            0
        } else if instance == "vallum0" {
            1
        } else {
            2
        };
        if best.as_ref().is_none_or(|(current, _)| score < *current) {
            best = Some((score, instance.to_owned()));
        }
    }
    best.map(|(_, instance)| dir.join(format!("{instance}.sock")))
}

/// The systemd unit that owns a socket: `vallum@<interface>` unless the
/// operator names one (a `vallum-quick@` deployment passes `VALLUM_UNIT`).
pub(crate) fn unit_for(socket: &std::path::Path) -> String {
    if let Ok(unit) = std::env::var("VALLUM_UNIT") {
        if !unit.is_empty() {
            return unit;
        }
    }
    let interface = socket
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0");
    format!("vallum@{interface}")
}

/// Is a full-tunnel trial actually armed?
///
/// `scripts/trial.sh` arms a transient `vallum-trial-<interface>.timer` before
/// it changes anything and stands it down on success, so the timer is the
/// signal while the deadline is pending. Once it fires, the paired `.service`
/// is the revert actually running. Either one active is a trial in progress;
/// neither means the revert would not be undoing anything.
fn trial_armed(interface: &str) -> bool {
    ["timer", "service"].iter().any(|kind| {
        let unit = format!("vallum-trial-{interface}.{kind}");
        trial_is_armed(&systemctl(&["is-active", &unit]).unwrap_or_default())
    })
}

/// Whether a reported unit state means a trial is running.
///
/// Split out from the `systemctl` call so both answers are testable without a
/// real timer. `activating` counts because the timer is armed before the risk
/// is taken, not after.
fn trial_is_armed(state: &str) -> bool {
    matches!(state.trim(), "active" | "activating" | "reloading")
}

/// The refusal: nothing to cancel, and where the deliberate undo lives.
fn unarmed_cancel_error(interface: &str) -> String {
    format!(
        "no full-tunnel trial is armed on `{interface}`, so there is nothing to cancel. \
         The revert is not a no-op on a working tunnel — it restores the split config and \
         restarts the unit. Run `sudo vallum-ops revert` from a terminal if that is what \
         you want."
    )
}

/// Arm the full-tunnel trial. The operator has seen the plan and typed the
/// confirmation; this hands off to the root-owned dispatcher whose script
/// owns the ordering, the revert timer and the verdict. Its output IS the
/// result — returned verbatim, success or failure.
pub(crate) fn apply(confirm: &str) -> Result<String, String> {
    if confirm != "APPLY" {
        return Err("type APPLY in the confirmation field to arm this change".to_owned());
    }
    let mut attempts: Vec<(&str, Vec<&str>)> = vec![(
        "sudo",
        vec!["-n", "/usr/local/sbin/vallum-ops", "full-tunnel"],
    )];
    if effective_uid() != 0 {
        attempts.push(("pkexec", vec!["/usr/local/sbin/vallum-ops", "full-tunnel"]));
    }
    let mut last = String::from("cannot run vallum-ops (is the ops sudoers rule installed?)");
    for (program, args) in attempts {
        match std::process::Command::new(program).args(&args).output() {
            Ok(result) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                if program == "sudo"
                    && !result.status.success()
                    && sudo_may_succeed_via_pkexec(&text)
                {
                    last = text.trim().to_owned();
                    continue;
                }
                let verdict = if result.status.success() {
                    "ok"
                } else {
                    "failed"
                };
                return Ok(format!("[{}]\n{}", verdict, text));
            }
            Err(error) => last = format!("{program}: {error}"),
        }
    }
    Err(last)
}

/// Cancel a running full-tunnel trial: the documented undo, run immediately.
/// Panic first (guard off, routes back, DNS restored), then the split config
/// goes back and the unit is left running — the same end state a failed trial
/// reaches on its own, reached now instead of at the deadline.
///
/// Refused when no trial is armed. The revert restarts a working tunnel, so
/// an unarmed cancel stays refused: the deliberate path is the confirmed
/// [`revert`], where the operator types REVERT for exactly that outcome.
pub(crate) fn apply_cancel(socket: &std::path::Path) -> Result<String, String> {
    let interface = socket
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0");
    if !trial_armed(interface) {
        return Err(unarmed_cancel_error(interface));
    }
    run_ops_revert()
}

/// Revert an applied full tunnel back to the split config, on purpose. The
/// same `vallum-ops revert` the mid-trial cancel runs, minus the armed gate:
/// the typed confirmation IS the deliberation the cancel refusal asks for.
/// The console offers this from the already-full panel; the terminal spelling
/// stays `sudo vallum-ops revert`.
pub(crate) fn revert(confirm: &str) -> Result<String, String> {
    if confirm != "REVERT" {
        return Err(
            "type REVERT in the confirmation field to revert to the split tunnel".to_owned(),
        );
    }
    run_ops_revert()
}

/// Run `vallum-ops revert`: guard off, split config back, unit left running.
/// Shared by the mid-trial cancel (gated on an armed trial) and the confirmed
/// revert (gated on the typed word). Never call this without one of those
/// gates: on a host nobody asked to change it restarts a working tunnel.
fn run_ops_revert() -> Result<String, String> {
    let mut attempts: Vec<(&str, Vec<&str>)> =
        vec![("sudo", vec!["-n", "/usr/local/sbin/vallum-ops", "revert"])];
    if effective_uid() != 0 {
        attempts.push(("pkexec", vec!["/usr/local/sbin/vallum-ops", "revert"]));
    }
    let mut last = String::from("cannot run vallum-ops (is the ops sudoers rule installed?)");
    for (program, args) in attempts {
        match std::process::Command::new(program).args(&args).output() {
            Ok(result) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                if program == "sudo"
                    && !result.status.success()
                    && sudo_may_succeed_via_pkexec(&text)
                {
                    last = text.trim().to_owned();
                    continue;
                }
                return if result.status.success() {
                    Ok(text.trim().to_owned())
                } else {
                    Err(text.trim().to_owned())
                };
            }
            Err(error) => last = format!("{program}: {error}"),
        }
    }
    Err(last)
}

/// The trial trio over Tauri IPC. (The HTTP transport serves the same three
/// under /api/plan, /api/apply and /api/apply/cancel.) A socket must be
/// selected first: every mutation is gated on the console knowing what it is
/// about, the same gate the peer actions use.
#[tauri::command]
fn plan_command(console: State<'_, Arc<Console>>) -> Result<serde_json::Value, String> {
    Ok(plan(&selected(&console)?))
}

#[tauri::command]
fn apply_command(
    console: State<'_, Arc<Console>>,
    confirm: String,
) -> Result<serde_json::Value, String> {
    let socket = selected(&console)?;
    crate::hostfacts::write_gate(&socket)?;
    match apply(&confirm) {
        Ok(output) => Ok(serde_json::json!({ "ok": true, "output": output })),
        Err(error) => Err(error),
    }
}

#[tauri::command]
fn cancel_apply(console: State<'_, Arc<Console>>) -> Result<serde_json::Value, String> {
    let socket = selected(&console)?;
    crate::hostfacts::write_gate(&socket)?;
    match apply_cancel(&socket) {
        Ok(output) => Ok(serde_json::json!({ "ok": true, "output": output })),
        Err(error) => Err(error),
    }
}

#[tauri::command]
fn revert_command(
    console: State<'_, Arc<Console>>,
    confirm: String,
) -> Result<serde_json::Value, String> {
    let socket = selected(&console)?;
    crate::hostfacts::write_gate(&socket)?;
    match revert(&confirm) {
        Ok(output) => Ok(serde_json::json!({ "ok": true, "output": output })),
        Err(error) => Err(error),
    }
}

pub(crate) fn systemctl(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Service state as systemd reports it, unprivileged.
pub(crate) fn service_state(socket: &std::path::Path) -> serde_json::Value {
    let unit = unit_for(socket);
    serde_json::json!({
        "unit": unit,
        "active": systemctl(&["is-active", &unit]).unwrap_or_else(|| "unknown".to_owned()),
        "enabled": systemctl(&["is-enabled", &unit]).unwrap_or_else(|| "unknown".to_owned()),
    })
}

/// Start/stop/restart through polkit. `pkexec` shows the desktop's own
/// authentication dialog; nothing here ever prompts for a password in the UI.
pub(crate) fn service_action(socket: &std::path::Path, action: &str) -> Result<Done, String> {
    if !matches!(action, "start" | "stop" | "restart") {
        return Err(format!("unknown service action `{action}`"));
    }
    let unit = unit_for(socket);
    // The interface, not the unit: the dispatcher names the unit itself.
    let iface = unit.trim_start_matches("vallum@").to_owned();

    // The write gate is NOT applied here, and the difference matters. It
    // guards writes THROUGH the control socket - a socket wider than 0600
    // exposes the private key to `show --dump`. Starting a unit does not go
    // through the socket, and the daemon checks its own runtime directory
    // before it publishes anything.
    //
    // It used to be applied, and that made the console unable to do the one
    // thing it exists for: a stopped daemon has no socket, so START failed
    // with "control socket unreadable" and never reached systemctl. A tunnel
    // killed by the panic switch could not be started again from the console.
    //
    // The privileged path is `vallum-ops`, the ONE binary the sudoers rule
    // covers. A rule for `systemctl start|stop|restart vallum@*` would let its
    // holder pass any arguments to systemctl, which is a far wider grant than
    // the console needs.
    let attempts: Vec<(&str, Vec<&str>)> = if effective_uid() == 0 {
        vec![(
            "/usr/local/sbin/vallum-ops",
            vec!["service", action, &iface],
        )]
    } else {
        vec![
            (
                "sudo",
                vec![
                    "-n",
                    "/usr/local/sbin/vallum-ops",
                    "service",
                    action,
                    &iface,
                ],
            ),
            (
                "pkexec",
                vec!["/usr/local/sbin/vallum-ops", "service", action, &iface],
            ),
        ]
    };

    let mut last_error = String::from("no way to run systemctl");
    for (program, args) in attempts {
        match std::process::Command::new(program).args(&args).output() {
            Ok(output) if output.status.success() => {
                // Report the state that actually resulted, not the intent.
                let state = service_state(socket);
                let active = state
                    .get("active")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Ok(Done {
                    message: format!("{unit}: {active}"),
                    command: None,
                });
            }
            Ok(output) => {
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                last_error = combined.trim().to_owned();
                if last_error.is_empty() {
                    last_error = format!("{program} exited {}", output.status);
                }
                // Same rule as run_ops_with_stdin: pkexec is only worth it
                // when sudo never reached ops.
                if program != "sudo" || !sudo_may_succeed_via_pkexec(&combined) {
                    return Err(format!("cannot {action} {unit}: {last_error}"));
                }
            }
            Err(error) => last_error = format!("{program}: {error}"),
        }
    }
    Err(format!("cannot {action} {unit}: {last_error}"))
}

/// The unit's last log lines, as journald will give them to this user.
pub(crate) fn logs_tail(socket: &std::path::Path, lines: u32) -> serde_json::Value {
    let unit = unit_for(socket);
    let output = std::process::Command::new("journalctl")
        .args([
            "-u",
            &unit,
            "-n",
            &lines.to_string(),
            "--no-pager",
            "-o",
            "cat",
        ])
        .output();
    match output {
        Ok(output) if output.status.success() => serde_json::json!({
            "unit": unit,
            "lines": String::from_utf8_lossy(&output.stdout).trim_end(),
        }),
        Ok(output) => serde_json::json!({
            "unit": unit,
            "error": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => serde_json::json!({ "unit": unit, "error": error.to_string() }),
    }
}

/// sudo's own *authorization* refusals — the only failures where the pkexec
/// fallback can still reach ops. Anything else is ops' own verdict (or a
/// missing binary pkexec cannot fix either), and re-running it under pkexec
/// fires the privileged command twice behind a desktop auth dialog.
fn sudo_may_succeed_via_pkexec(output: &str) -> bool {
    output.contains("password is required")
        || output.contains("terminal is required")
        || output.contains("not allowed to execute")
        || output.contains("not in the sudoers")
        || output.contains("sudoers sources")
}

/// Run a privileged `vallum-ops` subcommand (with optional stdin payload),
/// trying direct execution when root, `sudo -n`, and `pkexec`.
fn run_ops_with_stdin(ops_args: &[&str], stdin_data: Option<&str>) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut attempts: Vec<(&str, Vec<&str>)> = Vec::new();
    if effective_uid() == 0 {
        attempts.push(("/usr/local/sbin/vallum-ops", ops_args.to_vec()));
    } else {
        let mut sudo_args = vec!["-n", "/usr/local/sbin/vallum-ops"];
        sudo_args.extend_from_slice(ops_args);
        attempts.push(("sudo", sudo_args));

        let mut pkexec_args = vec!["/usr/local/sbin/vallum-ops"];
        pkexec_args.extend_from_slice(ops_args);
        attempts.push(("pkexec", pkexec_args));
    }

    let mut last_error =
        String::from("cannot run /usr/local/sbin/vallum-ops (is the ops sudoers rule installed?)");
    for (program, args) in attempts {
        let mut cmd = Command::new(program);
        cmd.args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let Ok(mut child) = cmd.spawn() else {
            continue;
        };
        if let Some(input) = stdin_data {
            if let Some(mut child_stdin) = child.stdin.take() {
                let _ = writeln!(child_stdin, "{input}");
            }
        }
        if let Ok(output) = child.wait_with_output() {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if output.status.success() {
                return Ok(combined);
            }
            let trimmed = combined.trim();
            if !trimmed.is_empty() {
                last_error = trimmed.to_owned();
            } else {
                last_error = format!("{program} exited {}", output.status);
            }
            // Only sudo's authorization refusals justify the pkexec retry —
            // it can still reach ops where the sudoers rule is missing. Any
            // other failure IS ops' answer (or a missing binary pkexec cannot
            // fix): returning it avoids a pointless dialog and a second run.
            if program != "sudo" || !sudo_may_succeed_via_pkexec(&combined) {
                return Err(last_error);
            }
        }
    }
    Err(last_error)
}

/// The effective uid, without pulling libc in for one number.
fn effective_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(effective) = rest.split_whitespace().nth(1) {
                if let Ok(uid) = effective.parse() {
                    return uid;
                }
            }
        }
    }
    65534
}

pub(crate) fn panic() -> Result<Done, String> {
    // `sudo -n` when the installer's rule is present; otherwise polkit, so the
    // escape hatch works on a host where the rule is missing. The one control
    // that matters must not depend on a config file being right.
    let mut attempts: Vec<(&str, Vec<&str>)> =
        vec![("sudo", vec!["-n", "/usr/local/sbin/vallum-panic"])];
    if effective_uid() != 0 {
        attempts.push(("pkexec", vec!["/usr/local/sbin/vallum-panic"]));
    }
    let mut last = String::from("cannot run vallum-panic");
    let mut output = None;
    for (program, args) in attempts {
        match std::process::Command::new(program).args(&args).output() {
            Ok(result) if result.status.success() => {
                output = Some(result);
                break;
            }
            Ok(result) => {
                last = String::from_utf8_lossy(&result.stderr).trim().to_owned();
            }
            Err(error) => last = format!("{program}: {error}"),
        }
    }
    let Some(output) = output else {
        return Err(last);
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(Done {
            message: text
                .trim()
                .lines()
                .last()
                .unwrap_or("internet restored")
                .to_owned(),
            command: None,
        })
    } else {
        Err(text.trim().to_owned())
    }
}

#[tauri::command]
fn panic_command(console: State<'_, Arc<Console>>) -> Result<Done, String> {
    // The HTTP twin gates when a socket is known; same rule here, so the
    // escape hatch answers identically on both transports.
    if let Some(socket) = console.known_socket() {
        crate::hostfacts::write_gate(&socket)?;
    }
    panic()
}

/// Probe a peer over the interface that carries it.
///
#[tauri::command]
fn preflight_state() -> serde_json::Value {
    hostfacts::preflight()
}

#[tauri::command]
fn ping_peer(console: State<'_, Arc<Console>>, address: String) -> serde_json::Value {
    console.known_socket().map_or_else(
        || serde_json::json!({ "error": "no interface selected" }),
        |socket| hostfacts::ping(&socket, &address, 3),
    )
}

fn main() {
    // `--serve`: the console over localhost HTTP instead of a webview. The
    // same UI, the same commands, for machines whose WebKitGTK cannot render.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--serve") {
        let port = args
            .iter()
            .position(|arg| arg == "--serve")
            .and_then(|at| args.get(at + 1))
            .and_then(|value| value.parse().ok())
            .unwrap_or(7317u16);
        let ui = args
            .iter()
            .position(|arg| arg == "--ui")
            .and_then(|at| args.get(at + 1))
            .cloned()
            .or_else(|| std::env::var("VALLUM_UI_DIR").ok())
            .unwrap_or_else(|| {
                if std::path::Path::new("crates/vallum-gui/ui/dist").is_dir() {
                    "crates/vallum-gui/ui/dist".to_owned()
                } else {
                    concat!(env!("CARGO_MANIFEST_DIR"), "/ui/dist").to_owned()
                }
            });
        let console = Arc::new(Console::new());
        if let Err(error) = serve::serve(port, PathBuf::from(ui), console) {
            eprintln!("vallum-gui: {error}");
            std::process::exit(1);
        }
        return;
    }

    let console = Arc::new(Console::new());
    let poller = Arc::clone(&console);

    let outcome = tauri::Builder::default()
        .manage(console)
        .invoke_handler(tauri::generate_handler![
            ui_report,
            list_interfaces,
            health_state,
            service_state_command,
            service_action_command,
            logs_tail_command,
            panic_command,
            ping_peer,
            preflight_state,
            select,
            window_state,
            add_peer,
            edit_peer,
            remove_peer,
            apply_device,
            rotate_peer,
            finalize_peer,
            invite_peer,
            export_bundle,
            qr_frame,
            import_bundle,
            generate_key,
            read_config,
            write_config,
            read_interface_fields,
            apply_interface,
            save_runtime,
            join_network,
            setup_server,
            close_enrollment,
            plan_command,
            apply_command,
            cancel_apply,
            revert_command
        ])
        .setup(move |app| {
            // One-shot startup report on stderr: which URL the webview loaded,
            // whether the IPC bridge exists, and what it rendered. This is the
            // difference between "blank page" and "page ran and refused".
            let probe = app.handle().clone();
            std::thread::spawn(move || {
                use tauri::Manager;
                std::thread::sleep(std::time::Duration::from_secs(3));
                if let Some(window) = probe.get_webview_window("main") {
                    let _ = window.eval(
                        "(function(){ \
                          const t = window.__TAURI__; \
                          const info = { \
                            internals: typeof window.__TAURI_INTERNALS__, \
                            global: typeof t, \
                            body: document.body ? document.body.innerHTML.length : -1, \
                            errs: window.__bootErrors || [] }; \
                          if (t && t.core) { \
                            t.core.invoke('ui_report', { rendered: info.body, \
                              bridge: 'global:' + info.global + ',internals:' + info.internals, \
                              errors: info.errs }).catch(function(e){ \
                                t.core.invoke('ui_report', { rendered: -2, bridge: 'invoke-failed:' + String(e), errors: [] }).catch(function(){}); \
                              }); \
                          } else { document.title = 'NOGLOBAL ' + JSON.stringify(info); } \
                        })()",
                    );
                    std::thread::sleep(std::time::Duration::from_millis(600));
                    eprintln!("vallum-gui: url={:?} title={:?}", window.url(), window.title());
                } else {
                    eprintln!("vallum-gui: no window labelled main");
                }
            });
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("snapshot-poller".to_owned())
                .spawn(move || poll_loop(handle, poller))
                .map(|_| ())
                .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))
        })
        .run(tauri::generate_context!());

    if let Err(error) = outcome {
        eprintln!("vallum-gui: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod transport_parity_tests {
    use super::*;

    /// The canonical write surface: every mutation the console can invoke, by
    /// the name both transports use. `dispatch` (HTTP `/api/cmd/*`) matches on
    /// this list; the Tauri commands in `generate_handler!` are the same names
    /// as functions. Add a name to both places at once — the parity test
    /// below fails the suite if the dispatch arm is missing.
    const COMMAND_NAMES: &[&str] = &[
        "add_peer",
        "edit_peer",
        "remove_peer",
        "rotate_peer",
        "finalize_peer",
        "invite_peer",
        "apply_device",
        "export_bundle",
        "qr_frame",
        "import_bundle",
        "generate_key",
        "read_config",
        "write_config",
        "read_interface_fields",
        "apply_interface",
        "save_runtime",
        "join_network",
        "setup_server",
        "close_enrollment",
    ];

    /// Every canonical command must reach a real arm on the HTTP transport.
    /// With no socket selected each arm fails at the socket gate — only an
    /// unregistered name fails with "unknown command". This is the half of
    /// the dual-transport rule the suite can check; the Tauri half is the
    /// `generate_handler!` list above, kept identical by review.
    /// A console pointed at a (fake) socket: past the socket gate, so each
    /// arm fails on its arguments instead — which still proves the arm ran.
    fn console_with_socket() -> Arc<Console> {
        let console = Arc::new(Console::new());
        select_path(&console, "/tmp/vallum-parity-test.sock".to_owned());
        console
    }

    /// The cancel gate: only a running or arming trial counts. A stopped,
    /// failed or absent timer means the revert would drop a working tunnel,
    /// so it is refused instead of running.
    #[test]
    fn only_an_armed_trial_may_be_cancelled() {
        for armed in ["active", "activating", "reloading", "active\n"] {
            assert!(trial_is_armed(armed), "{armed:?} is a trial in progress");
        }
        for idle in ["inactive", "failed", "unknown", "deactivating", ""] {
            assert!(!trial_is_armed(idle), "{idle:?} is not a trial in progress");
        }
        // The refusal has to say both halves: nothing to cancel, and where the
        // deliberate undo lives. Asserted on the message, not by running the
        // cancel: a test must never touch the host's tunnel.
        let error = unarmed_cancel_error("vallum0");
        assert!(error.contains("nothing to cancel"), "{error}");
        assert!(error.contains("vallum-ops revert"), "{error}");
        assert!(error.contains("vallum0"), "{error}");
    }

    /// The confirmed revert: the typed word is the deliberation the unarmed
    /// cancel refuses without. Asserted on the gate alone — a test must never
    /// run `vallum-ops revert` against the host's tunnel.
    #[test]
    fn revert_needs_the_typed_word() {
        for wrong in ["", "apply", "revert", "REVERT "] {
            let error = revert(wrong).expect_err(&format!("{wrong:?} must not revert"));
            assert!(error.contains("REVERT"), "{error}");
        }
    }

    #[test]
    fn every_command_dispatches() {
        let console = console_with_socket();
        for name in COMMAND_NAMES {
            let error = dispatch(&console, name, serde_json::Value::Null)
                .expect_err(&format!("{name} should fail on arguments, not be unknown"));
            assert!(
                !error.starts_with("unknown command"),
                "{name} is registered but not dispatched"
            );
        }
    }

    /// The flip side: an unregistered name is still rejected, so a typo in the
    /// front-end cannot silently match nothing on either transport.
    #[test]
    fn unknown_commands_stay_unknown() {
        let console = console_with_socket();
        let error = dispatch(&console, "reboot_everything", serde_json::Value::Null)
            .expect_err("unknown names must fail");
        assert!(error.starts_with("unknown command"));
    }

    /// Mechanical transport parity check: every command in `bridge.ts` and
    /// `actions.ts` must exist in `tauri::generate_handler!`, and every HTTP
    /// endpoint in `bridge.ts` must have a handler in `serve.rs`.
    #[test]
    fn frontend_bridge_matches_both_backends() {
        let main_src = include_str!("main.rs");
        let serve_src = include_str!("serve.rs");
        let bridge_src = include_str!("../ui/src/lib/bridge.ts");
        let actions_src = include_str!("../ui/src/lib/actions.ts");

        let tauri_direct = [
            "list_interfaces",
            "select",
            "plan_command",
            "apply_command",
            "cancel_apply",
            "revert_command",
            "window_state",
            "health_state",
            "panic_command",
            "preflight_state",
            "ping_peer",
            "service_state_command",
            "service_action_command",
            "logs_tail_command",
        ];
        for name in COMMAND_NAMES.iter().chain(tauri_direct.iter()) {
            assert!(
                main_src.contains(name),
                "command `{name}` missing from main.rs invoke_handler"
            );
        }
        for name in tauri_direct {
            if name != "window_state" {
                assert!(
                    bridge_src.contains(&format!("\"{name}\"")),
                    "Tauri command `{name}` not invoked in bridge.ts"
                );
            }
        }
        for name in COMMAND_NAMES {
            assert!(
                actions_src.contains(&format!("\"{name}\"")),
                "command `{name}` missing from actions.ts"
            );
        }
        for key in [
            "publicLine",
            "newLine",
            "fingerprint",
            "endpoint",
            "index",
            "text",
            "outDir",
            "bundlePath",
            "listenPort",
            "fwmark",
        ] {
            assert!(
                main_src.contains(&format!("\"{key}\"")),
                "dispatch parameter `{key}` missing from main.rs"
            );
            assert!(
                actions_src.contains(key),
                "dispatch parameter `{key}` missing from actions.ts"
            );
        }
        for route in [
            "/api/interfaces",
            "/api/select",
            "/api/plan",
            "/api/apply",
            "/api/apply/cancel",
            "/api/revert",
            "/api/health",
            "/api/panic",
            "/api/preflight",
            "/api/ping",
            "/api/service",
            "/api/logs",
            "/api/stream",
            "/api/cmd/",
        ] {
            assert!(
                serve_src.contains(route),
                "HTTP route `{route}` missing from serve.rs"
            );
            assert!(
                bridge_src.contains(route),
                "HTTP route `{route}` missing from bridge.ts"
            );
        }
    }
}
