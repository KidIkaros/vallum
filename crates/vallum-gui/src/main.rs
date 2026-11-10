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
pub(crate) mod serve;
pub(crate) mod snapshot;

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{Emitter, State};

use actions::{Done, InviteFields, PeerFields};
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
        Self {
            inner: Mutex::new(Inner {
                socket: None,
                last_socket: None,
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
        self.lock().socket.clone()
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
        .lock()
        .socket
        .clone()
        .ok_or_else(|| "no interface selected".to_owned())
}

/// The config that owns the selected socket, when this process can read it.
fn config_of(socket: &std::path::Path) -> Option<PathBuf> {
    // The installed layout keeps configs in /etc/vallum. A lab or a hand-run
    // daemon keeps its config beside the socket it publishes, and the console
    // should find that too rather than reporting "no config" at the operator.
    actions::config_for(socket, std::path::Path::new(CONFIG_DIR))
        .or_else(|| socket.parent().and_then(|dir| actions::config_for(socket, dir)))
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
    let config = config_of(socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to finalise"
        )
    })?;
    actions::finalize(&config, name)
}

fn invite_at(socket: &std::path::Path, fields: &InviteFields) -> Result<Done, String> {
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
    actions::invite(
        &interface,
        config.as_deref(),
        listen.as_deref(),
        &public_line,
        fields,
    )
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
fn health_state(console: State<'_, Arc<Console>>) -> serde_json::Value {
    console
        .known_socket()
        .map_or(serde_json::Value::Null, |socket| health(&socket))
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
                let interval = if inner.focused && inner.visible { FOCUSED } else { UNFOCUSED };
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
) -> Result<Done, String> {
    let socket = console
        .current_socket()
        .ok_or_else(|| "no interface selected".to_owned())?;
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
    match name {
        "add_peer" => {
            let fields: PeerFields = serde_json::from_value(body.clone()).map_err(|e| e.to_string())?;
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
            result
        }
        "edit_peer" => {
            let fields: PeerFields = serde_json::from_value(body).map_err(|e| e.to_string())?;
            actions::edit(&socket, &fields)
        }
        "remove_peer" => actions::remove(&socket, &text("publicLine")?),
        "rotate_peer" => rotate_at(&socket, &text("name")?, &text("newLine")?),
        "finalize_peer" => finalize_at(&socket, &text("name")?),
        "invite_peer" => {
            let fields: InviteFields = serde_json::from_value(body).map_err(|e| e.to_string())?;
            invite_at(&socket, &fields)
        }
        "apply_device" => actions::apply_device(&socket, &text("listenPort")?, &text("fwmark")?),
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

fn systemctl(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("systemctl").args(args).output().ok()?;
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
pub(crate) fn service_action(
    socket: &std::path::Path,
    action: &str,
) -> Result<Done, String> {
    if !matches!(action, "start" | "stop" | "restart") {
        return Err(format!("unknown service action `{action}`"));
    }
    let unit = unit_for(socket);
    // sudo -n first: a console that runs as a login user should not prompt for
    // every start/stop once the operator has granted the narrow rule. pkexec is
    // the fallback, and its prompt is the desktop's own.
    let attempts: Vec<(&str, Vec<&str>)> = if effective_uid() == 0 {
        vec![("systemctl", vec![action, unit.as_str()])]
    } else {
        vec![
            ("sudo", vec!["-n", "systemctl", action, unit.as_str()]),
            ("pkexec", vec!["systemctl", action, unit.as_str()]),
        ]
    };
    // A unit that has been killed a few times refuses to start until its
    // failure counter is cleared; START must be able to do that too, or the
    // console reports a failure it caused.
    if action == "start" {
        let reset: &[&str] = if effective_uid() == 0 {
            &["systemctl", "reset-failed", unit.as_str()]
        } else {
            &["sudo", "-n", "systemctl", "reset-failed", unit.as_str()]
        };
        let _ = std::process::Command::new(reset[0]).args(&reset[1..]).output();
    }

    let mut last_error = String::from("no way to run systemctl");
    for (program, args) in attempts {
        match std::process::Command::new(program).args(&args).output() {
            Ok(output) if output.status.success() => {
                // Report the state that actually resulted, not the intent.
                let state = service_state(socket);
                let active = state.get("active").and_then(|v| v.as_str()).unwrap_or("unknown");
                return Ok(Done {
                    message: format!("{unit}: {active}"),
                    command: None,
                });
            }
            Ok(output) => {
                last_error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                if last_error.is_empty() {
                    last_error = format!("{program} exited {}", output.status);
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

/// Which interface would carry traffic to `address`? `None` when the kernel
/// has no route at all — which, for v6 behind the guard, is the good answer.
fn route_device(address: &str, v6: bool) -> Option<String> {
    let mut command = std::process::Command::new("ip");
    if v6 {
        command.arg("-6");
    }
    let output = command.args(["route", "get", address]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();
    fields
        .iter()
        .position(|field| *field == "dev")
        .and_then(|at| fields.get(at + 1))
        .map(|dev| (*dev).to_owned())
}

fn nameservers() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|text| {
            text.lines()
                .filter_map(|line| line.trim().strip_prefix("nameserver "))
                .map(|server| server.trim().to_owned())
                .filter(|server| !server.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The facts an operator needs to answer "is this actually a VPN right now?".
/// Every one is measured from the host, not inferred from the config: a config
/// that says `0.0.0.0/0` and a route that says `wlp0s20f3` are the difference
/// between a product and a claim.
pub(crate) fn health(socket: &std::path::Path) -> serde_json::Value {
    let unit = unit_for(socket);
    let interface = socket
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
        .to_owned();
    let quick = format!("vallum-quick@{interface}");
    let guard = format!("vallum-guard@{interface}");

    let route4 = route_device("1.1.1.1", false);
    let route6 = route_device("2001:4860:4860::8888", true);
    let servers = nameservers();
    let dns_dev = servers
        .first()
        .and_then(|server| route_device(server, server.contains(':')));
    // The system resolver is usually systemd-resolved's stub (127.0.0.53);
    // what decides "DNS rides the tunnel" is whether the tunnel LINK carries
    // upstream servers — resolved forwards there. Reading only resolv.conf
    // turns a working setup into a false FAIL.
    let link_dns: Vec<String> = std::process::Command::new("resolvectl")
        .args(["dns", &interface])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| {
            text.lines().next().and_then(|line| line.split_once(':')).map(|(_, tail)| tail.to_owned())
        })
        .map(|tail| {
            tail.split_whitespace()
                .filter(|token| token.parse::<std::net::IpAddr>().is_ok())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let show = std::process::Command::new("systemctl")
        .args(["show", &unit, "-p", "NRestarts", "-p", "ExecMainStatus"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default();
    let field = |name: &str| -> Option<String> {
        show.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .map(str::to_owned)
    };
    let restarts: u64 = field("NRestarts").and_then(|v| v.parse().ok()).unwrap_or(0);

    let last_death = std::process::Command::new("journalctl")
        .args(["-u", &unit, "-n", "400", "--no-pager", "-o", "cat"])
        .output()
        .ok()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|line| {
                    line.contains("status=31/SYS")
                        || line.contains("Failed with result")
                        || line.contains("Main process exited")
                })
                .next_back()
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .unwrap_or_default();

    serde_json::json!({
        "unit": unit,
        "interface": interface,
        "route4": route4,
        "route4_via_tunnel": route4.as_deref() == Some(interface.as_str()),
        "route6": route6,
        "route6_via_tunnel": route6.as_deref() == Some(interface.as_str()),
        "dns": servers,
        "dns_via_tunnel": dns_dev.as_deref() == Some(interface.as_str()) || !link_dns.is_empty(),
        "dns_upstream": link_dns,
        "restarts": restarts,
        "last_death": last_death,
        "guard": {
            "unit": guard,
            "active": systemctl(&["is-active", &guard]).unwrap_or_else(|| "unknown".to_owned()),
        },
        "quick": {
            "unit": quick,
            "active": systemctl(&["is-active", &quick]).unwrap_or_else(|| "unknown".to_owned()),
        },
    })
}

/// Put the host back on the internet. The one control that must work when
/// everything else is broken, so it runs a root-owned script through the
/// narrow sudoers rule rather than doing anything itself.
pub(crate) fn panic() -> Result<Done, String> {
    // `sudo -n` when the installer's rule is present; otherwise polkit, so the
    // escape hatch works on a host where the rule is missing. The one control
    // that matters must not depend on a config file being right.
    let mut attempts: Vec<(&str, Vec<&str>)> = vec![("sudo", vec!["-n", "/usr/local/sbin/vallum-panic"])];
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
            message: text.trim().lines().last().unwrap_or("internet restored").to_owned(),
            command: None,
        })
    } else {
        Err(text.trim().to_owned())
    }
}

#[tauri::command]
fn panic_command() -> Result<Done, String> {
    panic()
}

/// Probe a peer over the interface that carries it.
///
/// Bound to the interface on purpose: the host's routing table may prefer a
/// different tunnel (or the physical link), and a probe that answers from
/// somewhere else is worse than no probe.
pub(crate) fn ping(
    socket: &std::path::Path,
    address: &str,
    count: u32,
) -> serde_json::Value {
    let interface = socket
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
        .to_owned();
    let output = std::process::Command::new("ping")
        .args([
            "-I",
            &interface,
            "-c",
            &count.to_string(),
            "-W",
            "2",
            address,
        ])
        .output();
    let Ok(output) = output else {
        return serde_json::json!({ "address": address, "error": "cannot run ping" });
    };
    let text = String::from_utf8_lossy(&output.stdout).to_owned();
    let received = text
        .lines()
        .find(|line| line.contains("packets transmitted"))
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse::<u32>().ok());
    let rtt = text
        .lines()
        .find(|line| line.starts_with("rtt") || line.starts_with("round-trip"))
        .and_then(|line| line.split('=').nth(1))
        .map(|value| value.trim().split('/').nth(1).map(str::to_owned))
        .flatten();
    serde_json::json!({
        "address": address,
        "interface": interface,
        "sent": count,
        "received": received,
        "avg_ms": rtt,
        "output": text.trim(),
    })
}

#[tauri::command]
fn preflight_state() -> serde_json::Value {
    preflight()
}

#[tauri::command]
fn ping_peer(console: State<'_, Arc<Console>>, address: String) -> serde_json::Value {
    console.known_socket().map_or_else(
        || serde_json::json!({ "error": "no interface selected" }),
        |socket| ping(&socket, &address, 3),
    )
}

/// What is on this host, before any daemon exists to ask. Every field is a fact
/// read from disk or systemd — a first-run screen that guesses is worse than one
/// that says nothing.
pub(crate) fn preflight() -> serde_json::Value {
    let exists = |path: &str| std::path::Path::new(path).exists();
    // A file the console cannot read is not the same as a file that is absent;
    // saying "no config" when it is merely root-owned sends the operator to
    // reinstall something they already have.
    let present = |path: &str| -> Option<bool> {
        match std::fs::metadata(path) {
            Ok(_) => Some(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
            Err(_) => None,
        }
    };
    let unit_installed = std::process::Command::new("systemctl")
        .args(["list-unit-files", "vallum@.service", "--no-legend"])
        .output()
        .ok()
        .map(|out| !String::from_utf8_lossy(&out.stdout).trim().is_empty())
        .unwrap_or(false);
    let runtime = vallum_config::runtime_dir();
    let (mode, group) = std::fs::metadata(runtime)
        .ok()
        .and_then(|meta| {
            use std::os::unix::fs::MetadataExt;
            Some((format!("{:04o}", meta.mode() & 0o7777), meta.gid()))
        })
        .unwrap_or_else(|| ("absent".to_owned(), 0));
    let sockets = std::fs::read_dir(runtime)
        .map(|read| {
            read.flatten()
                .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("sock"))
                .count()
        })
        .unwrap_or(0);

    serde_json::json!({
        "vallum": exists("/usr/bin/vallum"),
        "quick": exists("/usr/bin/vallum-quick"),
        "panic": exists("/usr/local/sbin/vallum-panic"),
        "deadman": exists("/usr/local/sbin/vallum-guard-deadman"),
        "unit": unit_installed,
        "config": present("/etc/vallum/vallum0.toml"),
        "runtime_dir": runtime.display().to_string(),
        "runtime_mode": mode,
        "sockets": sockets,
    })
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
            .unwrap_or_else(|| "crates/vallum-gui/ui/dist".to_owned());
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
            invite_peer
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
