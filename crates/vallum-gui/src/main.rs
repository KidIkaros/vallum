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
mod snapshot;

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
struct Payload {
    ok: bool,
    error: Option<String>,
    data: Option<Snapshot>,
}

/// One offer of a control socket, by display name and path.
#[derive(Debug, Serialize)]
struct InterfaceEntry {
    name: String,
    path: String,
}

#[derive(Debug)]
struct Inner {
    socket: Option<PathBuf>,
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
struct Console {
    inner: Mutex<Inner>,
    wake: Condvar,
}

impl Console {
    fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                socket: None,
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

/// The control sockets this host can offer.
///
/// Discovery reads the runtime directory the daemon binds its socket in, which
/// is also what the TUI scans. Nothing is invented when the directory is absent:
/// a machine with no daemon shows no interfaces.
#[tauri::command]
fn list_interfaces() -> Vec<InterfaceEntry> {
    let mut entries: Vec<InterfaceEntry> = Vec::new();
    if let Ok(read) = std::fs::read_dir(vallum_config::runtime_dir()) {
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
    console.changed(|inner| {
        inner.socket = Some(PathBuf::from(path));
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
    actions::config_for(socket, std::path::Path::new(CONFIG_DIR))
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

#[tauri::command]
fn rotate_peer(
    console: State<'_, Arc<Console>>,
    name: String,
    new_line: String,
) -> Result<Done, String> {
    let socket = selected(&console)?;
    let config = config_of(&socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to rotate the stored identity"
        )
    })?;
    let suite = snapshot::fetch(&socket)
        .ok()
        .map(|snapshot| snapshot.suite_id());
    actions::rotate(&config, &name, &new_line, suite)
}

#[tauri::command]
fn finalize_peer(console: State<'_, Arc<Console>>, name: String) -> Result<Done, String> {
    let socket = selected(&console)?;
    let config = config_of(&socket).ok_or_else(|| {
        format!(
            "no readable config under {CONFIG_DIR} names this socket — run the console as root to finalise"
        )
    })?;
    actions::finalize(&config, &name)
}

#[tauri::command]
fn invite_peer(console: State<'_, Arc<Console>>, fields: InviteFields) -> Result<Done, String> {
    let socket = selected(&console)?;
    let interface = socket
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
        .to_owned();
    let device = snapshot::fetch(&socket).ok();
    let config = config_of(&socket);
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
        &fields,
    )
}

/// Tell the poller how the window is behaving, so it can pick a cadence.
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
fn poll_loop(app: tauri::AppHandle, console: Arc<Console>) {
    loop {
        let socket = {
            let mut inner = console.lock();
            while !inner.visible || inner.socket.is_none() {
                inner = console
                    .wake
                    .wait(inner)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            if inner.immediate {
                inner.immediate = false;
                inner.socket.clone()
            } else {
                let interval = if inner.focused { FOCUSED } else { UNFOCUSED };
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
                if current.generation != generation || !current.visible {
                    None
                } else {
                    current.socket.clone()
                }
            }
        };

        let Some(path) = socket else {
            continue;
        };
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
        // A failed emit means the window is gone; the poller has no work left.
        if app.emit("snapshot", payload).is_err() {
            return;
        }
    }
}

fn main() {
    let console = Arc::new(Console::new());
    let poller = Arc::clone(&console);

    let outcome = tauri::Builder::default()
        .manage(console)
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
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
