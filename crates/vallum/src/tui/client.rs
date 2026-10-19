// SPDX-License-Identifier: Apache-2.0

//! Interface discovery and the control-socket read path.

use std::path::{Path, PathBuf};

use crate::commands::tui::TuiArgs;
use crate::config::{self, Config};
use crate::control;
use crate::uapi;

use super::app::{DeviceView, Interface};

/// Discover interfaces from explicit arguments, the config directory, and the
/// runtime socket directory. Deduplicated by control path.
#[must_use]
pub fn discover(args: &TuiArgs) -> Vec<Interface> {
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut push = |interface: Interface| {
        if !interfaces
            .iter()
            .any(|existing| existing.control_path == interface.control_path)
        {
            interfaces.push(interface);
        }
    };

    if let Some(path) = &args.control {
        push(Interface::new("control".to_owned(), None, path.clone()));
    }
    if let Some(path) = &args.config {
        if let Some(interface) = from_config(path) {
            push(interface);
        }
    }

    let directory = args
        .config_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/vallum"));
    if let Ok(entries) = std::fs::read_dir(&directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            if let Some(interface) = from_config(&path) {
                push(interface);
            }
        }
    }

    if let Ok(entries) = std::fs::read_dir("/run/vallum") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("sock") {
                let name = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("vallum")
                    .to_owned();
                push(Interface::new(name, None, path));
            }
        }
    }

    interfaces
}

fn from_config(path: &Path) -> Option<Interface> {
    let config = Config::load(path).ok()?;
    let name = config
        .interface
        .name
        .clone()
        .or_else(|| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "vallum0".to_owned());
    let control_path = config
        .interface
        .control
        .as_ref()
        .map(|declared| config::resolve_key_path(path, declared))
        .or_else(|| {
            let candidate = PathBuf::from(format!("/run/vallum/{name}.sock"));
            candidate.exists().then_some(candidate)
        })?;
    Some(Interface::new(name, Some(path.to_path_buf()), control_path))
}

/// Fetch one device snapshot.
///
/// # Errors
///
/// If the socket cannot be reached or the reply is not a successful `get`.
pub fn fetch(control_path: &Path) -> Result<DeviceView, String> {
    let reply = control::request(control_path, "get=1\n").map_err(|error| error.to_string())?;
    if !reply.lines().any(|line| line == "errno=0") {
        return Err(format!("control request failed: {}", reply.trim()));
    }
    Ok(DeviceView::from_response(&uapi::parse_response(&reply)))
}
