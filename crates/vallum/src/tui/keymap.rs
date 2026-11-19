// SPDX-License-Identifier: Apache-2.0

//! Configurable dashboard keymap and the command list behind the palette.
//!
//! Only dashboard-level actions are remappable; modal contexts (forms,
//! confirmations, filter input, the QR view, and scrolling views) keep fixed
//! keys so there is always a working way out. `Ctrl-C` quit is also fixed.
//!
//! Bindings live in `$XDG_CONFIG_HOME/vallum/tui-keys.toml` (or
//! `~/.config/vallum/tui-keys.toml`), or a file passed with `--keys`:
//!
//! ```toml
//! add_peer = "n"            # rebind
//! help = ["F1", "h"]        # multiple keys
//! quit = "none"             # unbind (Ctrl-C still quits)
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A user-facing dashboard action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    Quit,
    Help,
    Refresh,
    AutoRefresh,
    CommandPalette,
    Filter,
    ClearFilter,
    Sort,
    NextInterface,
    PrevInterface,
    NextPeer,
    PrevPeer,
    ScrollPeersDown,
    ScrollPeersUp,
    FirstPeer,
    LastPeer,
    AddPeer,
    InvitePeer,
    EditPeer,
    RotatePeer,
    FinalizePeer,
    RemovePeer,
    Keygen,
    ExportBundle,
    ImportBundle,
    Ping,
    YankPublicLine,
    YankAddress,
    SaveRuntime,
    RuntimeForm,
    InterfaceForm,
    EditConfig,
    ToggleService,
    Logs,
    Health,
    SetupServer,
    SetupClient,
    CloseEnrollment,
    SyncCheck,
    SyncHost,
    EnableUnits,
    DisableUnits,
    RestartService,
    TrialPlan,
    TrialRevert,
    AccountPanel,
}

/// One command-palette entry: category badge, name shown, keywords searched.
#[derive(Debug, Clone, Copy)]
pub struct Command {
    pub action: Action,
    pub category: &'static str,
    pub name: &'static str,
    pub keywords: &'static str,
}

/// The palette list, in the order shown when the input is empty.
/// Commands that open a form or confirmation carry a trailing `…` (GUI Blooper 31).
pub const COMMANDS: &[Command] = &[
    Command {
        action: Action::SetupServer,
        category: "SETUP",
        name: "host a vallum server…",
        keywords: "setup init server onboarding host install begin subnet nat",
    },
    Command {
        action: Action::SetupClient,
        category: "SETUP",
        name: "join a network (ticket / ssh)…",
        keywords: "setup client bundle join onboarding connect import enroll ticket ssh",
    },
    Command {
        action: Action::CloseEnrollment,
        category: "SETUP",
        name: "close enrolment responder (UDP 51821)",
        keywords: "enroll invite close responder port disable tidy",
    },
    Command {
        action: Action::SyncCheck,
        category: "SETUP",
        name: "check for updates",
        keywords: "update upgrade check stale version sync check",
    },
    Command {
        action: Action::SyncHost,
        category: "SETUP",
        name: "sync host with checkout",
        keywords: "update upgrade install deploy sync apply binary units",
    },
    Command {
        action: Action::EnableUnits,
        category: "SERVICE",
        name: "enable tunnel units (start at boot)",
        keywords: "enable boot persistence persist start units systemd",
    },
    Command {
        action: Action::DisableUnits,
        category: "SERVICE",
        name: "disable tunnel units…",
        keywords: "disable uninstall retire off boot persistence remove units",
    },
    Command {
        action: Action::RestartService,
        category: "SERVICE",
        name: "restart tunnel service",
        keywords: "restart bounce reload daemon unresponsive silent",
    },
    Command {
        action: Action::ToggleService,
        category: "SERVICE",
        name: "toggle tunnel service",
        keywords: "start stop up down restart",
    },
    Command {
        action: Action::Refresh,
        category: "SERVICE",
        name: "refresh snapshot",
        keywords: "reload poll live",
    },
    Command {
        action: Action::AutoRefresh,
        category: "SERVICE",
        name: "toggle auto-refresh",
        keywords: "poll live timer",
    },
    Command {
        action: Action::AddPeer,
        category: "PEER",
        name: "add peer…",
        keywords: "new device client",
    },
    Command {
        action: Action::InvitePeer,
        category: "PEER",
        name: "invite peer (one-time token)…",
        keywords: "invite token join enroll qr mobile",
    },
    Command {
        action: Action::RotatePeer,
        category: "PEER",
        name: "rotate peer key…",
        keywords: "rotate rekey replace identity",
    },
    Command {
        action: Action::FinalizePeer,
        category: "PEER",
        name: "finalize peer key rotation…",
        keywords: "finalize retire rotation old key",
    },
    Command {
        action: Action::EditPeer,
        category: "PEER",
        name: "edit peer…",
        keywords: "change endpoint keepalive psk",
    },
    Command {
        action: Action::RemovePeer,
        category: "PEER",
        name: "remove peer…",
        keywords: "delete revoke",
    },
    Command {
        action: Action::Keygen,
        category: "PEER",
        name: "generate key",
        keywords: "keygen identity",
    },
    Command {
        action: Action::ExportBundle,
        category: "BUNDLE",
        name: "export client bundle…",
        keywords: "qr share mobile",
    },
    Command {
        action: Action::ImportBundle,
        category: "BUNDLE",
        name: "import client bundle…",
        keywords: "load client config",
    },
    Command {
        action: Action::Ping,
        category: "PEER",
        name: "ping peer",
        keywords: "test reachability",
    },
    Command {
        action: Action::Filter,
        category: "VIEW",
        name: "filter peers…",
        keywords: "search find",
    },
    Command {
        action: Action::ClearFilter,
        category: "VIEW",
        name: "clear filter",
        keywords: "reset show all",
    },
    Command {
        action: Action::Sort,
        category: "VIEW",
        name: "cycle peer sort",
        keywords: "order name transfer handshake",
    },
    Command {
        action: Action::YankPublicLine,
        category: "PEER",
        name: "copy public line",
        keywords: "clipboard yank",
    },
    Command {
        action: Action::YankAddress,
        category: "PEER",
        name: "copy peer address",
        keywords: "clipboard yank endpoint ip",
    },
    Command {
        action: Action::SaveRuntime,
        category: "CONFIG",
        name: "save runtime config",
        keywords: "write persist disk",
    },
    Command {
        action: Action::RuntimeForm,
        category: "CONFIG",
        name: "runtime device form…",
        keywords: "listen port fwmark temporary",
    },
    Command {
        action: Action::InterfaceForm,
        category: "CONFIG",
        name: "interface config form…",
        keywords: "listen mtu addresses dns table",
    },
    Command {
        action: Action::EditConfig,
        category: "CONFIG",
        name: "edit config in $EDITOR…",
        keywords: "toml diff backup",
    },
    Command {
        action: Action::Logs,
        category: "VIEW",
        name: "view logs",
        keywords: "journal journalctl",
    },
    Command {
        action: Action::Health,
        category: "VIEW",
        name: "egress health check",
        keywords: "health egress route dns guard leak protected",
    },
    Command {
        action: Action::TrialPlan,
        category: "TRIAL",
        name: "preview full-tunnel trial…",
        keywords: "trial egress full tunnel plan route dns guard",
    },
    Command {
        action: Action::TrialRevert,
        category: "TRIAL",
        name: "revert full-tunnel trial (panic)",
        keywords: "trial revert panic undo split restore",
    },
    Command {
        action: Action::AccountPanel,
        category: "ACCOUNT",
        name: "read desk account…",
        keywords: "account desk plan quota expiry bytes devices usage cap",
    },
    Command {
        action: Action::NextInterface,
        category: "NAV",
        name: "next interface",
        keywords: "tab switch",
    },
    Command {
        action: Action::PrevInterface,
        category: "NAV",
        name: "previous interface",
        keywords: "tab switch",
    },
    Command {
        action: Action::NextPeer,
        category: "NAV",
        name: "next peer",
        keywords: "select down",
    },
    Command {
        action: Action::PrevPeer,
        category: "NAV",
        name: "previous peer",
        keywords: "select up",
    },
    Command {
        action: Action::FirstPeer,
        category: "NAV",
        name: "first peer",
        keywords: "home top",
    },
    Command {
        action: Action::LastPeer,
        category: "NAV",
        name: "last peer",
        keywords: "end bottom",
    },
    Command {
        action: Action::Help,
        category: "VIEW",
        name: "help",
        keywords: "keys guide shortcuts",
    },
    Command {
        action: Action::Quit,
        category: "SYSTEM",
        name: "quit",
        keywords: "exit close",
    },
];

/// Palette rows whose name, category, or keywords contain the input (case-insensitive).
/// An empty input lists everything.
#[must_use]
pub fn matching_commands(input: &str) -> Vec<&'static Command> {
    let needle = input.trim().to_lowercase();
    COMMANDS
        .iter()
        .filter(|command| {
            needle.is_empty()
                || command.name.to_lowercase().contains(&needle)
                || command.category.to_lowercase().contains(&needle)
                || command.keywords.to_lowercase().contains(&needle)
        })
        .collect()
}

/// First index of the visible window so `selected` stays on screen when the
/// filtered list exceeds `max_rows`, without scrolling the list while the
/// selection is still within the first page.
#[must_use]
pub fn window_start(len: usize, selected: usize, max_rows: usize) -> usize {
    if len <= max_rows || max_rows == 0 || selected < max_rows {
        0
    } else {
        (selected + 1 - max_rows).min(len - max_rows)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Binding {
    code: KeyCode,
    modifiers: KeyModifiers,
}

impl Binding {
    fn of(key: &KeyEvent) -> Self {
        Self {
            code: key.code,
            modifiers: key.modifiers,
        }
    }
}

fn parse_key(spec: &str) -> Option<Binding> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    let mut modifiers = KeyModifiers::empty();
    let mut token = spec;
    if let Some((head, tail)) = spec.rsplit_once('+') {
        let mut all_modifiers = true;
        let mut mods = KeyModifiers::empty();
        for part in head.split('+') {
            match part.trim().to_lowercase().as_str() {
                "ctrl" | "control" => mods |= KeyModifiers::CONTROL,
                "alt" | "meta" => mods |= KeyModifiers::ALT,
                "shift" => mods |= KeyModifiers::SHIFT,
                _ => {
                    all_modifiers = false;
                    break;
                }
            }
        }
        if all_modifiers && !mods.is_empty() {
            modifiers = mods;
            token = tail;
        }
    }
    let token = token.trim();
    let lower = token.to_lowercase();
    let code = match lower.as_str() {
        "space" => KeyCode::Char(' '),
        "tab" => KeyCode::Tab,
        "backtab" | "shift-tab" => KeyCode::BackTab,
        "esc" | "escape" => KeyCode::Esc,
        "enter" | "return" => KeyCode::Enter,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" | "pgup" => KeyCode::PageUp,
        "pagedown" | "pgdn" => KeyCode::PageDown,
        "backspace" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        "insert" | "ins" => KeyCode::Insert,
        name if name.starts_with('f') && name[1..].parse::<u8>().is_ok() => {
            KeyCode::F(name[1..].parse().ok()?)
        }
        _ => {
            let mut chars = token.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => KeyCode::Char(c),
                _ => return None,
            }
        }
    };
    Some(Binding { code, modifiers })
}

/// Display label for a parsed binding, e.g. `?`, `F1`, `Ctrl-x`.
fn key_label(spec: &str) -> String {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("space") {
        return "Space".to_owned();
    }
    if spec.len() == 1 {
        return spec.to_owned();
    }
    spec.to_owned()
}

/// The dashboard keymap: binding → action, plus display labels per action.
#[derive(Debug, Clone)]
pub struct KeyMap {
    map: HashMap<Binding, Action>,
    labels: HashMap<Action, Vec<String>>,
}

impl Default for KeyMap {
    fn default() -> Self {
        Self::new(Self::default_entries())
    }
}

impl KeyMap {
    fn default_entries() -> Vec<(String, Action, Vec<String>)> {
        let defaults: &[(&str, Action, &[&str])] = &[
            ("quit", Action::Quit, &["q", "Q"]),
            ("help", Action::Help, &["?", "F1"]),
            ("refresh", Action::Refresh, &["r"]),
            ("auto_refresh", Action::AutoRefresh, &["R"]),
            ("command_palette", Action::CommandPalette, &[":"]),
            ("filter", Action::Filter, &["/"]),
            ("clear_filter", Action::ClearFilter, &["Esc"]),
            ("sort", Action::Sort, &["o"]),
            ("next_interface", Action::NextInterface, &["Tab"]),
            ("prev_interface", Action::PrevInterface, &["BackTab"]),
            ("next_peer", Action::NextPeer, &["j", "Down"]),
            ("prev_peer", Action::PrevPeer, &["k", "Up"]),
            ("scroll_peers_down", Action::ScrollPeersDown, &["PageDown"]),
            ("scroll_peers_up", Action::ScrollPeersUp, &["PageUp"]),
            ("first_peer", Action::FirstPeer, &["Home"]),
            ("last_peer", Action::LastPeer, &["End"]),
            ("add_peer", Action::AddPeer, &["a"]),
            ("invite_peer", Action::InvitePeer, &["v"]),
            ("edit_peer", Action::EditPeer, &["e"]),
            ("rotate_peer", Action::RotatePeer, &["K"]),
            ("finalize_peer", Action::FinalizePeer, &["f"]),
            ("remove_peer", Action::RemovePeer, &["d"]),
            ("keygen", Action::Keygen, &["g"]),
            ("export_bundle", Action::ExportBundle, &["b", "x"]),
            ("import_bundle", Action::ImportBundle, &["i"]),
            ("ping", Action::Ping, &["p"]),
            ("yank_public_line", Action::YankPublicLine, &["y"]),
            ("yank_address", Action::YankAddress, &["Y"]),
            ("save_runtime", Action::SaveRuntime, &["W"]),
            ("runtime_form", Action::RuntimeForm, &["c"]),
            ("interface_form", Action::InterfaceForm, &["C"]),
            ("edit_config", Action::EditConfig, &["E"]),
            ("toggle_service", Action::ToggleService, &["s", "Space"]),
            // The first-run question is answered with the number it shows.
            ("setup_server", Action::SetupServer, &["1"]),
            ("setup_client", Action::SetupClient, &["2"]),
            ("logs", Action::Logs, &["l"]),
            ("health", Action::Health, &["H"]),
            // Trial arming is palette-only on purpose: there is no safe
            // single letter left for it, and a global key that reroutes all
            // host traffic is exactly the loaded-key class the GUI removed.
            // The TRIAL view's own `a`/`p` keys arm and panic once open.
            ("trial_plan", Action::TrialPlan, &[]),
            ("trial_revert", Action::TrialRevert, &[]),
            // The desk account read is palette-only: a read, not a reroute,
            // but the dashboard's single letters are all spoken for.
            ("account_panel", Action::AccountPanel, &[]),
        ];
        defaults
            .iter()
            .map(|(name, action, keys)| {
                (
                    (*name).to_owned(),
                    *action,
                    keys.iter().map(|k| (*k).to_owned()).collect(),
                )
            })
            .collect()
    }

    fn new(entries: Vec<(String, Action, Vec<String>)>) -> Self {
        let mut map = HashMap::new();
        let mut labels: HashMap<Action, Vec<String>> = HashMap::new();
        for (_name, action, keys) in entries {
            let action_labels = labels.entry(action).or_default();
            for key in keys {
                if let Some(binding) = parse_key(&key) {
                    map.insert(binding, action);
                    action_labels.push(key_label(&key));
                }
            }
        }
        Self { map, labels }
    }

    /// The action bound to this key, if any.
    #[must_use]
    pub fn action_for(&self, key: &KeyEvent) -> Option<Action> {
        self.map.get(&Binding::of(key)).copied()
    }

    /// Display labels bound to an action, for the palette and help.
    #[must_use]
    pub fn keys_for(&self, action: Action) -> &[String] {
        self.labels
            .get(&action)
            .map_or(&[], |labels| labels.as_slice())
    }

    /// Load overrides from a TOML file, replacing each named action's
    /// defaults. Returns the map and a warning describing ignored entries.
    #[must_use]
    pub fn load(path: Option<&Path>) -> (Self, Option<String>) {
        let Some(path) = resolved_path(path) else {
            return (Self::default(), None);
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                return (
                    Self::default(),
                    Some(format!("keymap {}: {error}", path.display())),
                )
            }
        };
        let table: HashMap<String, toml::Value> = match toml::from_str(&text) {
            Ok(table) => table,
            Err(error) => {
                return (
                    Self::default(),
                    Some(format!("keymap {}: {error}", path.display())),
                )
            }
        };

        let mut entries = Self::default_entries();
        let mut warnings = Vec::new();
        for (name, value) in &table {
            let Some(entry) = entries.iter_mut().find(|(known, _, _)| known == name) else {
                warnings.push(format!("unknown action '{name}'"));
                continue;
            };
            let keys: Vec<String> = match value {
                toml::Value::String(one) => vec![one.clone()],
                toml::Value::Array(many) => many
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect(),
                _ => {
                    warnings.push(format!("'{name}' must be a string or list"));
                    continue;
                }
            };
            entry.2 = keys
                .iter()
                .filter(|key| !key.trim().eq_ignore_ascii_case("none"))
                .filter(|key| {
                    if parse_key(key).is_none() {
                        warnings.push(format!("'{name}': cannot parse key '{key}'"));
                    }
                    parse_key(key).is_some()
                })
                .cloned()
                .collect();
        }
        let keymap = Self::new(entries);
        let warning = (!warnings.is_empty())
            .then(|| format!("keymap {}: {}", path.display(), warnings.join("; ")));
        (keymap, warning)
    }
}

fn resolved_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    let candidates = [
        std::env::var_os("XDG_CONFIG_HOME")
            .map(|dir| PathBuf::from(dir).join("vallum/tui-keys.toml")),
        std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".config/vallum/tui-keys.toml")),
    ];
    candidates.into_iter().flatten().find(|path| path.exists())
}
