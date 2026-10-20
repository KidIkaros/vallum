// SPDX-License-Identifier: Apache-2.0

//! Key handling: modes first, then the dashboard.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;

use super::actions;
use super::app::{App, Confirm, ConfirmAction, Form, PaletteState, View};
use super::keymap::{self, Action};

pub fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    let size = crossterm::terminal::size().unwrap_or((120, 32));
    handle_mouse_at(app, mouse, size);
}

pub fn handle_mouse_at(app: &mut App, mouse: MouseEvent, (width, height): (u16, u16)) {
    // Command palette: rows are clickable; a click outside closes it.
    if let Some(palette) = app.palette.take() {
        if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
            let popup = super::ui::palette_rect(Rect::new(0, 0, width, height));
            let first_row = popup.y + 2; // border + input line
            let max_rows = popup.height.saturating_sub(4) as usize;
            let commands = keymap::matching_commands(&palette.input);
            if mouse.row >= first_row
                && (mouse.row - first_row) < commands.len().min(max_rows) as u16
                && mouse.column > popup.x
                && mouse.column < popup.x + popup.width - 1
            {
                let index = keymap::window_start(commands.len(), palette.selected, max_rows)
                    + (mouse.row - first_row) as usize;
                if let Some(command) = commands.get(index) {
                    dispatch(app, command.action);
                    return;
                }
            }
        } else {
            // Scroll/drag inside the palette: keep it open.
            app.palette = Some(palette);
        }
        // Left-click outside a row dismisses (palette already taken).
        return;
    }
    match mouse.kind {
        MouseEventKind::ScrollDown => match app.view {
            View::Logs => app.logs_scroll = app.logs_scroll.saturating_add(3),
            View::Diff => app.diff_scroll = app.diff_scroll.saturating_add(3),
            View::Help => app.help_scroll = app.help_scroll.saturating_add(3),
            View::Dashboard => app.next_peer(),
        },
        MouseEventKind::ScrollUp => match app.view {
            View::Logs => app.logs_scroll = app.logs_scroll.saturating_sub(3),
            View::Diff => app.diff_scroll = app.diff_scroll.saturating_sub(3),
            View::Help => app.help_scroll = app.help_scroll.saturating_add(0).saturating_sub(3),
            View::Dashboard => app.previous_peer(),
        },
        MouseEventKind::Down(MouseButton::Left)
            if app.view == View::Dashboard
                && app.form.is_none()
                && app.confirm.is_none()
                && app.qr.is_none() =>
        {
            if mouse.row == 1 && !app.interfaces.is_empty() {
                let badge_len = app
                    .current()
                    .map_or(11u16, |iface| match iface.service_state {
                        Some(super::app::ServiceState::Active) => 10,
                        Some(super::app::ServiceState::Inactive) => 12,
                        Some(super::app::ServiceState::Activating) => 12,
                        Some(super::app::ServiceState::Deactivating) => 12,
                        Some(super::app::ServiceState::Failed) => 10,
                        None => 11,
                    });
                let mut col_accum = 1 + badge_len + 1;
                if mouse.column >= 1 && mouse.column < 1 + badge_len {
                    dispatch(app, Action::ToggleService);
                    return;
                }
                for (idx, iface) in app.interfaces.iter().enumerate() {
                    let tab_width =
                        format!(" [{}/{}] {} ", idx + 1, app.interfaces.len(), iface.name)
                            .chars()
                            .count() as u16;
                    if mouse.column >= col_accum && mouse.column < col_accum + tab_width {
                        app.selected = idx;
                        app.peer_selected = 0;
                        return;
                    }
                    col_accum += tab_width;
                }
                let toggle_start = col_accum + 1;
                if mouse.column >= toggle_start && mouse.column < toggle_start + 15 {
                    dispatch(app, Action::ToggleService);
                    return;
                }
            }
            if !app.filtering && height >= 4 {
                if mouse.row == height - 2 {
                    handle_footer_nav_click(app, mouse.column);
                    return;
                }
                if mouse.row == height - 1 && app.toast.is_none() {
                    handle_footer_action_click(app, mouse.column, width);
                    return;
                }
            }
            if mouse.row >= 8 && mouse.row < height.saturating_sub(2) {
                let clicked_row = (mouse.row - 8) as usize;
                let filtered_count = app.filtered_peers().len();
                if clicked_row < filtered_count {
                    app.peer_selected = clicked_row;
                }
            }
        }
        _ => {}
    }
}

fn handle_footer_nav_click(app: &mut App, column: u16) {
    // " : commands " pill (12 cols) + "  " (2 cols)
    if column < 12 {
        dispatch(app, Action::CommandPalette);
        return;
    }
    let mut col = 14u16;
    let items: &[(&str, &str, Option<Action>)] = &[
        ("Tab", "iface", Some(Action::NextInterface)),
        ("↑/↓", "peer", Some(Action::NextPeer)),
        ("/", "filter", Some(Action::Filter)),
        ("o", "sort", Some(Action::Sort)),
        ("│", "", None),
        ("?", "help", Some(Action::Help)),
        ("q", "quit", Some(Action::Quit)),
    ];
    for &(key, label, action) in items {
        let span_width = if label.is_empty() {
            key.chars().count() as u16 + 2
        } else {
            key.chars().count() as u16 + 1 + label.chars().count() as u16 + 2
        };
        if column >= col && column < col + span_width.saturating_sub(2) {
            if let Some(act) = action {
                dispatch(app, act);
            }
            return;
        }
        col += span_width;
    }
}

fn handle_footer_action_click(app: &mut App, column: u16, width: u16) {
    let compact: &[(&str, &str, Option<Action>)] = &[
        ("Space", "toggle", Some(Action::ToggleService)),
        ("a", "add", Some(Action::AddPeer)),
        ("e", "edit", Some(Action::EditPeer)),
        ("d", "rm", Some(Action::RemovePeer)),
        ("i", "import", Some(Action::ImportBundle)),
        ("b", "bundle", Some(Action::ExportBundle)),
        ("y", "copy", Some(Action::YankPublicLine)),
    ];
    let wide: &[(&str, &str, Option<Action>)] = &[
        ("Space", "toggle", Some(Action::ToggleService)),
        ("a", "add", Some(Action::AddPeer)),
        ("e", "edit", Some(Action::EditPeer)),
        ("d", "remove", Some(Action::RemovePeer)),
        ("b", "bundle", Some(Action::ExportBundle)),
        ("i", "import", Some(Action::ImportBundle)),
        ("p", "ping", Some(Action::Ping)),
        ("y", "copy", Some(Action::YankPublicLine)),
        ("│", "", None),
        ("C", "config", Some(Action::InterfaceForm)),
        ("E", "edit", Some(Action::EditConfig)),
        ("W", "save", Some(Action::SaveRuntime)),
        ("l", "logs", Some(Action::Logs)),
        ("r", "refresh", Some(Action::Refresh)),
    ];
    let items = if width < 100 { compact } else { wide };
    let mut col = 0u16;
    for &(key, label, action) in items {
        let span_width = if label.is_empty() {
            key.chars().count() as u16 + 1
        } else {
            key.chars().count() as u16 + 1 + label.chars().count() as u16 + 2
        };
        if column >= col && column < col + span_width.saturating_sub(2) {
            if let Some(act) = action {
                dispatch(app, act);
            }
            return;
        }
        col += span_width;
    }
}

pub fn handle_paste(app: &mut App, text: String) {
    let clean = text.replace(['\r', '\n'], "");
    if clean.is_empty() {
        return;
    }
    if let Some(palette) = app.palette.as_mut() {
        palette.input.push_str(&clean);
        palette.selected = 0;
        return;
    }
    if let Some(mut form) = app.form.take() {
        let field = &mut form.fields[form.focus];
        if field.masked {
            field.value.push_str(&clean);
            form.cursor = field.value.chars().count();
        } else {
            let byte_index = field
                .value
                .char_indices()
                .nth(form.cursor)
                .map_or(field.value.len(), |(index, _)| index);
            field.value.insert_str(byte_index, &clean);
            form.cursor += clean.chars().count();
        }
        app.form = Some(form);
        return;
    }
    if app.filtering {
        app.peer_filter.push_str(&clean);
        app.peer_selected = 0;
    }
}

pub fn handle(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.quit = true;
        return;
    }
    if app.qr.is_some() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => app.qr = None,
            KeyCode::Char('n') | KeyCode::Right => {
                if let Some(qr) = app.qr.as_mut() {
                    qr.next();
                }
            }
            KeyCode::Char('p') | KeyCode::Left => {
                if let Some(qr) = app.qr.as_mut() {
                    qr.previous();
                }
            }
            _ => {}
        }
        return;
    }
    if app.filtering {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('u') {
            app.peer_filter.clear();
            app.peer_selected = 0;
            return;
        }
        match key.code {
            KeyCode::Esc => {
                app.filtering = false;
                app.peer_filter.clear();
                app.peer_selected = 0;
            }
            KeyCode::Enter => {
                app.filtering = false;
            }
            KeyCode::Backspace => {
                app.peer_filter.pop();
                app.peer_selected = 0;
            }
            KeyCode::Char(c) => {
                app.peer_filter.push(c);
                app.peer_selected = 0;
            }
            _ => {}
        }
        return;
    }
    if app.form.is_some() {
        handle_form(app, key);
        return;
    }
    if app.confirm.is_some() {
        match key.code {
            KeyCode::Enter => actions::confirm(app),
            KeyCode::Esc => app.confirm = None,
            _ => {}
        }
        return;
    }
    // The `:` command palette: type to filter, Enter runs the highlighted
    // command — every dashboard action without memorizing a binding.
    if app.palette.is_some() {
        match key.code {
            KeyCode::Esc => app.palette = None,
            KeyCode::Enter => {
                if let Some(palette) = app.palette.take() {
                    let commands = keymap::matching_commands(&palette.input);
                    if let Some(command) = commands.get(palette.selected) {
                        dispatch(app, command.action);
                    }
                }
            }
            KeyCode::Backspace => {
                if let Some(palette) = app.palette.as_mut() {
                    palette.input.pop();
                    palette.selected = 0;
                }
            }
            KeyCode::Down => {
                if let Some(palette) = app.palette.as_mut() {
                    let last = keymap::matching_commands(&palette.input)
                        .len()
                        .saturating_sub(1);
                    palette.selected = (palette.selected + 1).min(last);
                }
            }
            KeyCode::Up => {
                if let Some(palette) = app.palette.as_mut() {
                    palette.selected = palette.selected.saturating_sub(1);
                }
            }
            KeyCode::PageDown => {
                if let Some(palette) = app.palette.as_mut() {
                    let last = keymap::matching_commands(&palette.input)
                        .len()
                        .saturating_sub(1);
                    palette.selected = (palette.selected + 8).min(last);
                }
            }
            KeyCode::PageUp => {
                if let Some(palette) = app.palette.as_mut() {
                    palette.selected = palette.selected.saturating_sub(8);
                }
            }
            KeyCode::Home => {
                if let Some(palette) = app.palette.as_mut() {
                    palette.selected = 0;
                }
            }
            KeyCode::End => {
                if let Some(palette) = app.palette.as_mut() {
                    palette.selected = keymap::matching_commands(&palette.input)
                        .len()
                        .saturating_sub(1);
                }
            }
            KeyCode::Char(character) => {
                if let Some(palette) = app.palette.as_mut() {
                    palette.input.push(character);
                    palette.selected = 0;
                }
            }
            _ => {}
        }
        return;
    }
    match app.view {
        View::Help => {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => {
                    app.view = View::Dashboard;
                    app.help_scroll = 0;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    app.help_scroll = app.help_scroll.saturating_add(1);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    app.help_scroll = app.help_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    app.help_scroll = app.help_scroll.saturating_add(8);
                }
                KeyCode::PageUp => {
                    app.help_scroll = app.help_scroll.saturating_sub(8);
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    app.help_scroll = 0;
                }
                KeyCode::End | KeyCode::Char('G') => {
                    app.help_scroll = 100;
                }
                _ => {}
            }
            return;
        }
        View::Logs => {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    app.view = View::Dashboard;
                    app.logs_scroll = 0;
                }
                KeyCode::Char('r') => actions::load_logs(app),
                KeyCode::Char('f') => {
                    app.logs_follow = !app.logs_follow;
                    app.notify(if app.logs_follow {
                        "log follow on"
                    } else {
                        "log follow off"
                    });
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    app.logs_scroll = app.logs_scroll.saturating_add(1);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    app.logs_scroll = app.logs_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    app.logs_scroll = app.logs_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    app.logs_scroll = app.logs_scroll.saturating_sub(10);
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    app.logs_scroll = 0;
                }
                KeyCode::End | KeyCode::Char('G') => {
                    app.logs_scroll = app.logs.len().saturating_sub(10);
                }
                _ => {}
            }
            return;
        }
        View::Diff => {
            match key.code {
                KeyCode::Enter => actions::apply_config(app),
                KeyCode::Esc | KeyCode::Char('q') => {
                    app.view = View::Dashboard;
                    app.diff_scroll = 0;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    app.diff_scroll = app.diff_scroll.saturating_add(1);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    app.diff_scroll = app.diff_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    app.diff_scroll = app.diff_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    app.diff_scroll = app.diff_scroll.saturating_sub(10);
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    app.diff_scroll = 0;
                }
                KeyCode::End | KeyCode::Char('G') => {
                    app.diff_scroll = app
                        .diff
                        .as_ref()
                        .map_or(0, |d| d.rows.len().saturating_sub(10));
                }
                _ => {}
            }
            return;
        }
        View::Dashboard => {}
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        app.quit = true;
        return;
    }
    if let Some(action) = app.keymap.action_for(&key) {
        dispatch(app, action);
    }
}

/// Run a dashboard action, whether it came from a key binding, the command
/// palette, or a mouse click on a palette row.
fn dispatch(app: &mut App, action: Action) {
    match action {
        Action::Quit => app.quit = true,
        Action::Help => {
            app.help_scroll = 0;
            app.view = View::Help;
        }
        Action::Refresh => {
            actions::refresh(app);
            if let Some(interface) = app.current() {
                if interface.error.is_some() {
                    app.notify("refresh failed: control unavailable");
                } else {
                    app.notify("refreshed · live");
                }
            } else {
                app.notify("refreshed");
            }
        }
        Action::AutoRefresh => {
            app.refresh_rate = if app.refresh_rate == 0 { 1000 } else { 0 };
            app.notify(if app.refresh_rate == 0 {
                "auto-refresh off · r refreshes"
            } else {
                "auto-refresh on (1s)"
            });
        }
        Action::CommandPalette => app.palette = Some(PaletteState::default()),
        Action::Filter => app.filtering = true,
        Action::ClearFilter => {
            if !app.peer_filter.is_empty() {
                app.peer_filter.clear();
                app.peer_selected = 0;
                app.notify("filter cleared");
            }
        }
        Action::Sort => app.cycle_sort(),
        Action::NextInterface => app.next_interface(),
        Action::PrevInterface => app.previous_interface(),
        Action::NextPeer => app.next_peer(),
        Action::PrevPeer => app.previous_peer(),
        Action::ScrollPeersDown => app.scroll_peers(5),
        Action::ScrollPeersUp => app.scroll_peers(-5),
        Action::FirstPeer => app.select_first_peer(),
        Action::LastPeer => app.select_last_peer(),
        Action::AddPeer => app.form = Some(Form::add_peer()),
        Action::EditPeer => {
            if let Some(peer) = app.current_peer().cloned() {
                let orig_index = app
                    .current_peer_original_index()
                    .unwrap_or(app.peer_selected);
                app.form = Some(Form::edit_peer(orig_index, &peer));
            } else {
                app.notify("no peer selected");
            }
        }
        Action::RemovePeer => {
            if let Some(peer) = app.current_peer().cloned() {
                let orig_index = app
                    .current_peer_original_index()
                    .unwrap_or(app.peer_selected);
                let label = if !peer.name.is_empty() {
                    format!("peer '{}' ({})", peer.name, peer.allowed_ips.join(", "))
                } else {
                    format!(
                        "peer {} ({})",
                        peer.fingerprint,
                        peer.allowed_ips.join(", ")
                    )
                };
                app.confirm = Some(Confirm {
                    action: ConfirmAction::RemovePeer {
                        index: orig_index,
                        label,
                    },
                    config: String::new(),
                });
            } else {
                app.notify("no peer selected");
            }
        }
        Action::Keygen => actions::keygen(app),
        Action::ExportBundle => actions::export_bundle(app),
        Action::EditConfig => actions::edit_config(app),
        Action::InterfaceForm => actions::interface_form(app),
        Action::RuntimeForm => {
            if let Some(device) = app.current_device().cloned() {
                app.form = Some(Form::device(&device));
            } else {
                app.notify("no device to configure");
            }
        }
        Action::ToggleService => actions::toggle_service(app),
        Action::Ping => actions::ping_peer(app),
        Action::ImportBundle => actions::import_bundle(app),
        Action::YankPublicLine => actions::yank_public_line(app),
        Action::YankAddress => actions::yank_peer_address(app),
        Action::SaveRuntime => actions::save_runtime_config(app),
        Action::Logs => actions::load_logs(app),
    }
}

fn handle_form(app: &mut App, key: KeyEvent) {
    let Some(mut form) = app.form.clone() else {
        return;
    };
    match key.code {
        KeyCode::Esc => {
            app.form = None;
            return;
        }
        KeyCode::Tab | KeyCode::Down => {
            form.focus = (form.focus + 1) % form.fields.len();
            form.cursor = form.fields[form.focus].value.chars().count();
        }
        KeyCode::BackTab | KeyCode::Up => {
            form.focus = (form.focus + form.fields.len() - 1) % form.fields.len();
            form.cursor = form.fields[form.focus].value.chars().count();
        }
        KeyCode::Enter => {
            app.form = Some(form);
            actions::submit_form(app);
            return;
        }
        KeyCode::Backspace => {
            let field = &mut form.fields[form.focus];
            if field.masked {
                field.value.pop();
                form.cursor = field.value.chars().count();
            } else if form.cursor > 0 {
                if let Some((byte_index, _)) = field.value.char_indices().nth(form.cursor - 1) {
                    field.value.remove(byte_index);
                    form.cursor -= 1;
                }
            }
        }
        KeyCode::Delete => {
            let field = &mut form.fields[form.focus];
            if !field.masked {
                if let Some((byte_index, _)) = field.value.char_indices().nth(form.cursor) {
                    field.value.remove(byte_index);
                }
            }
        }
        KeyCode::Left => {
            if !form.fields[form.focus].masked {
                form.cursor = form.cursor.saturating_sub(1);
            }
        }
        KeyCode::Right => {
            if !form.fields[form.focus].masked {
                form.cursor = (form.cursor + 1).min(form.fields[form.focus].value.chars().count());
            }
        }
        KeyCode::Home => {
            if !form.fields[form.focus].masked {
                form.cursor = 0;
            }
        }
        KeyCode::End => {
            form.cursor = form.fields[form.focus].value.chars().count();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            form.fields[form.focus].value.clear();
            form.cursor = 0;
        }
        KeyCode::Char(character) => {
            let field = &mut form.fields[form.focus];
            let byte_index = if field.masked {
                field.value.len()
            } else {
                field
                    .value
                    .char_indices()
                    .nth(form.cursor)
                    .map_or(field.value.len(), |(index, _)| index)
            };
            field.value.insert(byte_index, character);
            form.cursor += 1;
        }
        _ => {}
    }
    app.form = Some(form);
}
