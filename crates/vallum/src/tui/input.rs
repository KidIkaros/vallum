// SPDX-License-Identifier: Apache-2.0

//! Key handling: modes first, then the dashboard.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

use super::actions;
use super::app::{App, Confirm, ConfirmAction, Form, View};

pub fn handle_mouse(app: &mut App, mouse: MouseEvent) {
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
            View::Help => app.help_scroll = app.help_scroll.saturating_sub(3),
            View::Dashboard => app.previous_peer(),
        },
        MouseEventKind::Down(MouseButton::Left)
            if app.view == View::Dashboard
                && app.form.is_none()
                && app.confirm.is_none()
                && app.qr.is_none() =>
        {
            if mouse.row == 1 && !app.interfaces.is_empty() {
                let mut col_accum = 1;
                for (idx, iface) in app.interfaces.iter().enumerate() {
                    let tab_width =
                        format!(" [{}/{}] {} ", idx + 1, app.interfaces.len(), iface.name)
                            .chars()
                            .count() as u16;
                    if mouse.column >= col_accum && mouse.column < col_accum + tab_width {
                        app.selected = idx;
                        app.peer_selected = 0;
                        break;
                    }
                    col_accum += tab_width;
                }
            }
            if mouse.row >= 8 {
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

pub fn handle_paste(app: &mut App, text: String) {
    let clean = text.replace(['\r', '\n'], "");
    if clean.is_empty() {
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
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => app.quit = true,
        KeyCode::Char('?') => {
            app.help_scroll = 0;
            app.view = View::Help;
        }
        KeyCode::Char('/') => {
            app.filtering = true;
        }
        KeyCode::Esc => {
            if !app.peer_filter.is_empty() {
                app.peer_filter.clear();
                app.peer_selected = 0;
                app.notify("filter cleared");
            }
        }
        KeyCode::Tab => app.next_interface(),
        KeyCode::BackTab => app.previous_interface(),
        KeyCode::Char('j') | KeyCode::Down => app.next_peer(),
        KeyCode::Char('k') | KeyCode::Up => app.previous_peer(),
        KeyCode::PageDown => app.scroll_peers(5),
        KeyCode::PageUp => app.scroll_peers(-5),
        KeyCode::Home => app.select_first_peer(),
        KeyCode::End => app.select_last_peer(),
        KeyCode::Char('o') => app.cycle_sort(),
        KeyCode::Char('y') => actions::yank_public_line(app),
        KeyCode::Char('Y') => actions::yank_peer_address(app),
        KeyCode::Char('r') => {
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
        KeyCode::Char('a') => app.form = Some(Form::add_peer()),
        KeyCode::Char('e') => {
            if let Some(peer) = app.current_peer().cloned() {
                let orig_index = app
                    .current_peer_original_index()
                    .unwrap_or(app.peer_selected);
                app.form = Some(Form::edit_peer(orig_index, &peer));
            } else {
                app.notify("no peer selected");
            }
        }
        KeyCode::Char('d') => {
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
                });
            } else {
                app.notify("no peer selected");
            }
        }
        KeyCode::Char('g') => actions::keygen(app),
        KeyCode::Char('b') | KeyCode::Char('x') => actions::export_bundle(app),
        KeyCode::Char('E') => actions::edit_config(app),
        KeyCode::Char('C') => actions::interface_form(app),
        KeyCode::Char('c') => {
            if let Some(device) = app.current_device().cloned() {
                app.form = Some(Form::device(&device));
            } else {
                app.notify("no device to configure");
            }
        }
        KeyCode::Char('s') | KeyCode::Char(' ') => actions::toggle_service(app),
        KeyCode::Char('p') => actions::ping_peer(app),
        KeyCode::Char('i') => actions::import_bundle(app),
        KeyCode::Char('W') => actions::save_runtime_config(app),
        KeyCode::Char('l') => actions::load_logs(app),
        _ => {}
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
