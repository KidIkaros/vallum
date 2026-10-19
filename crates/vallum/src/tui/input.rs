// SPDX-License-Identifier: Apache-2.0

//! Key handling: modes first, then the dashboard.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::actions;
use super::app::{App, Confirm, ConfirmAction, Form, View};

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
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
            ) {
                app.view = View::Dashboard;
            }
            return;
        }
        View::Logs => {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => app.view = View::Dashboard,
                KeyCode::Char('r') => actions::load_logs(app),
                KeyCode::Char('f') => {
                    app.logs_follow = !app.logs_follow;
                    app.notify(if app.logs_follow {
                        "log follow on"
                    } else {
                        "log follow off"
                    });
                }
                _ => {}
            }
            return;
        }
        View::Diff => {
            match key.code {
                KeyCode::Enter => actions::apply_config(app),
                KeyCode::Esc | KeyCode::Char('q') => app.view = View::Dashboard,
                _ => {}
            }
            return;
        }
        View::Dashboard => {}
    }
    match key.code {
        KeyCode::Char('Q') => app.quit = true,
        KeyCode::Char('?') => app.view = View::Help,
        KeyCode::Tab => app.next_interface(),
        KeyCode::BackTab => app.previous_interface(),
        KeyCode::Char('j') | KeyCode::Down => app.next_peer(),
        KeyCode::Char('k') | KeyCode::Up => app.previous_peer(),
        KeyCode::Char('r') => actions::refresh(app),
        KeyCode::Char('a') => app.form = Some(Form::add_peer()),
        KeyCode::Char('e') => {
            if let Some(peer) = app.current_peer().cloned() {
                app.form = Some(Form::edit_peer(app.peer_selected, &peer));
            } else {
                app.notify("no peer selected");
            }
        }
        KeyCode::Char('d') => {
            if app.current_peer().is_some() {
                app.confirm = Some(Confirm {
                    action: ConfirmAction::RemovePeer(app.peer_selected),
                });
            } else {
                app.notify("no peer selected");
            }
        }
        KeyCode::Char('g') => actions::keygen(app),
        KeyCode::Char('q') => actions::export_bundle(app),
        KeyCode::Char('E') => actions::edit_config(app),
        KeyCode::Char('C') => actions::interface_form(app),
        KeyCode::Char('c') => {
            if let Some(device) = app.current_device().cloned() {
                app.form = Some(Form::device(&device));
            } else {
                app.notify("no device to configure");
            }
        }
        KeyCode::Char('s') => actions::toggle_service(app),
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
        }
        KeyCode::BackTab | KeyCode::Up => {
            form.focus = (form.focus + form.fields.len() - 1) % form.fields.len();
        }
        KeyCode::Enter => {
            app.form = Some(form);
            actions::submit_form(app);
            return;
        }
        KeyCode::Backspace => {
            form.fields[form.focus].value.pop();
        }
        KeyCode::Char(character) => {
            form.fields[form.focus].value.push(character);
        }
        _ => {}
    }
    app.form = Some(form);
}
