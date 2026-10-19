// SPDX-License-Identifier: Apache-2.0

//! Pure rendering: the frame is a function of `App`.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use super::app::{App, Form, View};

pub fn draw(frame: &mut Frame<'_>, app: &App) {
    match app.view {
        View::Help => draw_help(frame, app),
        View::Logs => draw_logs(frame, app),
        View::Diff => draw_diff(frame, app),
        View::Dashboard => draw_dashboard(frame, app),
    }
}

fn draw_dashboard(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let compact = area.width < 130;
    let header_height = if app.interfaces.is_empty() {
        3
    } else if compact {
        5
    } else {
        4
    };
    let chunks = Layout::vertical([
        Constraint::Length(header_height),
        Constraint::Min(6),
        Constraint::Length(2),
    ])
    .split(area);

    draw_header(frame, chunks[0], app, compact);
    if app.interfaces.is_empty() {
        draw_empty_state(frame, chunks[1]);
    } else if area.width < 100 {
        let body = Layout::vertical([Constraint::Percentage(54), Constraint::Percentage(46)])
            .split(chunks[1]);
        draw_peers(frame, body[0], app);
        draw_details(frame, body[1], app);
    } else {
        let body = Layout::horizontal([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(chunks[1]);
        draw_peers(frame, body[0], app);
        draw_details(frame, body[1], app);
    }
    draw_footer(frame, chunks[2], app);

    if let Some(qr) = &app.qr {
        draw_qr(frame, area, qr);
    }
    if let Some(form) = &app.form {
        draw_form(frame, area, form);
    }
    if app.confirm.is_some() {
        draw_confirm(frame, area, app);
    }
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App, compact: bool) {
    let Some(interface) = app.current() else {
        let text = vec![Line::from(Span::styled(
            "No interface connected",
            Style::default().fg(Color::Yellow),
        ))];
        frame.render_widget(
            Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Vallum")),
            area,
        );
        return;
    };
    let mut lines = Vec::new();
    let tabs: Vec<Span<'_>> = app
        .interfaces
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let style = if index == app.selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::Gray)
            };
            Span::styled(format!(" {} ", item.name), style)
        })
        .collect();
    lines.push(Line::from(tabs));
    match &interface.device {
        Some(device) => {
            if compact {
                lines.push(Line::from(format!(
                    "listen {}  suite {}  fwmark {}",
                    device.listen, device.suite, device.fwmark
                )));
                lines.push(Line::from(format!(
                    "id {}  addresses {}",
                    device.fingerprint,
                    device.addresses.join(", ")
                )));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("listen ", Style::default().fg(Color::DarkGray)),
                    Span::raw(device.listen.clone()),
                    Span::raw("  suite "),
                    Span::raw(device.suite.clone()),
                    Span::raw("  fwmark "),
                    Span::raw(device.fwmark.to_string()),
                    Span::raw("  "),
                    Span::raw(device.fingerprint.clone()),
                ]));
                lines.push(Line::from(format!(
                    "addresses {}",
                    device.addresses.join(", ")
                )));
            }
        }
        None => lines.push(Line::from(Span::styled(
            interface
                .error
                .clone()
                .unwrap_or_else(|| "no data".to_owned()),
            Style::default().fg(Color::Red),
        ))),
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Vallum")),
        area,
    );
}

fn draw_empty_state(frame: &mut Frame<'_>, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "No Vallum interface found",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Inspect a running tunnel: vallum tui --control /run/vallum/<name>.sock"),
        Line::from("Start a tunnel: sudo vallum-quick up /etc/vallum/<name>.toml"),
        Line::from("Or pass --config /path/to/config.toml or --config-dir DIR."),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Get started")),
        area,
    );
}

fn draw_peers(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let Some(device) = app.current_device() else {
        frame.render_widget(
            Paragraph::new("No device data. Press r to retry.")
                .block(Block::default().borders(Borders::ALL).title("Peers")),
            area,
        );
        return;
    };
    let expanded = area.width >= 160;
    let header = if expanded {
        Row::new(vec![
            "name",
            "fingerprint",
            "endpoint",
            "allowed",
            "handshake",
            "rx/tx",
            "epoch",
            "psk",
        ])
    } else {
        Row::new(vec!["peer", "endpoint", "handshake", "rx / tx"])
    }
    .style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    );
    let rows = device.peers.iter().map(|peer| {
        if expanded {
            Row::new(vec![
                Cell::from(peer.name.clone()),
                Cell::from(peer.fingerprint.clone()),
                Cell::from(peer.endpoint.clone()),
                Cell::from(peer.allowed_ips.join(",")),
                Cell::from(App::handshake_age(peer)),
                Cell::from(format!("{}/{}", bytes(peer.rx_bytes), bytes(peer.tx_bytes))),
                Cell::from(peer.epoch.to_string()),
                Cell::from(if peer.preshared_key { "yes" } else { "—" }),
            ])
        } else {
            Row::new(vec![
                Cell::from(peer.name.clone()),
                Cell::from(peer.endpoint.clone()),
                Cell::from(App::handshake_age(peer)),
                Cell::from(format!("{}/{}", bytes(peer.rx_bytes), bytes(peer.tx_bytes))),
            ])
        }
    });
    let widths = if expanded {
        vec![
            Constraint::Length(12),
            Constraint::Length(16),
            Constraint::Length(21),
            Constraint::Length(18),
            Constraint::Length(9),
            Constraint::Length(13),
            Constraint::Length(6),
            Constraint::Length(4),
        ]
    } else {
        vec![
            Constraint::Length(16),
            Constraint::Min(10),
            Constraint::Length(10),
            Constraint::Length(15),
        ]
    };
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(if expanded {
            "Peers"
        } else {
            "Peers (select for details)"
        }))
        .row_highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White));
    let mut state = TableState::default().with_selected(Some(app.peer_selected));
    frame.render_stateful_widget(table, area, &mut state);
}

fn draw_details(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines = Vec::new();
    if let Some(peer) = app.current_peer() {
        lines.push(Line::from(Span::styled(
            peer.name.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!("fingerprint {}", peer.fingerprint)));
        lines.push(Line::from(format!("endpoint   {}", peer.endpoint)));
        lines.push(Line::from(format!(
            "allowed    {}",
            peer.allowed_ips.join(", ")
        )));
        lines.push(Line::from(format!(
            "keepalive  {}",
            peer.keepalive
                .map_or_else(|| "off".to_owned(), |value| format!("{value}s"))
        )));
        lines.push(Line::from(format!(
            "handshake  {}",
            App::handshake_age(peer)
        )));
        lines.push(Line::from(format!(
            "transfer   rx {} / tx {}",
            bytes(peer.rx_bytes),
            bytes(peer.tx_bytes)
        )));
        lines.push(Line::from(format!("epoch      {}", peer.epoch)));
        lines.push(Line::from(format!(
            "PSK        {}",
            if peer.preshared_key {
                "configured (masked)"
            } else {
                "none"
            }
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "public line",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(peer.public_line.clone()));
    } else {
        lines.push(Line::from("No peer selected."));
    }
    if let Some(interface) = app.current() {
        if let Some(device) = &interface.device {
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "rates      rx {:.1} B/s / tx {:.1} B/s",
                interface.rx_rate, interface.tx_rate
            )));
            lines.push(Line::from(format!(
                "dataplane  offload {} · UDP batching {}",
                on_off(device.offload),
                on_off(device.batching)
            )));
            lines.push(Line::from(format!("device     {}", device.interface)));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Details"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let (navigation, actions) = if area.width < 100 {
        (
            "Tab interface  ↑/↓ peer  ? help  Q quit",
            "a add  e edit  d remove  g key  q export  s service  l logs",
        )
    } else {
        (
            "Tab interface  ↑/↓ peer  ? help  Q quit",
            "a add  e edit  d remove  g key  q export  c runtime  C config  s service  l logs  r refresh",
        )
    };
    let second = app
        .toast
        .as_ref()
        .map_or(actions, |toast| toast.message.as_str());
    let hint = vec![
        Line::from(navigation),
        Line::from(Span::styled(
            second,
            if app.toast.is_some() {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::DarkGray)
            },
        )),
    ];
    frame.render_widget(Paragraph::new(hint), area);
}

fn draw_help(frame: &mut Frame<'_>, _app: &App) {
    let text = vec![
        Line::from(Span::styled(
            "Vallum TUI",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from("Tab / Shift-Tab   switch interface"),
        Line::from("j / k, arrows     select peer"),
        Line::from("a                 add peer"),
        Line::from("e                 edit name, endpoint, allowed IPs, keepalive, PSK"),
        Line::from("d                 remove peer (confirmation)"),
        Line::from("g                 generate a key and prefill the add form"),
        Line::from("q                 export the client bundle and show its QR"),
        Line::from("c                 edit the runtime listen port and fwmark"),
        Line::from("E                 edit the TOML in $EDITOR"),
        Line::from("C                 edit listen/MTU/fwmark/addresses/DNS/table"),
        Line::from("s                 start/stop via systemd, then vallum-quick"),
        Line::from("l                 show journald logs"),
        Line::from("r                 refresh"),
        Line::from("?                 close help"),
        Line::from("Q / Ctrl-C        quit"),
        Line::from(""),
        Line::from("Forms: arrows/Home/End edit text, Ctrl-U clears the field."),
        Line::from("Secrets are masked; the private key and PSK are never shown."),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Help"))
            .wrap(Wrap { trim: false }),
        frame.area(),
    );
}

fn draw_diff(frame: &mut Frame<'_>, app: &App) {
    let Some(diff) = &app.diff else {
        return;
    };
    let width = usize::from(frame.area().width.saturating_sub(4) / 2);
    let mut lines = vec![Line::from(Span::styled(
        format!("old │ new    backup {}", diff.backup.display()),
        Style::default().fg(Color::DarkGray),
    ))];
    for row in &diff.rows {
        let style = match row.kind {
            super::app::DiffKind::Equal => Style::default().fg(Color::Gray),
            super::app::DiffKind::Delete => Style::default().fg(Color::Red),
            super::app::DiffKind::Insert => Style::default().fg(Color::Green),
            super::app::DiffKind::Replace => Style::default().fg(Color::Yellow),
        };
        let left = row.left.as_deref().unwrap_or("");
        let right = row.right.as_deref().unwrap_or("");
        lines.push(Line::from(vec![
            Span::styled(format!("{left:<width$}"), style),
            Span::raw(" │ "),
            Span::styled(right.to_owned(), style),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Config diff (Enter apply, Esc keep)"),
            )
            .wrap(Wrap { trim: false }),
        frame.area(),
    );
}

fn draw_logs(frame: &mut Frame<'_>, app: &App) {
    let lines: Vec<Line<'_>> = if app.logs.is_empty() {
        vec![Line::from(
            "No log lines loaded. Press l to fetch journald.",
        )]
    } else {
        app.logs
            .iter()
            .map(|line| Line::from(line.as_str()))
            .collect()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(if app.logs_follow {
                        "Logs (follow, f off, r refresh, Esc)"
                    } else {
                        "Logs (f follow, r refresh, Esc)"
                    }),
            )
            .wrap(Wrap { trim: false }),
        frame.area(),
    );
}

fn draw_qr(frame: &mut Frame<'_>, area: Rect, qr: &super::qr::QrState) {
    let popup = centered(area, 96, 96);
    frame.render_widget(Clear, popup);
    let mut lines = vec![Line::from(Span::styled(
        format!(
            "Bundle QR  frame {}/{}  hash {}  (secret: contains the private key)",
            qr.index + 1,
            qr.frames.len(),
            qr.hash
        ),
        Style::default().fg(Color::Yellow),
    ))];
    match super::qr::render(qr.current()) {
        Ok(rendered) => lines.extend(rendered.into_iter().map(Line::from)),
        Err(error) => lines.push(Line::from(error)),
    }
    lines.push(Line::from(format!("saved: {}", qr.path)));
    lines.push(Line::from("n/p frame  Esc close"));
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("QR")),
        popup,
    );
}

fn draw_form(frame: &mut Frame<'_>, area: Rect, form: &Form) {
    let popup = centered(area, 80, 60);
    frame.render_widget(Clear, popup);
    let mut lines = Vec::new();
    for (index, field) in form.fields.iter().enumerate() {
        let focused = index == form.focus;
        let invalid = form
            .error
            .as_ref()
            .is_some_and(|error| error.field == Some(field.label));
        let marker = if focused { ">" } else { " " };
        let mut value = if field.masked && !field.value.is_empty() {
            "************".to_owned()
        } else {
            field.value.clone()
        };
        if focused {
            if field.masked {
                value.push('|');
            } else {
                let byte_index = value
                    .char_indices()
                    .nth(form.cursor)
                    .map_or(value.len(), |(index, _)| index);
                value.insert(byte_index, '|');
            }
        }
        let style = if invalid {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else if focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{marker} {:<22} ", field.label), style),
            Span::styled(value, style),
        ]));
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("! {}", error.message),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Tab next  ←/→ move  Home/End  Ctrl-U clear  Enter submit  Esc cancel",
    ));
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(form.title.clone()),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_confirm(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let popup = centered(area, 60, 20);
    frame.render_widget(Clear, popup);
    let message = if let Some(confirm) = app.confirm {
        match confirm.action {
            super::app::ConfirmAction::RemovePeer(_) => {
                "Remove this peer?  Enter confirms, Esc cancels."
            }
            super::app::ConfirmAction::ApplyConfig => {
                "Config parsed. Apply now? Enter restarts, Esc keeps the file."
            }
        }
    } else {
        ""
    };
    frame.render_widget(
        Paragraph::new(message)
            .block(Block::default().borders(Borders::ALL).title("Confirm"))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

fn bytes(value: u64) -> String {
    if value < 1024 {
        format!("{value}B")
    } else if value < 1024 * 1024 {
        format!("{:.1}K", value as f64 / 1024.0)
    } else {
        format!("{:.1}M", value as f64 / (1024.0 * 1024.0))
    }
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}
