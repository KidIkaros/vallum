// SPDX-License-Identifier: Apache-2.0

//! Pure rendering: the frame is a function of `App`.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState, Wrap,
};
use ratatui::Frame;

use super::app::{App, Form, HandshakeFreshness, Interface, ServiceState, View};
use super::theme::{abbreviate_public_line, theme, transfer_share_bar};

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
    let header_height = if app.interfaces.is_empty() { 3 } else { 6 };
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
        let body = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)])
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
    if app.palette.is_some() {
        draw_palette(frame, area, app);
    }
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App, compact: bool) {
    let Some(interface) = app.current() else {
        frame.render_widget(
            Paragraph::new(vec![Line::from(Span::styled(
                "No interface connected",
                Style::default().fg(Color::Yellow),
            ))])
            .block(brand_block("TUNNEL CONTROL")),
            area,
        );
        return;
    };

    let (main_area, traffic_area) = if area.width >= 100 {
        let chunks = Layout::horizontal([Constraint::Min(60), Constraint::Length(34)]).split(area);
        (chunks[0], Some(chunks[1]))
    } else {
        (area, None)
    };

    // The badge reports the systemd unit state only. When no unit is known
    // (for example a --control socket with no config), it says so instead of
    // guessing from control reachability — the CONTROL line carries that.
    let status_badge = match interface.service_state {
        Some(ServiceState::Active) => Span::styled(
            " ● ACTIVE ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Some(ServiceState::Inactive) => Span::styled(
            " ○ INACTIVE ",
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Some(ServiceState::Activating) => Span::styled(
            " ◐ STARTING ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Some(ServiceState::Deactivating) => Span::styled(
            " ◑ STOPPING ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Some(ServiceState::Failed) => Span::styled(
            " ✖ FAILED ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        None => Span::styled(
            " ◌ NO UNIT ",
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let mut lines = Vec::new();
    let tabs: Vec<Span<'_>> = app
        .interfaces
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let style = if index == app.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Span::styled(
                format!(" [{}/{}] {} ", index + 1, app.interfaces.len(), item.name),
                style,
            )
        })
        .collect();

    let mut first_row = vec![status_badge, Span::raw(" ")];
    first_row.extend(tabs);
    first_row.push(Span::raw(" "));
    first_row.push(Span::styled(
        "[Space: toggle]",
        Style::default().fg(Color::DarkGray),
    ));
    lines.push(Line::from(first_row));
    lines.push(control_health_line(interface));
    match &interface.device {
        Some(device) => {
            let suite_display = suite_label(&device.suite);
            if compact {
                lines.push(Line::from(vec![
                    Span::styled("listen ", Style::default().fg(Color::DarkGray)),
                    Span::styled(device.listen.clone(), Style::default().fg(Color::White)),
                    Span::styled("  suite ", Style::default().fg(Color::DarkGray)),
                    Span::styled(suite_display, Style::default().fg(Color::Cyan)),
                    Span::styled("  fwmark ", Style::default().fg(Color::DarkGray)),
                    Span::styled(device.fwmark.to_string(), Style::default().fg(Color::Gray)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("id ", Style::default().fg(Color::DarkGray)),
                    Span::styled(device.fingerprint.clone(), Style::default().fg(Color::Gray)),
                    Span::styled("  addresses ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        device.addresses.join(", "),
                        Style::default().fg(Color::White),
                    ),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("listen ", Style::default().fg(Color::DarkGray)),
                    Span::styled(device.listen.clone(), Style::default().fg(Color::White)),
                    Span::styled("  suite ", Style::default().fg(Color::DarkGray)),
                    Span::styled(suite_display, Style::default().fg(Color::Cyan)),
                    Span::styled("  fwmark ", Style::default().fg(Color::DarkGray)),
                    Span::styled(device.fwmark.to_string(), Style::default().fg(Color::Gray)),
                    Span::styled("  id ", Style::default().fg(Color::DarkGray)),
                    Span::styled(device.fingerprint.clone(), Style::default().fg(Color::Gray)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("addresses ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        device.addresses.join(", "),
                        Style::default().fg(Color::White),
                    ),
                ]));
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
            .block(brand_block("TUNNEL CONTROL")),
        main_area,
    );

    if let Some(t_area) = traffic_area {
        let block = brand_block("TRAFFIC");
        let inner = block.inner(t_area);
        frame.render_widget(block, t_area);

        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

        let t = theme();
        let (total_rx, total_tx) = interface.device.as_ref().map_or((0u64, 0u64), |dev| {
            (
                dev.peers.iter().map(|p| p.rx_bytes).sum(),
                dev.peers.iter().map(|p| p.tx_bytes).sum(),
            )
        });
        let rx_peak = interface.rx_history.iter().copied().max().unwrap_or(0);
        let tx_peak = interface.tx_history.iter().copied().max().unwrap_or(0);
        // Shared scale ceiling across RX & TX with a 1 KB/s floor so sub-1KB/s
        // keepalive noise never renders as full-height bars (Tufte Lie Factor = 1).
        let scale_max = rx_peak.max(tx_peak).max(1024);
        let baseline = "▁".repeat(inner.width as usize);

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("▼ RX ", t.accent()),
                Span::styled(format!("{:<10}", rate_label(interface.rx_rate)), t.text()),
                Span::styled(
                    format!("Σ {} · pk {}", bytes(total_rx), bytes(rx_peak)),
                    t.muted(),
                ),
            ])),
            rows[0],
        );
        if rx_peak > 0 {
            frame.render_widget(
                Sparkline::default()
                    .data(&interface.rx_history)
                    .max(scale_max)
                    .style(t.signal()),
                rows[1],
            );
        } else {
            frame.render_widget(
                Paragraph::new(Span::styled(baseline.clone(), t.muted())),
                rows[1],
            );
        }
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("▲ TX ", t.tx_signal()),
                Span::styled(format!("{:<10}", rate_label(interface.tx_rate)), t.text()),
                Span::styled(
                    format!("Σ {} · pk {}", bytes(total_tx), bytes(tx_peak)),
                    t.muted(),
                ),
            ])),
            rows[2],
        );
        if tx_peak > 0 {
            frame.render_widget(
                Sparkline::default()
                    .data(&interface.tx_history)
                    .max(scale_max)
                    .style(t.tx_bar()),
                rows[3],
            );
        } else {
            frame.render_widget(Paragraph::new(Span::styled(baseline, t.muted())), rows[3]);
        }
    }
}

fn suite_label(suite: &str) -> String {
    match suite.trim() {
        "0x0003" => "0x0003 (tri-hybrid)".to_owned(),
        "0x0002" => "0x0002 (ml-kem-768)".to_owned(),
        "0x0001" => "0x0001 (sntrup761)".to_owned(),
        other => other.to_owned(),
    }
}

fn brand_title(section: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled("◆ ", Style::default().fg(Color::Cyan)),
        Span::styled(
            "Vallum".to_owned(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" ❯ ", Style::default().fg(Color::DarkGray)),
        Span::styled(section.into(), Style::default().fg(Color::Gray)),
    ])
}

fn brand_block(title: impl Into<String>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(brand_title(title))
}

fn modal_block(title: impl Into<String>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(brand_title(title))
}

fn control_health_line(interface: &Interface) -> Line<'static> {
    let (label, color) = match (&interface.device, &interface.error) {
        (Some(_), None) => ("CONTROL LIVE", Color::Green),
        (Some(_), Some(_)) => ("CONTROL STALE", Color::Yellow),
        (None, Some(_)) => ("CONTROL UNAVAILABLE", Color::Red),
        (None, None) => ("CONTROL CONNECTING", Color::DarkGray),
    };
    let mut spans = vec![Span::styled(
        label,
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )];
    if let Some(age) = interface.last_successful_poll_age() {
        spans.push(Span::raw(" · last reply "));
        spans.push(Span::raw(duration_label(age)));
    }
    if let Some(state) = interface.service_state {
        spans.push(Span::raw(" · systemd "));
        spans.push(Span::styled(
            state.label(),
            Style::default().fg(service_state_color(state)),
        ));
    }
    Line::from(spans)
}

fn service_state_color(state: ServiceState) -> Color {
    match state {
        ServiceState::Active => Color::Green,
        ServiceState::Inactive => Color::DarkGray,
        ServiceState::Failed => Color::Red,
        ServiceState::Activating | ServiceState::Deactivating => Color::Yellow,
    }
}

fn freshness_color(freshness: HandshakeFreshness) -> Color {
    match freshness {
        HandshakeFreshness::Never => Color::Red,
        HandshakeFreshness::Recent => Color::Green,
        HandshakeFreshness::Aging => Color::Yellow,
        HandshakeFreshness::Old => Color::DarkGray,
    }
}

fn handshake_summary(peer: &super::app::PeerView) -> String {
    let freshness = App::handshake_freshness(peer);
    if freshness == HandshakeFreshness::Never {
        freshness.label().to_owned()
    } else {
        format!("{} · {}", freshness.label(), App::handshake_age(peer))
    }
}

fn duration_label(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 60 * 60 {
        format!("{}m", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h", seconds / (60 * 60))
    } else {
        format!("{}d", seconds / (24 * 60 * 60))
    }
}

fn draw_empty_state(frame: &mut Frame<'_>, area: Rect) {
    let mut text = Vec::new();
    if area.height >= 10 {
        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled(
                " ◆ VALLUM ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  ──●──◆──●──  ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "EVERY BOUNDARY UNDER WATCH",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        text.push(Line::from(vec![
            Span::styled("  suite 0x0003 ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "X25519 + sntrup761 + ML-KEM-768 (tri-hybrid)",
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                " · layer-3 post-quantum tunnel",
                Style::default().fg(Color::Gray),
            ),
        ]));
        text.push(Line::from(""));
    }

    // The one question that decides everything after it. Two roles, the
    // command each needs for *this* machine, and nothing else — the full
    // command list is behind `vallum --help` and the palette.
    text.push(Line::from(vec![
        Span::styled("◌ ", Style::default().fg(Color::Yellow)),
        Span::styled(
            "No tunnel on this machine yet.",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  What is this machine?", Style::default().fg(Color::White)),
    ]));
    text.push(Line::from(""));
    for (key, role, detail, command) in [
        (
            " 1 ",
            "The server",
            "clients connect to it",
            "sudo vallum setup --server",
        ),
        (
            " 2 ",
            "The client",
            "it connects to a server (key stays on this machine)",
            "sudo vallum setup --remote you@<server>   (or --join / --client <file>.vallum-bundle)",
        ),
    ] {
        text.push(Line::from(vec![
            Span::styled(
                key,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {role:<12}"),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(detail, Style::default().fg(Color::Gray)),
        ]));
        // A visible marker, not leading spaces: the paragraph wraps with
        // `trim: true`, which eats indentation and left the command stranded
        // in column zero.
        text.push(Line::from(vec![
            Span::styled("  → ", Style::default().fg(Color::DarkGray)),
            Span::styled(command, Style::default().fg(Color::Cyan)),
        ]));
        text.push(Line::from(""));
    }
    text.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            "1 or 2 copies the command for this machine",
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        Span::styled("i", Style::default().fg(Color::Cyan)),
        Span::styled(
            " imports a bundle here ",
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("· ", Style::default().fg(Color::DarkGray)),
        Span::styled(":", Style::default().fg(Color::Cyan)),
        Span::styled(" every action ", Style::default().fg(Color::DarkGray)),
        Span::styled("· ", Style::default().fg(Color::DarkGray)),
        Span::styled("?", Style::default().fg(Color::Cyan)),
        Span::styled(" help", Style::default().fg(Color::DarkGray)),
    ]));
    if area.height >= 18 {
        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                "Already have a config? ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "vallum tui --config /path/to/config.toml",
                Style::default().fg(Color::Gray),
            ),
        ]));
    }
    text.push(Line::from(""));
    text.push(Line::from(Span::styled(
        "  Ikaros Digital × Atomguard · zero-compromise post-quantum systems engineering",
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .block(brand_block("GET STARTED")),
        area,
    );
}

fn draw_peers(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let Some(device) = app.current_device() else {
        let message = app
            .current()
            .and_then(|interface| interface.error.as_deref())
            .unwrap_or("No device data. Press r to retry.");
        frame.render_widget(Paragraph::new(message).block(brand_block("Peers")), area);
        return;
    };

    let is_stale = app
        .current()
        .is_some_and(|interface| interface.error.is_some());
    if device.peers.is_empty() {
        let title = if is_stale {
            "Peers (stale snapshot)"
        } else {
            "Peers"
        };
        let empty_text = if is_stale {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "Control socket disconnected — showing retained snapshot",
                    Style::default().fg(Color::Yellow),
                )),
                Line::from("Press 'r' to retry connecting."),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "No peers configured yet",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::raw("Press "),
                    Span::styled(
                        "a",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" to add a peer, or "),
                    Span::styled(
                        "g",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" to generate keys."),
                ]),
            ]
        };
        frame.render_widget(
            Paragraph::new(empty_text)
                .block(brand_block(title))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let filtered = app.filtered_peers();
    let total_count = device.peers.len();
    let filtered_count = filtered.len();

    let expanded = area.width >= 101;
    let header = if expanded {
        Row::new(vec![
            "name",
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
    let rows: Vec<Row> = if filtered_count == 0 {
        if expanded {
            vec![Row::new(vec![
                Cell::from("no match").style(Style::default().fg(Color::Yellow)),
                Cell::from(format!("filter: \"{}\"", app.peer_filter))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ])]
        } else {
            vec![Row::new(vec![
                Cell::from("no match").style(Style::default().fg(Color::Yellow)),
                Cell::from(format!("filter: \"{}\"", app.peer_filter))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(""),
                Cell::from(""),
            ])]
        }
    } else {
        filtered
            .iter()
            .map(|(_, peer)| {
                let freshness = App::handshake_freshness(peer);
                let hs_label = if expanded || freshness == HandshakeFreshness::Never {
                    freshness.label().to_owned()
                } else {
                    format!("{} {}", freshness.label(), App::handshake_age(peer))
                };
                let handshake = Cell::from(hs_label).style(
                    Style::default()
                        .fg(freshness_color(freshness))
                        .add_modifier(Modifier::BOLD),
                );
                if expanded {
                    Row::new(vec![
                        Cell::from(peer.name.clone()),
                        Cell::from(peer.endpoint.clone()),
                        Cell::from(peer.allowed_ips.join(",")),
                        handshake,
                        Cell::from(format!("{}/{}", bytes(peer.rx_bytes), bytes(peer.tx_bytes))),
                        Cell::from(peer.epoch.to_string()),
                        Cell::from(if peer.preshared_key { "yes" } else { "—" }),
                    ])
                } else {
                    Row::new(vec![
                        Cell::from(peer.name.clone()),
                        Cell::from(peer.endpoint.clone()),
                        handshake,
                        Cell::from(format!("{}/{}", bytes(peer.rx_bytes), bytes(peer.tx_bytes))),
                    ])
                }
            })
            .collect()
    };
    let widths = if expanded {
        vec![
            Constraint::Length(20),
            Constraint::Length(24),
            Constraint::Length(14),
            Constraint::Length(9),
            Constraint::Length(13),
            Constraint::Length(6),
            Constraint::Length(4),
        ]
    } else {
        vec![
            Constraint::Length(20),
            Constraint::Min(10),
            Constraint::Length(12),
            Constraint::Length(14),
        ]
    };
    let sort_suffix = if app.sort_mode != super::app::SortMode::Natural {
        format!(", sort: {}", app.sort_mode.label())
    } else {
        String::new()
    };
    let table_title = if app
        .current()
        .is_some_and(|interface| interface.error.is_some())
    {
        "Peers (stale snapshot)".to_owned()
    } else if !app.peer_filter.is_empty() || app.filtering {
        format!(
            "Peers (filter: \"{}\" [{filtered_count}/{total_count}]{sort_suffix})",
            app.peer_filter
        )
    } else if expanded {
        format!("Peers [{total_count}]{sort_suffix}")
    } else {
        format!("Peers [{total_count}]{sort_suffix} (select for details)")
    };
    let table = Table::new(rows, widths)
        .header(header)
        .block(brand_block(table_title))
        .row_highlight_style(theme().row_selected())
        .highlight_symbol("❯ ");
    let selected = if filtered_count > 0 {
        Some(app.peer_selected.min(filtered_count - 1))
    } else {
        None
    };
    let mut state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, area, &mut state);
}

fn detail_kv(label: &'static str, value: impl Into<String>, value_style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:<11} "),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(value.into(), value_style),
    ])
}

fn draw_details(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if area.height < 11 {
        draw_compact_details(frame, area, app);
        return;
    }
    let mut lines = Vec::new();
    if let Some(peer) = app.current_peer() {
        let freshness = App::handshake_freshness(peer);
        lines.push(Line::from(vec![
            Span::styled("● ", Style::default().fg(freshness_color(freshness))),
            Span::styled(
                peer.name.clone(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        let fp = if peer.fingerprint.is_empty() {
            "—".to_owned()
        } else {
            peer.fingerprint.clone()
        };
        lines.push(detail_kv(
            "fingerprint",
            fp,
            Style::default().fg(Color::Gray),
        ));
        lines.push(detail_kv(
            "endpoint",
            peer.endpoint.clone(),
            Style::default().fg(Color::White),
        ));
        lines.push(detail_kv(
            "allowed",
            peer.allowed_ips.join(", "),
            Style::default().fg(Color::White),
        ));
        lines.push(detail_kv(
            "keepalive",
            peer.keepalive
                .map_or_else(|| "off".to_owned(), |value| format!("{value}s")),
            Style::default().fg(Color::Gray),
        ));
        lines.push(Line::from(vec![
            Span::styled("handshake   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                freshness.label(),
                Style::default()
                    .fg(freshness_color(freshness))
                    .add_modifier(Modifier::BOLD),
            ),
            if freshness == HandshakeFreshness::Never {
                Span::raw("")
            } else {
                Span::styled(
                    format!(" · {}", App::handshake_age(peer)),
                    Style::default().fg(Color::Gray),
                )
            },
        ]));
        let t = theme();
        let (rx_bar, tx_bar) = transfer_share_bar(peer.rx_bytes, peer.tx_bytes, 10);
        lines.push(Line::from(vec![
            Span::styled("transfer    ", t.muted()),
            Span::styled(
                format!("rx {} / tx {} ", bytes(peer.rx_bytes), bytes(peer.tx_bytes)),
                t.text(),
            ),
            Span::styled(rx_bar, t.signal()),
            Span::styled(tx_bar, t.tx_bar()),
        ]));
        lines.push(detail_kv("epoch", peer.epoch.to_string(), t.subtext()));
        // An expiring credential is the one thing a peer detail can show that
        // the operator must act on, so it is never silent.
        if let Some(valid_until) = peer.valid_until {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            let days = (i64::try_from(valid_until).unwrap_or(i64::MAX)
                - i64::try_from(now).unwrap_or(i64::MAX))
            .div_euclid(86_400);
            let (label, style) = if days < 0 {
                (format!("EXPIRED {}d ago", -days), t.danger_bold())
            } else if days <= 14 {
                (format!("{days}d left"), t.warn_bold())
            } else {
                (format!("{days}d left"), t.ok())
            };
            lines.push(detail_kv("identity", label, style));
        }
        if peer.rotating {
            lines.push(detail_kv(
                "rotation",
                "open — previous key still accepted (press f to finalize)",
                t.warn_bold(),
            ));
        }
        lines.push(detail_kv(
            "PSK",
            if peer.preshared_key {
                "configured (masked)"
            } else {
                "none"
            },
            if peer.preshared_key {
                t.ok()
            } else {
                t.muted()
            },
        ));
        let inner_w = area.width.saturating_sub(2);
        lines.push(Line::from(""));
        lines.push(t.section_rule(inner_w, "public line (y to copy)"));
        lines.push(Line::from(Span::styled(
            abbreviate_public_line(&peer.public_line, usize::from(inner_w).max(36)),
            t.subtext(),
        )));
    } else if !app.peer_filter.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("No peers match filter \"{}\"", app.peer_filter),
            theme().warn(),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from("Press Esc or Ctrl-U to clear filter."));
    } else {
        lines.push(Line::from("No peer selected."));
    }
    if let Some(interface) = app.current() {
        if let Some(device) = &interface.device {
            lines.push(Line::from(""));
            lines.push(theme().section_rule(area.width.saturating_sub(2), "interface dataplane"));
            if let Some(stats) = device.stats {
                let t = theme();
                for (label, ok, failed) in [
                    ("datagrams", stats.datagrams_sent, stats.datagrams_failed),
                    ("packets", stats.packets_delivered, stats.packets_failed),
                    ("handshakes", stats.established, stats.refusals),
                    ("fragments", stats.reassembled, stats.fragments_dropped),
                ] {
                    let (ok_label, fail_label) = match label {
                        "datagrams" => ("sent", "send failed"),
                        "packets" => ("delivered", "write failed"),
                        "handshakes" => ("established", "refused"),
                        _ => ("reassembled", "dropped"),
                    };
                    let fail_style = if failed > 0 {
                        t.danger_bold()
                    } else {
                        t.muted()
                    };
                    lines.push(Line::from(vec![
                        Span::styled(format!("{label:<11}"), t.muted()),
                        Span::styled(format!("{ok_label} {ok}"), t.text()),
                        Span::styled("  ·  ", t.muted()),
                        Span::styled(format!("{fail_label} {failed}"), fail_style),
                    ]));
                }
            }
            lines.push(detail_kv(
                "rates",
                format!(
                    "rx {} / tx {}",
                    rate_label(interface.rx_rate),
                    rate_label(interface.tx_rate)
                ),
                Style::default().fg(Color::Gray),
            ));
            lines.push(detail_kv(
                "dataplane",
                format!(
                    "offload {} · UDP batching {}",
                    on_off(device.offload),
                    on_off(device.batching)
                ),
                Style::default().fg(Color::Gray),
            ));
            lines.push(detail_kv(
                "device",
                device.interface.clone(),
                Style::default().fg(Color::White),
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(brand_block("PEER DETAILS"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_compact_details(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let lines = if let Some(peer) = app.current_peer() {
        vec![
            Line::from(format!("{} [{}]", peer.name, peer.fingerprint)),
            Line::from(format!(
                "endpoint {} · keepalive {}",
                peer.endpoint,
                peer.keepalive
                    .map_or_else(|| "off".to_owned(), |value| format!("{value}s"))
            )),
            Line::from(format!("allowed {}", peer.allowed_ips.join(", "))),
            Line::from(format!("handshake {}", handshake_summary(peer))),
            Line::from(format!(
                "rx {} / tx {} · PSK {}",
                bytes(peer.rx_bytes),
                bytes(peer.tx_bytes),
                if peer.preshared_key {
                    "configured"
                } else {
                    "none"
                }
            )),
        ]
    } else if !app.peer_filter.is_empty() {
        vec![
            Line::from(Span::styled(
                format!("No peers match \"{}\"", app.peer_filter),
                Style::default().fg(Color::Yellow),
            )),
            Line::from("Esc or Ctrl-U to clear filter"),
        ]
    } else {
        let mut lines = vec![Line::from("No peer selected.")];
        if let Some(device) = app.current_device() {
            lines.push(Line::from(format!("device {}", device.interface)));
            lines.push(Line::from(format!(
                "offload {} · UDP batching {}",
                on_off(device.offload),
                on_off(device.batching)
            )));
        }
        lines
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(brand_block("PEER DETAILS"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn key_capsule<'a>(key: &'a str, label: &'a str) -> Vec<Span<'a>> {
    if label.is_empty() {
        vec![
            Span::styled(
                key,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
        ]
    } else {
        vec![
            Span::styled(
                key,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(label, Style::default().fg(Color::DarkGray)),
            Span::raw("  "),
        ]
    }
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if app.qr.is_some() || app.form.is_some() || app.confirm.is_some() || app.palette.is_some() {
        return;
    }
    if app.filtering {
        let filter_line = Line::from(vec![
            Span::styled(
                " FILTER ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                &app.peer_filter,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("█", Style::default().fg(Color::Cyan)),
            Span::raw("  "),
            Span::styled(
                "(Enter: apply · Esc: cancel · Ctrl-U: clear)",
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        frame.render_widget(Paragraph::new(vec![filter_line, Line::from("")]), area);
        return;
    }

    let mut nav_spans = vec![
        Span::styled(
            " : commands ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
    ];
    // Keys that need an interface are not shown when there is none: a footer
    // of actions that cannot run is a promise the screen does not keep.
    if app.current().is_some() {
        nav_spans.extend(key_capsule("Tab", "iface"));
        nav_spans.extend(key_capsule("↑/↓", "peer"));
        nav_spans.extend(key_capsule("/", "filter"));
        nav_spans.extend(key_capsule("o", "sort"));
        nav_spans.push(Span::styled("│  ", Style::default().fg(Color::DarkGray)));
    }
    nav_spans.extend(key_capsule("?", "help"));
    nav_spans.extend(key_capsule("q", "quit"));

    let second_line = if let Some(toast) = &app.toast {
        Line::from(vec![
            Span::styled(
                " ▸ ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                &toast.message,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else if app.current().is_none() {
        // Nothing is running: the only honest actions are the ones that work.
        Line::from(vec![
            Span::styled(" ▸ ", Style::default().fg(Color::DarkGray)),
            Span::styled("choose 1 or 2 above · ", Style::default().fg(Color::Gray)),
            Span::styled(":", Style::default().fg(Color::Cyan)),
            Span::styled(" every action · ", Style::default().fg(Color::DarkGray)),
            Span::styled("?", Style::default().fg(Color::Cyan)),
            Span::styled(" help", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        let has_peers = app
            .current_device()
            .is_some_and(|dev| !dev.peers.is_empty());
        let rotating = app.current_peer().is_some_and(|peer| peer.rotating);
        let mut act_spans = Vec::new();
        act_spans.extend(key_capsule("Space", "toggle"));
        act_spans.extend(key_capsule("a", "add"));
        act_spans.extend(key_capsule("v", "invite"));
        if has_peers {
            act_spans.extend(key_capsule("e", "edit"));
            if area.width < 100 {
                act_spans.extend(key_capsule("d", "rm"));
                act_spans.extend(key_capsule("y", "copy"));
            } else {
                act_spans.extend(key_capsule("d", "remove"));
                act_spans.extend(key_capsule("p", "ping"));
                act_spans.extend(key_capsule("y", "copy"));
            }
            if rotating {
                act_spans.push(Span::styled("f", theme().warn_bold()));
                act_spans.push(Span::raw(" "));
                act_spans.push(Span::styled("finalize  ", theme().warn()));
            }
        } else {
            act_spans.extend(key_capsule("i", "import"));
        }
        if area.width >= 100 {
            act_spans.push(Span::styled("│ ", theme().muted()));
            act_spans.extend(key_capsule("C", "config"));
            act_spans.extend(key_capsule("l", "logs"));
            act_spans.extend(key_capsule("r", "refresh"));
        }
        Line::from(act_spans)
    };

    let hint = vec![Line::from(nav_spans), second_line];
    frame.render_widget(Paragraph::new(hint), area);
}

fn help_row(keys: &'static str, desc: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {keys:<17} "),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(desc, Style::default().fg(Color::White)),
    ])
}

fn help_section(title: &'static str) -> Line<'static> {
    Line::from(Span::styled(
        format!("── {title} "),
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    ))
}

fn draw_help(frame: &mut Frame<'_>, app: &App) {
    let text = vec![
        Line::from(vec![
            Span::styled(
                " ◆ VALLUM ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  ──●──◆──●──  OPERATIONS COCKPIT REFERENCE",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        help_section("Command Palette & Navigation (or click footer / rows)"),
        help_row(
            ":",
            "command palette — every action by name, click or Enter",
        ),
        help_row("Tab / Shift-Tab", "switch interface (or click header tab)"),
        help_row("j / k, arrows", "select peer (or click row / scroll wheel)"),
        help_row("/", "filter peers by name, IP, endpoint, or fingerprint"),
        help_row(
            "o",
            "cycle peer sorting (natural, handshake, transfer, name)",
        ),
        help_row("Home / End", "jump to first / last peer"),
        help_row("PgUp / PgDn", "scroll 5 peers / scroll logs & diff"),
        help_row("g / G", "jump to top / bottom (logs, diff, help)"),
        Line::from(""),
        help_section("Peer Management & Optical Provisioning"),
        help_row("a", "add peer…"),
        help_row("v", "invite peer — one-time token + QR (no private key)…"),
        help_row("e", "edit name, endpoint, allowed IPs, keepalive, PSK…"),
        help_row("K", "rotate peer key — zero-downtime rekey…"),
        help_row("f", "finalize open key rotation — retires old key…"),
        help_row("d", "remove peer (with confirmation preview)…"),
        help_row("g", "generate a key and prefill the add form…"),
        help_row("b / x", "export client bundle and show scannable QR…"),
        help_row("i", "import client bundle (.vallum-bundle) into daemon…"),
        help_row("p", "ping selected peer's tunnel IP (runs off-loop)"),
        help_row("y", "copy peer public line (OSC 52 + wl-copy/xclip)"),
        help_row("Y", "copy peer address / endpoint (same reporting)"),
        Line::from(""),
        help_section("Tunnel Service & Configuration"),
        help_row(
            "Space / s",
            "toggle tunnel up / down (or click status badge)",
        ),
        help_row("c", "edit runtime listen port and fwmark (temporary)…"),
        help_row("C", "edit listen/MTU/fwmark/addresses/DNS/table (on disk)…"),
        help_row("E", "edit TOML in $EDITOR (with side-by-side diff review)…"),
        help_row("W", "write/save runtime configuration to disk"),
        help_row(
            "l",
            "show journald logs (scroll with j/k/PgUp/PgDn, f follow)",
        ),
        help_row("r / R", "refresh snapshot now / toggle 1s auto-refresh"),
        help_row("? / F1", "open or close this help"),
        help_row("q / Q / Ctrl-C", "quit / close view"),
        Line::from(""),
        help_section("Operational Semantics & Security"),
        Line::from("  CONTROL reports UAPI reachability; systemd unit state is separate."),
        Line::from("  Handshake tags: RECENT <5m, AGING <1h, OLD >1h, or NEVER."),
        Line::from("  Forms: Tab moves fields, arrows edit text, Ctrl-U clears."),
        Line::from("  Keys are remappable: vallum tui --keys FILE or"),
        Line::from("  ~/.config/vallum/tui-keys.toml (e.g. add_peer = \"n\")."),
        Line::from("  Secrets are masked; private keys and PSK are never rendered."),
        Line::from("  Developed in partnership by Ikaros Digital × Atomguard."),
    ];
    let visible = usize::from(frame.area().height.saturating_sub(2));
    let scroll_y = (app.help_scroll as u16).min(text.len().saturating_sub(visible) as u16);
    frame.render_widget(
        Paragraph::new(text)
            .scroll((scroll_y, 0))
            .block(modal_block("QUICK GUIDE"))
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
    let t = theme();
    for row in &diff.rows {
        let (glyph, style) = match row.kind {
            super::app::DiffKind::Equal => (' ', t.subtext()),
            super::app::DiffKind::Delete => ('-', t.danger()),
            super::app::DiffKind::Insert => ('+', t.ok()),
            super::app::DiffKind::Replace => ('~', t.warn()),
        };
        let left = row.left.as_deref().unwrap_or("");
        let right = row.right.as_deref().unwrap_or("");
        let col_w = width.saturating_sub(2);
        lines.push(Line::from(vec![
            Span::styled(format!("{glyph} {left:<col_w$}"), style),
            Span::raw(" │ "),
            Span::styled(format!("{glyph} {right}"), style),
        ]));
    }
    let visible = usize::from(frame.area().height.saturating_sub(2));
    let scroll_y = (app.diff_scroll as u16).min(lines.len().saturating_sub(visible) as u16);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll_y, 0))
            .block(modal_block(format!(
                "CONFIG DIFF [line {}/{}] · ENTER APPLY / ESC KEEP",
                scroll_y + 1,
                diff.rows.len()
            )))
            .wrap(Wrap { trim: false }),
        frame.area(),
    );
}

fn log_line_style(line: &str) -> Style {
    let lower = line.to_ascii_lowercase();
    if lower.contains("err") || lower.contains("fail") || lower.contains("panic") {
        Style::default().fg(Color::Red)
    } else if lower.contains("warn") {
        Style::default().fg(Color::Yellow)
    } else if lower.contains("handshake")
        || lower.contains("started")
        || lower.contains("established")
        || lower.contains("listening")
    {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Gray)
    }
}

fn format_log_line(line: &str) -> Line<'_> {
    if let Some(rest) = line.strip_prefix('[') {
        if let Some((ts, after_ts)) = rest.split_once("] ") {
            if let Some(level_rest) = after_ts.strip_prefix('[') {
                if let Some((level, msg)) = level_rest.split_once("] ") {
                    let level_style = match level {
                        "WARN" | "WARNING" => Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                        "ERR" | "ERROR" => {
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                        }
                        _ => Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    };
                    return Line::from(vec![
                        Span::styled(format!("[{ts}] "), Style::default().fg(Color::DarkGray)),
                        Span::styled(format!("[{level}] "), level_style),
                        Span::styled(msg, log_line_style(line)),
                    ]);
                }
            }
        }
    }
    Line::from(Span::styled(line, log_line_style(line)))
}

fn draw_logs(frame: &mut Frame<'_>, app: &App) {
    let lines: Vec<Line<'_>> = if app.logs.is_empty() {
        vec![Line::from(
            "No log lines loaded. Press l to fetch journald.",
        )]
    } else {
        app.logs
            .iter()
            .map(|line| format_log_line(line.as_str()))
            .collect()
    };
    let visible = usize::from(frame.area().height.saturating_sub(2));
    let scroll_y = (app.logs_scroll as u16).min(app.logs.len().saturating_sub(visible) as u16);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll_y, 0))
            .block(modal_block(if app.logs_follow {
                format!(
                    "Logs [line {}/{}] (follow, f off, r refresh, Esc)",
                    scroll_y + 1,
                    app.logs.len()
                )
            } else {
                format!(
                    "Logs [line {}/{}] (f follow, r refresh, Esc)",
                    scroll_y + 1,
                    app.logs.len()
                )
            })),
        frame.area(),
    );
}

fn draw_qr(frame: &mut Frame<'_>, area: Rect, qr: &super::qr::QrState) {
    let popup = centered(area, 92, 92);
    frame.render_widget(Clear, popup);
    let is_invite = qr.kind == super::qr::QrKind::Invite;
    let block = modal_block(if is_invite {
        "ONE-TIME ENROLMENT INVITE  ·  optical provisioning"
    } else {
        "CLIENT BUNDLE QR  ·  optical provisioning"
    });
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rendered = match super::qr::render(qr.current()) {
        Ok(lines) => lines,
        Err(error) => {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    error,
                    Style::default().fg(Color::Red),
                ))),
                inner,
            );
            return;
        }
    };

    let qr_rows = rendered.len() as u16;
    let qr_cols = rendered
        .first()
        .map_or(0, |line| line.chars().count() as u16);

    if inner.height < qr_rows || inner.width < qr_cols + 2 {
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "Terminal window is too small to render QR code cleanly.",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "Current size: {}x{} — resize to at least {}x{} for reliable camera scan.",
                area.width,
                area.height,
                qr_cols + 8,
                qr_rows + 4
            )),
            Line::from(""),
            Line::from(format!("Bundle file was saved to: {}", qr.path)),
            Line::from("You can import it directly on the client using:"),
            Line::from(Span::styled(
                format!("  vallum import-bundle {}", qr.path),
                Style::default().fg(Color::Cyan),
            )),
            Line::from(""),
            Line::from("n/p frame  Esc close"),
        ];
        frame.render_widget(Paragraph::new(lines), inner);
        return;
    }

    let qr_style = Style::default().fg(Color::White).bg(Color::Black);
    let total_frames = qr.frames.len().max(1);
    let current_frame = qr.index + 1;
    let bar_width = 16usize;
    let filled = (current_frame * bar_width) / total_frames;
    let progress_bar = format!(
        "[{}{}]",
        "█".repeat(filled),
        "░".repeat(bar_width.saturating_sub(filled))
    );

    if inner.width >= qr_cols + 36 {
        let cols =
            Layout::horizontal([Constraint::Length(qr_cols + 4), Constraint::Min(32)]).split(inner);

        let pad_top = cols[0].height.saturating_sub(qr_rows) / 2;
        let pad_left = cols[0].width.saturating_sub(qr_cols) / 2;
        let qr_rect = Rect::new(cols[0].x + pad_left, cols[0].y + pad_top, qr_cols, qr_rows);
        let qr_lines: Vec<Line<'_>> = rendered
            .into_iter()
            .map(|row| Line::from(Span::styled(row, qr_style)))
            .collect();
        frame.render_widget(Paragraph::new(qr_lines), qr_rect);

        let info_lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                if is_invite {
                    " ● ONE-TIME ENROLMENT INVITE "
                } else {
                    " ● OPTICAL CLIENT PROVISIONING "
                },
                theme().pill_accent(),
            )),
            Line::from(""),
            if is_invite {
                Line::from(vec![
                    Span::styled(" ✔ ZERO PRIVATE KEYS ", theme().pill_ok()),
                    Span::styled(" token + server fingerprint only", theme().ok()),
                ])
            } else {
                Line::from(vec![
                    Span::styled(" ⚠ SECRET MATERIAL ", theme().pill_warn()),
                    Span::styled(" contains peer private key", theme().warn()),
                ])
            },
            Line::from(""),
            Line::from(Span::styled(
                "── Frame Telemetry ─────────────────────",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(vec![
                Span::styled("frame       ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{current_frame}/{total_frames} "),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(progress_bar, Style::default().fg(Color::Cyan)),
            ]),
            detail_kv("hash", qr.hash.clone(), Style::default().fg(Color::Cyan)),
            detail_kv(
                "encoding",
                "VALLUM1 · ISO/IEC 18004 (EC-L, 2px quiet zone)",
                Style::default().fg(Color::Gray),
            ),
            Line::from(""),
            Line::from(Span::styled(
                "── Offline File Fallback ───────────────",
                Style::default().fg(Color::DarkGray),
            )),
            detail_kv("saved", qr.path.clone(), Style::default().fg(Color::White)),
            Line::from(vec![
                Span::styled("import      ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("vallum import-bundle {}", qr.path),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "── Controls ────────────────────────────",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(vec![
                Span::styled(
                    "n / →",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" next frame   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "p / ←",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" prev frame", Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled(
                    "Esc / q",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " close modal & clear secret from display",
                    Style::default().fg(Color::Gray),
                ),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(info_lines).wrap(Wrap { trim: false }),
            cols[1],
        );
    } else {
        let mut lines = vec![Line::from(Span::styled(
            format!(
                "Bundle QR  frame {current_frame}/{total_frames}  hash {}  (secret: contains the private key)",
                qr.hash
            ),
            Style::default().fg(Color::Yellow),
        ))];
        for row in rendered {
            lines.push(Line::from(Span::styled(row, qr_style)));
        }
        lines.push(Line::from(format!("saved: {}", qr.path)));
        lines.push(Line::from("n/p frame  Esc close"));
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

fn field_help_hint(label: &str) -> &'static str {
    match label {
        "name" => "Friendly alias for this peer (e.g. laptop, phone, staging-us)",
        "public line" => "Base64 public identity string from 'g' (keygen) or peer export",
        "endpoint" => "Public IP or hostname and UDP listen port (e.g. 198.51.100.1:51820)",
        "allowed IPs" => {
            "Comma-separated subnets routed to peer (e.g. 10.7.0.2/32, 192.168.1.0/24)"
        }
        "keepalive" => "NAT keepalive interval in seconds (recommended 25 behind NAT; 0 = off)",
        "PSK (hex, optional)" => "Optional 32-byte (64 hex) preshared key for defense-in-depth",
        "listen port" => "UDP port daemon listens on for handshakes (1–65535; 0 = random)",
        "fwmark" => "Firewall mark for policy routing loop prevention (0 = off)",
        "addresses" => "IP addresses assigned to interface with CIDR (e.g. 10.7.0.1/24)",
        "MTU" => "Interface Maximum Transmission Unit (e.g. 1420; 0 = default)",
        "DNS" => "Comma-separated DNS server addresses pushed to client (e.g. 1.1.1.1)",
        "table" => "Routing table for interface routes ('auto', 'off', or table number)",
        "client endpoint" => "Public IP:port where remote peers can connect to this daemon",
        "bundle file" => "Path to .vallum-bundle file to import into daemon configuration",
        "force overwrite" => "Overwrite existing interface configuration ('true' or 'false')",
        _ => "Fill in value and press Enter to submit",
    }
}

/// Render a field value on one line. Long values (a public line is hundreds of
/// characters) get an elided window so the rest of the form stays visible; the
/// focused field shows a window that keeps the cursor in view.
pub(crate) fn field_value_display(
    value: &str,
    cursor: usize,
    width: usize,
    focused: bool,
) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= width {
        if focused {
            let mut display = chars.clone();
            display.insert(cursor.min(chars.len()), '|');
            return display.iter().collect();
        }
        return value.to_owned();
    }
    if !focused {
        let head: String = chars.iter().take(width.saturating_sub(1)).collect();
        return format!("{head}…");
    }
    let cursor = cursor.min(chars.len());
    let mut start = cursor.saturating_sub(width.saturating_sub(2));
    if start + width > chars.len() {
        start = chars.len().saturating_sub(width);
    }
    let mut window: Vec<char> = chars[start..(start + width).min(chars.len())].to_vec();
    window.insert(cursor.saturating_sub(start).min(window.len()), '|');
    let mut display = String::new();
    if start > 0 {
        display.push('…');
    }
    display.extend(window);
    if start + width < chars.len() {
        display.push('…');
    }
    display
}

fn draw_form(frame: &mut Frame<'_>, area: Rect, form: &Form) {
    let popup = centered(area, 80, 60);
    frame.render_widget(Clear, popup);
    // Borders + marker + label column; a field value never wraps to a second
    // line so every field stays on screen regardless of its length.
    let value_width = (popup.width as usize).saturating_sub(26).max(8);
    let mut lines = Vec::new();
    for (index, field) in form.fields.iter().enumerate() {
        let focused = index == form.focus;
        let invalid = form
            .error
            .as_ref()
            .is_some_and(|error| error.field == Some(field.label));
        let marker = if focused { ">" } else { " " };
        let is_empty = field.value.is_empty();
        let value = if field.masked && !is_empty {
            "************".to_owned()
        } else {
            field.value.clone()
        };
        let style = if invalid {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else if focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        let mut spans = vec![Span::styled(
            format!("{marker} {:<22} ", field.label),
            style,
        )];

        if focused {
            if is_empty && !field.placeholder.is_empty() {
                spans.push(Span::styled("|", Style::default().fg(Color::Cyan)));
                spans.push(Span::styled(
                    field.placeholder,
                    Style::default().fg(Color::DarkGray),
                ));
            } else if field.masked {
                spans.push(Span::styled(format!("{value}|"), style));
            } else {
                spans.push(Span::styled(
                    field_value_display(&field.value, form.cursor, value_width, true),
                    style,
                ));
            }
        } else if is_empty && !field.placeholder.is_empty() {
            spans.push(Span::styled(
                field.placeholder,
                Style::default().fg(Color::DarkGray),
            ));
        } else {
            spans.push(Span::styled(
                field_value_display(&value, 0, value_width, false),
                style,
            ));
        }

        lines.push(Line::from(spans));
    }
    let focused_label = form.fields.get(form.focus).map(|f| f.label).unwrap_or("");
    let hint = field_help_hint(focused_label);
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("ℹ ", Style::default().fg(Color::Cyan)),
        Span::styled(hint, Style::default().fg(Color::DarkGray)),
    ]));
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("! {}", error.message),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Tab", Style::default().fg(Color::Cyan)),
        Span::styled(" next  ", Style::default().fg(Color::DarkGray)),
        Span::styled("←/→", Style::default().fg(Color::Cyan)),
        Span::styled(" move  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Home/End", Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::styled("Ctrl-U", Style::default().fg(Color::Cyan)),
        Span::styled(" clear  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::Cyan)),
        Span::styled(" submit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Cyan)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));
    frame.render_widget(
        Paragraph::new(lines)
            .block(modal_block(format!("FORM · {}", form.title)))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_confirm(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let popup = centered(area, 64, 25);
    frame.render_widget(Clear, popup);
    let mut lines = Vec::new();
    if let Some(confirm) = &app.confirm {
        match &confirm.action {
            super::app::ConfirmAction::RemovePeer { label, .. } => {
                lines.push(Line::from(Span::styled(
                    format!("Remove {label}?"),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "This will disconnect the peer and revoke access.",
                ));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled(
                        "Enter",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" confirms  ·  "),
                    Span::styled(
                        "Esc",
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" cancels"),
                ]));
            }
            super::app::ConfirmAction::FinalizePeer { name } => {
                lines.push(Line::from(Span::styled(
                    format!("Finalize key rotation for '{name}'?"),
                    theme().warn_bold(),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "The previous identity will be retired immediately.",
                ));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("Enter", theme().accent()),
                    Span::raw(" retires old key  ·  "),
                    Span::styled("Esc", theme().muted()),
                    Span::raw(" keeps rotation open"),
                ]));
            }
            super::app::ConfirmAction::ApplyConfig => {
                lines.push(Line::from(Span::styled(
                    "Config parsed successfully.",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from("Apply new configuration now?"));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled(
                        "Enter",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" restarts service  ·  "),
                    Span::styled(
                        "Esc",
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" keeps file unapplied"),
                ]));
            }
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(modal_block("CONFIRM ACTION"))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// The command palette popup rect; also used by the mouse hit test.
pub(crate) fn palette_rect(area: Rect) -> Rect {
    centered(area, 68, 60)
}

fn palette_command_context(app: &App, action: super::keymap::Action) -> (Option<String>, bool) {
    use super::keymap::Action;
    let peer_name = app.current_peer().map(|peer| {
        if !peer.name.is_empty() {
            peer.name.clone()
        } else {
            peer.fingerprint.clone()
        }
    });
    let has_device = app.current_device().is_some();
    let has_iface = app.current().is_some();
    match action {
        Action::EditPeer
        | Action::RotatePeer
        | Action::FinalizePeer
        | Action::RemovePeer
        | Action::ExportBundle
        | Action::Ping => {
            if let Some(name) = peer_name {
                (Some(format!("({name})")), true)
            } else {
                (Some("(no peer selected)".to_owned()), false)
            }
        }
        Action::YankPublicLine | Action::YankAddress => {
            if let Some(name) = peer_name {
                (Some(format!("({name})")), true)
            } else if has_device {
                (Some("(device)".to_owned()), true)
            } else {
                (Some("(no target)".to_owned()), false)
            }
        }
        Action::RuntimeForm => (None, has_device),
        Action::ToggleService
        | Action::InterfaceForm
        | Action::EditConfig
        | Action::SaveRuntime => (None, has_iface),
        _ => (None, true),
    }
}

fn draw_palette(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let Some(palette) = &app.palette else {
        return;
    };
    let popup = palette_rect(area);
    frame.render_widget(Clear, popup);
    let block = modal_block("COMMAND PALETTE  ·  type to filter · enter/click runs · esc closes");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let commands = super::keymap::matching_commands(&palette.input);
    let count_label = format!("{}/{} ", commands.len(), super::keymap::COMMANDS.len());
    let input = Line::from(vec![
        Span::styled(
            " : ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            &palette.input,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("▌", Style::default().fg(Color::Cyan)),
        Span::styled(
            format!(
                "{:>width$}",
                count_label,
                width = (inner.width as usize).saturating_sub(palette.input.chars().count() + 5)
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(input),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    let max_rows = popup.height.saturating_sub(4) as usize;
    let offset = super::keymap::window_start(commands.len(), palette.selected, max_rows);
    if commands.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  no matching commands",
                Style::default().fg(Color::DarkGray),
            ))),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
    for (visible, command) in commands.iter().skip(offset).take(max_rows).enumerate() {
        let index = offset + visible;
        let selected = index == palette.selected;
        let keys = app.keymap.keys_for(command.action).join(" ");
        let (ctx_suffix, available) = palette_command_context(app, command.action);
        let full_name = if let Some(suffix) = ctx_suffix {
            format!("{} {}", command.name, suffix)
        } else {
            command.name.to_owned()
        };
        let base_style = if selected {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if !available {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };
        let cat_style = if selected {
            base_style
        } else {
            Style::default().fg(Color::Cyan)
        };
        let prefix = format!(
            "{} {:<7} ",
            if selected { "▸" } else { " " },
            command.category
        );
        let prefix_len = prefix.chars().count() as u16;
        let keys_len = keys.chars().count() as u16;
        let name_width = inner.width.saturating_sub(prefix_len + keys_len + 2);
        let name: String = full_name.chars().take(name_width as usize).collect();
        let pad = inner
            .width
            .saturating_sub(prefix_len + name.chars().count() as u16 + keys_len + 1);
        let row = Line::from(vec![
            Span::styled(prefix, cat_style),
            Span::styled(name, base_style),
            Span::styled(" ".repeat(pad as usize), base_style),
            Span::styled(
                format!("{keys} "),
                base_style.fg(if selected {
                    Color::Black
                } else {
                    Color::DarkGray
                }),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(row),
            Rect::new(inner.x, inner.y + 1 + visible as u16, inner.width, 1),
        );
    }
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

pub(crate) fn rate_label(rate: f64) -> String {
    if rate < 1024.0 {
        format!("{:.1} B/s", rate)
    } else if rate < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", rate / 1024.0)
    } else if rate < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB/s", rate / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB/s", rate / (1024.0 * 1024.0 * 1024.0))
    }
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}
