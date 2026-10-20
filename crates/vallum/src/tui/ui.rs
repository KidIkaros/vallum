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
            Paragraph::new(text).block(brand_block("TUNNEL CONTROL")),
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

    let status_badge = match (
        interface.service_state,
        interface.device.is_some(),
        interface.error.is_none(),
    ) {
        (Some(ServiceState::Active), _, _) | (None, true, true) => Span::styled(
            " ● ACTIVE ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        (Some(ServiceState::Activating), _, _) => Span::styled(
            " ◐ STARTING ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        (Some(ServiceState::Deactivating), _, _) => Span::styled(
            " ◑ STOPPING ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        (Some(ServiceState::Failed), _, _) => Span::styled(
            " ✖ FAILED ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        _ => Span::styled(
            " ○ INACTIVE ",
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

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    "RX ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(rate_label(interface.rx_rate)),
            ])),
            rows[0],
        );
        frame.render_widget(
            Sparkline::default()
                .data(&interface.rx_history)
                .style(Style::default().fg(Color::Cyan)),
            rows[1],
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    "TX ",
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(rate_label(interface.tx_rate)),
            ])),
            rows[2],
        );
        frame.render_widget(
            Sparkline::default()
                .data(&interface.tx_history)
                .style(Style::default().fg(Color::Magenta)),
            rows[3],
        );
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
    if area.height >= 16 {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            "   ██╗   ██╗ █████╗ ██╗     ██╗     ██╗   ██╗███╗   ███╗",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        text.push(Line::from(vec![
            Span::styled(
                "   ██║   ██║██╔══██╗██║     ██║     ██║   ██║████╗ ████║",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "   POST-QUANTUM WIRE ENCLAVE",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        text.push(Line::from(vec![
            Span::styled(
                "   ╚██╗ ██╔╝███████║██║     ██║     ██║   ██║██╔████╔██║",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "   Kyber-768 / Tri-Hybrid · Layer-3 VPN",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        text.push(Line::from(vec![
            Span::styled(
                "    ╚████╔╝ ██║  ██║███████╗███████╗╚██████╔╝██║ ╚═╝ ██║",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "   Ikaros Digital × Atomguard",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        text.push(Line::from(Span::styled(
            "     ╚═══╝  ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        text.push(Line::from(""));
    }

    text.push(Line::from(Span::styled(
        "No Vallum interface found",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    text.push(Line::from(""));
    text.push(Line::from(
        "Inspect a running tunnel: vallum tui --control /run/vallum/<name>.sock",
    ));
    text.push(Line::from(
        "Start a tunnel: sudo vallum-quick up /etc/vallum/<name>.toml",
    ));
    text.push(Line::from(
        "Or pass --config /path/to/config.toml or --config-dir DIR.",
    ));
    text.push(Line::from(""));
    text.push(Line::from(Span::styled(
        "Tip: Press i to import a client bundle (.vallum-bundle) directly.",
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
                let handshake = Cell::from(freshness.label()).style(
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
            Constraint::Length(16),
            Constraint::Min(10),
            Constraint::Length(10),
            Constraint::Length(15),
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
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 45, 60))
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("❯ ");
    let selected = if filtered_count > 0 {
        Some(app.peer_selected.min(filtered_count - 1))
    } else {
        None
    };
    let mut state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, area, &mut state);
}

fn draw_details(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if area.height < 11 {
        draw_compact_details(frame, area, app);
        return;
    }
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
        let freshness = App::handshake_freshness(peer);
        lines.push(Line::from(vec![
            Span::styled(
                format!("handshake  {}", freshness.label()),
                Style::default()
                    .fg(freshness_color(freshness))
                    .add_modifier(Modifier::BOLD),
            ),
            if freshness == HandshakeFreshness::Never {
                Span::raw("")
            } else {
                Span::raw(format!(" · {}", App::handshake_age(peer)))
            },
        ]));
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
    } else if !app.peer_filter.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("No peers match filter \"{}\"", app.peer_filter),
            Style::default().fg(Color::Yellow),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from("Press Esc or Ctrl-U to clear filter."));
    } else {
        lines.push(Line::from("No peer selected."));
    }
    if let Some(interface) = app.current() {
        if let Some(device) = &interface.device {
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "rates      rx {} / tx {}",
                rate_label(interface.rx_rate),
                rate_label(interface.tx_rate)
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
    if app.filtering {
        let filter_line = Line::from(vec![
            Span::styled(
                "FILTER: ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                &app.peer_filter,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("█", Style::default().fg(Color::Cyan)),
            Span::raw("  "),
            Span::styled(
                "(Enter: apply, Esc: cancel, Ctrl-U: clear)",
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        frame.render_widget(Paragraph::new(vec![filter_line, Line::from("")]), area);
        return;
    }

    let mut nav_spans = Vec::new();
    nav_spans.extend(key_capsule("Tab", "iface"));
    nav_spans.extend(key_capsule("↑/↓", "peer"));
    if area.width >= 100 {
        nav_spans.extend(key_capsule("Home/End", ""));
    }
    nav_spans.extend(key_capsule("/", "filter"));
    nav_spans.extend(key_capsule("o", "sort"));
    nav_spans.extend(key_capsule("?", "help"));
    nav_spans.extend(key_capsule("q", "quit"));

    let second_line = if let Some(toast) = &app.toast {
        Line::from(Span::styled(
            &toast.message,
            Style::default().fg(Color::Yellow),
        ))
    } else {
        let mut act_spans = Vec::new();
        act_spans.extend(key_capsule("Space", "toggle"));
        act_spans.extend(key_capsule("a", "add"));
        act_spans.extend(key_capsule("e", "edit"));
        if area.width < 100 {
            act_spans.extend(key_capsule("d", "rm"));
            act_spans.extend(key_capsule("i", "import"));
            act_spans.extend(key_capsule("b", "bundle"));
            act_spans.extend(key_capsule("y", "copy"));
        } else {
            act_spans.extend(key_capsule("d", "remove"));
            act_spans.extend(key_capsule("i", "import"));
            act_spans.extend(key_capsule("b", "bundle"));
            act_spans.extend(key_capsule("y", "copy"));
            act_spans.extend(key_capsule("p", "ping"));
            act_spans.extend(key_capsule("W", "save"));
            act_spans.extend(key_capsule("c", "runtime"));
            act_spans.extend(key_capsule("C", "config"));
            act_spans.extend(key_capsule("E", "edit"));
            act_spans.extend(key_capsule("l", "logs"));
            act_spans.extend(key_capsule("r", "refresh"));
        }
        Line::from(act_spans)
    };

    let hint = vec![Line::from(nav_spans), second_line];
    frame.render_widget(Paragraph::new(hint), area);
}

fn draw_help(frame: &mut Frame<'_>, app: &App) {
    let text = vec![
        Line::from("Space / s         toggle tunnel up / down"),
        Line::from("Tab / Shift-Tab   switch interface (or click tab)"),
        Line::from("j / k, arrows     select peer (or click row / scroll wheel)"),
        Line::from("/                 filter peers by name, IP, endpoint, or fingerprint"),
        Line::from("o                 cycle peer sorting (natural, handshake, transfer, name)"),
        Line::from("Home / End        jump to first / last peer"),
        Line::from("PgUp / PgDn       scroll 5 peers / scroll logs & diff"),
        Line::from("g / G             jump to top / bottom (logs, diff, help)"),
        Line::from("a                 add peer"),
        Line::from("e                 edit name, endpoint, allowed IPs, keepalive, PSK"),
        Line::from("d                 remove peer (with confirmation preview)"),
        Line::from("i                 import client bundle (.vallum-bundle) into daemon"),
        Line::from("g                 generate a key and prefill the add form"),
        Line::from("b                 export client bundle and show animated QR"),
        Line::from("y                 copy peer public line to clipboard"),
        Line::from("Y                 copy peer address / endpoint to clipboard"),
        Line::from("p                 ping selected peer's tunnel IP"),
        Line::from("W                 write/save runtime configuration to disk"),
        Line::from("c                 edit runtime listen port and fwmark (temporary)"),
        Line::from("C                 edit listen/MTU/fwmark/addresses/DNS/table (on disk)"),
        Line::from("E                 edit TOML in $EDITOR (with diff review)"),
        Line::from("l                 show journald logs (scroll with j/k/PgUp/PgDn)"),
        Line::from("r                 refresh device snapshot"),
        Line::from("?                 close help"),
        Line::from("q / Q / Ctrl-C    quit / close view"),
        Line::from(""),
        Line::from("CONTROL reports UAPI reachability; systemd unit state is separate."),
        Line::from("Handshake tags: RECENT <5m, AGING <1h, OLD >1h, or NEVER."),
        Line::from("Forms: Tab moves fields, arrows edit text, Ctrl-U clears."),
        Line::from("Secrets are masked; private keys and PSK are never rendered."),
        Line::from("Developed in partnership by Ikaros Digital × Atomguard."),
    ];
    let scroll_y = (app.help_scroll as u16).min(text.len().saturating_sub(1) as u16);
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
    let scroll_y = (app.diff_scroll as u16).min(lines.len().saturating_sub(1) as u16);
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

fn draw_logs(frame: &mut Frame<'_>, app: &App) {
    let lines: Vec<Line<'_>> = if app.logs.is_empty() {
        vec![Line::from(
            "No log lines loaded. Press l to fetch journald.",
        )]
    } else {
        app.logs
            .iter()
            .map(|line| Line::from(Span::styled(line.as_str(), log_line_style(line))))
            .collect()
    };
    let scroll_y = (app.logs_scroll as u16).min(app.logs.len().saturating_sub(1) as u16);
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
    if area.width < 75 || area.height < 30 {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Terminal window is too small to render QR code cleanly.",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!(
            "Current size: {}x{} — resize to at least 80x32 for reliable camera scan.",
            area.width, area.height
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Bundle file was saved to: {}", qr.path)));
        lines.push(Line::from(
            "You can import it directly on the client using:",
        ));
        lines.push(Line::from(Span::styled(
            format!("  vallum import-bundle {}", qr.path),
            Style::default().fg(Color::Cyan),
        )));
    } else {
        match super::qr::render(qr.current()) {
            Ok(rendered) => lines.extend(rendered.into_iter().map(Line::from)),
            Err(error) => lines.push(Line::from(error)),
        }
    }
    lines.push(Line::from(format!("saved: {}", qr.path)));
    lines.push(Line::from("n/p frame  Esc close"));
    frame.render_widget(
        Paragraph::new(lines).block(modal_block("CLIENT BUNDLE QR")),
        popup,
    );
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
            } else {
                let mut display_val = value;
                if field.masked {
                    display_val.push('|');
                } else {
                    let byte_index = display_val
                        .char_indices()
                        .nth(form.cursor)
                        .map_or(display_val.len(), |(index, _)| index);
                    display_val.insert(byte_index, '|');
                }
                spans.push(Span::styled(display_val, style));
            }
        } else if is_empty && !field.placeholder.is_empty() {
            spans.push(Span::styled(
                field.placeholder,
                Style::default().fg(Color::DarkGray),
            ));
        } else {
            spans.push(Span::styled(value, style));
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
