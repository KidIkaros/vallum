// SPDX-License-Identifier: Apache-2.0

//! Pure rendering: the frame is a function of `App`.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState, Wrap,
};
use ratatui::Frame;

use super::app::{App, Form, HandshakeFreshness, Interface, ServiceState, View};
use super::theme::{abbreviate_public_line, theme, transfer_share_bar, Theme};

pub fn draw(frame: &mut Frame<'_>, app: &App) {
    match app.view {
        View::Help => draw_help(frame, app),
        View::Logs => draw_logs(frame, app),
        View::Trial => draw_trial(frame, app),
        View::Health => draw_health(frame, app),
        View::Diff => draw_diff(frame, app),
        View::Dashboard => draw_dashboard(frame, app),
    }
}

fn draw_dashboard(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let compact = area.width < 130;
    let header_height = if app.interfaces.is_empty() { 3 } else { 6 };
    // The footer grows by one row per shown suggestion (at most two) so the
    // strip sits against the key hints it points at.
    let suggestion_rows = u16::try_from(app.suggestions.len().min(2)).unwrap_or(0);
    let chunks = Layout::vertical([
        Constraint::Length(header_height),
        Constraint::Min(6),
        Constraint::Length(2 + suggestion_rows),
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
    } else if sparse_peer_list(app) {
        // A handful of peers in a 62%-wide column leaves most of the body as an
        // empty box. Give the list the width it wants and stack the details under
        // it instead of ringing an empty band with a border.
        let peer_rows = peer_count(app);
        let peers_height = (u16::try_from(peer_rows).unwrap_or(u16::MAX) + 3)
            .min(chunks[1].height.saturating_sub(8));
        let body = Layout::vertical([Constraint::Length(peers_height), Constraint::Min(8)])
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

fn peer_count(app: &App) -> usize {
    app.current_device().map_or(0, |device| device.peers.len())
}

/// True when the peer list is short enough that a side-by-side split wastes the
/// column: below this, the list and the details read better stacked.
fn sparse_peer_list(app: &App) -> bool {
    peer_count(app) <= 4
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App, compact: bool) {
    let t = theme();
    let Some(interface) = app.current() else {
        frame.render_widget(
            Paragraph::new(vec![Line::from(Span::styled(
                "No interface connected",
                t.warn(),
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
        Some(ServiceState::Active) => Span::styled(" ● ACTIVE ", t.pill_ok()),
        Some(ServiceState::Inactive) => Span::styled(" ○ INACTIVE ", t.pill_muted()),
        Some(ServiceState::Activating) => Span::styled(" ◐ STARTING ", t.pill_warn()),
        Some(ServiceState::Deactivating) => Span::styled(" ◑ STOPPING ", t.pill_warn()),
        Some(ServiceState::Failed) => Span::styled(" ✖ FAILED ", t.pill_danger()),
        None => Span::styled(" ◌ NO UNIT ", t.pill_muted()),
    };

    let mut lines = Vec::new();
    // Two control paths can serve the same interface name — an explicit
    // --control plus the runtime dir's own socket, two configs for one name —
    // and the poll renames every tab to what its daemon reports. Identical
    // tabs with no way to tell them apart, so colliding names carry the
    // directory that owns their socket (the full path when even those match).
    let origins: Vec<String> = app
        .interfaces
        .iter()
        .map(|item| {
            item.control_path
                .parent()
                .and_then(|parent| parent.file_name())
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    let origin_unique = {
        let mut seen = std::collections::HashSet::new();
        origins.iter().all(|origin| seen.insert(origin))
    };
    let mut name_counts = std::collections::HashMap::new();
    for item in &app.interfaces {
        *name_counts.entry(item.name.as_str()).or_insert(0usize) += 1;
    }
    let disambiguated = name_counts.values().any(|count| *count > 1);
    let tabs: Vec<Vec<Span<'_>>> = app
        .interfaces
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let style = if index == app.selected {
                t.pill_accent()
            } else {
                t.subtext()
            };
            let mut spans = vec![Span::styled(
                format!(" [{}/{}] {} ", index + 1, app.interfaces.len(), item.name),
                style,
            )];
            if name_counts
                .get(item.name.as_str())
                .is_some_and(|count| *count > 1)
            {
                let origin = origins.get(index).cloned().unwrap_or_default();
                let origin = if origin_unique && !origin.is_empty() {
                    origin
                } else {
                    item.control_path.display().to_string()
                };
                spans.push(Span::styled(format!("· {origin} "), t.muted()));
            }
            spans
        })
        .collect();

    // Expected egress mode, straight from the config's own allowlist: a peer
    // with 0.0.0.0/0 means the operator armed a full tunnel, anything else is
    // split by design. Naming the mode keeps "outside the tunnel" from
    // reading as failure when split is the configuration.
    let egress = interface.device.as_ref().map(|device| {
        // The daemon's field is the one source; both ends now ship it.
        if device.egress == "full" {
            Span::styled(" ◆ EGRESS FULL ", t.pill_accent())
        } else {
            Span::styled(" ◇ EGRESS SPLIT ", t.muted())
        }
    });

    let mut first_row = vec![status_badge, Span::raw(" ")];
    for tab in tabs {
        first_row.extend(tab);
    }
    if let Some(egress) = egress {
        first_row.push(egress);
        first_row.push(Span::raw(" "));
    }
    // The guard only matters for a full tunnel: on split it is not needed, so
    // its state is not shown (a pill for a component nobody needs is noise).
    if interface
        .device
        .as_ref()
        .is_some_and(|d| d.egress == "full")
    {
        match interface.guard_state {
            Some(ServiceState::Active) => first_row.push(Span::styled(" ◆ GUARD ON ", t.pill_ok())),
            Some(_) => first_row.push(Span::styled(" ◇ GUARD OFF ", t.pill_warn())),
            None => {}
        }
        first_row.push(Span::raw(" "));
    }
    // The toggle hint also lives in the footer; when tabs carry origins the
    // row is already at its width budget, so the duplicate hint gives way
    // instead of wrapping the header into the traffic panel.
    if !disambiguated {
        first_row.push(Span::raw(" "));
        first_row.push(Span::styled("[Space: toggle]", t.muted()));
    }
    lines.push(Line::from(first_row));
    lines.push(control_health_line(interface));
    match &interface.device {
        Some(device) => {
            let suite_display = suite_label(&device.suite);
            if compact {
                lines.push(Line::from(vec![
                    Span::styled("listen ", t.muted()),
                    Span::styled(device.listen.clone(), t.text()),
                    Span::styled("  suite ", t.muted()),
                    Span::styled(suite_display, t.signal()),
                    Span::styled("  fwmark ", t.muted()),
                    Span::styled(device.fwmark.to_string(), t.subtext()),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("id ", t.muted()),
                    Span::styled(device.fingerprint.clone(), t.subtext()),
                    Span::styled("  addresses ", t.muted()),
                    Span::styled(device.addresses.join(", "), t.text()),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("listen ", t.muted()),
                    Span::styled(device.listen.clone(), t.text()),
                    Span::styled("  suite ", t.muted()),
                    Span::styled(suite_display, t.signal()),
                    Span::styled("  fwmark ", t.muted()),
                    Span::styled(device.fwmark.to_string(), t.subtext()),
                    Span::styled("  id ", t.muted()),
                    Span::styled(device.fingerprint.clone(), t.subtext()),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("addresses ", t.muted()),
                    Span::styled(device.addresses.join(", "), t.text()),
                ]));
            }
        }
        None => lines.push(Line::from(Span::styled(
            interface
                .error
                .clone()
                .unwrap_or_else(|| "no data".to_owned()),
            t.danger(),
        ))),
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(brand_block("TUNNEL CONTROL")),
        main_area,
    );

    if let Some(t_area) = traffic_area {
        // The scale ceiling goes in the title: RX and TX share one scale, so a
        // per-series "peak" printed beside each line was two numbers for one
        // fact, and it overflowed the 32-column panel.
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
        let block = section_block(format!("TRAFFIC · scale {}", bytes(scale_max)));
        let inner = block.inner(t_area);
        frame.render_widget(block, t_area);

        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

        let baseline = "▁".repeat(inner.width as usize);

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("▼ RX ", t.accent()),
                Span::styled(format!("{:<9}", rate_label(interface.rx_rate)), t.text()),
                Span::styled(format!("{} total", bytes(total_rx)), t.muted()),
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
                Span::styled(format!("{:<9}", rate_label(interface.tx_rate)), t.text()),
                Span::styled(format!("{} total", bytes(total_tx)), t.muted()),
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
    let t = theme();
    Line::from(vec![
        Span::styled("◆ ", t.signal()),
        Span::styled("Vallum".to_owned(), t.accent()),
        Span::styled(" ❯ ", t.muted()),
        Span::styled(section.into(), t.subtext()),
    ])
}

fn brand_block(title: impl Into<String>) -> Block<'static> {
    let t = theme();
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(t.muted())
        .title(brand_title(title))
}

/// A section header without the brand mark. The brand belongs once per screen,
/// on the panel that carries the product's own name; repeating "◆ Vallum ❯" on
/// every box made four headers of equal weight and spent the width the peer
/// table needed.
fn section_block(title: impl Into<String>) -> Block<'static> {
    let t = theme();
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(t.muted())
        .title(Line::from(Span::styled(title.into(), t.subtext())))
}

fn modal_block(title: impl Into<String>) -> Block<'static> {
    let t = theme();
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(t.signal())
        .title(brand_title(title))
}

fn control_health_line(interface: &Interface) -> Line<'static> {
    let t = theme();
    let (label, style) = match (&interface.device, &interface.error) {
        (Some(_), None) => ("CONTROL LIVE", t.ok_bold()),
        (Some(_), Some(_)) => ("CONTROL STALE", t.warn_bold()),
        (None, Some(_)) => ("CONTROL UNAVAILABLE", t.danger_bold()),
        (None, None) => ("CONTROL CONNECTING", t.muted().add_modifier(Modifier::BOLD)),
    };
    let mut spans = vec![Span::styled(label, style)];
    if let Some(age) = interface.last_successful_poll_age() {
        spans.push(Span::raw(" · last reply "));
        spans.push(Span::raw(duration_label(age)));
    }
    if let Some(state) = interface.service_state {
        spans.push(Span::raw(" · systemd "));
        spans.push(Span::styled(state.label(), service_state_style(t, state)));
    }
    Line::from(spans)
}

fn service_state_style(t: Theme, state: ServiceState) -> Style {
    match state {
        ServiceState::Active => t.ok(),
        ServiceState::Inactive => t.muted(),
        ServiceState::Failed => t.danger(),
        ServiceState::Activating | ServiceState::Deactivating => t.warn(),
    }
}

fn freshness_style(t: Theme, freshness: HandshakeFreshness) -> Style {
    match freshness {
        HandshakeFreshness::Never => t.danger(),
        HandshakeFreshness::Recent => t.ok(),
        HandshakeFreshness::Aging => t.warn(),
        HandshakeFreshness::Old => t.muted(),
    }
}

fn handshake_summary(peer: &super::app::PeerView, now: u64) -> String {
    let freshness = App::handshake_freshness_at(peer, now);
    if freshness == HandshakeFreshness::Never {
        freshness.label().to_owned()
    } else {
        format!(
            "{} · {}",
            freshness.label(),
            App::handshake_age_at(peer, now)
        )
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
    let t = theme();
    let mut text = Vec::new();
    if area.height >= 10 {
        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled(" ◆ VALLUM ", t.pill_accent()),
            Span::styled("  ──●──◆──●──  ", t.accent()),
            Span::styled("EVERY BOUNDARY UNDER WATCH", t.text_bold()),
        ]));
        text.push(Line::from(vec![
            Span::styled("  suite 0x0003 ", t.muted()),
            Span::styled("X25519 + sntrup761 + ML-KEM-768 (tri-hybrid)", t.signal()),
            Span::styled(" · layer-3 post-quantum tunnel", t.subtext()),
        ]));
        text.push(Line::from(""));
    }

    // The one question that decides everything after it. Two roles, the
    // command each needs for *this* machine, and nothing else — the full
    // command list is behind `vallum --help` and the palette.
    text.push(Line::from(vec![
        Span::styled("◌ ", t.warn()),
        Span::styled("No tunnel on this machine yet.", t.warn_bold()),
        Span::styled("  What is this machine?", t.text()),
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
            "sudo vallum join vallum1-join:…   (or --remote / --client <file>.vallum-bundle)",
        ),
    ] {
        text.push(Line::from(vec![
            Span::styled(key, t.pill_accent()),
            Span::styled(format!("  {role:<12}"), t.text_bold()),
            Span::styled("  ", Style::default()),
            Span::styled(detail, t.subtext()),
        ]));
        // A visible marker, not leading spaces: the paragraph wraps with
        // `trim: true`, which eats indentation and left the command stranded
        // in column zero.
        text.push(Line::from(vec![
            Span::styled("  → ", t.muted()),
            Span::styled(command, t.signal()),
        ]));
        text.push(Line::from(""));
    }
    text.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled("1 or 2 copies the command for this machine", t.muted()),
        Span::styled(" · ", t.muted()),
        Span::styled("i", t.signal()),
        Span::styled(" imports a bundle here ", t.muted()),
        Span::styled("· ", t.muted()),
        Span::styled(":", t.signal()),
        Span::styled(" every action ", t.muted()),
        Span::styled("· ", t.muted()),
        Span::styled("?", t.signal()),
        Span::styled(" help", t.muted()),
    ]));
    if area.height >= 18 {
        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled("Already have a config? ", t.muted()),
            Span::styled("vallum tui --config /path/to/config.toml", t.subtext()),
        ]));
    }
    text.push(Line::from(""));
    text.push(Line::from(Span::styled(
        "  Ikaros Digital × Atomguard · zero-compromise post-quantum systems engineering",
        t.muted(),
    )));

    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .block(brand_block("GET STARTED")),
        area,
    );
}

fn draw_peers(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let t = theme();
    let Some(device) = app.current_device() else {
        let message = app
            .current()
            .and_then(|interface| interface.error.as_deref())
            .unwrap_or("No device data. Press r to retry.");
        frame.render_widget(Paragraph::new(message).block(section_block("PEERS")), area);
        return;
    };

    let is_stale = app
        .current()
        .is_some_and(|interface| interface.error.is_some());
    if device.peers.is_empty() {
        let title = if is_stale {
            "PEERS (stale snapshot)"
        } else {
            "PEERS"
        };
        let empty_text = if is_stale {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "Control socket disconnected — showing retained snapshot",
                    t.warn(),
                )),
                Line::from("Press 'r' to retry connecting."),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled("No peers configured yet", t.accent())),
                Line::from(""),
                Line::from(vec![
                    Span::raw("Press "),
                    Span::styled("a", t.accent()),
                    Span::raw(" to add a peer, or "),
                    Span::styled("g", t.accent()),
                    Span::raw(" to generate keys."),
                ]),
            ]
        };
        frame.render_widget(
            Paragraph::new(empty_text)
                .block(section_block(title))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let filtered = app.filtered_peers();
    let total_count = device.peers.len();
    let filtered_count = filtered.len();

    let expanded = area.width >= 101;
    // A column that reads "—" or "0" on every row is a demand the operator
    // cannot use: show epoch and psk only when some peer actually has one.
    let show_epoch = device.peers.iter().any(|peer| peer.epoch != 0);
    let show_psk = device.peers.iter().any(|peer| peer.preshared_key);
    let mut header_cells = vec!["name", "endpoint", "allowed", "handshake", "rx/tx"];
    if show_epoch {
        header_cells.push("epoch");
    }
    if show_psk {
        header_cells.push("psk");
    }
    let header = if expanded {
        Row::new(header_cells)
    } else {
        Row::new(vec!["peer", "endpoint", "handshake", "rx / tx"])
    }
    .style(t.accent());
    let rows: Vec<Row> = if filtered_count == 0 {
        if expanded {
            let mut cells = vec![
                Cell::from("no match").style(t.warn()),
                Cell::from(format!("filter: \"{}\"", app.peer_filter)).style(t.muted()),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ];
            if show_epoch {
                cells.push(Cell::from(""));
            }
            if show_psk {
                cells.push(Cell::from(""));
            }
            vec![Row::new(cells)]
        } else {
            vec![Row::new(vec![
                Cell::from("no match").style(t.warn()),
                Cell::from(format!("filter: \"{}\"", app.peer_filter)).style(t.muted()),
                Cell::from(""),
                Cell::from(""),
            ])]
        }
    } else {
        filtered
            .iter()
            .map(|(_, peer)| {
                let freshness = App::handshake_freshness_at(peer, app.now);
                let hs_label = if expanded || freshness == HandshakeFreshness::Never {
                    freshness.label().to_owned()
                } else {
                    format!(
                        "{} {}",
                        freshness.label(),
                        App::handshake_age_at(peer, app.now)
                    )
                };
                let handshake = Cell::from(hs_label)
                    .style(freshness_style(t, freshness).add_modifier(Modifier::BOLD));
                if expanded {
                    let mut cells = vec![
                        Cell::from(peer.name.clone()),
                        Cell::from(peer.endpoint.clone()),
                        Cell::from(peer.allowed_ips.join(",")),
                        handshake,
                        Cell::from(format!("{}/{}", bytes(peer.rx_bytes), bytes(peer.tx_bytes))),
                    ];
                    if show_epoch {
                        cells.push(Cell::from(peer.epoch.to_string()));
                    }
                    if show_psk {
                        cells.push(Cell::from(if peer.preshared_key { "yes" } else { "—" }));
                    }
                    Row::new(cells)
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
        // The list owns the terminal's full width: fixed columns pin the
        // numbers, flexible ones absorb the slack so wide screens do not end
        // in a dead band. Minimums match the old fixed widths, so narrow
        // terminals render exactly as before.
        let mut widths = vec![
            Constraint::Min(20),
            Constraint::Min(24),
            Constraint::Length(14),
            Constraint::Length(9),
            Constraint::Length(13),
        ];
        if show_epoch {
            widths.push(Constraint::Length(6));
        }
        if show_psk {
            widths.push(Constraint::Length(4));
        }
        widths
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
        "PEERS (stale snapshot)".to_owned()
    } else if !app.peer_filter.is_empty() || app.filtering {
        format!(
            "PEERS (filter: \"{}\" [{filtered_count}/{total_count}]{sort_suffix})",
            app.peer_filter
        )
    } else if expanded {
        format!("PEERS [{total_count}]{sort_suffix}")
    } else {
        format!("PEERS [{total_count}]{sort_suffix} (select for details)")
    };
    let table = Table::new(rows, widths)
        .header(header)
        .block(section_block(table_title))
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
    let t = theme();
    Line::from(vec![
        Span::styled(format!("{label:<11} "), t.muted()),
        Span::styled(value.into(), value_style),
    ])
}

fn draw_details(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let t = theme();
    if area.height < 11 {
        draw_compact_details(frame, area, app);
        return;
    }
    let mut lines = Vec::new();
    if let Some(peer) = app.current_peer() {
        let freshness = App::handshake_freshness_at(peer, app.now);
        lines.push(Line::from(vec![
            Span::styled("● ", freshness_style(t, freshness)),
            Span::styled(peer.name.clone(), t.accent()),
        ]));
        let fp = if peer.fingerprint.is_empty() {
            "—".to_owned()
        } else {
            peer.fingerprint.clone()
        };
        lines.push(detail_kv("fingerprint", fp, t.subtext()));
        lines.push(detail_kv("endpoint", peer.endpoint.clone(), t.text()));
        lines.push(detail_kv("allowed", peer.allowed_ips.join(", "), t.text()));
        lines.push(detail_kv(
            "keepalive",
            peer.keepalive
                .map_or_else(|| "off".to_owned(), |value| format!("{value}s")),
            t.subtext(),
        ));
        lines.push(Line::from(vec![
            Span::styled("handshake   ", t.muted()),
            Span::styled(
                freshness.label(),
                freshness_style(t, freshness).add_modifier(Modifier::BOLD),
            ),
            if freshness == HandshakeFreshness::Never {
                Span::raw("")
            } else {
                Span::styled(
                    format!(" · {}", App::handshake_age_at(peer, app.now)),
                    t.subtext(),
                )
            },
        ]));
        lines.push(detail_kv(
            "verdict",
            App::peer_verdict_at(peer, app.now),
            freshness_style(t, freshness),
        ));
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
        if peer.window_received + peer.window_sent > 0 {
            lines.push(detail_kv(
                "window",
                format!("rx {} / tx {} pkts", peer.window_received, peer.window_sent),
                t.subtext(),
            ));
        }
        if peer.dropped_after_auth > 0 {
            lines.push(detail_kv(
                "auth drop",
                format!(
                    "{} rejected after auth — peer key changed; re-enrol",
                    peer.dropped_after_auth
                ),
                t.danger_bold(),
            ));
        }
        if peer.dropped_allowed_ips > 0 {
            let source = peer.last_rejected_source.as_deref().unwrap_or("none");
            lines.push(detail_kv(
                "allowlist",
                format!(
                    "{} dropped (last inner source: {source})",
                    peer.dropped_allowed_ips
                ),
                t.warn_bold(),
            ));
        }
        if peer.dropped_no_session + peer.dropped_replay + peer.reinit_offered > 0 {
            lines.push(detail_kv(
                "peer drops",
                format!(
                    "no-session {} · replay {} · reinit {}",
                    peer.dropped_no_session, peer.dropped_replay, peer.reinit_offered
                ),
                t.subtext(),
            ));
        }
        // An expiring credential is the one thing a peer detail can show that
        // the operator must act on, so it is never silent.
        if let Some(valid_until) = peer.valid_until {
            let now = app.now;
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
        lines.push(t.section_rule(inner_w, "public line (y to copy)"));
        let public_line = abbreviate_public_line(
            &peer.public_line,
            usize::from(inner_w.saturating_sub(2)).max(36),
        );
        // A peer with no public line still gets a row: the rule promises
        // one, and a blank line reads as a rendering glitch.
        lines.push(Line::from(if public_line.is_empty() {
            Span::styled("—", t.muted())
        } else {
            Span::styled(public_line, t.subtext())
        }));
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
            lines.push(theme().section_rule(area.width.saturating_sub(2), "interface dataplane"));
            if let Some(stats) = device.stats {
                for (label, ok, failed) in [
                    ("datagrams", stats.datagrams_sent, stats.datagrams_failed),
                    ("packets", stats.packets_delivered, stats.packets_failed),
                    ("handshakes", stats.established, stats.refusals),
                    ("fragments", stats.reassembled, stats.fragments_dropped),
                ] {
                    let (ok_label, fail_label) = match label {
                        "datagrams" => ("sent", "failed"),
                        "packets" => ("delivered", "failed"),
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
                if stats.dropped_malformed
                    + stats.dropped_unknown_index
                    + stats.fragments_rate_limited
                    > 0
                {
                    lines.push(detail_kv(
                        "wire drops",
                        format!(
                            "malformed {} · unknown-idx {} · frag-limit {}",
                            stats.dropped_malformed,
                            stats.dropped_unknown_index,
                            stats.fragments_rate_limited
                        ),
                        t.danger(),
                    ));
                }
                if stats.handshake_dropped_no_mac
                    + stats.handshake_dropped_unidentifiable
                    + stats.handshake_dropped_unknown_peer
                    + stats.handshake_dropped_endpoint_conflict
                    + stats.handshake_dropped_stale
                    > 0
                {
                    lines.push(detail_kv(
                        "hs drops",
                        format!(
                            "no-mac {} · unid {} · unknown {} · conflict {} · stale {}",
                            stats.handshake_dropped_no_mac,
                            stats.handshake_dropped_unidentifiable,
                            stats.handshake_dropped_unknown_peer,
                            stats.handshake_dropped_endpoint_conflict,
                            stats.handshake_dropped_stale
                        ),
                        t.warn(),
                    ));
                }
            }
            lines.push(detail_kv(
                "rates",
                format!(
                    "rx {} / tx {}",
                    rate_label(interface.rx_rate),
                    rate_label(interface.tx_rate)
                ),
                t.subtext(),
            ));
            lines.push(detail_kv(
                "dataplane",
                format!(
                    "offload {} · UDP batching {}",
                    on_off(device.offload),
                    on_off(device.batching)
                ),
                t.subtext(),
            ));
            lines.push(detail_kv("device", device.interface.clone(), t.text()));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(section_block("PEER DETAILS"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_compact_details(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let t = theme();
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
            Line::from(format!("handshake {}", handshake_summary(peer, app.now))),
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
                t.warn(),
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
            .block(section_block("PEER DETAILS"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn key_capsule<'a>(key: &'a str, label: &'a str) -> Vec<Span<'a>> {
    let t = theme();
    if label.is_empty() {
        vec![Span::styled(key, t.accent()), Span::raw("  ")]
    } else {
        vec![
            Span::styled(key, t.accent()),
            Span::raw(" "),
            Span::styled(label, t.muted()),
            Span::raw("  "),
        ]
    }
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let t = theme();
    if app.qr.is_some() || app.form.is_some() || app.confirm.is_some() || app.palette.is_some() {
        return;
    }
    let mut suggestion_lines: Vec<Line<'_>> = app
        .suggestions
        .iter()
        .take(2)
        .map(|suggestion| {
            let (badge, style) = match suggestion.tone {
                crate::guidance::Tone::Act => (" NEXT ", t.pill_accent()),
                crate::guidance::Tone::Warn => (" WARN ", t.pill_warn()),
                crate::guidance::Tone::Info => (" NOTE ", t.pill_muted()),
            };
            let mut spans = vec![
                Span::styled(badge, style),
                Span::raw(" "),
                Span::styled(&suggestion.title, t.text_bold()),
                Span::styled(format!("  ·  {}", suggestion.detail), t.muted()),
            ];
            // The harness' promise: every suggestion names the key or palette
            // verb that resolves it — the footer teaches the map.
            if let Some(action) = &suggestion.action {
                spans.push(Span::styled("   →  ", t.muted()));
                spans.push(Span::styled(suggestion_hint(action), t.signal()));
            }
            Line::from(spans)
        })
        .collect();
    if app.filtering {
        let filter_line = Line::from(vec![
            Span::styled(" FILTER ", t.pill_accent()),
            Span::raw(" "),
            Span::styled(&app.peer_filter, t.text_bold()),
            Span::styled("█", t.signal()),
            Span::raw("  "),
            Span::styled("(Enter: apply · Esc: cancel · Ctrl-U: clear)", t.muted()),
        ]);
        frame.render_widget(Paragraph::new(vec![filter_line, Line::from("")]), area);
        return;
    }

    let mut nav_spans = vec![
        Span::styled(" : commands ", t.pill_accent()),
        Span::raw("  "),
    ];
    // Keys that need an interface are not shown when there is none: a footer
    // of actions that cannot run is a promise the screen does not keep.
    if app.current().is_some() {
        nav_spans.extend(key_capsule("Tab", "iface"));
        nav_spans.extend(key_capsule("↑/↓", "peer"));
        nav_spans.extend(key_capsule("/", "filter"));
        nav_spans.extend(key_capsule("o", "sort"));
        nav_spans.push(Span::styled("│  ", t.muted()));
    }
    nav_spans.extend(key_capsule("?", "help"));
    nav_spans.extend(key_capsule("q", "quit"));

    let second_line = if let Some(toast) = &app.toast {
        Line::from(vec![
            Span::styled(" ▸ ", t.pill_warn()),
            Span::raw(" "),
            Span::styled(&toast.message, t.warn_bold()),
        ])
    } else if app.current().is_none() {
        // Nothing is running: the only honest actions are the ones that work.
        Line::from(vec![
            Span::styled(" ▸ ", t.muted()),
            Span::styled("choose 1 or 2 above · ", t.subtext()),
            Span::styled(":", t.signal()),
            Span::styled(" every action · ", t.muted()),
            Span::styled("?", t.signal()),
            Span::styled(" help", t.muted()),
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
        Line::from(act_spans)
    };

    suggestion_lines.push(Line::from(nav_spans));
    suggestion_lines.push(second_line);
    frame.render_widget(Paragraph::new(suggestion_lines), area);
}

/// The key or palette verb that resolves a suggestion's action — the learning
/// curve made concrete: the machine says what it needs *and* which button does
/// it, so an operator who has never read the manual can still act.
fn suggestion_hint(action: &crate::guidance::Action) -> &'static str {
    use crate::guidance::Action;
    match action {
        Action::JoinNetwork => "2 join a network",
        Action::SetupServer => "1 host a server",
        Action::StartService => "Space start",
        Action::EnableService => ": enable units",
        Action::RestartService => ": restart service",
        Action::DisableUnits => ": disable units",
        Action::InvitePeer => "v invite",
        Action::CloseEnrolment => ": close enrolment",
        Action::FinalizePeer(_) => "f finalize (select peer)",
        Action::PingPeer => "p ping",
        Action::SyncHost => ": sync host",
        Action::OpenLogs => "l logs",
        Action::HealthCheck => "H health",
        Action::EditConfig => "E edit config",
        Action::CopyPublicLine => "y copy",
    }
}

fn help_row(keys: &'static str, desc: &'static str) -> Line<'static> {
    let t = theme();
    Line::from(vec![
        Span::styled(format!("  {keys:<17} "), t.accent()),
        Span::styled(desc, t.text()),
    ])
}

fn help_section(width: u16, title: &'static str) -> Line<'static> {
    theme().section_rule(width, title)
}

fn draw_help(frame: &mut Frame<'_>, app: &App) {
    let t = theme();
    let help_width = frame.area().width.saturating_sub(2);
    let text = vec![
        Line::from(vec![
            Span::styled(" ◆ VALLUM ", t.pill_accent()),
            Span::styled("  ──●──◆──●──  OPERATIONS COCKPIT REFERENCE", t.accent()),
        ]),
        Line::from(""),
        help_section(
            help_width,
            "Command Palette & Navigation (or click footer / rows)",
        ),
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
        help_section(help_width, "Peer Management & Optical Provisioning"),
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
        help_section(help_width, "Tunnel Service & Configuration"),
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
        help_section(help_width, "Operational Semantics & Security"),
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
    let t = theme();
    let Some(diff) = &app.diff else {
        return;
    };
    let width = usize::from(frame.area().width.saturating_sub(4) / 2);
    let mut lines = vec![Line::from(Span::styled(
        format!("old │ new    backup {}", diff.backup.display()),
        t.muted(),
    ))];
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
    let t = theme();
    let lower = line.to_ascii_lowercase();
    if lower.contains("err") || lower.contains("fail") || lower.contains("panic") {
        t.danger()
    } else if lower.contains("warn") {
        t.warn()
    } else if lower.contains("handshake")
        || lower.contains("started")
        || lower.contains("established")
        || lower.contains("listening")
    {
        t.ok()
    } else {
        t.subtext()
    }
}

fn format_log_line(line: &str) -> Line<'_> {
    let t = theme();
    if let Some(rest) = line.strip_prefix('[') {
        if let Some((ts, after_ts)) = rest.split_once("] ") {
            if let Some(level_rest) = after_ts.strip_prefix('[') {
                if let Some((level, msg)) = level_rest.split_once("] ") {
                    let level_style = match level {
                        "WARN" | "WARNING" => t.warn_bold(),
                        "ERR" | "ERROR" => t.danger_bold(),
                        _ => t.accent(),
                    };
                    return Line::from(vec![
                        Span::styled(format!("[{ts}] "), t.muted()),
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
                    "LOGS [line {}/{}] (follow, f off, r refresh, Esc)",
                    scroll_y + 1,
                    app.logs.len()
                )
            } else {
                format!(
                    "LOGS [line {}/{}] (f follow, r refresh, Esc)",
                    scroll_y + 1,
                    app.logs.len()
                )
            })),
        frame.area(),
    );
}

fn draw_trial(frame: &mut Frame<'_>, app: &App) {
    let lines: Vec<Line<'_>> = if app.trial_lines.is_empty() {
        vec![Line::from("No trial plan loaded.")]
    } else {
        app.trial_lines
            .iter()
            .map(|line| Line::from(line.as_str()))
            .collect()
    };
    let visible = usize::from(frame.area().height.saturating_sub(2));
    let scroll_y =
        (app.trial_scroll as u16).min(app.trial_lines.len().saturating_sub(visible) as u16);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll_y, 0))
            .block(modal_block(format!(
                "FULL-TUNNEL TRIAL [line {}/{}] (a arm, p panic, r refresh, Esc)",
                scroll_y + 1,
                app.trial_lines.len()
            ))),
        frame.area(),
    );
}

fn draw_health(frame: &mut Frame<'_>, app: &App) {
    let tone = match app.health_tone {
        super::health::Level::Ok => theme().ok_bold(),
        super::health::Level::Warn => theme().warn_bold(),
        super::health::Level::Fail => theme().danger_bold(),
    };
    let mut lines: Vec<Line<'_>> = Vec::new();
    let mut body = app.health_lines.iter();
    if let Some(first) = body.next() {
        lines.push(Line::from(Span::styled(first.as_str(), tone)));
    }
    lines.extend(body.map(|line| Line::from(line.as_str())));
    if lines.is_empty() {
        lines.push(Line::from("No health reading yet."));
    }
    let visible = usize::from(frame.area().height.saturating_sub(2));
    let scroll_y =
        (app.health_scroll as u16).min(app.health_lines.len().saturating_sub(visible) as u16);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll_y, 0))
            .block(modal_block(format!(
                "EGRESS HEALTH [line {}/{}] (r refresh, Esc)",
                scroll_y + 1,
                app.health_lines.len()
            ))),
        frame.area(),
    );
}

fn draw_qr(frame: &mut Frame<'_>, area: Rect, qr: &super::qr::QrState) {
    let t = theme();
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
                Paragraph::new(Line::from(Span::styled(error, t.danger()))),
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
                t.danger_bold(),
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
                t.signal(),
            )),
            Line::from(""),
            Line::from("n/p frame  Esc close"),
        ];
        frame.render_widget(Paragraph::new(lines), inner);
        return;
    }

    let qr_style = t.qr_module();
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
                    Span::styled(" ● ZERO PRIVATE KEYS ", theme().pill_ok()),
                    Span::styled(" token + server fingerprint only", theme().ok()),
                ])
            } else {
                Line::from(vec![
                    Span::styled(" ⚠ SECRET MATERIAL ", theme().pill_warn()),
                    Span::styled(" contains peer private key", theme().warn()),
                ])
            },
            Line::from(""),
            t.section_rule(cols[1].width, "Frame Telemetry"),
            Line::from(vec![
                Span::styled("frame       ", t.muted()),
                Span::styled(format!("{current_frame}/{total_frames} "), t.text_bold()),
                Span::styled(progress_bar, t.signal()),
            ]),
            detail_kv("hash", qr.hash.clone(), t.signal()),
            detail_kv(
                "encoding",
                "VALLUM1 · ISO/IEC 18004 (EC-L, 2px quiet zone)",
                t.subtext(),
            ),
            Line::from(""),
            t.section_rule(
                cols[1].width,
                if is_invite {
                    "Client Handoff"
                } else {
                    "Offline File Fallback"
                },
            ),
            detail_kv(
                if is_invite { "invite" } else { "saved" },
                qr.path.clone(),
                t.text(),
            ),
            Line::from(vec![
                Span::styled(
                    if is_invite {
                        "join        "
                    } else {
                        "import      "
                    },
                    t.muted(),
                ),
                Span::styled(
                    if is_invite {
                        "vallum join vallum1-join:… (copied)".to_owned()
                    } else {
                        format!("vallum import-bundle {}", qr.path)
                    },
                    t.ok(),
                ),
            ]),
            Line::from(""),
            t.section_rule(cols[1].width, "Controls"),
            Line::from(vec![
                Span::styled("n / →", t.accent()),
                Span::styled(" next frame   ", t.subtext()),
                Span::styled("p / ←", t.accent()),
                Span::styled(" prev frame", t.subtext()),
            ]),
            Line::from(vec![
                Span::styled("Esc / q", t.accent()),
                Span::styled(" close modal & clear secret from display", t.subtext()),
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
            t.warn(),
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
    let t = theme();
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
            t.danger_bold()
        } else if focused {
            t.accent()
        } else {
            Style::default()
        };

        let mut spans = vec![Span::styled(
            format!("{marker} {:<22} ", field.label),
            style,
        )];

        if focused {
            if is_empty && !field.placeholder.is_empty() {
                spans.push(Span::styled("|", t.signal()));
                spans.push(Span::styled(field.placeholder, t.muted()));
            } else if field.masked {
                spans.push(Span::styled(format!("{value}|"), style));
            } else {
                spans.push(Span::styled(
                    field_value_display(&field.value, form.cursor, value_width, true),
                    style,
                ));
            }
        } else if is_empty && !field.placeholder.is_empty() {
            spans.push(Span::styled(field.placeholder, t.muted()));
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
        Span::styled("ℹ ", t.signal()),
        Span::styled(hint, t.muted()),
    ]));
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("! {}", error.message),
            t.danger_bold(),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Tab", t.signal()),
        Span::styled(" next  ", t.muted()),
        Span::styled("←/→", t.signal()),
        Span::styled(" move  ", t.muted()),
        Span::styled("Home/End", t.signal()),
        Span::raw("  "),
        Span::styled("Ctrl-U", t.signal()),
        Span::styled(" clear  ", t.muted()),
        Span::styled("Enter", t.signal()),
        Span::styled(" submit  ", t.muted()),
        Span::styled("Esc", t.signal()),
        Span::styled(" cancel", t.muted()),
    ]));
    frame.render_widget(
        Paragraph::new(lines)
            .block(modal_block(format!("FORM · {}", form.title.to_uppercase())))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_confirm(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let t = theme();
    let popup = centered(area, 64, 25);
    frame.render_widget(Clear, popup);
    let mut lines = Vec::new();
    if let Some(confirm) = &app.confirm {
        match &confirm.action {
            super::app::ConfirmAction::RemovePeer { label, .. } => {
                lines.push(Line::from(Span::styled(
                    format!("Remove {label}?"),
                    t.warn_bold(),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "This will disconnect the peer and revoke access.",
                ));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("Enter", t.accent()),
                    Span::raw(" confirms  ·  "),
                    Span::styled("Esc", t.muted()),
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
            super::app::ConfirmAction::DisableUnits { stem } => {
                lines.push(Line::from(Span::styled(
                    format!("Disable all units for '{stem}'?"),
                    theme().warn_bold(),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "The tunnel stops now and stays off after reboot. The config \
                     and keys stay — enabling brings them back.",
                ));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("Enter", theme().accent()),
                    Span::raw(" disables units  ·  "),
                    Span::styled("Esc", theme().muted()),
                    Span::raw(" cancels"),
                ]));
            }
            super::app::ConfirmAction::ApplyConfig => {
                lines.push(Line::from(Span::styled(
                    "Config parsed successfully.",
                    t.ok_bold(),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from("Apply new configuration now?"));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("Enter", t.accent()),
                    Span::raw(" restarts service  ·  "),
                    Span::styled("Esc", t.muted()),
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
    let t = theme();
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
        Span::styled(" : ", t.pill_accent()),
        Span::raw(" "),
        Span::styled(&palette.input, t.text_bold()),
        Span::styled("▌", t.signal()),
        Span::styled(
            format!(
                "{:>width$}",
                count_label,
                width = (inner.width as usize).saturating_sub(palette.input.chars().count() + 5)
            ),
            t.muted(),
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
                t.muted(),
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
            t.pill_accent()
        } else if !available {
            t.muted()
        } else {
            t.text()
        };
        let cat_style = if selected { base_style } else { t.signal() };
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
                if selected { base_style } else { t.muted() },
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
