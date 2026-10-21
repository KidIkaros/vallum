// SPDX-License-Identifier: Apache-2.0

//! The terminal operations console.

pub mod actions;
pub mod app;
pub mod bundle;
pub mod client;
pub mod input;
pub mod keymap;
pub mod qr;
pub mod theme;
pub mod ui;

use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{CrosstermBackend, TestBackend};
use ratatui::Terminal;

use crate::commands::tui::TuiArgs;
use crate::Error;

use app::App;

pub fn run(args: &TuiArgs) -> Result<(), Error> {
    if args.snapshot {
        return snapshot(args);
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        let msg = "this flow needs a terminal; `vallum tui` was given a non-tty.\n".to_string()
            + "Try inside a real terminal: tmux new-session -d -x 80 -y 24 'vallum tui'\n"
            + "Or via script:             script -qec 'vallum tui' /dev/null\n"
            + "Fallback UI:               vallum tui --snapshot\n"
            + "(no root/CAP_NET_ADMIN:    the daemon cannot open a TUN interface)";
        return Err(Error::Usage(msg));
    }
    let mut app = App::new(client::discover(args));
    let (keymap, warning) = keymap::KeyMap::load(args.keymap_file());
    app.keymap = keymap;
    if let Some(warning) = warning {
        app.notify(warning);
    }
    actions::refresh(&mut app);

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableBracketedPaste
        );
        default_hook(info);
    }));

    enable_raw_mode().map_err(Error::Io)?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )
    .map_err(Error::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(Error::Io)?;
    let result = event_loop(&mut terminal, &mut app);
    disable_raw_mode().map_err(Error::Io)?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        DisableBracketedPaste
    )
    .map_err(Error::Io)?;
    terminal.show_cursor().map_err(Error::Io)?;
    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Error> {
    let mut last_refresh = Instant::now();
    while !app.quit {
        if app.refresh_rate > 0 && last_refresh.elapsed() >= Duration::from_millis(app.refresh_rate)
        {
            actions::refresh(app);
            last_refresh = Instant::now();
        }
        app.expire_toast();
        app.poll_ping();
        if let Some(qr) = app.qr.as_mut() {
            qr.tick();
        }
        if app.view == app::View::Logs
            && app.logs_follow
            && app.last_logs.elapsed() >= Duration::from_secs(1)
        {
            actions::load_logs(app);
        }
        if let Some(path) = app.editor.take() {
            open_editor(terminal, &path)?;
            actions::finish_edit_config(app, &path);
            actions::refresh(app);
        }
        terminal
            .draw(|frame| ui::draw(frame, app))
            .map_err(Error::Io)?;
        if event::poll(Duration::from_millis(100)).map_err(Error::Io)? {
            match event::read().map_err(Error::Io)? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    input::handle(app, key);
                }
                Event::Mouse(mouse) => {
                    input::handle_mouse(app, mouse);
                }
                Event::Paste(text) => {
                    input::handle_paste(app, text);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn open_editor(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    path: &std::path::Path,
) -> Result<(), Error> {
    disable_raw_mode().map_err(Error::Io)?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableBracketedPaste
    )
    .map_err(Error::Io)?;
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_owned());
    let _ = std::process::Command::new(editor).arg(path).status();
    execute!(
        terminal.backend_mut(),
        EnterAlternateScreen,
        EnableBracketedPaste
    )
    .map_err(Error::Io)?;
    enable_raw_mode().map_err(Error::Io)?;
    terminal.clear().map_err(Error::Io)?;
    Ok(())
}

fn color_to_ansi_fg(color: ratatui::style::Color) -> String {
    use ratatui::style::Color;
    match color {
        Color::Reset => "\x1b[39m".to_owned(),
        Color::Black => "\x1b[30m".to_owned(),
        Color::Red => "\x1b[31m".to_owned(),
        Color::Green => "\x1b[32m".to_owned(),
        Color::Yellow => "\x1b[33m".to_owned(),
        Color::Blue => "\x1b[34m".to_owned(),
        Color::Magenta => "\x1b[35m".to_owned(),
        Color::Cyan => "\x1b[36m".to_owned(),
        Color::Gray => "\x1b[37m".to_owned(),
        Color::DarkGray => "\x1b[90m".to_owned(),
        Color::LightRed => "\x1b[91m".to_owned(),
        Color::LightGreen => "\x1b[92m".to_owned(),
        Color::LightYellow => "\x1b[93m".to_owned(),
        Color::LightBlue => "\x1b[94m".to_owned(),
        Color::LightMagenta => "\x1b[95m".to_owned(),
        Color::LightCyan => "\x1b[96m".to_owned(),
        Color::White => "\x1b[97m".to_owned(),
        Color::Rgb(r, g, b) => format!("\x1b[38;2;{r};{g};{b}m"),
        _ => String::new(),
    }
}

fn color_to_ansi_bg(color: ratatui::style::Color) -> String {
    use ratatui::style::Color;
    match color {
        Color::Reset => "\x1b[49m".to_owned(),
        Color::Black => "\x1b[40m".to_owned(),
        Color::Red => "\x1b[41m".to_owned(),
        Color::Green => "\x1b[42m".to_owned(),
        Color::Yellow => "\x1b[43m".to_owned(),
        Color::Blue => "\x1b[44m".to_owned(),
        Color::Magenta => "\x1b[45m".to_owned(),
        Color::Cyan => "\x1b[46m".to_owned(),
        Color::Gray => "\x1b[47m".to_owned(),
        Color::DarkGray => "\x1b[100m".to_owned(),
        Color::LightRed => "\x1b[101m".to_owned(),
        Color::LightGreen => "\x1b[102m".to_owned(),
        Color::LightYellow => "\x1b[103m".to_owned(),
        Color::LightBlue => "\x1b[104m".to_owned(),
        Color::LightMagenta => "\x1b[105m".to_owned(),
        Color::LightCyan => "\x1b[106m".to_owned(),
        Color::White => "\x1b[107m".to_owned(),
        Color::Rgb(r, g, b) => format!("\x1b[48;2;{r};{g};{b}m"),
        _ => String::new(),
    }
}

fn snapshot(args: &TuiArgs) -> Result<(), Error> {
    let mut app = App::new(client::discover(args));
    let (keymap, _warning) = keymap::KeyMap::load(args.keymap_file());
    app.keymap = keymap;
    actions::refresh(&mut app);

    if let Some(iface) = app.interfaces.first_mut() {
        if iface.device.is_some() && iface.service_state.is_none() {
            iface.service_state = Some(app::ServiceState::Active);
        }
        if iface.rx_history.is_empty() && iface.device.is_some() {
            iface.rx_rate = 1_420_800.0;
            iface.tx_rate = 3_891_200.0;
            iface.rx_history = vec![
                420, 680, 910, 1250, 1100, 1480, 1920, 1640, 1380, 1750, 2100, 1890, 1520, 1680,
                2240, 1980, 1760, 1420, 1650, 1890, 2310, 2050, 1780, 1940, 2180, 1840,
            ];
            iface.tx_history = vec![
                980, 1420, 1850, 2400, 2150, 2890, 3420, 3100, 2780, 3250, 3910, 3540, 2980, 3320,
                4120, 3780, 3450, 2910, 3380, 3720, 4280, 3950, 3610, 3840, 4090, 3891,
            ];
        }
    }

    match args.snapshot_view.as_str() {
        "empty" => {
            app.interfaces.clear();
        }
        "logs" => {
            app.view = app::View::Logs;
            app.logs = vec![
                "[2026-10-19 20:30:11] [INFO] daemon started listening on 0.0.0.0:51820".to_owned(),
                "[2026-10-19 20:30:12] [INFO] interface vallum0 configured with address 10.7.0.1/24".to_owned(),
                "[2026-10-19 20:30:14] [INFO] handshake established with gateway-us-east (suite 0x0003 tri-hybrid)".to_owned(),
                "[2026-10-19 20:30:15] [INFO] cryptokey routing prefix 10.7.0.2/32 bound to peer 8b7e6d5c4b3a2918".to_owned(),
                "[2026-10-19 20:30:42] [INFO] handshake established with charlie-macbook (suite 0x0003)".to_owned(),
                "[2026-10-19 20:31:18] [WARN] dev-bastion-01: keepalive packet delayed (1420ms)".to_owned(),
                "[2026-10-19 20:32:05] [INFO] rekey triggered for epoch 1; ratchet PCS confirmed".to_owned(),
                "[2026-10-19 20:33:40] [INFO] datagram batching active (16 pkts/call via sendmmsg)".to_owned(),
            ];
        }
        "help" => {
            app.view = app::View::Help;
        }
        "qr" => {
            app.qr = Some(qr::QrState {
                frames: vec![
                    "VALLUM1:1/1:afa1f7be:sudo vallum join vallum1-join:198.51.100.10:51821/charlie-macbook/f19e9b24b97a687e4b3a7a1bdc16aaed/a1b2-c3d4-e5f6-7890-a1b2-c3d4-e5f6-7890/afa1f7be2ef6".to_owned(),
                ],
                index: 0,
                last: Instant::now(),
                hash: "afa1f7be".to_owned(),
                path: "/run/vallum/enroll-vallum0-f19e9b24.json".to_owned(),
                kind: qr::QrKind::Invite,
            });
        }
        "palette" => {
            app.palette = Some(app::PaletteState {
                input: String::new(),
                selected: 3,
            });
        }
        "filter" => {
            app.filtering = true;
            app.peer_filter = "psk".to_owned();
        }
        "ping" => {
            app.peer_selected = 1;
            app.notify("ping 10.7.0.3: reply in 18.2 ms");
        }
        "peer1" => {
            app.peer_selected = 1;
        }
        "peer2" => {
            app.peer_selected = 2;
        }
        _ => {}
    }

    let backend = TestBackend::new(args.width.max(40), args.height.max(12));
    let mut terminal =
        Terminal::new(backend).map_err(|error| Error::Usage(format!("tui snapshot: {error}")))?;
    terminal
        .draw(|frame| ui::draw(frame, &app))
        .map_err(|error| Error::Usage(format!("tui snapshot: {error}")))?;
    let buffer = terminal.backend().buffer();
    let mut out = io::stdout();
    for y in 0..args.height.max(12) {
        let mut last_fg = ratatui::style::Color::Reset;
        let mut last_bg = ratatui::style::Color::Reset;
        let mut last_bold = false;

        for x in 0..args.width.max(40) {
            if let Some(cell) = buffer.cell((x, y)) {
                if args.ansi {
                    let bold = cell.modifier.contains(ratatui::style::Modifier::BOLD);
                    if bold != last_bold {
                        if bold {
                            write!(out, "\x1b[1m").map_err(Error::Io)?;
                        } else {
                            write!(out, "\x1b[22m").map_err(Error::Io)?;
                        }
                        last_bold = bold;
                    }
                    if cell.fg != last_fg {
                        write!(out, "{}", color_to_ansi_fg(cell.fg)).map_err(Error::Io)?;
                        last_fg = cell.fg;
                    }
                    if cell.bg != last_bg {
                        write!(out, "{}", color_to_ansi_bg(cell.bg)).map_err(Error::Io)?;
                        last_bg = cell.bg;
                    }
                }
                write!(out, "{}", cell.symbol()).map_err(Error::Io)?;
            } else {
                write!(out, " ").map_err(Error::Io)?;
            }
        }
        if args.ansi {
            write!(out, "\x1b[0m").map_err(Error::Io)?;
        }
        writeln!(out).map_err(Error::Io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
