// SPDX-License-Identifier: Apache-2.0

//! The terminal operations console.

pub mod actions;
pub mod app;
pub mod bundle;
pub mod client;
pub mod input;
pub mod qr;
pub mod ui;

use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEventKind};
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
        return Err(Error::Usage(
            "`vallum tui` needs a terminal; use `vallum show` or `vallum tui --snapshot`"
                .to_owned(),
        ));
    }
    let mut app = App::new(client::discover(args));
    actions::refresh(&mut app);

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        default_hook(info);
    }));

    enable_raw_mode().map_err(Error::Io)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(Error::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(Error::Io)?;
    let result = event_loop(&mut terminal, &mut app);
    disable_raw_mode().map_err(Error::Io)?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(Error::Io)?;
    terminal.show_cursor().map_err(Error::Io)?;
    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Error> {
    let mut last_refresh = Instant::now();
    while !app.quit {
        if last_refresh.elapsed() >= Duration::from_secs(1) {
            actions::refresh(app);
            last_refresh = Instant::now();
        }
        app.expire_toast();
        if let Some(qr) = app.qr.as_mut() {
            qr.tick();
        }
        if let Some(path) = app.editor.take() {
            open_editor(terminal, &path)?;
            actions::refresh(app);
            app.notify("config edited; restart or syncconf to apply");
        }
        terminal
            .draw(|frame| ui::draw(frame, app))
            .map_err(Error::Io)?;
        if event::poll(Duration::from_millis(100)).map_err(Error::Io)? {
            if let Event::Key(key) = event::read().map_err(Error::Io)? {
                if key.kind == KeyEventKind::Press {
                    input::handle(app, key);
                }
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
    execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(Error::Io)?;
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_owned());
    let _ = std::process::Command::new(editor).arg(path).status();
    execute!(terminal.backend_mut(), EnterAlternateScreen).map_err(Error::Io)?;
    enable_raw_mode().map_err(Error::Io)?;
    terminal.clear().map_err(Error::Io)?;
    Ok(())
}

fn snapshot(args: &TuiArgs) -> Result<(), Error> {
    let mut app = App::new(client::discover(args));
    actions::refresh(&mut app);
    let backend = TestBackend::new(args.width.max(40), args.height.max(12));
    let mut terminal =
        Terminal::new(backend).map_err(|error| Error::Usage(format!("tui snapshot: {error}")))?;
    terminal
        .draw(|frame| ui::draw(frame, &app))
        .map_err(|error| Error::Usage(format!("tui snapshot: {error}")))?;
    let buffer = terminal.backend().buffer();
    let mut out = io::stdout();
    for y in 0..args.height.max(12) {
        for x in 0..args.width.max(40) {
            let symbol = buffer.cell((x, y)).map_or(" ", |cell| cell.symbol());
            write!(out, "{symbol}").map_err(Error::Io)?;
        }
        writeln!(out).map_err(Error::Io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
