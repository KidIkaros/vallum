// SPDX-License-Identifier: Apache-2.0

//! `vallum tui`: the terminal operations console.

use std::path::PathBuf;

use clap::Args;

use crate::Error;

#[derive(Debug, Args)]
pub struct TuiArgs {
    /// A configuration file to operate on.
    #[arg(long, short, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// A control socket, instead of a config.
    #[arg(long, value_name = "SOCKET")]
    pub control: Option<PathBuf>,

    /// A directory of `*.toml` configs (default `/etc/vallum`).
    #[arg(long, value_name = "DIR")]
    pub config_dir: Option<PathBuf>,

    /// Render one frame headlessly and exit (for CI and the README).
    #[arg(long)]
    pub snapshot: bool,

    /// Snapshot width.
    #[arg(long, default_value = "120")]
    pub width: u16,

    /// Snapshot height.
    #[arg(long, default_value = "36")]
    pub height: u16,

    /// Render snapshot with ANSI colors and styles.
    #[arg(long)]
    pub ansi: bool,

    /// Snapshot view mode (dashboard, logs, help, qr, empty, filter, ping).
    #[arg(long, default_value = "dashboard")]
    pub snapshot_view: String,
}

pub fn run(args: &TuiArgs) -> Result<(), Error> {
    crate::tui::run(args)
}
