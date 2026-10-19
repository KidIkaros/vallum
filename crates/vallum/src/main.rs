// SPDX-License-Identifier: Apache-2.0

//! The `vallum` command: parse, dispatch, and exit.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vallum::commands::bench::BenchArgs;
use vallum::commands::control::{SetconfArgs, ShowArgs, ShowconfArgs};
use vallum::commands::keys::{KeygenArgs, PubkeyArgs};
use vallum::commands::run::RunArgs;
use vallum::commands::{bench, control, keys, run};

#[derive(Parser)]
#[command(
    name = "vallum",
    version = concat!(env!("CARGO_PKG_VERSION"), " (linux-only)"),
    about = "Vallum — hybrid post-quantum layer-3 tunnel",
    long_about = "A hybrid post-quantum VPN. Keys are generated with `keygen`, exchanged \
                  by hand, and the tunnel is started with `run`.\n\n\
                  The daemon is Linux-only this release; see docs/proof/platforms.md."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Use a private key file that its group or the world can read.
    ///
    /// Refused by default: a key that someone else can read is not private, and
    /// a warning in a log is not a control. Pass this only when the exposure is
    /// deliberate — a sealed volume, a test fixture — and note that the warning
    /// is still logged.
    #[arg(long, global = true)]
    allow_insecure_key_permissions: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Run the tunnel described by a configuration file.
    Run(RunArgs),
    /// Generate a private key, and print the public line for a peer.
    Keygen(KeygenArgs),
    /// Print the public line for an existing private key.
    Pubkey(PubkeyArgs),
    /// Generate a 32-byte preshared key as 64 hex characters.
    Genpsk,
    /// Show a running daemon's device and peers.
    Show(ShowArgs),
    /// Apply a configuration file, replacing every peer.
    Setconf(SetconfArgs),
    /// Add the peers from a configuration file.
    Addconf(SetconfArgs),
    /// Apply only the differences between a config and the running daemon.
    Syncconf(SetconfArgs),
    /// Export a running daemon as a config (secrets are not included).
    Showconf(ShowconfArgs),
    /// Measure the data plane's seal/open cost on this host.
    Bench(BenchArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Run(args) => run::run(&args, cli.allow_insecure_key_permissions),
        Command::Keygen(args) => keys::keygen(&args),
        Command::Pubkey(args) => keys::pubkey(&args, cli.allow_insecure_key_permissions),
        Command::Genpsk => keys::genpsk(),
        Command::Show(args) => control::show(&args),
        Command::Setconf(args) => control::setconf(&args, true),
        Command::Addconf(args) => control::setconf(&args, false),
        Command::Syncconf(args) => control::syncconf(&args),
        Command::Showconf(args) => control::showconf(&args),
        Command::Bench(args) => bench::bench(&args),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vallum: {error}");
            ExitCode::FAILURE
        }
    }
}
