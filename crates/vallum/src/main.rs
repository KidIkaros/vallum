// SPDX-License-Identifier: Apache-2.0

//! The `vallum` command: parse, dispatch, and exit.

use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use vallum::commands::bench::BenchArgs;
use vallum::commands::client::ClientArgs;
use vallum::commands::control::{SetconfArgs, ShowArgs, ShowconfArgs};
use vallum::commands::doctor::DoctorArgs;
use vallum::commands::identity::IdentityArgs;
use vallum::commands::import::ImportArgs;
use vallum::commands::keys::{KeygenArgs, PubkeyArgs};
use vallum::commands::metrics::MetricsArgs;
use vallum::commands::peer::PeerArgs;
use vallum::commands::run::RunArgs;
use vallum::commands::server::ServerArgs;
use vallum::commands::setup::SetupArgs;
#[cfg(feature = "tui")]
use vallum::commands::tui::TuiArgs;
use vallum::commands::{
    bench, client, control, doctor, identity, import, keys, metrics, peer, run, server, setup,
};
use vallum::Error;

#[derive(Parser)]
#[command(
    name = "vallum",
    version = concat!(env!("CARGO_PKG_VERSION"), " (linux-only)"),
    about = "Vallum — hybrid post-quantum layer-3 tunnel",
    long_about = "A hybrid post-quantum VPN. `vallum server init` prepares a server \
                  (key, config, forwarding, firewall, NAT, service), `vallum peer add` enrols \
                  a device, and `vallum import-bundle` sets up the client.\n\n\
                  The daemon is Linux-only this release; see docs/deployment/server.md."
)]
struct Cli {
    /// Absent means "tell me what this machine can be", not an error.
    #[command(subcommand)]
    command: Option<Command>,

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
    /// Set this machine up as a server, or as a client.
    Setup(SetupArgs),
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
    /// Check the platform, config, control socket, and helper tools.
    Doctor(DoctorArgs),
    /// Prepare this host to be a tunnel server.
    Server(ServerArgs),
    /// Disconnect and remove a client tunnel installed by `vallum setup`.
    Client(ClientArgs),
    /// Enrol, list, inspect, and remove peers.
    Peer(PeerArgs),
    /// Print the daemon's state as Prometheus metrics.
    Metrics(MetricsArgs),
    /// Issue, sign, verify, and inspect identity documents.
    Identity(IdentityArgs),
    /// Import a client `.vallum-bundle` file.
    ImportBundle(ImportArgs),
    /// Answer token-gated enrolment requests (runs as its own service).
    EnrollServe(EnrollServeArgs),
    /// Operate a tunnel in a terminal dashboard.
    #[cfg(feature = "tui")]
    Tui(TuiArgs),
    /// Print a shell completion script.
    Completions(CompletionsArgs),
}

#[derive(Debug, Args)]
struct EnrollServeArgs {
    /// The configuration file whose `[enroll]` section governs the responder.
    #[arg(long, value_name = "FILE", default_value = "/etc/vallum/vallum0.toml")]
    config: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct CompletionsArgs {
    /// The shell to generate for.
    #[arg(value_enum)]
    shell: clap_complete::Shell,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        // A wall of twenty subcommands is not an answer to "what now?".
        println!(
            "Vallum — a post-quantum tunnel between two machines.\n\n\
             On the server, where clients connect:\n\
             \x20  sudo vallum setup --server\n\n\
             On a machine that a server gave a .vallum-bundle:\n\
             \x20  sudo vallum setup --client <file>.vallum-bundle\n\n\
             `vallum setup` with no flags asks which one this machine is.\n\
             Every command is under `vallum --help`; the dashboard is `vallum tui`."
        );
        return ExitCode::SUCCESS;
    };
    let outcome = match command {
        Command::Setup(args) => setup::setup(&args),
        Command::EnrollServe(args) => vallum::enroll::serve(&args.config),
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
        Command::Doctor(args) => doctor::doctor(&args),
        Command::Server(args) => server::server(&args),
        Command::Client(args) => client::client(&args),
        Command::Peer(args) => peer::peer(&args),
        Command::Metrics(args) => metrics::metrics(&args),
        Command::Identity(args) => identity::identity(&args),
        Command::ImportBundle(args) => import::import(&args),
        #[cfg(feature = "tui")]
        Command::Tui(args) => vallum::commands::tui::run(&args),
        Command::Completions(args) => {
            clap_complete::generate(
                args.shell,
                &mut Cli::command(),
                "vallum",
                &mut std::io::stdout(),
            );
            Ok(())
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => {
            ExitCode::SUCCESS
        }
        // A precondition that was not met attempted nothing, and a partial run
        // names what is already in place. Automation distinguishes them.
        Err(Error::Precondition(message)) => {
            eprintln!("vallum: {message}");
            ExitCode::from(2)
        }
        Err(Error::Partial(message)) => {
            eprintln!("vallum: {message}");
            ExitCode::from(3)
        }
        Err(error) => {
            eprintln!("vallum: {error}");
            ExitCode::FAILURE
        }
    }
}
