// SPDX-License-Identifier: Apache-2.0

//! The `vallum` command.
//!
//! Three verbs and no configuration state: `keygen` writes a private key and
//! prints the line a peer must be configured with, `pubkey` reprints that line
//! from an existing key, and `run` starts the tunnel. There is no `set`/`show`
//! pair and no control socket, because this phase has no live-reconfiguration
//! story and inventing one would be a second source of truth for the peer table.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use vallum::clock::{SystemClock, TimeSource};
use vallum::config::{self, Config};
use vallum::entropy;
use vallum::keys;
use vallum::logging::Logger;
use vallum::net::{DatagramSocket, UdpTransport};
use vallum::privileges;
use vallum::run::{self, Shutdown};
use vallum::tun::{self, InterfaceSpec};
use vallum::{log_info, log_warn, Error};
use vallum_crypto_sdk::SdkSuite;
use vallum_tunnel::Device;

#[derive(Parser)]
#[command(
    name = "vallum",
    version,
    about = "Vallum — hybrid post-quantum layer-3 tunnel",
    long_about = "A hybrid post-quantum VPN. Keys are generated with `keygen`, exchanged \
                  by hand, and the tunnel is started with `run`."
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
}

#[derive(Args)]
struct RunArgs {
    /// The configuration file.
    #[arg(long, short, value_name = "FILE")]
    config: PathBuf,

    /// How often the loop wakes with nothing to do, in milliseconds.
    ///
    /// Bounds timer-deadline latency and shutdown latency; data packets do not
    /// wait for it.
    #[arg(long, value_name = "MS")]
    tick_ms: Option<u64>,
}

#[derive(Args)]
struct KeygenArgs {
    /// Where to write the private key. Refuses to overwrite an existing file.
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,

    /// The suite id, decimal or `0x`-prefixed hex. Defaults to the tri-hybrid.
    #[arg(long, default_value = "3", value_name = "ID")]
    suite: String,

    /// Also derive a hybrid signing key pair, turning on P3 identity.
    #[arg(long)]
    signing: bool,
}

#[derive(Args)]
struct PubkeyArgs {
    /// The private key to read.
    #[arg(long, short = 'k', value_name = "FILE")]
    private_key: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Run(args) => run_tunnel(&args, cli.allow_insecure_key_permissions),
        Command::Keygen(args) => keygen(&args),
        Command::Pubkey(args) => pubkey(&args, cli.allow_insecure_key_permissions),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vallum: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `run`.
fn run_tunnel(args: &RunArgs, allow_insecure_key: bool) -> Result<(), Error> {
    let config = Config::load(&args.config)?;

    // The key's mode is checked before the file is expanded: a key the group or
    // the world can read is refused, not warned about. The override is explicit
    // and still produces a warning once the logger exists.
    let key_path = config::resolve_key_path(&args.config, &config.interface.private_key);
    let insecure_key = keys::check_permissions(&key_path, allow_insecure_key)?;

    // The suite is a property of the key, not of a flag: a seed is only a key
    // under the suite it was expanded with, so the key file is the one place it
    // can come from and the config cannot disagree with it.
    let suite = SdkSuite::from_id(config.suite_id(&args.config)?)
        .map_err(|e| Error::Suite(format!("key file names a suite this build cannot use: {e}")))?;

    let resolved = config.resolve(&args.config, &suite)?;
    let log = Logger::new(resolved.level);
    if let Some(warning) = insecure_key {
        log_warn!(
            log,
            "{warning} (allowed by --allow-insecure-key-permissions)"
        );
    }
    for warning in &resolved.warnings {
        log_warn!(log, "{warning}");
    }

    let clock = Arc::new(SystemClock::new());
    let mut rng = entropy::OsRng::new();

    let spec = InterfaceSpec {
        name: resolved.interface_name.clone(),
        address: resolved.address,
        mtu: resolved.mtu,
    };
    let mut interface_warnings = Vec::new();
    let parts =
        tun::open(&spec, &mut |warning| interface_warnings.push(warning)).map_err(|source| {
            Error::Interface {
                name: spec.name.clone(),
                source,
            }
        })?;
    for warning in &interface_warnings {
        log_warn!(log, "{warning}");
    }

    let socket: Arc<dyn DatagramSocket> = Arc::new(UdpTransport::bind(resolved.listen)?);

    // Everything privileged is done: the interface exists, the socket is bound,
    // and the key has been read. From here the daemon needs no more than the two
    // file descriptors it already holds, so it sheds what it was started with.
    if let Some(privileges) = &resolved.privileges {
        privileges::drop_to(privileges)?;
        log_info!(log, "dropped privileges to {}", privileges.describe());
    }

    let device = Device::new(
        Arc::new(suite),
        resolved.identity,
        resolved.peers,
        &mut rng,
        clock.monotonic_ms(),
    )?;

    let shutdown = Shutdown::new();
    install_signal_handlers(&shutdown)?;

    log_info!(
        log,
        "starting: interface `{}`, listening on {}, {} peer(s)",
        parts.name,
        resolved.listen,
        device.peer_count(),
    );

    let policy = run::Loop {
        tick_ms: args.tick_ms.unwrap_or(run::DEFAULT_TICK_MS),
        ..run::Loop::default()
    };
    let stats = run::run(
        device,
        run::Attached {
            parts,
            socket,
            clock: Arc::clone(&clock) as Arc<dyn TimeSource>,
            budget: resolved.outer_budget,
        },
        &mut rng,
        log,
        policy,
        shutdown,
    )?;
    log_info!(log, "stopped after {} handshake(s)", stats.established);
    Ok(())
}

/// Raise the shutdown flag on `SIGINT` and `SIGTERM`.
///
/// A signal handler is the one piece of the daemon that is neither testable nor
/// portable, so it lives here, at the very edge, and does exactly one thing: set
/// a flag. The handlers are never unregistered — the process is on its way out.
fn install_signal_handlers(shutdown: &Shutdown) -> Result<(), Error> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    signal_hook::flag::register(SIGINT, shutdown.atomic()).map_err(Error::Io)?;
    signal_hook::flag::register(SIGTERM, shutdown.atomic()).map_err(Error::Io)?;
    Ok(())
}

/// `keygen`.
fn keygen(args: &KeygenArgs) -> Result<(), Error> {
    let suite_id = parse_suite(&args.suite)?;
    // Refuse to write a key for a suite this build cannot expand.
    let suite = SdkSuite::from_id(suite_id)
        .map_err(|e| Error::Suite(format!("suite `{}`: {e}", args.suite)))?;

    let file = keys::new_secret(suite_id, args.signing, entropy::seed());
    let identity = keys::identity(&suite, &file)?;
    keys::save_secret(&args.output, &file)?;

    println!("{}", keys::encode_public(suite_id, &identity.to_peer()));
    eprintln!(
        "vallum: wrote {} ({}, {})",
        args.output.display(),
        keys::describe_suite(suite_id),
        if args.signing {
            "with signing"
        } else {
            "KEM-only"
        },
    );
    Ok(())
}

/// `pubkey`.
fn pubkey(args: &PubkeyArgs, allow_insecure_key: bool) -> Result<(), Error> {
    // Reading the key at all is the exposure, so `pubkey` enforces the same rule
    // as `run`: the mode is checked before the file is read.
    if let Some(warning) = keys::check_permissions(&args.private_key, allow_insecure_key)? {
        eprintln!("vallum: warning: {warning} (allowed by --allow-insecure-key-permissions)");
    }
    let file = keys::load_secret(&args.private_key)?;
    let suite = SdkSuite::from_id(file.suite)
        .map_err(|e| Error::Suite(format!("key file names a suite this build cannot use: {e}")))?;
    let identity = keys::identity(&suite, &file)?;
    println!("{}", keys::encode_public(file.suite, &identity.to_peer()));
    Ok(())
}

/// Parse a suite id, accepting `3` and `0x0003`.
fn parse_suite(text: &str) -> Result<u16, Error> {
    let text = text.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16)
    } else {
        text.parse::<u16>()
    };
    parsed.map_err(|e| {
        Error::Usage(format!(
            "suite `{text}` is not an id (decimal, or hex with a 0x prefix): {e}"
        ))
    })
}
