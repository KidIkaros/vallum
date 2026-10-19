// SPDX-License-Identifier: Apache-2.0

//! `vallum run`: the daemon startup path.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use vallum_crypto_sdk::SdkSuite;
use vallum_tunnel::Device;

use crate::clock::{SystemClock, TimeSource};
use crate::config::{self, Config, ResolveConfig};
use crate::control;
use crate::entropy;
use crate::keys;
use crate::logging::Logger;
use crate::net::{DatagramSocket, SharedSocket, UdpTransport};
use crate::privileges;
use crate::run::{self, Shutdown};
use crate::tun::{self, InterfaceSpec};
use crate::{log_info, log_warn, Error};

#[derive(Debug, Args)]
pub struct RunArgs {
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

/// `run`.
pub fn run(args: &RunArgs, allow_insecure_key: bool) -> Result<(), Error> {
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

    let resolved = config.resolve_with(&args.config, &suite, allow_insecure_key)?;
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
        addresses: resolved.addresses.clone(),
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

    let socket: Arc<dyn DatagramSocket> = Arc::new(UdpTransport::bind_with_fwmark(
        resolved.listen,
        resolved.fwmark,
    )?);
    let bound = socket.local_addr().unwrap_or(resolved.listen);
    let shared = Arc::new(SharedSocket::new(Arc::clone(&socket)));

    // Everything privileged is done: the interface exists, the socket is bound,
    // and the key has been read. From here the daemon needs no more than the two
    // file descriptors it already holds, so it sheds what it was started with.
    if let Some(privileges) = &resolved.privileges {
        privileges::drop_to(privileges)?;
        log_info!(log, "dropped privileges to {}", privileges.describe());
    }

    let suite: Arc<dyn vallum_crypto::CryptoSuite> = Arc::new(suite);

    let device = Device::new(
        Arc::clone(&suite),
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
        bound,
        device.peer_count(),
    );

    let interface_name = parts.name.clone();
    let policy = run::Loop {
        tick_ms: args.tick_ms.unwrap_or(run::DEFAULT_TICK_MS),
        ..run::Loop::default()
    };
    let stats = run::run(
        device,
        run::Attached {
            parts,
            socket: Arc::clone(&shared),
            clock: Arc::clone(&clock) as Arc<dyn TimeSource>,
            budget: resolved.outer_budget,
            control: resolved.control.clone().map(|path| control::ControlServer {
                path,
                context: control::ControlContext {
                    interface: interface_name,
                    addresses: resolved.addresses.clone(),
                    private_key: resolved.seed.clone(),
                    private_key_path: key_path.clone(),
                    listen: bound,
                    fwmark: resolved.fwmark,
                    socket: Arc::clone(&shared),
                    suite,
                },
            }),
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
