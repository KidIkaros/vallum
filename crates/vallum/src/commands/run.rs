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
use crate::net::{self, SharedSocket};
use crate::privileges;
use crate::run::{self, Shutdown};
use crate::sandbox;
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

    // A peer whose endpoint is one of this host's own addresses cannot carry a
    // tunnel through itself — the packets would loop back into the interface
    // they left. This is the class that bit the lab (a host-network container
    // seeding routes to itself); the config now refuses instead of failing
    // mysteriously later.
    {
        let own = crate::net::local_addresses();
        for peer in &resolved.peers {
            let Some(endpoint) = peer.endpoint() else {
                continue;
            };
            let host = endpoint.ip().to_string();
            if own.iter().any(|address| address == &host) {
                return Err(Error::Precondition(format!(
                    "peer `{}` endpoint {endpoint} is this host's own address — a tunnel \
                     cannot carry through itself",
                    peer.name()
                )));
            }
        }
    }

    // A peer whose endpoint is one of this host's own addresses cannot carry a
    // tunnel through itself — the packets would loop back into the interface
    // they left. This is the class that bit the lab (a host-network container
    // seeding routes to itself); the config now refuses instead of failing
    // mysteriously later.
    {
        let own = crate::net::local_addresses();
        for peer in &resolved.peers {
            let Some(endpoint) = peer.endpoint() else {
                continue;
            };
            let host = endpoint.ip().to_string();
            if own.iter().any(|address| address == &host) {
                return Err(Error::Precondition(format!(
                    "peer `{}` endpoint {endpoint} is this host's own address — a tunnel \
                     cannot carry through itself",
                    peer.name()
                )));
            }
        }
    }

    let clock = Arc::new(SystemClock::new());
    let mut rng = entropy::OsRng::new();

    // The config can only guess the path MTU; probing it discovers what the path actually carries.
    // If `interface.outer_mtu` was not explicitly configured, probe the configured peer endpoints
    // (with kernel route cache fallback) before opening the TUN interface, so both the TUN interface
    // MTU (governing TCP MSS) and the outer segmentation budget are sized correctly from the start.
    let explicit_outer_mtu = config.interface.outer_mtu.is_some();
    let floor_budget = usize::from(crate::tun::MIN_MTU) + crate::tun::DATA_OVERHEAD;
    let min_outer_mtu = floor_budget + usize::from(config::OUTER_HEADER_LEN);

    let discovered_path_mtu = resolved
        .peers
        .iter()
        .filter_map(|peer| peer.endpoint())
        .filter_map(|endpoint| {
            crate::net::probe_path_mtu(endpoint).or_else(|| crate::net::path_mtu(endpoint).ok())
        })
        .min();

    let mut outer_budget = resolved.outer_budget;
    let mut inner_mtu = resolved.mtu;

    if let Some(discovered) = discovered_path_mtu {
        if (discovered as usize) < min_outer_mtu {
            log_warn!(
                log,
                "discovered path MTU {discovered} is below the minimum supported outer MTU of \
                 {min_outer_mtu} bytes; tunnel packets will likely fail on this link"
            );
        }
        if !explicit_outer_mtu && discovered < config::DEFAULT_OUTER_MTU {
            let clamped_mtu = (discovered as usize).max(min_outer_mtu);
            let derived_budget = clamped_mtu.saturating_sub(usize::from(config::OUTER_HEADER_LEN));
            outer_budget = outer_budget.min(derived_budget);
            let mut derived_inner =
                u16::try_from(outer_budget.saturating_sub(crate::tun::DATA_OVERHEAD))
                    .unwrap_or(crate::tun::DEFAULT_MTU)
                    .min(crate::tun::DEFAULT_MTU);
            let has_v6 = resolved
                .addresses
                .iter()
                .any(|prefix| prefix.as_ipnet().addr().is_ipv6());
            if has_v6 && derived_inner < config::IPV6_MIN_MTU {
                derived_inner = config::IPV6_MIN_MTU;
            }
            inner_mtu = inner_mtu.min(derived_inner);
            log_info!(
                log,
                "path MTU discovered as {discovered} bytes (PPPoE/DS-Lite link); \
                 outer budget set to {outer_budget}, inner MTU set to {inner_mtu}"
            );
        }
    }

    let spec = InterfaceSpec {
        name: resolved.interface_name.clone(),
        addresses: resolved.addresses.clone(),
        mtu: inner_mtu,
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

    let socket = net::bind_with_transport_options(
        resolved.carrier,
        resolved.listen,
        resolved.fwmark,
        net::TransportOptions {
            tcp_upgrade: resolved.tcp_upgrade.as_deref(),
            ss_psk: resolved.ss_psk.as_deref(),
            tls_sni: resolved.tls_sni.as_deref(),
        },
    )?;
    let bound = socket.local_addr().unwrap_or(resolved.listen);
    let shared = Arc::new(SharedSocket::new(Arc::clone(&socket)));

    // Everything privileged is done: the interface exists, the socket is bound,
    // and the key has been read. From here the daemon needs no more than the two
    // file descriptors it already holds, so it sheds what it was started with.
    if let Some(privileges) = &resolved.privileges {
        // Pin key pages before the drop: after setuid the memlock limit may be
        // gone. A failure warns — an unpinned key is worse than a warning, and
        // a tunnel that refuses to start over mlock is worse than both.
        if let Err(error) = privileges::lock_memory() {
            log_warn!(log, "cannot pin key material in memory (mlockall): {error}");
        }
        privileges::drop_to(privileges)?;
        log_info!(log, "dropped privileges to {}", privileges.describe());
        // Before any thread exists: the control server, the readers, and the
        // carrier's threads all start below, and each inherits this filter. That
        // ordering is the reason the filter is complete rather than partial, and
        // moving this call after them would lose it silently (ADR-0028).
        sandbox::install(resolved.sandbox)?;
        log_info!(log, "syscall filter installed in {} mode", resolved.sandbox);
    }

    let budget = outer_budget;

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
            budget,
            addresses: resolved.addresses.clone(),
            forward: resolved.forward,
            control: resolved.control.clone().map(|path| control::ControlServer {
                path: path.clone(),
                context: control::ControlContext {
                    interface: interface_name,
                    addresses: resolved.addresses.clone(),
                    private_key: resolved.seed.clone(),
                    private_key_path: key_path.clone(),
                    control_path: Some(path),
                    listen: bound,
                    carrier: resolved.carrier,
                    tcp_upgrade: resolved.tcp_upgrade.clone(),
                    ss_psk: resolved.ss_psk.clone(),
                    tls_sni: resolved.tls_sni.clone(),
                    fwmark: resolved.fwmark,
                    socket: Arc::clone(&shared),
                    suite,
                    clock: Arc::clone(&clock) as Arc<dyn TimeSource>,
                    stats: Arc::new(run::SharedStats::default()),
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
