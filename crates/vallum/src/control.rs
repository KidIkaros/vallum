// SPDX-License-Identifier: Apache-2.0

//! The control socket: a Unix listener that speaks [`crate::uapi`].
//!
//! The socket is `0600` and same-user only; it is the same trust boundary as
//! the private-key file. The mode is set before the path is published (staged
//! in a `0700` directory, then renamed), so a permissive umask cannot expose a
//! connectable socket even briefly. A request is parsed here, forwarded to the
//! loop thread as an [`Input`](crate::run::Input), and answered there — all
//! mutation happens on the thread that owns the device, never concurrently
//! with a packet.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown as NetShutdown;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use vallum_core::identity::{PeerIdentity, StaticIdentity};
use vallum_crypto::KemPublicKey;
use vallum_crypto::{CryptoSuite, SharedSecret};
use vallum_tunnel::{Device, PeerConfig};

use crate::run::{Input, Shutdown};
use crate::uapi::errno::{EADDRINUSE, EADDRNOTAVAIL, EEXIST, EINVAL, ENOENT, EPERM, ETIMEDOUT};
use crate::uapi::{self, errno, Request, Set};

/// How long a client may take to send its request before the connection is
/// dropped.
///
/// The accept loop is serial — one connection at a time, so that every mutation
/// happens on the thread that owns the device. That invariant is sound, but it
/// means an unbounded read is an unbounded outage: a client that connects and
/// then says nothing holds the whole plane.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest request the control plane will read.
///
/// A request is a handful of short lines — except `setconf`, which carries a
/// whole configuration. That config is not small: a hybrid post-quantum public
/// line is ~4.7 KB, so 64 KiB ran out at thirteen peers and the daemon closed
/// the connection mid-write. The operator saw "Connection reset by peer" on the
/// fourteenth device, with the file already edited and the daemon not.
///
/// The bound is now set by the peer target (2,000 peers × ~5 KB ≈ 10 MB) with
/// headroom, because a cap below the product's own capacity claim is a bug that
/// only shows up in someone's rollout. Without any cap a client could stream
/// bytes at the serial loop until the process ran out of memory.
const MAX_REQUEST: usize = 16 * 1024 * 1024;

/// A `setconf` carries the whole config, and one peer costs a hybrid public
/// line (~4.7 KB). This is the relation that broke at thirteen peers, so it is
/// asserted rather than remembered: a cap below the product's own peer target
/// is a defect that only appears in someone's rollout.
const _: () = assert!(
    MAX_REQUEST >= 2_000 * 4_900,
    "MAX_REQUEST cannot carry the peer target"
);

/// How long a client waits for a reply.
///
/// Longer than the daemon's own reply budget (5 s, below), so a slow but healthy
/// daemon still answers and the timeout means what it says.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// What the control plane needs to describe the device.
pub struct ControlContext {
    /// The private-key seed, as the daemon holds it.
    pub private_key: SharedSecret,
    /// The path the seed was read from, for a config export.
    pub private_key_path: PathBuf,
    /// The path the control socket is served at, if configured.
    pub control_path: Option<PathBuf>,
    /// The kernel interface name.
    pub interface: String,
    /// The interface addresses.
    pub addresses: Vec<vallum_tunnel::Prefix>,
    /// The bound address, for the configured carrier.
    pub listen: SocketAddr,
    /// The transport, so a rebind binds the same one.
    pub carrier: crate::config::Carrier,
    /// Optional HTTP/1.1 `Upgrade: vallum` `Host` header for outbound TCP dials.
    pub tcp_upgrade: Option<String>,
    pub ss_psk: Option<String>,
    /// Optional TLS SNI hostname for `carrier = "tls"` and `carrier = "quic"`.
    pub tls_sni: Option<String>,
    /// The socket mark.
    pub fwmark: u32,
    /// The swappable socket, for a runtime rebind.
    pub socket: Arc<crate::net::SharedSocket>,
    /// The suite, for a runtime identity change.
    pub suite: Arc<dyn CryptoSuite>,
    /// The daemon's clock.
    ///
    /// Carried here so the snapshot can turn a peer's last-activity stamp into
    /// an age. The stamps are on this process's monotonic origin, which no other
    /// process shares, so the subtraction has to happen here — and it must use a
    /// clock that keeps ticking even if the data plane stops, which is exactly
    /// the case the age exists to report.
    pub clock: Arc<dyn crate::clock::TimeSource>,
    /// Live loop counters; `run` publishes here once per iteration.
    pub stats: Arc<crate::run::SharedStats>,
}

impl fmt::Debug for ControlContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlContext")
            .field("listen", &self.listen)
            .field("fwmark", &self.fwmark)
            .field("private_key", &self.private_key)
            .finish_non_exhaustive()
    }
}

/// A control socket to serve.
#[derive(Debug)]
pub struct ControlServer {
    /// The path to bind.
    pub path: PathBuf,
    /// The context used to answer `get`; owned by the loop.
    pub context: ControlContext,
}

/// Refuse to take a control path that a live daemon is still answering on.
///
/// Connecting is what tells a stale socket from a live one: a listener accepts,
/// a leftover inode refuses. Anything other than "nothing there" or "refused"
/// means this process cannot tell, and in that case it must not delete a socket
/// it has no business touching.
fn claim_path(path: &Path) -> io::Result<()> {
    match UnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "`{}` is already answering; another daemon is using this control path",
                path.display()
            ),
        )),
        Err(error) => match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => Ok(()),
            _ => Err(io::Error::new(
                error.kind(),
                format!(
                    "`{}`: cannot tell whether it is in use: {error}",
                    path.display()
                ),
            )),
        },
    }
}

/// How many staged sockets this process has bound, so their staging
/// directories cannot collide when one process binds more than one.
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The dedicated control group's gid, resolved once at startup *before* the
/// seccomp sandbox installs (#35, ADR-0048). A dropped daemon cannot look up
/// groups (getgrnam is filtered), so the socket widening reads this instead.
/// `None` means "no control group" → the socket stays owner-only.
static CONTROL_GROUP_GID: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();

/// Record the control group gid before the privilege drop / sandbox. Idempotent;
/// the first call wins, so a re-bind cannot change the access decision mid-run.
pub fn set_control_group(gid: Option<u32>) {
    let _ = CONTROL_GROUP_GID.set(gid);
}

/// The access decision, pure so it can be tested without root or a real group:
/// widen only when a control group is recorded AND the daemon is root or runs as
/// that group. No group → never widen (fail-closed).
fn control_widening_applies(euid_root: bool, egid: u32, control_gid: Option<u32>) -> bool {
    match control_gid {
        Some(gid) => euid_root || egid == gid,
        None => false,
    }
}

/// Publish the control socket to the dedicated `vallum` control group when this
/// daemon is root or already runs as that group (#35, ADR-0048).
///
/// Best-effort and fail-closed: with no control group recorded, or a personal
/// client dropped to its own login user, the socket stays owner-only `0600`.
/// Only sandbox-safe calls run here: `geteuid`/`getegid` and `fchmod` are allowed
/// after the drop; `chgrp` is attempted only when root (a root daemon installs no
/// sandbox). A daemon already in the control group keeps that group, so the mode
/// widening alone suffices — connecting needs the write bit, hence `0660`.
#[cfg(target_os = "linux")]
fn widen_to_control_group(path: &Path) {
    let Some(gid) = CONTROL_GROUP_GID.get().copied().flatten() else {
        return;
    };
    let euid = nix::unistd::geteuid();
    if !control_widening_applies(euid.is_root(), nix::unistd::getegid().as_raw(), Some(gid)) {
        return;
    }
    if euid.is_root() {
        let _ = nix::unistd::chown(path, None, Some(nix::unistd::Gid::from_raw(gid)));
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o660));
}

#[cfg(not(target_os = "linux"))]
fn widen_to_control_group(_path: &Path) {}

/// Bind a Unix socket inside `dir` and give it its final mode there.
///
/// `UnixListener::bind` creates the socket with `0777 & ~umask`, and a chmod
/// afterwards leaves the inode reachable under that looser mode until it runs.
/// The directory is created `0700` first and the socket is chmodded `0600`
/// inside it, so neither the socket nor its name is reachable while the mode is
/// still provisional — the rename that publishes it happens only after both.
fn stage_socket(dir: &Path) -> io::Result<(UnixListener, PathBuf)> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        // A leftover from a previous process with this pid and sequence: the
        // name is ours by construction, so clearing it cannot touch anyone
        // else's staging directory.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_dir_all(dir)?;
            fs::DirBuilder::new().mode(0o700).create(dir)?;
        }
        other => {
            other?;
        }
    }
    let staged = dir.join("control.sock");
    let result = (|| {
        let listener = UnixListener::bind(&staged)?;
        // Owner-only first: the socket is the same trust boundary as the
        // private-key file, and a world-writable control socket would be a
        // remote `set`. The staging dir is 0700, so this provisional mode is
        // never reachable by anyone else.
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
        // #35 (ADR-0048): a desktop console must be able to read a root-owned
        // daemon. When this daemon is root, or runs as the dedicated `vallum`
        // control group, publish the socket group-accessible (0660) so a console
        // user in that group can connect. Connecting to a Unix socket needs the
        // write bit, so group access is necessarily read+write (full uapi): the
        // `vallum` group is the trusted-operator set, not "any local user". A
        // personal client dropped to its login user (a different group) keeps
        // 0600 — its console reads as the socket's owner, unchanged.
        widen_to_control_group(&staged);
        Ok::<UnixListener, io::Error>(listener)
    })();
    match result {
        Ok(listener) => Ok((listener, staged)),
        Err(error) => {
            let _ = fs::remove_dir_all(dir);
            Err(error)
        }
    }
}

/// Publish a socket at `path` with its mode already `0600`.
///
/// The socket is bound and chmodded in a `0700` staging directory beside the
/// final path, then hard-linked into place — a link keeps the inode and its
/// mode, so the first appearance at `path` is already private. A permissive
/// umask cannot publish a connectable socket, because the only umask-derived
/// mode ever exists in a directory no other user can traverse.
///
/// `link` refuses an occupied path. That is the same refusal `bind` gives, and
/// it is what keeps a daemon that raced in from being silently replaced: an
/// unconditional rename over an occupied path would succeed and orphan its
/// accept loop. Reserving the path with a placeholder file refuses the same way,
/// but the name then exists for a moment with nothing accepting on it, and a
/// client that connects as soon as it sees the name is refused. Linking
/// publishes the name only once a listener is already behind it.
fn bind_private(path: &Path) -> io::Result<UnixListener> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{}` has no file name to publish", path.display()),
        )
    })?;
    // #35: a group-accessible socket needs a group-traversable runtime dir. When
    // this daemon is root (the only identity that can chgrp a root-owned dir),
    // put the runtime dir in the control group too. A non-root daemon relies on
    // the installer having done this; it cannot chgrp a dir it does not own.
    #[cfg(target_os = "linux")]
    if parent == crate::host::paths::runtime_dir() && nix::unistd::geteuid().is_root() {
        if let Some(gid) = CONTROL_GROUP_GID.get().copied().flatten() {
            let _ = nix::unistd::chown(parent, None, Some(nix::unistd::Gid::from_raw(gid)));
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o1770));
        }
    }
    let staging = parent.join(format!(
        ".{}.bind-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));

    let (listener, staged) = stage_socket(&staging)?;
    if let Err(error) = fs::hard_link(&staged, path) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    // The link is the published name now. These leave only litter on failure,
    // which is not a reason to take the plane down.
    let _ = fs::remove_file(&staged);
    let _ = fs::remove_dir(&staging);
    Ok(listener)
}

/// Whether the peer at the other end of an accepted connection may mutate —
/// the daemon's own uid or root. Anyone else who can connect is a `vallum`
/// group console: `get` answers with secrets redacted and `set`/`stop` is
/// refused. `getsockopt` is on the seccomp allow-list, so this is safe to call
/// after the filter installs; a credential the kernel cannot produce is
/// treated as unprivileged, the fail-closed direction.
#[cfg(target_os = "linux")]
fn peer_is_privileged(stream: &UnixStream) -> bool {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    match getsockopt(stream, PeerCredentials) {
        Ok(cred) => {
            let uid = cred.uid();
            uid == 0 || uid == nix::unistd::geteuid().as_raw()
        }
        Err(_) => false,
    }
}

/// No peercred on non-Linux targets — the socket is same-user there anyway.
#[cfg(not(target_os = "linux"))]
fn peer_is_privileged(_stream: &UnixStream) -> bool {
    true
}

/// Bind the socket and serve requests until shutdown.
///
/// # Errors
///
/// If the path cannot be staged, reserved, or published.
pub(crate) fn serve(
    path: PathBuf,
    tx: mpsc::SyncSender<Input>,
    shutdown: Shutdown,
    tunnel: Shutdown,
) -> io::Result<JoinHandle<()>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // A stale socket from a daemon that is gone should be replaced; a live one
    // must not be stolen. Without this, a second daemon on the same `control`
    // path unlinks the first daemon's socket and orphans a plane that is still
    // serving — with no `EADDRINUSE` and no log line anywhere.
    claim_path(&path)?;
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        // The runtime dir is sticky (1770): only the owner may unlink a
        // socket. A stale socket left by a daemon running under a different
        // uid (root → dropped-user migration) is reclaimed by root, not by
        // this process — name that instead of a bare EPERM.
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "`{}` is a stale socket owned by another uid — remove it as root \
                     (the runtime dir is sticky by design, ADR-0048)",
                    path.display()
                ),
            ));
        }
        Err(error) => return Err(error),
    }
    let listener = bind_private(&path)?;
    listener.set_nonblocking(true)?;

    thread::Builder::new()
        .name("vallum-control".to_owned())
        .spawn(move || {
            loop {
                if shutdown.is_triggered() {
                    break;
                }
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        stream
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    Err(_) => break,
                };
                // Bound the request read. Without this a client that connects and
                // sends nothing — a paused debugger, a `tui` that died mid-request
                // — holds the serial loop forever and every other command hangs.
                if stream.set_read_timeout(Some(REQUEST_TIMEOUT)).is_err() {
                    continue;
                }
                let mut text = String::new();
                // The client writes the request and shuts its write half; the
                // read ends at EOF. The read timeout bounds each read, but a
                // per-read timeout is not a deadline — a client that drips one
                // byte every few seconds resets it forever, so the whole request
                // is bounded here too.
                let deadline = Instant::now() + REQUEST_TIMEOUT;
                let mut buffer = [0u8; 512];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => {
                            text.push_str(&String::from_utf8_lossy(&buffer[..read]));
                            if Instant::now() >= deadline || text.len() >= MAX_REQUEST {
                                break;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            break;
                        }
                        Err(_) => break,
                    }
                }
                // `stop=1` is answered here, not on the tunnel thread: the reply
                // has to be on the wire before the loop stops. A client that asks
                // a daemon to stop and is then told nothing cannot tell success
                // from a dead socket, and the process may exit while this thread
                // is still writing.
                // SO_PEERCRED: the `vallum` group gets the console's intended
                // role — `get` answers with secrets redacted; `set`/`stop` are
                // refused. The socket mode cannot express this (group needs the
                // write bit merely to connect), so the credential does it.
                let privileged = peer_is_privileged(&stream);
                let mut stop_after_reply = false;
                let reply = match uapi::parse(&text) {
                    Ok(request) if !privileged && !matches!(request, Request::Get) => {
                        uapi::render_errno(EPERM)
                    }
                    Ok(Request::Stop) => {
                        stop_after_reply = true;
                        uapi::render_ok()
                    }
                    Ok(request) => {
                        let (reply_tx, reply_rx) = mpsc::channel();
                        if tx
                            .send(Input::Control {
                                request,
                                privileged,
                                reply: reply_tx,
                            })
                            .is_err()
                        {
                            break;
                        }
                        reply_rx
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap_or_else(|_| uapi::render_errno(ETIMEDOUT))
                    }
                    Err(_) => uapi::render_errno(EINVAL),
                };
                let _ = stream.write_all(reply.as_bytes());
                if stop_after_reply {
                    // The reply is written; the loop stops on the next iteration.
                    // This thread stops too, because a stopped tunnel has nothing
                    // left for a control plane to report.
                    let _ = stream.shutdown(NetShutdown::Both);
                    tunnel.trigger();
                    break;
                }
            }
        })
}

/// Send one request to a control socket and read the reply.
///
/// # Errors
///
/// If the socket cannot be reached or the reply cannot be read.
pub fn request(path: &Path, body: &str) -> Result<String, crate::error::Error> {
    let io_path = |source: std::io::Error| crate::error::Error::IoPath {
        action: "control socket",
        path: path.to_path_buf(),
        source,
    };
    let mut stream = UnixStream::connect(path).map_err(io_path)?;
    // A socket that accepts but never answers must not hang the caller. A hung
    // scrape is worse than a failed one: node_exporter keeps serving the last
    // textfile, so `up 1` outlives the daemon that produced it and the alert
    // that exists to catch this cannot fire.
    stream
        .set_read_timeout(Some(REPLY_TIMEOUT))
        .map_err(io_path)?;
    stream
        .set_write_timeout(Some(REPLY_TIMEOUT))
        .map_err(io_path)?;
    stream.write_all(body.as_bytes()).map_err(io_path)?;
    stream.shutdown(NetShutdown::Write).map_err(io_path)?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).map_err(|source| {
        if matches!(
            source.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            // Name the real condition: the socket exists and accepted, so
            // "connection refused" would send the operator to the wrong place.
            io_path(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "no reply within {}s; the socket accepted the connection but did not answer",
                    REPLY_TIMEOUT.as_secs()
                ),
            ))
        } else {
            io_path(source)
        }
    })?;
    Ok(reply)
}

/// Answer one request against the device. `privileged` is the accept loop's
/// SO_PEERCRED verdict: an unprivileged `get` renders with secrets redacted
/// (the `vallum`-group console's read role); `set` is refused at the accept
/// loop and refused again here in case a caller ever reaches this seam
/// directly.
#[must_use]
pub fn handle(
    device: &mut Device,
    context: &mut ControlContext,
    request: Request,
    privileged: bool,
) -> String {
    match request {
        Request::Get => uapi::render_get(&snapshot(device, context), !privileged),
        Request::Set(_) if !privileged => uapi::render_errno(EPERM),
        Request::Set(set) => match apply(device, context, set) {
            Ok(()) => uapi::render_ok(),
            Err(errno) => uapi::render_errno(errno),
        },
        // Never reached: the control thread answers `stop=1` itself, because the
        // loop it would stop cannot be the one to acknowledge the stop. This arm
        // exists so the enum stays exhaustive, and says so if a caller routes one
        // here anyway.
        Request::Stop => uapi::render_errno(errno::ENOSYS),
    }
}

fn snapshot(device: &Device, context: &ControlContext) -> uapi::DeviceState {
    let mut peers = Vec::new();
    // Read once so every peer in one answer is aged against the same instant.
    let now_ms = context.clock.monotonic_ms();
    for (id, config) in device.peers() {
        let (tx_bytes, rx_bytes, last_handshake, rejected) = match device.stats(id) {
            Some(stats) => (
                stats.tx_bytes,
                stats.rx_bytes,
                stats.last_handshake,
                stats.rejected,
            ),
            None => (0, 0, None, 0),
        };
        peers.push(uapi::PeerState {
            name: config.name().to_owned(),
            public_key: config.identity().kem().as_bytes().to_vec(),
            public_line: crate::keys::encode_public(device.suite_id(), config.identity()),
            fingerprint: device.fingerprint(id).unwrap_or([0u8; 8]),
            preshared_key: config.preshared_key().map(|psk| *psk.as_bytes()),
            previous_public_key: config
                .previous_identities()
                .first()
                .map_or_else(Vec::new, |accepted| {
                    accepted.identity().kem().as_bytes().to_vec()
                }),
            endpoint: device.endpoint(id),
            last_handshake: last_handshake.map(|stamp| (stamp.unix_seconds(), stamp.nanos())),
            tx_bytes,
            rejected,
            rx_bytes,
            window_sent: device.stats(id).map_or(0, |stats| stats.window_sent),
            window_received: device.stats(id).map_or(0, |stats| stats.window_received),
            last_received_age_ms: device
                .stats(id)
                .and_then(|stats| stats.last_received_ms)
                .map(|stamp| now_ms.saturating_sub(stamp)),
            last_sent_age_ms: device
                .stats(id)
                .and_then(|stats| stats.last_sent_ms)
                .map(|stamp| now_ms.saturating_sub(stamp)),
            dropped_no_session: device.stats(id).map_or(0, |stats| stats.dropped_no_session),
            dropped_replay: device.stats(id).map_or(0, |stats| stats.dropped_replay),
            dropped_allowed_ips: device
                .stats(id)
                .map_or(0, |stats| stats.dropped_allowed_ips),
            reinit_offered: device.stats(id).map_or(0, |stats| stats.reinit_offered),
            last_rejected_source: device
                .stats(id)
                .and_then(|stats| stats.last_rejected_source),
            keepalive: config
                .persistent_keepalive()
                .map(|interval| u16::try_from(interval.as_secs()).unwrap_or(u16::MAX)),
            allowed_ips: config.allowed_ips().nets().to_vec(),
            valid_until: config.validity().map(|window| window.not_after),
            rotating: !config.previous_identities().is_empty(),
            epoch: device.epoch(id).unwrap_or(0),
        });
    }
    let handshake_drops = device.handshake_drops();
    uapi::DeviceState {
        interface: context.interface.clone(),
        private_key: context.private_key.clone(),
        private_key_path: context.private_key_path.display().to_string(),
        public_key: device.public_key().as_bytes().to_vec(),
        public_line: crate::keys::encode_public(device.suite_id(), &device.identity().to_peer()),
        fingerprint: vallum_core::peer_hint(&*context.suite, device.public_key()),
        listen: context.listen,
        carrier: context.carrier,
        control: context
            .control_path
            .as_ref()
            .map(|path| path.display().to_string()),
        fwmark: context.fwmark,
        suite: device.suite_id(),
        addresses: context.addresses.clone(),
        offload: false,
        batching: cfg!(target_os = "linux"),
        capabilities: uapi::Capabilities {
            set_private_key: true,
            set_listen_port: true,
            set_fwmark: true,
        },
        stats: context.stats.snapshot(),
        handshake_dropped_no_mac: handshake_drops.no_mac,
        handshake_dropped_unidentifiable: handshake_drops.unidentifiable,
        handshake_dropped_unknown_peer: handshake_drops.unknown_peer,
        handshake_dropped_endpoint_conflict: handshake_drops.endpoint_conflict,
        handshake_dropped_stale: handshake_drops.stale,
        peers,
    }
}

fn apply(device: &mut Device, context: &mut ControlContext, set: Set) -> Result<(), i32> {
    if let Some(seed) = set.private_key {
        let identity = if device.has_signing() {
            StaticIdentity::generate_with_signing(&*context.suite, &seed)
                .or_else(|_| StaticIdentity::generate(&*context.suite, &seed))
        } else {
            StaticIdentity::generate(&*context.suite, &seed)
        };
        match identity {
            Ok(identity) => {
                device.set_identity(identity);
                // The context carries the seed that `get` reports, and it was
                // never updated: the device got the new identity and the
                // report kept answering with the old seed, so `show --field
                // private-key` handed the operator a key that was not in use.
                context.private_key = SharedSecret::new(seed);
            }
            Err(_) => return Err(EINVAL),
        }
    }
    // A device-level change is a rebind: bind the new socket first, and only
    // swap it in once it exists. A failure leaves the running socket untouched.
    let current_listen = context.listen;
    let current_mark = context.fwmark;
    let desired_port = set.listen_port.unwrap_or(current_listen.port());
    let desired_mark = set.fwmark.unwrap_or(current_mark);
    if desired_port != current_listen.port() || desired_mark != current_mark {
        let address = SocketAddr::new(current_listen.ip(), desired_port);
        match crate::net::bind_with_transport_options(
            context.carrier,
            address,
            desired_mark,
            crate::net::TransportOptions {
                tcp_upgrade: context.tcp_upgrade.as_deref(),
                ss_psk: context.ss_psk.as_deref(),
                tls_sni: context.tls_sni.as_deref(),
            },
        ) {
            Ok(socket) => {
                let bound = socket.local_addr().unwrap_or(address);
                context.socket.replace(socket);
                context.listen = bound;
                context.fwmark = desired_mark;
            }
            Err(error) => return Err(errno_for(&error)),
        }
    }
    let expected_key_len = context.suite.sizes().kem_pk;
    if set.replace_peers {
        // The old set is snapshotted first. The table used to be wiped and
        // then filled, and the FIRST refusal returned - so one bad peer left
        // the daemon with no peers at all, and the reply said "failed" while
        // the tunnel had lost every peer it had.
        let previous: Vec<vallum_tunnel::PeerConfig> =
            device.peers().map(|(_, config)| config.clone()).collect();
        device.remove_all_peers();
        for peer in set.peers {
            if let Err(errno) = apply_peer(device, peer, expected_key_len) {
                // Put the old set back. The sessions are gone - they
                // re-handshake - but the peers are there, which is the
                // difference between a tunnel that recovers and one that has
                // silently lost everybody.
                device.remove_all_peers();
                for config in previous {
                    let _ = device.add_peer(config);
                }
                return Err(errno);
            }
        }
        return Ok(());
    }
    for peer in set.peers {
        apply_peer(device, peer, expected_key_len)?;
    }
    Ok(())
}

fn errno_for(error: &io::Error) -> i32 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => EPERM,
        io::ErrorKind::AddrInUse => EADDRINUSE,
        io::ErrorKind::AddrNotAvailable => EADDRNOTAVAIL,
        _ => EINVAL,
    }
}

fn apply_peer(device: &mut Device, update: uapi::Peer, expected_key_len: usize) -> Result<(), i32> {
    let name = update.name.clone();
    let Some(public_key) = update.public_key else {
        return Err(EINVAL);
    };
    if public_key.len() != expected_key_len {
        return Err(EINVAL);
    }
    // The row this update addresses. A rotation names the key it replaces and
    // the row still answers to it while the window is open — the block's own
    // key is the peer's *new* identity, which no row carries yet. An empty
    // previous (`peer finalize`) is keyed by the current key, exactly like an
    // ordinary update, so the fallback covers that case too.
    if let Some(previous) = &update.previous_public_key {
        if !previous.is_empty() && previous.len() != expected_key_len {
            return Err(EINVAL);
        }
    }
    let existing = match update.previous_public_key.as_deref() {
        Some(previous) if !previous.is_empty() => device
            .peer_by_kem(previous)
            .or_else(|| device.peer_by_kem(&public_key)),
        _ => device.peer_by_kem(&public_key),
    };
    if update.remove {
        if let Some(id) = existing {
            device.remove_peer(id);
        }
        return Ok(());
    }

    let id = match existing {
        Some(id) => id,
        None if update.update_only => return Err(ENOENT),
        None => {
            let identity = PeerIdentity::kem_only(KemPublicKey::new(public_key.to_vec()));
            // A rotated config can reach a daemon that never saw the row — a
            // restart while the window was open. The row comes up already
            // carrying the window, so the replaced identity is accepted from
            // the first packet.
            let window = update
                .previous_public_key
                .as_ref()
                .filter(|key| !key.is_empty())
                .map(|key| PeerIdentity::kem_only(KemPublicKey::new(key.to_vec())));
            let generated = format!(
                "peer-{}",
                crate::keys::hex_encode(
                    public_key
                        .iter()
                        .take(4)
                        .copied()
                        .collect::<Vec<_>>()
                        .as_slice()
                )
            );
            let name = name.unwrap_or(generated);
            let mut config = PeerConfig::new(name, identity);
            if let Some(previous) = window {
                config = config.with_previous_identity(previous, None);
            }
            device.add_peer(config).map_err(|_| EEXIST)?
        }
    };

    // Install the rotation on the row: the block's identity becomes current,
    // the named one stays accepted — or the window is retired, for `finalize`.
    // Both are no-ops when the daemon already runs that state, so a re-sent
    // syncconf changes nothing.
    if let Some(previous) = &update.previous_public_key {
        if previous.is_empty() {
            device.finalize_identity(id);
        } else {
            let new = PeerIdentity::kem_only(KemPublicKey::new(public_key.to_vec()));
            device.rotate_identity(id, new);
        }
    }

    if let Some(name) = update.name {
        device.set_name(id, name);
    }
    if let Some(endpoint) = update.endpoint {
        device.set_endpoint(id, endpoint);
    }
    if let Some(keepalive) = update.keepalive {
        device.set_keepalive(
            id,
            (keepalive > 0).then(|| Duration::from_secs(u64::from(keepalive))),
        );
    }
    if let Some(psk) = update.preshared_key {
        device.set_preshared_key(id, psk.map(SharedSecret::new));
    }
    if update.replace_allowed_ips {
        device
            .set_allowed_ips(id, update.allowed_ips)
            .map_err(|_| EINVAL)?;
    } else if !update.allowed_ips.is_empty() {
        device
            .add_allowed_ips(id, update.allowed_ips)
            .map_err(|_| EINVAL)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use vallum_tunnel::Randomness;

    struct ZeroRng;
    impl Randomness for ZeroRng {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(0);
        }
    }

    fn context(suite: Arc<dyn CryptoSuite>) -> ControlContext {
        let socket = Arc::new(
            crate::net::UdpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("bind"),
        );
        let listen = crate::net::DatagramSocket::local_addr(&*socket).expect("local addr");
        ControlContext {
            interface: "vallum0".to_owned(),
            addresses: Vec::new(),
            private_key: SharedSecret::new([9u8; 32]),
            private_key_path: PathBuf::from("test.key"),
            control_path: None,
            listen,
            carrier: crate::config::Carrier::Udp,
            tcp_upgrade: None,
            ss_psk: None,
            tls_sni: None,
            fwmark: 0,
            socket: Arc::new(crate::net::SharedSocket::new(socket)),
            suite,
            clock: Arc::new(crate::clock::SystemClock::new()),
            stats: Arc::new(crate::run::SharedStats::default()),
        }
    }

    #[test]
    fn a_set_adds_a_peer_and_get_reports_it() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x01; 32]).expect("identity");
        let peer = StaticIdentity::generate(&*suite, &[0x02; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite);

        let body = format!(
            "set=1\npublic_key={}\nallowed_ip=10.7.0.2/32\n",
            crate::keys::hex_encode(peer.public().as_bytes())
        );
        let request = uapi::parse(&body).expect("a legal set");
        assert!(handle(&mut device, &mut context, request, true).contains("errno=0"));

        let reply = handle(&mut device, &mut context, Request::Get, true);
        assert!(reply.contains("allowed_ip=10.7.0.2/32"));
        assert!(reply.contains("vallum_epoch=0"));
    }

    #[test]
    fn a_refused_peer_does_not_take_the_others_with_it() {
        // The bug: `replace_peers` wiped the table and then filled it, and
        // the first refusal returned - so one bad peer left the daemon with
        // NO peers, while the reply said the set had failed.
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x01; 32]).expect("identity");
        let peer = StaticIdentity::generate(&*suite, &[0x02; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite);

        // One good peer.
        let body = format!(
            "set=1\npublic_key={}\nallowed_ip=10.7.0.2/32\n",
            crate::keys::hex_encode(peer.public().as_bytes())
        );
        let request = uapi::parse(&body).expect("a legal set");
        assert!(handle(&mut device, &mut context, request, true).contains("errno=0"));

        // Now replace the set with one peer whose key is the wrong length.
        // It parses - the length is the device's business - and the device
        // refuses it.
        let body =
            "set=1\nreplace_peers=true\npublic_key=00112233445566778899\nallowed_ip=10.7.0.3/32\n";
        let request = uapi::parse(body).expect("the request parses");
        let reply = handle(&mut device, &mut context, request, true);
        assert!(
            !reply.contains("errno=0"),
            "the bad peer must be refused: {reply}"
        );

        // The peer that was there is still there.
        let reply = handle(&mut device, &mut context, Request::Get, true);
        assert!(
            reply.contains("allowed_ip=10.7.0.2/32"),
            "a refused peer must not take the others with it: {reply}"
        );
    }

    #[test]
    fn the_group_console_reads_without_secrets_and_cannot_write() {
        // ADR-0048's read role made real: a `vallum`-group member connects but
        // is not the socket owner — `get` answers the snapshot with keys
        // elided, `set` and `stop` are refused rather than answered.
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x01; 32]).expect("identity");
        let peer = StaticIdentity::generate(&*suite, &[0x02; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite);

        let body = format!(
            "set=1\npublic_key={}\npreshared_key={}\nallowed_ip=10.7.0.2/32\n",
            crate::keys::hex_encode(peer.public().as_bytes()),
            "ab".repeat(32)
        );
        let request = uapi::parse(&body).expect("a legal set");
        assert!(handle(&mut device, &mut context, request, true).contains("errno=0"));

        // Unprivileged get: the snapshot answers, the secrets do not.
        let reply = handle(&mut device, &mut context, Request::Get, false);
        assert!(reply.contains("private_key=(redacted)"), "{reply}");
        assert!(reply.contains("preshared_key=(redacted)"), "{reply}");
        assert!(
            !reply.contains(&"ab".repeat(32)),
            "the PSK must not leak: {reply}"
        );
        assert!(
            reply.contains("allowed_ip=10.7.0.2/32"),
            "the rest of the snapshot stays: {reply}"
        );

        // Mutations are refused at the handler too — the accept loop is not
        // the only place that must say no.
        let request = uapi::parse(&body).expect("a legal set");
        let reply = handle(&mut device, &mut context, request, false);
        assert!(
            reply.contains("errno=1"),
            "unprivileged set must be EPERM: {reply}"
        );
    }

    #[test]
    fn peer_credentials_mark_the_owner_privileged() {
        // UnixStream::pair carries this process's own uid — the same check a
        // `vallum` member fails and the owner passes.
        let (_a, b) = UnixStream::pair().expect("a socket pair");
        assert!(peer_is_privileged(&b));
    }

    #[test]
    fn a_runtime_key_change_is_reported_as_the_key_in_use() {
        // The bug: the device got the new identity and the context kept the
        // old seed, so `get` answered with a key that was not in use.
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x01; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite);

        let body = format!(
            "set=1\nprivate_key={}\n",
            crate::keys::hex_encode(&[0x07; 32])
        );
        let request = uapi::parse(&body).expect("a legal set");
        assert!(handle(&mut device, &mut context, request, true).contains("errno=0"));

        let reply = handle(&mut device, &mut context, Request::Get, true);
        assert!(
            reply.contains(&crate::keys::hex_encode(&[0x07; 32])),
            "the reported key must be the key in use: {reply}"
        );
        assert!(
            !reply.contains(&crate::keys::hex_encode(&[9u8; 32])),
            "the old seed must not still be reported: {reply}"
        );
    }

    #[test]
    fn a_remove_marks_the_peer_gone() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x03; 32]).expect("identity");
        let peer = StaticIdentity::generate(&*suite, &[0x04; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite);
        let key = crate::keys::hex_encode(peer.public().as_bytes());

        let add = uapi::parse(&format!(
            "set=1\npublic_key={key}\nallowed_ip=10.7.0.2/32\n"
        ))
        .expect("a legal set");
        assert!(handle(&mut device, &mut context, add, true).contains("errno=0"));
        let remove =
            uapi::parse(&format!("set=1\npublic_key={key}\nremove=true\n")).expect("a legal set");
        assert!(handle(&mut device, &mut context, remove, true).contains("errno=0"));
        let reply = handle(&mut device, &mut context, Request::Get, true);
        assert!(!reply.contains(&format!("public_key={key}")));
    }

    #[test]
    fn a_listen_port_change_rebinds_the_socket() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x07; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite);
        let before = context.socket.generation();

        let request = uapi::parse("set=1\nlisten_port=0\n").expect("a legal set");
        assert!(handle(&mut device, &mut context, request, true).contains("errno=0"));
        assert!(context.socket.generation() > before);
        assert_ne!(context.listen.port(), 0);
    }

    #[test]
    fn an_update_only_peer_that_is_absent_is_enoent() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x05; 32]).expect("identity");
        let peer = StaticIdentity::generate(&*suite, &[0x06; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite);
        let body = format!(
            "set=1\npublic_key={}\nupdate_only=true\n",
            crate::keys::hex_encode(peer.public().as_bytes())
        );
        let request = uapi::parse(&body).expect("a legal set");
        assert!(handle(&mut device, &mut context, request, true).contains("errno=2"));
    }

    /// A rotation update names both keys and lives on the row it names.
    ///
    /// The identity swap is the whole point: the block's key becomes current,
    /// the replaced one stays accepted inside the window, and the set replays
    /// like an ordinary syncconf — no remove-then-add, no replacement row.
    #[test]
    fn a_rotation_apply_swaps_the_identity_and_opens_a_window() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x11; 32]).expect("identity");
        let old = StaticIdentity::generate(&*suite, &[0x12; 32]).expect("identity");
        let new = StaticIdentity::generate(&*suite, &[0x13; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite.clone());
        let old_key = crate::keys::hex_encode(old.public().as_bytes());
        let new_key = crate::keys::hex_encode(new.public().as_bytes());

        let add = uapi::parse(&format!(
            "set=1\npublic_key={old_key}\nvallum_name=laptop\nallowed_ip=10.7.0.2/32\n"
        ))
        .expect("a legal set");
        assert!(handle(&mut device, &mut context, add, true).contains("errno=0"));

        let rotate = uapi::parse(&format!(
            "set=1\npublic_key={new_key}\nvallum_previous_public_key={old_key}\
             \nvallum_name=laptop\nupdate_only=true\n"
        ))
        .expect("a legal rotation");
        assert!(handle(&mut device, &mut context, rotate, true).contains("errno=0"));

        let reply = handle(&mut device, &mut context, Request::Get, true);
        // The row is keyed by the new key now, and the window reports the old.
        assert!(reply.contains(&format!("public_key={new_key}")), "{reply}");
        assert!(
            reply.contains(&format!(
                "{}={old_key}",
                uapi::field::VALLUM_PREVIOUS_PUBLIC_KEY
            )),
            "{reply}"
        );
        // The old identity is still accepted, so in-flight traffic survives.
        assert!(device.peer_by_kem(old.public().as_bytes()).is_some());
        // One row, not a replacement pair.
        let reply = uapi::parse_response(&reply);
        assert_eq!(reply.peers.len(), 1);
        assert_eq!(
            reply.peer_field(0, uapi::field::VALLUM_NAME),
            Some("laptop")
        );
    }

    /// Replaying the same syncconf must not re-open or re-wind anything: a
    /// rotation sent twice installs once, and the row keeps one window.
    #[test]
    fn re_applying_a_rotation_leaves_the_row_unchanged() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x14; 32]).expect("identity");
        let old = StaticIdentity::generate(&*suite, &[0x15; 32]).expect("identity");
        let new = StaticIdentity::generate(&*suite, &[0x16; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite.clone());
        let old_key = crate::keys::hex_encode(old.public().as_bytes());
        let new_key = crate::keys::hex_encode(new.public().as_bytes());

        let add = uapi::parse(&format!(
            "set=1\npublic_key={old_key}\nvallum_name=laptop\n"
        ))
        .expect("a legal set");
        assert!(handle(&mut device, &mut context, add, true).contains("errno=0"));
        let rotate = uapi::parse(&format!(
            "set=1\npublic_key={new_key}\nvallum_previous_public_key={old_key}\
             \nvallum_name=laptop\nupdate_only=true\n"
        ))
        .expect("a legal rotation");
        assert!(handle(&mut device, &mut context, rotate.clone(), true).contains("errno=0"));
        let before = uapi::parse_response(&handle(&mut device, &mut context, Request::Get, true));

        assert!(handle(&mut device, &mut context, rotate, true).contains("errno=0"));
        let after = uapi::parse_response(&handle(&mut device, &mut context, Request::Get, true));
        assert_eq!(
            before, after,
            "a replayed rotation changed the running state"
        );
        // Still one row, still accepting the replaced identity.
        assert_eq!(after.peers.len(), 1);
        assert!(device.peer_by_kem(old.public().as_bytes()).is_some());
    }

    /// `vallum_previous_public_key=(none)` retires the window: afterwards the
    /// replaced identity stops answering and the row is a plain single-key
    /// peer again.
    #[test]
    fn a_finalize_apply_closes_the_window() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x17; 32]).expect("identity");
        let old = StaticIdentity::generate(&*suite, &[0x18; 32]).expect("identity");
        let new = StaticIdentity::generate(&*suite, &[0x19; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite.clone());
        let old_key = crate::keys::hex_encode(old.public().as_bytes());
        let new_key = crate::keys::hex_encode(new.public().as_bytes());

        let add = uapi::parse(&format!(
            "set=1\npublic_key={old_key}\nvallum_name=laptop\n"
        ))
        .expect("a legal set");
        assert!(handle(&mut device, &mut context, add, true).contains("errno=0"));
        let rotate = uapi::parse(&format!(
            "set=1\npublic_key={new_key}\nvallum_previous_public_key={old_key}\
             \nvallum_name=laptop\nupdate_only=true\n"
        ))
        .expect("a legal rotation");
        assert!(handle(&mut device, &mut context, rotate, true).contains("errno=0"));

        let finalize = uapi::parse(&format!(
            "set=1\npublic_key={new_key}\nvallum_previous_public_key=(none)\
             \nupdate_only=true\n"
        ))
        .expect("a legal finalize");
        assert!(handle(&mut device, &mut context, finalize, true).contains("errno=0"));

        assert!(!device.peer_by_kem(old.public().as_bytes()).is_some());
        let reply = uapi::parse_response(&handle(&mut device, &mut context, Request::Get, true));
        assert_eq!(
            reply.peer_field(0, uapi::field::VALLUM_PREVIOUS_PUBLIC_KEY),
            Some("(none)")
        );
    }

    /// A rotation update arriving at a daemon that never saw the row — a
    /// restart while the window was open — adds the row already carrying the
    /// window, instead of failing `update_only` or building a peerless window.
    #[test]
    fn a_rotation_update_can_arrive_at_a_cold_daemon() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x1a; 32]).expect("identity");
        let old = StaticIdentity::generate(&*suite, &[0x1b; 32]).expect("identity");
        let new = StaticIdentity::generate(&*suite, &[0x1c; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let mut context = context(suite);
        let old_key = crate::keys::hex_encode(old.public().as_bytes());
        let new_key = crate::keys::hex_encode(new.public().as_bytes());

        let rotate = uapi::parse(&format!(
            "set=1\npublic_key={new_key}\nvallum_previous_public_key={old_key}\
             \nvallum_name=laptop\n"
        ))
        .expect("a legal rotation on an empty daemon");
        assert!(handle(&mut device, &mut context, rotate, true).contains("errno=0"));

        assert!(device.peer_by_kem(new.public().as_bytes()).is_some());
        assert!(device.peer_by_kem(old.public().as_bytes()).is_some());
        let reply = handle(&mut device, &mut context, Request::Get, true);
        assert!(reply.contains(&format!("public_key={new_key}")), "{reply}");
        assert!(
            reply.contains(&format!(
                "{}={old_key}",
                uapi::field::VALLUM_PREVIOUS_PUBLIC_KEY
            )),
            "{reply}"
        );
    }

    /// A socket that accepts and then says nothing must not hang the caller.
    ///
    /// This is the failure that made `VallumDown` unable to fire: the exporter
    /// hung instead of returning, so node_exporter kept serving the previous
    /// `up 1` and the one alert covering the control plane could never trigger.
    /// The bound is what lets the "did not answer" path run at all.
    #[test]
    fn a_socket_that_never_answers_is_given_up_on() {
        let dir = std::env::temp_dir().join(format!("vallum-ctl-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("silent.sock");
        let _ = fs::remove_file(&path);

        let listener = UnixListener::bind(&path).expect("bind");
        // Accept, then hold the connection open without ever replying. Detached
        // on purpose: joining it would make this test wait out the hold.
        let _silent_server = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                thread::sleep(REPLY_TIMEOUT + Duration::from_secs(2));
                drop(stream);
            }
        });

        let started = std::time::Instant::now();
        let result = request(&path, "get=1\n");
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "a silent socket must not be read as a successful reply"
        );
        assert!(
            elapsed < REPLY_TIMEOUT + Duration::from_secs(5),
            "gave up after {elapsed:?}; the caller was not bounded"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    /// A live daemon's socket must not be unlinked by a second daemon that
    /// happens to use the same `control` path.
    #[test]
    fn a_live_control_socket_is_not_stolen() {
        let dir = std::env::temp_dir().join(format!("vallum-claim-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("live.sock");
        let _ = fs::remove_file(&path);

        let listener = UnixListener::bind(&path).expect("bind");
        let error = claim_path(&path).expect_err("a live socket must not be claimed");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);

        // A crashed daemon leaves the inode behind with nobody listening. That
        // one must stay reclaimable, or a restart could never recover.
        drop(listener);
        claim_path(&path).expect("a stale socket may be claimed");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    /// `stop=1` is acknowledged, and it stops the tunnel.
    ///
    /// The ordering is the claim: a daemon that stopped first and answered after
    /// would leave the client holding a closed socket, which is
    /// indistinguishable from asking a daemon that had already died.
    #[test]
    fn a_stop_is_acknowledged_before_the_tunnel_stops() {
        let dir = std::env::temp_dir().join(format!("vallum-stop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ctl.sock");

        // Nothing answers on the channel: a stop must not need the loop.
        let (tx, _rx) = mpsc::sync_channel(8);
        let shutdown = Shutdown::new();
        let tunnel = Shutdown::new();
        let handle = serve(path.clone(), tx, shutdown.clone(), tunnel.clone()).expect("serve");

        let reply = request(&path, "stop=1\n").expect("a stop is answered");
        assert!(reply.contains("errno=0"), "got {reply:?}");
        // The ack is written before the trigger by design, so the trigger may
        // land a moment later; asserting instantly raced the control thread
        // and failed under parallel test load.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !tunnel.is_triggered() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            tunnel.is_triggered(),
            "the stop was acknowledged but not acted on within 2 s"
        );

        // The control thread stops with the tunnel, so this returns.
        let _ = handle.join();
        let _ = fs::remove_dir_all(&dir);
    }

    /// A client that drips one byte at a time must not hold the plane.
    ///
    /// A per-read timeout is not a deadline: each byte resets it, so the first
    /// attempt at this bound (read timeout only) was still bypassable. The whole
    /// request has to be bounded, which is what this pins.
    #[test]
    fn a_dripping_client_does_not_hold_the_plane() {
        let dir = std::env::temp_dir().join(format!("vallum-drip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ctl.sock");

        let (tx, rx) = mpsc::sync_channel(8);
        let shutdown = Shutdown::new();
        // Answer every request, so the server never waits on this test.
        let responder = thread::spawn(move || {
            while let Ok(Input::Control { reply, .. }) = rx.recv() {
                if reply.send(uapi::render_ok()).is_err() {
                    break;
                }
            }
        });
        let handle = serve(path.clone(), tx, shutdown.clone(), Shutdown::new()).expect("serve");

        // One byte every two seconds: always under the five-second read timeout.
        let drip = {
            let path = path.clone();
            thread::spawn(move || {
                if let Ok(mut stream) = UnixStream::connect(&path) {
                    for _ in 0..3 {
                        if stream.write_all(b"g").is_err() {
                            break;
                        }
                        thread::sleep(Duration::from_secs(2));
                    }
                }
            })
        };
        thread::sleep(Duration::from_millis(200));

        // A second client must be answered inside the drip's lifetime.
        let started = Instant::now();
        let reply = request(&path, "get=1\n").expect("the plane must answer");
        let waited = started.elapsed();
        assert!(reply.contains("errno=0"), "got {reply:?}");
        assert!(
            waited < Duration::from_secs(9),
            "the drip held the plane for {waited:?}"
        );

        shutdown.trigger();
        // The accept loop only sees the flag after a connection, so unblock it.
        let _ = UnixStream::connect(&path);
        let _ = drip.join();
        let _ = handle.join();
        let _ = responder.join();
        let _ = fs::remove_dir_all(&dir);
    }

    /// The bind-time inode is private before it has a published name: created
    /// `0600` inside a `0700` directory that no other user can traverse.
    ///
    /// This is the property a chmod after `bind` cannot offer — between the two
    /// calls the socket is reachable at its configured path under `0777 & ~umask`.
    #[test]
    fn the_staged_socket_is_unreachable_and_already_private() {
        let dir = std::env::temp_dir().join(format!("vallum-stage-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let staging = dir.join("stage");

        let (_listener, staged) = stage_socket(&staging).expect("stage");
        let dir_mode = fs::metadata(&staging)
            .expect("staging metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "the staging directory is {dir_mode:o}");
        let socket_mode = fs::metadata(&staged)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            socket_mode, 0o600,
            "the staged socket is {socket_mode:o}, not the umask's 0777"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #35 (ADR-0048): the widening decision is fail-closed — no control group
    /// never widens; root or a daemon in the control group widens; an unrelated
    /// login user does not. Pure, so it needs neither root nor a real group.
    #[test]
    fn control_widening_is_fail_closed_and_group_scoped() {
        assert!(!control_widening_applies(true, 0, None));
        assert!(!control_widening_applies(false, 1000, None));
        assert!(control_widening_applies(true, 0, Some(986)));
        assert!(control_widening_applies(false, 986, Some(986)));
        assert!(!control_widening_applies(false, 1000, Some(986)));
    }

    /// The published socket carries `0600` from its first appearance, the owner
    /// still reaches it, and the staging directory does not outlive the bind.
    #[test]
    fn a_published_socket_is_private_and_leaves_no_staging_behind() {
        let dir = std::env::temp_dir().join(format!("vallum-publish-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ctl.sock");

        let listener = bind_private(&path).expect("bind");
        let mode = fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the published socket is {mode:o}");
        UnixStream::connect(&path).expect("the owner can connect");

        let entries: Vec<_> = fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(entries.len(), 1, "staging left behind: {entries:?}");

        drop(listener);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Publishing must not replace a path that is already occupied: the
    /// reservation refuses it the way `bind` would, so a daemon that raced in
    /// keeps its socket instead of being silently orphaned by a rename.
    #[test]
    fn publishing_refuses_an_occupied_path() {
        let dir = std::env::temp_dir().join(format!("vallum-occupied-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ctl.sock");

        let live = UnixListener::bind(&path).expect("the first daemon binds");
        let error = bind_private(&path).expect_err("an occupied path must be refused");
        assert_eq!(
            error.kind(),
            io::ErrorKind::AlreadyExists,
            "the refusal is {error:?}"
        );
        // The original listener is untouched and still answers.
        UnixStream::connect(&path).expect("the first daemon's socket survives");

        drop(live);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A watcher that samples `path` and counts every state in which the name
    /// exists as something *other* than a socket.
    fn watch_for_a_name_without_a_listener(
        path: &Path,
    ) -> (Arc<AtomicBool>, Arc<AtomicUsize>, JoinHandle<()>) {
        use std::os::unix::fs::FileTypeExt;
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let watcher = {
            let (path, stop, seen) = (path.to_path_buf(), Arc::clone(&stop), Arc::clone(&seen));
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(meta) = fs::symlink_metadata(&path) {
                        if !meta.file_type().is_socket() {
                            seen.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        };
        (stop, seen, watcher)
    }

    /// Nothing may appear at the control path until a listener is behind it.
    ///
    /// This is the property the gate test
    /// `a_removed_control_socket_is_rebound_by_the_daemon` lost a request to.
    /// Reserving the name with a placeholder file — the way publishing first
    /// refused an occupied path — leaves the path existing as a regular file
    /// for two syscalls, and a client that connects the moment it appears is
    /// refused. Linking the bound inode publishes the name already listening,
    /// which is what the connect below requires of every one of these cycles: no
    /// retry, no tolerance for `ECONNREFUSED`.
    #[test]
    fn the_control_name_is_never_published_without_a_listener_behind_it() {
        let dir = std::env::temp_dir().join(format!("vallum-atomic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ctl.sock");

        let (stop, seen, watcher) = watch_for_a_name_without_a_listener(&path);
        for _ in 0..500 {
            let listener = bind_private(&path).expect("bind");
            UnixStream::connect(&path).expect("the name accepts as soon as it exists");
            drop(listener);
            fs::remove_file(&path).expect("unpublish");
        }
        stop.store(true, Ordering::Relaxed);
        watcher.join().expect("watcher");

        assert_eq!(
            seen.load(Ordering::Relaxed),
            0,
            "the path existed as something other than a socket"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The watcher above has to be able to see the state it forbids, or the
    /// assertion in the test above says nothing. A plain file at the path is
    /// exactly the placeholder the reservation wrote, and it is caught at once.
    #[test]
    fn the_watch_notices_a_name_without_a_listener() {
        let dir = std::env::temp_dir().join(format!("vallum-watch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ctl.sock");

        let (stop, seen, watcher) = watch_for_a_name_without_a_listener(&path);
        fs::write(&path, b"a placeholder, not a listener").expect("write");
        let deadline = Instant::now() + Duration::from_secs(2);
        while seen.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        stop.store(true, Ordering::Relaxed);
        watcher.join().expect("watcher");

        assert!(
            seen.load(Ordering::Relaxed) > 0,
            "the watcher missed a name with no listener behind it"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
