// SPDX-License-Identifier: Apache-2.0

//! The control socket: a Unix listener that speaks [`crate::uapi`].
//!
//! The socket is `0600` and same-user only; it is the same trust boundary as
//! the private-key file. A request is parsed here, forwarded to the loop thread
//! as an [`Input`](crate::run::Input), and answered there — all mutation happens
//! on the thread that owns the device, never concurrently with a packet.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown as NetShutdown;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use vallum_core::identity::{PeerIdentity, StaticIdentity};
use vallum_crypto::KemPublicKey;
use vallum_crypto::{CryptoSuite, SharedSecret};
use vallum_tunnel::{Device, PeerConfig};

use crate::net::DatagramSocket;
use crate::run::{Input, Shutdown};
use crate::uapi::errno::{EADDRINUSE, EADDRNOTAVAIL, EEXIST, EINVAL, ENOENT, EPERM, ETIMEDOUT};
use crate::uapi::{self, Request, Set};

/// How long a client may take to send its request before the connection is
/// dropped.
///
/// The accept loop is serial — one connection at a time, so that every mutation
/// happens on the thread that owns the device. That invariant is sound, but it
/// means an unbounded read is an unbounded outage: a client that connects and
/// then says nothing holds the whole plane.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// The kernel interface name.
    pub interface: String,
    /// The interface addresses.
    pub addresses: Vec<vallum_tunnel::Prefix>,
    /// The bound UDP address.
    pub listen: SocketAddr,
    /// The socket mark.
    pub fwmark: u32,
    /// The swappable socket, for a runtime rebind.
    pub socket: Arc<crate::net::SharedSocket>,
    /// The suite, for a runtime identity change.
    pub suite: Arc<dyn CryptoSuite>,
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

/// Bind the socket and serve requests until shutdown.
///
/// # Errors
///
/// If the path cannot be created, bound, or chmodded.
pub(crate) fn serve(
    path: PathBuf,
    tx: mpsc::SyncSender<Input>,
    shutdown: Shutdown,
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
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(&path)?;
    // The socket is the same trust boundary as the private-key file: same user
    // only. A world-writable control socket would be a remote `set`.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

    thread::Builder::new()
        .name("vallum-control".to_owned())
        .spawn(move || {
            for stream in listener.incoming() {
                if shutdown.is_triggered() {
                    break;
                }
                let Ok(mut stream) = stream else {
                    continue;
                };
                // Bound the request read. Without this a client that connects and
                // sends nothing — a paused debugger, a `tui` that died mid-request
                // — holds the serial loop forever and every other command hangs.
                if stream.set_read_timeout(Some(REQUEST_TIMEOUT)).is_err() {
                    continue;
                }
                let mut text = String::new();
                // The client writes the request and shuts its write half; the
                // read ends at EOF.
                let _ = stream.read_to_string(&mut text);
                let reply = match uapi::parse(&text) {
                    Ok(request) => {
                        let (reply_tx, reply_rx) = mpsc::channel();
                        if tx
                            .send(Input::Control {
                                request,
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
            }
            let _ = fs::remove_file(&path);
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

/// Answer one request against the device.
#[must_use]
pub fn handle(device: &mut Device, context: &mut ControlContext, request: Request) -> String {
    match request {
        Request::Get => uapi::render_get(&snapshot(device, context)),
        Request::Set(set) => match apply(device, context, set) {
            Ok(()) => uapi::render_ok(),
            Err(errno) => uapi::render_errno(errno),
        },
    }
}

fn snapshot(device: &Device, context: &ControlContext) -> uapi::DeviceState {
    let mut peers = Vec::new();
    for (id, config) in device.peers() {
        let (tx_bytes, rx_bytes, last_handshake) = match device.stats(id) {
            Some(stats) => (stats.tx_bytes, stats.rx_bytes, stats.last_handshake),
            None => (0, 0, None),
        };
        peers.push(uapi::PeerState {
            name: config.name().to_owned(),
            public_key: config.identity().kem().as_bytes().to_vec(),
            public_line: crate::keys::encode_public(device.suite_id(), config.identity()),
            fingerprint: device.fingerprint(id).unwrap_or([0u8; 8]),
            preshared_key: config.preshared_key().map(|psk| *psk.as_bytes()),
            endpoint: device.endpoint(id),
            last_handshake: last_handshake.map(|stamp| (stamp.unix_seconds(), stamp.nanos())),
            tx_bytes,
            rx_bytes,
            keepalive: config
                .persistent_keepalive()
                .map(|interval| u16::try_from(interval.as_secs()).unwrap_or(u16::MAX)),
            allowed_ips: config.allowed_ips().nets().to_vec(),
            valid_until: config.validity().map(|window| window.not_after),
            rotating: !config.previous_identities().is_empty(),
            epoch: device.epoch(id).unwrap_or(0),
        });
    }
    uapi::DeviceState {
        interface: context.interface.clone(),
        private_key: context.private_key.clone(),
        private_key_path: context.private_key_path.display().to_string(),
        public_key: device.public_key().as_bytes().to_vec(),
        public_line: crate::keys::encode_public(device.suite_id(), &device.identity().to_peer()),
        fingerprint: vallum_core::peer_hint(&*context.suite, device.public_key()),
        listen: context.listen,
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
            Ok(identity) => device.set_identity(identity),
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
        match crate::net::UdpTransport::bind_with_fwmark(address, desired_mark) {
            Ok(socket) => {
                let bound = socket.local_addr().unwrap_or(address);
                context.socket.replace(Arc::new(socket));
                context.listen = bound;
                context.fwmark = desired_mark;
            }
            Err(error) => return Err(errno_for(&error)),
        }
    }
    if set.replace_peers {
        device.remove_all_peers();
    }
    let expected_key_len = context.suite.sizes().kem_pk;
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
    let existing = device.peer_by_kem(&public_key);
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
            device
                .add_peer(PeerConfig::new(name.unwrap_or(generated), identity))
                .map_err(|_| EEXIST)?
        }
    };

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
        let listen = socket.local_addr().expect("local addr");
        ControlContext {
            interface: "vallum0".to_owned(),
            addresses: Vec::new(),
            private_key: SharedSecret::new([9u8; 32]),
            private_key_path: PathBuf::from("test.key"),
            listen,
            fwmark: 0,
            socket: Arc::new(crate::net::SharedSocket::new(socket)),
            suite,
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
        assert!(handle(&mut device, &mut context, request).contains("errno=0"));

        let reply = handle(&mut device, &mut context, Request::Get);
        assert!(reply.contains("allowed_ip=10.7.0.2/32"));
        assert!(reply.contains("vallum_epoch=0"));
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
        assert!(handle(&mut device, &mut context, add).contains("errno=0"));
        let remove =
            uapi::parse(&format!("set=1\npublic_key={key}\nremove=true\n")).expect("a legal set");
        assert!(handle(&mut device, &mut context, remove).contains("errno=0"));
        let reply = handle(&mut device, &mut context, Request::Get);
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
        assert!(handle(&mut device, &mut context, request).contains("errno=0"));
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
        assert!(handle(&mut device, &mut context, request).contains("errno=2"));
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
}
