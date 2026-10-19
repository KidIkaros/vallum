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

use crate::run::{Input, Shutdown};
use crate::uapi::{self, Request, Set};

/// `EINVAL`: a malformed request or an overlapping prefix.
const EINVAL: i32 = 22;
/// `ENOENT`: `update_only` named a peer that is not configured.
const ENOENT: i32 = 2;
/// `EEXIST`: the peer was already present.
const EEXIST: i32 = 17;
/// `EOPNOTSUPP`: a device-level field that needs a restart.
const EOPNOTSUPP: i32 = 95;
/// `ETIMEDOUT`: the loop did not answer.
const ETIMEDOUT: i32 = 110;

/// What the control plane needs to describe the device.
#[derive(Clone)]
pub struct ControlContext {
    /// The private-key seed, as the daemon holds it.
    pub private_key: [u8; 32],
    /// The kernel interface name.
    pub interface: String,
    /// The interface addresses.
    pub addresses: Vec<vallum_tunnel::Prefix>,
    /// The bound UDP address.
    pub listen: SocketAddr,
    /// The socket mark.
    pub fwmark: u32,
    /// The suite, for a runtime identity change.
    pub suite: Arc<dyn CryptoSuite>,
}

impl fmt::Debug for ControlContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlContext")
            .field("listen", &self.listen)
            .field("fwmark", &self.fwmark)
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A control socket to serve.
#[derive(Debug)]
pub struct ControlServer {
    /// The path to bind.
    pub path: PathBuf,
    /// The context used to answer `get`.
    pub context: ControlContext,
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
    stream.write_all(body.as_bytes()).map_err(io_path)?;
    stream.shutdown(NetShutdown::Write).map_err(io_path)?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).map_err(io_path)?;
    Ok(reply)
}

/// Answer one request against the device.
#[must_use]
pub fn handle(device: &mut Device, context: &ControlContext, request: Request) -> String {
    match request {
        Request::Get => uapi::render_get(&snapshot(device, context)),
        Request::Set(set) => apply(device, context, set),
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
            epoch: device.epoch(id).unwrap_or(0),
        });
    }
    uapi::DeviceState {
        interface: context.interface.clone(),
        private_key: context.private_key,
        public_key: device.public_key().as_bytes().to_vec(),
        public_line: crate::keys::encode_public(device.suite_id(), &device.identity().to_peer()),
        fingerprint: vallum_core::peer_hint(&*context.suite, device.public_key()),
        listen: context.listen,
        fwmark: context.fwmark,
        suite: device.suite_id(),
        addresses: context.addresses.clone(),
        capabilities: uapi::Capabilities {
            set_private_key: true,
            set_listen_port: false,
            set_fwmark: false,
        },
        peers,
    }
}

fn apply(device: &mut Device, context: &ControlContext, set: Set) -> String {
    if let Some(seed) = set.private_key {
        let identity = if device.has_signing() {
            StaticIdentity::generate_with_signing(&*context.suite, &seed)
                .or_else(|_| StaticIdentity::generate(&*context.suite, &seed))
        } else {
            StaticIdentity::generate(&*context.suite, &seed)
        };
        match identity {
            Ok(identity) => device.set_identity(identity),
            Err(_) => return uapi::render_errno(EINVAL),
        }
    }
    // Device-level socket fields need a rebind, which is not in this cut; a
    // change that matches the current value is accepted so a `syncconf` that
    // repeats the config is idempotent.
    if let Some(port) = set.listen_port {
        if port != context.listen.port() {
            return uapi::render_errno(EOPNOTSUPP);
        }
    }
    if let Some(mark) = set.fwmark {
        if mark != context.fwmark {
            return uapi::render_errno(EOPNOTSUPP);
        }
    }
    if set.replace_peers {
        device.remove_all_peers();
    }
    let expected_key_len = context.suite.sizes().kem_pk;
    for peer in set.peers {
        if let Err(errno) = apply_peer(device, peer, expected_key_len) {
            return uapi::render_errno(errno);
        }
    }
    uapi::render_ok()
}

fn apply_peer(device: &mut Device, update: uapi::Peer, expected_key_len: usize) -> Result<(), i32> {
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
            let name = format!(
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
                .add_peer(PeerConfig::new(name, identity))
                .map_err(|_| EEXIST)?
        }
    };

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
        ControlContext {
            interface: "vallum0".to_owned(),
            addresses: Vec::new(),
            private_key: [9u8; 32],
            listen: "0.0.0.0:51820".parse().unwrap(),
            fwmark: 0,
            suite,
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
        let context = context(suite);

        let body = format!(
            "set=1\npublic_key={}\nallowed_ip=10.7.0.2/32\n",
            crate::keys::hex_encode(peer.public().as_bytes())
        );
        let request = uapi::parse(&body).expect("a legal set");
        assert!(handle(&mut device, &context, request).contains("errno=0"));

        let reply = handle(&mut device, &context, Request::Get);
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
        let context = context(suite);
        let key = crate::keys::hex_encode(peer.public().as_bytes());

        let add = uapi::parse(&format!(
            "set=1\npublic_key={key}\nallowed_ip=10.7.0.2/32\n"
        ))
        .expect("a legal set");
        assert!(handle(&mut device, &context, add).contains("errno=0"));
        let remove =
            uapi::parse(&format!("set=1\npublic_key={key}\nremove=true\n")).expect("a legal set");
        assert!(handle(&mut device, &context, remove).contains("errno=0"));
        let reply = handle(&mut device, &context, Request::Get);
        assert!(!reply.contains(&format!("public_key={key}")));
    }

    #[test]
    fn an_update_only_peer_that_is_absent_is_enoent() {
        let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
        let me = StaticIdentity::generate(&*suite, &[0x05; 32]).expect("identity");
        let peer = StaticIdentity::generate(&*suite, &[0x06; 32]).expect("identity");
        let mut rng = ZeroRng;
        let mut device =
            Device::new(Arc::clone(&suite), me, Vec::new(), &mut rng, 0).expect("device");
        let context = context(suite);
        let body = format!(
            "set=1\npublic_key={}\nupdate_only=true\n",
            crate::keys::hex_encode(peer.public().as_bytes())
        );
        let request = uapi::parse(&body).expect("a legal set");
        assert!(handle(&mut device, &context, request).contains("errno=2"));
    }
}
