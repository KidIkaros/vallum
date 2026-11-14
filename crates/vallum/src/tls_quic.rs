// SPDX-License-Identifier: Apache-2.0

//! Outer TLS 1.3 (`carrier = "tls"`) and QUIC v1 DATAGRAM (`carrier = "quic"`)
//! transports, implementing [`crate::net::DatagramSocket`].
//!
//! Both carriers wrap Vallum's own post-quantum / Noise-authenticated packets
//! in standard wire protocols without introducing an async runtime or extra
//! syscalls outside the daemon's seccomp allow-list (`poll` + `std::io::pipe`).

use std::collections::{HashMap, VecDeque};
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig as QuicClientCfg, Connection, ConnectionHandle, DatagramEvent, Endpoint,
    EndpointConfig, Event as QuicEvent, ServerConfig as QuicServerCfg, TransportConfig,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme,
};
use vallum_tunnel::stream::{frame, FrameReader};

use crate::net::{bind_udp_socket, dial, listen_socket, wake_addr, DatagramSocket, CARRIER_QUEUE};

const DEFAULT_SNI: &str = "localhost";
const TLS_ALPN: &[&[u8]] = &[b"http/1.1", b"vallum"];
const QUIC_ALPN: &[&[u8]] = &[b"h3", b"vallum"];
const QUIC_PENDING_CAP: usize = 64;

#[derive(Debug)]
struct EphemeralServerVerifier {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl EphemeralServerVerifier {
    fn new() -> Self {
        Self {
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for EphemeralServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Peer identity is cryptographically authenticated inside Vallum's
        // inner Noise/PQ handshake; outer TLS provides DPI mimicry.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn generate_self_signed_cert(
    sni: &str,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certified = rcgen::generate_simple_self_signed(vec![sni.to_owned()])
        .map_err(|e| io::Error::other(format!("self-signed cert generation: {e}")))?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    Ok((vec![cert], key))
}

fn build_tls_configs(
    sni: &str,
    alpn: &[&[u8]],
) -> io::Result<(Arc<ServerConfig>, Arc<ClientConfig>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (certs, key) = generate_self_signed_cert(sni)?;

    let mut server_cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("rustls server versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::other(format!("rustls server cert: {e}")))?;
    server_cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("rustls client versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EphemeralServerVerifier::new()))
        .with_no_client_auth();
    client_cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    Ok((Arc::new(server_cfg), Arc::new(client_cfg)))
}

fn normalize_sni(tls_sni: Option<&str>) -> String {
    tls_sni
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SNI)
        .to_owned()
}

fn server_name_for(sni: &str) -> io::Result<ServerName<'static>> {
    ServerName::try_from(sni.to_owned())
        .or_else(|_| ServerName::try_from(DEFAULT_SNI.to_owned()))
        .map_err(|e| io::Error::other(format!("invalid TLS SNI: {e}")))
}

fn wake_pipe(tx: &Mutex<PipeWriter>) {
    if let Ok(mut guard) = tx.lock() {
        let _ = guard.write(&[1u8]);
    }
}

fn drain_pipe(rx: &mut PipeReader) {
    let mut scratch = [0u8; 64];
    loop {
        match rx.read(&mut scratch) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "linux")]
fn poll_two_fds<Fd1: std::os::fd::AsFd, Fd2: std::os::fd::AsFd>(
    primary: &Fd1,
    primary_out: bool,
    wake_rx: &Fd2,
    timeout: Option<Duration>,
) {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    let mut primary_events = PollFlags::IN;
    if primary_out {
        primary_events |= PollFlags::OUT;
    }
    let mut fds = [
        PollFd::new(primary, primary_events),
        PollFd::new(wake_rx, PollFlags::IN),
    ];
    let ts = timeout.map(|d| Timespec {
        tv_sec: i64::try_from(d.as_secs()).unwrap_or(1),
        tv_nsec: i64::from(d.subsec_nanos()),
    });
    let _ = poll(&mut fds, ts.as_ref());
}

// ── TLS 1.3 Stream Carrier ───────────────────────────────────────────────

struct TlsPeerHandle {
    outbound: mpsc::SyncSender<Vec<u8>>,
    wake: Mutex<PipeWriter>,
    stream: TcpStream,
}

enum TlsConn {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl TlsConn {
    fn wants_write(&self) -> bool {
        match self {
            Self::Server(c) => c.wants_write(),
            Self::Client(c) => c.wants_write(),
        }
    }

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        match self {
            Self::Server(c) => c.read_tls(rd),
            Self::Client(c) => c.read_tls(rd),
        }
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        match self {
            Self::Server(c) => c.write_tls(wr),
            Self::Client(c) => c.write_tls(wr),
        }
    }

    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            Self::Server(c) => c.process_new_packets(),
            Self::Client(c) => c.process_new_packets(),
        }
    }

    fn reader(&mut self) -> rustls::Reader<'_> {
        match self {
            Self::Server(c) => c.reader(),
            Self::Client(c) => c.reader(),
        }
    }

    fn writer(&mut self) -> rustls::Writer<'_> {
        match self {
            Self::Server(c) => c.writer(),
            Self::Client(c) => c.writer(),
        }
    }
}

/// TLS 1.3 carrier over TCP (`carrier = "tls"`).
pub struct TlsTransport {
    local: SocketAddr,
    closed: Arc<AtomicBool>,
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    outbound: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    peers: Arc<Mutex<HashMap<SocketAddr, Arc<TlsPeerHandle>>>>,
    inbound_dropped: Arc<AtomicU64>,
    outbound_dropped: Arc<AtomicU64>,
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport")
            .field("local", &self.local)
            .field("peers", &self.peers.lock().map(|m| m.len()).unwrap_or(0))
            .field(
                "dropped",
                &(self.inbound_dropped.load(Ordering::Relaxed)
                    + self.outbound_dropped.load(Ordering::Relaxed)),
            )
            .finish()
    }
}

impl TlsTransport {
    /// Listen on `address` and dial peers on demand over TLS 1.3.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_with_options(address, 0, None)
    }

    /// Bind with `SO_MARK` and optional TLS SNI hostname.
    pub fn bind_with_options(
        address: SocketAddr,
        fwmark: u32,
        tls_sni: Option<&str>,
    ) -> io::Result<Self> {
        let sni = normalize_sni(tls_sni);
        let (server_cfg, client_cfg) = build_tls_configs(&sni, TLS_ALPN)?;
        let listener = listen_socket(address, fwmark)?;
        let local = listener.local_addr()?;
        let closed = Arc::new(AtomicBool::new(false));
        let peers: Arc<Mutex<HashMap<SocketAddr, Arc<TlsPeerHandle>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let inbound_dropped = Arc::new(AtomicU64::new(0));
        let outbound_dropped = Arc::new(AtomicU64::new(0));

        let (inbound_tx, inbound_rx) = mpsc::sync_channel::<(SocketAddr, Vec<u8>)>(CARRIER_QUEUE);
        let (outbound_tx, outbound_rx) = mpsc::sync_channel::<(SocketAddr, Vec<u8>)>(CARRIER_QUEUE);

        spawn_tls_acceptor(
            listener,
            server_cfg,
            Arc::clone(&closed),
            Arc::clone(&peers),
            inbound_tx.clone(),
            Arc::clone(&inbound_dropped),
            Arc::clone(&outbound_dropped),
        );
        spawn_tls_dispatcher(
            outbound_rx,
            client_cfg,
            sni,
            fwmark,
            Arc::clone(&closed),
            Arc::clone(&peers),
            inbound_tx,
            Arc::clone(&inbound_dropped),
            Arc::clone(&outbound_dropped),
        );

        Ok(Self {
            local,
            closed,
            inbound: Mutex::new(inbound_rx),
            outbound: outbound_tx,
            peers,
            inbound_dropped,
            outbound_dropped,
        })
    }

    /// Close all active TLS streams and unblock the acceptor.
    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(mut map) = self.peers.lock() {
            for handle in map.values() {
                let _ = handle.stream.shutdown(std::net::Shutdown::Both);
                wake_pipe(&handle.wake);
            }
            map.clear();
        }
        let _ = TcpStream::connect_timeout(&wake_addr(self.local), Duration::from_millis(200));
    }
}

impl Drop for TlsTransport {
    fn drop(&mut self) {
        self.close();
    }
}

impl DatagramSocket for TlsTransport {
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        if self
            .outbound
            .try_send((destination, bytes.to_vec()))
            .is_err()
        {
            self.outbound_dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Ok(inbound) = self.inbound.lock() else {
            return Err(io::Error::other("tls inbound queue is poisoned"));
        };
        match inbound.recv_timeout(Duration::from_millis(250)) {
            Ok((source, bytes)) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok((n, source))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(io::Error::new(io::ErrorKind::TimedOut, "no frame waiting"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tls carrier closed",
            )),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

fn spawn_tls_acceptor(
    listener: TcpListener,
    server_cfg: Arc<ServerConfig>,
    closed: Arc<AtomicBool>,
    peers: Arc<Mutex<HashMap<SocketAddr, Arc<TlsPeerHandle>>>>,
    inbound_tx: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    inbound_dropped: Arc<AtomicU64>,
    outbound_dropped: Arc<AtomicU64>,
) {
    let _ = thread::Builder::new()
        .name("vallum-tls-accept".to_owned())
        .spawn(move || loop {
            match listener.accept() {
                Ok((stream, remote)) => {
                    if closed.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(conn) = ServerConnection::new(Arc::clone(&server_cfg)) else {
                        continue;
                    };
                    register_tls_peer(
                        stream,
                        remote,
                        TlsConn::Server(conn),
                        &peers,
                        &inbound_tx,
                        &inbound_dropped,
                        &outbound_dropped,
                        &closed,
                    );
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) if closed.load(Ordering::Relaxed) => break,
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        });
}

#[allow(clippy::too_many_arguments)]
fn spawn_tls_dispatcher(
    outbound_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    client_cfg: Arc<ClientConfig>,
    sni: String,
    fwmark: u32,
    closed: Arc<AtomicBool>,
    peers: Arc<Mutex<HashMap<SocketAddr, Arc<TlsPeerHandle>>>>,
    inbound_tx: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    inbound_dropped: Arc<AtomicU64>,
    outbound_dropped: Arc<AtomicU64>,
) {
    let _ = thread::Builder::new()
        .name("vallum-tls-dispatch".to_owned())
        .spawn(move || {
            while let Ok((destination, bytes)) = outbound_rx.recv() {
                if closed.load(Ordering::Relaxed) {
                    break;
                }
                let handle = {
                    let existing = peers
                        .lock()
                        .ok()
                        .and_then(|map| map.get(&destination).map(Arc::clone));
                    if let Some(h) = existing {
                        Some(h)
                    } else {
                        let Ok(stream) = dial(destination, fwmark) else {
                            outbound_dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let Ok(server_name) = server_name_for(&sni) else {
                            outbound_dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let Ok(conn) = ClientConnection::new(Arc::clone(&client_cfg), server_name)
                        else {
                            outbound_dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        register_tls_peer(
                            stream,
                            destination,
                            TlsConn::Client(conn),
                            &peers,
                            &inbound_tx,
                            &inbound_dropped,
                            &outbound_dropped,
                            &closed,
                        )
                    }
                };
                if let Some(h) = handle {
                    if h.outbound.try_send(bytes).is_err() {
                        outbound_dropped.fetch_add(1, Ordering::Relaxed);
                    } else {
                        wake_pipe(&h.wake);
                    }
                } else {
                    outbound_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
}

#[allow(clippy::too_many_arguments)]
fn register_tls_peer(
    stream: TcpStream,
    remote: SocketAddr,
    conn: TlsConn,
    peers: &Arc<Mutex<HashMap<SocketAddr, Arc<TlsPeerHandle>>>>,
    inbound_tx: &mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    inbound_dropped: &Arc<AtomicU64>,
    outbound_dropped: &Arc<AtomicU64>,
    closed: &Arc<AtomicBool>,
) -> Option<Arc<TlsPeerHandle>> {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_nonblocking(true);
    let (wake_rx, wake_tx) = std::io::pipe().ok()?;
    #[cfg(target_os = "linux")]
    let _ = set_pipe_nonblocking(&wake_rx);
    let stream_clone = stream.try_clone().ok()?;
    let (peer_out_tx, peer_out_rx) = mpsc::sync_channel::<Vec<u8>>(CARRIER_QUEUE);

    let handle = Arc::new(TlsPeerHandle {
        outbound: peer_out_tx,
        wake: Mutex::new(wake_tx),
        stream: stream_clone,
    });
    if let Ok(mut map) = peers.lock() {
        map.insert(remote, Arc::clone(&handle));
    }

    let peers_weak = Arc::clone(peers);
    let handle_ref = Arc::clone(&handle);
    let inbound_tx = inbound_tx.clone();
    let inbound_dropped = Arc::clone(inbound_dropped);
    let outbound_dropped = Arc::clone(outbound_dropped);
    let closed = Arc::clone(closed);

    let _ = thread::Builder::new()
        .name("vallum-tls-peer".to_owned())
        .spawn(move || {
            run_tls_peer_loop(
                stream,
                remote,
                conn,
                peer_out_rx,
                wake_rx,
                inbound_tx,
                inbound_dropped,
                outbound_dropped,
                closed,
            );
            if let Ok(mut map) = peers_weak.lock() {
                if map
                    .get(&remote)
                    .is_some_and(|current| Arc::ptr_eq(current, &handle_ref))
                {
                    map.remove(&remote);
                }
            }
        });

    Some(handle)
}

#[cfg(target_os = "linux")]
fn set_pipe_nonblocking(rx: &PipeReader) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let raw = fcntl(rx, FcntlArg::F_GETFL).map_err(io::Error::from)?;
    let flags = OFlag::from_bits_retain(raw) | OFlag::O_NONBLOCK;
    fcntl(rx, FcntlArg::F_SETFL(flags)).map_err(io::Error::from)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_tls_peer_loop(
    mut stream: TcpStream,
    remote: SocketAddr,
    mut conn: TlsConn,
    outbound_rx: mpsc::Receiver<Vec<u8>>,
    mut wake_rx: PipeReader,
    inbound_tx: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    inbound_dropped: Arc<AtomicU64>,
    outbound_dropped: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
) {
    let mut frames = FrameReader::new();
    let mut plain_buf = [0u8; 4096];

    loop {
        if closed.load(Ordering::Relaxed) {
            break;
        }
        drain_pipe(&mut wake_rx);

        while let Ok(bytes) = outbound_rx.try_recv() {
            match frame(&bytes) {
                Ok(framed) => {
                    if conn.writer().write_all(&framed).is_err() {
                        outbound_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
                Err(_) => {
                    outbound_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        while conn.wants_write() {
            match conn.write_tls(&mut stream) {
                Ok(0) => return,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }

        let mut eof = false;
        loop {
            match conn.read_tls(&mut stream) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(_) => {
                    if conn.process_new_packets().is_err() {
                        return;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }

        loop {
            match conn.reader().read(&mut plain_buf) {
                Ok(0) => break,
                Ok(n) => {
                    frames.push(&plain_buf[..n]);
                    loop {
                        match frames.next_frame() {
                            Ok(Some(packet)) => {
                                if inbound_tx.try_send((remote, packet)).is_err() {
                                    inbound_dropped.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }

        if eof {
            break;
        }

        #[cfg(target_os = "linux")]
        poll_two_fds(
            &stream,
            conn.wants_write(),
            &wake_rx,
            Some(Duration::from_millis(250)),
        );
        #[cfg(not(target_os = "linux"))]
        thread::sleep(Duration::from_millis(5));
    }
}

// ── QUIC v1 DATAGRAM Carrier ─────────────────────────────────────────────

/// QUIC v1 DATAGRAM (RFC 9221) carrier over UDP (`carrier = "quic"`).
pub struct QuicTransport {
    local: SocketAddr,
    closed: Arc<AtomicBool>,
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    outbound: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    wake: Mutex<PipeWriter>,
    inbound_dropped: Arc<AtomicU64>,
    outbound_dropped: Arc<AtomicU64>,
}

impl std::fmt::Debug for QuicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTransport")
            .field("local", &self.local)
            .field(
                "dropped",
                &(self.inbound_dropped.load(Ordering::Relaxed)
                    + self.outbound_dropped.load(Ordering::Relaxed)),
            )
            .finish()
    }
}

impl QuicTransport {
    /// Bind a QUIC DATAGRAM transport on `address`.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_with_options(address, 0, None)
    }

    /// Bind with `SO_MARK` and optional TLS SNI hostname.
    pub fn bind_with_options(
        address: SocketAddr,
        fwmark: u32,
        tls_sni: Option<&str>,
    ) -> io::Result<Self> {
        let sni = normalize_sni(tls_sni);
        let (server_tls, client_tls) = build_tls_configs(&sni, QUIC_ALPN)?;

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.datagram_receive_buffer_size(Some(1024 * 1024));
        transport_cfg.datagram_send_buffer_size(1024 * 1024);
        if let Ok(idle) = Duration::from_secs(30).try_into() {
            transport_cfg.max_idle_timeout(Some(idle));
        }
        let transport_cfg = Arc::new(transport_cfg);

        let quic_server_crypto = QuicServerConfig::try_from(server_tls)
            .map_err(|e| io::Error::other(format!("quic server tls: {e}")))?;
        let mut quic_server_cfg = QuicServerCfg::with_crypto(Arc::new(quic_server_crypto));
        quic_server_cfg.transport_config(Arc::clone(&transport_cfg));

        let quic_client_crypto = QuicClientConfig::try_from(client_tls)
            .map_err(|e| io::Error::other(format!("quic client tls: {e}")))?;
        let mut quic_client_cfg = QuicClientCfg::new(Arc::new(quic_client_crypto));
        quic_client_cfg.transport_config(transport_cfg);

        let socket = bind_udp_socket(address, fwmark)?;
        socket.set_nonblocking(true)?;
        let local = socket.local_addr()?;

        let (wake_rx, wake_tx) = std::io::pipe()?;
        #[cfg(target_os = "linux")]
        set_pipe_nonblocking(&wake_rx)?;

        let closed = Arc::new(AtomicBool::new(false));
        let inbound_dropped = Arc::new(AtomicU64::new(0));
        let outbound_dropped = Arc::new(AtomicU64::new(0));
        let (inbound_tx, inbound_rx) = mpsc::sync_channel::<(SocketAddr, Vec<u8>)>(CARRIER_QUEUE);
        let (outbound_tx, outbound_rx) = mpsc::sync_channel::<(SocketAddr, Vec<u8>)>(CARRIER_QUEUE);

        let endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(Arc::new(quic_server_cfg)),
            false,
            None,
        );

        spawn_quic_worker(
            socket,
            endpoint,
            quic_client_cfg,
            sni,
            wake_rx,
            inbound_tx,
            outbound_rx,
            Arc::clone(&closed),
            Arc::clone(&inbound_dropped),
            Arc::clone(&outbound_dropped),
        );

        Ok(Self {
            local,
            closed,
            inbound: Mutex::new(inbound_rx),
            outbound: outbound_tx,
            wake: Mutex::new(wake_tx),
            inbound_dropped,
            outbound_dropped,
        })
    }

    /// Stop the QUIC I/O worker.
    pub(crate) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            wake_pipe(&self.wake);
        }
    }
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        self.close();
    }
}

impl DatagramSocket for QuicTransport {
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        if self
            .outbound
            .try_send((destination, bytes.to_vec()))
            .is_err()
        {
            self.outbound_dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            wake_pipe(&self.wake);
        }
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Ok(inbound) = self.inbound.lock() else {
            return Err(io::Error::other("quic inbound queue is poisoned"));
        };
        match inbound.recv_timeout(Duration::from_millis(250)) {
            Ok((source, bytes)) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok((n, source))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no datagram waiting",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "quic carrier closed",
            )),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_quic_worker(
    socket: UdpSocket,
    mut endpoint: Endpoint,
    client_cfg: QuicClientCfg,
    sni: String,
    mut wake_rx: PipeReader,
    inbound_tx: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    outbound_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    closed: Arc<AtomicBool>,
    inbound_dropped: Arc<AtomicU64>,
    outbound_dropped: Arc<AtomicU64>,
) {
    let _ = thread::Builder::new()
        .name("vallum-quic-io".to_owned())
        .spawn(move || {
            let mut conns: HashMap<ConnectionHandle, Connection> = HashMap::new();
            let mut addr_to_handle: HashMap<SocketAddr, ConnectionHandle> = HashMap::new();
            let mut handle_to_addr: HashMap<ConnectionHandle, SocketAddr> = HashMap::new();
            let mut pending: HashMap<ConnectionHandle, VecDeque<Bytes>> = HashMap::new();
            let mut recv_buf = [0u8; 65_535];
            let mut resp_buf = Vec::with_capacity(2048);
            let mut tx_buf = Vec::with_capacity(2048);

            loop {
                if closed.load(Ordering::Relaxed) {
                    break;
                }
                drain_pipe(&mut wake_rx);
                let now = Instant::now();

                loop {
                    match socket.recv_from(&mut recv_buf) {
                        Ok((n, remote)) => {
                            resp_buf.clear();
                            let Some(event) = endpoint.handle(
                                now,
                                remote,
                                None,
                                None,
                                BytesMut::from(&recv_buf[..n]),
                                &mut resp_buf,
                            ) else {
                                continue;
                            };
                            match event {
                                DatagramEvent::NewConnection(incoming) => {
                                    resp_buf.clear();
                                    if let Ok((handle, conn)) =
                                        endpoint.accept(incoming, now, &mut resp_buf, None)
                                    {
                                        conns.insert(handle, conn);
                                        addr_to_handle.insert(remote, handle);
                                        handle_to_addr.insert(handle, remote);
                                    } else if !resp_buf.is_empty() {
                                        let _ = socket.send_to(&resp_buf, remote);
                                    }
                                }
                                DatagramEvent::ConnectionEvent(handle, ev) => {
                                    if let Some(conn) = conns.get_mut(&handle) {
                                        conn.handle_event(ev);
                                    }
                                }
                                DatagramEvent::Response(transmit) => {
                                    let _ = socket.send_to(&resp_buf, transmit.destination);
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }

                while let Ok((dest, bytes)) = outbound_rx.try_recv() {
                    let handle = if let Some(&h) = addr_to_handle.get(&dest) {
                        Some(h)
                    } else {
                        match endpoint.connect(now, client_cfg.clone(), dest, &sni) {
                            Ok((h, conn)) => {
                                conns.insert(h, conn);
                                addr_to_handle.insert(dest, h);
                                handle_to_addr.insert(h, dest);
                                Some(h)
                            }
                            Err(_) => None,
                        }
                    };
                    let Some(h) = handle else {
                        outbound_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let Some(conn) = conns.get_mut(&h) else {
                        outbound_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let payload = Bytes::from(bytes);
                    if conn.is_handshaking() {
                        let q = pending.entry(h).or_default();
                        if q.len() >= QUIC_PENDING_CAP {
                            q.pop_front();
                            outbound_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        q.push_back(payload);
                    } else if conn.datagrams().send(payload, true).is_err() {
                        outbound_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }

                let mut terminated = Vec::new();
                let mut earliest_timeout: Option<Instant> = None;

                for (&handle, conn) in &mut conns {
                    if let Some(deadline) = conn.poll_timeout() {
                        if deadline <= now {
                            conn.handle_timeout(now);
                        }
                    }

                    while let Some(ev) = conn.poll() {
                        match ev {
                            QuicEvent::HandshakeDataReady | QuicEvent::Connected => {
                                if !conn.is_handshaking() {
                                    if let Some(mut queue) = pending.remove(&handle) {
                                        while let Some(pkt) = queue.pop_front() {
                                            if conn.datagrams().send(pkt, true).is_err() {
                                                outbound_dropped.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                }
                            }
                            QuicEvent::DatagramReceived => {
                                let remote = handle_to_addr.get(&handle).copied();
                                while let Some(dgram) = conn.datagrams().recv() {
                                    if let Some(src) = remote {
                                        if inbound_tx.try_send((src, dgram.to_vec())).is_err() {
                                            inbound_dropped.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            QuicEvent::ConnectionLost { .. } => {
                                terminated.push(handle);
                            }
                            _ => {}
                        }
                    }

                    while let Some(ev) = conn.poll_endpoint_events() {
                        if let Some(con_ev) = endpoint.handle_event(handle, ev) {
                            conn.handle_event(con_ev);
                        }
                    }

                    loop {
                        tx_buf.clear();
                        let Some(transmit) = conn.poll_transmit(now, 8, &mut tx_buf) else {
                            break;
                        };
                        let _ = socket.send_to(&tx_buf, transmit.destination);
                    }

                    if let Some(t) = conn.poll_timeout() {
                        earliest_timeout = Some(match earliest_timeout {
                            Some(cur) => cur.min(t),
                            None => t,
                        });
                    }
                }

                for h in terminated {
                    conns.remove(&h);
                    pending.remove(&h);
                    if let Some(addr) = handle_to_addr.remove(&h) {
                        if addr_to_handle.get(&addr) == Some(&h) {
                            addr_to_handle.remove(&addr);
                        }
                    }
                }

                let wait = earliest_timeout
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|| Duration::from_millis(250))
                    .min(Duration::from_millis(250));

                #[cfg(target_os = "linux")]
                poll_two_fds(&socket, false, &wake_rx, Some(wait));
                #[cfg(not(target_os = "linux"))]
                thread::sleep(wait.min(Duration::from_millis(5)));
            }
        });
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn recv_until(
        sock: &dyn DatagramSocket,
        deadline: Instant,
    ) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 4096];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => return Ok((buf[..n].to_vec(), src)),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[test]
    fn tls_transport_round_trips_bidirectional_packets() {
        let server = TlsTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Some("cdn.example.com"),
        )
        .expect("bind tls server");
        let client = TlsTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Some("cdn.example.com"),
        )
        .expect("bind tls client");
        let server_addr = server.local_addr().expect("server addr");

        let ping = b"vallum-tls-ping-payload";
        client.send_to(ping, server_addr).expect("client send");
        let (got_ping, client_addr) =
            recv_until(&server, Instant::now() + Duration::from_secs(5)).expect("server recv");
        assert_eq!(got_ping, ping);

        let pong = b"vallum-tls-pong-payload";
        server.send_to(pong, client_addr).expect("server send");
        let (got_pong, from) =
            recv_until(&client, Instant::now() + Duration::from_secs(5)).expect("client recv");
        assert_eq!(from, server_addr);
        assert_eq!(got_pong, pong);
    }

    #[test]
    fn quic_transport_round_trips_bidirectional_datagrams() {
        let server = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Some("cdn.example.com"),
        )
        .expect("bind quic server");
        let client = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Some("cdn.example.com"),
        )
        .expect("bind quic client");
        let server_addr = server.local_addr().expect("server addr");

        let ping = b"vallum-quic-ping-datagram";
        client.send_to(ping, server_addr).expect("client send");
        let (got_ping, client_addr) =
            recv_until(&server, Instant::now() + Duration::from_secs(5)).expect("server recv");
        assert_eq!(got_ping, ping);

        let pong = b"vallum-quic-pong-datagram";
        server.send_to(pong, client_addr).expect("server send");
        let (got_pong, from) =
            recv_until(&client, Instant::now() + Duration::from_secs(5)).expect("client recv");
        assert_eq!(from, server_addr);
        assert_eq!(got_pong, pong);
    }
}
