// SPDX-License-Identifier: Apache-2.0

//! The loopback UDP DNS forwarder: the humble shell around [`super::wire`] and
//! [`super::resolvers`]. It owns the sockets, the threads and the concurrency
//! bound; every decision it makes is delegated to the pure modules.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use vallum_config::Config;

use super::resolvers::{is_local_domain, split_resolvers, tunnel_is_ipv4_only};
use super::wire::{
    parse_dns_query, synthesize_captive_portal_a_response, synthesize_nodata_response,
    DnsQueryQuestion, DNS_TYPE_AAAA,
};
use crate::session::uapi_get;
use crate::watch::{parse_session_health_at, DEAD_AFTER, WATCH_POLL};

/// Maximum concurrent forwarded upstream UDP DNS queries handled by
/// [`LoopbackDnsProxy`] at once.
pub(crate) const MAX_CONCURRENT_DNS_QUERIES: usize = 64;

const DNS_PORT: u16 = 53;
const DNS_MAX_PACKET: usize = 4096;
const DNS_HEADER_LEN: usize = 12;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// What the proxy does with a query on its own, before any forwarding.
///
/// Plain named fields rather than two bare booleans at every call site.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProxyPolicy {
    /// Answer every `A` query with the captive-portal address (`NODATA` for the rest).
    pub(crate) captive_spoof: bool,
    /// Answer `AAAA` with `NODATA`: an IPv4-only tunnel has no use for them.
    pub(crate) suppress_aaaa: bool,
}

/// [`ProxyPolicy`] as the dispatch thread reads it: togglable while running.
#[derive(Debug)]
struct LivePolicy {
    captive_spoof: AtomicBool,
    suppress_aaaa: AtomicBool,
}

impl LivePolicy {
    fn new(initial: ProxyPolicy) -> Self {
        Self {
            captive_spoof: AtomicBool::new(initial.captive_spoof),
            suppress_aaaa: AtomicBool::new(initial.suppress_aaaa),
        }
    }

    /// The answer the proxy gives itself, if the policy says not to forward.
    fn local_answer(&self, query: &[u8], question: &DnsQueryQuestion) -> Option<Vec<u8>> {
        if self.captive_spoof.load(Ordering::Acquire) {
            return synthesize_captive_portal_a_response(query);
        }
        if self.suppress_aaaa.load(Ordering::Acquire) && question.qtype == DNS_TYPE_AAAA {
            return synthesize_nodata_response(query);
        }
        None
    }
}

/// Where forwarded queries go: LAN names to LAN resolvers, the rest to the tunnel.
#[derive(Debug, Clone, Default)]
pub(crate) struct Upstreams {
    pub(crate) tunnel: Vec<SocketAddr>,
    pub(crate) lan: Vec<SocketAddr>,
}

impl Upstreams {
    /// The resolvers that should see `qname`. LAN resolvers get local names, and
    /// everything when the tunnel has none; otherwise the tunnel answers.
    fn for_name(&self, qname: &str) -> &[SocketAddr] {
        let local_only = !self.lan.is_empty() && (is_local_domain(qname) || self.tunnel.is_empty());
        if local_only {
            &self.lan
        } else {
            &self.tunnel
        }
    }
}

/// Counts one in-flight forwarded query; releases its slot when dropped.
struct InFlightSlot(Arc<AtomicUsize>);

impl InFlightSlot {
    /// Take a slot, or `None` if [`MAX_CONCURRENT_DNS_QUERIES`] are already out.
    fn acquire(counter: &Arc<AtomicUsize>) -> Option<Self> {
        let previous = counter.fetch_add(1, Ordering::AcqRel);
        let slot = Self(Arc::clone(counter));
        // Dropping `slot` on the refusal path gives the increment back.
        (previous < MAX_CONCURRENT_DNS_QUERIES).then_some(slot)
    }
}

impl Drop for InFlightSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// An unbound address of the same family as `peer`, port chosen by the OS.
fn unspecified_like(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// A loopback address that reaches a listener bound to `addr`.
fn reachable_loopback(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), v4.port())
        }
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), v6.port())
        }
        other => other,
    }
}

/// Ask each upstream in turn until one answers, and relay that answer to `client`.
/// Silence is the client's timeout: a query nobody answered is simply dropped.
fn forward_query(
    reply_via: &UdpSocket,
    client: SocketAddr,
    query: &[u8],
    upstreams: &[SocketAddr],
) {
    let mut answer = [0u8; DNS_MAX_PACKET];
    for &upstream in upstreams {
        let Ok(socket) = UdpSocket::bind(unspecified_like(upstream)) else {
            continue;
        };
        let _ = socket.set_read_timeout(Some(UPSTREAM_TIMEOUT));
        let _ = socket.set_write_timeout(Some(UPSTREAM_TIMEOUT));
        if socket.send_to(query, upstream).is_err() {
            continue;
        }
        if let Ok((len, _)) = socket.recv_from(&mut answer) {
            if len >= DNS_HEADER_LEN {
                let _ = reply_via.send_to(&answer[..len], client);
                return;
            }
        }
    }
}

fn is_transient(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    )
}

/// Everything the dispatch thread shares with its owner.
struct Shared {
    shutdown: AtomicBool,
    policy: LivePolicy,
    in_flight: Arc<AtomicUsize>,
}

/// Handle one datagram: answer it locally, forward it, or drop it.
fn dispatch(
    socket: &UdpSocket,
    shared: &Shared,
    upstreams: &Arc<Upstreams>,
    query: &[u8],
    client: SocketAddr,
) {
    let Some(question) = parse_dns_query(query) else {
        return;
    };
    if let Some(answer) = shared.policy.local_answer(query, &question) {
        let _ = socket.send_to(&answer, client);
        return;
    }
    if upstreams.for_name(&question.qname).is_empty() {
        return;
    }
    let Some(slot) = InFlightSlot::acquire(&shared.in_flight) else {
        return; // over the bound: shed load rather than queue it
    };
    let Ok(reply_via) = socket.try_clone() else {
        return;
    };
    let (query, upstreams) = (query.to_vec(), Arc::clone(upstreams));
    let _ = thread::Builder::new()
        .name("vallum-dns-fwd".to_owned())
        .spawn(move || {
            let _slot = slot;
            forward_query(
                &reply_via,
                client,
                &query,
                upstreams.for_name(&question.qname),
            );
        });
}

/// The dispatch loop: read datagrams until told to stop.
fn serve(socket: &UdpSocket, shared: &Shared, upstreams: &Arc<Upstreams>) {
    let mut buf = vec![0u8; DNS_MAX_PACKET];
    while !shared.shutdown.load(Ordering::Acquire) {
        match socket.recv_from(&mut buf) {
            Ok((len, client)) if len > 0 && !shared.shutdown.load(Ordering::Acquire) => {
                dispatch(socket, shared, upstreams, &buf[..len], client);
            }
            Ok(_) => {}
            Err(err) if is_transient(&err) => {}
            Err(_) => break,
        }
    }
}

/// Whether the proxy should answer `A` queries with the captive-portal address.
///
/// The blocked state is a session with no fresh handshake: forwarding then sends
/// every query into a void, and apps hang on a resolver that never answers.
/// Answering `198.51.100.1` instead lets them fail fast, the way a captive
/// portal is detected. Pure, so the rule is testable without a daemon.
#[must_use]
pub(crate) fn captive_spoof_from_health(age: Option<Duration>, dead_after: Duration) -> bool {
    !age.is_some_and(|age| age < dead_after)
}

/// The watcher thread behind `run_dns_proxy`'s session-following mode: poll
/// the daemon's control socket and keep the captive-portal switch pointed at
/// the session's liveness until the proxy is dropped.
fn spawn_session_follower(shared: Arc<Shared>, control: PathBuf) {
    let worker = thread::Builder::new()
        .name("vallum-dns-watch".to_owned())
        .spawn(move || loop {
            if shared.shutdown.load(Ordering::Acquire) {
                return;
            }
            let now_unix_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let age = uapi_get(&control)
                .ok()
                .and_then(|reply| parse_session_health_at(&reply, now_unix_secs).age);
            let spoof = captive_spoof_from_health(age, DEAD_AFTER);
            shared.policy.captive_spoof.store(spoof, Ordering::Release);
            thread::sleep(WATCH_POLL);
        });
    // The watcher's lifetime is the proxy's: dropping the handle detaches it,
    // and the shutdown flag ends it within one poll after Drop.
    drop(worker);
}

/// Bounded-concurrency local loopback UDP DNS proxy supporting LAN/tunnel split,
/// IPv4-only `AAAA` `NODATA` suppression, and captive-portal `A` spoofing.
#[derive(Debug)]
pub(crate) struct LoopbackDnsProxy {
    local: SocketAddr,
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("policy", &self.policy)
            .field("in_flight", &self.in_flight.load(Ordering::Relaxed))
            .finish()
    }
}

impl LoopbackDnsProxy {
    /// Bind the loopback UDP DNS listener on `listen` and spawn its dispatch loop.
    pub(crate) fn bind(
        listen: SocketAddr,
        upstreams: Upstreams,
        policy: ProxyPolicy,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(listen)?;
        socket.set_read_timeout(Some(POLL_INTERVAL))?;
        let local = socket.local_addr()?;

        let shared = Arc::new(Shared {
            shutdown: AtomicBool::new(false),
            policy: LivePolicy::new(policy),
            in_flight: Arc::new(AtomicUsize::new(0)),
        });
        let upstreams = Arc::new(upstreams);

        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("vallum-dns-proxy".to_owned())
            .spawn(move || serve(&socket, &worker_shared, &upstreams))?;

        Ok(Self {
            local,
            shared,
            worker: Some(worker),
        })
    }

    /// The bound local socket address.
    #[must_use]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Enable or disable captive-portal `A` spoofing (`198.51.100.1`).
    ///
    /// The test suite flips it while the proxy runs; in a running attach the
    /// session follower writes the same atomic directly, so this stays
    /// test-only until another surface needs the handle.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn set_captive_spoof(&self, enabled: bool) {
        self.shared
            .policy
            .captive_spoof
            .store(enabled, Ordering::Release);
    }

    /// Number of upstream queries currently in flight.
    #[must_use]
    pub(crate) fn active_queries(&self) -> usize {
        self.shared.in_flight.load(Ordering::Acquire)
    }
}

impl Drop for LoopbackDnsProxy {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::Release);
        // A zero-byte datagram wakes the loop now instead of at its next poll.
        let target = reachable_loopback(self.local);
        if let Ok(socket) = UdpSocket::bind(unspecified_like(target)) {
            let _ = socket.send_to(&[], target);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Run the local loopback DNS proxy using `[quick]` resolver settings.
///
/// `follow_session` names the daemon's control socket; when set, a watcher
/// thread toggles captive-portal spoofing off while the session is fresh and
/// on once no handshake has arrived within the watchdog window.
pub(crate) fn run_dns_proxy(
    config: &Config,
    listen: SocketAddr,
    captive_spoof: bool,
    follow_session_at: Option<PathBuf>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let servers = config.quick.effective_dns_servers();
    let (tunnel_ips, lan_ips) = split_resolvers(&servers, config.quick.allow_lan);
    let policy = ProxyPolicy {
        captive_spoof,
        suppress_aaaa: tunnel_is_ipv4_only(config),
    };

    if dry_run {
        println!(
            "would run loopback DNS proxy on {listen} (tunnel={tunnel_ips:?}, lan={lan_ips:?}, {policy:?})"
        );
        return Ok(());
    }

    let at_dns_port = |ips: Vec<IpAddr>| -> Vec<SocketAddr> {
        ips.into_iter()
            .map(|ip| SocketAddr::new(ip, DNS_PORT))
            .collect()
    };
    let upstreams = Upstreams {
        tunnel: at_dns_port(tunnel_ips),
        lan: at_dns_port(lan_ips),
    };

    let proxy = LoopbackDnsProxy::bind(listen, upstreams, policy)?;
    if let Some(control) = follow_session_at {
        spawn_session_follower(Arc::clone(&proxy.shared), control);
    }
    println!(
        "vallum-quick: loopback DNS proxy listening on {} (active={})",
        proxy.local_addr(),
        proxy.active_queries()
    );
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
