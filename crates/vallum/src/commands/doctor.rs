// SPDX-License-Identifier: Apache-2.0

//! `vallum doctor`: a read-only readiness report.

use std::path::{Path, PathBuf};

use clap::Args;
use vallum_crypto_sdk::SdkSuite;

use crate::config::{Config, ResolveConfig};
use crate::control;
use crate::uapi;
use crate::Error;

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// The configuration file to check.
    #[arg(long, short, value_name = "FILE")]
    config: Option<PathBuf>,

    /// The control socket to query, instead of the config's `control`.
    #[arg(long, value_name = "SOCKET")]
    control: Option<PathBuf>,

    /// Probe the path MTU to this host with `ping -M do` and compare it with
    /// the config's `outer_mtu`.
    #[arg(long, value_name = "HOST")]
    probe_mtu: Option<String>,

    /// Dial each peer's endpoint and report whether its port answers.
    ///
    /// A connection attempt, so it is one of the two active checks: without a
    /// probe flag, `doctor` sends nothing. It only means something on
    /// `carrier = "tcp"`, where a listener accepts or refuses; UDP has no
    /// connection to make, and the check says so instead of guessing.
    #[arg(long)]
    probe_path: bool,

    /// Sweep candidate MTUs against each peer endpoint and combine with live
    /// UAPI fragmentation counters to recommend an optimal MTU profile.
    #[arg(long)]
    pub tune_mtu: bool,

    /// Emit JSON instead of a table.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    /// Ordering for "which peer's verdict is the report's verdict": the worst
    /// one wins, because one dead path is not offset by a live one.
    const fn rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Warn => 1,
            Self::Fail => 2,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }

    fn json(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Clone)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

impl Check {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
        }
    }
}

/// Run the checks and print the report.
///
/// # Errors
///
/// Returns an error after printing if any check failed.
pub fn doctor(args: &DoctorArgs, allow_insecure_key: bool) -> Result<(), Error> {
    let mut checks = Vec::new();
    checks.push(Check::new(
        "platform",
        if cfg!(target_os = "linux") {
            Status::Pass
        } else {
            Status::Warn
        },
        format!(
            "{} (Linux is the supported tier this release)",
            std::env::consts::OS
        ),
    ));

    // The [account] table is not part of the resolved runtime config (the
    // daemon is account-ignorant, ADR-0044); read it from the file for the
    // desk hint (ADR-0046). A config that will not parse has already failed
    // the config check — no hint is guessed from it.
    let mut account_table: Option<vallum_config::Account> = None;
    let mut file_config: Option<vallum_config::Config> = None;
    let config = match args.config.as_deref() {
        Some(path) => match check_config(path, allow_insecure_key) {
            Ok((config, key_path)) => {
                file_config = vallum_config::Config::load(path).ok();
                account_table = vallum_config::Config::load(path).ok().map(|c| c.account);
                checks.push(Check::new(
                    "config",
                    Status::Pass,
                    format!("{} parsed and resolved", path.display()),
                ));
                // The resolver computes the things that will bite - an
                // `allowed_ips` outside the interface's prefix, an MTU over
                // the outer budget, the cost of a TCP carrier - and the
                // daemon logs them at startup. The doctor used to discard
                // them, so every non-fatal "this will bite you" was invisible
                // to the one tool that runs without a TUN.
                if config.warnings.is_empty() {
                    checks.push(Check::new(
                        "config warnings",
                        Status::Pass,
                        "nothing the resolver wants to warn about",
                    ));
                } else {
                    checks.push(Check::new(
                        "config warnings",
                        Status::Warn,
                        config.warnings.join("; "),
                    ));
                }
                checks.push(check_key_permissions(&key_path, allow_insecure_key));
                Some(config)
            }
            Err(error) => {
                checks.push(Check::new("config", Status::Fail, error.to_string()));
                None
            }
        },
        None => {
            checks.push(Check::new(
                "config",
                Status::Warn,
                "no --config given; only the control socket and tools are checked",
            ));
            None
        }
    };

    // A client dials; a server listens. The doctor has to know which side it
    // is looking at, because "no handshake yet" is ordinary for a server whose
    // clients are offline and is a failure for a client.
    //
    // Two things have to hold, and both are needed. The listen port is
    // ephemeral on a client and fixed on a server - but a config with NO peers
    // is not a client that failed: it is a side with nothing to protect, and
    // a report that fails it would be crying wolf over a config that has not
    // been set up yet.
    let is_client = config
        .as_ref()
        .is_some_and(|resolved| resolved.listen.port() == 0 && !resolved.peers.is_empty());

    // The probe answers the one question the rest of the report cannot: is the
    // path up? It runs first because the verdict for a silent tunnel depends
    // on it - a server that answers and refuses this client is a different
    // problem from a server that is not there.
    let probe = if args.probe_path {
        config.as_ref().map(check_path_probe)
    } else {
        None
    };
    let reachable = probe.as_ref().and_then(|(_, reachable)| *reachable);

    let socket = args
        .control
        .clone()
        .or_else(|| config.as_ref().and_then(control_from_config));
    let mut tunnel_live = false;
    match &socket {
        Some(path) => {
            match check_control(path) {
                Ok(detail) => {
                    tunnel_live = true;
                    checks.push(Check::new("control", Status::Pass, detail));
                    // The parts can all pass while nothing crosses the wire. This
                    // is the only check that says whether the tunnel is *live*.
                    checks.push(check_tunnel(
                        path,
                        config.as_ref().map(|resolved| resolved.carrier),
                        is_client,
                        reachable,
                        account_table.as_ref(),
                    ));
                    // Handshake age says the keys were agreed; this says data is
                    // still moving. The two come apart in the one failure that
                    // matters — a path that dies while the daemon keeps dialling.
                    checks.push(check_path_liveness(path));
                    checks.push(check_handshake_drops(path));
                    // The config and the running daemon must agree about each
                    // peer's key. They can disagree silently (#34) — this is
                    // the surface that says so.
                    if let Some(file_cfg) = file_config.as_ref() {
                        if let Some(check) = check_peer_sync(
                            file_cfg,
                            path,
                            control::request(path, "get=1\n").ok().as_deref(),
                        ) {
                            checks.push(check);
                        }
                    }
                }
                Err(error) => {
                    let is_offline = match &error {
                        Error::IoPath { source, .. } => matches!(
                            source.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                        ),
                        _ => false,
                    };
                    if is_offline && args.control.is_none() {
                        // A client whose daemon is not running is not protected -
                        // and its traffic is going out in the clear, because
                        // nothing is moving it into a tunnel. The report used to
                        // say `Warn` here, and `Warn` does not fail the run, so
                        // `doctor` exited 0 - "everything is fine" - for a client
                        // that was sending every byte in the open.
                        checks.push(Check::new(
                        "control",
                        if is_client { Status::Fail } else { Status::Warn },
                        format!(
                            "daemon is not running (socket `{}` not responding{})",
                            path.display(),
                            if is_client {
                                " - this client is NOT protected: nothing is moving its traffic \
                                 into a tunnel, so it is going out in the clear. Start the service \
                                 with `systemctl start vallum@<interface>`"
                            } else {
                                "; start service to inspect live session"
                            }
                        ),
                    ));
                    } else {
                        checks.push(Check::new("control", Status::Fail, error.to_string()));
                    }
                }
            }
        }
        None => checks.push(Check::new(
            "control",
            if args.config.is_none() && args.control.is_none() {
                Status::Fail
            } else {
                Status::Warn
            },
            "no control socket configured; give --control or a config with `control`",
        )),
    }

    if let Some(resolved) = &config {
        // Which transport the tunnel actually uses. It is one field, and every
        // other check in this report means something different depending on it:
        // a closed UDP port and a closed TCP port are the same failure with a
        // different fix.
        checks.push(check_carrier(resolved.carrier));
        checks.push(check_sandbox(resolved));
        if let Some((check, _)) = &probe {
            checks.push(check.clone());
        }
        // A port of 0 is an ephemeral client; anything else is a server, and a
        // server that cannot forward or is not reachable is not working.
        if resolved.listen.port() != 0 {
            checks.push(check_forwarding(resolved));
            checks.push(check_firewall(resolved.listen.port(), resolved.carrier));
        }
        // Enrolment listens on its own port, opened by a different code path
        // than the tunnel's. A config edited by hand leaves the rule where it
        // was, which is how the production server ended up answering nobody with
        // the config saying it was on (security-redteam.md H2). The running unit
        // is the honest signal: the port is in use exactly when it is active.
        if resolved.listen.port() != 0 {
            checks.push(check_enroll_firewall(resolved));
        }
        if let Some(leak_check) = check_leak_guard(args.config.as_deref(), resolved) {
            checks.push(leak_check);
        }
        if let Some(route_check) = check_route_leak(args.config.as_deref(), resolved, tunnel_live) {
            checks.push(route_check);
        }
        if let Some(active_check) = check_active_leak(args.config.as_deref(), resolved, tunnel_live)
        {
            checks.push(active_check);
        }
        let rotating: Vec<&str> = resolved
            .peers
            .iter()
            .filter(|peer| !peer.previous_identities().is_empty())
            .map(vallum_tunnel::PeerConfig::name)
            .collect();
        if !rotating.is_empty() {
            checks.push(Check::new(
                "rotation",
                Status::Warn,
                format!(
                    "{} still accepts a previous key; run `vallum peer finalize` once the \
                     device has the new one",
                    rotating.join(", ")
                ),
            ));
        }
        checks.push(check_service(args.config.as_deref()));
        checks.push(check_config_mode(args.config.as_deref()));
        let frag_counters = live_fragmentation_counters(socket.as_deref(), tunnel_live);
        if let Some(host) = &args.probe_mtu {
            checks.push(check_path_mtu(host, resolved));
            checks.push(check_mtu_tune(host, resolved, frag_counters));
        } else {
            let mut probed = std::collections::HashSet::new();
            for peer in &resolved.peers {
                if let Some(endpoint) = peer.endpoint() {
                    let host = endpoint.ip().to_string();
                    if probed.insert(host.clone()) {
                        checks.push(check_path_mtu(&host, resolved));
                        if args.tune_mtu {
                            checks.push(check_mtu_tune(&host, resolved, frag_counters));
                        }
                    }
                }
            }
        }
    }

    checks.push(check_clock());
    checks.push(check_metrics());

    for tool in ["ip", "systemctl", "journalctl", "resolvconf", "nft"] {
        let found = which(tool);
        checks.push(Check::new(
            tool,
            if found { Status::Pass } else { Status::Warn },
            if found {
                "found on PATH".to_owned()
            } else {
                "not found on PATH; the related action will show a command instead".to_owned()
            },
        ));
    }

    let failures = checks
        .iter()
        .filter(|check| check.status == Status::Fail)
        .count();
    if args.json {
        let value = serde_json::json!(checks
            .iter()
            .map(|check| serde_json::json!({
                "check": check.name,
                "status": check.status.json(),
                "detail": check.detail,
            }))
            .collect::<Vec<_>>());
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|e| Error::Usage(e.to_string()))?
        );
    } else {
        for check in &checks {
            println!(
                "{} {:<10} {}",
                crate::style::status_badge(check.status.as_str()),
                check.name,
                check.detail
            );
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(Error::Usage(format!("doctor found {failures} failure(s)")))
    }
}

/// Which transport the tunnel uses, said plainly.
///
/// Not a pass/fail judgement: both carriers are supported. It is here because
/// it changes the meaning of every other line in the report, and because the
/// one failure an operator cannot see is two ends configured differently — TCP
/// on one side and UDP on the other is silence, not an error message.
/// Whether the syscall filter would be installed, and what it would do.
///
/// Three states are worth telling apart, because they are three different
/// problems: no filter at all (there is no privilege drop to attach it to), a
/// filter that only logs, and a filter the kernel would refuse. The first two
/// are the operator's choice; the third is the kernel's, and it means the
/// daemon would refuse to start rather than run unfiltered.
fn check_sandbox(resolved: &crate::config::Resolved) -> Check {
    if resolved.privileges.is_none() {
        return Check::new(
            "seccomp",
            Status::Warn,
            "no syscall filter: it is installed with the privilege drop, so set \
             `interface.user` or `interface.group`",
        );
    }
    if let Err(why) = crate::sandbox::support() {
        return Check::new(
            "seccomp",
            Status::Fail,
            format!("the daemon would refuse to start with `interface.seccomp`: {why}"),
        );
    }
    if resolved.sandbox == crate::sandbox::Mode::Enforce {
        return Check::new(
            "seccomp",
            Status::Pass,
            "enforced: a syscall off the allow-list kills the daemon",
        );
    }
    Check::new(
        "seccomp",
        Status::Warn,
        "log mode, set explicitly in the config: a syscall off the allow-list is \
         logged and allowed — remove `interface.seccomp = \"log\"` to enforce",
    )
}

fn check_carrier(carrier: vallum_config::Carrier) -> Check {
    let detail = match carrier {
        vallum_config::Carrier::Udp => {
            "udp (the default): datagrams, one packet each, and peers may roam".to_owned()
        }
        vallum_config::Carrier::Lwo => {
            "lwo: zero-overhead UDP header masking (SplitMix64 tail-keyed XOR); peers may roam \
             and unmodified `udp` listeners auto-detect it"
                .to_owned()
        }
        vallum_config::Carrier::Auto => {
            "auto: races LWO-obfuscated UDP first, staggers TCP after 500ms if unanswered, \
             and locks onto UDP for 15s when UDP responds"
                .to_owned()
        }
        vallum_config::Carrier::Tcp => {
            "tcp: framed packets over one connection per peer — both ends must set \
             `carrier = \"tcp\"`, and a peer cannot roam under it"
                .to_owned()
        }
        vallum_config::Carrier::Ss => {
            "ss: Shadowsocks-style 24-byte nonce AEAD UDP obfuscation — uniform-random \
             wire packets with no plaintext header"
                .to_owned()
        }
        vallum_config::Carrier::Tls => {
            "tls: TLS 1.3 stream carrier over TCP — wraps framed Vallum packets in a \
             standard TLS 1.3 session"
                .to_owned()
        }
        vallum_config::Carrier::Quic => {
            "quic: QUIC v1 DATAGRAM (RFC 9221) carrier over UDP — carries Vallum packets \
             as unreliable QUIC datagrams without TCP head-of-line blocking"
                .to_owned()
        }
    };
    Check::new("carrier", Status::Pass, detail)
}

/// Dial each peer's endpoint, when the carrier has something to dial.
///
/// This is the check that separates "the path blocks it" from "the other end is
/// not listening", which the daemon cannot tell apart: it sends and hears
/// nothing either way. Only TCP can answer it — a UDP port that nobody listens
/// on is silent, not refused — so under UDP the check says what it cannot do
/// rather than reporting a pass it did not earn.
fn check_path_probe(resolved: &crate::config::Resolved) -> (Check, Option<bool>) {
    let endpoints: Vec<std::net::SocketAddr> = resolved
        .peers
        .iter()
        .filter_map(vallum_tunnel::PeerConfig::endpoint)
        .collect();
    probe_endpoints(
        resolved.carrier,
        endpoints,
        std::time::Duration::from_secs(2),
        |endpoint, timeout| std::net::TcpStream::connect_timeout(endpoint, timeout).map(|_| ()),
    )
}

/// The probe's decision, separated from the dial so both branches are testable
/// without a network or a config.
fn probe_endpoints(
    carrier: vallum_config::Carrier,
    mut endpoints: Vec<std::net::SocketAddr>,
    timeout: std::time::Duration,
    connect: impl Fn(&std::net::SocketAddr, std::time::Duration) -> std::io::Result<()>,
) -> (Check, Option<bool>) {
    endpoints.sort();
    endpoints.dedup();

    if endpoints.is_empty() {
        return (
            Check::new(
                "path",
                Status::Pass,
                "no peer endpoint configured, so this host listens and there is nothing to dial",
            ),
            None,
        );
    }
    if !carrier.is_probeable() {
        return (
            Check::new(
                "path",
                Status::Pass,
                format!(
                    "udp: not probeable — a UDP port that is closed or filtered is silence, not a \
                     refusal; `vallum show` reports the last handshake for {}",
                    endpoints
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
            None,
        );
    }

    let mut failed = Vec::new();
    for endpoint in &endpoints {
        // Short by default: a filtered port costs a full timeout, and several of
        // them should not make `doctor` feel hung.
        if let Err(error) = connect(endpoint, timeout) {
            failed.push(format!("{endpoint} ({})", error.kind()));
        }
    }
    if failed.is_empty() {
        let joined = endpoints
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let detail = if carrier == vallum_config::Carrier::Auto {
            format!("auto: tcp fallback {joined} accepted a connection (lwo udp tried first)")
        } else {
            format!("tcp: {joined} accepted a connection")
        };
        (Check::new("path", Status::Pass, detail), Some(true))
    } else {
        let detail = if carrier == vallum_config::Carrier::Auto {
            format!(
                "auto: tcp fallback closed/filtered on {}; lwo/udp datagrams will still be \
                 attempted first",
                failed.join(", ")
            )
        } else {
            format!(
                "tcp: no answer from {}; the port is closed or filtered, or the far end is not \
                 on `carrier = \"tcp\"` — UDP to the same host is the other half of the question",
                failed.join(", ")
            )
        };
        (Check::new("path", Status::Warn, detail), Some(false))
    }
}

/// Resolve a config the way the daemon will.
///
/// With the permission override, because the flag is global and the doctor
/// used to ignore it: it told the operator to pass
/// `--allow-insecure-key-permissions` and then refused anyway, because the
/// strict `resolve` never saw it. A preflight that disagrees with the daemon
/// it preflights is worse than no preflight.
fn check_config(
    path: &Path,
    allow_insecure_key: bool,
) -> Result<(crate::config::Resolved, PathBuf), Error> {
    let config = Config::load(path)?;
    let suite_id = config.suite_id(path)?;
    let suite = SdkSuite::from_id(suite_id)
        .map_err(|e| Error::Suite(format!("suite 0x{suite_id:04x}: {e}")))?;
    let resolved = config.resolve_with(path, &suite, allow_insecure_key)?;
    let key_path = crate::config::resolve_key_path(path, &config.interface.private_key);
    Ok((resolved, key_path))
}

/// The private key's mode, checked the way the daemon checks it.
///
/// `run` refuses a key the group or the world can read. The doctor used not
/// to look at all: it reported the config as healthy, and then the daemon
/// refused to start on the same file.
fn check_key_permissions(key_path: &Path, allow_insecure_key: bool) -> Check {
    match crate::keys::check_permissions(key_path, allow_insecure_key) {
        Ok(None) => Check::new(
            "key permissions",
            Status::Pass,
            format!("{} is not readable by anyone else", key_path.display()),
        ),
        Ok(Some(warning)) => Check::new(
            "key permissions",
            Status::Warn,
            format!("{warning} (allowed by --allow-insecure-key-permissions)"),
        ),
        Err(error) => Check::new("key permissions", Status::Fail, error.to_string()),
    }
}

fn control_from_config(config: &crate::config::Resolved) -> Option<PathBuf> {
    config.control.clone()
}

fn check_control(path: &Path) -> Result<String, Error> {
    let reply = control::request(path, "get=1\n")?;
    if !reply.lines().any(|line| line == "errno=0") {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            what: format!("control request failed: {}", reply.trim()),
        });
    }
    let response = uapi::parse_response(&reply);
    let interface = response.field(uapi::field::VALLUM_INTERFACE).unwrap_or("?");
    let port = response.field(uapi::field::LISTEN_PORT).unwrap_or("?");
    let suite = response.field(uapi::field::VALLUM_SUITE).unwrap_or("?");
    let peers = response.peers.len();
    Ok(format!(
        "interface `{interface}`, listen {port}, suite {suite}, {peers} peer(s)"
    ))
}

/// Whether traffic is actually crossing: the age of the newest handshake.
///
/// Three dogfood failures ended in "everything configured" and "no internet":
/// a unit that could not exec, a config root could not read, and a default
/// route into a dead interface. `doctor` checked the parts and passed all three
/// times. This check is about the whole.
/// Is anything actually arriving from each peer?
///
/// The handshake check answers "did we agree on keys"; this answers "is data
/// still moving". They come apart in exactly one failure — a path that dies
/// while the daemon keeps dialling — and every other check in this report
/// passes through it, because a dead path looks like a quiet one from every
/// angle except this: datagrams going out, nothing coming back.
/// Did this responder refuse initiations, and why?
///
/// Every refusal on the handshake path is silent on the wire, deliberately: an
/// unauthenticated datagram gets no oracle. That is correct and it is also why a
/// server that receives an initiation and ignores it looks exactly like one that
/// never received it. This is the only place the reason reaches a human.
/// A peer whose messages were authenticated and then rejected.
///
/// On the client, the server's response lands here when the server's key has
/// changed. The counter was there and was never published, so this report
/// could not tell a changed server key from a dead path - and those two have
/// opposite fixes: re-enrol, or chase a firewall.
///
/// Separated from the socket so the verdict is testable without a daemon.
fn rejected_peer(response: &uapi::Response) -> Option<Check> {
    for peer in &response.peers {
        let rejected = peer
            .iter()
            .find(|(name, _)| name == uapi::field::VALLUM_DROPPED_AFTER_AUTH)
            .and_then(|(_, value)| value.parse::<u64>().ok())
            .unwrap_or(0);
        if rejected > 0 {
            let name = peer
                .iter()
                .find(|(key, _)| key == uapi::field::VALLUM_NAME)
                .map_or("unnamed", |(_, value)| value.as_str());
            return Some(Check::new(
                "handshakes",
                Status::Fail,
                format!(
                    "peer `{name}`: {rejected} of its messages were authenticated and then \
                     rejected - its key is NOT the one this side enrolled. The server was \
                     re-enrolled, or something is answering in its place. Re-enrol with \
                     `vallum peer add` before trusting the tunnel"
                ),
            ));
        }
    }
    None
}

fn check_handshake_drops(path: &Path) -> Check {
    let reply = match control::request(path, "get=1\n") {
        Ok(reply) => reply,
        Err(error) => return Check::new("handshakes", Status::Warn, error.to_string()),
    };
    let response = uapi::parse_response(&reply);
    let count = |field: &str| {
        response
            .field(field)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let mut reasons = Vec::new();
    for (field, why) in [
        (
            uapi::field::VALLUM_HANDSHAKE_DROPPED_NO_MAC,
            "failed admission (the peer's copy of this server's public key is wrong, or something is spoofing)",
        ),
        (
            uapi::field::VALLUM_HANDSHAKE_DROPPED_UNIDENTIFIABLE,
            "did not decapsulate (wrong suite, or corrupt)",
        ),
        (
            uapi::field::VALLUM_HANDSHAKE_DROPPED_UNKNOWN_PEER,
            "named a peer this server does not have (a stale client config)",
        ),
        (
            uapi::field::VALLUM_HANDSHAKE_DROPPED_ENDPOINT_CONFLICT,
            "came from another peer's pinned endpoint",
        ),
        (
            uapi::field::VALLUM_HANDSHAKE_DROPPED_STALE,
            "carried a timestamp that was not newer than the last accepted one \
             (the peer's clock stepped back, or it is replaying)",
        ),
    ] {
        let value = count(field);
        if value > 0 {
            reasons.push(format!("{value} {why}"));
        }
    }
    if let Some(check) = rejected_peer(&response) {
        return check;
    }
    if reasons.is_empty() {
        Check::new("handshakes", Status::Pass, "no initiation refused")
    } else {
        Check::new(
            "handshakes",
            Status::Warn,
            format!("refused: {}", reasons.join("; ")),
        )
    }
}

fn check_path_liveness(path: &Path) -> Check {
    let reply = match control::request(path, "get=1\n") {
        Ok(reply) => reply,
        Err(error) => return Check::new("path", Status::Warn, error.to_string()),
    };
    let response = uapi::parse_response(&reply);
    if response.peers.is_empty() {
        return Check::new("path", Status::Warn, "no peers configured");
    }
    let mut verdict: Option<Check> = None;
    for peer in &response.peers {
        let field = |key: &str| {
            peer.iter()
                .find(|(name, _)| name == key)
                .and_then(|(_, value)| value.parse::<u64>().ok())
        };
        let name = peer
            .iter()
            .find(|(key, _)| key == uapi::field::VALLUM_NAME)
            .map_or("unnamed", |(_, value)| value.as_str());
        let received = field(uapi::field::LAST_RECEIVED_MS);
        let sent = field(uapi::field::LAST_SENT_MS);
        let keepalive = field(uapi::field::PERSISTENT_KEEPALIVE_INTERVAL).unwrap_or(0);
        let limit_ms = if keepalive > 0 {
            keepalive * 2 * 1_000
        } else {
            60_000
        };
        let (status, detail) = match (received, sent) {
            (Some(received), Some(sent)) if received > limit_ms && sent < 120_000 => (
                Status::Fail,
                format!(
                    "peer `{name}`: sending, but nothing has arrived for {}s (last send {}s ago) \
                     — the path is dead, not the peer",
                    received / 1_000,
                    sent / 1_000
                ),
            ),
            (None, Some(_)) => (
                // Datagrams sent, nothing ever arrived: this side is the one
                // dialling, and it has never been answered. `Warn` does not
                // fail the run, and a report that exits 0 while nothing is
                // protected is the one thing this command must never say.
                Status::Fail,
                format!(
                    "peer `{name}`: datagrams sent, nothing has ever arrived - this side is \
                     dialling and has never been answered, so nothing is protected"
                ),
            ),
            (Some(received), _) => (
                Status::Pass,
                format!("peer `{name}`: last heard {}s ago", received / 1_000),
            ),
            (None, None) => (Status::Warn, format!("peer `{name}`: no traffic yet")),
        };
        // The worst peer is the answer: one dead peer is not offset by a live one.
        if verdict
            .as_ref()
            .is_none_or(|worst| status.rank() > worst.status.rank())
        {
            verdict = Some(Check::new("path", status, detail));
        }
    }
    verdict.unwrap_or_else(|| Check::new("path", Status::Warn, "no peers configured"))
}

/// The account-cause hint (ADR-0046): a config that carries a desk account
/// may be refused because the account expired or hit its byte cap — and an
/// invite-code user cannot run `vallum peer add` on the server, so the next
/// step is the desk. `None` when no token is recorded: the existing advice
/// stands unchanged. Shared with `vallum status` so the two surfaces speak
/// with one voice.
pub(crate) fn desk_account_hint(account: &vallum_config::Account) -> Option<String> {
    account.token.as_deref()?;
    Some(match account.endpoint.as_deref() {
        Some(endpoint) => format!(
            "this config carries a desk account - it may have expired or hit its byte cap; \
             run `vallum account` or open {}/account",
            endpoint.trim_end_matches('/')
        ),
        None => "this config carries a desk account - it may have expired or hit its byte cap; \
                 run `vallum account` (no desk endpoint is recorded)"
            .to_owned(),
    })
}

/// The verdict for a tunnel that has never handshook.
///
/// Separated from the socket so both branches are testable without a daemon.
///
/// The asymmetry is the whole point. A **server** whose peers have not
/// connected is ordinary - the client is off, or asleep, or behind a wall.
/// A **client** that has never completed a handshake is not ordinary: it is
/// carrying nothing, and every byte it sends is going out in the clear. The
/// doctor used to say `Warn` for both, and `Warn` does not fail the run, so
/// a client that had never protected a single byte exited **0** - the report
/// said everything was fine while nothing was.
///
/// `reachable` is what the path probe found, when it ran: `Some(true)` means
/// the server answered, so the silence is the server refusing this client
/// rather than the path being down.
///
/// `account` is the config's `[account]` table, when a config was given: a
/// recorded token turns the refusal advice into the desk hint (ADR-0046).
fn handshake_verdict(
    is_client: bool,
    reachable: Option<bool>,
    account: Option<&vallum_config::Account>,
) -> (Status, String) {
    if !is_client {
        return (
            Status::Warn,
            "no handshake since the daemon started: the peers may simply be offline".to_owned(),
        );
    }
    let hint = account.and_then(desk_account_hint);
    let cause = match reachable {
        Some(true) => match hint {
            Some(hint) => format!(
                "the server answers on the wire but does not complete a handshake with this \
                 client, so it is refusing this client - {hint}"
            ),
            None => {
                "the server answers on the wire but does not complete a handshake with this client, \
                 so it is refusing this client - most likely the server no longer has this client's \
                 key (it was re-enrolled, or this config is stale). Re-enrol with `vallum peer add`"
                    .to_owned()
            }
        },
        Some(false) => {
            "the server does not answer on the wire at all, so the path is down - a firewall \
             between the two, or the server's daemon is not running"
                .to_owned()
        }
        None => match hint {
            Some(hint) => format!(
                "the likely causes, in the order to check them: {hint}; the server no longer \
                 has this client's key (it was re-enrolled, or this config is stale); the \
                 endpoint is wrong or filtered; or the server's daemon is not running"
            ),
            None => "the likely causes, in the order to check them: the server does not have this \
                 client's key (it was re-enrolled, or this config is stale) - re-enrol with `vallum \
                 peer add`; the endpoint is wrong or filtered; or the server's daemon is not running"
                .to_owned(),
        },
    };
    (
        Status::Fail,
        format!(
            "no handshake has ever completed - this client is NOT protected, and every byte \
             it sends is going out in the clear. {cause}"
        ),
    )
}

/// One peer whose config key and daemon-session key disagree.
struct PeerDesync {
    name: String,
    config_fingerprint: String,
    session_fingerprint: String,
}

/// Compare the config's peers against the daemon's session, by name.
///
/// `config_peers` and `session_peers` are (peer, fingerprint) pairs. Only
/// peers present on BOTH sides can desync: a peer the daemon has not loaded
/// is the tunnel check's domain, and a session peer the config dropped was
/// already removed from one side.
fn peer_desyncs(
    config_peers: &[(String, String)],
    session_peers: &[(String, String)],
) -> Vec<PeerDesync> {
    config_peers
        .iter()
        .filter_map(|(name, config_fp)| {
            session_peers
                .iter()
                .find(|(session_name, _)| session_name == name)
                .and_then(|(_, session_fp)| {
                    (session_fp != config_fp).then(|| PeerDesync {
                        name: name.clone(),
                        config_fingerprint: config_fp.clone(),
                        session_fingerprint: session_fp.clone(),
                    })
                })
        })
        .collect()
}

/// The config and the session must agree about each peer's key.
///
/// They can disagree silently — a config edit without a sync, a rotation that
/// was never applied — and the tunnel keeps answering while neither surface
/// says a word. The alpha server shipped exactly that state (#34): `peer show
/// laptop` answered one fingerprint, `show` and `metrics` another, and nothing
/// warned. `reply` is injected so tests can feed a fixture; the caller passes
/// the `get=1` reply, `None` when the daemon cannot be asked (the tunnel check
/// already warns about that, so this check stays out of the report).
fn check_peer_sync(
    config: &vallum_config::Config,
    control: &Path,
    reply: Option<&str>,
) -> Option<Check> {
    let _ = control;
    let response = uapi::parse_response(reply?);
    let session_peers: Vec<(String, String)> = (0..response.peers.len())
        .filter_map(|index| {
            let name = response
                .peer_field(index, uapi::field::VALLUM_NAME)
                .map(String::from)
                .unwrap_or_default();
            // Compare like-for-like: fingerprint the daemon's public-key LINE
            // with the same line-hash the config side uses. The raw
            // `vallum_fingerprint` field is the daemon's 8-byte device
            // fingerprint — a different algorithm and length — so comparing it
            // to the config's 6-byte line-hash always reported false drift.
            // The public line is the same form both sides hold.
            let line = response.peer_field(index, uapi::field::VALLUM_PUBLIC_LINE)?;
            Some((name, crate::keys::fingerprint(line)))
        })
        .collect();
    let config_peers: Vec<(String, String)> = config
        .peers
        .iter()
        .filter_map(|peer| {
            let line = peer.public_key.as_deref()?;
            Some((peer.name.clone(), crate::keys::fingerprint(line)))
        })
        .collect();
    if config_peers.is_empty() || session_peers.is_empty() {
        return None;
    }
    let desyncs = peer_desyncs(&config_peers, &session_peers);
    if desyncs.is_empty() {
        return Some(Check::new(
            "peer sync",
            Status::Pass,
            "every peer's key in the config matches the running daemon",
        ));
    }
    let detail = desyncs
        .iter()
        .map(|desync| {
            format!(
                "peer {}: the config holds key {} but the running daemon holds {} — \
                 the tunnel is not running what the config says; re-apply the config \
                 (syncconf) or restart the daemon",
                desync.name, desync.config_fingerprint, desync.session_fingerprint
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Some(Check::new("peer sync", Status::Warn, detail))
}

fn check_tunnel(
    path: &Path,
    carrier: Option<vallum_config::Carrier>,
    is_client: bool,
    reachable: Option<bool>,
    account: Option<&vallum_config::Account>,
) -> Check {
    let reply = match control::request(path, "get=1\n") {
        Ok(reply) => reply,
        Err(error) => return Check::new("tunnel", Status::Warn, error.to_string()),
    };
    let response = uapi::parse_response(&reply);
    if response.peers.is_empty() {
        return Check::new(
            "tunnel",
            Status::Warn,
            "no peers yet: enrol one, then this check reports the handshake age",
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    // `parse_response` returns raw key/value blocks; read the field directly.
    let newest = response
        .peers
        .iter()
        .filter_map(|peer| {
            peer.iter()
                .find(|(key, _)| key == uapi::field::LAST_HANDSHAKE_TIME_SEC)
                .and_then(|(_, value)| value.parse::<u64>().ok())
        })
        .max();
    match newest {
        Some(secs) if secs > 0 => {
            let age = now.saturating_sub(secs);
            if age <= 180 {
                Check::new("tunnel", Status::Pass, format!("handshake {age}s ago"))
            } else {
                Check::new(
                    "tunnel",
                    Status::Warn,
                    format!(
                        "last handshake {age}s ago — the peer may be offline, or the path \
                         changed. `vallum show` has the counters"
                    ),
                )
            }
        }
        _ => {
            let protocol = carrier.map_or("udp", vallum_config::Carrier::protocol);
            let (status, detail) = handshake_verdict(is_client, reachable, account);
            Check::new(
                "tunnel",
                status,
                format!(
                    "{detail} ({protocol} {})",
                    response.field(uapi::field::LISTEN_PORT).unwrap_or("?")
                ),
            )
        }
    }
}

fn which(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

fn output(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn sysctl_eq(path: &str, expected: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|value| value.trim() == expected)
}

fn sysctl(path: &str) -> bool {
    sysctl_eq(path, "1")
}

#[allow(clippy::struct_excessive_bools)]
struct LeakGuardInputs {
    has_v4: bool,
    policy_mode: crate::policy::Mode,
    guard: crate::policy::GuardState,
    src_valid_mark: bool,
    arp_ignore_strict: bool,
}

fn evaluate_leak_guard(interface: &str, inputs: &LeakGuardInputs) -> Check {
    let mut missing_sysctls = Vec::new();
    if inputs.has_v4 {
        if !inputs.src_valid_mark {
            missing_sysctls.push("net.ipv4.conf.all.src_valid_mark=1");
        }
        if !inputs.arp_ignore_strict {
            missing_sysctls.push("net.ipv4.conf.all.arp_ignore=2");
        }
    }

    if inputs.policy_mode == crate::policy::Mode::Off {
        return Check::new(
            "leak_guard",
            Status::Warn,
            "full tunnel configured, but `[quick] policy = \"off\"` disables the nftables \
             kill-switch and CVE-2019-14899 input guard"
                .to_owned(),
        );
    }

    match inputs.guard {
        crate::policy::GuardState::Absent => Check::new(
            "leak_guard",
            Status::Warn,
            format!(
                "nftables leak guard for `{interface}` is not installed (egress unrestricted); \
                 run `vallum up` or `vallum policy on`"
            ),
        ),
        crate::policy::GuardState::Unknown => {
            if missing_sysctls.is_empty() {
                Check::new(
                    "leak_guard",
                    Status::Warn,
                    format!(
                        "could not inspect nftables guard for `{interface}` (needs CAP_NET_ADMIN); \
                         CVE-2019-14899 sysctls (src_valid_mark=1, arp_ignore=2) are active"
                    ),
                )
            } else {
                Check::new(
                    "leak_guard",
                    Status::Warn,
                    format!(
                        "could not inspect nftables guard for `{interface}`, and CVE-2019-14899 \
                         sysctls missing: {}",
                        missing_sysctls.join(", ")
                    ),
                )
            }
        }
        crate::policy::GuardState::Installed => {
            if missing_sysctls.is_empty() {
                Check::new(
                    "leak_guard",
                    Status::Pass,
                    format!(
                        "nftables egress + CVE-2019-14899 input guard active on `{interface}`; \
                         src_valid_mark=1 and arp_ignore=2"
                    ),
                )
            } else {
                Check::new(
                    "leak_guard",
                    Status::Warn,
                    format!(
                        "nftables egress + input guard active on `{interface}`, but missing \
                         CVE-2019-14899 sysctl hardening: {}",
                        missing_sysctls.join(", ")
                    ),
                )
            }
        }
    }
}

fn check_leak_guard(
    config_path: Option<&Path>,
    resolved: &crate::config::Resolved,
) -> Option<Check> {
    let path = config_path?;
    let cfg = Config::load(path).ok()?;
    let full_tunnel = cfg.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|cidr| cidr.trim() == "0.0.0.0/0" || cidr.trim() == "::/0")
    });
    if !full_tunnel {
        return None;
    }

    let interface = resolved.interface_name.as_deref().unwrap_or("vallum0");
    let has_v4 = crate::policy::carries(&cfg).0;
    let inputs = LeakGuardInputs {
        has_v4,
        policy_mode: crate::policy::resolve(&cfg),
        guard: crate::policy::guard_state(interface),
        src_valid_mark: sysctl("/proc/sys/net/ipv4/conf/all/src_valid_mark"),
        arp_ignore_strict: sysctl_eq("/proc/sys/net/ipv4/conf/all/arp_ignore", "2"),
    };
    Some(evaluate_leak_guard(interface, &inputs))
}

#[allow(clippy::struct_excessive_bools)]
struct RouteLeakInputs {
    has_v4: bool,
    has_v6: bool,
    route4_dev: Option<String>,
    route6_dev: Option<String>,
    resolv_nameservers: Vec<String>,
    dns_routes_via_tunnel: bool,
}

fn parse_ip_route_dev(route_output: &str) -> Option<String> {
    let mut tokens = route_output.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "dev" {
            return tokens.next().map(str::to_owned);
        }
    }
    None
}

fn parse_resolv_nameservers(resolv_text: &str) -> Vec<String> {
    resolv_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with(';'))
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let key = parts.next()?;
            let addr = parts.next()?;
            (key == "nameserver").then(|| addr.to_owned())
        })
        .collect()
}

fn is_loopback_resolver(ns: &str) -> bool {
    ns.parse::<std::net::IpAddr>().map_or_else(
        |_| matches!(ns, "127.0.0.53" | "127.0.0.1" | "::1"),
        |ip| ip.is_loopback(),
    )
}

fn ip_route_dev(family_flag: &str, dest: &str) -> Option<String> {
    output("ip", &[family_flag, "route", "get", dest]).and_then(|out| parse_ip_route_dev(&out))
}

fn evaluate_route_leak(interface: &str, inputs: &RouteLeakInputs) -> Check {
    let mut leaks = Vec::new();
    if inputs.has_v4 {
        match inputs.route4_dev.as_deref() {
            Some(dev) if dev == interface => {}
            Some(dev) => leaks.push(format!(
                "IPv4 egress (1.1.1.1) resolves via `{dev}` instead of `{interface}`"
            )),
            None => leaks.push("no active IPv4 route to 1.1.1.1".to_owned()),
        }
    }
    if inputs.has_v6 {
        if let Some(dev) = inputs.route6_dev.as_deref() {
            if dev != interface {
                leaks.push(format!(
                    "IPv6 egress (2606:4700:4700::1111) resolves via `{dev}` instead of `{interface}`"
                ));
            }
        }
    }
    if !inputs.resolv_nameservers.is_empty() && !inputs.dns_routes_via_tunnel {
        let non_loopbacks: Vec<&str> = inputs
            .resolv_nameservers
            .iter()
            .map(String::as_str)
            .filter(|ns| !is_loopback_resolver(ns))
            .collect();
        let summary = if non_loopbacks.is_empty() {
            "configured resolvers".to_owned()
        } else {
            non_loopbacks.join(", ")
        };
        leaks.push(format!(
            "DNS resolver(s) ({summary}) do not route via `{interface}`"
        ));
    }

    if leaks.is_empty() {
        Check::new(
            "route_leak",
            Status::Pass,
            format!("active full-tunnel egress and DNS resolvers route cleanly via `{interface}`"),
        )
    } else {
        Check::new("route_leak", Status::Warn, leaks.join("; "))
    }
}

fn check_route_leak(
    config_path: Option<&Path>,
    resolved: &crate::config::Resolved,
    tunnel_live: bool,
) -> Option<Check> {
    if !tunnel_live {
        return None;
    }
    let path = config_path?;
    let cfg = Config::load(path).ok()?;
    let full_tunnel = cfg.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|cidr| cidr.trim() == "0.0.0.0/0" || cidr.trim() == "::/0")
    });
    if !full_tunnel {
        return None;
    }

    let interface = resolved.interface_name.as_deref().unwrap_or("vallum0");
    let (has_v4, has_v6) = crate::policy::carries(&cfg);
    let route4_dev = if has_v4 {
        ip_route_dev("-4", "1.1.1.1")
    } else {
        None
    };
    let route6_dev = if has_v6 {
        ip_route_dev("-6", "2606:4700:4700::1111")
    } else {
        None
    };

    let resolv_text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let resolv_nameservers = parse_resolv_nameservers(&resolv_text);
    let dns_routes_via_tunnel = resolv_nameservers.iter().all(|ns| {
        is_loopback_resolver(ns) || {
            let flag = if ns.contains(':') { "-6" } else { "-4" };
            ip_route_dev(flag, ns).as_deref() == Some(interface)
        }
    });

    let inputs = RouteLeakInputs {
        has_v4,
        has_v6,
        route4_dev,
        route6_dev,
        resolv_nameservers,
        dns_routes_via_tunnel,
    };
    Some(evaluate_route_leak(interface, &inputs))
}

fn evaluate_active_leak(status: &str, detail: &str) -> Check {
    match status {
        "clean" => Check::new("active_leak", Status::Pass, detail.to_owned()),
        "leaking" => Check::new("active_leak", Status::Fail, detail.to_owned()),
        _ => Check::new(
            "active_leak",
            Status::Warn,
            format!("active leak probe inconclusive: {detail}"),
        ),
    }
}

fn check_active_leak(
    config_path: Option<&Path>,
    resolved: &crate::config::Resolved,
    tunnel_live: bool,
) -> Option<Check> {
    if !tunnel_live {
        return None;
    }
    let path = config_path?;
    let cfg = Config::load(path).ok()?;
    let full_tunnel = cfg.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|cidr| cidr.trim() == "0.0.0.0/0" || cidr.trim() == "::/0")
    });
    if !full_tunnel {
        return None;
    }

    let interface = resolved.interface_name.as_deref().unwrap_or("vallum0");
    let state_file = Path::new("/run/vallum").join(format!("{interface}.leak-check"));
    if let Ok(raw) = std::fs::read_to_string(&state_file) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let checked_at = val.get("checked_at").and_then(|v| v.as_u64()).unwrap_or(0);
            if now.saturating_sub(checked_at) <= 180 {
                if let (Some(status), Some(detail)) = (
                    val.get("status").and_then(|v| v.as_str()),
                    val.get("detail").and_then(|v| v.as_str()),
                ) {
                    return Some(evaluate_active_leak(status, detail));
                }
            }
        }
    }

    // No fresh watchdog verdict; ask vallum-quick to run a one-shot probe.
    let quick_bin = if Path::new("/usr/bin/vallum-quick").exists() {
        "/usr/bin/vallum-quick"
    } else {
        "vallum-quick"
    };
    let out = std::process::Command::new(quick_bin)
        .args(["leak-check", "--json"])
        .arg(path)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let val: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    let status = val.get("status").and_then(|v| v.as_str())?;
    let detail = val.get("detail").and_then(|v| v.as_str()).unwrap_or("");
    Some(evaluate_active_leak(status, detail))
}

/// A server has to forward, or clients reach nothing but the server.
fn check_forwarding(resolved: &crate::config::Resolved) -> Check {
    let has_v4 = resolved
        .addresses
        .iter()
        .any(|prefix| prefix.as_ipnet().addr().is_ipv4());
    let has_v6 = resolved
        .addresses
        .iter()
        .any(|prefix| prefix.as_ipnet().addr().is_ipv6());
    let mut missing = Vec::new();
    if has_v4 && !sysctl("/proc/sys/net/ipv4/ip_forward") {
        missing.push("net.ipv4.ip_forward");
    }
    if has_v6 && !sysctl("/proc/sys/net/ipv6/conf/all/forwarding") {
        missing.push("net.ipv6.conf.all.forwarding");
    }
    // A firewall can filter forwarding even with the sysctl on: Docker,
    // Tailscale, and iptables-based ufw all install chains in `ip filter`,
    // which is invisible to the nft-native chains the firewall check reads.
    if missing.is_empty() && crate::hostnet::inspect().iptables_forward_drop {
        let interface = resolved.interface_name.as_deref().unwrap_or("vallum0");
        let accepted = output("iptables", &["-S", "FORWARD"]).is_some_and(|rules| {
            rules
                .lines()
                .any(|line| line.contains(&format!("-i {interface}")) && line.contains("-j ACCEPT"))
        });
        return if accepted {
            Check::new(
                "forwarding",
                Status::Pass,
                format!("IP forwarding is on, and iptables accepts traffic on {interface}"),
            )
        } else {
            Check::new(
                "forwarding",
                Status::Warn,
                format!(
                    "IP forwarding is on, but iptables filters forwarded traffic (Docker, \
                     Tailscale, or another manager); run `vallum server init --force`, or \
                     `iptables -I FORWARD -i {interface} -j ACCEPT`"
                ),
            )
        };
    }
    if missing.is_empty() {
        Check::new(
            "forwarding",
            Status::Pass,
            "IP forwarding is enabled for every address family the tunnel uses",
        )
    } else {
        Check::new(
            "forwarding",
            Status::Warn,
            format!(
                "{} is off; clients will not reach beyond this host — \
                 `vallum server init` enables it",
                missing.join(" and ")
            ),
        )
    }
}

/// The listening port has to be reachable from outside, or nothing connects.
///
/// The protocol is the configured carrier's, because a rule that opens UDP
/// 51820 does nothing for a tunnel that speaks TCP on it.
/// Is the enrolment port reachable, now that enrolment is on?
///
/// `server enroll --enable` opens this port and `--disable` closes it. Nothing
/// keeps the rule in step with a config that was edited by hand, so a server can
/// advertise an invite flow that dials into silence — the invite is minted, the
/// client sends its hello, and no firewall anywhere allows the answer out.
fn check_enroll_firewall(resolved: &crate::config::Resolved) -> Check {
    let interface = resolved.interface_name.as_deref().unwrap_or("vallum0");
    let unit = format!("vallum-enroll@{interface}");
    let active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", &unit])
        .status()
        .is_ok_and(|status| status.success());
    if !active {
        // A config that asks for the responder and has no unit running is the
        // failure this check exists for; reporting PASS was the bug.
        return if resolved.enroll_enabled {
            Check::new(
                "enroll",
                Status::Fail,
                format!("[enroll] enabled but {unit} is not running — no device can enrol"),
            )
        } else {
            Check::new("enroll", Status::Pass, format!("{unit} is not running"))
        };
    }
    let port = resolved.enroll_port;
    let state = crate::hostnet::inspect();
    match state.firewall {
        crate::hostnet::Firewall::Ufw => {
            if ufw_allows(port, "udp") {
                Check::new("enroll", Status::Pass, format!("ufw allows udp {port}"))
            } else {
                Check::new(
                    "enroll",
                    Status::Warn,
                    format!(
                        "enrolment is on but ufw does not allow udp {port}: invites will \
                         dial into silence. `vallum server enroll --enable` opens it, or \
                         `ufw allow {port}/udp`"
                    ),
                )
            }
        }
        _ => Check::new(
            "enroll",
            Status::Warn,
            format!("enrolment is on; confirm UDP {port} is reachable from outside"),
        ),
    }
}

fn check_firewall(port: u16, carrier: vallum_config::Carrier) -> Check {
    let proto = carrier.protocol();
    let state = crate::hostnet::inspect();
    let (status, detail) = match state.firewall {
        crate::hostnet::Firewall::Ufw => {
            let allowed = ufw_allows(port, proto);
            (
                if allowed { Status::Pass } else { Status::Warn },
                if allowed {
                    format!("ufw allows {proto} {port}")
                } else {
                    format!("ufw does not allow {proto} {port}; run `ufw allow {port}/{proto}`")
                },
            )
        }
        crate::hostnet::Firewall::Firewalld => {
            let allowed =
                output("firewall-cmd", &[&format!("--query-port={port}/{proto}")]).is_some();
            (
                if allowed { Status::Pass } else { Status::Warn },
                if allowed {
                    format!("firewalld allows {proto} {port}")
                } else {
                    format!(
                        "firewalld does not allow {proto} {port}; run \
                         `firewall-cmd --permanent --add-port={port}/{proto}`"
                    )
                },
            )
        }
        crate::hostnet::Firewall::Nftables => {
            let allowed = output("nft", &["list", "ruleset"])
                .is_some_and(|rules| rules.contains(&format!("dport {port}")));
            if allowed {
                (Status::Pass, format!("nftables accepts {proto} {port}"))
            } else if !state.input_drop {
                // Nothing is dropping the port, so there is no rule to add.
                // Saying otherwise sends the operator to edit a chain that is
                // not blocking anything.
                (
                    Status::Pass,
                    if state.ufw_installed {
                        if ufw_allows(port, proto) {
                            format!(
                                "nothing blocks {proto} {port}; ufw is installed but not enabled, \
                                 and the allow rule is stored for when you enable it"
                            )
                        } else {
                            format!(
                                "nothing blocks {proto} {port}; ufw is installed but not enabled \
                                 — if you enable it, run `ufw allow {port}/{proto}` first"
                            )
                        }
                    } else {
                        format!(
                            "nothing blocks {proto} {port}; the nftables input chain has no \
                             drop policy"
                        )
                    },
                )
            } else {
                (
                    Status::Warn,
                    format!(
                        "the nftables input chain drops {proto} {port}; run `vallum server init \
                         --force`, or add an accept rule to `inet filter input`"
                    ),
                )
            }
        }
        crate::hostnet::Firewall::None => (
            Status::Pass,
            if state.ufw_installed && !ufw_allows(port, proto) {
                format!(
                    "no host firewall is active, so nothing blocks {proto} {port}; ufw is \
                     installed but not enabled — run `ufw allow {port}/{proto}` before \
                     enabling it"
                )
            } else {
                "no host firewall detected, so nothing is blocking the port".to_owned()
            },
        ),
    };
    Check::new("firewall", status, detail)
}

/// Whether ufw stores an allow rule for this port and protocol.
///
/// `ufw status` only lists rules while ufw is enabled; `ufw show added` reads
/// the stored ones, which is what matters for a manager that is installed but
/// switched off.
fn ufw_allows(port: u16, proto: &str) -> bool {
    let rule = format!("{port}/{proto}");
    ["status", "show added"].iter().any(|args| {
        let args: Vec<&str> = args.split(' ').collect();
        output("ufw", &args).is_some_and(|text| {
            text.lines()
                .any(|line| line.contains(&rule) && line.to_lowercase().contains("allow"))
        })
    })
}

/// Whether the unit that should own this config is running.
fn check_service(config: Option<&Path>) -> Check {
    let Some(path) = config else {
        return Check::new(
            "service",
            Status::Warn,
            "no --config given, so there is no unit to look up",
        );
    };
    if !Path::new("/run/systemd/system").exists() {
        return Check::new(
            "service",
            Status::Warn,
            "no systemd on this host; the daemon is run directly",
        );
    }
    let instance = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0");
    let unit = format!("vallum@{instance}");
    // `systemctl is-active` exits non-zero for anything but `active`, so the
    // status is the text, not the exit code.
    let state = std::process::Command::new("systemctl")
        .args(["--no-ask-password", "is-active", &unit])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    match state.as_str() {
        "active" => Check::new("service", Status::Pass, format!("{unit} is active")),
        "inactive" => Check::new(
            "service",
            Status::Warn,
            format!("{unit} is inactive; `systemctl enable --now {unit}`"),
        ),
        "failed" => Check::new(
            "service",
            Status::Fail,
            format!("{unit} failed; `journalctl -u {unit}` has the reason"),
        ),
        other => Check::new("service", Status::Warn, format!("{unit} is {other}")),
    }
}

/// The largest ICMP payload that crosses the path, by bisection.
#[cfg(test)]
fn bisect_mtu(fits: impl FnMut(u16) -> bool) -> Option<u16> {
    crate::net::bisect_mtu(fits)
}

/// Measure the outer path and say whether `outer_mtu` fits it.
fn check_path_mtu(host: &str, resolved: &crate::config::Resolved) -> Check {
    let configured = u16::try_from(resolved.outer_budget + 48).unwrap_or(u16::MAX);
    let floor_budget = usize::from(crate::tun::MIN_MTU) + crate::tun::DATA_OVERHEAD;
    let min_outer_mtu = (floor_budget + usize::from(crate::config::OUTER_HEADER_LEN)) as u16;

    let Some(measured) = crate::net::probe_path_mtu_host(host) else {
        return Check::new(
            "path-mtu",
            Status::Warn,
            format!(
                "inconclusive: no ICMP reply from {host} at any size (filtered, or no route). \
                 Measure it by hand: ping -M do -s 1472 {host}"
            ),
        );
    };
    if measured < min_outer_mtu {
        Check::new(
            "path-mtu",
            Status::Fail,
            format!(
                "{host} carries {measured} bytes, below the minimum supported outer MTU of \
                 {min_outer_mtu} bytes"
            ),
        )
    } else if measured >= configured {
        Check::new(
            "path-mtu",
            Status::Pass,
            format!("{host} carries {measured} bytes; outer_mtu {configured} fits"),
        )
    } else {
        Check::new(
            "path-mtu",
            Status::Warn,
            format!(
                "{host} carries {measured} bytes, below outer_mtu {configured}; \
                 set `interface.outer_mtu = {measured}` or packets will be dropped"
            ),
        )
    }
}

fn parse_uapi_fragmentation_counters(response: &uapi::Response) -> (u64, u64, u64) {
    let count = |field: &str| {
        response
            .field(field)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    };
    (
        count(uapi::field::VALLUM_FRAGMENTS_DROPPED),
        count(uapi::field::VALLUM_REASSEMBLED),
        count(uapi::field::VALLUM_PACKETS_DELIVERED),
    )
}

fn live_fragmentation_counters(socket: Option<&Path>, tunnel_live: bool) -> (u64, u64, u64) {
    if !tunnel_live {
        return (0, 0, 0);
    }
    let Some(path) = socket else {
        return (0, 0, 0);
    };
    let Ok(reply) = control::request(path, "get=1\n") else {
        return (0, 0, 0);
    };
    let response = uapi::parse_response(&reply);
    parse_uapi_fragmentation_counters(&response)
}

/// Sweep candidate inner MTUs (`1280`, `1380`, `1420`) against RTT jitter,
/// path ceiling, and live UAPI fragmentation counters to recommend the optimal
/// inner MTU profile and TCP MSS values.
fn check_mtu_tune(
    host: &str,
    resolved: &crate::config::Resolved,
    counters: (u64, u64, u64),
) -> Check {
    let Some(rec) =
        crate::net::tune_path_mtu_host_with_counters(host, counters.0, counters.1, counters.2)
    else {
        return Check::new(
            "mtu-tune",
            Status::Warn,
            format!("{host}: path MTU tuning inconclusive (ICMP blocked or unreachable)"),
        );
    };
    let configured = if resolved.mtu == 0 {
        "auto".to_owned()
    } else {
        resolved.mtu.to_string()
    };
    let sample_summary = if rec.samples.is_empty() {
        "none".to_owned()
    } else {
        rec.samples
            .iter()
            .map(|s| {
                format!(
                    "{}:p50={}us/jit={}us/loss={}%",
                    s.inner_mtu, s.rtt_p50_us, s.rtt_jitter_us, s.loss_pct
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    Check::new(
        "mtu-tune",
        Status::Pass,
        format!(
            "{host}: profile={} recommends mtu = {} (outer_mtu = {}, IPv4 MSS = {}, IPv6 MSS = {}; ceiling = {}, configured = {configured}): {} [samples: {sample_summary}]",
            rec.profile.as_str(),
            rec.recommended_inner_mtu,
            rec.recommended_outer_mtu,
            rec.ipv4_tcp_mss,
            rec.ipv6_tcp_mss,
            rec.ceiling_outer_mtu,
            rec.rationale
        ),
    )
}

/// Replay-window timestamps and identity validity windows are wall-clock
/// checks, so a host drifting minutes or hours peers and re-keys badly. Warn,
/// never fail: an offline lab without NTP still tunnels correctly today.
/// Is the scrape that feeds every dashboard still happening?
///
/// A metrics pipeline fails silently by nature: the graphs keep showing the last
/// value they had. This check answers the question the graph cannot — when was
/// the file last written.
fn check_metrics() -> Check {
    let path = crate::host::paths::runtime_dir().join("metrics.prom");
    let Ok(meta) = std::fs::metadata(path) else {
        return Check::new(
            "metrics",
            Status::Warn,
            "no scrape file at /run/vallum/metrics.prom — `vallum-ops sync` enables \
             vallum-metrics.timer",
        );
    };
    let age = meta
        .modified()
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .map_or(0, |elapsed| elapsed.as_secs());
    if age <= 60 {
        Check::new("metrics", Status::Pass, format!("scraped {age}s ago"))
    } else {
        Check::new(
            "metrics",
            Status::Warn,
            format!(
                "last scrape {age}s ago — is vallum-metrics.timer running? \
                 `systemctl status vallum-metrics.timer`"
            ),
        )
    }
}

fn check_clock() -> Check {
    let synced = std::process::Command::new("timedatectl")
        .args(["show", "-p", "NTPSynchronized", "--value"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .eq_ignore_ascii_case("yes")
        });
    match synced {
        Some(true) => Check::new("clock", Status::Pass, "NTP synchronized"),
        Some(false) => Check::new(
            "clock",
            Status::Warn,
            "system clock is not NTP-synchronized; handshake timestamps and \
             identity validity windows depend on wall clock (timedatectl)",
        ),
        None => Check::new(
            "clock",
            Status::Warn,
            "cannot check clock sync (no timedatectl); handshake timestamps \
             and identity validity windows depend on wall clock",
        ),
    }
}

/// A config can name a PSK file, so it should not be group- or world-readable.
fn check_config_mode(config: Option<&Path>) -> Check {
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = config else {
        return Check::new("config mode", Status::Warn, "no --config given");
    };
    let Ok(metadata) = std::fs::metadata(path) else {
        return Check::new(
            "config mode",
            Status::Warn,
            format!("cannot read {}", path.display()),
        );
    };
    // The units run with a bounded capability set, so root does not get
    // CAP_DAC_OVERRIDE and cannot read a 0600 file owned by someone else. A
    // config moved in from a user's directory keeps its owner and then fails
    // to load with "permission denied" — as root.
    let owned_by_root = std::os::unix::fs::MetadataExt::uid(&metadata) == 0;
    if path.starts_with(crate::host::paths::config_dir()) && !owned_by_root {
        return Check::new(
            "config owner",
            Status::Warn,
            format!(
                "{} is owned by uid {}; the units run without CAP_DAC_OVERRIDE, so they                  cannot read it. `sudo chown root:root {}`",
                path.display(),
                std::os::unix::fs::MetadataExt::uid(&metadata),
                path.display()
            ),
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        Check::new(
            "config mode",
            Status::Pass,
            format!("{mode:04o} (owner only)"),
        )
    } else {
        Check::new(
            "config mode",
            Status::Warn,
            format!(
                "{mode:04o} is group/world readable; `chmod 600 {}`",
                path.display()
            ),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::bisect_mtu;

    #[test]
    fn peer_sync_names_a_config_daemon_key_mismatch() {
        // Issue #34, live on the alpha server: `peer show laptop` answered one
        // fingerprint (the config) while `show`/`metrics` answered another (the
        // daemon session), with no rotation window in the config and no surface
        // saying so. The config-vs-session comparison is what makes it visible.
        let config_peers = vec![
            ("laptop".to_owned(), "7db904af471a".to_owned()),
            ("lab8".to_owned(), "7252c337c2a77406".to_owned()),
        ];
        let session_peers = vec![
            ("laptop".to_owned(), "abc04277bba25668".to_owned()),
            ("lab8".to_owned(), "7252c337c2a77406".to_owned()),
        ];
        let desyncs = super::peer_desyncs(&config_peers, &session_peers);
        assert_eq!(desyncs.len(), 1, "laptop is the desync; lab8 agrees");
        assert_eq!(desyncs[0].name, "laptop");
        assert_eq!(desyncs[0].config_fingerprint, "7db904af471a");
        assert_eq!(desyncs[0].session_fingerprint, "abc04277bba25668");

        // Keys that agree are not a desync.
        assert!(super::peer_desyncs(&config_peers, &config_peers).is_empty());
        // A config peer the daemon has not loaded yet is the tunnel check's
        // domain, not a key mismatch.
        assert!(super::peer_desyncs(&config_peers, &[]).is_empty());
    }

    #[test]
    fn peer_sync_check_warns_and_points_at_the_fix() {
        let line_a = "vallum1:0003:aa:bb:-";
        let line_b = "vallum1:0003:cc:dd:-";
        let dir = std::env::temp_dir().join(format!("vallum-peer-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("peersync.toml");
        let socket_path = dir.join("peersync.sock");
        std::fs::write(
            &config_path,
            format!(
                "[interface]\nname = \"peersync\"\nprivate_key = \"k\"\nlisten = \"127.0.0.1:0\"\ncontrol = \"{}\"\n\n[[peer]]\nname = \"laptop\"\npublic_key = \"{line_a}\"\n",
                socket_path.display()
            ),
        )
        .unwrap();
        let config = vallum_config::Config::load(&config_path).expect("config parses");
        // The daemon answers with a public-key LINE that is NOT the config key's.
        // The real get=1 emits vallum_public_line; the check fingerprints it the
        // same way as the config side. (Comparing the raw 8-byte vallum_fingerprint
        // field would be a different algorithm and length, and always false-drift.)
        let reply = format!(
            "private_key=(hidden)\nvallum_interface=peersync\nlisten_port=51990\nerrno=0\n\npublic_key=zzz\nvallum_name=laptop\nvallum_public_line={line_b}\nrx_bytes=0\ntx_bytes=0\nerrno=0\n",
        );
        let check = super::check_peer_sync(&config, &socket_path, Some(&reply))
            .expect("the daemon answered, so the check runs");
        assert_eq!(check.status, super::Status::Warn);
        assert!(check.detail.contains("laptop"));
        assert!(
            check.detail.contains("syncconf"),
            "the detail names the fix"
        );

        // When the keys agree, the check passes.
        let agreeing_reply = reply.replace(line_b, line_a);
        let check = super::check_peer_sync(&config, &socket_path, Some(&agreeing_reply))
            .expect("the daemon answered");
        assert_eq!(check.status, super::Status::Pass);

        // An unreachable daemon means the check cannot run: the tunnel check
        // already warns about that, so this one stays out of the report.
        assert!(super::check_peer_sync(&config, &socket_path, None).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_search_finds_the_threshold() {
        assert_eq!(bisect_mtu(|size| size <= 1400), Some(1400));
        assert_eq!(bisect_mtu(|size| size <= 1471), Some(1471));
        assert_eq!(bisect_mtu(|size| size <= 548), Some(548));
    }

    #[test]
    fn a_path_that_carries_everything_reports_the_ceiling() {
        assert_eq!(bisect_mtu(|_| true), Some(1472));
    }

    #[test]
    fn a_path_that_carries_nothing_is_inconclusive() {
        assert_eq!(bisect_mtu(|_| false), None);
    }

    #[test]
    fn the_search_is_bounded() {
        let mut probes = 0;
        let found = bisect_mtu(|size| {
            probes += 1;
            size <= 1200
        });
        assert_eq!(found, Some(1200));
        assert!(probes <= 12, "{probes} probes is too many");
    }

    #[test]
    fn a_peer_whose_key_does_not_match_is_a_failure() {
        // The gap this closes: the client counts a server response that fails
        // verification - the server's key changed - but the counter was never
        // published, so the doctor could not tell that from a dead path.
        let response = crate::uapi::Response {
            device: Vec::new(),
            peers: vec![vec![
                (
                    crate::uapi::field::VALLUM_NAME.to_owned(),
                    "server".to_owned(),
                ),
                (
                    crate::uapi::field::VALLUM_DROPPED_AFTER_AUTH.to_owned(),
                    "4".to_owned(),
                ),
            ]],
        };
        let check = super::rejected_peer(&response).expect("a peer that was rejected");
        assert_eq!(check.status, super::Status::Fail);
        assert!(
            check.detail.contains("NOT the one this side enrolled"),
            "{}",
            check.detail
        );
        assert!(check.detail.contains("re-enrol"), "{}", check.detail);
    }

    #[test]
    fn a_peer_with_no_rejections_is_not_a_failure() {
        let response = crate::uapi::Response {
            device: Vec::new(),
            peers: vec![vec![
                (
                    crate::uapi::field::VALLUM_NAME.to_owned(),
                    "server".to_owned(),
                ),
                (
                    crate::uapi::field::VALLUM_DROPPED_AFTER_AUTH.to_owned(),
                    "0".to_owned(),
                ),
            ]],
        };
        assert!(super::rejected_peer(&response).is_none());
    }

    #[test]
    fn a_client_that_never_handshook_is_a_failure() {
        // The bug this closes: `Warn` does not fail the run, so a client that
        // had never protected a single byte exited 0 - the report said
        // everything was fine while nothing was.
        let (status, detail) = super::handshake_verdict(true, None, None);
        assert_eq!(status, super::Status::Fail);
        assert!(detail.contains("NOT protected"), "{detail}");
        // The likeliest cause is named, because the operator has to act on it.
        assert!(detail.contains("key"), "{detail}");
    }

    #[test]
    fn a_server_with_silent_peers_is_only_a_warning() {
        // The asymmetry is deliberate: a server whose clients are offline is
        // ordinary. Failing it would train people to ignore the line.
        let (status, detail) = super::handshake_verdict(false, None, None);
        assert_eq!(status, super::Status::Warn);
        assert!(detail.contains("offline"), "{detail}");
    }

    #[test]
    fn a_reachable_server_that_refuses_is_named_as_a_refusal() {
        // The probe answered, so the path is up: the silence is the server
        // refusing this client, not the server being absent. Those two have
        // different fixes, and the old message gave neither.
        let (status, detail) = super::handshake_verdict(true, Some(true), None);
        assert_eq!(status, super::Status::Fail);
        assert!(detail.contains("refusing"), "{detail}");

        let (status, detail) = super::handshake_verdict(true, Some(false), None);
        assert_eq!(status, super::Status::Fail);
        assert!(detail.contains("does not answer"), "{detail}");
    }

    #[test]
    fn the_carrier_check_names_the_transport_and_its_price() {
        use vallum_config::Carrier;

        let udp = super::check_carrier(Carrier::Udp);
        assert_eq!(udp.status, super::Status::Pass);
        assert!(
            udp.detail.starts_with("udp (the default)"),
            "{}",
            udp.detail
        );

        let lwo = super::check_carrier(Carrier::Lwo);
        assert_eq!(lwo.status, super::Status::Pass);
        assert!(lwo.detail.starts_with("lwo:"), "{}", lwo.detail);

        let auto = super::check_carrier(Carrier::Auto);
        assert_eq!(auto.status, super::Status::Pass);
        assert!(auto.detail.starts_with("auto:"), "{}", auto.detail);

        let tcp = super::check_carrier(Carrier::Tcp);
        assert_eq!(tcp.status, super::Status::Pass);
        // The failure this line exists to prevent: one end on tcp, the other
        // on udp, which is silence rather than an error.
        assert!(tcp.detail.contains("both ends"), "{}", tcp.detail);
        assert!(tcp.detail.contains("cannot roam"), "{}", tcp.detail);
    }

    #[test]
    fn leak_guard_evaluation_verifies_cve_2019_14899_sysctls_and_nft_state() {
        use crate::policy::{GuardState, Mode};

        let healthy = super::evaluate_leak_guard(
            "vallum-laptop",
            &super::LeakGuardInputs {
                has_v4: true,
                policy_mode: Mode::On,
                guard: GuardState::Installed,
                src_valid_mark: true,
                arp_ignore_strict: true,
            },
        );
        assert_eq!(healthy.status, super::Status::Pass);
        assert!(healthy.detail.contains("src_valid_mark=1"));

        let missing_sysctl = super::evaluate_leak_guard(
            "vallum-laptop",
            &super::LeakGuardInputs {
                has_v4: true,
                policy_mode: Mode::On,
                guard: GuardState::Installed,
                src_valid_mark: true,
                arp_ignore_strict: false,
            },
        );
        assert_eq!(missing_sysctl.status, super::Status::Warn);
        assert!(missing_sysctl.detail.contains("arp_ignore=2"));

        let unguarded = super::evaluate_leak_guard(
            "vallum-laptop",
            &super::LeakGuardInputs {
                has_v4: true,
                policy_mode: Mode::On,
                guard: GuardState::Absent,
                src_valid_mark: true,
                arp_ignore_strict: true,
            },
        );
        assert_eq!(unguarded.status, super::Status::Warn);
        assert!(unguarded.detail.contains("not installed"));
    }

    #[test]
    fn route_leak_evaluation_detects_clean_tunnel_egress_and_dns_leaks() {
        let clean = super::evaluate_route_leak(
            "vallum-laptop",
            &super::RouteLeakInputs {
                has_v4: true,
                has_v6: true,
                route4_dev: Some("vallum-laptop".to_owned()),
                route6_dev: Some("vallum-laptop".to_owned()),
                resolv_nameservers: vec!["127.0.0.53".to_owned()],
                dns_routes_via_tunnel: true,
            },
        );
        assert_eq!(clean.status, super::Status::Pass);
        assert!(clean.detail.contains("route cleanly via `vallum-laptop`"));

        let v4_leak = super::evaluate_route_leak(
            "vallum-laptop",
            &super::RouteLeakInputs {
                has_v4: true,
                has_v6: false,
                route4_dev: Some("wlan0".to_owned()),
                route6_dev: None,
                resolv_nameservers: vec!["1.1.1.1".to_owned()],
                dns_routes_via_tunnel: true,
            },
        );
        assert_eq!(v4_leak.status, super::Status::Warn);
        assert!(v4_leak.detail.contains("wlan0"));

        let dns_leak = super::evaluate_route_leak(
            "vallum-laptop",
            &super::RouteLeakInputs {
                has_v4: true,
                has_v6: false,
                route4_dev: Some("vallum-laptop".to_owned()),
                route6_dev: None,
                resolv_nameservers: vec!["192.168.1.1".to_owned()],
                dns_routes_via_tunnel: false,
            },
        );
        assert_eq!(dns_leak.status, super::Status::Warn);
        assert!(dns_leak.detail.contains("192.168.1.1"));

        assert_eq!(
            super::parse_ip_route_dev(
                "1.1.1.1 dev vallum-laptop table 51820 src 10.7.0.2 uid 1000"
            ),
            Some("vallum-laptop".to_owned())
        );
        assert_eq!(
            super::parse_resolv_nameservers(
                "# comment\nnameserver 127.0.0.53\nnameserver 1.1.1.1\n"
            ),
            vec!["127.0.0.53".to_owned(), "1.1.1.1".to_owned()]
        );

        let active_clean =
            super::evaluate_active_leak("clean", "non-tunnel egress blocked on eth0(IPv4)");
        assert_eq!(active_clean.status, super::Status::Pass);

        let active_leak =
            super::evaluate_active_leak("leaking", "IPv4 probe via `eth0` escaped host");
        assert_eq!(active_leak.status, super::Status::Fail);
    }

    #[test]
    fn the_path_probe_only_claims_what_it_can_test() {
        use std::net::SocketAddr;
        use std::time::Duration;
        use vallum_config::Carrier;

        let endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();

        // UDP: no connection to make, so no pass and no fail — the honest
        // answer, because a filtered UDP port looks exactly like a quiet one.
        let (udp, udp_reachable) = super::probe_endpoints(
            Carrier::Udp,
            vec![endpoint],
            Duration::from_secs(1),
            |_, _| panic!("a UDP carrier must not dial"),
        );
        assert_eq!(udp.status, super::Status::Pass);
        assert!(udp.detail.contains("not probeable"), "{}", udp.detail);
        // A carrier that cannot be probed must not claim a reachability: the
        // verdict for a silent tunnel depends on this being the truth.
        assert_eq!(udp_reachable, None);

        // A listening port answers.
        let (reachable, reachable_says) = super::probe_endpoints(
            Carrier::Tcp,
            vec![endpoint, endpoint],
            Duration::from_secs(1),
            |_, _| Ok(()),
        );
        assert_eq!(reachable.status, super::Status::Pass);
        assert_eq!(reachable_says, Some(true));
        assert!(reachable.detail.contains("accepted a connection"));
        // The same endpoint twice is one dial, because the report is per path.
        assert_eq!(reachable.detail.matches("127.0.0.1:51820").count(), 1);

        // A closed or filtered port is a warning naming the endpoint, not a
        // failure: the far end may simply be restarting.
        let (unreachable, unreachable_says) = super::probe_endpoints(
            Carrier::Tcp,
            vec![endpoint],
            Duration::from_secs(1),
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "refused",
                ))
            },
        );
        assert_eq!(unreachable.status, super::Status::Warn);
        assert_eq!(unreachable_says, Some(false));
        assert!(unreachable.detail.contains("127.0.0.1:51820"));
        assert!(
            unreachable.detail.contains("carrier"),
            "{}",
            unreachable.detail
        );

        // A server has nothing to dial, and says so rather than passing quietly.
        let nothing =
            super::probe_endpoints(Carrier::Tcp, Vec::new(), Duration::from_secs(1), |_, _| {
                panic!("nothing to dial")
            })
            .0;
        assert_eq!(nothing.status, super::Status::Pass);
        assert!(nothing.detail.contains("nothing to dial"));
    }

    /// A key path that is not a regular file must be refused, not read.
    ///
    /// `/dev/zero` never reaches EOF and a FIFO blocks in `open`, so the
    /// unbounded read left the daemon - and `doctor`, the preflight tool -
    /// sitting there instead of reporting the mistake. Both are things an
    /// operator plausibly writes into a config.
    #[test]
    fn a_key_that_is_not_a_regular_file_is_refused_rather_than_read() {
        let dir = std::env::temp_dir().join(format!("vallum-doctor-dev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config_path = dir.join("dev.toml");
        std::fs::write(
            &config_path,
            "[interface]\nname = \"dev\"\nprivate_key = \"/dev/zero\"\nlisten = \"127.0.0.1:0\"\n",
        )
        .unwrap();

        // The point is that this RETURNS. Before the bound it did not: the
        // read of a character device never ends.
        let error =
            super::check_config(&config_path, false).expect_err("a device is not a key file");
        let message = error.to_string();
        assert!(
            message.contains("regular file"),
            "the message must name what is wrong: {message}"
        );
    }

    /// The doctor must honour the flag it tells the operator to pass.
    ///
    /// It used to print "pass --allow-insecure-key-permissions if this is
    /// deliberate" and then refuse anyway, because the strict resolve never
    /// saw the flag. A preflight that disagrees with the daemon it preflights
    /// is worse than no preflight.
    #[test]
    fn the_doctor_honours_the_permission_override() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("vallum-doctor-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = dir.join("mode.key");
        let file = crate::keys::new_secret(0x0003, false, [7u8; 32]);
        crate::keys::save_secret(&key, &file).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let config_path = dir.join("mode.toml");
        std::fs::write(
            &config_path,
            format!(
                "[interface]\nname = \"mode\"\nprivate_key = \"{}\"\nlisten = \"127.0.0.1:0\"\n",
                key.display()
            ),
        )
        .unwrap();

        // The resolver does not police the private key's mode - `run` does,
        // in its own step - so the doctor does the same, and that check is
        // where the two tools must agree.
        let (_resolved, key_path) = super::check_config(&config_path, false).expect("resolves");

        // Strict: the daemon would refuse this key, so the doctor must too.
        let refused = super::check_key_permissions(&key_path, false);
        assert_eq!(
            refused.status,
            super::Status::Fail,
            "the doctor must fail a key the daemon refuses: {}",
            refused.detail
        );
        assert!(
            refused.detail.contains("allow-insecure-key-permissions"),
            "the refusal must name the override: {}",
            refused.detail
        );

        // With the override: accepted, and the report says why it was allowed.
        let allowed = super::check_key_permissions(&key_path, true);
        assert_eq!(allowed.status, super::Status::Warn);
        assert!(
            allowed.detail.contains("allow-insecure-key-permissions"),
            "{}",
            allowed.detail
        );
    }

    /// The resolver's warnings are what the daemon logs at startup. The doctor
    /// used to discard them, so every non-fatal "this will bite you" was
    /// invisible to the one tool that runs without a TUN.
    #[test]
    fn the_doctor_surfaces_the_resolvers_warnings() {
        let dir = std::env::temp_dir().join(format!("vallum-doctor-warn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = dir.join("warn.key");
        let file = crate::keys::new_secret(0x0003, false, [7u8; 32]);
        crate::keys::save_secret(&key, &file).unwrap();

        // A real peer key: the suite's public key is 2374 bytes, and a stub
        // is refused by the resolver before the warning is ever reached.
        let suite = super::SdkSuite::from_id(0x0003).expect("the suite");
        let secret = crate::keys::new_secret(0x0003, false, crate::entropy::seed());
        let identity = crate::keys::identity(&suite, &secret).expect("an identity");
        let peer_line = crate::keys::encode_public(0x0003, &identity.to_peer());

        // The peer claims an address outside the interface's own prefix: the
        // daemon logs "a route to it is needed" at startup.
        let config_path = dir.join("warn.toml");
        std::fs::write(
            &config_path,
            format!(
                "[interface]\nname = \"warn\"\nprivate_key = \"{}\"\naddresses = [\"10.9.0.1/24\"]\nlisten = \"127.0.0.1:0\"\n\n[[peer]]\nname = \"laptop\"\npublic_key = \"{peer_line}\"\nallowed_ips = [\"192.168.44.0/24\"]\n",
                key.display()
            ),
        )
        .unwrap();

        let (resolved, _key_path) = super::check_config(&config_path, false).expect("resolves");
        assert!(
            resolved
                .warnings
                .iter()
                .any(|warning| warning.contains("outside the interface")),
            "the warning the daemon logs must be here: {:?}",
            resolved.warnings
        );
    }

    #[test]
    fn doctor_reports_offline_daemon_as_warning_not_failure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("vallum-doctor-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = dir.join("doctortest.key");
        let file = crate::keys::new_secret(0x0003, false, [7u8; 32]);
        crate::keys::save_secret(&key, &file).unwrap();

        let config_path = dir.join("doctortest.toml");
        let socket_path = dir.join("doctortest.sock");
        let text = format!(
            "[interface]\nname = \"doctortest\"\nprivate_key = \"{}\"\nlisten = \"127.0.0.1:0\"\ncontrol = \"{}\"\n",
            key.display(),
            socket_path.display()
        );
        std::fs::write(&config_path, text).unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let args = super::DoctorArgs {
            config: Some(config_path.clone()),
            control: None,
            probe_mtu: None,
            probe_path: false,
            tune_mtu: false,
            json: false,
        };
        // Ephemeral port 0 means no firewall/forwarding check; socket is offline so control warns.
        // Overall result must be Ok(()), not Err(failure).
        let outcome = super::doctor(&args, false);
        assert!(
            outcome.is_ok(),
            "doctor on offline config should pass with warning, got: {outcome:?}"
        );

        let (resolved, _key_path) = super::check_config(&config_path, false).unwrap();
        let loopback_check = super::check_path_mtu("127.0.0.1", &resolved);
        assert_eq!(loopback_check.status, super::Status::Pass);
        assert!(loopback_check.detail.contains("fits"));

        let tune_check = super::check_mtu_tune("127.0.0.1", &resolved, (0, 0, 0));
        assert_eq!(tune_check.status, super::Status::Pass);
        assert!(tune_check.detail.contains("recommends mtu ="));
        assert!(tune_check.detail.contains("IPv4 MSS ="));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uapi_fragmentation_counters_parse_and_feed_mtu_recommendation() {
        let reply = "vallum_interface=vallum0\nvallum_fragments_dropped=3\n\
                     vallum_reassembled=120\nvallum_packets_delivered=5000\nerrno=0\n";
        let parsed = crate::uapi::parse_response(reply);
        let (dropped, reassembled, delivered) = super::parse_uapi_fragmentation_counters(&parsed);
        assert_eq!((dropped, reassembled, delivered), (3, 120, 5000));

        let rec =
            crate::net::recommend_mtu_from_telemetry(1500, &[], dropped, reassembled, delivered);
        assert_eq!(rec.recommended_inner_mtu, 1380);
        assert_eq!(rec.profile, crate::net::MtuProfile::GamingLowFrag1380);
    }

    /// ADR-0046: an invite-code enrolment cannot run `vallum peer add` on
    /// the server. When the config carries a desk account and the server
    /// refuses the handshake, the next step is the desk, not re-enrolment.
    #[test]
    fn a_refused_client_with_a_desk_account_is_pointed_at_the_desk() {
        let account = vallum_config::Account {
            token: Some("0123456789abcdef0123456789abcdef".to_owned()),
            endpoint: Some("https://desk.wingman.gold".to_owned()),
        };
        let (status, detail) = super::handshake_verdict(true, Some(true), Some(&account));
        assert_eq!(status, super::Status::Fail);
        assert!(detail.contains("refusing"), "{detail}");
        assert!(detail.contains("desk account"), "{detail}");
        assert!(detail.contains("expired"), "{detail}");
        assert!(detail.contains("byte cap"), "{detail}");
        assert!(detail.contains("vallum account"), "{detail}");
        assert!(
            detail.contains("https://desk.wingman.gold/account"),
            "{detail}"
        );
        assert!(!detail.contains("peer add"), "{detail}");
    }

    /// Without an account token the existing advice is unchanged — the
    /// file/SSH enrolment still re-enrols with `vallum peer add`.
    #[test]
    fn a_refused_client_without_an_account_keeps_the_existing_advice() {
        let (status, detail) = super::handshake_verdict(true, Some(true), None);
        assert_eq!(status, super::Status::Fail);
        assert!(
            detail.contains("Re-enrol with `vallum peer add`"),
            "{detail}"
        );
        assert!(!detail.contains("desk account"), "{detail}");
        // An empty [account] table (no token) is the same as none.
        let empty = vallum_config::Account::default();
        let (_, detail) = super::handshake_verdict(true, Some(true), Some(&empty));
        assert!(
            detail.contains("Re-enrol with `vallum peer add`"),
            "{detail}"
        );
    }

    /// A token recorded before the endpoint field existed still gets the
    /// hint — without inventing a URL.
    #[test]
    fn an_account_without_an_endpoint_gets_the_hint_without_a_url() {
        let account = vallum_config::Account {
            token: Some("0123456789abcdef0123456789abcdef".to_owned()),
            endpoint: None,
        };
        let (_, detail) = super::handshake_verdict(true, Some(true), Some(&account));
        assert!(detail.contains("vallum account"), "{detail}");
        assert!(!detail.contains("/account"), "{detail}");
    }

    /// The unprobed branch lists causes in order; with an account the desk
    /// is the first cause, and `peer add` is not advised to an invite-code
    /// user. A dead path (Some(false)) is never an account's fault.
    #[test]
    fn the_unprobed_and_dead_path_branches_stay_honest_about_the_account() {
        let account = vallum_config::Account {
            token: Some("0123456789abcdef0123456789abcdef".to_owned()),
            endpoint: Some("https://desk.wingman.gold".to_owned()),
        };
        let (_, detail) = super::handshake_verdict(true, None, Some(&account));
        assert!(detail.contains("desk account"), "{detail}");
        assert!(!detail.contains("peer add"), "{detail}");
        let (_, detail) = super::handshake_verdict(true, Some(false), Some(&account));
        assert!(detail.contains("does not answer"), "{detail}");
        assert!(!detail.contains("desk account"), "{detail}");
    }
}
