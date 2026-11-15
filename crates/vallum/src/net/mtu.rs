// SPDX-License-Identifier: Apache-2.0

//! Path-MTU discovery, probing, and telemetry-driven MTU tuning.
//!
//! Split out of the carrier module because nothing here touches a socket the
//! daemon owns: it reads the routing table, shells out to `ping`, and turns
//! counters into a recommended profile. Callers keep using `crate::net::*`;
//! `net` re-exports this module.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// The path MTU the kernel currently believes leads to `endpoint`.
///
/// A connected UDP socket carries the route's MTU, so this reads the routing
/// table rather than probing: no packet is sent and no state is disturbed.
///
/// The daemon sizes its datagrams before the first handshake, and a handshake
/// cut to a budget the path cannot carry is dropped by the kernel — the tunnel
/// then never comes up at all. `interface.outer_mtu` prevents that only for an
/// operator who already knew the number, which is not the same as discovering
/// it.
#[cfg(target_os = "linux")]
/// Every IP address this host currently holds, CIDR stripped.
///
/// The same `ip -o addr` shell-out the health probes use: std has no
/// `getifaddrs`, and a wrong answer here would refuse a legitimate config.
pub fn local_addresses() -> Vec<String> {
    let output = match std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
    {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            // "2: eth0    inet 10.0.0.2/24 brd ..." — the address is the token
            // after inet/inet6.
            let mut fields = line.split_whitespace();
            let mut previous = "";
            for field in fields.by_ref() {
                if previous == "inet" || previous == "inet6" {
                    return field.split('/').next().map(str::to_owned);
                }
                previous = field;
            }
            None
        })
        .collect()
}

/// The route's MTU as the kernel reports it. `IP_MTU`/`IPV6_MTU` are Linux
/// sockopts; off Linux the callers' `Option`/`io::Result` handling already
/// treats an unsupported probe as "unknown" rather than wrong.
#[cfg(target_os = "linux")]
pub fn path_mtu(endpoint: SocketAddr) -> io::Result<u16> {
    let any = SocketAddr::new(
        if endpoint.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    let socket = UdpSocket::bind(any)?;
    socket.connect(endpoint)?;
    let mtu = if endpoint.is_ipv4() {
        rustix::net::sockopt::ip_mtu(&socket)
    } else {
        rustix::net::sockopt::ipv6_mtu(&socket)
    }
    .map_err(|e| io::Error::other(format!("path MTU: {e}")))?;
    u16::try_from(mtu).map_err(|_| io::Error::other(format!("path MTU {mtu} does not fit in u16")))
}

/// As [`path_mtu`], for a build whose kernel does not report route MTUs.
#[cfg(not(target_os = "linux"))]
pub fn path_mtu(_endpoint: SocketAddr) -> io::Result<u16> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "route MTU discovery is only implemented for Linux",
    ))
}

/// Every IP address this host holds. `getifaddrs` is the portable Unix answer;
/// the Linux version above shells out to `ip` only because it predates this.
#[cfg(not(target_os = "linux"))]
pub fn local_addresses() -> Vec<String> {
    nix::ifaddrs::getifaddrs()
        .map(|addrs| {
            addrs
                .filter_map(|a| a.address)
                .filter_map(|a| {
                    a.as_sockaddr_in()
                        .map(|s| IpAddr::V4(s.ip()))
                        .or_else(|| a.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())))
                })
                .map(|ip| ip.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The largest ICMP payload that crosses the path, by bisection.
///
/// Bisects between `min` and `max`. Nine probes at most.
pub fn bisect_mtu_bounds(min: u16, max: u16, mut fits: impl FnMut(u16) -> bool) -> Option<u16> {
    if !fits(min) {
        return None;
    }
    if fits(max) {
        return Some(max);
    }
    let mut good = min;
    let mut bad = max;
    while bad - good > 1 {
        let middle = good + (bad - good) / 2;
        if fits(middle) {
            good = middle;
        } else {
            bad = middle;
        }
    }
    Some(good)
}

/// The largest ICMP payload that crosses the path, by bisection on standard IPv4 bounds.
///
/// Bounds are the IPv4 minimum reassembly buffer (576 - 28 = 548) and a
/// 1500-byte Ethernet path (1500 - 28 = 1472). Nine probes at most.
pub fn bisect_mtu(fits: impl FnMut(u16) -> bool) -> Option<u16> {
    const MIN: u16 = 548;
    const MAX: u16 = 1472;
    bisect_mtu_bounds(MIN, MAX, fits)
}

/// Parse `mtu=<digits>` from ping output if reported by kernel or router ICMP error.
fn parse_reported_mtu(output: &str) -> Option<u16> {
    let tag = "mtu=";
    let idx = output.find(tag)?;
    let rest = &output[idx + tag.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Parse `time=<ms>` from `ping` stdout and convert it to integer microseconds.
pub fn parse_ping_rtt_micros(output: &str) -> Option<u32> {
    let tag = "time=";
    let idx = output.find(tag)?;
    let rest = output[idx + tag.len()..].trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if token.is_empty() {
        return None;
    }
    let (whole_str, frac_str) = match token.split_once('.') {
        Some((w, f)) => (w, f),
        None => (token.as_str(), ""),
    };
    let whole_ms: u32 = if whole_str.is_empty() {
        0
    } else {
        whole_str.parse().ok()?
    };
    let mut frac_digits = frac_str.bytes().filter(u8::is_ascii_digit);
    let d1 = u32::from(frac_digits.next().map_or(0, |b| b - b'0'));
    let d2 = u32::from(frac_digits.next().map_or(0, |b| b - b'0'));
    let d3 = u32::from(frac_digits.next().map_or(0, |b| b - b'0'));
    let mut frac_us = d1 * 100 + d2 * 10 + d3;
    if frac_digits.next().is_some_and(|b| b >= b'5') {
        frac_us += 1;
    }
    whole_ms.checked_mul(1_000)?.checked_add(frac_us)
}

/// Test whether an ICMP packet with `payload` bytes fits the path to `host` with DF set,
/// returning `(fits, reported_mtu, rtt_us)`.
fn default_ping_probe_with_rtt(host: &str, payload: u16) -> (bool, Option<u16>, Option<u32>) {
    let output = std::process::Command::new("ping")
        .args([
            "-M",
            "do",
            "-s",
            &payload.to_string(),
            "-c",
            "1",
            "-W",
            "1",
            host,
        ])
        .output();
    let Ok(output) = output else {
        return (false, None, None);
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        return (true, None, parse_ping_rtt_micros(&stdout));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stderr}\n{stdout}");
    (false, parse_reported_mtu(&combined), None)
}

/// Test whether an ICMP packet with `payload` bytes fits the path to `host` with DF set.
///
/// Returns `(fits, reported_mtu)`.
fn default_ping_probe(host: &str, payload: u16) -> (bool, Option<u16>) {
    let (fits, reported, _) = default_ping_probe_with_rtt(host, payload);
    (fits, reported)
}

/// Probe the path MTU to `host` using PMTUD with a custom probe function.
///
/// Returns `Some(mtu)` if the path was measured, or `None` if inconclusive (all probes failed).
pub fn probe_path_mtu_with(
    host: &str,
    is_ipv6: bool,
    mut prober: impl FnMut(&str, u16) -> (bool, Option<u16>),
) -> Option<u16> {
    let (min, max, overhead) = if is_ipv6 {
        (1232u16, 1452u16, 48u16)
    } else {
        (548u16, 1472u16, 28u16)
    };

    // 1. Probe the ceiling first (1500 byte path).
    let (fits_max, reported_mtu) = prober(host, max);
    if fits_max {
        return Some(max + overhead);
    }

    // 2. If the kernel or an intermediate router reported the next-hop MTU directly,
    // verify it with a single probe rather than bisecting.
    if let Some(reported) = reported_mtu {
        if reported >= min + overhead && reported <= max + overhead {
            let target_payload = reported - overhead;
            let (verified, _) = prober(host, target_payload);
            if verified {
                return Some(reported);
            }
        }
    }

    // 3. Probe the floor. If the minimum packet also fails, ICMP is blocked or
    // the host is unreachable.
    let (fits_min, _) = prober(host, min);
    if !fits_min {
        return None;
    }

    // 4. Bisect between min and max.
    let payload = bisect_mtu_bounds(min, max, |size| prober(host, size).0)?;
    Some(payload + overhead)
}

/// Parse a destination host string or endpoint, stripping brackets and port if present.
pub fn parse_probe_host(host_or_endpoint: &str) -> (String, bool) {
    let trimmed = host_or_endpoint.trim();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return (addr.ip().to_string(), addr.is_ipv6());
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return (ip.to_string(), ip.is_ipv6());
    }
    if trimmed.starts_with('[') {
        if let Some(end) = trimmed.find(']') {
            let inner = &trimmed[1..end];
            return (inner.to_owned(), true);
        }
    }
    if let Some((h, _)) = trimmed.split_once(':') {
        if !h.contains(':') {
            return (h.to_owned(), false);
        }
    }
    let is_v6 = trimmed.contains(':');
    (trimmed.to_owned(), is_v6)
}

/// Probe the path MTU to an IP address / socket destination.
pub fn probe_path_mtu(destination: SocketAddr) -> Option<u16> {
    probe_path_mtu_with(
        &destination.ip().to_string(),
        destination.is_ipv6(),
        within_budget(default_ping_probe),
    )
}

/// Total time a path-MTU probe may spend before settling for what it has proved.
///
/// Each ICMP probe costs up to a second when the path silently swallows it, and
/// the bisection needs about ten. `run` probes before the TUN interface exists,
/// so an unreachable endpoint would otherwise delay every daemon start by ~10 s,
/// and N endpoints by N times that — against systemd's 90 s `TimeoutStartSec`.
///
/// When the budget runs out the prober stops probing and reports "does not
/// fit", so the bisection converges on the largest size it actually confirmed.
/// Conservative, and never a stall: an unmeasured path keeps the configured
/// default rather than blocking the interface from coming up.
pub const PROBE_BUDGET: Duration = Duration::from_secs(3);

fn within_budget(
    prober: impl FnMut(&str, u16) -> (bool, Option<u16>),
) -> impl FnMut(&str, u16) -> (bool, Option<u16>) {
    within_budget_with(PROBE_BUDGET, prober)
}

pub(super) fn within_budget_with(
    budget: Duration,
    mut prober: impl FnMut(&str, u16) -> (bool, Option<u16>),
) -> impl FnMut(&str, u16) -> (bool, Option<u16>) {
    let start = Instant::now();
    move |host, payload| {
        if start.elapsed() >= budget {
            return (false, None);
        }
        prober(host, payload)
    }
}

/// Probe the path MTU to a host name, IP, or endpoint string.
pub fn probe_path_mtu_host(host_or_endpoint: &str) -> Option<u16> {
    let (host, is_ipv6) = parse_probe_host(host_or_endpoint);
    probe_path_mtu_with(&host, is_ipv6, within_budget(default_ping_probe))
}

/// Standard outer encapsulation overhead (IPv4/UDP + Vallum transport header + AEAD tag)
/// mapping `1420` inner MTU to `1484` outer wire MTU.
pub const WIRE_ENCAP_OVERHEAD: u16 = 64;

/// Operating profile selected by the telemetry-driven adaptive MTU optimizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuProfile {
    /// `1280` inner MTU: minimizes tail jitter and buffer straddling on USB Ethernet,
    /// Wi-Fi, cellular, or lossy driver paths.
    LowJitterUsb1280,
    /// `1380` inner MTU: balances ~1300-byte real-time game/voice UDP datagrams with
    /// outer headroom against path fragmentation.
    GamingLowFrag1380,
    /// `1420` inner MTU: maximizes bulk TCP/UDP goodput on clean, low-jitter paths.
    BulkStandard1420,
    /// Path MTU ceiling is below `1344`, forcing the inner MTU down to fit.
    ConstrainedPath,
}

impl MtuProfile {
    /// Machine-readable identifier emitted in `doctor --json` and telemetry logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LowJitterUsb1280 => "low-jitter-1280",
            Self::GamingLowFrag1380 => "gaming-pq-1380",
            Self::BulkStandard1420 => "bulk-1420",
            Self::ConstrainedPath => "constrained-path",
        }
    }
}

/// Measured latency, jitter, and loss metrics for a candidate inner/outer MTU pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuCandidateSample {
    pub inner_mtu: u16,
    pub outer_mtu: u16,
    pub rtt_p50_us: u32,
    pub rtt_jitter_us: u32,
    pub loss_pct: u8,
}

/// Output of the adaptive MTU optimizer, including MSS alignment for JA4T/TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuTuneRecommendation {
    pub ceiling_outer_mtu: u16,
    pub recommended_inner_mtu: u16,
    pub recommended_outer_mtu: u16,
    pub ipv4_tcp_mss: u16,
    pub ipv6_tcp_mss: u16,
    pub profile: MtuProfile,
    pub samples: Vec<MtuCandidateSample>,
    pub rationale: String,
}

fn build_recommendation(
    ceiling_outer_mtu: u16,
    inner_mtu: u16,
    profile: MtuProfile,
    samples: Vec<MtuCandidateSample>,
    rationale: String,
) -> MtuTuneRecommendation {
    let outer_mtu = inner_mtu.saturating_add(WIRE_ENCAP_OVERHEAD);
    MtuTuneRecommendation {
        ceiling_outer_mtu,
        recommended_inner_mtu: inner_mtu,
        recommended_outer_mtu: outer_mtu,
        ipv4_tcp_mss: inner_mtu.saturating_sub(40),
        ipv6_tcp_mss: inner_mtu.saturating_sub(60),
        profile,
        samples,
        rationale,
    }
}

/// Score measured candidate MTU probes alongside live fragmentation counters
/// (`fragments_dropped`, `reassembled`, `packets_delivered`) to recommend an optimal MTU.
#[must_use]
pub fn recommend_mtu_from_telemetry(
    ceiling_outer_mtu: u16,
    samples: &[MtuCandidateSample],
    fragments_dropped: u64,
    reassembled: u64,
    packets_delivered: u64,
) -> MtuTuneRecommendation {
    let owned_samples = samples.to_vec();
    let min_standard_outer = 1280u16.saturating_add(WIRE_ENCAP_OVERHEAD);
    if ceiling_outer_mtu < min_standard_outer {
        let clamped_inner = ceiling_outer_mtu
            .saturating_sub(WIRE_ENCAP_OVERHEAD)
            .max(576);
        return build_recommendation(
            ceiling_outer_mtu,
            clamped_inner,
            MtuProfile::ConstrainedPath,
            owned_samples,
            format!(
                "path ceiling {ceiling_outer_mtu} B is below {min_standard_outer} B; \
                 clamping inner MTU to {clamped_inner}"
            ),
        );
    }

    let usable: Vec<&MtuCandidateSample> = samples
        .iter()
        .filter(|s| s.outer_mtu <= ceiling_outer_mtu && s.loss_pct < 100)
        .collect();

    let s1280 = usable.iter().copied().find(|s| s.inner_mtu == 1280);
    let s1380 = usable.iter().copied().find(|s| s.inner_mtu == 1380);
    let s1420 = usable.iter().copied().find(|s| s.inner_mtu == 1420);

    let frag_pressure = fragments_dropped > 0
        || (packets_delivered > 0 && reassembled.saturating_mul(100) / packets_delivered >= 2);

    // USB Ethernet URB straddling or driver buffer pressure shows up as packet loss
    // or a >1.0 ms (>2x baseline) tail jitter jump at larger frame sizes vs 1280.
    let larger_lossy = [s1380, s1420].into_iter().flatten().any(|s| s.loss_pct > 0)
        && s1280.is_some_and(|s| s.loss_pct == 0);
    let larger_jitter_spike = s1280.is_some_and(|base| {
        let spike_threshold = base
            .rtt_jitter_us
            .saturating_add(1_000)
            .max(base.rtt_jitter_us.saturating_mul(2).saturating_add(300));
        [s1380, s1420]
            .into_iter()
            .flatten()
            .any(|larger| larger.rtt_jitter_us > spike_threshold)
    });

    if larger_lossy || larger_jitter_spike {
        return build_recommendation(
            ceiling_outer_mtu,
            1280,
            MtuProfile::LowJitterUsb1280,
            owned_samples,
            "1280 MTU eliminates larger-frame jitter spikes / loss (USB NIC URB or access link profile)"
                .to_owned(),
        );
    }

    let fit_1420 = ceiling_outer_mtu >= 1420 + WIRE_ENCAP_OVERHEAD;
    let fit_1380 = ceiling_outer_mtu >= 1380 + WIRE_ENCAP_OVERHEAD;
    let degraded_1420 = s1420.is_some_and(|s| s.loss_pct > 0)
        || (s1380.is_some()
            && s1420.is_some_and(|l| {
                let b = s1380.map_or(0, |s| s.rtt_jitter_us);
                l.rtt_jitter_us > b.saturating_add(1_000)
            }));

    if fit_1380 && (frag_pressure || !fit_1420 || degraded_1420) {
        let reason = if frag_pressure {
            "inner fragmentation/reassembly pressure detected; 1380 keeps ~1300B gaming/UDP frames unfragmented"
        } else if !fit_1420 {
            "path ceiling fits 1380 (1444B outer) without hitting 1484B overflow"
        } else {
            "1380 delivers lower tail jitter than 1420 while preserving gaming UDP headroom"
        };
        return build_recommendation(
            ceiling_outer_mtu,
            1380,
            MtuProfile::GamingLowFrag1380,
            owned_samples,
            reason.to_owned(),
        );
    }

    if !fit_1380 && ceiling_outer_mtu >= 1340 + WIRE_ENCAP_OVERHEAD {
        return build_recommendation(
            ceiling_outer_mtu,
            1340,
            MtuProfile::GamingLowFrag1380,
            owned_samples,
            "path ceiling fits 1340 (1404B outer) for PPPoE/cellular links without fragmenting"
                .to_owned(),
        );
    }

    if fit_1420 {
        return build_recommendation(
            ceiling_outer_mtu,
            1420,
            MtuProfile::BulkStandard1420,
            owned_samples,
            "clean low-jitter path with negligible inner fragmentation favors 1420 bulk goodput"
                .to_owned(),
        );
    }

    build_recommendation(
        ceiling_outer_mtu,
        1280,
        MtuProfile::LowJitterUsb1280,
        owned_samples,
        "selecting 1280 safe baseline within path MTU ceiling".to_owned(),
    )
}

fn tune_path_mtu_with_counters_and_overhead(
    ceiling_outer_mtu: u16,
    icmp_overhead: u16,
    fragments_dropped: u64,
    reassembled: u64,
    packets_delivered: u64,
    mut probe_rtt_us: impl FnMut(u16) -> Option<u32>,
) -> MtuTuneRecommendation {
    let mut samples = Vec::new();
    if ceiling_outer_mtu >= 1280 + WIRE_ENCAP_OVERHEAD {
        for inner_mtu in [1280u16, 1380, 1420] {
            let outer_mtu = inner_mtu.saturating_add(WIRE_ENCAP_OVERHEAD);
            if outer_mtu > ceiling_outer_mtu {
                continue;
            }
            let payload = outer_mtu.saturating_sub(icmp_overhead);
            let mut rtts = Vec::with_capacity(3);
            let mut lost = 0u8;
            for _ in 0..3 {
                match probe_rtt_us(payload) {
                    Some(rtt) => rtts.push(rtt),
                    None => lost += 1,
                }
            }
            rtts.sort_unstable();
            let loss_pct = ((u16::from(lost) * 100) / 3) as u8;
            let (rtt_p50_us, rtt_jitter_us) = if rtts.is_empty() {
                (0, 0)
            } else {
                let p50 = rtts[rtts.len() / 2];
                let min = rtts[0];
                let max = rtts[rtts.len() - 1];
                (p50, max.saturating_sub(min))
            };
            samples.push(MtuCandidateSample {
                inner_mtu,
                outer_mtu,
                rtt_p50_us,
                rtt_jitter_us,
                loss_pct,
            });
        }
    }
    recommend_mtu_from_telemetry(
        ceiling_outer_mtu,
        &samples,
        fragments_dropped,
        reassembled,
        packets_delivered,
    )
}

/// Sweep candidate MTUs (`1280`, `1380`, `1420`) capped by `ceiling_outer_mtu` using
/// a caller-supplied IPv4 ICMP payload RTT prober (`payload -> Option<rtt_us>`).
pub fn tune_path_mtu_with(
    ceiling_outer_mtu: u16,
    probe_rtt_us: impl FnMut(u16) -> Option<u32>,
) -> MtuTuneRecommendation {
    tune_path_mtu_with_counters_and_overhead(ceiling_outer_mtu, 28, 0, 0, 0, probe_rtt_us)
}

/// Discover the path MTU ceiling to `host_or_endpoint`, sweep candidate payloads, and
/// combine with live UAPI fragmentation counters (`fragments_dropped`, `reassembled`,
/// `packets_delivered`) to return a closed-loop MTU profile recommendation.
pub fn tune_path_mtu_host_with_counters(
    host_or_endpoint: &str,
    fragments_dropped: u64,
    reassembled: u64,
    packets_delivered: u64,
) -> Option<MtuTuneRecommendation> {
    let ceiling_outer_mtu = probe_path_mtu_host(host_or_endpoint)?;
    let (host, is_ipv6) = parse_probe_host(host_or_endpoint);
    let icmp_overhead = if is_ipv6 { 48 } else { 28 };
    let started = Instant::now();
    Some(tune_path_mtu_with_counters_and_overhead(
        ceiling_outer_mtu,
        icmp_overhead,
        fragments_dropped,
        reassembled,
        packets_delivered,
        |payload| {
            if started.elapsed() >= PROBE_BUDGET {
                return None;
            }
            let (fits, _, rtt_us) = default_ping_probe_with_rtt(&host, payload);
            if fits {
                Some(rtt_us.unwrap_or(500))
            } else {
                None
            }
        },
    ))
}

/// Discover the path MTU ceiling to `host_or_endpoint`, sweep candidate payloads, and
/// return a telemetry-backed MTU profile recommendation.
pub fn tune_path_mtu_host(host_or_endpoint: &str) -> Option<MtuTuneRecommendation> {
    tune_path_mtu_host_with_counters(host_or_endpoint, 0, 0, 0)
}
