// SPDX-License-Identifier: Apache-2.0

//! Resolver policy: which configured resolvers are LAN-local and which belong
//! in the tunnel, which names are local, and whether the tunnel is IPv4-only.
//! Pure decisions over addresses and config; no I/O.

use std::net::IpAddr;

use vallum_config::Config;
use vallum_core::Prefix;

/// Returns `true` when `ip` is a private/link-local LAN resolver address
/// (RFC 1918 / RFC 3927 / RFC 4193 / fe80::/10).
///
/// Specifically excludes CGNAT `100.64.0.0/10` (used by Vallum's `100.64.0.X`
/// server-side content-blocker resolvers), keeping those in the tunnel.
#[must_use]
pub(crate) fn is_private_lan_resolver(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            // fc00::/7 ULA or fe80::/10 link-local unicast.
            (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

/// Split configured DNS server strings into `(tunnel_resolvers, lan_resolvers)`.
///
/// Invalid IP strings are ignored. When `allow_lan` is `true`, RFC1918 / ULA /
/// link-local resolvers go to `lan_resolvers` while CGNAT magic resolvers and
/// public resolvers stay in `tunnel_resolvers`. When `allow_lan` is `false`, all
/// valid resolvers stay in `tunnel_resolvers`.
#[must_use]
pub(crate) fn split_resolvers(servers: &[String], allow_lan: bool) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let mut tunnel = Vec::new();
    let mut lan = Vec::new();
    for raw in servers {
        if let Ok(ip) = raw.trim().parse::<IpAddr>() {
            if allow_lan && is_private_lan_resolver(ip) {
                lan.push(ip);
            } else {
                tunnel.push(ip);
            }
        }
    }
    (tunnel, lan)
}

/// Returns `true` for hostnames that belong exclusively to a local LAN naming
/// scope (`localhost`, `.local`, `.lan`, `.home.arpa`, `.internal`, `.intranet`,
/// `.corp`).
#[must_use]
pub(crate) fn is_local_domain(qname: &str) -> bool {
    let trimmed = qname.trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    trimmed == "localhost"
        || trimmed == "local"
        || trimmed.ends_with(".local")
        || trimmed.ends_with(".lan")
        || trimmed.ends_with(".home.arpa")
        || trimmed.ends_with(".internal")
        || trimmed.ends_with(".intranet")
        || trimmed.ends_with(".corp")
}

/// Returns `true` when the tunnel carries IPv4 routes/addresses without any IPv6
/// address or `allowed_ips` prefix, enabling zero-leak `AAAA` `NODATA` replies.
#[must_use]
pub(crate) fn tunnel_is_ipv4_only(config: &Config) -> bool {
    let mut saw_v4 = false;
    let mut saw_v6 = false;

    for raw in config
        .interface
        .address
        .iter()
        .chain(config.interface.addresses.iter())
        .chain(config.peers.iter().flat_map(|peer| peer.allowed_ips.iter()))
    {
        if let Ok(prefix) = raw.parse::<Prefix>() {
            match prefix.as_ipnet().addr() {
                IpAddr::V4(_) => saw_v4 = true,
                IpAddr::V6(_) => saw_v6 = true,
            }
        } else if let Ok(ip) = raw.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(_) => saw_v4 = true,
                IpAddr::V6(_) => saw_v6 = true,
            }
        }
    }

    saw_v4 && !saw_v6
}
