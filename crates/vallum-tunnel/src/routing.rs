// SPDX-License-Identifier: Apache-2.0

//! Cryptokey routing: which peer may speak for which addresses.
//!
//! WireGuard's central idea is that the peer table *is* the routing table. A
//! peer's `allowed_ips` are both the destinations we send to it and the source
//! addresses we accept from it, and the two are checked in opposite directions:
//!
//! | direction | check | why |
//! |-----------|-------|-----|
//! | outbound | `packet.dst ∈ allowed_ips` | the packet goes to the one peer that claims the destination |
//! | inbound | `packet.src ∈ allowed_ips` | *this* is the anti-spoofing rule: a peer that can encrypt cannot thereby claim an address it was not given |
//!
//! The inbound check is the one that matters. Without it, any peer could inject
//! traffic that appears to come from every other host in the network, and the
//! tunnel would be a source-address forgery machine.
//!
//! Prefix matching is delegated to [`ipnet`]. The alternative — hand-rolled CIDR
//! comparison in the code that decides where a packet goes — is exactly the kind
//! of "obviously correct" arithmetic that turns into a routing bug, and a routing
//! bug in a VPN is a security bug.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use ipnet::IpNet;

/// The set of addresses one peer is responsible for.
///
/// An empty set is legal and means "this peer may not originate traffic and has
/// no destinations" — a peer configured only to *be* dialled, or a peer whose
/// addresses have not been filled in yet. It is not an error, because a peer with
/// an empty set can still complete a handshake; it just carries no packets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowedIps {
    nets: Vec<IpNet>,
}

impl AllowedIps {
    /// Build from a list of prefixes.
    #[must_use]
    pub fn new(nets: Vec<IpNet>) -> Self {
        Self { nets }
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// The prefixes, in configuration order.
    #[must_use]
    pub fn nets(&self) -> &[IpNet] {
        &self.nets
    }

    /// Whether `ip` falls inside any prefix.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(ip))
    }

    /// Whether any prefix here overlaps any prefix in `other`.
    ///
    /// Overlap is a **configuration error**, not a tie to be broken: two peers
    /// claiming the same address is either a mistake or an attempt to shadow one
    /// peer with another, and resolving it by configuration order would make
    /// routing depend on file order. [`crate::Device::new`] refuses it.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> Option<IpNet> {
        for left in &self.nets {
            for right in &other.nets {
                if let Some(net) = intersection(left, right) {
                    return Some(net);
                }
            }
        }
        None
    }
}

impl FromIterator<IpNet> for AllowedIps {
    fn from_iter<I: IntoIterator<Item = IpNet>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

impl IntoIterator for AllowedIps {
    type Item = IpNet;
    type IntoIter = std::vec::IntoIter<IpNet>;

    fn into_iter(self) -> Self::IntoIter {
        self.nets.into_iter()
    }
}

/// The overlap of two prefixes, if any.
///
/// Only same-family prefixes can overlap; a v4 prefix and a v6 prefix are
/// disjoint by construction, which is also why an `Ipv4Net` and an
/// `Ipv6Net` never conflict in the peer table.
fn intersection(left: &IpNet, right: &IpNet) -> Option<IpNet> {
    // Both operands are *networks* — their host bits are zero — so two prefixes
    // overlap exactly when the narrower one's base address lies in the broader
    // one. One containment test, no arithmetic.
    match (left, right) {
        (IpNet::V4(a), IpNet::V4(b)) => {
            let (broad, narrow) = if a.prefix_len() <= b.prefix_len() {
                (a, b)
            } else {
                (b, a)
            };
            broad
                .contains(&narrow.network())
                .then_some(IpNet::V4(*narrow))
        }
        (IpNet::V6(a), IpNet::V6(b)) => {
            let (broad, narrow) = if a.prefix_len() <= b.prefix_len() {
                (a, b)
            } else {
                (b, a)
            };
            broad
                .contains(&narrow.network())
                .then_some(IpNet::V6(*narrow))
        }
        _ => None,
    }
}

/// The source address of a layer-3 packet, if it is an IPv4 or IPv6 packet.
///
/// Returns `None` for anything that is not a well-formed IP header — a truncated
/// packet, a non-IP protocol, or a version nibble that does not match the
/// header's length. The caller drops what it cannot classify; a tunnel has no
/// business inventing an interpretation for bytes it cannot parse.
#[must_use]
pub fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    addresses(packet).map(|(source, _)| source)
}

/// The destination address of a layer-3 packet. See [`packet_source`].
#[must_use]
pub fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    addresses(packet).map(|(_, destination)| destination)
}

/// Extract `(source, destination)` from a raw IPv4 or IPv6 packet.
///
/// This is the whole of Vallum's IP parsing. It reads two fixed fields at fixed
/// offsets and validates the version and the header length; it does not
/// reassemble, fragment, or interpret options. A malformed packet is `None`.
fn addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let version = *packet.first()? >> 4;
    match version {
        4 => {
            // The IPv4 header is at least 20 bytes, and `ihl` may extend it with
            // options — which shift nothing we read, but may not *shorten* it.
            let ihl = usize::from(packet.first()? & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Some((IpAddr::V4(source), IpAddr::V4(destination)))
        }
        6 => {
            // Fixed 40-byte header; extension headers sit behind the addresses,
            // so the offsets never move.
            if packet.len() < 40 {
                return None;
            }
            let mut source = [0u8; 16];
            source.copy_from_slice(&packet[8..24]);
            let mut destination = [0u8; 16];
            destination.copy_from_slice(&packet[24..40]);
            Some((
                IpAddr::V6(Ipv6Addr::from(source)),
                IpAddr::V6(Ipv6Addr::from(destination)),
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn net(s: &str) -> IpNet {
        IpNet::from_str(s).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn ip6(s: &str) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from_str(s).unwrap()
    }

    #[test]
    fn membership_is_by_prefix_not_by_string() {
        let allowed = AllowedIps::new(vec![net("10.0.0.0/8"), net("2001:db8::/32")]);
        assert!(allowed.contains(&ip("10.255.255.255")));
        assert!(!allowed.contains(&ip("11.0.0.0")));
        assert!(allowed.contains(&ip("2001:db8:1::1")));
        assert!(!allowed.contains(&ip("2001:db9::1")));
    }

    #[test]
    fn an_empty_set_claims_nothing() {
        let allowed = AllowedIps::default();
        assert!(allowed.is_empty());
        assert!(!allowed.contains(&ip("10.0.0.1")));
    }

    #[test]
    fn overlap_is_detected_in_both_nesting_directions() {
        // The broader prefix swallows the narrower one.
        assert!(AllowedIps::new(vec![net("10.0.0.0/8")])
            .overlaps(&AllowedIps::new(vec![net("10.1.0.0/16")]))
            .is_some());
        // ...and the argument order does not matter.
        assert!(AllowedIps::new(vec![net("10.1.0.0/16")])
            .overlaps(&AllowedIps::new(vec![net("10.0.0.0/8")]))
            .is_some());
        // Identical prefixes overlap.
        assert!(AllowedIps::new(vec![net("10.0.0.0/8")])
            .overlaps(&AllowedIps::new(vec![net("10.0.0.0/8")]))
            .is_some());
    }

    #[test]
    fn disjoint_prefixes_and_families_do_not_overlap() {
        assert!(AllowedIps::new(vec![net("10.0.0.0/16")])
            .overlaps(&AllowedIps::new(vec![net("10.1.0.0/16")]))
            .is_none());
        // A v4 prefix and a v6 prefix can never conflict.
        assert!(AllowedIps::new(vec![net("10.0.0.0/8")])
            .overlaps(&AllowedIps::new(vec![net("2001:db8::/32")]))
            .is_none());
    }

    #[test]
    fn a_v4_packet_yields_its_addresses() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // version 4, ihl 5
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        assert_eq!(packet_source(&packet), Some(ip("10.0.0.1")));
        assert_eq!(packet_destination(&packet), Some(ip("10.0.0.2")));
    }

    #[test]
    fn ipv4_options_do_not_shift_the_addresses() {
        let mut packet = vec![0u8; 24];
        packet[0] = 0x46; // version 4, ihl 6 => 24 bytes
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        assert_eq!(packet_source(&packet), Some(ip("10.0.0.1")));
    }

    #[test]
    fn a_bogus_ihl_or_a_truncated_header_is_not_parsed() {
        // ihl 0 is impossible; a header that claims to be longer than it is.
        let mut packet = vec![0u8; 20];
        packet[0] = 0x40;
        assert!(packet_source(&packet).is_none());
        packet[0] = 0x45;
        assert!(packet_source(&packet[..19]).is_none());
        assert!(packet_source(&[]).is_none());
    }

    #[test]
    fn a_v6_packet_yields_its_addresses() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[8..24].copy_from_slice(&ip6("2001:db8::1").octets());
        packet[24..40].copy_from_slice(&ip6("2001:db8::2").octets());
        assert_eq!(packet_source(&packet), Some(ip("2001:db8::1")));
        assert_eq!(packet_destination(&packet), Some(ip("2001:db8::2")));
        assert!(packet_source(&packet[..39]).is_none());
    }

    #[test]
    fn a_non_ip_packet_is_not_interpreted() {
        // Version 5 does not exist; version 0 is reserved.
        let packet = vec![0x50u8; 40];
        assert!(packet_source(&packet).is_none());
    }

    #[test]
    fn a_default_route_covers_every_v4_destination() {
        // The full-tunnel case: one peer owns the whole v4 space. `ipnet`'s /0
        // containment is the whole mechanism, and the family is not crossed.
        let all = AllowedIps::new(vec![net("0.0.0.0/0")]);
        assert!(all.contains(&ip("10.7.0.2")));
        assert!(all.contains(&ip("224.0.0.1")));
        assert!(all.contains(&ip("255.255.255.255")));
        assert!(!all.contains(&ip("2001:db8::1")));
    }

    #[test]
    fn multicast_and_broadcast_destinations_are_matched_by_prefix() {
        // A peer may be granted a multicast group or a LAN's broadcast address;
        // nothing in the routing layer special-cases them, which is the point.
        let multicast = AllowedIps::new(vec![net("224.0.0.0/4")]);
        assert!(multicast.contains(&ip("224.0.0.1")));
        assert!(multicast.contains(&ip("239.255.255.250")));
        assert!(!multicast.contains(&ip("10.0.0.1")));

        let lan = AllowedIps::new(vec![net("10.7.0.0/24")]);
        assert!(lan.contains(&ip("10.7.0.0")));
        assert!(lan.contains(&ip("10.7.0.255")));
        assert!(!lan.contains(&ip("10.7.1.0")));
    }
}
