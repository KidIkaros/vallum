// SPDX-License-Identifier: Apache-2.0

//! An IP prefix, as a value the whole workspace shares.
//!
//! This lives here rather than in the tunnel crate because it is a *value*: the
//! supervisor needs it to compare an address against what an interface owns,
//! and nothing about that is protocol-specific. Keeping it in `vallum-tunnel`
//! made every consumer depend on the entire handshake and device stack to name
//! a CIDR.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// An IP prefix, as the peer table stores it.
///
/// A newtype rather than a re-export: `ipnet` is an implementation detail of
/// this crate, so the public API does not change if it is replaced. The daemon
/// still needs the underlying `IpNet` for netlink, which is what
/// [`Prefix::as_ipnet`] is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix(IpNet);

impl Prefix {
    /// Wrap an `IpNet`.
    #[must_use]
    pub fn new(net: IpNet) -> Self {
        Self(net)
    }

    /// The underlying `IpNet`, for the daemon's netlink path.
    #[must_use]
    pub fn as_ipnet(&self) -> IpNet {
        self.0
    }

    /// Whether `ip` falls inside this prefix.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.0.contains(ip)
    }

    /// The prefix length, in bits.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.0.prefix_len()
    }

    /// The network address.
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.0.addr()
    }

    /// The netmask.
    #[must_use]
    pub fn netmask(&self) -> IpAddr {
        self.0.netmask()
    }

    /// The overlap with `other`, if any.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> Option<Self> {
        intersection(&self.0, &other.0).map(Self)
    }
}

impl From<IpNet> for Prefix {
    fn from(net: IpNet) -> Self {
        Self(net)
    }
}

impl From<Prefix> for IpNet {
    fn from(prefix: Prefix) -> Self {
        prefix.0
    }
}

impl FromStr for Prefix {
    type Err = ipnet::AddrParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse::<IpNet>().map(Self)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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
