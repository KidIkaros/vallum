#![allow(clippy::expect_used, clippy::unwrap_used)]
// SPDX-License-Identifier: Apache-2.0

//! Cryptokey routing through the public event/action API.
//!
//! These were unit tests on `Device::route`, which is private. Driving an
//! outbound packet and observing the `Action` is the same assertion from
//! outside, and it is the surface a caller actually uses.

use std::net::SocketAddr;
use std::sync::Arc;

use vallum_core::identity::StaticIdentity;
use vallum_core::Tai64n;
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;
use vallum_tunnel::{Action, Clock, Device, Event, PeerConfig, Randomness};

struct ZeroRng;

impl Randomness for ZeroRng {
    fn fill(&mut self, out: &mut [u8]) {
        out.fill(0);
    }
}

fn ipv4(destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[12..16].copy_from_slice(&[10, 7, 0, 1]);
    packet[16..20].copy_from_slice(&destination);
    packet
}

fn device(allowed: &[&str], endpoint: SocketAddr) -> (Device, ZeroRng) {
    let suite: Arc<dyn CryptoSuite> = Arc::new(SdkSuite::tri_hybrid());
    let me = StaticIdentity::generate(&*suite, &[0x01; 32]).expect("identity");
    let peer = StaticIdentity::generate(&*suite, &[0x02; 32]).expect("identity");
    let config = PeerConfig::new("peer", peer.to_peer())
        .with_allowed_ips(allowed.iter().map(|net| net.parse().expect("a prefix")))
        .with_endpoint(endpoint);
    let mut rng = ZeroRng;
    let device = Device::new(suite, me, vec![config], &mut rng, 0).expect("device");
    (device, rng)
}

fn sends_to(device: &mut Device, rng: &mut ZeroRng, packet: Vec<u8>, endpoint: SocketAddr) -> bool {
    let clock = Clock::new(0, Tai64n::ZERO);
    device
        .handle(clock, Event::OutboundIp { packet }, rng)
        .iter()
        .any(
            |action| matches!(action, Action::Send { destination, .. } if *destination == endpoint),
        )
}

/// One packet on a fresh device: the first outbound packet starts a handshake,
/// and a second would queue behind it rather than produce a second `Send`.
fn routes_v4(allowed: &[&str], destination: [u8; 4]) -> bool {
    let endpoint: SocketAddr = "203.0.113.9:51820".parse().expect("an endpoint");
    let (mut device, mut rng) = device(allowed, endpoint);
    sends_to(&mut device, &mut rng, ipv4(destination), endpoint)
}

#[test]
fn a_default_route_peer_owns_every_v4_destination() {
    assert!(routes_v4(&["0.0.0.0/0"], [8, 8, 8, 8]));
    assert!(routes_v4(&["0.0.0.0/0"], [224, 0, 0, 1]));

    // A v4 default route does not claim v6: a v6 packet produces no action.
    let endpoint: SocketAddr = "203.0.113.9:51820".parse().expect("an endpoint");
    let (mut device, mut rng) = device(&["0.0.0.0/0"], endpoint);
    let mut v6 = vec![0u8; 40];
    v6[0] = 0x60;
    v6[24..40].copy_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert!(!sends_to(&mut device, &mut rng, v6, endpoint));
}

#[test]
fn multicast_and_broadcast_destinations_route_to_a_peer_that_owns_them() {
    // A multicast group and a LAN's broadcast address are ordinary prefix
    // matches; nothing special-cases them, which is the point.
    assert!(routes_v4(&["224.0.0.0/4", "10.7.0.0/24"], [224, 0, 0, 1]));
    assert!(routes_v4(
        &["224.0.0.0/4", "10.7.0.0/24"],
        [239, 255, 255, 250]
    ));
    assert!(routes_v4(&["224.0.0.0/4", "10.7.0.0/24"], [10, 7, 0, 255]));
    assert!(!routes_v4(&["224.0.0.0/4", "10.7.0.0/24"], [10, 8, 0, 1]));
}
