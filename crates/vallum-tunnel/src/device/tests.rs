use super::data::pad_target;
use super::handshake::client_bytes;
use super::*;
use vallum_crypto_sdk::SdkSuite;

#[test]
fn client_encoding_distinguishes_address_and_port() {
    let a: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let b: SocketAddr = "10.0.0.1:1001".parse().unwrap();
    let c: SocketAddr = "10.0.0.2:1000".parse().unwrap();
    assert_ne!(client_bytes(a), client_bytes(b));
    assert_ne!(client_bytes(a), client_bytes(c));
    assert_ne!(client_bytes(a), client_bytes(c));
    // Same address and port, same encoding — the ciphertext is keyed by it.
    assert_eq!(client_bytes(a), client_bytes(a));
}

#[test]
fn a_default_route_peer_owns_every_v4_destination() {
    // The full-tunnel case: one peer is granted `0.0.0.0/0`. The device
    // cannot also hold a more specific peer — overlapping `allowed_ips` are
    // refused at construction — so the routing answer is unambiguous.
    struct ZeroRng;
    impl Randomness for ZeroRng {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(0);
        }
    }

    let suite: Arc<dyn CryptoSuite> = Arc::new(SdkSuite::tri_hybrid());
    let me = StaticIdentity::generate(&*suite, &[0x01; 32]).expect("identity");
    let peer = StaticIdentity::generate(&*suite, &[0x02; 32]).expect("identity");
    let config = PeerConfig::new("all", peer.to_peer())
        .with_allowed_ips(["0.0.0.0/0".parse().expect("a v4 default route")]);
    let mut rng = ZeroRng;
    let device = Device::new(suite, me, vec![config], &mut rng, 0).expect("device");

    assert_eq!(device.route(&"10.7.0.2".parse().unwrap()), Some(0));
    assert_eq!(device.route(&"224.0.0.1".parse().unwrap()), Some(0));
    // A v4 default route does not claim v6.
    assert_eq!(device.route(&"2001:db8::1".parse().unwrap()), None);
}

#[test]
fn multicast_and_broadcast_destinations_route_to_a_peer_that_owns_them() {
    struct ZeroRng;
    impl Randomness for ZeroRng {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(0);
        }
    }

    let suite: Arc<dyn CryptoSuite> = Arc::new(SdkSuite::tri_hybrid());
    let me = StaticIdentity::generate(&*suite, &[0x03; 32]).expect("identity");
    let peer = StaticIdentity::generate(&*suite, &[0x04; 32]).expect("identity");
    let config = PeerConfig::new("lan", peer.to_peer()).with_allowed_ips([
        "224.0.0.0/4".parse().expect("a multicast prefix"),
        "10.7.0.0/24".parse().expect("a LAN prefix"),
    ]);
    let mut rng = ZeroRng;
    let device = Device::new(suite, me, vec![config], &mut rng, 0).expect("device");

    // A multicast group and a LAN's broadcast address are ordinary prefix
    // matches; nothing special-cases them, which is the point.
    assert_eq!(device.route(&"224.0.0.1".parse().unwrap()), Some(0));
    assert_eq!(device.route(&"239.255.255.250".parse().unwrap()), Some(0));
    assert_eq!(device.route(&"10.7.0.255".parse().unwrap()), Some(0));
    assert_eq!(device.route(&"10.8.0.1".parse().unwrap()), None);
}

#[test]
fn pad_target_takes_the_largest_of_several_machines() {
    let effects = vec![
        Effect {
            machine: 0,
            action: ShapingAction::Pad { target: 512 },
        },
        Effect {
            machine: 1,
            action: ShapingAction::Pad { target: 1400 },
        },
        Effect {
            machine: 2,
            action: ShapingAction::Block { timeout_ms: 10 },
        },
    ];
    assert_eq!(pad_target(&effects), Some(1400));
    assert_eq!(pad_target(&[]), None);
}
