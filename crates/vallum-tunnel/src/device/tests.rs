use super::data::pad_target;
use super::handshake::client_bytes;
use super::*;

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

/// A deterministic source, acceptable here because the test needs reproducibility
/// rather than unpredictability (`rng.rs` says so explicitly).
struct ZeroRng;

impl Randomness for ZeroRng {
    fn fill(&mut self, out: &mut [u8]) {
        out.fill(0);
    }
}

/// A rotation moves the peer's *current* hint, not only its window.
///
/// Measured on the real link: `peer rotate` + `peer finalize` left the daemon
/// with the replaced key's hint, so the rotated peer's handshake resolved to no
/// row and was dropped in silence — the tunnel kept working on its existing
/// session until the next rekey, then never came back. The fresh daemon that
/// reads the same config worked, which is what made it look like a crypto
/// problem instead of a projection that was never rebuilt.
#[test]
fn a_finalized_rotation_resolves_the_new_key_and_forgets_the_old() {
    let suite: Arc<dyn CryptoSuite> = Arc::new(vallum_crypto_sdk::SdkSuite::tri_hybrid());
    let me = StaticIdentity::generate(&*suite, &[0x01; 32]).expect("our identity");
    let old = StaticIdentity::generate(&*suite, &[0x02; 32]).expect("the replaced identity");
    let new = StaticIdentity::generate(&*suite, &[0x03; 32]).expect("the rotated identity");
    let hint_of = |identity: &StaticIdentity| peer_hint(&*suite, identity.public());

    let mut device = Device::new(
        Arc::clone(&suite),
        me,
        vec![PeerConfig::new("laptop", old.to_peer())],
        &mut ZeroRng,
        0,
    )
    .expect("device");
    let id = device.peers().next().expect("one peer").0;
    assert_eq!(device.peer_with_hint(&hint_of(&old)), Some((0, 0)));

    assert!(device.rotate_identity(id, new.to_peer()));
    assert_eq!(
        device.peer_with_hint(&hint_of(&new)),
        Some((0, 0)),
        "the new key must resolve while its window is open"
    );
    assert_eq!(
        device.peer_with_hint(&hint_of(&old)),
        Some((0, 1)),
        "the replaced key answers from the window until finalize"
    );

    assert!(device.finalize_identity(id));
    assert_eq!(
        device.peer_with_hint(&hint_of(&new)),
        Some((0, 0)),
        "finalize must leave the rotated key resolvable, not the retired one"
    );
    assert_eq!(
        device.peer_with_hint(&hint_of(&old)),
        None,
        "the retired key must stop resolving when the window closes"
    );
}
