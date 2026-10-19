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
