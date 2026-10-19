#![no_main]

//! The handshake decoder, on arbitrary bytes.
//!
//! `responder_identify`, `initiator_process_resp`, and `responder_process_conf`
//! are the three functions that consume a message from the network before any
//! session exists. Invariants: never panic, and every rejection is a typed
//! `HandshakeError` rather than an unwrap.
//!
//! The fixture uses the ML-KEM-only suite on purpose: the decoder and the
//! transcript code are suite-independent, and the tri-hybrid's sntrup761 costs
//! ~25 ms per operation, which would make the fuzzer do a few dozen inputs a
//! second instead of thousands.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use vallum_core::{
    initiator_hello, initiator_process_resp, responder_identify, responder_process_conf,
    responder_process_init, PeerIdentity, StaticIdentity,
};
use vallum_crypto_sdk::SdkSuite;

const TIMESTAMP: [u8; 12] = [
    0x40, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];

struct Fixture {
    suite: SdkSuite,
    initiator: StaticIdentity,
    responder: StaticIdentity,
    init_hello: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let suite = SdkSuite::from_id(0x0002).expect("the ML-KEM suite is compiled in");
        let initiator = StaticIdentity::generate(&suite, &[0x11; 32]).expect("initiator");
        let responder = StaticIdentity::generate(&suite, &[0x22; 32]).expect("responder");
        let (init_hello, _) = initiator_hello(
            &suite,
            &initiator,
            &PeerIdentity::from_identity(&responder),
            1,
            TIMESTAMP,
            &[0x33; 32],
        )
        .expect("hello");
        Fixture {
            suite,
            initiator,
            responder,
            init_hello,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();

    // The responder's first phase: parse, decapsulate op A, unseal the hint.
    let _ = responder_identify(&f.suite, &f.responder, data);

    // The initiator's second phase: parse a RespHello and verify the tag before
    // any decapsulation.
    let (_, state) = initiator_hello(
        &f.suite,
        &f.initiator,
        &PeerIdentity::from_identity(&f.responder),
        1,
        TIMESTAMP,
        &[0x33; 32],
    )
    .expect("hello");
    let _ = initiator_process_resp(&f.suite, state, &f.initiator, data);

    // The responder's last phase: parse an InitConf and verify it.
    let (_, r_state) = responder_process_init(
        &f.suite,
        &f.responder,
        &PeerIdentity::from_identity(&f.initiator),
        &f.init_hello,
        2,
        &[0x44; 32],
    )
    .expect("response");
    let _ = responder_process_conf(&f.suite, r_state, data);
});
