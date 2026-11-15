#![no_main]

//! Stream (`FrameReader` / `unframe`) and `ss` obfuscation framing on arbitrary bytes.
//!
//! Both sit directly on untrusted network bytes for `carrier = "tcp"`, `"auto"`,
//! `"tls"`, and `"ss"` before a tunnel packet is handed to `Session::open`.
//! Invariants:
//!
//! * arbitrary/chunked bytes never panic or loop unboundedly;
//! * valid `frame(p)` always round-trips through `unframe`;
//! * valid `seal_ss_packet` always round-trips through `open_ss_packet`.

use libfuzzer_sys::fuzz_target;
use vallum_crypto_sdk::SdkSuite;
use vallum_tunnel::ss::{derive_ss_key, open_ss_packet, seal_ss_packet, SS_NONCE_LEN};
use vallum_tunnel::stream::{frame, unframe, FrameReader};

fuzz_target!(|data: &[u8]| {
    // 1. Direct unframe + round-trip.
    if let Ok(Some((pkt, consumed))) = unframe(data) {
        assert!(consumed <= data.len());
        assert!(consumed >= pkt.len());
    }
    if let Ok(framed) = frame(data) {
        let parsed = unframe(&framed).expect("freshly framed packet must unframe");
        assert_eq!(parsed, Some((data, framed.len())));
    }

    // 2. Chunked FrameReader (simulating partial TCP/TLS reads + HTTP Upgrade header).
    let mut reader = FrameReader::new();
    let chunk_size = data.first().map_or(1, |b| ((*b as usize) % 64) + 1);
    for chunk in data.chunks(chunk_size) {
        reader.push(chunk);
        let _ = reader.take_upgrade_reply();
        while let Ok(Some(_frame)) = reader.next_frame() {}
    }

    // 3. SS AEAD obfuscation open + round-trip.
    let suite = SdkSuite::tri_hybrid();
    let key = derive_ss_key(&suite, Some("fuzz-psk"));
    let _ = open_ss_packet(&suite, &key, data);
    if data.len() <= 65_535 {
        let mut nonce = [0u8; SS_NONCE_LEN];
        let copy_len = data.len().min(SS_NONCE_LEN);
        nonce[..copy_len].copy_from_slice(&data[..copy_len]);
        if let Ok(sealed) = seal_ss_packet(&suite, &key, &nonce, data) {
            let opened = open_ss_packet(&suite, &key, &sealed);
            assert_eq!(opened.as_deref(), Some(data));
        }
    }
});
