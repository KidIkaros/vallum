#![no_main]

//! The enrolment (VEN2) framing, on arbitrary bytes.
//!
//! `parse_hello`, `parse_cookie` and `reply_framing` are what the responder and
//! the client run on a datagram from the network before any token is verified.
//! They are the first code an unauthenticated peer reaches, so the invariants
//! are: never panic, and never accept a datagram whose fields do not tile it
//! exactly — a parser that reads past a length it accepted is how a length
//! confusion becomes a memory bug in the next consumer.
//!
//! The round-trip is the stronger invariant, as in `message_parse`: a `HELLO`
//! that parses must re-encode from its own fields to the same bytes. A mismatch
//! means the parser accepts something the builder would never emit.

use libfuzzer_sys::fuzz_target;
use vallum::enroll::{encode_hello, parse_cookie, parse_hello, reply_framing, Token};

fuzz_target!(|data: &[u8]| {
    let _ = parse_cookie(data);
    let _ = reply_framing(data);

    let Some(hello) = parse_hello(data) else {
        return;
    };

    // Fields the parser accepted must be self-consistent.
    assert_eq!(hello.id.len(), 32, "an id is 16 bytes of hex");
    assert!(
        hello.id.chars().all(|c| c.is_ascii_hexdigit()),
        "an id is hex"
    );

    // Re-encode from the parsed fields and require the same datagram back.
    // The token only keys the admission tag, so a fixed one is enough here: the
    // property under test is the framing, not the tag.
    let Ok(token) = Token::parse("00000000000000000000000000000000") else {
        return;
    };
    if let Ok(rebuilt) = encode_hello(
        &hello.id,
        &hello.client_nonce,
        &hello.ephemeral_pk,
        &hello.public_line,
        hello.cookie.as_ref(),
        &token,
    ) {
        // The tag is recomputed, so compare everything before it.
        let body = &data[..data.len().saturating_sub(32)];
        assert_eq!(
            &rebuilt[..body.len()],
            body,
            "a parsed HELLO did not re-encode to the same framing"
        );
    }
});
