// SPDX-License-Identifier: Apache-2.0

//! The segment layer: parse a datagram, then feed it to the reassembler.
//!
//! The reassembler is where an unauthenticated peer can reach the daemon's
//! memory management, so it gets its own target. A panic here is a panic on
//! the daemon's loop thread, and there is no `catch_unwind` on that path: the
//! process dies.
//!
//! One target did not exist, and the gap was not theoretical: two fragments
//! whose claimed totals disagreed made the copy index past the end of the
//! entry's buffer. The first fragment sized the entry; the second was
//! bounded by its own claim.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vallum_tunnel::segment::Segments;

fuzz_target!(|data: &[u8]| {
    let mut segments = Segments::new();
    let source = "203.0.113.9:51820".parse().expect("a v4 endpoint");

    // Every datagram goes through the reassembler, whatever it claims to be.
    // The reply is ignored: the target is the daemon surviving it.
    let _ = segments.inbound(1_000, source, data.to_vec());

    // And again with a different source, so a fragment that is accepted for
    // one peer cannot lean on another peer's entry.
    let other = "198.51.100.7:51820".parse().expect("a v4 endpoint");
    let _ = segments.inbound(2_000, other, data.to_vec());

    // And a second datagram against the first source, so the two-fragment
    // case - the one that panicked - is reachable: the first datagram opens
    // the entry, the second disagrees with it.
    let _ = segments.inbound(3_000, source, data.to_vec());
});
