#![no_main]

//! The replay window, on an arbitrary sequence of counters.
//!
//! Invariants: `next()` never decreases, a counter is accepted at most once,
//! and nothing panics. A window that slid the wrong way would show up as a
//! duplicate acceptance; one that wrapped would show up as `next()` going
//! backwards.

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use vallum_core::ReplayFilter;

fuzz_target!(|data: &[u8]| {
    let mut filter = ReplayFilter::new();
    let mut accepted = HashSet::new();
    let mut last_next = 0u64;

    for chunk in data.chunks(9) {
        if chunk.len() < 9 {
            break;
        }
        let counter = u64::from_be_bytes(chunk[..8].try_into().expect("8 bytes"));
        // Every other chunk is a probe that must not move the window.
        if chunk[8] & 1 == 0 {
            if filter.accept(counter).is_ok() {
                assert!(
                    accepted.insert(counter),
                    "counter {counter} was accepted twice"
                );
            }
        }
        let next = filter.next();
        assert!(next >= last_next, "next() went backwards");
        last_next = next;
    }
});
