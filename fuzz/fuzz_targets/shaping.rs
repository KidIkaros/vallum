#![no_main]

//! The shaping framework, on an arbitrary event/draw stream.
//!
//! The machines are the reference ones (pad, inject, block), so the invariants
//! are the framework's: no panic, an effect names a real machine, and a machine
//! past its state limit still transitions without producing the suppressed
//! action (that property is what P5's unit tests assert; here it is exercised on
//! arbitrary interleavings).

use libfuzzer_sys::fuzz_target;
use vallum_core::shaping::{Action, Event, Machine, Shaper};

const MACHINES: usize = 3;

fuzz_target!(|data: &[u8]| {
    let mut shaper = Shaper::new(vec![
        Machine::pad_to_size(1400),
        Machine::respond_with_padding(1400, 4, 8),
        Machine::min_interval(20),
    ]);

    for chunk in data.chunks(9) {
        if chunk.len() < 9 {
            break;
        }
        let event = match chunk[0] % 5 {
            0 => Event::NormalSent,
            1 => Event::NormalRecv,
            2 => Event::TunnelSent,
            3 => Event::TunnelRecv,
            _ => Event::Timeout,
        };
        let draw = u64::from_le_bytes(chunk[1..9].try_into().expect("8 bytes"));

        for effect in shaper.handle(event, draw) {
            assert!(effect.machine < MACHINES, "effect from an unknown machine");
            match effect.action {
                Action::Pad { .. } | Action::Inject { .. } | Action::Block { .. } => {}
            }
        }
    }
});
