// SPDX-License-Identifier: Apache-2.0

//! `vallum bench`: the data-plane microbenchmark.

use std::time::{Duration, Instant};

use clap::Args;
use vallum_core::{Role, SessionKeys};
use vallum_crypto::SharedSecret;
use vallum_crypto_sdk::SdkSuite;

use crate::commands::keys::parse_suite;
use crate::keys;
use crate::Error;

#[derive(Debug, Args)]
pub struct BenchArgs {
    /// The suite id, decimal or `0x`-prefixed hex. Defaults to the tri-hybrid.
    #[arg(long, default_value = "3", value_name = "ID")]
    suite: String,

    /// Payload size in bytes.
    #[arg(long, default_value = "1380", value_name = "BYTES")]
    bytes: usize,

    /// Iterations to time.
    #[arg(long, default_value = "2000", value_name = "N")]
    iterations: usize,
}

pub fn bench(args: &BenchArgs) -> Result<(), Error> {
    let suite_id = parse_suite(&args.suite)?;
    let suite = SdkSuite::from_id(suite_id)
        .map_err(|e| Error::Suite(format!("suite `{}`: {e}", args.suite)))?;
    if args.bytes == 0 || args.iterations == 0 {
        return Err(Error::Usage(
            "bench needs a non-zero --bytes and --iterations".to_owned(),
        ));
    }
    let base = SessionKeys {
        transcript: [0x11; 32],
        key: SharedSecret::new([0x22; 32]),
        confirm_initiator: SharedSecret::new([0x33; 32]),
        confirm_responder: SharedSecret::new([0x44; 32]),
        own_index: 1,
        peer_index: 2,
    };
    let mut initiator = base.clone();
    initiator.own_index = 1;
    initiator.peer_index = 2;
    let mut responder = base;
    responder.own_index = 2;
    responder.peer_index = 1;
    let (mut sender, _) = vallum_core::establish(&suite, &initiator, Role::Initiator)
        .map_err(|e| Error::Usage(format!("bench: {e}")))?;
    let (_, mut receiver) = vallum_core::establish(&suite, &responder, Role::Responder)
        .map_err(|e| Error::Usage(format!("bench: {e}")))?;
    let payload = vec![0u8; args.bytes];

    for _ in 0..16 {
        let _ = sender
            .seal(&suite, &payload)
            .map_err(|e| Error::Usage(format!("bench: {e}")))?;
    }
    let start = Instant::now();
    let mut packets = Vec::with_capacity(args.iterations);
    for _ in 0..args.iterations {
        packets.push(
            sender
                .seal(&suite, &payload)
                .map_err(|e| Error::Usage(format!("bench: {e}")))?,
        );
    }
    let seal = start.elapsed();

    let start = Instant::now();
    for packet in &packets {
        let _ = receiver
            .open(&suite, packet)
            .map_err(|e| Error::Usage(format!("bench: {e}")))?;
    }
    let open = start.elapsed();

    let mib = |elapsed: Duration| {
        (args.bytes.saturating_mul(args.iterations)) as f64
            / elapsed.as_secs_f64()
            / (1024.0 * 1024.0)
    };
    println!(
        "suite {suite_id} ({}), {} B payload, {} iterations",
        keys::describe_suite(suite_id),
        args.bytes,
        args.iterations
    );
    println!(
        "  seal: {:?}/packet, {:.1} MiB/s",
        seal / args.iterations as u32,
        mib(seal)
    );
    println!(
        "  open: {:?}/packet, {:.1} MiB/s",
        open / args.iterations as u32,
        mib(open)
    );
    #[cfg(debug_assertions)]
    println!("  note: debug build; use `cargo run --release` for a meaningful number");
    println!("  crypto only; the loop adds one read/write syscall per packet");
    Ok(())
}
