// SPDX-License-Identifier: Apache-2.0

//! `vallum bench`: the data-plane microbenchmark.
//!
//! One number hides a skewed distribution, so the loop is sampled in batches:
//! each sample is the per-packet time of one batch, and the report carries the
//! median, the IQR, the tail percentiles, and a 95% interval for the mean —
//! the Practical Statistics answer to "how fast is seal?" rather than a single
//! aggregate.

use std::time::Instant;

use clap::Args;
use vallum_core::{Role, SessionKeys};
use vallum_crypto::SharedSecret;
use vallum_crypto_sdk::SdkSuite;

use crate::commands::keys::parse_suite;
use crate::keys;
use crate::Error;

/// How many timed batches to collect per direction.
///
/// Enough that percentiles and the mean's interval are meaningful, few enough
/// that `--iterations 2000` still finishes quickly. The last batch may be
/// short; each sample is normalised to per-packet time, so that is fine.
const SAMPLES: usize = 64;

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

/// A robust summary of per-packet nanoseconds.
///
/// The variable is continuous, positive, and typically right-skewed — timer
/// resolution floors it, scheduler noise stretches the tail — so location is
/// the median and spread is the IQR plus tail percentiles, not only the mean.
/// `ci95` is the classic `mean ± 1.96·s/√n` normal interval *for the mean of
/// this run*; it says nothing about another machine or a loaded system.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Dist {
    /// Samples taken (batches, not packets).
    pub n: usize,
    /// Mean per-packet time, nanoseconds.
    pub mean: f64,
    /// Median.
    pub p50: f64,
    /// First quartile.
    pub p25: f64,
    /// Third quartile.
    pub p75: f64,
    /// 95th percentile.
    pub p95: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Half-width of the 95% interval for the mean, nanoseconds.
    pub ci95: f64,
}

/// Summarize `samples` (per-packet nanoseconds) into a [`Dist`].
///
/// Percentiles use the type-7 rule (`h = p·(n−1)`, linear interpolation), the
/// same default R's `quantile` uses.
pub(crate) fn summarize(samples: &[f64]) -> Option<Dist> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let n = sorted.len();
    let percentile = |p: f64| -> f64 {
        let rank = p * (n - 1) as f64;
        let low = sorted[rank.floor() as usize];
        let high = sorted[(rank.ceil() as usize).min(n - 1)];
        low + (high - low) * rank.fract()
    };
    let mean = sorted.iter().sum::<f64>() / n as f64;
    let variance = if n > 1 {
        sorted.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    Some(Dist {
        n,
        mean,
        p50: percentile(0.50),
        p25: percentile(0.25),
        p75: percentile(0.75),
        p95: percentile(0.95),
        p99: percentile(0.99),
        ci95: 1.96 * variance.sqrt() / (n as f64).sqrt(),
    })
}

/// Run `body` `iterations` times, timing in batches of `batch` packets.
///
/// Timing each packet would let the clock reads dominate; timing the whole run
/// would give one number. Per-batch timing is the middle path, and each sample
/// records per-packet nanoseconds.
fn timed_batches(
    iterations: usize,
    batch: usize,
    mut body: impl FnMut() -> Result<(), Error>,
) -> Result<Vec<f64>, Error> {
    let mut samples = Vec::new();
    let mut done = 0;
    while done < iterations {
        let take = batch.min(iterations - done);
        let start = Instant::now();
        for _ in 0..take {
            body()?;
        }
        samples.push(start.elapsed().as_secs_f64() * 1e9 / take as f64);
        done += take;
    }
    Ok(samples)
}

fn render(label: &str, dist: &Dist, bytes_per_packet: usize) {
    let mib_s = bytes_per_packet as f64 / (dist.mean * 1e-9) / (1024.0 * 1024.0);
    println!(
        "  {label}: median {:.1} µs · IQR {:.1}–{:.1} · p95 {:.1} · p99 {:.1}",
        dist.p50 / 1000.0,
        dist.p25 / 1000.0,
        dist.p75 / 1000.0,
        dist.p95 / 1000.0,
        dist.p99 / 1000.0,
    );
    println!(
        "       mean {:.1} ± {:.1} µs (95% CI, n={}) · {mib_s:.1} MiB/s",
        dist.mean / 1000.0,
        dist.ci95 / 1000.0,
        dist.n,
    );
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
        epoch: None,
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

    // Seal, then open what was sealed — the open phase needs real packets, and
    // counters/replay forbid reusing them.
    let batch = args.iterations.div_ceil(SAMPLES).max(1);
    let mut sealed: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    let seal_samples = timed_batches(args.iterations, batch, || {
        sealed.push_back(
            sender
                .seal(&suite, &payload)
                .map_err(|e| Error::Usage(format!("bench: {e}")))?,
        );
        Ok(())
    })?;
    let open_samples = timed_batches(args.iterations, batch, || {
        let packet = sealed
            .pop_front()
            .ok_or_else(|| Error::Usage("bench: seal produced fewer packets".to_owned()))?;
        let _ = receiver
            .open(&suite, &packet)
            .map_err(|e| Error::Usage(format!("bench: {e}")))?;
        Ok(())
    })?;

    let seal = summarize(&seal_samples);
    let open = summarize(&open_samples);
    let (Some(seal), Some(open)) = (seal, open) else {
        return Err(Error::Usage("bench: no samples collected".to_owned()));
    };

    println!(
        "suite {suite_id} ({}), {} B payload, {} iterations in {} batches",
        keys::describe_suite(suite_id),
        args.bytes,
        args.iterations,
        seal.n,
    );
    render("seal", &seal, args.bytes);
    render("open", &open, args.bytes);
    #[cfg(debug_assertions)]
    println!("  note: debug build; use `cargo run --release` for a meaningful number");
    println!("  crypto only; the loop adds one read/write syscall per packet");
    println!("  the 95% interval covers this run's mean, not a different machine or load");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{summarize, timed_batches};

    #[test]
    fn a_constant_distribution_reports_itself() {
        let samples = vec![100.0f64; 64];
        let dist = summarize(&samples).expect("dist");
        assert_eq!(dist.n, 64);
        assert!((dist.mean - 100.0).abs() < 1e-9);
        assert!((dist.p50 - 100.0).abs() < 1e-9);
        assert_eq!(dist.p25, dist.p75);
        assert_eq!(dist.ci95, 0.0);
    }

    #[test]
    fn percentiles_interpolate_and_the_tail_is_visible() {
        // 90 fast samples and 10 slow ones: the median stays at the mode while
        // the upper percentiles move into the tail — the reason the report is
        // not a mean alone.
        let mut samples = vec![10.0f64; 90];
        samples.extend([1000.0f64; 10]);
        let dist = summarize(&samples).expect("dist");
        assert!((dist.p50 - 10.0).abs() < 1e-9);
        assert!(dist.p99 > 900.0);
        assert!(dist.p95 > dist.p75);
        assert!(dist.mean > dist.p50); // the outlier pulls the mean, not the median
    }

    #[test]
    fn the_interval_shrinks_with_more_samples() {
        let alternating: Vec<f64> = (0..8)
            .map(|i| if i % 2 == 0 { 90.0 } else { 110.0 })
            .collect();
        let few = summarize(&alternating).expect("few");
        let many = summarize(&alternating.repeat(16)).expect("many");
        assert!(many.ci95 < few.ci95);
        assert!((few.mean - 100.0).abs() < 1e-9);
        assert!((many.mean - 100.0).abs() < 1e-9);
    }

    #[test]
    fn empty_input_reports_nothing() {
        assert!(summarize(&[]).is_none());
    }

    #[test]
    fn batches_cover_every_iteration() {
        let mut calls = 0usize;
        let samples = timed_batches(101, 10, || {
            calls += 1;
            Ok(())
        })
        .expect("timed");
        assert_eq!(calls, 101);
        assert_eq!(samples.len(), 11); // ten batches of 10, one of 1
    }

    #[test]
    fn an_error_stops_the_run() {
        let mut calls = 0usize;
        assert!(timed_batches(64, 8, || {
            calls += 1;
            if calls == 3 {
                return Err(crate::Error::Usage("boom".to_owned()));
            }
            Ok(())
        })
        .is_err());
        assert_eq!(calls, 3);
    }
}
