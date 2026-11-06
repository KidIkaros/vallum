// SPDX-License-Identifier: Apache-2.0

//! P5 gate tests: the shaping machine, and the cost of using it.
//!
//! The gate is *"the privacy parameter is documented and the bandwidth/latency
//! cost is measured, not asserted"*. So the test file is mostly a **simulator**:
//! it replays one synthetic traffic trace through a real
//! [`Sender`]/[`Receiver`] pair, applies whatever the machines ask for, and
//! reports the numbers. The assertions are relations between measured values
//! (same size, more bytes, bounded delay), not magic constants.
//!
//! 1. **Baseline.** Unshaped traffic exposes every payload length; the size set
//!    is as rich as the trace. That is the leak.
//! 2. **The length channel closes.** `pad_to_size` collapses the observable size
//!    set to a single value, and the payload still arrives unchanged — so the
//!    privacy claim and the correctness claim are tested together.
//! 3. **The cost is a number.** Bandwidth grows with the target; `min_interval`
//!    delays measurable traffic; injection costs bytes. Each is printed.
//! 4. **Padding is indistinguishable in kind.** An injected padding packet is an
//!    openable keepalive — no new message type, nothing an observer can pick out
//!    of the stream by form.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fmt;

use vallum_core::{
    establish_epoch, Action, Event, Machine, Receiver, Role, Sender, Shaper, PAYLOAD_LEN_SIZE,
    UNLIMITED,
};
use vallum_crypto::SharedSecret;
use vallum_crypto_sdk::SdkSuite;

const OWN: u32 = 0x1111_1111;
const PEER: u32 = 0x2222_2222;

/// A synthetic traffic trace: `(inbound, payload_bytes, gap_ms)`.
///
/// A page load: a small request, an asymmetric burst of large responses, a
/// couple of acknowledgements, then a long idle tail. This shape — small
/// outbound, bursty inbound — is exactly what a website fingerprinting attack
/// reads, so it is the honest trace to cost a defense against.
const PAGE_LOAD: &[(bool, usize, u64)] = &[
    (false, 40, 0),
    (true, 1400, 12),
    (true, 1400, 2),
    (true, 900, 3),
    (true, 1400, 2),
    (true, 600, 4),
    (false, 40, 18),
    (true, 300, 25),
    (true, 1400, 2),
    (false, 120, 40),
    (true, 512, 30),
    (true, 1400, 3),
    (false, 60, 900),
    (false, 400, 4),
    (true, 1400, 1500),
    (false, 84, 6),
    (true, 220, 8),
    (false, 40, 2200),
];

/// A deterministic draw source for the machines.
///
/// SplitMix64, test-only. The library holds no generator on purpose: the caller
/// supplies the draw, because where a tunnel's shaping entropy comes from is a
/// deployment decision, not a protocol one.
struct Draws(u64);

impl Draws {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// A deterministic payload of `len` bytes.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A mirrored key pair, as a completed handshake would leave one.
///
/// Returns `(suite, a_send, a_recv, b_send, b_recv)`; `a`'s packets are
/// addressed to `b` and vice versa.
fn link() -> (SdkSuite, Sender, Receiver, Sender, Receiver) {
    let suite = SdkSuite::tri_hybrid();
    let root = SharedSecret::new([0x11; 32]);
    let transcript = [0x22u8; 32];

    let (a_send, a_recv) =
        establish_epoch(&suite, &root, &transcript, 0, Role::Initiator, OWN, PEER).expect("a");
    let (b_send, b_recv) =
        establish_epoch(&suite, &root, &transcript, 0, Role::Responder, PEER, OWN).expect("b");

    (suite, a_send, a_recv, b_send, b_recv)
}

/// What one simulation measured.
#[derive(Debug, Default)]
struct Report {
    /// Outbound packets put on the wire, normal and injected alike.
    packets: usize,
    /// Outbound bytes, framing and tags included.
    bytes: usize,
    /// Distinct outbound packet sizes — the observable size set.
    sizes: BTreeSet<usize>,
    /// Padding packets injected.
    injected: usize,
    /// Normal packets held back by a `Block`.
    held: usize,
    /// Total milliseconds those packets spent waiting.
    held_ms: u64,
}

impl Report {
    fn record(&mut self, packet_len: usize) {
        self.packets += 1;
        self.bytes += packet_len;
        self.sizes.insert(packet_len);
    }

    /// Bandwidth overhead against a baseline, as a percentage.
    fn overhead_percent(&self, baseline: &Self) -> f64 {
        if baseline.bytes == 0 {
            return 0.0;
        }
        (self.bytes as f64 / baseline.bytes as f64 - 1.0) * 100.0
    }

    /// Mean delay added to a held packet, in milliseconds.
    fn mean_hold_ms(&self) -> f64 {
        if self.held == 0 {
            return 0.0;
        }
        self.held_ms as f64 / self.held as f64
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} packets, {} bytes, {} distinct sizes, {} injected, {} held ({} ms)",
            self.packets,
            self.bytes,
            self.sizes.len(),
            self.injected,
            self.held,
            self.held_ms
        )
    }
}

/// Seal `count` padding packets of `size` bytes and record them.
fn inject_padding(
    suite: &SdkSuite,
    sender: &mut Sender,
    shaper: &mut Shaper,
    draws: &mut Draws,
    report: &mut Report,
    count: u16,
    size: u16,
) {
    for _ in 0..count {
        let packet = sender
            .seal_padded(suite, &[], usize::from(size))
            .expect("padding packet");
        report.record(packet.len());
        report.injected += 1;
        // The framework is told about its own padding, as Maybenot's machines
        // are: a defense is allowed to react to its own output.
        shaper.handle(Event::TunnelSent, draws.next());
    }
}

/// Deliver everything a `Block` was holding, and measure how long each waited.
///
/// A block delays traffic; it never drops it. So the packets sealed here are the
/// same payloads, at the same targets, as they would have been — just late.
fn release_held(
    suite: &SdkSuite,
    sender: &mut Sender,
    report: &mut Report,
    waiting: &mut Vec<(u64, usize, usize)>,
    until: u64,
) {
    for (held_at, size, target) in waiting.drain(..) {
        report.held += 1;
        report.held_ms += until.saturating_sub(held_at);
        let packet = sender
            .seal_padded(suite, &payload(size), target)
            .expect("held packet");
        report.record(packet.len());
    }
}

/// Replay one trace through a shaper and measure the local cost.
///
/// Shaping is per-endpoint local policy, so this measures the *outbound*
/// direction of one end: inbound packets only generate events. A `Block` holds
/// packets rather than dropping them, so held traffic is delayed, never lost.
fn simulate(machines: Vec<Machine>, trace: &[(bool, usize, u64)], seed: u64) -> Report {
    let (suite, mut a_send, mut a_recv, mut b_send, _b_recv) = link();
    let mut shaper = Shaper::new(machines);
    let mut draws = Draws::new(seed);
    let mut report = Report::default();

    let mut now = 0u64;
    let mut blocked_until: Option<u64> = None;
    let mut waiting: Vec<(u64, usize, usize)> = Vec::new();
    // When an armed machine wants a `Timeout`. The daemon keeps this per peer
    // (`Peer::shape_wake_ms`) and re-arms it after every event; a simulator that
    // did not would leave a time-driven machine inert, and would measure its
    // cost as zero.
    let mut wake_due: Option<u64> = shaper.wake_after();

    for &(inbound, size, gap) in trace {
        now += gap;

        // Time passing is itself an event: a block ends at its deadline, and an
        // armed machine — the constant-rate floor — is told the clock moved
        // whether or not anything else happened. Both are served from one
        // `Timeout`, in deadline order, because acting can arm the next one.
        loop {
            let nearest = blocked_until
                .into_iter()
                .chain(wake_due)
                .filter(|&at| now >= at)
                .min();
            let Some(at) = nearest else { break };
            if blocked_until == Some(at) {
                release_held(&suite, &mut a_send, &mut report, &mut waiting, at);
                blocked_until = None;
            }
            for effect in shaper.handle(Event::Timeout, draws.next()) {
                if let Action::Inject { count, size } = effect.action {
                    inject_padding(
                        &suite,
                        &mut a_send,
                        &mut shaper,
                        &mut draws,
                        &mut report,
                        count,
                        size,
                    );
                }
            }
            // Re-arm from the deadline rather than from `now`: a floor that
            // came due while the trace was idle keeps its cadence instead of
            // bunching its packets at the instant something else happened.
            wake_due = shaper
                .wake_after()
                .map(|interval| at.saturating_add(interval));
        }

        if inbound {
            let body = payload(size);
            let packet = b_send
                .seal_padded(&suite, &body, size + PAYLOAD_LEN_SIZE)
                .expect("peer seal");
            assert_eq!(a_recv.open(&suite, &packet).expect("peer open"), body);

            for effect in shaper.handle(Event::NormalRecv, draws.next()) {
                if let Action::Inject { count, size } = effect.action {
                    inject_padding(
                        &suite,
                        &mut a_send,
                        &mut shaper,
                        &mut draws,
                        &mut report,
                        count,
                        size,
                    );
                }
            }
        } else {
            // Outbound: the machine sees the event before the seal, so a `Pad`
            // applies to this very packet.
            let mut target = size + PAYLOAD_LEN_SIZE;
            let mut asked_to_block = false;
            for effect in shaper.handle(Event::NormalSent, draws.next()) {
                match effect.action {
                    Action::Pad { target: padded } => target = usize::from(padded),
                    Action::Inject { count, size } => inject_padding(
                        &suite,
                        &mut a_send,
                        &mut shaper,
                        &mut draws,
                        &mut report,
                        count,
                        size,
                    ),
                    Action::Block { timeout_ms } => {
                        asked_to_block = true;
                        if blocked_until.is_none() {
                            blocked_until = Some(now.saturating_add(timeout_ms));
                        }
                    }
                }
            }

            // A block holds packets, whether it was requested for this one or is
            // still running from an earlier one.
            if asked_to_block || blocked_until.is_some() {
                waiting.push((now, size, target));
            } else {
                let packet = a_send
                    .seal_padded(&suite, &payload(size), target)
                    .expect("seal");
                report.record(packet.len());
            }
        }

        // Every event restarts an armed interval, so the deadline moves with it.
        wake_due = shaper
            .wake_after()
            .map(|interval| now.saturating_add(interval));
    }

    // Flush a block still running when the trace ends: the packets were delayed
    // for the rest of the interval, and the measurement should say so.
    if let Some(until) = blocked_until {
        release_held(&suite, &mut a_send, &mut report, &mut waiting, until);
    }

    report
}

// ── 1. the baseline: length is the leak ──────────────────────────────

#[test]
fn unshaped_traffic_exposes_every_payload_length() {
    let report = simulate(Vec::new(), PAGE_LOAD, 1);
    println!("unshaped: {report}");
    println!("  size set: {:?}", report.sizes);

    assert_eq!(report.injected, 0);
    assert_eq!(report.held, 0);
    assert_eq!(
        report.packets,
        PAGE_LOAD.iter().filter(|(i, _, _)| !i).count()
    );
    // Distinct lengths to distinct packets: the length channel is wide open.
    assert!(
        report.sizes.len() >= 4,
        "the baseline should leak a rich size set, got {:?}",
        report.sizes
    );
}

// ── 2. the length channel closes, and the payload still arrives ──────

#[test]
fn pad_to_size_collapses_the_size_set_to_one_value() {
    const TARGET: u16 = 1400;

    let baseline = simulate(Vec::new(), PAGE_LOAD, 1);
    let shaped = simulate(vec![Machine::pad_to_size(TARGET)], PAGE_LOAD, 1);
    println!("baseline: {baseline}");
    println!("padded:   {shaped}");
    println!(
        "  bandwidth overhead: {:.1}%",
        shaped.overhead_percent(&baseline)
    );

    // Every outbound packet is the same length: the size set is a singleton, so
    // packet length carries no information, which is the whole privacy claim.
    assert_eq!(shaped.sizes.len(), 1, "sizes: {:?}", shaped.sizes);
    assert_eq!(shaped.packets, baseline.packets, "padding adds no packets");
    assert!(
        shaped.bytes > baseline.bytes,
        "closing the channel cannot be free"
    );

    // The single length is exactly what a full-size payload produces, so the
    // target is honoured rather than approximately honoured.
    let (suite, mut sender, _, _, _) = link();
    let reference = sender
        .seal_padded(
            &suite,
            &payload(usize::from(TARGET) - PAYLOAD_LEN_SIZE),
            usize::from(TARGET),
        )
        .expect("reference")
        .len();
    assert_eq!(shaped.sizes.iter().next().copied(), Some(reference));
}

#[test]
fn padding_is_stripped_so_the_payload_arrives_unchanged() {
    let (suite, mut a_send, _, _, mut b_recv) = link();

    // 1398 is the largest payload a 1400-byte sealed plaintext can hold.
    for len in [0usize, 1, 40, 1398] {
        let body = payload(len);
        let packet = a_send.seal_padded(&suite, &body, 1400).expect("seal");
        assert_eq!(
            b_recv.open(&suite, &packet).expect("open"),
            body,
            "a {len}-byte payload must survive padding unchanged"
        );
    }
}

// ── 3. the cost is measured ──────────────────────────────────────────

#[test]
fn bandwidth_cost_grows_with_the_padding_target() {
    let baseline = simulate(Vec::new(), PAGE_LOAD, 1);
    println!("baseline: {baseline}");

    let mut previous = 0.0f64;
    for target in [512u16, 768, 1024, 1400] {
        let shaped = simulate(vec![Machine::pad_to_size(target)], PAGE_LOAD, 1);
        let overhead = shaped.overhead_percent(&baseline);
        println!("pad to {target:>5}: {shaped}  (+{overhead:.1}%)");

        assert_eq!(shaped.sizes.len(), 1);
        assert!(
            overhead >= previous,
            "a larger target cannot cost less bandwidth"
        );
        previous = overhead;
    }
    assert!(previous > 0.0, "something must have cost something");
}

#[test]
fn injected_padding_costs_bandwidth_and_is_counted() {
    let baseline = simulate(Vec::new(), PAGE_LOAD, 1);
    let noisy = simulate(
        vec![Machine::respond_with_padding(1400, 1, UNLIMITED)],
        PAGE_LOAD,
        1,
    );
    println!("baseline:   {baseline}");
    println!("inject 1/2: {noisy}");

    // One padding packet per two inbound packets, by the machine's weights.
    let inbound = PAGE_LOAD.iter().filter(|(i, _, _)| *i).count();
    assert!(noisy.injected > 0);
    assert!(
        noisy.injected <= inbound,
        "the weights cannot inject more than once per event"
    );
    assert!(noisy.bytes > baseline.bytes);
    assert_eq!(noisy.packets, baseline.packets + noisy.injected);
}

#[test]
fn min_interval_trades_latency_for_timing_obscurity() {
    const INTERVAL: u64 = 20;

    let baseline = simulate(Vec::new(), PAGE_LOAD, 1);
    let paced = simulate(vec![Machine::min_interval(INTERVAL)], PAGE_LOAD, 1);
    println!("baseline:      {baseline}");
    println!("min_interval:  {paced}");
    println!("  mean hold: {:.1} ms", paced.mean_hold_ms());

    assert!(paced.held > 0, "a rate limiter must hold something");
    assert!(paced.held_ms > 0);
    assert!(
        paced.held_ms <= paced.held as u64 * INTERVAL,
        "a packet cannot wait longer than the interval"
    );
    // A block delays traffic, it does not drop it: the same packets leave, just
    // later. The cost is the latency, and it is what the machine trades against.
    assert_eq!(
        paced.packets, baseline.packets,
        "holding must not lose packets"
    );
    assert_eq!(paced.bytes, baseline.bytes, "holding must not add bytes");
}

#[test]
fn the_same_padding_target_costs_the_same_bytes_however_it_is_reached() {
    // `pad_to_size` and a hand-written equivalent machine must agree, so a
    // custom defense's cost is comparable with the built-in one.
    let builtin = simulate(vec![Machine::pad_to_size(1024)], PAGE_LOAD, 1);

    let hand_written = Machine::new(vec![vallum_core::State::new(UNLIMITED).on(
        Event::NormalSent,
        vec![vallum_core::Branch::act(1, Action::Pad { target: 1024 }, 0)],
    )]);
    let custom = simulate(vec![hand_written], PAGE_LOAD, 1);

    assert_eq!(builtin.bytes, custom.bytes);
    assert_eq!(builtin.sizes, custom.sizes);
}

#[test]
fn a_bigger_machine_budget_lasts_longer() {
    // The state limit is the cost bound: with a cap, injection stops, and the
    // measurement shows exactly where.
    let capped = simulate(
        vec![Machine::respond_with_padding(1400, 1, 3)],
        PAGE_LOAD,
        1,
    );
    let uncapped = simulate(
        vec![Machine::respond_with_padding(1400, 1, UNLIMITED)],
        PAGE_LOAD,
        1,
    );
    println!("cap 3:      {capped}");
    println!("uncapped:   {uncapped}");

    assert_eq!(capped.injected, 3, "the cap is exact");
    assert!(uncapped.injected > capped.injected);
}

/// An idle hour: one small packet, then nothing for 3 600 s.
///
/// The floor is the only defence whose cost does not depend on the traffic, so
/// the trace that prices it is the empty one.
const IDLE_HOUR: &[(bool, usize, u64)] = &[(false, 40, 3_600_000)];

#[test]
fn the_constant_rate_floor_costs_a_flat_rate_per_hour() {
    const INTERVAL_MS: u64 = 500;
    const SIZE: u16 = 1400;

    let floor = simulate(
        vec![Machine::constant_rate_floor(INTERVAL_MS, SIZE)],
        IDLE_HOUR,
        1,
    );
    let expected = 3_600_000 / INTERVAL_MS;
    let per_packet = floor.bytes / floor.packets;
    // `bytes` is already one hour's worth, so the rate is a plain division.
    let kbit_s = floor.bytes as f64 * 8.0 / 3600.0 / 1000.0;
    let mb_hour = floor.bytes as f64 / 1_048_576.0;
    println!("floor {INTERVAL_MS} ms / {SIZE} B: {floor}");
    println!("  {per_packet} bytes per packet, {kbit_s:.2} kbit/s, {mb_hour:.1} MiB/h");

    // One packet per interval, exactly: the rate is the parameter, not traffic.
    assert_eq!(floor.injected as u64, expected, "{floor}");
    // The cost is entirely the injections: nothing else was sent for an hour.
    assert_eq!(floor.packets, expected as usize + 1, "{floor}");
    // And it is the same size every time: a floor whose packets varied would be
    // a different defence, and a worse one.
    assert_eq!(floor.sizes.len(), 2, "sizes: {:?}", floor.sizes);
}

#[test]
fn a_shorter_floor_interval_costs_more_bandwidth() {
    let mut previous = 0usize;
    for interval in [2000u64, 500, 100] {
        let floor = simulate(
            vec![Machine::constant_rate_floor(interval, 1400)],
            IDLE_HOUR,
            1,
        );
        println!("interval {interval:>4} ms: {floor}");
        assert!(
            floor.bytes > previous,
            "a shorter interval cannot cost less"
        );
        previous = floor.bytes;
    }
}

// ── 4. the front is spent once ──────────────────────────────────────

/// Two idle hours: one small packet at the start, then nothing.
///
/// The floor and the front burst are the two time-driven shapes, and this is the
/// trace that separates them: one costs a rate that never stops, the other a
/// count that is over in a minute.
const TWO_IDLE_HOURS: &[(bool, usize, u64)] = &[(false, 40, 7_200_000)];

#[test]
fn the_front_burst_is_a_one_off_and_the_floor_is_a_rate() {
    const COUNT: u32 = 60;
    const INTERVAL_MS: u64 = 100;
    const SIZE: u16 = 1400;

    let front = simulate(
        vec![Machine::front_padding(COUNT, INTERVAL_MS, SIZE)],
        TWO_IDLE_HOURS,
        1,
    );
    let floor = simulate(
        vec![Machine::constant_rate_floor(INTERVAL_MS, SIZE)],
        TWO_IDLE_HOURS,
        1,
    );
    println!("front, 2 idle h: {front}");
    println!("floor, 2 idle h: {floor}");

    // Exactly the configured count, and it does not grow with the idle time:
    // that is the difference between a burst and a rate.
    assert_eq!(front.injected, COUNT as usize, "{front}");
    assert!(
        floor.injected > front.injected * 100,
        "an hour of floor is thousands of packets, a front is sixty: {floor}"
    );
    // The burst went out at the configured size, so it is indistinguishable
    // from what a padded tunnel would have sent anyway.
    assert_eq!(front.sizes.len(), 2, "sizes: {:?}", front.sizes);
}

#[test]
fn a_busy_front_spends_the_burst_on_traffic() {
    const COUNT: u32 = 4;

    let front = simulate(vec![Machine::front_padding(COUNT, 100, 1400)], PAGE_LOAD, 1);
    println!("front over a page load: {front}");

    // The trace has more outbound packets than the burst has slots, and the
    // count is still exact: the machine walks a chain of states and ends.
    let outbound = PAGE_LOAD.iter().filter(|(inbound, _, _)| !inbound).count();
    assert!(
        outbound > COUNT as usize,
        "the trace must outlast the burst"
    );
    assert_eq!(front.injected, COUNT as usize, "{front}");
}

// ── 5. padding is indistinguishable in kind ──────────────────────────

#[test]
fn an_injected_padding_packet_is_an_openable_keepalive() {
    let (suite, mut a_send, _, _, mut b_recv) = link();

    // A padding packet is an empty payload padded to the target: the peer opens
    // it to an empty payload and discards it. No new message type, and nothing
    // about its form distinguishes it from a real keepalive — only its length,
    // which a `pad_to_size` machine makes identical to everything else's.
    let padding = a_send.seal_padded(&suite, &[], 1400).expect("padding");
    let keepalive = a_send.seal(&suite, &[]).expect("keepalive");

    assert_eq!(b_recv.open(&suite, &padding).expect("open padding"), b"");
    assert_eq!(
        b_recv.open(&suite, &keepalive).expect("open keepalive"),
        b""
    );
    assert!(
        padding.len() > keepalive.len(),
        "padding is what makes it the size of a full packet"
    );
}
