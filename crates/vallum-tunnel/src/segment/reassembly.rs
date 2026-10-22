// SPDX-License-Identifier: Apache-2.0

//! Segmentation: the half of the envelope that has state.
//!
//! [`super`] is the format. This module is the part that decides
//! when to use it and puts the pieces back together: a small, bounded table of
//! half-assembled messages keyed by source address and message id, and a
//! splitting rule for the way out.
//!
//! It sits between the socket and the [`Device`](crate::device::Device), on both
//! directions of the same datagram:
//!
//! ```text
//!   UDP datagram ──▶ Segments::inbound ──▶ a whole message ──▶ Device
//!   Device ──▶ a whole message ──▶ Segments::outbound ──▶ UDP datagrams
//! ```
//!
//! [`Device`](crate::device::Device) never sees a fragment and never emits one,
//! so the protocol above is unchanged by segmentation and the frozen vectors do
//! not move. This is a transport concern, and it belongs with the transport.
//!
//! # Why not IP fragmentation
//!
//! A tri-hybrid `InitHello` is 4 609 bytes: four IP fragments on a 1500-byte
//! path. Fragments two through four carry no UDP header, so a NAPT has no port
//! to rewrite and drops them; a stateful firewall commonly does the same, and
//! IPv6 fragment handling is worse than IPv4's. The failure is silent and
//! permanent — the handshake retransmits into the same wall — and it looks
//! exactly like a peer that is down. Every fragment here is a complete UDP
//! datagram with a transport header, so it traverses a NAT the same way the data
//! plane does.
//!
//! # What an attacker can spend
//!
//! A fragment is unauthenticated, like a whole datagram. The reassembled bytes
//! are authenticated the same way they would have been arriving whole (`mac1`
//! for a handshake, an AEAD tag for data), so an attacker cannot forge a message
//! by injecting a fragment, and cannot make one mean something else. What an
//! attacker *can* do is make the table hold memory it does not need, so the
//! table is bounded three ways:
//!
//! - At most [`MAX_REASSEMBLIES`] messages are held, each at most
//!   [`MAX_HANDSHAKE_MESSAGE`](vallum_core::MAX_HANDSHAKE_MESSAGE) bytes: 256 KiB of
//!   reassembly buffer, at the
//!   ceiling, for the whole device.
//! - An entry that has not seen a fragment for [`REASSEMBLY_TIMEOUT_MS`] is
//!   dropped. That is shorter than the 5 s handshake retransmission interval, so
//!   an abandoned attempt cannot hold a slot into the next one.
//! - When the table is full, the entry that has waited longest makes room. A
//!   live handshake is refreshed by every fragment, so it is never the oldest,
//!   and an attacker with a hundred addresses and a hundred partial messages can
//!   still only occupy [`MAX_REASSEMBLIES`] slots.
//!
//! `total` is validated against
//! [`MAX_HANDSHAKE_MESSAGE`](vallum_core::MAX_HANDSHAKE_MESSAGE) before anything is
//! allocated, so an entry is never bigger than a message could be.

use std::net::SocketAddr;

use super::{MAX_OUTER_DATAGRAM, OUTER_HEADER_LEN_V4, OUTER_HEADER_LEN_V6, REASSEMBLY_TIMEOUT_MS};

use crate::rng::Randomness;

/// How many messages the device will half-assemble at once.
///
/// A peer's handshake is one of these, and a device talks to few peers, so this
/// is generous for the legitimate case and a hard bound on the hostile one. See
/// the module docs for the arithmetic.
pub const MAX_REASSEMBLIES: usize = 16;

/// Splits outbound messages and reassembles inbound fragments.
///
/// One instance serves a whole device: the outbound half is stateless apart from
/// the ids it draws, and the inbound half is keyed by source address, so two
/// peers behind one NAT do not disturb each other.
#[derive(Debug)]
pub struct Segments {
    table: Vec<Partial>,
    dropped: u64,
    reassembled: u64,
    /// The largest UDP payload this path carries, in bytes.
    budget: usize,
}

impl Default for Segments {
    fn default() -> Self {
        Self::new()
    }
}

impl Segments {
    /// An empty segmenter for a 1500-byte outer path.
    #[must_use]
    pub fn new() -> Self {
        Self::with_budget(MAX_OUTER_DATAGRAM)
    }

    /// An empty segmenter for a path whose largest UDP payload is `budget`.
    ///
    /// `budget` is `path_mtu - 48` (IPv6 header + UDP header). The default is
    /// [`MAX_OUTER_DATAGRAM`]; a narrower path passes less. The receiver does not
    /// need to know it: the envelope carries explicit offsets.
    ///
    /// # Panics
    ///
    /// If `budget` is outside `FRAGMENT_HEADER_LEN + 1 ..= MAX_OUTER_DATAGRAM`.
    /// A budget that cannot carry an envelope is a construction bug, like an
    /// empty shaping machine — the config validates it before this is reached,
    /// and silently clamping would hide the one value the caller got wrong.
    #[must_use]
    pub fn with_budget(budget: usize) -> Self {
        assert!(
            (super::FRAGMENT_HEADER_LEN + 1..=MAX_OUTER_DATAGRAM).contains(&budget),
            "fragment budget {budget} cannot carry an envelope"
        );
        Self {
            table: Vec::with_capacity(MAX_REASSEMBLIES),
            dropped: 0,
            reassembled: 0,
            budget,
        }
    }

    /// The conservative budget this segmenter was built with.
    ///
    /// This is `outer_mtu − 48`, the IPv6 worst case, because the configured
    /// peer set may be reached over either family. The budget actually used for
    /// a message is [`Segments::budget_for`], which knows the destination.
    #[must_use]
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// Lower the budget after the path reported that a datagram did not fit.
    ///
    /// Only ever narrows. A budget is a ceiling, and raising it on the strength
    /// of one observation is how a tunnel starts blackholing again; widening is
    /// a separate decision that needs its own evidence. A value that cannot
    /// carry an envelope is ignored rather than panicking, because this runs on
    /// a live path where the alternative is killing the daemon.
    pub fn narrow_budget(&mut self, budget: usize) {
        if (super::FRAGMENT_HEADER_LEN + 1..=MAX_OUTER_DATAGRAM).contains(&budget)
            && budget < self.budget
        {
            self.budget = budget;
        }
    }

    /// The largest datagram for a destination of this family.
    ///
    /// The configured budget assumes the IPv6 header (48 bytes). An IPv4
    /// destination spends only 28, so it gets those 20 bytes back — capped by
    /// [`MAX_OUTER_DATAGRAM`], which is the protocol's ceiling. This is
    /// per-message rather than per-daemon, so a dual-stack peer set is handled
    /// without guessing.
    #[must_use]
    pub fn budget_for(&self, destination: SocketAddr) -> usize {
        let header = if destination.is_ipv4() {
            OUTER_HEADER_LEN_V4
        } else {
            OUTER_HEADER_LEN_V6
        };
        (self.budget + (OUTER_HEADER_LEN_V6 - header)).min(MAX_OUTER_DATAGRAM)
    }

    /// Fragments refused, and half-assembled messages abandoned.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Whole messages delivered out of fragments.
    #[must_use]
    pub fn reassembled(&self) -> u64 {
        self.reassembled
    }

    /// Messages currently half-assembled.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.table.len()
    }

    /// The datagrams to put on the wire for one message.
    ///
    /// A message that fits [`Segments::budget_for`] for `destination` is
    /// returned unchanged, as one datagram. A larger one is cut into fragments
    /// sharing one freshly drawn
    /// [`message_id`](vallum_core::super::Fragment::message_id).
    ///
    /// The id is drawn per call, so a retransmission is a new id and a fresh
    /// reassembly on the far side. That is deliberate: the far side would
    /// otherwise have to reason about whether two fragment sets are the same
    /// message, and the timeout is shorter than the retransmission interval, so
    /// the abandoned entry is gone before the new attempt arrives.
    ///
    /// A message longer than
    /// [`MAX_HANDSHAKE_MESSAGE`](vallum_core::MAX_HANDSHAKE_MESSAGE) — which the device cannot
    /// build, because `wire` refuses it at construction — is dropped rather than
    /// put on the wire whole. The budget is a property this module exists to
    /// keep, so a bug above it loses one message instead of quietly breaking the
    /// invariant for every caller downstream. It is counted in
    /// [`Segments::dropped`].
    pub fn outbound<R: Randomness + ?Sized>(
        &mut self,
        message: Vec<u8>,
        destination: SocketAddr,
        rng: &mut R,
    ) -> Vec<Vec<u8>> {
        let budget = self.budget_for(destination);
        if message.len() <= budget {
            return vec![message];
        }

        let mut id_bytes = [0u8; 4];
        rng.fill(&mut id_bytes);
        let message_id = u32::from_be_bytes(id_bytes);

        match super::split_with_budget(message_id, &message, budget) {
            Ok(datagrams) => datagrams,
            Err(_) => {
                self.dropped += 1;
                Vec::new()
            }
        }
    }

    /// Feed one datagram from `source`.
    ///
    /// Returns `Some(message)` when this datagram completed a message — either
    /// because it was one to begin with, or because it was the last fragment
    /// missing. Returns `None` when the datagram was a fragment that was
    /// accepted and held, or was refused.
    pub fn inbound(&mut self, now_ms: u64, source: SocketAddr, bytes: Vec<u8>) -> Option<Vec<u8>> {
        if !super::is_fragment(&bytes) {
            return Some(bytes);
        }

        self.expire(now_ms);

        let Ok((head, data)) = super::parse(&bytes) else {
            self.dropped += 1;
            return None;
        };

        let slot = match self.position(source, head.message_id) {
            Some(position) => position,
            None => self.open(source, head.message_id, usize::from(head.total), now_ms),
        };

        // `parse` has already checked that this fragment fits inside the message
        // it claims to be part of, so no copy can run past the end.
        let offset = usize::from(head.offset);
        let entry = &mut self.table[slot];
        entry.data[offset..offset + data.len()].copy_from_slice(data);
        entry.received += entry.cover(offset, data.len());
        entry.updated_ms = now_ms;

        if entry.received < entry.total {
            return None;
        }

        self.reassembled += 1;
        Some(self.table.swap_remove(slot).data)
    }

    /// Drop entries that have waited longer than the timeout.
    fn expire(&mut self, now_ms: u64) {
        let before = self.table.len();
        self.table
            .retain(|entry| now_ms.saturating_sub(entry.updated_ms) < REASSEMBLY_TIMEOUT_MS);
        self.dropped += (before - self.table.len()) as u64;
    }

    fn position(&self, source: SocketAddr, message_id: u32) -> Option<usize> {
        self.table
            .iter()
            .position(|entry| entry.source == source && entry.message_id == message_id)
    }

    /// Start a reassembly, making room if the table is full.
    fn open(&mut self, source: SocketAddr, message_id: u32, total: usize, now_ms: u64) -> usize {
        if self.table.len() >= MAX_REASSEMBLIES {
            // The entry that has waited longest goes. A live handshake is
            // refreshed by every fragment, so it is never the oldest.
            if let Some((position, _)) = self
                .table
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.updated_ms)
            {
                self.table.swap_remove(position);
                self.dropped += 1;
            }
        }

        self.table.push(Partial {
            source,
            message_id,
            total,
            data: vec![0u8; total],
            coverage: vec![0u64; total.div_ceil(64)],
            received: 0,
            updated_ms: now_ms,
        });
        self.table.len() - 1
    }
}

/// One message being reassembled.
#[derive(Debug)]
struct Partial {
    source: SocketAddr,
    message_id: u32,
    total: usize,
    data: Vec<u8>,
    /// One bit per byte of `data`: whether that byte has arrived. A duplicate or
    /// overlapping fragment cannot inflate `received` past `total`, because only
    /// unset bits count as fresh.
    coverage: Vec<u64>,
    received: usize,
    updated_ms: u64,
}

impl Partial {
    /// Mark `offset..offset + len` as arrived, returning how many bytes were new.
    fn cover(&mut self, offset: usize, len: usize) -> usize {
        let mut fresh = 0;
        for index in offset..offset + len {
            let word = index / 64;
            let bit = 1u64 << (index % 64);
            if self.coverage[word] & bit == 0 {
                self.coverage[word] |= bit;
                fresh += 1;
            }
        }
        fresh
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::super::{Fragment, MAX_FRAGMENT_DATA};
    use super::*;
    use vallum_core::MAX_HANDSHAKE_MESSAGE;

    /// A deterministic generator, so an id is reproducible. See [`Randomness`].
    #[derive(Debug)]
    struct Counting(u32);

    impl Randomness for Counting {
        fn fill(&mut self, out: &mut [u8]) {
            for byte in out.iter_mut() {
                *byte = (self.0 & 0xFF) as u8;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// A hand-built fragment, for the cases a well-behaved sender will not make.
    fn fragment(id: u32, offset: u16, total: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Fragment {
            message_id: id,
            offset,
            total,
        }
        .encode()
        .to_vec();
        out.extend_from_slice(data);
        out
    }

    fn split(id: u32, data: &[u8]) -> Vec<Vec<u8>> {
        super::super::split(id, data).expect("a legal message")
    }

    fn v4_dest() -> SocketAddr {
        "203.0.113.9:51820".parse().expect("a v4 endpoint")
    }

    fn v6_dest() -> SocketAddr {
        "[2001:db8::9]:51820".parse().expect("a v6 endpoint")
    }

    #[test]
    fn a_message_that_fits_is_one_datagram() {
        let mut segments = Segments::new();
        let mut rng = Counting(0);
        assert_eq!(
            segments.outbound(message(100), v4_dest(), &mut rng),
            vec![message(100)]
        );
        // Exactly at the budget is still one datagram: only over it is cut.
        assert_eq!(
            segments
                .outbound(message(MAX_OUTER_DATAGRAM), v4_dest(), &mut rng)
                .len(),
            1
        );
        assert!(
            segments
                .outbound(message(MAX_OUTER_DATAGRAM + 1), v4_dest(), &mut rng)
                .len()
                > 1
        );
        assert_eq!(segments.dropped(), 0);
    }

    #[test]
    fn a_large_message_never_produces_an_oversize_datagram() {
        let mut segments = Segments::new();
        let mut rng = Counting(0);
        // The tri-hybrid InitHello, the RespHello, and the largest message the
        // cap admits.
        for len in [4609, 4378, MAX_HANDSHAKE_MESSAGE] {
            let outbound = segments.outbound(message(len), v4_dest(), &mut rng);
            assert!(
                outbound
                    .iter()
                    .all(|datagram| datagram.len() <= segments.budget_for(v4_dest())),
                "a {len}-byte message produced an oversize datagram"
            );
            assert_eq!(segments.pending(), 0, "outbound holds no state");
        }
    }

    #[test]
    fn fragments_reassemble_in_any_order_and_only_once() {
        let source = addr(5000);
        let original = message(4609);
        let datagrams = split(7, &original);
        assert!(datagrams.len() > 1);

        let mut receiver = Segments::new();
        // Reverse order, with one fragment duplicated before the set completes.
        let mut order: Vec<usize> = (0..datagrams.len()).rev().collect();
        order.insert(1, order[0]);

        let mut completed = None;
        for index in order {
            if let Some(whole) = receiver.inbound(1_000, source, datagrams[index].clone()) {
                assert!(completed.is_none(), "a fragment set completed twice");
                completed = Some(whole);
            }
        }
        assert_eq!(completed.expect("the message completed"), original);
        assert_eq!(receiver.pending(), 0, "a completed reassembly is dropped");
        assert_eq!(receiver.reassembled(), 1);
        assert_eq!(receiver.dropped(), 0);
    }

    #[test]
    fn two_messages_from_one_address_do_not_mix() {
        let source = addr(5000);
        let mut receiver = Segments::new();
        let first = message(3000);
        let second = message(4000);
        let one = split(1, &first);
        let two = split(2, &second);

        let mut got = Vec::new();
        for index in 0..one.len().max(two.len()) {
            for datagrams in [&one, &two] {
                if let Some(whole) = datagrams
                    .get(index)
                    .and_then(|datagram| receiver.inbound(1_000, source, datagram.clone()))
                {
                    got.push(whole);
                }
            }
        }
        assert_eq!(got, vec![first, second], "both completed, neither mixed");
        assert_eq!(receiver.pending(), 0);
    }

    #[test]
    fn two_peers_behind_one_address_are_separate() {
        // The same fragment set, from two ports: one NAT, and the reason the key
        // is the whole address rather than the host.
        let datagrams = split(3, &message(3000));
        let mut receiver = Segments::new();
        let mut done = 0;
        for port in [5000u16, 5001] {
            for datagram in &datagrams {
                if receiver
                    .inbound(1_000, addr(port), datagram.clone())
                    .is_some()
                {
                    done += 1;
                }
            }
        }
        assert_eq!(done, 2, "one message each");
    }

    #[test]
    fn a_whole_message_is_passed_through_untouched() {
        let mut receiver = Segments::new();
        // An `InitHello` header: `01 01`, not `01 07`.
        let datagram = {
            let mut bytes = vec![0x01, 0x01];
            bytes.extend_from_slice(&[0xAA; 64]);
            bytes
        };
        assert_eq!(
            receiver.inbound(1_000, addr(5000), datagram.clone()),
            Some(datagram)
        );
        assert_eq!(receiver.pending(), 0, "a whole message is not held");
        assert_eq!(receiver.dropped(), 0);
    }

    #[test]
    fn a_bad_fragment_is_refused_and_claims_nothing() {
        let mut receiver = Segments::new();
        let source = addr(5000);
        let refused = [
            // Truncated inside the envelope.
            vec![0x01, 0x07],
            // A message past the cap.
            fragment(1, 0, u16::MAX, b"x"),
            // Data beyond the message it claims to be part of.
            fragment(1, 90, 100, &[0u8; 20]),
            // More data than the envelope has room for.
            fragment(1, 0, u16::MAX, &[0u8; MAX_FRAGMENT_DATA + 1]),
            // A zero-length message.
            fragment(1, 0, 0, b""),
        ];
        for datagram in refused {
            assert_eq!(receiver.inbound(1_000, source, datagram), None);
        }
        assert_eq!(receiver.dropped(), 5);
        assert_eq!(receiver.pending(), 0, "a refused fragment holds nothing");
    }

    #[test]
    fn a_stale_reassembly_is_abandoned_and_a_retransmission_starts_over() {
        let source = addr(5000);
        let datagrams = split(9, &message(4609));
        let mut receiver = Segments::new();

        assert_eq!(receiver.inbound(1_000, source, datagrams[0].clone()), None);
        assert_eq!(receiver.pending(), 1);

        // A duplicate one millisecond short of the timeout refreshes the entry
        // rather than expiring it.
        assert_eq!(
            receiver.inbound(
                1_000 + REASSEMBLY_TIMEOUT_MS - 1,
                source,
                datagrams[0].clone()
            ),
            None
        );
        assert_eq!(receiver.pending(), 1, "a fragment refreshes the clock");
        assert_eq!(receiver.dropped(), 0);

        // Past the timeout, the entry goes — and the fragment that follows opens
        // a fresh one, which is why a retransmission never sees a stale half.
        assert_eq!(
            receiver.inbound(
                2_000 + 2 * REASSEMBLY_TIMEOUT_MS,
                source,
                datagrams[0].clone()
            ),
            None
        );
        assert_eq!(receiver.dropped(), 1, "the abandoned entry was counted");
        assert_eq!(receiver.pending(), 1, "and the new one is open");

        // The rest of the set completes it, so nothing was lost with the entry.
        let mut completed = None;
        for datagram in &datagrams[1..] {
            if let Some(whole) = receiver.inbound(9_000, source, datagram.clone()) {
                completed = Some(whole);
            }
        }
        assert_eq!(completed, Some(message(4609)));
        assert_eq!(receiver.reassembled(), 1);
    }

    #[test]
    fn the_table_is_bounded_and_evicts_the_longest_waiting() {
        let mut receiver = Segments::new();
        // The first fragment of a 16 KiB message, from a different port each
        // time: the shape of a flood.
        for port in 0..(MAX_REASSEMBLIES as u16 + 4) {
            let datagram = fragment(1, 0, MAX_HANDSHAKE_MESSAGE as u16, &[0u8; 16]);
            assert_eq!(receiver.inbound(1_000, addr(5_000 + port), datagram), None);
            assert!(
                receiver.pending() <= MAX_REASSEMBLIES,
                "the table outgrew its bound"
            );
        }
        assert_eq!(receiver.pending(), MAX_REASSEMBLIES);
        assert!(receiver.dropped() >= 4, "the four oldest were evicted");
    }

    #[test]
    fn a_message_the_device_could_not_have_built_is_dropped_not_sent_whole() {
        // A caller bug: more than the cap. The budget is kept — the message does
        // not go on the wire in pieces, and not whole either.
        let mut segments = Segments::new();
        assert!(segments
            .outbound(
                message(MAX_HANDSHAKE_MESSAGE + 1),
                v4_dest(),
                &mut Counting(0)
            )
            .is_empty());
        assert_eq!(segments.dropped(), 1);
    }

    #[test]
    fn a_v4_destination_gets_the_header_slack_back() {
        // The configured budget assumes the IPv6 header (48). A v4 destination
        // spends 28, so it gets 20 bytes back — never above the protocol cap.
        let narrow = Segments::with_budget(1_000);
        assert_eq!(narrow.budget_for(v4_dest()), 1_020);
        assert_eq!(narrow.budget_for(v6_dest()), 1_000);

        let default = Segments::new();
        assert_eq!(default.budget_for(v4_dest()), MAX_OUTER_DATAGRAM);
        assert_eq!(default.budget_for(v6_dest()), MAX_OUTER_DATAGRAM);
    }

    #[test]
    fn a_narrow_budget_is_honoured_on_the_way_out() {
        // A 1000-byte path: every datagram must fit it, including the ones that
        // would have been whole at the default budget.
        let mut segments = Segments::with_budget(1_000);
        assert_eq!(segments.budget(), 1_000);

        let datagrams = segments.outbound(message(1_200), v4_dest(), &mut Counting(0));
        assert!(datagrams.len() > 1, "a 1200-byte message must be cut");
        for datagram in &datagrams {
            assert!(
                datagram.len() <= segments.budget_for(v4_dest()),
                "a datagram exceeded the narrow budget: {}",
                datagram.len()
            );
        }

        // And the receiver, which does not know the budget, still reassembles it.
        let mut receiver = Segments::new();
        let mut whole = None;
        for datagram in datagrams {
            if let Some(message) = receiver.inbound(0, "10.0.0.1:1".parse().unwrap(), datagram) {
                whole = Some(message);
            }
        }
        assert_eq!(whole, Some(message(1_200)));
    }

    #[test]
    #[should_panic(expected = "cannot carry an envelope")]
    fn a_budget_too_small_for_the_envelope_is_a_construction_bug() {
        let _ = Segments::with_budget(super::super::FRAGMENT_HEADER_LEN);
    }

    #[test]
    fn narrowing_a_budget_takes_effect_and_never_widens() {
        let mut segments = Segments::with_budget(1_448);
        segments.narrow_budget(1_152);
        assert_eq!(segments.budget(), 1_152, "a narrower path must be adopted");
        // A later reading that looks wider must not undo it. A budget is a
        // ceiling, and one observation is not evidence to raise it.
        segments.narrow_budget(1_400);
        assert_eq!(segments.budget(), 1_152);
    }

    #[test]
    fn narrowing_to_a_value_that_cannot_carry_an_envelope_is_ignored() {
        // This runs on a live path. Killing the daemon over a nonsensical
        // reading would be worse than keeping the budget it already had.
        let mut segments = Segments::with_budget(1_448);
        segments.narrow_budget(super::super::FRAGMENT_HEADER_LEN);
        assert_eq!(segments.budget(), 1_448);
        segments.narrow_budget(MAX_OUTER_DATAGRAM + 1);
        assert_eq!(segments.budget(), 1_448);
    }
}
