// SPDX-License-Identifier: Apache-2.0

//! Traffic-analysis shaping: probabilistic machines that pad and delay.
//!
//! A tunnel that is cryptographically flawless still leaks through its
//! **metadata**: which packets are large, which direction dominates, how long
//! the silences are. That is what traffic analysis keys on, and no amount of
//! cipher strength touches it. This module is Vallum's answer, modelled on
//! Maybenot's: a defense is a small **probabilistic state machine**, the
//! transport feeds it **events**, and it answers with **actions**.
//!
//! The framework is the deliverable, not any one defense. Attacks and defenses
//! both move; a machine is data, and a new defense is a new table, not a new
//! release of the protocol.
//!
//! ```text
//! transport ──Event──▶ Shaper ──Effect(Action)──▶ transport
//!   NormalSent  ─┬─▶ machine 0 : Pad { target: 1400 } ─▶ seal_padded(pkt, 1400)
//!   NormalRecv  ─┼─▶ machine 1 : Inject { count: 1 } ─▶ seal_padded(&[], size)
//!   Timeout     ─┴─▶ machine 2 : Block { timeout_ms } ─▶ hold outgoing
//! ```
//!
//! # The privacy parameter
//!
//! A shaped tunnel's residual signal is described by two things, and they are
//! what a machine trades bandwidth and latency against:
//!
//! * **the size set** — the set of distinct observable packet lengths. Its
//!   *cardinality* is the length channel's capacity in the worst case: one
//!   length carries no information, `n` lengths carry `log₂ n` bits per packet.
//!   [`Machine::pad_to_size`] collapses the set to one value, closing the length
//!   channel entirely; that is the strongest statement this module can make.
//! * **the timing and volume profile** — inter-packet gaps and packet-count
//!   bursts. [`Machine::min_interval`] edits the gaps;
//!   [`Machine::respond_with_padding`] edits the counts. Neither is closed, only
//!   blurred, and the cost is the point: every injected packet is bandwidth and
//!   every block is latency. `docs/proof/traffic-shaping.md` measures both.
//!
//! # Where the padding actually goes
//!
//! A `Pad` action names the length of the **sealed plaintext**
//! ([`crate::data::Sender::seal_padded`]): the ciphertext's length is then a
//! chosen quantity rather than a leak of the payload's size, and the true length
//! travels *inside* the AEAD, so it cannot be forged. Nothing here is
//! unauthenticated — a padding scheme you can strip from the outside would be
//! worse than none, because it would tell an observer precisely which packets
//! were padded.
//!
//! Shaping is **off by default**: build no [`Shaper`], or give it an empty
//! machine list, and the transport pads nothing. Nothing in the handshake or the
//! key schedule depends on this module.
//!
//! # What this is not
//!
//! Not a port of Maybenot. Deliberately omitted, and not claimed:
//!
//! * **framework-wide fraction limits** — Maybenot's global cost budget over
//!   total blocking duration. Vallum bounds cost per machine and per state
//!   ([`UNLIMITED`] to opt out), which is coarser and simpler; a deployment that
//!   wants a global budget should bound the machines it installs.
//! * **the sampled-timeout scheduler** — here a machine acts on the event it
//!   sees and a long-lived action carries its own duration. The transport owns
//!   the clock, exactly as it does for [`crate::timer::Timers`].
//! * **machine negotiation and replacement** — which machines run is local
//!   policy on each end, like identity mode. Padding changes the size of a
//!   packet, not its meaning, so the two ends need not agree on machines at all.
//! * **the network model** — the simulator in the gate artefact measures the
//!   *local* cost of shaping (bytes added, packets held), not an adversary's
//!   inference. A defense that is measured cheap and a defense that is measured
//!   *effective* are different claims, and this module only makes the first.

use core::fmt;

/// A next-state value meaning "the machine is done".
pub const MACHINE_END: u16 = u16::MAX;

/// A state limit meaning "no limit".
pub const UNLIMITED: u32 = u32::MAX;

/// What the transport tells the framework.
///
/// Events are the transport's, not the protocol's: nothing here is on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// About to seal and send a normal (non-padding) packet.
    ///
    /// Fires *before* the seal, so a [`Action::Pad`] produced in response
    /// applies to this packet. This is the one place Vallum's timing differs
    /// from Maybenot's `NormalSent`, which is a post-send notification.
    NormalSent,
    /// A normal packet arrived.
    NormalRecv,
    /// About to send a padding (keepalive) packet.
    TunnelSent,
    /// A padding packet arrived.
    TunnelRecv,
    /// The duration of an [`Action::Block`] has elapsed.
    ///
    /// Delivered only to machines that are currently blocked, and it releases
    /// all of them: the transport has one clock, and a machine that is blocked
    /// is precisely one that is waiting for this event.
    Timeout,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::NormalSent => "NormalSent",
            Self::NormalRecv => "NormalRecv",
            Self::TunnelSent => "TunnelSent",
            Self::TunnelRecv => "TunnelRecv",
            Self::Timeout => "Timeout",
        };
        f.write_str(name)
    }
}

/// What a machine asks the transport to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Pad the packet being sent so its sealed plaintext is `target` bytes.
    ///
    /// `target` must be at least the payload's length plus
    /// [`crate::data::PAYLOAD_LEN_SIZE`], and at most what
    /// [`crate::wire::MAX_DATA_MESSAGE`] can frame; a machine that asks for
    /// either extreme gets a [`crate::error::DataError`] from the seal rather
    /// than a silently unpadded packet.
    Pad {
        /// The sealed-plaintext length to pad to.
        target: u16,
    },
    /// Send `count` padding packets, each with `size` bytes of sealed plaintext.
    ///
    /// A padding packet is a keepalive — an empty payload — padded to `size`.
    /// The peer discards it on open, so no message type is needed for it.
    Inject {
        /// How many packets to send.
        count: u16,
        /// Each one's sealed-plaintext length.
        size: u16,
    },
    /// Hold normal outgoing traffic for `timeout_ms`.
    ///
    /// The transport reports the wait's end with [`Event::Timeout`]. Blocking is
    /// what buys timing obscurity, and it is paid for in latency.
    Block {
        /// How long to hold.
        timeout_ms: u64,
    },
}

/// One branch out of a state: a weighted choice of what to do and where to go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Branch {
    /// Relative weight. Weights need not sum to anything; the sample is
    /// `draw mod Σweight`, so a weight of `0` is never chosen (and a set of all
    /// zero weights is a dead end).
    pub weight: u32,
    /// What to do if this branch is taken, if anything.
    pub action: Option<Action>,
    /// The state to move to, or [`MACHINE_END`].
    pub next: u16,
}

impl Branch {
    /// A branch that acts and moves on.
    #[must_use]
    pub const fn act(weight: u32, action: Action, next: u16) -> Self {
        Self {
            weight,
            action: Some(action),
            next,
        }
    }

    /// A branch that only moves.
    #[must_use]
    pub const fn pass(weight: u32, next: u16) -> Self {
        Self {
            weight,
            action: None,
            next,
        }
    }
}

/// One state: what to do per event, and how often it may act at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// How many actions this state may produce before it goes quiet.
    ///
    /// The state keeps transitioning — only the *action* is suppressed. Use
    /// [`UNLIMITED`] for no cap. This is the cost bound: a machine that injects
    /// padding cannot be talked into injecting without end.
    pub limit: u32,
    /// Event-keyed branches. An event with no entry is a no-op, not an error:
    /// machines see events they do not care about all the time.
    pub on: Vec<(Event, Vec<Branch>)>,
}

impl State {
    /// A state with the given limit and no transitions.
    #[must_use]
    pub const fn new(limit: u32) -> Self {
        Self {
            limit,
            on: Vec::new(),
        }
    }

    /// Add the branches taken on `event`.
    #[must_use]
    pub fn on(mut self, event: Event, branches: Vec<Branch>) -> Self {
        self.on.push((event, branches));
        self
    }
}

/// A shaping defense: a probabilistic finite state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    /// The states. State `0` is where the machine starts.
    pub states: Vec<State>,
}

impl Machine {
    /// A machine over the given states, starting in state `0`.
    ///
    /// # Panics
    ///
    /// If `states` is empty — a machine with nowhere to be is a construction
    /// bug, not a runtime condition, and silently doing nothing would hide it.
    #[must_use]
    pub fn new(states: Vec<State>) -> Self {
        assert!(
            !states.is_empty(),
            "a shaping machine needs at least one state"
        );
        Self { states }
    }

    /// Pad every normal packet to `target` bytes of sealed plaintext.
    ///
    /// The strongest statement in this module: the observable size set becomes
    /// `{target}`, so packet length carries no information at all. It is also
    /// the most expensive in bandwidth, because a small packet is padded to the
    /// same length as a large one.
    #[must_use]
    pub fn pad_to_size(target: u16) -> Self {
        Self::new(vec![State::new(UNLIMITED).on(
            Event::NormalSent,
            vec![Branch::act(1, Action::Pad { target }, 0)],
        )])
    }

    /// With probability `injections / (injections + 1)`, answer a received
    /// packet with one padding packet of `size` bytes, up to `cap` times.
    ///
    /// The weights are integer, so the odds are exact and the sampler needs only
    /// a `u64`. `injections = 0` makes the machine inert — useful in a config
    /// file where a defense is written down but disabled.
    #[must_use]
    pub fn respond_with_padding(size: u16, injections: u32, cap: u32) -> Self {
        Self::new(vec![State::new(cap).on(
            Event::NormalRecv,
            vec![
                Branch::act(injections, Action::Inject { count: 1, size }, 0),
                Branch::pass(1, 0),
            ],
        )])
    }

    /// Hold further outgoing packets for `interval_ms` after each normal send.
    ///
    /// A crude rate limiter: it turns a burst into a train, which is what makes
    /// the timing channel fuzzy. The cost is exactly `interval_ms` of added
    /// latency per packet, paid in full.
    #[must_use]
    pub fn min_interval(interval_ms: u64) -> Self {
        Self::new(vec![
            State::new(UNLIMITED).on(
                Event::NormalSent,
                vec![Branch::act(
                    1,
                    Action::Block {
                        timeout_ms: interval_ms,
                    },
                    1,
                )],
            ),
            State::new(UNLIMITED).on(Event::Timeout, vec![Branch::pass(1, 0)]),
        ])
    }
}

/// An action, and the machine that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effect {
    /// The index of the machine in the [`Shaper`]'s list.
    pub machine: usize,
    /// What to do.
    pub action: Action,
}

/// One running machine.
#[derive(Debug, Clone)]
struct Running {
    machine: Machine,
    state: u16,
    /// How many actions each state has produced so far.
    activations: Vec<u32>,
}

impl Running {
    fn new(machine: Machine) -> Self {
        let activations = vec![0; machine.states.len()];
        Self {
            machine,
            state: 0,
            activations,
        }
    }

    /// Whether the machine has reached [`MACHINE_END`].
    fn ended(&self) -> bool {
        self.state == MACHINE_END
    }

    /// Take one step, returning the action to take if any.
    fn step(&mut self, event: Event, draw: u64) -> Option<Action> {
        let index = usize::from(self.state);
        let state = self.machine.states.get(index)?;

        let branches = state
            .on
            .iter()
            .find(|(candidate, _)| *candidate == event)
            .map(|(_, branches)| branches)?;

        let total: u64 = branches.iter().map(|b| u64::from(b.weight)).sum();
        if total == 0 {
            return None;
        }

        // Sample `draw` uniformly in `[0, total)`. A caller-supplied draw rather
        // than an internal generator keeps this module free of any RNG, and
        // keeps a machine's behaviour reproducible under test.
        let mut point = draw % total;
        let mut chosen = None;
        for branch in branches {
            if point < u64::from(branch.weight) {
                chosen = Some(branch);
                break;
            }
            point -= u64::from(branch.weight);
        }
        let chosen = chosen?;

        // The limit suppresses the *action*, not the transition: a machine that
        // has spent its budget still tracks the traffic, it just stops acting.
        let action = match chosen.action {
            Some(action) => {
                let spent = self.activations.get(index).copied().unwrap_or(u32::MAX);
                if spent < state.limit {
                    if let Some(slot) = self.activations.get_mut(index) {
                        *slot = spent.saturating_add(1);
                    }
                    Some(action)
                } else {
                    None
                }
            }
            None => None,
        };

        self.state = chosen.next;
        action
    }
}

/// A set of shaping machines, driven by the transport.
///
/// The shaper is deliberately passive: it holds no clock, no sockets, and no
/// keys. It is a pure function of `(state, event, draw)`, which is what makes a
/// defense reviewable and its cost measurable.
#[derive(Debug, Clone)]
pub struct Shaper {
    machines: Vec<Running>,
    /// Which machines have a [`Action::Block`] outstanding.
    awaiting: Vec<bool>,
}

impl Shaper {
    /// A shaper over the given machines. An empty list is the default: no
    /// shaping happens and `handle` returns nothing.
    #[must_use]
    pub fn new(machines: Vec<Machine>) -> Self {
        let awaiting = vec![false; machines.len()];
        Self {
            machines: machines.into_iter().map(Running::new).collect(),
            awaiting,
        }
    }

    /// The number of machines installed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.machines.len()
    }

    /// Whether no machines are installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.machines.is_empty()
    }

    /// The current state of machine `index`, if it exists and has not ended.
    #[must_use]
    pub fn state_of(&self, index: usize) -> Option<u16> {
        let running = self.machines.get(index)?;
        (!running.ended()).then_some(running.state)
    }

    /// Feed one event, returning everything the machines want done.
    ///
    /// `draw` is the caller's randomness: one uniform `u64` is enough for every
    /// machine (each takes it modulo its own weight total). Reusing the same
    /// draw for two machines correlates them; the transport should draw once per
    /// event from a source an observer cannot predict.
    ///
    /// [`Event::Timeout`] reaches only the machines that are blocked.
    pub fn handle(&mut self, event: Event, draw: u64) -> Vec<Effect> {
        let mut effects = Vec::new();

        for index in 0..self.machines.len() {
            let blocked = self.awaiting.get(index).copied().unwrap_or(false);
            if event == Event::Timeout {
                if !blocked {
                    continue;
                }
                if let Some(slot) = self.awaiting.get_mut(index) {
                    *slot = false;
                }
            }

            let Some(running) = self.machines.get_mut(index) else {
                continue;
            };
            let Some(action) = running.step(event, draw) else {
                continue;
            };

            if matches!(action, Action::Block { .. }) {
                if let Some(slot) = self.awaiting.get_mut(index) {
                    *slot = true;
                }
            }

            effects.push(Effect {
                machine: index,
                action,
            });
        }

        effects
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_acts_only_on_its_own_event() {
        let mut shaper = Shaper::new(vec![Machine::pad_to_size(1400)]);

        assert_eq!(
            shaper.handle(Event::NormalSent, 0),
            vec![Effect {
                machine: 0,
                action: Action::Pad { target: 1400 },
            }]
        );
        assert!(shaper.handle(Event::NormalRecv, 0).is_empty());
        assert!(
            shaper.handle(Event::Timeout, 0).is_empty(),
            "nothing blocked"
        );
        assert_eq!(shaper.len(), 1);
        assert!(!shaper.is_empty());
        assert_eq!(shaper.state_of(0), Some(0));
    }

    #[test]
    fn the_weights_are_exact_and_draw_driven() {
        // 2/3 chance of injecting, 1/3 of passing: 3 total weight.
        let mut shaper = Shaper::new(vec![Machine::respond_with_padding(300, 2, UNLIMITED)]);

        for draw in 0..6u64 {
            let effects = shaper.handle(Event::NormalRecv, draw);
            let expected = if draw % 3 < 2 {
                vec![Effect {
                    machine: 0,
                    action: Action::Inject {
                        count: 1,
                        size: 300,
                    },
                }]
            } else {
                Vec::new()
            };
            assert_eq!(effects, expected, "draw {draw}");
        }
    }

    #[test]
    fn a_state_limit_caps_the_actions_it_can_produce() {
        let mut shaper = Shaper::new(vec![Machine::respond_with_padding(300, 1, 2)]);

        // Weights 1 and 1: even draws inject, odd draws pass. Take three
        // injecting draws; the third is refused by the cap.
        assert_eq!(shaper.handle(Event::NormalRecv, 0).len(), 1);
        assert_eq!(shaper.handle(Event::NormalRecv, 2).len(), 1);
        assert!(
            shaper.handle(Event::NormalRecv, 4).is_empty(),
            "cap reached"
        );
        // The machine also still tracks a non-acting branch.
        assert!(shaper.handle(Event::NormalRecv, 1).is_empty());
    }

    #[test]
    fn an_inert_machine_does_nothing() {
        let mut shaper = Shaper::new(vec![Machine::respond_with_padding(300, 0, UNLIMITED)]);
        for draw in 0..4u64 {
            assert!(shaper.handle(Event::NormalRecv, draw).is_empty());
        }
    }

    #[test]
    fn a_block_arms_and_only_a_timeout_disarms_it() {
        let mut shaper = Shaper::new(vec![Machine::min_interval(50)]);

        assert_eq!(
            shaper.handle(Event::NormalSent, 0),
            vec![Effect {
                machine: 0,
                action: Action::Block { timeout_ms: 50 },
            }]
        );
        assert_eq!(shaper.state_of(0), Some(1), "moved into the waiting state");

        // A timeout that arrives while blocked is delivered.
        assert!(
            shaper.handle(Event::Timeout, 0).is_empty(),
            "no action, but seen"
        );
        assert_eq!(shaper.state_of(0), Some(0));

        // A second timeout with nothing outstanding reaches no machine.
        assert!(shaper.handle(Event::Timeout, 0).is_empty());
    }

    #[test]
    fn a_machine_that_reaches_the_end_stops() {
        let machine = Machine::new(vec![State::new(UNLIMITED).on(
            Event::NormalSent,
            vec![Branch::act(1, Action::Pad { target: 64 }, MACHINE_END)],
        )]);
        let mut shaper = Shaper::new(vec![machine]);

        assert_eq!(shaper.handle(Event::NormalSent, 0).len(), 1);
        assert_eq!(shaper.state_of(0), None, "the machine has ended");
        assert!(shaper.handle(Event::NormalSent, 0).is_empty());
    }

    #[test]
    fn an_empty_shaper_is_a_no_op() {
        let mut shaper = Shaper::new(Vec::new());
        assert!(shaper.is_empty());
        assert!(shaper.handle(Event::NormalSent, 7).is_empty());
        assert!(shaper.handle(Event::Timeout, 7).is_empty());
    }

    #[test]
    #[should_panic(expected = "at least one state")]
    fn a_machine_without_states_is_a_bug() {
        let _ = Machine::new(Vec::new());
    }
}
