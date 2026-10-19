// SPDX-License-Identifier: Apache-2.0

//! Cryptokey routing, peer lookup, and index allocation.

use super::*;

impl Device {
    /// The peer with the longest matching prefix for `destination`.
    ///
    /// Longest-prefix match, not first match: a `/32` host route must beat a
    /// `/24` subnet, or a peer given a single address could be shadowed by another
    /// peer's wider prefix.
    pub(super) fn route(&self, destination: &IpAddr) -> Option<usize> {
        let mut best: Option<(u8, usize)> = None;
        for (index, peer) in self.peers.iter().enumerate() {
            let mut longest: Option<u8> = None;
            for net in peer.config.allowed_ips().nets() {
                if net.contains(destination) {
                    let prefix = net.prefix_len();
                    longest = Some(longest.map_or(prefix, |current| current.max(prefix)));
                }
            }
            if let Some(prefix) = longest {
                if best.is_none_or(|(best_prefix, _)| prefix > best_prefix) {
                    best = Some((prefix, index));
                }
            }
        }
        best.map(|(_, index)| index)
    }

    /// The peer, if any, whose *configured* endpoint is `source`.
    pub(super) fn peer_owning_endpoint(&self, source: SocketAddr) -> Option<PeerId> {
        self.peers
            .iter()
            .position(|peer| peer.config.endpoint() == Some(source))
            .map(PeerId::from_index)
    }

    /// The peer whose precomputed hint matches.
    ///
    /// The hint is confidential but **not** authenticated, so a match here is a
    /// lookup, not a conclusion: [`responder_accept`] re-derives the hint for the
    /// chosen peer and refuses if they disagree. A collision costs a failed
    /// handshake, never a session under the wrong peer.
    pub(super) fn peer_with_hint(&self, hint: &[u8; PEER_HINT_SIZE]) -> Option<usize> {
        self.peers.iter().position(|peer| &peer.hint == hint)
    }

    /// Reserve a session index that nothing else owns.
    pub(super) fn alloc_index(&mut self) -> u32 {
        loop {
            let index = self.next_index;
            // Zero is reserved for cookie replies, which belong to no session.
            self.next_index = self.next_index.wrapping_add(1).max(1);
            if index != 0 && !self.index.contains_key(&index) {
                return index;
            }
        }
    }

    /// Rebuild this peer's entries in the index map from its current state.
    ///
    /// Called after *every* change to a session, a handshake, or a retained epoch,
    /// so the map is a projection of the peer table rather than a second source of
    /// truth that can drift.
    pub(super) fn remap(&mut self, index: usize) {
        let peer_id = PeerId::from_index(index);
        for stale in self.peers[index].indices.drain(..) {
            self.index.remove(&stale);
        }
        let mut current = Vec::with_capacity(3);
        if let Some(session) = &self.peers[index].session {
            current.push(session.own_index());
        }
        if let Some(previous) = self.peers[index].previous_own_index {
            current.push(previous);
        }
        if let Some(handshake) = self.peers[index].handshake.index() {
            current.push(handshake);
        }
        for owned in &current {
            self.index.insert(*owned, peer_id);
        }
        self.peers[index].indices = current;
    }
}
