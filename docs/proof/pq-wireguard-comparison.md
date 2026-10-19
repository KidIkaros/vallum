# PQ-WireGuard comparison

**Source:** Hülsing, Ning, Weber, Schwabe, Zimmermann, *Post-quantum WireGuard*,
25 September 2023. This artefact records what Vallum shares with the paper, what
it deliberately does differently, and what it does **not** claim.

---

## 1. The paper's numbers

| Quantity | PQ-WireGuard |
|---|---|
| Handshake messages | 3 |
| Packets | 3, each ≤ 1232 B of UDP payload (one unfragmented IPv6 packet) |
| Total traffic (IPv6) | 2654 B |
| Client / server time | ~1.0 ms / ~0.79 ms on the paper's hardware |
| KEMs | Classic McEliece (CCA, code-based) + Dagger (CPA, a Saber variant) |
| PSK | `H(spk_i ⊕ spk_r)` by default; a secret PSK restores DoS protection |
| PSK mixes | twice (handshake-key and final-key derivation) |
| Proofs | eCK-PFS-PSK (computational) + Tamarin (DoS, replay, identity, full PFS) |

The McEliece public key (~1 MB) is provisioned out of band; it is not sent in
the handshake.

## 2. Vallum's numbers

| Quantity | Vallum |
|---|---|
| Handshake messages | 3 |
| Wire bytes | 4609 + 4414 + 52 = **9075 B** (tri-hybrid, no PSK) |
| Segmentation | application-layer, bounded reassembly; no IP fragmentation |
| Full handshake | 54.27 ms tri-hybrid; **1.81 ms** for `0x0002` X25519+ML-KEM-768 |
| KEMs | X25519 + sntrup761 + ML-KEM-768 (default); X25519+ML-KEM-768 (fast) |
| PSK | optional configured secret; mixed once after the public UKS psk; `PSK_TAG` authenticates `InitHello` |
| Proofs | eCK-PFS-PSK adaptation; Tamarin for agreement/PCS/PSK-tag/replay/DoS; no identity/IK proof |

## 3. What matches

- Three-message handshake, explicit mutual key confirmation.
- Static-key authentication plus ephemeral forward secrecy.
- MEX-bound static operations; a public psk derived from both static public
  keys for UKS mitigation.
- Explicit `InitConf`; a responder confirmation in `RespHello`.
- Cookie/MAC admission; replay protection (Vallum uses TAI64N + the replay
  window).
- PSK-authenticated initiation (Vallum: `PSK_TAG`; the paper: the PSK-keyed
  timestamp). Both reject a forged initiation before the responder's expensive
  operations.

## 4. What Vallum adds

- Tri-hybrid KEM: X25519 + sntrup761 + ML-KEM-768, with the suite id bound into
  the transcript.
- Hybrid identity signatures (Ed25519 + Falcon-1024), CA-issued identity
  documents, and a signed validity window.
- An epoch ratchet with key erasure and root independence; a `2^48` cap.
- Committing AEAD, a sealed peer hint, the `RespHello` pre-tag, traffic shaping,
  and MTU-aware application-layer segmentation.
- A runtime control plane and a TUI (this release).

## 5. Deliberate differences and non-claims

1. **Single-packet handshake.** Not met: ML-KEM ciphertexts make the tri-hybrid
   messages larger than 1232 B, so Vallum segments at the application layer.
   The segmenter is bounded (16 entries, 16 KiB) and fuzzed; the paper's
   IP-fragmentation concern does not apply, but the reassembly state is a
   bounded DoS surface.
2. **KEM family diversity.** No code-based leg. sntrup761 and ML-KEM are both
   NTRU/lattice; Classic McEliece is the paper's conservative, code-based
   choice. A code-based suite is roadmap work, not v0.1.0.
3. **PSK mix count.** The paper mixes the PSK twice; Vallum mixes it once after
   the UKS psk. D3 in `eck-pfs-psk.md` records this as a **margin loss**, not a
   property break. The `PSK_TAG` is a separate admission check, not a second
   schedule mix.
4. **Identity hiding.** Not claimed. The 8-byte sealed hint is a routing index,
   not a proof. The paper's symbolic identity proof requires KEM
   **IK-CCA/IK-CPA**, which IND-CCA does not imply; Vallum's KEMs are not shown
   IK-CCA. Tamarin does not model identity.
5. **Timestamp confidentiality.** Vallum sends the TAI64N timestamp in clear and
   guards replay; the paper encrypts `time`. The timestamp is public metadata,
   not a key.
6. **Hint size.** 8-byte sealed fingerprint vs the paper's 32-byte `H(spk_i)`
   inside `1tk`. The hint is checked against the resolved peer; a collision can
   only cause a failed handshake, not a wrong session.
7. **Performance.** The tri-hybrid is ~54 ms per handshake on this host because
   of the SDK's sntrup761; the paper's ~1 ms is a different KEM choice and
   hardware. The `0x0002` fast profile is 1.81 ms but still not single-packet.
8. **PSK compromise resilience.** With a configured PSK, a forged initiation is
   rejected before ops B/C, matching the paper's DoS property. The PSK is not a
   substitute for the PQ KEM; it is defence in depth.
9. **Formal coverage.** Tamarin covers agreement, PCS, the PSK tag, replay, and
   the DoS path; it does not cover identity/IK, segmentation, shaping, or the
   full eCK game. The eCK document is an adaptation, not machine-checked.

## 6. Reproducing the numbers

- `cargo bench -p vallum-protocol-tests` (see `benchmarks.md`).
- `vallum bench --suite 2` for the fast profile.
- `docs/proof/tamarin.md` for the model and the bounded run command.

The paper's numbers are from its own hardware and implementation; no
head-to-head timing is claimed.
