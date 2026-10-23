# CONTEXT.md — the project's vocabulary

This file is the terse glossary of terms that must mean **exactly one thing**
when plans are written, code is reviewed, or an interview (`/grilling`) is run
against this repository. Each entry points at the doc or module that *owns* the
definition; this file only fixes which one owns it and disambiguates the places
words could carry two meanings.

It is a living document: when a grilling session, an ADR, or a review sharpens
a term, the sharpened wording moves here.

## The component graph (shipping dependencies)

```
vallum ──▶ vallum-config ──▶ vallum-core ──▶ vallum-crypto     (I = 0.00)
   └─────▶ vallum-crypto-sdk ──▶ vallum-crypto
   └─────▶ vallum-tunnel ──▶ vallum-core, vallum-crypto
vallum-quick ──▶ vallum-config, vallum-core
vallum-crypto-contract ──▶ vallum-crypto          [test component]
vallum-protocol-tests ──▶ dev only                [test component]
```

Verified acyclic (ADP ✓), every edge points toward stability (SDP ✓), and the
stablest crate is the abstract one (SAP ✓): `vallum-crypto` holds the
`CryptoSuite` trait with **zero dependencies** — deliberately, so a provider
can be swapped underneath the whole protocol. The check is structural and
re-runnable in one glance at the manifests (e.g. `cargo -Z features` analysis
or the package-principles pass); no audit doc owns it.

## Glossary

| Term | The one thing it means | Owner |
|---|---|---|
| **CryptoSuite** | The crypto boundary itself: trait, no implementation, no deps of its own | `crates/vallum-crypto` |
| **Handshake** | The three-message hybrid KEX: InitHello, RespHello, InitConf. Not a synonym for "connection setup" generally | `vallum-core::handshake`, `docs/proof/eck-pfs-psk.md` |
| **Epoch axis** | The session ratchet: each rekey is a *fresh* handshake, not a symmetric chain — PCS by construction. A superseded epoch is retained receive-only, then erased | `vallum-core::session`, `docs/proof/ratchet-pcs.md` |
| **Cookie gate** | The mac1/mac2 anti-flood layer. Not rate limiting generally — that belt is `MAX_INJECTION_BURST` | `vallum-core::cookie` |
| **Data plane** | Seal/open transport packets, header + counter as AD. Padding lives *inside* the AEAD | `vallum-core::data`, `docs/proof/committing-aead-multikey.md` |
| **Shaping machine** | A probabilistic FSM in `vallum-core::shaping`: a *passive* pure `f(state, event, draw)` — no clock, no sockets, no keys. `Shaper` = a set of machines. ADR-0022 calls it "the policy machine"; elsewhere say **shaping machine** — it is machine, not policy-configuration | `vallum-core::shaping`, `docs/proof/traffic-shaping.md`, **ADR-0022** |
| **Driver** | The single consumer that feeds shaping events in and applies effects out (hold a queue, pad a sealed packet). The `Device` is it; it owns no shaping policy | `vallum-tunnel::device`, **ADR-0022** |
| **Handshake driver** | **Not the same word as Driver.** It is the per-peer handshake machinery *inside* the Device: start, retransmit, accept, confirm, install | `vallum-tunnel::device/handshake.rs` |
| **Action / Effect / draw** | An *Action* is one machine's ask: pad to a pre-image target, or hold. An *Effect* is that action tagged with the machine that issued it (`{machine, action}`). A *draw* is the caller-supplied `u64` that drives probabilistic transitions. Events: `NormalSent` fires **before** the seal (deliberately unlike Maybenot's post-send `NormalSent`), plus `NormalRecv` and `Timeout` | `vallum-core::shaping` |
| **Shaping tripwire** | The condition that re-opens ADR-0022's watch: *shaping state accumulating driver-side* (cross-peer scheduling, per-session shaping history in the Device). Not: call counts | **ADR-0022** |
| **Segmentation / the envelope** | Application-layer message splitting that keeps a handshake off the IP-fragment path; nothing above knows it travelled in pieces | `vallum-tunnel::segment` |
| **Peer** | Config: a public key plus allowed addresses. Identity mode is **local policy and never negotiated** — an attacker cannot downgrade one | `vallum-tunnel::peer` |
| **Cryptokey routing** | `allowed_ips` in both directions: outbound destinations, inbound anti-spoofing. Inbound is "the check that matters" | `vallum-tunnel::routing` |
| **Fail-closed egress** | A packet leaves only through the tunnel, or to the endpoint. `vallum-guard@` + `vallum policy` | **ADR-0018** |
| **Carrying / degraded** | A tunnel *carries* when the delivery ratio is ≥ 0.1 over a window with ≥ 100 datagrams sent. **Under 100 sent is neither carried nor degraded** — the sample is too small (an idle peer reports ratio 1.0). Degraded = ratio < 0.1 over a ≥ 100-datagram window *while handshakes stay fresh*. Status verbiage (`up`/`degraded`/`blocked`/`leaking`) is defined there | `docs/requirements.md`, Delivery & Carrying |
| **Rotation window** | The overlap where a rotated row answers both keys until `peer finalize` | **ADR-0014**, **ADR-0021** |
| **Route plan / the record** | `RoutePlan`: the exact `ip` invocations an attach performs, recorded to `/var/lib/vallum/<iface>.quick` and *reversed verbatim* at teardown — not re-derived from the (possibly edited) config. Two words from its seam: `render`/`parse` round-trip must hold; `reversed` is one-way (a `replace` re-reverses as `add`) | `vallum-quick/routes.rs` |
| **Privilege boundary** | The config file is a privilege boundary *because of hooks*: a hook string runs as root. Only hook execution escalates — routes and DNS from a user's own config are not a boundary. Hook-bearing configs must be root-owned, 0600 | `vallum-quick/hooks.rs` |

## Conventions worth not re-deriving

* `scripts/verify.sh` is the gate of record ("green" = that script's `PASS`).
* Numbers quoted in docs are measured or marked **unmeasured**; `docs/requirements.md`
  owns the discipline that keeps wishes from being quoted as facts. Do not quote
  a throughput number until one exists.
* An ADR decides *why*; the code comments decide *where*; this file fixes *what
  words mean*. When the three disagree, neither wins — it gets grilled.
