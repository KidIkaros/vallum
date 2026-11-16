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

## The console's reader

`vallum-gui` is read by three readers at once, and its defaults are set for all
three rather than for the middle one. Decided 2026-11-11, in an interview; the
consequence is a rule, not a preference.

| Reader | What they need on the first screen | Where it lives |
|---|---|---|
| The **operator** already running a tunnel | exact state in exact terms — `SPLIT`, `PSK`, fingerprint, epoch | the panels as they stand; the `:` palette for every verb |
| The **newcomer** who just installed | the next single step, in plain words, with a command to copy | `FirstRun`, the hero's sentence, the failure cards |
| An **agent** in a harness — OMP, DeepSeek Harness, Pi, Hermes, OpenCode, Freebuff — or a page reader | stable ids, `aria-label`s, copyable commands, and no state that exists only as colour or only in a `title=` | `id=` on every action, the copy buttons, the failure cards' raw error lines |

The agent reader's real surface is not the page: it is
`packaging/utcp/vallum.utcp.json`, the published manual those harnesses load. A
verb the console can do and the manual cannot is a gap, and one with a test —
`crates/vallum/tests/utcp_manual.rs` — behind it.

That reader cannot read a sentence and act on it. Every verb an agent is handed
has to answer in a shape it can branch on, which is why `vallum policy` grew
`--json` (`egress: blocked | unrestricted | unknown`, and `fix` when a guard is
wanted but missing) and why `vallum_status` already had it. `vallum keygen`
grew it next (`public` as a field, not a line to scrape), with `--signing` as a
second tool rather than a flag input — a CLI template cannot branch, so a toggle
is either always on or a tool of its own, and the manual already speaks in pairs. A tool description
that names a field the command does not emit is the same defect as a page that
names a state the host does not have.

**The rule: plain words on the surface, exact terms one level down.** A panel's
headline reads without the glossary; its row labels, tooltips and the palette keep
the daemon's own vocabulary. Where both cannot be true, the surface wins and the
term moves into this file.

Two calls that followed, and their status:

* The hero's word for a split host stays **SPLIT** — a mode name, amber, with the
  sentence beneath it carrying the meaning ("traffic leaves via … — the tunnel
  carries only its own subnet"). **Provisional**: the interview did not settle
  the word, and the sentence is what a newcomer reads, so renaming it changes
  little; revisit if a first-run test says otherwise.
* The interface counters are **datagrams sent** and **packets delivered**, the
  words `docs/proof/transport.md` already uses of the wire. The collapsed summary
  may shorten to `N datagrams out · M packets in`; it may not introduce a third
  noun.

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
| **Enrolment path** | One of four ways a client obtains its configuration: **the file** (`peer add --client-config-out` → `setup --client-config`), **SSH** (`setup --remote`), **the ticket** (`peer invite` → `join`), **the bundle** (`import-bundle`). The file is primary; the ticket is a convenience; the bundle is the only one that moves the key, and is refused unless asked for by name. Five spellings existed for two operations — `join`/`setup --join`, `import-bundle`/`setup --client` — and they are the same enrolment with different install semantics | **ADR-0034**, `docs/deployment/client.md` |
| **Client config** | The file the server writes that tells a device how to reach the server: the interface (name, addresses, and the *name* of the key file) and the peer (the server's public line, the endpoint, the allowed IPs). It does **not** carry the private key — it **names** it, and the name is the PEER's name, so `peer add laptop` expects `laptop.key` | `crates/vallum/src/commands/peer.rs` |
| **The receiver** | The client-side command that installs a client config: `vallum setup --client-config`. It finds the key the config names, places both files in `/etc/vallum` as root `0600`, installs the units and proves the tunnel. Before it existed, the client side of the file path was prose — copy two files, enable two units by hand | `crates/vallum/src/commands/setup.rs` |
| **The handover** | The operator's half of the file path: the device makes its own key and sends its **public line**; the server records that line and writes a config naming the key; the file travels back. "The server writes the config" is **not** "the client receives and installs the config" — the second half is the receiver's job | **ADR-0034** |
| **Key custody** | Which machine holds the client's private key. Every path keeps it on the device, which is the property the whole enrolment design exists to protect; the bundle is the exception, and it now says so in the policy report and refuses by default | **ADR-0033** |
| **Peer** | Config: a public key plus allowed addresses. Identity mode is **local policy and never negotiated** — an attacker cannot downgrade one | `vallum-tunnel::peer` |
| **Cryptokey routing** | `allowed_ips` in both directions: outbound destinations, inbound anti-spoofing. Inbound is "the check that matters" | `vallum-tunnel::routing` |
| **Fail-closed egress** | A packet leaves only through the tunnel, or to the endpoint. `vallum-guard@` + `vallum policy` | **ADR-0018** |
| **Carrying / degraded** | A tunnel *carries* when the delivery ratio is ≥ 0.1 over a window with ≥ 100 datagrams sent. **Under 100 sent is neither carried nor degraded** — the sample is too small (an idle peer reports ratio 1.0). Degraded = ratio < 0.1 over a ≥ 100-datagram window *while handshakes stay fresh*. **Stale** is the idle-host case: the daemon answers but the oldest handshake is past `REJECT_AFTER_TIME`, so the session is dead and no delivery sample exists to say so. Status verbiage (`up`/`degraded`/`stale`/`blocked`/`leaking`) is defined there | `docs/requirements.md`, Delivery & Carrying |
| **Rotation window** | The overlap where a rotated row answers both keys until `peer finalize` | **ADR-0014**, **ADR-0021** |
| **Route plan / the record** | `RoutePlan`: the exact `ip` invocations an attach performs, recorded to `/var/lib/vallum/<iface>.quick` and *reversed verbatim* at teardown — not re-derived from the (possibly edited) config. Two words from its seam: `render`/`parse` round-trip must hold; `reversed` is one-way (a `replace` re-reverses as `add`) | `vallum-quick/routes.rs` |
| **Datagram** | The unit the carrier sends: one sealed packet in one UDP datagram. The canonical **outbound** noun — never "packet" | `vallum-tunnel` carriers, `docs/proof/transport.md` |
| **Packet** | The unit the tunnel reads from, and delivers to, the TUN interface. The canonical **inbound** noun. "Received" is reserved for socket-level kernel counters (`RcvbufErrors`), never for deliveries | `vallum-tunnel::device`, `docs/proof/transport.md` |
| **Control socket** | The daemon's unix socket that the console and the TUI read. **Silent** = it answered nothing; **retained** = the last snapshot that did answer, still on screen and marked as such; **unmanaged** = a daemon answers with no systemd unit behind it. Not "offline" — that is a network word | `crates/vallum-gui`, `crates/vallum/src/tui` |
| **Desk** | The self-service layer: an HTTP service on loopback that turns a signup into an account and a join ticket. A *third party* on the machine interface (ADR-0044) — it calls the CLI and the daemon cannot see it. Not "the control plane", which ADR-0013 refused. It is also the product an operator deploys as their enrolment front (ADR-0045) | `service/vallum-desk`, **ADR-0044**, **ADR-0045** |
| **Account** | The desk's record of one *credential*: a plan, a shared byte cap, an expiry, a status — and, since ADR-0045, up to N **devices** (device peers) under it. The daemon has no concept of it — the account is the service's, and the peers are the tunnel's | `service/vallum-desk`, **ADR-0045** |
| **Account token** | The bearer credential the desk mints at signup — the Mullvad account-number analogue: PII-free, and the only auth the account page, `/api/devices` and `/api/voucher` know. It rides into the sealed client config (via the `vallum://` URI), never the enrolment wire | `service/vallum-desk`, **ADR-0045** |
| **Device** | A peer enrolled under an account (1:N since ADR-0045). Peers keep their `uNNNN` names; the account's label distinguishes whose. Not a person — the desk cannot tell "one person, two devices" from "two people", by design | `service/vallum-desk`, **ADR-0045** |
| **Plan** | A row, not code: a byte cap, an expiry, a paid-until, a status. A paid tier is a plan, and the sweep enforces it against the account's *aggregate* peer counters — the cap is a shared pool across devices | `service/vallum-desk`, `POST /api/admin/plan`, **ADR-0045** |
| **Invite code** | A single-use code the desk accepts in place of the operator — carrying a plan payload (days, byte cap, plan label) that overrides trial defaults at signup. In open mode it is optional and anonymous signups are bounded per IP and by capacity | `service/vallum-desk`, **ADR-0045** |
| **Voucher** | An invite code consumed by an *existing* account (`POST /api/voucher`, bearer-token auth) to extend expiry and bytes — the same code path as signup, a different consumption point | `service/vallum-desk`, **ADR-0045** |
| **`vallum://` URI** | The webpage→client bridge: `vallum://join?ticket=<t>&account=<token>` emitted by the ticket page's Connect button. Baseline handler is a packaged `x-scheme-handler` desktop entry execing `vallum join`; `vallum-gui` takes over the scheme when installed | `service/vallum-desk`, **ADR-0045** |
| **Privilege boundary** | The config file is a privilege boundary *because of hooks*: a hook string runs as root. Only hook execution escalates — routes and DNS from a user's own config are not a boundary. Hook-bearing configs must be root-owned, 0600 | `vallum-quick/hooks.rs` |

## Conventions worth not re-deriving

* `scripts/verify.sh` is the gate of record ("green" = that script's `PASS`).
* Numbers quoted in docs are measured or marked **unmeasured**; `docs/requirements.md`
  owns the discipline that keeps wishes from being quoted as facts. Do not quote
  a throughput number until one exists.
* An ADR decides *why*; the code comments decide *where*; this file fixes *what
  words mean*. When the three disagree, neither wins — it gets grilled.
