# ADR-0034: The file is the enrolment; the token protocol is a convenience

**Date:** 2026-11-12
**Status:** accepted in part — the responder is started and never armed, and `peer invite` prints its own teardown. **The file path is not yet a method**: it has no client-side receiver. That gap is the open decision this ADR left, and a premortem on the client's first hour found it.
**Deciders:** Vallum maintainers
**Answers:** the operator's question — "comparing how WireGuard's client/server connects, can we replicate that?"

## Context

Vallum's client configuration is already WireGuard's shape. `client_config`
(`crates/vallum/src/commands/peer.rs:2098`) emits exactly:

```toml
public_key = "<server_line>"
endpoint = "<endpoint>"
allowed_ips = [...]
```

That is WireGuard's `[Peer]` stanza, and WireGuard's whole connection model is
those three values plus the server's key. What WireGuard does **not** have is a
protocol for delivering them.

Vallum has one, and it is substantial (`crates/vallum/src/enroll.rs`):

- a **second listening port** (`listen + 1`, 51821) that needs its own firewall
  rule;
- a **separate responder daemon** (`vallum-enroll@`) to run and harden;
- **128-bit single-use tokens** with expiry, admission tags, and reply keys
  derived from the token;
- **invite files** on disk (`/run/vallum/enroll-*.json`), each a secret;
- a **sealed exchange** whose every stage is a place a bug can live — and has
  (the applied-peer failure, `report.applied` conflating "not attempted" with
  "attempted and failed", the silent-burnt-invite case).

All of that machinery automates **one** step: telling the server the client's
public key. WireGuard asks the operator to do that step by copy-paste, and is
still the reference implementation a decade later.

### The decisive evidence

`scripts/accept-pair.sh` — the self-contained gate — does **not** use the
enrolment responder at all. It hand-writes the client config, runs `vallum peer
add --public-key-file` on the server, and the pair handshakes and carries. The
WireGuard-style flow therefore **already works today**, and is proven by a gate
that runs on every push.

## Decision

**Make the file the enrolment path, and demote the token protocol to an
optional convenience.**

The primary flow becomes:

1. The client generates a keypair; it keeps the private half (`vallum keygen`,
   or `vallum setup`, which never lets the private half leave the machine).
2. The client's **public line** reaches the server operator out of band —
   however they already talk.
3. The server records it: `vallum peer add <name> --public-key-file <line>
   --client-config-out <client.toml>`.
4. The client receives the config and runs it.

That is WireGuard's model, with one improvement WireGuard does not have: **the
server generates the client's config**, so the client cannot fat-finger a
prefix, an endpoint or a key.

`vallum join <ticket>` stays, because it is genuinely nicer for the common case
— but it becomes a **convenience wrapper over the same exchange**, not the
definition of how a peer joins.

## Alternatives Considered

### Alternative 1: keep the responder as the primary path
- **Pros:** no manual key exchange; scales to many devices unattended.
- **Cons:** every defect class above stays live: a second port to firewall, a
  daemon to harden, tokens to leak, and a bespoke protocol whose failure modes
  are already producing bugs — for an alpha whose stated goal is *provable
  correctness*.
- **Why not:** the machinery buys convenience, and the alpha does not yet need
  convenience at the cost of provability.

### Alternative 2: drop the responder entirely
- **Pros:** the smallest possible surface; nothing to harden, nothing to leak.
- **Cons:** throws away the one-command onboarding that makes an alpha
  approachable, and the enrolment code has already been written and hardened.
- **Why not:** it is the wrong time to delete working code. Demote it; it stays
  available, and the file path is what the docs lead with.

### Alternative 3: keep the responder, add the file path as an alternative
- **Pros:** both exist.
- **Cons:** exactly today's state — and today the responder is the *only* path
  that produces a working client, so the file path would be an undocumented
  alternative nobody uses.
- **Why not:** the point is which path is primary, not which exists.

## Consequences

### Positive
- **A peer is a file.** Diffable, auditable, copyable, committable, reviewable.
  "The server's config lists this public key" needs no protocol to verify;
  "the responder issued a token" does.
- **One fewer port.** No 51821, no firewall rule for it, no responder daemon,
  no invite files holding secrets in `/run`.
- **The trust model becomes WireGuard's**: the client trusts the server key it
  was given; the server trusts the client key it was given. No protocol to
  reason about, and no protocol to get wrong.
- **Onboarding is reproducible.** A person can be told: here is a public line,
  here is a config. That is a sentence that survives being repeated.

### Negative
- **The operator copies a public line.** WireGuard's known wart. It is manual,
  and it does not scale unattended — which is precisely the case the responder
  exists for, and precisely why it stays.
- **Two paths must be kept working.** The docs lead with one; the other is a
  convenience. Two paths is one more thing to test, and it is why the file path
  needs its own gate (`accept-pair.sh` already is that gate).

### Risks
- **The docs and the CLI disagree about which path is primary** → the docs
  lead with the file path, and `vallum join`'s own output should say which path
  it used.
- **A peer added by hand skips whatever the responder checked** → the responder
  applies the peer to the running daemon and reports whether it took; the file
  path must reach the same end state, and `accept-pair.sh` is where that is
  asserted.
- **Rotation and revocation get no cheaper** → they never did; both are server
  operations either way.

## Implementation order, and where it stands

1. **Document the file path as the primary one.** *Done* —
   `docs/quickstart.md` already leads with `vallum setup --remote` ("its key is
   generated here, and only the public line crosses SSH") and offers the ticket
   as the alternative; `docs/wireguard-comparison.md` now spells out the
   side-by-side for readers.
2. **`vallum peer add --client-config-out` as the advertised way to get a client
   config.** **NOT DONE, and the premise was wrong.** The flag is not
   mentioned in the quickstart or the README; the only exercise of it in the
   tree is a unit test (`crates/vallum/tests/provisioning.rs:124`); and
   **nothing on the client consumes its output.** `vallum import-bundle` reads
   only a versioned JSON bundle (`crates/vallum/src/bundle.rs:98-103`), and
   there is no command that takes a plain client config.

   The client side of the file path is therefore prose in
   `docs/deployment/client.md:42-47`: copy the TOML to
   `/etc/vallum/<name>.toml` next to `<name>.key`, then enable two units by
   hand. And the config names the key by **peer name**
   (`crates/vallum/src/commands/peer.rs:2068` — `private_key = "{name}.key"`),
   so a keyfile the operator named anything else is orphaned: `keygen
   --output desk.key` with `peer add laptop` yields a config pointing at a
   file that does not exist.

   "The server writes the config" is not "the client receives and installs the
   config". The handover was somebody else's problem, and the somebody was the
   user.
3. **The responder stops standing open.** *Done, and enforced in code* — it
   was first done by hand on one host, and the premortem's investigators then
   found that the code undid it:

   - `crates/vallum/src/commands/peer.rs:838` — `peer invite` on a root+systemd
     host called `server::enroll(enable: true)`, which writes
     `enroll.enabled = true` into the config, installs the unit and opens the
     port. The first invite after the demotion re-armed everything.
   - `crates/vallum/src/commands/server.rs:952` — the `enroll.enabled` branch
     ran `systemctl enable` on the responder, so the flag did double duty:
     "the responder may serve" (the runtime gate at
     `crates/vallum/src/enroll.rs:759`) and "the responder starts at boot".
   - `crates/vallum/src/commands/peer.rs:855` — the already-enabled path ran
     `systemctl enable --now`, re-arming it a second way.

   The three now **start** the responder and never **enable** it, and `peer
   invite` prints the teardown (`systemctl stop`, `ufw delete allow`) where the
   invite is minted. `docs/deployment/server.md` gives the same procedure.
4. **`vallum join` keeps working and says which path it used.** *Not done.*
   The ticket path also never checks the server's `applied` verdict — that
   check exists only in `setup --remote` (`crates/vallum/src/commands/setup.rs:611`)
   — so a ticket enrolment can be accepted by a server that never applied the
   peer, and the failure surfaces 35 seconds later as "no handshake within
   35s".
5. **Only then consider removing the responder.** *Not done, deliberately* — a
   device that cannot reach the server over SSH has no other way in.
6. **New, from the comparison**: the SSH variant (`setup --remote`) is the
   documented primary path. *Corrected on review*: this ADR first said it had
   no gate. It does — `scripts/verify-remote.sh` enrols one client **per
   transport** (bundle at `:552`, `setup --remote` at `:563`, `peer invite` +
   `setup --join` at `:571`) and proves each carries traffic. What is missing is
   the opposite: `accept-pair.sh` proves the manual file path on any machine,
   while the SSH path can only be proven against a real server over SSH.
7. **New, from the premortem (2026-11-12)**: the two-host gate could report
   PASS with the production host's NAT table destroyed. `restore_nat` had no
   else branch, the cleanup ran with `set +e`, the trap's status did not
   replace the script's exit status, and the "this commit passed" stamp was
   written *before* the cleanup ran. A failed restore is now loud, fails the
   run, and revokes the stamp. See `scripts/verify-remote.sh`.
