# ADR-0034: The file is the enrolment; the token protocol is a convenience

**Date:** 2026-11-12
**Status:** accepted — and the file path now has the receiver it lacked. A premortem on the client's first hour found that this ADR's premise was wrong: *"the server writes the config" is not "the client receives and installs the config"*. The client side was prose. `vallum setup --client-config` is that receiver, and the file path is a method rather than a ritual.
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

## What the premortem changed

The premortem on the client's first hour (seven investigators, every claim
verified against the tree) found seven failure modes. Four were fixed in the
same pass, and they changed this ADR's substance rather than its wording:

- **The receiver exists.** `vallum setup --client-config <file>`
  (`--no-service` where there is no systemd to install into;
  `--expect-server <fingerprint>` to refuse a config that names another
  server): it finds the
  key the config names, places both files in `/etc/vallum` as root `0600`,
  installs the units, proves the tunnel, and prints the command that checks
  it. If the key is not beside the config, the message IS the remedy. Before
  this, the primary path was a ritual.
- **One guidance screen, one order.** `vallum setup` with no flags, `vallum`
  with no arguments, the quickstart, the README and the client guide all used
  to name a *different* set of paths in a different order — and the answer a
  user got first was the token path this ADR demoted. The text now lives in
  one function (`setup::guidance_text`) that every surface prints.
- **The bundle path is guarded.** A bundle carries the client's private key,
  and the policy report could not see it: `PolicyFinding` had no variant for
  it. There is one now, and the import **refuses** a bundle that carries a
  key unless `--allow-shipped-key` says so explicitly. Every other path keeps
  the key on the device.
- **The failures name their cause.** The SSH leg reported "the server refused
  the enrolment" for three different causes — no `vallum` on the server, a
  sudo that wants a password, an ssh connection that failed — and the server
  refused nothing: the command never ran. The join timeout pointed at a stale
  invite when the likelier cause is a filtered port. Both name their causes
  now.

Three remain open, and are recorded in `docs/alpha-readiness-2026-11-12.md`:
the ticket's port is derived three ways, the client's doctor cannot tell a
changed server key from a dead path, and `vallum join` does not say which path
it used.

## Implementation order, and where it stands

1. **Document the file path as the primary one.** *Done* —
   `docs/quickstart.md` already leads with `vallum setup --remote` ("its key is
   generated here, and only the public line crosses SSH") and offers the ticket
   as the alternative; `docs/wireguard-comparison.md` now spells out the
   side-by-side for readers.
2. **`vallum peer add --client-config-out` as the advertised way to get a client
   config, and a client command that consumes it.** **DONE.** The flag is not
   mentioned in the quickstart or the README; the only exercise of it in the
   tree is a unit test (`crates/vallum/tests/provisioning.rs:124`); and
   **nothing on the client consumes its output.** `vallum import-bundle` reads
   only a versioned JSON bundle (`crates/vallum/src/bundle.rs:98-103`), and
   there is no command that takes a plain client config.

   The client side of the file path was therefore prose: copy the TOML to
   `/etc/vallum/<name>.toml` next to `<name>.key`, then enable two units by
   hand. **That prose is now `vallum setup --client-config <file>`** — it finds
   the key the config names, places both files, installs the units, proves the
   tunnel, and prints the command that checks it. And the config names the key
   by **peer name**
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

## Amendment (2026-11-19): the enrolment front TLS posture (#31, ratified)

The enrolment front (`enroll::front_round_trip` + `tls_quic::build_tls_configs`)
deliberately does **not** verify the outer TLS certificate
(`EphemeralServerVerifier`, `tls_quic.rs:52-64`): outer TLS is DPI mimicry, not the
authentication boundary. The server is authenticated **inside** the sealed PQ
handshake, and the client pins it:

1. The join ticket carries the server's public-line fingerprint
   (`enroll.rs:176-177`, `keys::fingerprint` of the server public line).
2. The ticket+fingerprint arrive over the desk's **verified** HTTPS (the account
   read path verifies the desk cert, ADR-0046/#28, because the bearer token has no
   inner auth), so the fingerprint the client pins is itself authentic.
3. Before writing anything, the client checks the server's presented public line
   against that fingerprint and refuses a mismatch — "this is not the server the
   invite named … treat this as an attack" (`setup.rs:1406-1428`; the same
   `check_server_fingerprint` invariant is tested at `setup.rs:1856`). A MITM cannot
   impersonate the server without its private key, regardless of the outer cert.

**Decision (operator-ratified 2026-11-19):** keep the no-outer-verify posture for
enrolment; the inner-handshake authentication + ticket pin is the boundary. This is
consistent with, not contradictory to, the account-read path verifying outer TLS:
there the bearer token has no inner authentication, so outer TLS *is* the boundary;
here the inner handshake is. The load-bearing invariant to guard is the client-side
pin (step 3) — if it is ever absent or bypassed the posture collapses; the outer cert
is not the thing to protect. Adding outer cert verification would be defense-in-depth
at the cost of a real cert on the enrolment front, and would still not replace the pin.
