# ADR-0044: The service layer is a third party that calls the CLI

**Date**: 2026-11-16
**Status**: accepted
**Deciders**: operator

## Context

ADR-0013 refused a control plane inside Vallum and named the compromise: the
machine interface — `--json`, a versioned bundle schema, documented exit codes.
" A third party can build the enrolment service; it calls the same commands a
person does, and Vallum does not have to grow an API to support it."

On-demand access is that third party. Users need to enrol themselves, without
the operator minting a ticket per person and without SSH. `service/vallum-desk`
is the service: it speaks HTTP on loopback, keeps accounts in SQLite, and
reaches the daemon only by running `vallum` as a subprocess — `peer invite`,
`peer remove`, `show --json`.

The question this record settles is what the desk is *in relation to Vallum*,
because the answer decides where it lives, what it may depend on, and what
Vallum is allowed to grow to support it.

## Decision

The desk is a third-party service on ADR-0013's machine interface, not part of
the tunnel. It:

- runs as its own process and unit (`vallum-desk@`), never inside the daemon;
- calls the CLI as a subprocess and parses `--json` output — it holds no
  library dependency on `vallum`, `vallum-config` or `vallum-tunnel`, and the
  daemon knows nothing of it;
- owns its own state (SQLite), its own auth (an admin token, invite codes) and
  its own HTTP surface, which is bound to loopback and fronted by a TLS
  reverse proxy the operator runs;
- ships in the deb, the rpm and `install.sh` because an operator who has to
  assemble it is an operator who does not run it — but it is not started
  unless enabled, and Vallum's own behaviour is identical when it is absent.

Vallum grows no API for it. If the desk needs something the CLI cannot say,
the fix is a CLI surface (`--json`, an exit code), not a socket the desk
speaks to directly — the same rule ADR-0013 set, applied to the first thing
that actually exercised it.

## Alternatives Considered

### Alternative 1: The desk inside the daemon
- **Pros**: no subprocess calls; direct access to peer state.
- **Cons**: an HTTP surface in the trust path of every tunnel; the daemon's
  sandbox and its seccomp filter grow; a bug in the desk becomes a bug in the
  data plane.
- **Why not**: ADR-0013 refused exactly this, and the reason still holds.

### Alternative 2: The desk as a separate repository
- **Pros**: the strongest separation; Vallum's tree stays a tunnel.
- **Cons**: two release trains for one product; the desk's tests stop running
  in the gate that already exists; the alpha's install story doubles.
- **Why not**: the boundary is enforced by *dependencies and process*, not by
  a repository wall. `service/` has no Rust in it and the daemon cannot see it;
  that is the property that matters, and it is checkable (`grep` finds no
  `vallum-desk` in `crates/`).

### Alternative 3: Document the CLI and ship nothing
- **Pros**: zero maintenance; operators build their own.
- **Cons**: every operator re-solves invite codes, quotas, expiry and
  revocation, badly; the alpha's "on-demand access" is then a promise with no
  artifact.
- **Why not**: it is the state the product was in before this ADR, and the
  operator asked for the opposite.

## Consequences

- **The desk's failure cannot take the tunnel down.** It is a separate unit
  with `PartOf=vallum@%i.service` and no privileges beyond what the CLI needs.
- **The CLI is the contract, so it is tested as one.** `service/test_*.py`
  drives a fake `Daemon` port; the real one shells out. A CLI output change
  that breaks the desk breaks a test.
- **Two surfaces to secure.** The daemon's control socket (0600, root) and the
  desk's HTTP (loopback + operator TLS). The desk's admin token is compared in
  constant time and its page needs no JavaScript.
- **`CONTEXT.md` gains the vocabulary** the product actually uses: desk,
  account, plan, quota, invite code — as the service layer's terms, marked as
  belonging to `service/` and not to the tunnel.
