# ADR 0029: Ops trust model — dev dispatcher vs production pinning

Date: 2026-11-10
Status: Accepted for development; production path designed, not yet built

## Context

Phase 3 trials need root (systemd units, nft, routes, /etc). The operator
(ikaaros) was copy-pasting every sudo command and relaying outputs — the
agent could do all the surrounding work (build, test, monitor, diagnose) but
not the one privileged step. That made live monitoring impossible: the agent
sees results only after the human relays them.

`packaging/vallum-ops` is a root-owned dispatcher with four named
subcommands (`full-tunnel`, `revert`, `status`, `journal`). The dev rule is
one line in `/etc/sudoers.d/vallum-ops`: NOPASSWD for that path only.

## Decision

**Development (this machine):** the dispatcher is the trade we accept. It
executes scripts under `/home/ikaaros` and the repo — both writable by the
agent — so the sudoers rule effectively grants the agent root for these ops.
Accepted because this is a single-operator box where the agent already runs
arbitrary code as the user; the password was the only thing removed from a
path already under the agent's control.

**Production (any machine we ship):** this trade is NOT acceptable. The
product path must be:

1. `install.sh` copies all root-executed code (ops dispatcher, trial,
   dead-man, panic, hook scripts) to `/usr/local/lib/vallum/`, root-owned,
   0755 — nothing user-writable is ever executed as root.
2. The sudoers file (if any) references only `/usr/local/lib/vallum/` paths.
3. Configs and keys stay 0600/0640 owner-locked; the ops user is a dedicated
   non-login account, not the tunnel owner.
4. The quick unit's `CAP_DAC_OVERRIDE` gets replaced by explicit socket
   permissions at publish time (0660 + a dedicated group), so the bounding
   set can stay `CAP_NET_ADMIN` only.

## Consequences

- Dev velocity: the agent runs trials, monitors live, and pulls journals
  without a human in the loop.
- Production hardening is a listed install.sh requirement, not an idea.
  Before any ship: audit that no root path dereferences a user-writable file.

---

## Amendment (2026-11-11): the dev dispatcher is a privilege boundary

The red team (security-redteam.md M4) found the obvious consequence of this ADR
in its dev form: `self-update` — and `sync`, which copies binaries — install from
`$REPO`, defaulting to `/home/ikaaros/Coding/Gold/vallum`. Anything running as
that user gets root at the next `vallum-ops self-update`, so the NOPASSWD rule
for the dispatcher is effectively full root for the checkout's owner.

That is acceptable on the single-operator development host it was written for,
and it is **not** acceptable on any host with another user account. The fix is
the production path this ADR already designs: artifacts owned by root, installed
from a root-owned location, with the checkout unable to influence what runs.
Until that exists, the rule is:

- **A host that runs `vallum-ops` must not have a second user account** unless
  the dispatcher was installed from a root-owned path.
- A checkout is a build input, not an install source, once the host has users.

Named trigger for building the pinned path: the first deployment that is not
this laptop. It is not a task to do before the alpha on a machine the operator
owns alone; it is the first thing to do before the alpha reaches anyone else's
machine.

