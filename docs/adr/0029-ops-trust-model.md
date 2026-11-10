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
