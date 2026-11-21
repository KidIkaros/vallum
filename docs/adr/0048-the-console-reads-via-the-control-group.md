# ADR-0048: The desktop console reads the daemon through a dedicated control group

**Date**: 2026-11-20
**Status**: accepted (operator-ratified 2026-11-20, issue #35)
**Deciders**: operator (Ikaaros) + Hermes agent
**Supersedes the read-path gap noted in**: ADR-0039 (GUI at beta), issue #35

## Context

The desktop console's *actions* (start/stop/restart) elevate through pkexec, but its
*reads* (the snapshot that drives the whole cockpit) did not. On a server the daemon
runs as root (or drops to a `vallum` service user) and publishes its control socket
`0600`, owner-only. A console run as a normal user therefore saw nothing: the live
tunnel rendered as `OFFLINE` beside `SERVICE: ACTIVE`, and the console guided a fresh
setup over an existing tunnel (#35). The console could act on a daemon it could not
see.

The control socket is a local privilege boundary: connecting to it speaks the full
uapi (`get` *and `set`). Who may connect is a security decision, not a UX one.

## Decision

A dedicated system group, **`vallum`**, is the control-socket access group.

1. **Daemon** (`control.rs`): the socket is still bound and chmodded `0600` inside a
   `0700` staging directory, then hard-linked into place — it is never reachable under
   a provisional mode. After that, `widen_to_control_group` publishes it `0660` with
   group `vallum` **only when the daemon is root or already runs as the `vallum`
   group**. A root daemon also puts `/run/vallum` in that group (`0770`) so the socket
   is traversable.
2. **Installer** (`install.sh`): creates the `vallum` group if absent, adds the
   invoking user to it, and sets `/run/vallum` to `0770 root:vallum`. Fail-soft: a host
   without group management keeps the owner-only socket; the daemon still runs.
3. **Personal client unchanged**: a daemon dropped to its login user (a different
   group) keeps `0600`. Its console runs as the socket's owner and reads it directly —
   no group, no widening, no behaviour change.

### The read/write nuance (named, not hidden)

Connecting to a Unix domain socket requires the **write** permission bit on the socket
inode. There is no "read-only" socket mode: `0640` would not let the group connect at
all. So group access is necessarily `0660` — read **and write**, i.e. the full uapi
including `set`. **Membership in `vallum` grants control of the daemon, not just
visibility.** The group is therefore the *trusted-operator set* — the same people who
may start/stop the tunnel — not "any local user". This is the deliberate tradeoff
against per-read polkit prompts, and it is consistent with the runtime dir already
being `0770` for "the group that runs daemons" (ADR-0017, `vallum-tmpfiles.conf`).

## Alternatives rejected

- **Polkit broker for reads** — the GUI asks pkexec for every snapshot. More moving
  parts and a prompt (or a cached authorization) per read; rejected for the alpha.
- **Privileged sidecar** — a tiny root daemon the GUI talks to. The most new surface
  area; rejected unless the group model fails review.

## Consequences

- A console user must be in `vallum` to see a system daemon. The installer adds the
  invoking user; an operator adds others with `sudo usermod -aG vallum <user>` (re-login
  to pick up the group).
- The private-key file stays `0600`; only the control socket widens, and only to the
  named group. The fail-closed default (no group → `0600`) means a misconfigured host
  degrades to "console must elevate", never to "any local user can control the tunnel".
- The GUI copy can now tell the truth: `Tunnel: disconnected` carries the caveat that
  the console may lack permission to see a root-owned daemon (#35 / #36).
- Guarded by `control.rs` tests (owner-only default) and a live check that a
  non-member is refused while a group member reads the snapshot.