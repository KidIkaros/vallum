# ADR-0017: The runtime directory is a machine resource, not a service's private state

**Status:** accepted · **Date:** 2026-10-21

---

## Context

A dogfooding pass on the control plane turned up a class of defect that is not a
bug in any one function: the pieces disagree about who owns what. Three
observations, all reproduced:

- `vallum peer add` printed `applied  no — the daemon is not running; start it
  to apply` **while the daemon was running** with one peer.
- A daemon started, logged `tunnel up on interface owtest0`, and never created
  its control socket — with no warning at all.
- `vallum@vallumtest0` twice failed to start with `Failed to set up mount
  namespacing: /run/vallum: No such file or directory`, `status=226/NAMESPACE`.

They share one cause. `/run/vallum` is created by `RuntimeDirectory=vallum`,
which is declared by **one** unit, `vallum@.service`. But 34 references across
`crates/` and `packaging/` depend on it: every `vallum run` client daemon,
`vallum-quick@`, `vallum-quick-watch@`, `vallum-enroll@`, `vallum-metrics`, and
the CLI itself, which finds sockets by path. When the server unit stops, systemd
deletes the directory and every other daemon's socket with it.

The code then reports the consequence as a cause. `syncconf_running`
(`commands/control.rs:469`) returns `bool`:

```rust
if !socket.exists() { return Ok(false); }
```

and four call sites (`commands/peer.rs:1187`, `1358`, `1411`, `1648`) turn that
`false` into the sentence *"the daemon is not running"*. A missing socket file
is a symptom with at least three causes — daemon down, daemon up with its socket
removed, daemon up inside a mount namespace the host cannot see — and the CLI
asserts the one that is most often wrong.

## Findings, by lens

| # | Finding | GoF | Norman | Mind-in-Mind | Ponytail |
|---|---|---|---|---|---|
| F1 | One unit owns a directory five units and 34 sites depend on | Lifetime bound to an arbitrary participant; no owner abstraction | The coupling is invisible, so the user's model of the system is wrong | #6 memory: operator must recall an unstated dependency | The platform already owns machine-level runtime dirs — `tmpfiles.d` |
| F2 | `bool` collapses three states to two, and the CLI invents a cause | No pattern applies: the fix is the return type, not indirection | False signifier → wrong corrective action (restart a healthy daemon) | #12 errors, #9 satisficing: the first plausible fix is the wrong one | Change the return type; print what was observed |
| F3 | Daemon runs with no control socket and says nothing | — | No feedback; Gulf of Evaluation never closes | #7 change blindness: absence is not noticed | One log line at startup |
| F4 | `/run/vallum` spelled three ways in 34 places | No single source of truth for a shared resource | — | — | One `const` plus one resolver function |
| F5 | Unit both creates the path and requires it to pre-exist | Contradictory contract inside one declaration | — | — | Delete the redundant line |
| F6 | `attach` waits up to 20 s with no output | — | Gulf of Evaluation: a silent wait is indistinguishable from a hang | #11: ~10 s is the attention limit | A ticker every 2 s |

**On F1 and GoF**: no design pattern resolves this. A Singleton would make the
directory a global owned by *nobody*, which is the current problem restated. A
Factory would add indirection over a path string. The defect is ownership, and
ownership is fixed by assigning an owner, not by wrapping the resource. Recorded
here because the review pass requires naming why no pattern applies.

## Decision

1. **`/run/vallum` becomes a machine resource.** Ship
   `packaging/vallum-tmpfiles.conf` (`d /run/vallum 0750 root root -`) and
   install it to `/usr/lib/tmpfiles.d/vallum-tmpfiles.conf` (packages) or
   `/etc/tmpfiles.d/` (install.sh). Drop `RuntimeDirectory` and
   `RuntimeDirectoryMode` from `vallum@.service` — nothing creates the directory
   on a unit's lifecycle any more, and nothing deletes it on the way out.
   `ReadWritePaths=/run/vallum` **stays**: under `ProtectSystem=strict` the
   daemon needs explicit write access to bind its socket, and now that
   tmpfiles.d guarantees the path exists, that line can no longer fail the way
   it did at `226/NAMESPACE`.
2. **`syncconf_running` returns a reason, not a bool.** `ApplyOutcome {
   Applied, NoControlSocket, NoControlDeclared }`; the four call sites print the
   observation (`no control socket at <path>`) instead of a diagnosis.
3. **The daemon says so when it has no control server.** One `warn` at startup:
   the tunnel is up, the control plane is not.
4. **One source of truth for the path.** A `runtime_dir()` and
   `socket_path(name)` in `vallum-config`, replacing the 34 literals.
5. **`attach` prints progress** while it waits for a handshake.

Items 1 and 2 are the fix. Items 3–5 are the same defect surfacing elsewhere and
are cheap enough to do in the same pass.

## Alternatives Considered

### Alternative 1: `RuntimeDirectoryPreserve=yes`
- **Pros**: one line; the directory survives the server stopping.
- **Cons**: one service still owns a directory five others depend on, and the
  owner is still arbitrary — the *client* units cannot start before the server
  has ever run.
- **Why not**: it hides the coupling instead of removing it.

### Alternative 2: One directory per daemon, `/run/vallum/<name>/`
- **Pros**: no sharing at all; each daemon owns its own socket.
- **Cons**: does not fix the ownership question (who creates the parent?), and
  every CLI invocation would need to know which subdirectory to look in.
- **Why not**: more moving parts, same problem.

### Alternative 3: Move runtime state to `/var/lib/vallum`
- **Pros**: already exists and is already written to.
- **Cons**: wrong lifetime — runtime sockets must not survive a reboot, and
  `/var/lib` is for state that must.
- **Why not**: conflates two storage classes the FHS keeps separate.

### Alternative 4: Keep the `bool`, reword the message
- **Pros**: a one-line change per site.
- **Cons**: the caller still cannot distinguish "down" from "unreachable", so
  the message can only be vague ("could not apply") exactly where the operator
  needs precision.
- **Why not**: it trades a wrong answer for an unhelpful one.

## Consequences

### Positive
- Any unit can start in any order, on a fresh boot, with no server ever having
  run — the 226/NAMESPACE failure cannot occur.
- Stopping one daemon no longer breaks another's control plane.
- The CLI stops asserting a cause it cannot know, which removes the single most
  misleading message in the tool.

### Negative
- One more packaging file, and one more thing `install.sh`, the deb and the rpm
  must agree on (the manifest check already enforces that).
- `ApplyOutcome` is a slightly larger type than `bool` at four call sites.

### Risks
- **The tmpfiles entry must exist before the unit starts.** On a boot,
  `systemd-tmpfiles-setup` guarantees that. On an *upgrade*, where the package
  is installed onto a running host, it would not — the unit would start before
  the next boot and fail at `226/NAMESPACE` because `ReadWritePaths` needs the
  path to be there. Mitigated by every channel running
  `systemd-tmpfiles --create` from its post-install hook (`debian/postinst`, the
  rpm `%post`, and `install.sh`).
- **Existing deployments** have `/run/vallum` owned by the unit; after upgrade
  the ownership changes silently. Mitigated by noting it in the changelog.
