# ADR-0028: A seccomp filter, derived from the daemon's own syscall surface

**Date**: 2026-11-08
**Status**: accepted — implemented in log mode (see “Implementation status”)
**Deciders**: the maintainer
**Relates to**: ADR-0005 / ADR-0011 (Linux-only scope), ADR-0017 (runtime directory), ADR-0027 (mesh agent)

## Context

Vallum's privilege story stops at dropping ids. `privileges::drop_to`
(`crates/vallum/src/privileges.rs:138`) does `setgroups([])`, `setgid`, `setuid`,
`PR_SET_NO_NEW_PRIVS`, then verifies the ids took. That is a correct and
well-ordered drop — the module's own doc comment explains why the order is the
mechanism — and it is the whole of it.

What it does not do is bound what the process may ask the kernel for. After the
drop the daemon still holds a full syscall table. A bug in the wire parser, the
config parser, or any dependency runs with the ability to open files, spawn
processes, and make sockets it has no business making.

The project says so itself, in three places:

- `docs/proof/privileges.md:109` — *"No `seccomp`. The syscall surface is
  unchanged."*
- `docs/proof/daemon.md:352` — *"Still no `seccomp`, no sandbox."*
- `docs/proof/pentest.md:304` — names the absence as a finding.

MOOR has one (`src/sandbox.c:191`, a syscall allow-list with `getrandom`,
`no_new_privs` and rlimits), which is where this was first noticed
(`docs/research/moor-reference.md`, addendum §1). That is the whole of MOOR's
relevance here: it is not a design to port. A seccomp filter is a list of the
syscalls *this* daemon makes, and that list has to come from this daemon.

### The insertion point is unusually good

`drop_to` is called at `crates/vallum/src/commands/run.rs:146`, and the comment
above it states the boundary exactly: *"Everything privileged is done: the
interface exists, the socket is bound, and the key has been read. From here the
daemon needs no more than the two file descriptors it already holds."*

Critically, that call site is **before every thread is spawned**. The control
server (`control::serve`, `run.rs:461`), the TUN reader (`run.rs:804`), the UDP
reader (`run.rs:835`), and the TCP carrier's acceptor and writer
(`net.rs:499`, `net.rs:537`) all start after it. A filter installed at that point
is inherited by every thread the daemon will ever have, with no per-thread
installation problem and no window where an unfiltered thread exists.

That is the reason this ADR is worth writing now rather than later: the ordering
is already right, and it is easy to lose.

### The constraint that shapes the implementation

The workspace sets `unsafe_code = "forbid"` (`Cargo.toml`). That rules out the
`libseccomp` bindings, which are FFI. The filter must be built and installed from
safe Rust.

**Choice: `seccompiler` 0.5.0** (`github.com/rust-vmm/seccompiler`,
Apache-2.0 OR BSD-3-Clause — licence-compatible with Vallum's Apache-2.0). It
compiles a filter description to BPF and installs it, and it is the crate
Firecracker uses for the same job. It is not a hand-rolled BPF program, which is
the alternative and is exactly the kind of code that should not be written twice.

## Decision

**Install a seccomp allow-list after the privilege drop, in two stages: log-only
first, then enforce.**

### 1. Where

A new function in `privileges.rs`, called immediately after `drop_to` at
`commands/run.rs:146`, inside the same `if let Some(privileges)` block and
therefore only when the daemon is configured to drop. A daemon that was not asked
to drop privileges is not asked to sandbox either — the two are one posture, and
splitting them would let an operator believe they had hardened something they had
not.

### 2. What the filter allows

The list is **derived by observation, not by reading the source**. Reading gives
the syscalls a developer remembers; observation gives the ones libc, the
allocator, and `signal-hook` actually make. The derivation procedure:

1. Run the daemon under `strace -f -c` through a full exercise: handshake both
   directions, traffic both ways, a control-socket `show`, a `syncconf`, a
   rekey, a keepalive, a shutdown, and the TCP carrier path.
2. Collect the union of syscalls across every thread.
3. Classify each as *needed after the drop* or *startup-only*, and allow only the
   first set.
4. Record the list and the trace that produced it in `docs/proof/seccomp.md`.

The categories that must be present, stated here so a reviewer can check the
derivation rather than trust it:

| Category | Syscalls | Why the daemon needs them after the drop |
|---|---|---|
| Datagram I/O | `read`, `write`, `recvfrom`, `sendto` | the tunnel's whole job |
| Stream I/O | `recvmsg`, `sendmsg`, `shutdown` | the TCP carrier (ADR-0026) |
| Socket lifecycle | `socket`, `connect`, `setsockopt`, `getsockopt` | the carrier dials and marks **after** the drop |
| Control plane | `bind`, `listen`, `accept4`, `unlink`, `mkdir`, `readdir`, `rename`, `fchmod` | `control::serve` runs after the drop and publishes its socket by rename |
| Threads | `clone`/`clone3`, `futex`, `sched_getaffinity`, `set_robust_list` | every reader and writer thread starts after the drop |
| Waiting | `poll`, `ppoll`, `nanosleep`, `clock_nanosleep` | `net.rs:619` polls; the acceptor sleeps |
| Time and entropy | `clock_gettime`, `getrandom` | the clock and the RNG |
| Signals | whatever `signal-hook` uses | `install_signal_handlers` runs after the drop |
| Memory | `mmap`, `munmap`, `mremap`, `brk`, `madvise` | the allocator, for the life of the process |
| Exit | `exit`, `exit_group` | shutdown |

The table is a starting point for the derivation, not a substitute for it. A
filter written from this table alone will be wrong, because `signal-hook`'s
mechanism and glibc's occasional fallbacks are not visible from the source.

### 3. Two stages, because a wrong filter is a dead daemon

`SECCOMP_RET_LOG` first. The filter is installed in log-only mode, the daemon
runs its full test suite and the dogfood path, and every syscall that *would*
have been killed is counted. Only when the log is empty across the whole exercise
does the filter move to `SECCOMP_RET_KILL_PROCESS`.

This is not caution for its own sake. The failure mode of a wrong allow-list is
the daemon dying on a path nobody exercised — a rekey after 40 minutes, a
carrier dial under load, a control request during a rotation. Those are exactly
the paths that are hardest to test and most expensive to break.

The mode is a config field, `[interface] seccomp = "log" | "enforce"`, defaulting
to `"log"` for one release and `"enforce"` after. A daemon that cannot install
its filter **fails closed** and exits with the reason, matching `drop_to`'s
existing posture: *"A daemon that cannot drop exits with the reason; it does not
run with the privileges it was meant to shed."*

### 4. What is deliberately not in scope

- **`landlock`.** Filesystem-path restriction is a different mechanism with a
  different compatibility story (kernel 5.13+, and it is additive rather than
  allow-list). It is the natural companion and it is not this ADR. Note that
  `landlock 0.4.7` is already in the local cargo cache from `origin-network`,
  so the dependency cost is known.
- **Capability retention** (`CAP_NET_ADMIN` kept rather than dropped). That is a
  privilege-model change, not a syscall filter, and it would widen what the
  daemon can do rather than narrow it.
- **Per-peer isolation.** One process, one peer table. A filter does not change
  that and should not be sold as if it does.
- **Non-Linux.** The filter is Linux-only, consistent with ADR-0005/0011. On
  other platforms the field is refused rather than silently ignored, exactly as
  `interface.user`/`interface.group` already are
  (`privileges.rs`, the `not(target_os = "linux")` branch).

## Alternatives Considered

### Alternative 1: `libseccomp` bindings
- **Pros**: the reference implementation; every other tool uses it; well
  understood.
- **Cons**: FFI, and the workspace sets `unsafe_code = "forbid"`.
- **Why not**: it would require relaxing a workspace-wide invariant for one
  dependency. That invariant is worth more than the convenience.

### Alternative 2: Hand-write the BPF program
- **Pros**: no dependency at all; total control.
- **Cons**: BPF is a stack machine with its own verifier rules; a hand-written
  filter is unauditable by anyone who has not written one before, and a subtle
  error is a filter that permits too much or kills the daemon.
- **Why not**: `seccompiler` is the same job done by people who maintain it for
  Firecracker. Writing it again is not a security improvement.

### Alternative 3: Enforce immediately, no log stage
- **Pros**: the property holds from the first release; no interim window.
- **Cons**: the first wrong entry kills the daemon on a path the test suite does
  not cover, and the operator sees a crash rather than a diagnostic.
- **Why not**: the log stage is how the list gets correct. Skipping it trades a
  measurable risk for an unmeasurable one.

### Alternative 4: Do nothing, document the gap
- **Pros**: zero risk of breaking a working daemon; the gap is already stated
  honestly in three proof documents.
- **Cons**: the gap stays. A VPN daemon that parses hostile input from the
  network with an unbounded syscall surface is the exact shape seccomp exists
  for, and the insertion point is already correct.
- **Why not**: the honest documentation is what makes this a decision rather
  than an oversight. Having named it three times, the next step is to close it.

## Consequences

### Positive

- The blast radius of a parser bug shrinks from "anything the user could do" to
  "the syscalls the tunnel actually makes".
- The filter is inherited by every thread because it is installed before any
  thread exists — no per-thread installation, no unfiltered window.
- The syscall list becomes a measured artifact in `docs/proof/seccomp.md`, which
  is also a precise description of what the daemon does. That has value beyond
  security: it is the most honest architecture document the project could have.
- `unsafe_code = "forbid"` survives.

### Negative

- **A compatibility commitment.** The allow-list is now a promise about every
  kernel and libc the daemon runs on. A glibc update that starts using a
  different syscall for the same operation breaks the daemon, and it breaks it
  at runtime on someone else's machine.
- **The log stage is a release where the property does not hold.** That must be
  said in the documentation for that release, not implied away.
- **Debugging gets harder.** A killed syscall produces a signal, not a stack
  trace. The log mode is the answer, and it must stay available in release builds
  for exactly this reason.
- **The TCP carrier and the mesh agent (ADR-0027) both add syscalls after the
  drop** — `connect`, `socket`, `setsockopt` for the carrier; whatever the agent
  does is a separate process and therefore unaffected. The filter must be
  re-derived when the carrier changes, and that is a maintenance obligation
  nobody will remember.

### Risks

- **A wrong entry kills the daemon on a rare path.** Mitigation: the log stage,
  and a test that runs the full exercise with the filter in enforce mode before
  the mode can be the default.
- **The list drifts from the code.** Mitigation: derive it in CI from an
  `strace` of the test suite and fail the build when the observed set contains a
  syscall the filter does not allow. This is the only mitigation that survives
  contact with a codebase that keeps changing.
- **`clone3` versus `clone`.** Newer libcs prefer `clone3`; older kernels return
  `ENOSYS` and the libc falls back. A filter that allows only one of them breaks
  on one side of that line. Mitigation: allow both, and note that `ENOSYS` must
  be *returned* rather than killed for the fallback to work — which means
  `SECCOMP_RET_ERRNO`, not `KILL`, for that entry.
- **The filter becomes a false sense of security.** It bounds syscalls; it does
  not bound what the daemon does with the descriptors it already holds. The TUN
  device and the socket are still a trusted boundary, as `pentest.md` §6.9
  already says.

## Implementation sequence

1. **Derive the list.** `strace -f -c` over the full exercise, recorded in
   `docs/proof/seccomp.md` with the trace command. No code yet.
2. **Install in log mode.** `seccompiler` behind a `[interface] seccomp` field,
   defaulting to `"log"`. Ship it, run the dogfood path, collect what would have
   been killed.
3. **Empty the log.** Fix the list until a full exercise produces no would-kill
   entries. This is where the real work is and it is not a coding task.
4. **Add the CI guard.** Fail the build when the observed syscall set is not a
   subset of the allowed set.
5. **Flip the default to `"enforce"`** in the release after the log is clean, and
   say in that release's notes that the property now holds.

## Implementation status

| Step | State |
|---|---|
| 1. Derive the list | **done** — `docs/proof/seccomp.md` records the exercise, the 20-syscall post-startup trace it produced, and the 81 entries that cover it |
| 2. Install in log mode | **done** — `crates/vallum/src/sandbox.rs`, `interface.seccomp`, default `log`, installed immediately after `drop_to` |
| 3. Empty the log | **not done** — the list has been traced once, not exercised; this is where the real work is |
| 4. Add the CI guard | **done** — `scripts/seccomp-trace.sh` traces the exercise and fails when the daemon's syscalls are not a subset of `vallum sandbox --names`; the `e2e` job runs it |
| 5. Flip the default to `enforce` | **not done** — the default is `log` until step 3 finishes |

What has been verified: the filter installs and kills what the list does not
name (a test re-executes itself, installs enforce mode, and asserts the child
dies on `SIGSYS` when it tries `execve`), and every syscall in the post-startup
trace is on the list. What has not: a live daemon in enforce mode, because the
privilege drop calls `setgroups`, which an unprivileged user namespace denies —
that run belongs to CI, where the drop happens under `sudo`.

The guard is checked both ways: it passes on the current list, and removing
`sendto` from the list made it exit 1 and name that syscall — a guard nobody has
seen fail is a guard that might not be able to.

Open question 1 is settled: its own module (`sandbox.rs`). Question 2 is settled
too: the mode is a startup log line, `vallum doctor` reports it (with `FAIL` when
the kernel could not install the filter), and `vallum sandbox` prints the list.

## Open questions

1. **Does the filter belong in `privileges.rs` or its own module?** It is a
   privilege mechanism, but it is a large table with its own proof document.
   Leaning: its own `sandbox.rs`, called from the same place.
2. **Should `seccomp = "log"` be allowed in a release build?** It has to be, for
   debugging, but it is also a way to run with the property off. Leaning: yes,
   with the mode printed at startup and reported by `doctor`.
3. **What is the story for a kernel without `seccomp`?** Every Linux since 3.5
   has it, so this is theoretical — but the daemon should say what it did rather
   than assume.
4. **Does the mesh agent (ADR-0027) need its own filter?** It is a separate
   process with a very different syscall surface (it dials, it parses JSON, it
   writes to a socket). Almost certainly yes, and it is a separate derivation.
