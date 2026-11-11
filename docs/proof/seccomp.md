# The syscall filter

**Date**: 2026-11-08
**Status**: enforced by default since 1.6.5; `seccomp = "log"` is the debugging opt-out
**Decision**: ADR-0028

## 1. What this claims

After the privilege drop, the daemon may make the syscalls on an allow-list and
no others. The list is derived from a trace of the daemon, not from reading the
source, and it is installed before any thread is spawned, so every thread the
process will ever have inherits it.

It did **not** claim, while it shipped in log mode, that the list was complete:
the kernel logged what the list would have killed, and the list was corrected
from those logs. The log stage is over — the audit window of §5 came back clean
on 2026-11-09, and the filter enforces by default since 1.6.5. What §5 says has
not been done is still not done: a window proves the paths it took, not every
path there is.

## 2. Where it is installed

`privileges::drop_to` bounds *who* the process is; the filter bounds what it may
ask the kernel for. `commands::run` calls `sandbox::install` immediately after
`drop_to`, and the comment there states why that is the only acceptable place:

- The control server, the TUN reader, the UDP reader, and the TCP carrier's
  acceptor and writer all start **after** that line. A filter installed there is
  inherited by every one of them.
- Installing it later — after the threads exist — would need a per-thread
  installation and would leave a window in which an unfiltered thread runs.

The filter is installed only when `interface.user` or `interface.group` is set:
the two are one posture. `interface.seccomp` without one of them is refused
rather than ignored, because a hardening field the daemon quietly does not apply
is how an operator comes to believe they hardened something they did not.

```toml
[interface]
user = "vallum"
# unset is "enforce"; "log" is the debugging opt-out
seccomp = "log"
```

The mode is printed at startup (`syscall filter installed in log mode`).
`vallum sandbox` prints the list the binary would install (a table by default,
`--names` one per line, `--json` for machines), and `vallum doctor` reports the
mode this configuration resolves to — `FAIL` when the kernel could not install
the filter, which is the answer the daemon would give by refusing to start.

## 3. How the list was derived

By observation. The exercise was two daemons in one network namespace, a real
TUN each, the outer path over loopback UDP, a handshake, packets both ways
through the tunnel (three `ping`s each way), a control-socket request, and a
`SIGTERM` shutdown. The trace was taken with `strace -f -p <pid>` attached to the
client daemon **after** the tunnel was up, so what it recorded is what a running
daemon asks for — not what startup asks for:

```
strace -f -c -p <daemon pid>      # summarised form; the list below is the same set
```

The 20 syscalls the trace produced:

```
accept4 clock_nanosleep close exit_group fcntl futex getrandom ioctl munmap
read recvfrom restart_syscall rt_sigreturn sendmmsg sendto setsockopt
sigaltstack statx unlink write
```

Every one of them is on the allow-list. The exercise also produced a startup
phase of 63 syscalls — `execve` and `openat` from the `ip` calls that configure
the interface, `setuid`, `capset`, and the rest — and all of it happens before
the drop, so none of it is on the list. That is the whole point: after this line
the daemon cannot spawn a process or open a file.

The list is in `crates/vallum/src/sandbox.rs`, grouped by what each group is for
(one group is the tunnel, one is the control plane, one is thread creation, one
is the allocator). 79 syscalls are allowed.

The same exercise, run through the committed script (`scripts/seccomp-trace.sh`),
runs twice — once per carrier — and starts the client daemon under
`strace -f -o` instead of attaching to it. Across runs it sees 40–43 distinct
syscalls per leg and 42–44 in union, all of them on the list. The counts move by
a couple with timing — a ping that takes the slow path, a thread that starts
earlier — which is why the guard diffs sets rather than counting them.

The checked window begins at the daemon's first `bind`: `commands::run` opens the
TUN, binds the carrier socket, and only then drops privileges and installs the
filter, so everything from the bind onward is filtered in production. Starting
the trace at `execve` rather than after the tunnel is what brings the phase
between the bind and the tunnel into the window — publishing the control socket
happens there, and so does the `linkat` that killed the first live `enforce` run.
A traced daemon is not killed at `SIGTERM` any more either, so its shutdown path
is in the trace too.

The counts differ from the 20 above because no two exercises are identical: the
script uses `vallum show` as the control client, pings in both directions, and
repeats the shutdown the same way every time. No count is the argument: the guard
diffs the trace against the list, not against this page.

### What the trace did not reach

The trace shows what a *running* daemon does; it cannot show what the daemon does
on a path the exercise did not take. Two gaps remain, and one earlier claim was
wrong and is corrected below.

1. **Thread creation, entry by entry.** The first derivation attached after the
   tunnel was up, when the threads already existed, so it never saw `clone3`,
   `set_robust_list`, `rseq`, or `sched_getaffinity`. The trace starts at
   `execve` now and all four are observed: the window covers the moment the
   threads are created. What is still unobserved is the *absence* of threads — 35
   to 37 of the 79 entries appear in neither trace, depending on the run, most of
   them startup-only
   (`arch_prctl`, `set_tid_address`, `rt_sigaction`) or libc and allocator
   fallbacks (`brk`, `clone` where `clone3` is the observed one). They are
   allowed because the drop happens after them or because a fallback may take
   them, not because a trace justified each one. The log window of §5 adds one
   kind of evidence for the paths it took — the full exercise under the filter,
   both carriers, across a rekey — and none for the entries it did not reach;
   the count stays a range.
2. **The TCP carrier has teardown paths the exercise stops short of.** The
   carrier itself is now traced: `socket`, `connect`, `poll`, `getsockopt`, and
   the framed stream's   `read`/`write` all appear in the TCP leg. `shutdown` still does not, even with
   the trace now running through the daemon's exit: the two call sites are
   teardown paths the exercise does not take, so that entry rests on reading the
   code.
   `recvmsg`, `sendmsg` and `recvmmsg` appeared in neither trace, and nothing in
   the crate calls them or a `*_vectored` form — the carrier sends with
   `sendmmsg` (batched UDP) and `write` (TCP). An earlier revision of this page
   kept all three "for a libc fallback"; on inspection there is no fallback to
   take them, so they are gone from the list rather than carried unexplained. A
   syscall an allowed call cannot decompose into is not something a fallback
   reaches.
3. **The terminal is a different process, not a path in this one.** An earlier
   revision of this document claimed a daemon started with `--tui` would lose its
   console in enforce mode. There is no `--tui` on `run`: the dashboard is
   `vallum tui`, a client that speaks to the control socket, and it runs without
   the daemon's filter. The daemon opens no terminal and no file, so there is no
   gap here — there was an error here.
4. **The window between the install and `tunnel up`.** This one was open: the
   guard attached after the tunnel was up, so everything the daemon did *under
   the filter* but *before* that point was invisible to it, and publishing the
   control socket happens there. The enforce leg covered that window, and on its
   first live run the daemon died in it: publication hard-links a chmodded socket
   out of a staging directory, `fs::hard_link` issues `linkat`, and the list had
   `unlinkat` but not `linkat`. No trace *at that time* could have found it; only
   a run with the filter on could. It is closed now: the guard traces from
   `execve` and cuts the window at the carrier bind, so the publish is inside it,
   and removing `linkat` from the list makes the guard exit 1 and name it. That
   negative test is the reason to believe the guard covers what the old one
   missed. `scripts/seccomp-enforce.sh` still replays a startup death under
   `strace`, so a syscall this window cannot reach — one made by the drop, or by
   the install — arrives named in the failure report rather than costing an
   investigation; that replay is what rejected `link` (the name one would guess)
   in favour of `linkat` (the name the binary issues).

## 4. What is deliberately absent

`execve`, `execveat`, `openat`, `open`, `openat2`, `fork`, `vfork`, `ptrace`,
`mount`, `umount2`, `chroot`, `unshare`, `setns`, `bpf`, `setuid`, `setgid`,
`setgroups`.

`socket` is allowed (the TCP carrier dials after the drop) but `socketpair` is
not, and no file-descriptor-opening call is: the daemon works with the
descriptors it was handed.

## 5. What is not established

1. **The log has been emptied over the exercise; production still has not run
   it.** On 2026-11-09 the filter ran in log mode across a real `auditd` window
   on this kernel, on tree `ab45af2` (the handoff page was written against
   `074b32b`; nothing in the sandbox changed between them). The
   development host has no `auditd` and no password-free `sudo`, so the window
   ran inside a rootful container — the blocked attempt, and the method that
   got around it, are in `docs/seccomp-audit-handoff.md`. The window: two
   daemons, each dropping to `nobody:nogroup` with the filter installed and
   `Seccomp: 2` confirmed on the process, one lifecycle per carrier; traffic
   both directions plus a 1228-byte payload, the control plane (`show`,
   `show --dump`, `show --json`, `syncconf`), a keepalive window, a full rekey
   to epoch 1 with traffic on both sides of it, and one daemon stopped by
   `stop=1`, the other by `SIGTERM`. `scripts/seccomp-log.sh` read the kernel's
   records — auditing verified `enabled 1`, `auditd` running — and exited 0:
   no would-kill record for the daemon across either window.
   The pipeline was proven live rather than assumed. A standalone filter (the
   same `seccompiler`, the allow-list shape: allow the mapped call, log
   everything else) made four off-list calls under `SECCOMP_RET_LOG`; the
   kernel wrote them as `SECCOMP` records and the collector named them
   (`write`, `sigaltstack`, `munmap`, `exit_group`) and exited 1. So the
   daemon window's zero is a real answer, not a deaf one.
   What this does not establish: no production deployment has run log mode
   long — no 40-minute idle window, no roaming peer, no fault-injected outer
   path — and a window proves only the paths it took. The list remains as
   informed as §3's traces plus this window, not as production would make it.
2. **Enforce mode has run live, but its kill has not been seen live.**
   `scripts/seccomp-enforce.sh` runs in CI as root, where the drop can call
   `setgroups`, and asserts six things about a dropped daemon in enforce mode:
   that it reports installing the filter, that the kernel reports `Seccomp: 2`
   and `NoNewPrivs: 1` for it, that the uid is fully dropped, that every thread
   it started after the install inherited the filter, that a ping crosses the
   tunnel and the control plane answers while filtered, and that `SIGTERM` still
   exits 0. What no live run can show is the kill: there is no way to ask the
   daemon to take an off-list path on demand without a debugger inside it. That
   half stays with the unit test, which re-executes itself, installs the same
   filter in enforce mode, and asserts the child dies on `SIGSYS` when it calls
   `execve`.
   On a development machine the script refuses to run without root (it says so
   and exits 1) rather than quietly testing less.
   It has already paid for itself: its first live run killed the daemon on
   `linkat` during startup, before any traffic, which is §3's fourth gap. The
   next run passes all eight checks, including the control plane answering in
   enforce mode — the path that died.
3. **The guard covers the traced paths only.** `scripts/seccomp-trace.sh` (run
   by the `e2e` job in CI) repeats the exercise on both carriers and fails when
   the daemon's syscalls are not a subset of `vallum sandbox --names`, from the
   carrier bind onward. It has been shown to fail twice: removing `sendto` made
   it exit 1 and name that syscall, and removing `linkat` — the syscall the old
   attach-after-tunnel window could not see — made it exit 1 and name that one.
   What it cannot see is §3 — paths the exercise does not take, and
   the ~36 entries no trace justifies individually. The list is as current as the
   exercise, not as the code.
4. **Nothing spawns a process after the drop — as of this audit.** Every place
   the daemon could run a program was checked: `nft` (policy installation) is
   called from `vallum policy`, `status`, and `metrics`, never from `run`; `ip`
   from `tun`, `hostnet`, `server`, and `quick`, all before the drop; `ping` only
   from `doctor --probe-mtu` and `setup`; `systemctl` from `service`, `doctor`,
   and the dashboard. The daemon path spawns nothing, so no exception to the
   list was needed. If one is added, enforce mode kills the daemon on it, and a
   traced path would also show `execve` and fail the guard — but a path the
   exercise does not take would only be found by the log.

## 6. How to reproduce the trace

```
cargo build -p vallum
scripts/seccomp-trace.sh              # 0: every traced syscall is on the list
KEEP=1 scripts/seccomp-trace.sh       # keep the configs, logs and raw trace
```

The script builds the same exercise — two configs that differ only in name,
address, listen port and peer, a real TUN each, the outer path over loopback, a
handshake, three pings each way, a control request, `stop=1` — twice: once over
UDP and once over the TCP carrier, inside one network namespace, attaching
`strace -f -p` to the client daemon after each tunnel is up. It reads the
allow-list back from the binary, so it needs no privileges of its own beyond the
user namespace (or `sudo` where user namespaces are restricted), and `ip`,
`ping`, and `strace`.

`scripts/seccomp-enforce.sh` is the other half, and it needs real root:

```
bash scripts/seccomp-enforce.sh || sudo -E bash scripts/seccomp-enforce.sh
```

It runs one exercise with `user`, `group`, and `seccomp = "enforce"` on both
daemons and checks the filter from the outside — `/proc/<pid>/status`,
`/proc/<pid>/task/*/status`, the ping, the control request, the exit status —
because the daemon's own log is a claim, not evidence.

When it fails it prints the syscalls the list does not name, keeps the scratch
directory, and points at the raw trace — which is the whole edit: add them to
`ALLOWED` in `crates/vallum/src/sandbox.rs`, or stop making the call. When a
daemon dies during startup instead, it replays that daemon under `strace` and
prints the call that killed it, because the exit status says only "Bad system
call" and the guard's trace starts after the window in question.

Step 3 needs a third script, root, and `auditd` running:

```
sudo scripts/seccomp-log.sh                        # /var/log/audit/audit.log
sudo scripts/seccomp-log.sh /var/log/audit/audit.log.1
```

It counts the `SECCOMP` records whose `comm` is the daemon, names the syscalls
when `ausearch` is available and prints the numbers when it is not, and exits 1
if there is one such record at all. It exits 2 — rather than report zero — when
it cannot see any records: no audit log, no read permission, or `auditctl -s`
saying auditing is off. That distinction is the point; a collector that answers
"clean" when it was collecting nothing would turn ADR-0028's step 3 into a
green check that proves nothing.

The 2026-11-09 window ran without host root, in a rootful container: `auditd`
installed inside it, `--network=host --pid=host` (the audit control netlink
refuses a private PID namespace once any auditd has registered), the repo
mounted read-only, the two daemons in private network namespaces so no host
interface was touched, and kernel auditing restored to `enabled 0` on the way
out. The container image, the harness, and the positive-control probe are
described in `docs/seccomp-audit-handoff.md`.


## The missing syscall, named (2026-11-11)

Phase 2's deferred diagnostic closed with `vallum-ops trace` (60 s strace of
the running daemon under a real 150 MB transfer through the tunnel, console
polling live):

```
openat(AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_RDONLY|O_CLOEXEC) = -1 EPERM
```

**The file is `/proc/sys/vm/overcommit_memory`** — the allocator's lazy
overcommit probe. It fires under memory pressure (bulk traffic), not at
startup, which is why the startup trace never saw it and why the deaths
needed load to reproduce.

**Why it is harmless now:** the probe is optional — the allocator falls back
to its default strategy on EPERM. Before the EPERM action shipped, the same
call was a SIGSYS kill: one optional probe took the whole tunnel down.
seccomp cannot filter by path (only by syscall number), so the honest choice
is the one already made: deny openat wholesale and let this one probe degrade,
rather than allow every file open to keep one probe happy.

**Rationale, one line:** the daemon needs no file opens at runtime; the only
openat it makes is a best-effort allocator probe whose failure is designed to
be survivable — EPERM is the correct answer, and the filter stays closed.
