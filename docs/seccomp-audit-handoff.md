# ADR-0028 step 3 — the audit run, and the work left around it

**Status:** resolved on 2026-11-09 — the run this page asked for happened, on
this machine, without host root. The way around the block, the outcome, and
what the window does and does not establish are in "The run that happened,
2026-11-09" below; the blocked attempt is kept as written, because the method
that got around it only makes sense against what stopped the first one.
This page exists so someone
with root on a host that has `auditd` can finish the step without re-deriving
what was already tried.

The tree this page was written against is `074b32b`: `scripts/verify.sh` passes,
and CI is green end to end on that commit (run `42608252621` — stable 18m11, MSRV
5m55, e2e 2m58, audit 20s; 36 minutes wall clock, of which the first 9 were the
runner still being busy).

## Why this is open

Step 3 of [ADR-0028](adr/0028-seccomp-filter.md) is "empty the log": run the
daemon with the filter in `log` mode for a real working window and read what the
kernel would have killed. The allow-list was derived from traces, so the entries
no trace justified are the ones this step exists to settle — currently 35 to 37
of the 79, depending on the run (see `proof/seccomp.md` §3).

The reading half is built: `scripts/seccomp-log.sh` aggregates the kernel's
`SECCOMP` audit records for the daemon and names the syscalls a run would have
died on. It refuses to answer when it cannot see records — exit 0 means read and
clean, exit 1 means records were found, exit 2 means the collector could not
observe anything — because "no records" and "no collection" look identical in a
log that was never written.

## The run that happened, 2026-11-09

The block was around, not through: this account is in the `docker` group, and a
rootful container is effective root without touching host state. No `auditctl`
on the host was ever installed; everything ran inside.

**Method.** An image from `debian:stable-slim` with `auditd` 4.0.2,
`iproute2` and `iputils-ping`; the container run with `--privileged
--network=host --pid=host`, the repo mounted read-only. The two daemons ran in
two *private* network namespaces joined by a veth pair, so no host interface or
route was touched, and kernel auditing was restored to `enabled 0` (its state
before the window) when the container exited. Binary: `target/debug/vallum`
built from `ab45af2`, the tree this page's follow-ups were finished on.

A lesson worth keeping: after any `auditd` has registered and died, the kernel
**refuses audit control requests from processes in a private PID namespace**
with `EPERM` — even `auditctl -s`. The first container's abrupt `auditd` death
wedged every later non-`--pid=host` container this way; sharing the host's PID
namespace is what makes `auditctl` work again. The `--network=host` half is
older and better known: `auditd` only runs in the initial network namespace.

**The window.** Both daemons configured with `user = "nobody"`, `group =
"nogroup"`, `seccomp` at its default (`log`), a control socket on A, a 1 s
keepalive on B. One lifecycle per carrier:

* UDP: handshake both roles, pings both directions, a 1228-byte payload,
  `show` / `show --dump` / `show --json`, `syncconf`, a keepalive window, a
  full rekey to **epoch 1** with traffic on both sides of it, then A stopped by
  `stop=1` and B by `SIGTERM` — the informative ending this page asked for.
* TCP (`carrier = "tcp"` on both ends): handshake, pings both directions, a
  control `show --dump`, a rekey to epoch 1, then `stop=1` and `SIGTERM`.

`Seccomp: 2` and `Seccomp_filters: 1` were read from the daemon's
`/proc/<pid>/status`, and the daemon's own log line names the mode.

**The answer.** `scripts/seccomp-log.sh` exited **0**: no `SECCOMP` record for
`comm="vallum"` in either window, with auditing verified `enabled 1` and
`auditd` running (pid visible in `auditctl -s`), and the log's line count
recorded before and after.

**The positive control.** A zero is only an answer if the pipeline was live, so
a standalone probe — `seccompiler` 0.5, the allow-list shape (allow the mapped
call, log everything else, same as `sandbox.rs`) — ran in the same setup and
made four off-list calls under `SECCOMP_RET_LOG`. The kernel wrote them as
`SECCOMP` records; the collector named them (`write`, `sigaltstack`,
`munmap`, `exit_group`), printed the window's first timestamp, and exited 1.
The daemon's zero is therefore a real answer, not a deaf one.

**What this does not establish.** No production deployment has run log mode:
no 40-minute idle window, no roaming peer, no fault-injected outer path, no
carrier teardown past `shutdown`. A window proves the paths it took. The
unobserved-entry count in `docs/proof/seccomp.md` §3 stays a range; step 5
(flip the default to `enforce`) is now unblocked but remains the maintainer's
release decision.

## The attempt on 2026-11-09, and what stopped it

On the development host, on this tree:

```
$ command -v auditctl
(not found)
$ command -v ausearch
(not found)
$ ls -l /var/log/audit/
ls: cannot access '/var/log/audit/': No such file or directory
$ sudo -n true
sudo: a password is required
$ id -u
1000
```

No `auditd`, so no `SECCOMP` records exist to collect: the kernel emits them into
the audit subsystem, and without it there is nothing for a collector to read.
No password-free `sudo`, so one cannot be installed for the length of a run
either. Running it in CI was rejected rather than impossible: the runner is a
shared self-hosted host, enabling auditing there changes machine state for every
job on it, and the `e2e` job was just cut from 26 minutes to 3.

The collector's own logic was exercised against synthetic records instead: three
daemon records produced `2 chmod / 1 linkat` with an `ausearch` stub on `PATH`,
the same three produced numbered `syscall 92 / 86` lines without one, a clean log
exited 0, and a missing log exited 2. That proves the script, not the filter.

On this machine the daemon also cannot install the filter at all: the install
lives inside the privilege-drop branch (`commands::run` calls `sandbox::install`
only under `if let Some(privileges)`), and the drop calls `setgroups`, which an
unprivileged user namespace denies. `config.rs` refuses `interface.seccomp`
without `interface.user` or `interface.group` for the same reason. So step 3 is
root-only twice over: the drop, and reading the log.

## What a real run needs

1. Root (or a password for `sudo`), and `auditd` running: `auditctl -s` reports
   `enabled 1`. `ausearch` is optional — without it the collector prints syscall
   numbers instead of names.
2. A config whose `[interface]` names `user` and `group`, with `seccomp` left at
   its default (`log`). Without a drop the filter is never installed, the run is
   unobservable, and the collector will correctly say so by exiting 2.
3. A window in which the daemon does real work — a peer, traffic through the
   tunnel, a control request — not just a start and a stop.

## The run

```sh
# 1. auditing is on
auditctl -s | head -3

# 2. record the size of the log, so "no records" cannot be confused with
#    "the log was rotated"
ls -l /var/log/audit/audit.log

# 3. start the daemon in log mode, as root, with a drop configured
sudo vallum run --config /etc/vallum/handoff.toml

# 4. exercise it: ping a peer address through the tunnel, `vallum show
#    --control ...`, then stop it. `vallum stop --control ...` sends `stop=1`,
#    which is acknowledged before the tunnel stops; SIGTERM works too and is the
#    path systemd takes, so a window that ends with both is the more
#    informative one.

# 5. read what the filter would have killed
sudo scripts/seccomp-log.sh
```

Exit status is the answer, not the text:

| exit | meaning | what to do |
|---|---|---|
| 0 | read, and clean — no daemon record in the log | say so, with the log's size and the window it covers |
| 1 | records found; each is a syscall `enforce` mode would have killed | add it to `ALLOWED` in `crates/vallum/src/sandbox.rs` with the reason beside it, or stop making the call |
| 2 | could not observe: no log, no read permission, or auditing off | fix that and re-run; never report this as "clean" |

A single record is enough. The failure mode this step exists to catch is one
syscall on one path — that is what `linkat` was.

## What to record afterwards

* `docs/proof/seccomp.md` §3: which entries the log justified, and which are
  still carried on the strength of reading the code. The unobserved count is a
  range today because the trace is not deterministic to the syscall; a log run
  narrows it with evidence rather than another trace.
* `docs/proof/seccomp.md` §5.1: the claim "the log has not been emptied in
  production" only stops being true with a real window.
* ADR-0028's step 3 row: from "in progress" to done, with the window described.

## The rest of the follow-ups from this session

| # | Item | Status | Where |
|---|---|---|---|
| 1 | Enforce-mode leg failing in CI | **done** — the daemon died on `linkat` while publishing its control socket; entry added, replay added | `crates/vallum/src/sandbox.rs`, `scripts/seccomp-enforce.sh` |
| 2 | Prune entries no trace and no caller justifies | **done** — `recvmsg`, `sendmsg`, `recvmmsg` removed; 81 → 79 entries | `crates/vallum/src/sandbox.rs`, `proof/seccomp.md` §3 |
| 3 | A log-mode collection path for step 3 | **built** — `scripts/seccomp-log.sh`, exit 0/1/2 | `scripts/seccomp-log.sh`, `proof/seccomp.md` §6 |
| 4 | CI wall clock under an hour for a push | **done** — 27m15s of work measured, from ~79 min; fuzz is one job, the MSRV leg compiles instead of testing | `.github/workflows/ci.yml`, `fuzz.yml` |
| 5 | Trace the daemon from startup, not from "tunnel up" | **done** — window starts at the carrier bind; removing `linkat` now fails the guard | `scripts/seccomp-trace.sh`, `proof/seccomp.md` §3 gap 4 |
| 6 | Run the collector against a real auditd window | **done** — 2026-11-09, in a rootful container (`docker` group = effective root): collector exit 0 across both carriers with a rekey to epoch 1; positive control exit 1 in the same setup — see "The run that happened" above | `docs/proof/seccomp.md` §5.1, ADR-0028 step 3 |
| 7 | Give the daemon a control-plane stop verb | **done** — `vallum stop`, i.e. `stop=1`, answered before the daemon stops; the trace guard stops the daemon through it | `crates/vallum/src/control.rs`, `docs/proof/uapi.md` |
| 8 | Make a push's checks independent of what is queued on the one runner | **open** — a second runner, or splitting jobs across hosted runners, is infrastructure this repo does not have. The `074b32b` run sat 9 minutes before its first job started, which is why item 4 is quoted as work done rather than wall clock | `.github/workflows/` |

Item 7 is the one with a bug story behind it: stopping the traced daemon by a
pid discovered at startup failed in CI with "No such process" while the daemon
was still serving, and the two attempts to fix it from the test side (a
`/proc` lookup, then a shutdown by config path) were both workarounds for a
missing verb. `stop=1` is that verb: the socket is the handle the caller already
has, and the reply is written before the daemon stops, so the client can tell a
stop it caused from a socket that had already closed.
