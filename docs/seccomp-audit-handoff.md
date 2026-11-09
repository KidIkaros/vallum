# ADR-0028 step 3 — the audit run, and the work left around it

**Status:** blocked on the machine, not on the code. This page exists so someone
with root on a host that has `auditd` can finish the step without re-deriving
what was already tried.

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
#    --control ...`, then SIGTERM the daemon

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
| 4 | CI wall clock under an hour for a push | **done** — 27m15s measured, from ~79 min; fuzz is one job, the MSRV leg compiles instead of testing | `.github/workflows/ci.yml`, `fuzz.yml` |
| 5 | Trace the daemon from startup, not from "tunnel up" | **done** — window starts at the carrier bind; removing `linkat` now fails the guard | `scripts/seccomp-trace.sh`, `proof/seccomp.md` §3 gap 4 |
| 6 | Run the collector against a real auditd window | **blocked** — this page | needs root + `auditd` |
| 7 | Give the daemon a control-plane stop verb | **done** — `vallum stop`, i.e. `stop=1`, answered before the daemon stops; the trace guard stops the daemon through it | `crates/vallum/src/control.rs`, `docs/proof/uapi.md` |
| 8 | Make a push's checks independent of what is queued on the one runner | **open** — a second runner, or splitting jobs across hosted runners, is infrastructure this repo does not have | `.github/workflows/` |

Item 7 is the one with a bug story behind it: stopping the traced daemon by a
pid discovered at startup failed in CI with "No such process" while the daemon
was still serving, and the two attempts to fix it from the test side (a
`/proc` lookup, then a shutdown by config path) were both workarounds for a
missing verb. `stop=1` is that verb: the socket is the handle the caller already
has, and the reply is written before the daemon stops, so the client can tell a
stop it caused from a socket that had already closed.
