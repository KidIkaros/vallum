# The syscall filter

**Date**: 2026-11-08
**Status**: shipped in log mode, not yet enforced
**Decision**: ADR-0028

## 1. What this claims

After the privilege drop, the daemon may make the syscalls on an allow-list and
no others. The list is derived from a trace of the daemon, not from reading the
source, and it is installed before any thread is spawned, so every thread the
process will ever have inherits it.

It does **not** claim that the list is complete. The filter ships in log mode for
exactly that reason: the kernel logs what the list would have killed, and the
list is corrected from those logs. Section 5 says what has not been done.

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
seccomp = "log"      # or "enforce"; "log" is the default
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
is the allocator). 81 syscalls are allowed.

The same exercise, run through the committed script (`scripts/seccomp-trace.sh`),
runs twice — once per carrier — and sees 27 distinct syscalls over UDP and 35
over TCP, 36 in union, all of them on the list. The counts differ from the 20
above because neither exercise is identical to the first derivation: the script
uses `vallum show` as the control client, pings in both directions, and repeats
the shutdown the same way every time. No count is the argument: the guard diffs
the trace against the list, not against this page.

### What the trace did not reach

The trace shows what a *running* daemon does; it cannot show what the daemon does
on a path the exercise did not take. Two gaps remain, and one earlier claim was
wrong and is corrected below.

1. **Thread creation, entry by entry.** The threads exist by the time the trace
   attaches over UDP, so the first derivation never saw `clone3`,
   `set_robust_list`, `rseq`, or `sched_getaffinity`. The TCP leg does see them,
   because the carrier starts its reader and writer threads on demand rather than
   at startup — so those entries are observed now, in the leg that creates a
   thread late. What is still unobserved is the *absence* of threads: 45 of the
   81 entries appear in neither trace, most of them startup-only (`arch_prctl`,
   `set_tid_address`, `rt_sigaction`) or libc and allocator fallbacks (`brk`,
   `clone` where `clone3` is the observed one). They are allowed because the
   drop happens after them or because a fallback may take them, not because a
   trace justified each one.
2. **The TCP carrier has teardown paths the exercise stops short of.** The
   carrier itself is now traced: `socket`, `connect`, `poll`, `getsockopt`, and
   the framed stream's `read`/`write` all appear in the TCP leg. `shutdown` does
   not, because the connection is closed during shutdown, after the trace stops.
   `recvmsg`, `sendmsg` and `recvmmsg` appear in neither trace and are called
   nowhere in the daemon — the carrier sends with `sendmmsg` (batched UDP) and
   `write` (TCP), not with vectored or ancillary calls. They stay on the list as
   the entries a libc fallback would use, and this paragraph is what that rests
   on: nothing measured.
3. **The terminal is a different process, not a path in this one.** An earlier
   revision of this document claimed a daemon started with `--tui` would lose its
   console in enforce mode. There is no `--tui` on `run`: the dashboard is
   `vallum tui`, a client that speaks to the control socket, and it runs without
   the daemon's filter. The daemon opens no terminal and no file, so there is no
   gap here — there was an error here.

## 4. What is deliberately absent

`execve`, `execveat`, `openat`, `open`, `openat2`, `fork`, `vfork`, `ptrace`,
`mount`, `umount2`, `chroot`, `unshare`, `setns`, `bpf`, `setuid`, `setgid`,
`setgroups`.

`socket` is allowed (the TCP carrier dials after the drop) but `socketpair` is
not, and no file-descriptor-opening call is: the daemon works with the
descriptors it was handed.

## 5. What is not established

1. **The log has not been emptied.** No production exercise has run with the
   filter in log mode long enough to collect what it would have killed on paths
   nobody traced. That is ADR-0028's step 3, and it is not a coding task.
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
3. **The guard covers the traced paths only.** `scripts/seccomp-trace.sh` (run
   by the `e2e` job in CI) repeats the exercise on both carriers and fails when
   the daemon's syscalls are not a subset of `vallum sandbox --names`. It has
   been shown to fail: removing `sendto` from the list made it exit 1 and name
   that syscall. What it cannot see is §3 — paths the exercise does not take, and
   the 45 entries no trace justifies individually. The list is as current as the
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
handshake, three pings each way, a control request, `SIGTERM` — twice: once over
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
`ALLOWED` in `crates/vallum/src/sandbox.rs`, or stop making the call.
