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

### What the trace did not reach

The trace shows what a *running* daemon does; it cannot show what the daemon
does on a path that exercise did not take. Three of those paths need entries the
trace cannot justify on its own:

1. **Thread creation.** The threads already existed when the trace attached, so
   `clone3`, `set_robust_list`, `rseq`, and `sched_getaffinity` never appear —
   but the control server and every reader start *after* the filter, so they must
   be allowed. They are, and they are the entries a reviewer should look at
   first.
2. **The TCP carrier** (ADR-0026) is not the default carrier and was not in this
   exercise: `recvmsg`, `sendmsg`, `shutdown`, `poll`, and `ppoll` are on the
   list because the carrier's code path calls them, not because the trace saw
   them.
3. **The terminal console** (`--tui`, on in the default feature set) opens
   `/dev/tty` and uses `ioctl`, which the list allows, but it also uses `openat`,
   which the list does not. A daemon started with `--tui` will lose that console
   in enforce mode. That is stated here rather than fixed: the console is a
   debugging surface, and widening the list for it would undo the property for
   every deployment that does not use it.

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
2. **Enforce mode has not run against a live daemon here.** The daemon installs
   the filter as part of the privilege drop, and a privilege drop inside an
   unprivileged user namespace cannot call `setgroups` (`EPERM`), so the
   end-to-end exercise could not take that path on a development machine. What
   was verified: the filter installs and kills what the list does not name (a
   unit test re-executes itself, installs enforce mode, and asserts the child
   dies on `SIGSYS` when it tries `execve`), and the 20-syscall post-startup
   trace is entirely inside the list. The live run belongs to CI, where the
   privilege drop is exercised under `sudo`.
3. **The CI guard does not exist yet.** ADR-0028 step 4: fail the build when a
   trace of the test suite observes a syscall the list does not allow. Until
   then the list is only as current as this document.
4. **A path that shells out would now die.** If any code after the drop spawns a
   process — policy installation is the one to check — enforce mode kills the
   daemon on it. Log mode is the answer until that is settled.

## 6. How to reproduce the trace

The exercise is not a script in this repository; it was run once to produce the
list above, with two configs that differed only in name, address, listen port,
and peer, and with `strace -f -p` attached after the handshake. A future
derivation should be committed as a script beside this document rather than
re-invented, and the CI guard in §5.3 is how it stops being re-invented at all.
