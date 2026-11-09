// SPDX-License-Identifier: Apache-2.0

//! The syscall filter: what the daemon may still ask the kernel for once the
//! interface is up and the privileges are gone (ADR-0028).
//!
//! `privileges::drop_to` bounds *who* the daemon is. It does not bound what the
//! process may ask the kernel for: after the drop the daemon still holds a full
//! syscall table, so a bug in the wire parser runs with the ability to open
//! files and spawn processes it has no business spawning. This module closes
//! that: an allow-list of the syscalls the daemon actually makes, installed once
//! and inherited by every thread.
//!
//! # Where it is installed, and why that is the whole trick
//!
//! `commands::run` calls [`install`] immediately after `drop_to`, and that call
//! site is before every thread is spawned — the control server, the TUN reader,
//! the UDP reader, and the TCP carrier's acceptor and writer all start later. A
//! filter installed there is inherited by every thread the daemon will ever
//! have: no per-thread installation, and no window in which an unfiltered
//! thread exists. Moving the call later would lose that property silently.
//!
//! # Two stages
//!
//! A wrong entry in an enforcing filter kills the daemon on a path nobody
//! exercised, and the operator sees a crash rather than a diagnostic. So the
//! filter has two modes: [`Mode::Log`] asks the kernel to log and allow the
//! syscalls the list does not name, and [`Mode::Enforce`] kills the process.
//! Both are selectable with `interface.seccomp`; the default is `enforce`
//! since 1.6.5 — the log stage found its last entry and the audit window came
//! back clean — and `log` remains the explicit debugging opt-out.
//!
//! # How the list was derived
//!
//! By observation, not by reading this crate: two daemons in one network
//! namespace, a real TUN each, the outer path over loopback UDP, a handshake,
//! packets both ways through the tunnel, a control-socket request, and a
//! `SIGTERM` shutdown, with `strace -f -p` attached to the client daemon *after*
//! the tunnel was up. The startup phase — interface creation, address
//! assignment, and the `ip` calls that do it — is deliberately not in the list:
//! all of it happens before the drop. `docs/proof/seccomp.md` records the trace,
//! the syscalls it produced, and what it did not cover.

use crate::error::Error;

/// What the kernel does with a syscall the allow-list does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Kill the process. The default: the stage that holds the property.
    #[default]
    Enforce,
    /// Log the syscall and let it through. The debugging opt-out: it finds a
    /// missing entry without costing the daemon its life, and a config that
    /// names it says the property is off rather than assuming it.
    Log,
}

impl Mode {
    /// The name used in the log line and in `interface.seccomp`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Enforce => "enforce",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The syscalls the daemon may still make after the privilege drop.
///
/// Grouped by what they are for, because the list is also a description of the
/// daemon. Names are kept beside the numbers so the list can be read, tested
/// against, and compared with a trace without a lookup table.
#[cfg(target_os = "linux")]
const ALLOWED: &[(&str, i64)] = {
    use nix::libc as c;
    &[
        // The tunnel: one file descriptor read per packets, one write per packet.
        ("read", c::SYS_read),
        ("write", c::SYS_write),
        ("pread64", c::SYS_pread64),
        ("close", c::SYS_close),
        // The datagram carrier.
        ("recvfrom", c::SYS_recvfrom),
        ("sendto", c::SYS_sendto),
        ("sendmmsg", c::SYS_sendmmsg),
        // The stream carrier (ADR-0026): it dials and marks after the drop. It
        // reads and writes each frame with `read`/`write`; nothing in the crate
        // calls `sendmsg`, `recvmsg`, `recvmmsg` or a `*_vectored` form, and no
        // trace has ever seen one, so none is allowed. `shutdown` is: the
        // carrier takes a stream down deliberately when a peer stops answering.
        ("socket", c::SYS_socket),
        ("connect", c::SYS_connect),
        ("shutdown", c::SYS_shutdown),
        ("setsockopt", c::SYS_setsockopt),
        ("getsockopt", c::SYS_getsockopt),
        ("getsockname", c::SYS_getsockname),
        ("getpeername", c::SYS_getpeername),
        // The control plane: `control::serve` runs after the drop and publishes
        // its socket by hard-linking a chmodded socket out of a staging
        // directory, so the published name is never reachable with a provisional
        // mode. `linkat` is what `fs::hard_link` issues; the initiator is a
        // staged socket this process just created, and the link is a name in a
        // directory the daemon already writes to.
        ("bind", c::SYS_bind),
        ("listen", c::SYS_listen),
        ("accept4", c::SYS_accept4),
        ("linkat", c::SYS_linkat),
        ("unlink", c::SYS_unlink),
        ("unlinkat", c::SYS_unlinkat),
        ("mkdir", c::SYS_mkdir),
        ("rmdir", c::SYS_rmdir),
        ("rename", c::SYS_rename),
        ("chmod", c::SYS_chmod),
        ("fchmod", c::SYS_fchmod),
        ("getdents64", c::SYS_getdents64),
        ("readlink", c::SYS_readlink),
        ("readlinkat", c::SYS_readlinkat),
        ("access", c::SYS_access),
        ("faccessat2", c::SYS_faccessat2),
        // Statistics on what is already open, and on the socket path.
        ("fstat", c::SYS_fstat),
        ("statx", c::SYS_statx),
        ("newfstatat", c::SYS_newfstatat),
        ("fstatfs", c::SYS_fstatfs),
        ("statfs", c::SYS_statfs),
        // Every reader and writer thread starts after the drop.
        ("clone", c::SYS_clone),
        ("clone3", c::SYS_clone3),
        ("futex", c::SYS_futex),
        ("set_robust_list", c::SYS_set_robust_list),
        ("rseq", c::SYS_rseq),
        ("sched_getaffinity", c::SYS_sched_getaffinity),
        ("sched_yield", c::SYS_sched_yield),
        ("gettid", c::SYS_gettid),
        ("set_tid_address", c::SYS_set_tid_address),
        // Waiting. The loop sleeps on the clock; the stream carrier polls.
        ("poll", c::SYS_poll),
        ("ppoll", c::SYS_ppoll),
        ("clock_nanosleep", c::SYS_clock_nanosleep),
        ("nanosleep", c::SYS_nanosleep),
        ("clock_gettime", c::SYS_clock_gettime),
        ("restart_syscall", c::SYS_restart_syscall),
        // Signals: the handlers are installed after the drop.
        ("rt_sigaction", c::SYS_rt_sigaction),
        ("rt_sigprocmask", c::SYS_rt_sigprocmask),
        ("rt_sigreturn", c::SYS_rt_sigreturn),
        ("sigaltstack", c::SYS_sigaltstack),
        ("tgkill", c::SYS_tgkill),
        // The allocator, for the life of the process.
        ("mmap", c::SYS_mmap),
        ("munmap", c::SYS_munmap),
        ("mprotect", c::SYS_mprotect),
        ("mremap", c::SYS_mremap),
        ("madvise", c::SYS_madvise),
        ("brk", c::SYS_brk),
        // Entropy, for every handshake and every rekey.
        ("getrandom", c::SYS_getrandom),
        // Knowing what this process is, and saying so.
        ("getpid", c::SYS_getpid),
        ("getppid", c::SYS_getppid),
        ("getuid", c::SYS_getuid),
        ("geteuid", c::SYS_geteuid),
        ("getgid", c::SYS_getgid),
        ("getegid", c::SYS_getegid),
        ("getcwd", c::SYS_getcwd),
        ("prctl", c::SYS_prctl),
        ("prlimit64", c::SYS_prlimit64),
        ("arch_prctl", c::SYS_arch_prctl),
        ("capget", c::SYS_capget),
        ("fcntl", c::SYS_fcntl),
        ("ioctl", c::SYS_ioctl),
        ("dup2", c::SYS_dup2),
        ("pipe2", c::SYS_pipe2),
        // Shutdown.
        ("exit", c::SYS_exit),
        ("exit_group", c::SYS_exit_group),
    ]
};

/// As [`ALLOWED`], for a build without the Linux backend: there is no filter to
/// install, so there is no list.
#[cfg(not(target_os = "linux"))]
const ALLOWED: &[(&str, i64)] = &[];

/// The allow-list as syscall numbers, for the filter and for a test that wants
/// to assert what is and is not in it.
#[must_use]
pub fn allowed_numbers() -> Vec<i64> {
    ALLOWED.iter().map(|(_, number)| *number).collect()
}

/// The allow-list as names, for the proof document and the CI guard.
#[must_use]
pub fn allowed_names() -> Vec<&'static str> {
    ALLOWED.iter().map(|(name, _)| *name).collect()
}

/// Install the filter with the given mode, and fail closed if it cannot be.
///
/// # Errors
///
/// [`Error::Sandbox`] if the list cannot be compiled or the kernel refuses it.
/// The daemon must not continue in that case: a daemon that believes it is
/// filtered and is not has a worse posture than one that never tried.
#[cfg(target_os = "linux")]
pub fn install(mode: Mode) -> Result<(), Error> {
    use seccompiler::{
        apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;

    let mismatch = match mode {
        Mode::Log => SeccompAction::Log,
        Mode::Enforce => SeccompAction::KillProcess,
    };
    // An empty rule vector matches the syscall whatever its arguments, which is
    // what an allow-list wants: the daemon does not need to police arguments to
    // get the benefit of a smaller table.
    let rules: BTreeMap<i64, Vec<SeccompRule>> = allowed_numbers()
        .into_iter()
        .map(|number| (number, Vec::new()))
        .collect();
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|why| Error::Sandbox(format!("this architecture has no syscall table: {why}")))?;
    let filter: BpfProgram = SeccompFilter::new(rules, mismatch, SeccompAction::Allow, arch)
        .and_then(BpfProgram::try_from)
        .map_err(|why| Error::Sandbox(format!("compiling the syscall allow-list: {why}")))?;
    apply_filter(&filter)
        .map_err(|why| Error::Sandbox(format!("installing the syscall allow-list: {why}")))?;
    Ok(())
}

/// As [`install`], for a build without the Linux backend.
///
/// # Errors
///
/// Never; the configuration refuses `interface.seccomp` on this platform, so
/// there is nothing to do and nothing to pretend.
#[cfg(not(target_os = "linux"))]
pub fn install(_mode: Mode) -> Result<(), Error> {
    Ok(())
}

/// Whether this kernel can install the filter, and what is missing if it cannot.
///
/// [`install`] fails closed, so the daemon refuses to start rather than run
/// unfiltered when this says no. That makes the answer worth showing an operator
/// *before* they restart into it, which is why `vallum doctor` reports it.
///
/// It is a prediction, not a proof: only an install proves it, and a diagnostic
/// must not install anything. The two facts that decide it are checked directly
/// — `PR_GET_SECCOMP` exists, and the kernel's action list carries the two
/// actions the filter uses. The second read is evidence, not authority: a
/// container runtime can mask `/proc/sys/kernel/seccomp/actions_avail`, so a
/// missing entry is reported as the doubt it is.
///
/// # Errors
///
/// What is missing: no `seccomp` in this kernel, an action older than 4.14, or an
/// architecture with no syscall table.
#[cfg(target_os = "linux")]
pub fn support() -> Result<(), String> {
    // A kernel built without `CONFIG_SECCOMP` omits this field entirely; with it,
    // the field is there whether or not a filter is installed, and its value is
    // the mode this process is in (which for a diagnostic is 0).
    const STATUS: &str = "/proc/self/status";
    let status = std::fs::read_to_string(STATUS)
        .map_err(|error| format!("`{STATUS}` is unreadable ({error})"))?;
    if !status.lines().any(|line| line.starts_with("Seccomp:")) {
        return Err(format!(
            "`{STATUS}` has no `Seccomp:` line, which is what a kernel built without \
             CONFIG_SECCOMP looks like"
        ));
    }
    seccompiler::TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|why| format!("no syscall table for `{}`: {why}", std::env::consts::ARCH))?;
    const ACTIONS: &str = "/proc/sys/kernel/seccomp/actions_avail";
    let available = std::fs::read_to_string(ACTIONS)
        .map_err(|error| format!("`{ACTIONS}` is unreadable ({error})"))?;
    for action in ["log", "kill_process"] {
        if !available.split_whitespace().any(|name| name == action) {
            return Err(format!(
                "`{ACTIONS}` does not list `{action}`: {} — the filter needs the seccomp \
                 actions of Linux 4.14",
                available.trim()
            ));
        }
    }
    Ok(())
}

/// As [`support`], for a build without the Linux backend.
///
/// # Errors
///
/// Always: there is no filter to install, and the configuration says so when an
/// operator asks for one.
#[cfg(not(target_os = "linux"))]
pub fn support() -> Result<(), String> {
    Err("seccomp is only implemented on Linux".to_owned())
}

/// The allow-list as `(name, number)` pairs, for `vallum sandbox` and the CI
/// guard that diffs a trace against it.
#[must_use]
pub fn entries() -> Vec<(&'static str, i64)> {
    ALLOWED.to_vec()
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_list_names_the_tunnel_and_refuses_a_shell() {
        let names = allowed_names();
        for needed in [
            "read",
            "write",
            "recvfrom",
            "sendto",
            "bind",
            "accept4",
            "getrandom",
        ] {
            assert!(names.contains(&needed), "the allow-list lost `{needed}`");
        }
        // The point of the filter: a parser bug cannot become a shell, and it
        // cannot open a file the daemon was not handed.
        for refused in [
            "execve", "execveat", "openat", "open", "openat2", "fork", "vfork",
        ] {
            assert!(
                !names.contains(&refused),
                "the allow-list lets `{refused}` through"
            );
        }
    }

    /// If this fails the daemon will not start with `interface.seccomp`, so it is
    /// worth knowing before a deployment finds out. The kernel this runs on is
    /// expected to have seccomp; a container that masks the action list makes
    /// this fail with the file's contents in the message.
    #[test]
    fn this_kernel_can_install_the_filter() {
        if let Err(why) = support() {
            panic!("the syscall filter cannot be installed here: {why}");
        }
    }

    #[test]
    fn modes_have_stable_names() {
        assert_eq!(Mode::Log.as_str(), "log");
        assert_eq!(Mode::Enforce.as_str(), "enforce");
        // The default is a security posture, not an accident: unset `seccomp`
        // enforces, and `log` is reachable only by naming it in the config.
        assert_eq!(Mode::default(), Mode::Enforce);
    }

    /// The filter only means something in enforce mode, so the one property
    /// worth testing is that it kills what the list does not name. It cannot be
    /// tested in-process — installing it is irrevocable — so the test re-executes
    /// itself and checks the child.
    #[test]
    fn enforce_kills_a_syscall_the_list_does_not_name() {
        const MARKER: &str = "VALLUM_SANDBOX_SELFTEST";

        if std::env::var_os(MARKER).is_some() {
            install(Mode::Enforce).expect("install the filter");
            // `Command::status` clones (allowed) and then asks for `execve`,
            // which the list does not name: the child must die before `/bin/true`
            // runs, not fail to spawn.
            let _ = std::process::Command::new("/bin/true").status();
            // Reaching this line means the filter permitted `execve`.
            std::process::exit(0);
        }

        let exe = std::env::current_exe().expect("current exe");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "sandbox::tests::enforce_kills_a_syscall_the_list_does_not_name",
            ])
            .env(MARKER, "1")
            .output()
            .expect("spawn the self-test child");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            output.status.signal(),
            Some(nix::libc::SIGSYS),
            "the enforcing filter did not kill the child: {output:?}"
        );
    }
}
