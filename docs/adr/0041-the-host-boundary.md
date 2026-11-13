# ADR-0041: The host boundary — OS knowledge lives under `host/`

**Date**: 2026-11-13
**Status**: accepted
**Deciders**: operator + Devin

## Context

Vallum was built Linux-first, and most of that assumption was absorbed into
individual modules: `tun.rs` gates its backend on `#[cfg(target_os =
"linux")]`, `sandbox.rs` degrades seccomp to a no-op elsewhere, `policy.rs`
and `hostnet.rs` are nftables/iptables-shaped, `probes.rs` answers with
`systemctl`, and `/etc/vallum` + `/run/vallum` were spelled wherever a path
was needed. The product now wants a second platform — other Unix first,
Android on the roadmap — and Android does not merely add a backend: its
`VpnService` *hands the process an fd to adopt* rather than a device to
create, outbound carrier sockets must run a `protect` hook or they route
through the tunnel itself, and the entire privilege model (`vallum-ops`,
sudoers, systemd lifecycle) collapses into the app process.

The risk of porting in place: every platform difference leaks into whichever
module happens to touch it first, and six months later `run.rs` knows what
an APK is. The same week saw the concrete version of this failure — the TUI
and GUI had each re-implemented systemd/SSH probing, and the copies had
already drifted into different bugs.

## Decision

Inside the `vallum` crate, **everything that knows which operating system
this machine runs lives under `src/host/`** — and nowhere else.

- `host::paths` owns where Vallum's files live: `config_dir()`,
  `runtime_dir()` (including the `VALLUM_RUN_DIR`/`VALLUM_RUNTIME_DIR`
  override, which `enroll` had re-stated), `config_path`, `config_stem`.
- `host::probes` owns read-only host facts: systemd unit state, enabled and
  restart counts, the operator's SSH config, `vallum-ops` output parsing.
- Future members join the same way `tun` already works: a `#[cfg]`'d
  implementation behind one interface — not a trait, not a plugin registry.
  The product compiles for one target at a time; dynamic dispatch would buy
  nothing and cost an abstraction.

Consoles and CLI verbs never run `systemctl` or read `/etc` themselves; they
ask `host::` and accept `None` as "the host cannot say" — the same
honesty contract `guidance` already depends on.

**What stays where it is.** `policy.rs`, `hostnet.rs`, `tun.rs`,
`sandbox.rs`, `net.rs`'s socket options, and `vallum-ops`/`vallum-quick`
are *also* host knowledge — they are not moved under `host/` wholesale,
because each already isolates its platform facts behind its own narrow
surface (`tun::open`, `sandbox::enforce`, `policy::plan`), and moving them
would churn for no hidden-information gain. The boundary is about the
*direction of the question*, not the file layout: new OS-specific knowledge
may only be added under `host/` or behind an existing cfg'd seam like
`tun`'s. When a second backend exists for one of them, it moves under
`host/` as part of that work.

**What Android changes, stated for the record.** `tun` gains an
fd-adoption backend and `net`/`run` gain a `protect`-socket hook;
`host::paths` answers app-private directories; `host::probes`' systemd
family answers `None` and the guidance engine keeps working because its
facts are optional; `vallum-ops` has no analogue — the app process is the
trust boundary. None of that invalidates this boundary; it is what the
boundary is for.

## Consequences

- The portability proof for the seam is a second Unix (macOS is cheapest:
  `tun2` already does `utun`, launchd probes are small) *before* Android's
  exotic requirements validate it — generalize on the second backend, not
  the third.
- `vallum-config`'s `RUNTIME_DIR` const remains the compiled default;
  `host::paths::runtime_dir()` is where the env override lives.
- The Android deliverable is a thin `VpnService` host process around the
  `vallum` library — same relationship the TUI has — not a separate stack.
