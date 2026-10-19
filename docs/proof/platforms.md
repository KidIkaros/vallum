# G6 — cross-platform (status and plan)

**Status:** **Linux is the supported target.** macOS, Windows and BSD are
**not supported** in this cut; the blockers are enumerated so a port starts from
facts, not from a `cfg` guess.

---

## 1. What is Linux-specific today

| Area | Where | Why it is Linux-specific |
|---|---|---|
| TUN backend | `crates/vallum/src/tun.rs` (`#[cfg(target_os = "linux")]`) | `tun2` is pulled in only for Linux; non-Linux `open` returns `Unsupported` |
| Address assignment | `tun::platform::assign_address` | netlink `RTM_NEWADDR`; macOS/BSD use `ifconfig`/ioctl, Windows uses the IP Helper API |
| Privilege drop | `crates/vallum/src/privileges.rs` | `prctl(PR_SET_NO_NEW_PRIVS)` is Linux; macOS/BSD use `setgroups/setgid/setuid`, Windows uses a restricted token |
| Socket options | `crates/vallum/src/net.rs` | `IP_MTU_DISCOVER`/`IPV6_DONTFRAG` and `SO_MARK` are Linux; macOS has `IP_DONTFRAG`/`IPV6_DONTFRAG` and no `SO_MARK`; Windows differs again |
| IPv6 route/address | `config`/`tun` | connected routes come from the kernel on Linux; other OSes need explicit work |

`tun2` itself has `macos`, `windows`, `freebsd`, `ios` and `android` platform
modules, so the TUN layer is not the hard part — the daemon's OS policy is.

---

## 2. Staged plan

1. **macOS first.** Generalise the `tun` platform module to use `tun2`'s macOS
   backend; replace netlink with `ifconfig`/ioctl for addresses; `setuid`-based
   privilege drop (no `no_new_privs`); `IP_DONTFRAG`/`IPV6_DONTFRAG`; no
   `SO_MARK` (document `fwmark` as Linux-only). `vallum-quick` stays Unix-shell
   based.
2. **Windows.** `tun2`'s wintun backend; restricted-token privilege drop; routes
   and DNS through the IP Helper API; a PowerShell `vallum-quick`.
3. **BSD.** `tun` + `ifconfig`; the same Unix privilege drop as macOS.
4. **CI.** Add a `cargo check` job per target only once the target compiles;
   a red cross-check job is noise. Runtime tests need a runner that can create
   the interface.

Each target gets its own go/no-go gate, and the docs will say which tier it is
in (supported / experimental).

---

## 3. The signifier

`vallum --version` prints `0.1.0 (linux-only)` and `--help` states the tier and
points here. A user on another platform learns the boundary before building,
rather than from a wall of `cfg` errors.

---

## 4. What this does **not** claim

- No macOS/Windows/BSD binary is built or tested here.
- No cross-compilation CI job is added yet; the current workflow stays
  Linux-only so it stays green.
- No platform abstraction is pretended: the `cfg` boundaries are real and
  listed above.
