# H5 — privilege separation and key-file enforcement

**Status:** closes P6.5's two accepted risks — F6 (no privilege separation) and
F7 (a loose key mode warned, not refused).
**Depends on:** P6.4 for the daemon's startup order (`docs/proof/daemon.md`),
P6.5 for the findings (`docs/proof/pentest.md`).
**Wire change:** none. No protocol, message, or vector moves.

---

## 1. The gap

P6.5 recorded both and accepted them:

- **F6.** The daemon opened a TUN interface and a UDP socket — the only
  operations that need privilege — and then kept everything it started with for
  its whole life. A bug in the wire parser ran as root.
- **F7.** A private-key file with mode `0644` produced a warning on stderr and
  was used anyway. A warning in a log is not a control, and this is the one file
  whose exposure makes every other property moot.

Both are fixed here, and both are fail-closed.

---

## 2. The configuration surface

```toml
[interface]
private_key = "private.key"
user  = "vallum"   # optional
group = "vallum"   # optional; defaults to the user's primary group
```

- Names are resolved at load time. An unknown user or group is a startup error
  naming the field — not a silent no-op.
- `group` without `user` is legal (drop the group id only) and produces a warning,
  because it is rarely what an operator means.
- Neither field set means "keep the privileges the process started with", which
  is what every earlier deployment did. The change is opt-in.

---

## 3. The order, and why it is the mechanism

Applied after `tun::open` and `UdpTransport::bind`, before the loop starts:

1. **`setgroups(&[])`** — after `setuid` this call cannot succeed, so it must be
   first. Leaving supplementary groups behind is the classic half-drop.
2. **`setgid`** — before `setuid`, so the saved-set-uid dance cannot regain root.
3. **`setuid`** — with no saved-set-uid, the process cannot climb back.
4. **`PR_SET_NO_NEW_PRIVS`** — even if a later `exec` happened, setuid binaries
   could not raise privileges.
5. **Verify** `geteuid`/`getegid` equal the target. A `setuid` that silently did
   not take is exactly the failure this module exists to prevent, so it is
   checked rather than assumed.

Every step fails closed: the daemon exits with the failing call and the errno,
rather than running with the privileges it was meant to shed.

The key file is read, and the interface and socket are opened, **before** the
drop. Nothing after it needs a privilege.

---

## 4. Key-file policy

`keys::check_permissions(path, allow_insecure)`:

- mode has no group or world bits → `Ok(None)`;
- mode is loose and the override is absent → `Err(KeyPermissions)`, whose message
  names the path, the mode, and `--allow-insecure-key-permissions`;
- mode is loose and the override is present → `Ok(Some(warning))`, logged, so the
  exposure is still visible.

Both `run` and `pubkey` enforce it, and both enforce it **before** reading the
file: the check is about who can read the bytes, so doing it after the read would
be theatre.

---

## 5. What is and is not tested

**Tested**
- Unknown user and unknown group are startup errors (`privileges.rs` unit tests,
  and `an_unknown_privilege_target_is_refused_at_load` through a real config).
- A group without a user is accepted and warned about.
- Nothing configured resolves to `None` (no drop, no warning).
- A `0644` key is refused, the error names the override, and the override is
  accepted with a warning (`a_world_readable_key_file_is_refused_unless_overridden`).
- The default path is unchanged: the e2e runs with no `user`/`group` and passes.

**Not tested here**
- The actual `setuid` transition. It requires a privileged start, and this
  environment has no root. The sequence is therefore reasoned and unit-tested at
  the resolution layer, not exercised end to end. A root-run check is:

  ```sh
  sudo vallum run -c config.toml   # config has user = "nobody"
  # expect: "dropped privileges to nobody:nogroup", and `ps -o user= -p <pid>`
  ```

  This is a real gap and is stated rather than implied.

---

## 6. What this does **not** claim

1. **No `seccomp`.** The syscall surface is unchanged.
2. **No `chroot`, no mount namespace, no capability retention.** The drop is
   `set*id` + `no_new_privs`, nothing more.
3. **No per-peer isolation.** One process, one peer table.
4. **No protection against an attacker who can already read the key file.** The
   mode check is against accidental exposure (a backup, a copied directory, a
   permissive umask), not against a local attacker with the owner's rights.
5. **No protection against a compromised parent or a ptrace-capable process.**
6. **No claim that the drop happens on non-Linux.** The fields are refused there
   rather than silently ignored; the daemon is Linux-only this effort.
7. **No privilege *gain*.** `setuid` is one-way; the daemon cannot reopen a TUN
   interface after the drop, and it does not try.
