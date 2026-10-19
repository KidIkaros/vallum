# G4 — `vallum-quick`, packaging, and the installer

**Status:** the OS-level helper, systemd/man/completion/deb-rpm metadata, and an
installer with client add/remove.
**Depends on:** G2 (`uapi.md`) for `syncconf`, G3 (`socket-ops.md`) for `fwmark`.
**Wire change:** none.

---

## 1. The boundary

The daemon owns the tunnel, the interface, the socket, and the peer table. It
runs **no shell**, writes **no routes**, and touches **no DNS**. Everything
host-specific lives in `vallum-quick`, an admin-run binary:

| Concern | Owner |
|---|---|
| TUN, UDP, handshake, data plane, control socket | `vallum` daemon |
| routes, DNS, firewall/NAT, hooks | `vallum-quick` |
| package/service/man/completion | `packaging/` |
| OS detection, first install, client add/remove | `scripts/install.sh` |

This preserves the property that a compromised packet parser cannot execute a
shell, while still giving operators the `wg-quick`-shaped workflow.

---

## 2. `vallum-quick`

```
vallum-quick up   <config> [--dry-run]
vallum-quick down <config> [--dry-run]
vallum-quick strip <config>
```

- `up` runs `pre_up`, starts `vallum run` (or prints it under `--dry-run`),
  waits for the interface, adds a route per `allowed_ips` entry (`ip` or `ip -6`,
  optionally `table N`), installs DNS through `resolvconf` when present, and runs
  `post_up`. The child's pid goes to `<config>.pid`.
- `down` runs `pre_down`, removes the routes and DNS, sends `SIGTERM` to the
  pidfile, and runs `post_down`.
- `strip` prints the config without its `[quick]` table — the form the daemon
  consumes, and the one to hand to `syncconf`.
- `save` runs `vallum showconf` and writes the result to stdout or `--output`.
  `--in-place --include-secrets` replaces the config after copying it to
  `<config>.bak`; either flag alone is refused, because a secret-free export
  would drop the key path and every PSK.
- `VALLUM_BIN` overrides the daemon path (tests, non-standard installs).

The `[quick]` table (parsed by the daemon and ignored by it):

```toml
[quick]
dns = ["1.1.1.1"]
table = "auto"        # auto | off | a number
pre_up = ["…"]
post_up = ["…"]
pre_down = ["…"]
post_down = ["…"]
```

Hooks run through `sh -c` **in the admin tool**, never in the daemon. That is
the explicit trade: the operator asked for a shell; a packet did not.

---

## 3. Packaging

- `packaging/vallum@.service`: a template unit, `ExecStart=/usr/bin/vallum run
  --config /etc/vallum/%i.toml`, with `CAP_NET_ADMIN`, `NoNewPrivileges`, and a
  writable `/run/vallum` only.
- `packaging/vallum.8`, `vallum-quick.8`, `vallum.toml.5`: man pages.
- `packaging/vallum.bash`: completion for both binaries.
- `[package.metadata.deb]`/`[package.metadata.rpm]` in `crates/vallum`: the
  assets a `cargo-deb`/`cargo-rpm` build needs.

---

## 4. The installer

`scripts/install.sh` supports Debian/Ubuntu and Fedora/RHEL:

- installs `nftables`, the binaries, and `/etc/vallum`; a client QR is shown only
  when `qrencode` is already present;
- generates the server key and a config with a control socket and `fwmark`;
- installs and enables the template unit;
- adds a NAT table for the tunnel subnet;
- `--add-client NAME` allocates the next address, appends the peer, runs
  `syncconf`, writes the client config, and prints a QR;
- `--remove-client NAME` removes the peer block and the client files;
- `--uninstall` reverses it;
- `--dry-run` prints every command without running it.

---

## 5. Measured

- `vallum-quick` unit tests: `strip` removes `[quick]` and nothing else; a v6
  prefix is recognised for `ip -6`.
- A dry run against a real config prints `sh -c`, `vallum run`, `ip route add`,
  `ip -6 route add`, and the `resolvconf` heredoc, in order.
- `scripts/install.sh --dry-run` parses and prints; the script passes `bash -n`.

---

## 6. What this does **not** claim

1. **`save` is a new file by default.** In-place requires both `--in-place` and
   `--include-secrets`, and keeps a `.bak`; the export is still not
   byte-for-byte (comments, `[quick]` and unknown keys are not preserved).
2. **No automatic DNS backend choice.** `resolvconf` only; without it, DNS is
   left to the host with a warning.
3. **No firewall management in the daemon.** `vallum-quick`/the installer own
   it.
4. **No Windows/macOS helper.** `vallum-quick` is Unix-shell based.
5. **No package signing or repository hosting.** The metadata is present; the
   release pipeline is not.
