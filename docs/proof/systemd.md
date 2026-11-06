# systemd / `vallum-quick` host test

**Status:** manual root-required test; not part of the normal local gate.

`scripts/systemd-host-test.sh` exercises the privileged paths that unit tests
cannot reach:

- a transient `vallum@vallum0.service` started with `systemd-run`;
- `systemctl is-active`, `vallum show --control`, and `systemctl stop`;
- a `vallum-quick up`/`down` fallback with `table = "off"`.

It creates a temporary `/tmp/vallum-systemd-test.*` directory, a
`vallum-sys0` interface, and a `vallum-quick0` interface; the cleanup trap
removes all three. Run it after `cargo build`:

```sh
sudo VALLUM=./target/debug/vallum VALLUM_QUICK=./target/debug/vallum-quick \
  ./scripts/systemd-host-test.sh
```

This still does not prove interactive polkit behavior: polkit prompts depend
on the desktop session and the caller's privileges. The script verifies that
`systemctl`/`systemd-run`/`vallum-quick` can actually start, query, and stop
the daemon when the caller is already root.
