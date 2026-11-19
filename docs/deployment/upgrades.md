# Upgrading Vallum

An upgrade is an in-place binary swap plus a service restart. There is no
state migration to run: all durable state lives in `/etc/vallum`, and every
release reads the config and peer files the previous release wrote.

## The two-host proof

This path is not just documented, it is tested: `scripts/verify-remote.sh
--upgrade <host>` installs the previous published release on a real host,
enrols a client, proves traffic, swaps in the new binaries and unit files,
restarts the service, and proves the same client still tunnels — including
that `peer list` shows the same peers after the upgrade. The release gate
(`scripts/release.sh`) stamps that pass onto the commit it ran against.

## Upgrading a server

```sh
curl -fsSL -o /tmp/vallum-install.sh https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh \
  && sudo bash /tmp/vallum-install.sh --from-release v1.6.1 --install-only
sudo systemctl restart vallum@vallum0 vallum-quick@vallum0
sudo vallum doctor --config /etc/vallum/vallum0.toml
```

`--install-only` puts the new binaries and units in place without touching
your config. The restart picks them up; peers re-key on the next handshake
cycle (up to ~2 minutes for an idle peer, sooner once traffic flows). Check
`vallum metrics` or `vallum show` for fresh handshakes before calling it done.

What the restart changes and what it does not:

- **Changed**: the daemon binary, the unit files (`install.sh` refreshes
  them — e.g. `Type=notify` + `WatchdogSec` landed in v1.6.1).
- **Changed in 1.6.2**: the unit no longer carries `RuntimeDirectory=vallum`.
  `/run/vallum` is created by `/usr/lib/tmpfiles.d/vallum-tmpfiles.conf`, and the
  package's post-install hook runs `systemd-tmpfiles --create` so it exists
  immediately rather than at the next boot. An upgraded host needs nothing done
  by hand; the existing directory is kept. See ADR-0017.
- **Unchanged**: `/etc/vallum/*.toml`, `/etc/vallum/*.key`, peer lists, invite
  files in `/run/vallum` (they are TTL-bounded anyway).
- **Downtime**: one daemon restart per interface — a few seconds where peers
  cannot reach this host. WireGuard-style: there is no connection to keep.

## Upgrading a client

Same shape, on the client:

```sh
sudo bash -s -- --from-release v1.6.1 --install-only < <(curl -fsSL \
  https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh)
sudo systemctl restart vallum@<name>
```

Or from a checkout: `cargo build --release` then
`scripts/install.sh --local`, then restart the unit.

## Compatibility contract

- **Config schema**: `vallum.toml` uses `deny_unknown_fields` — a config with
  fields the running binary does not know fails *loudly* at parse time rather
  than silently ignoring them. New fields only land in minor releases; a
  patch release never changes the schema.
- **Downgrade**: if a newer config will not parse on an older binary, restore
  the previous release's config from your `/etc/vallum` backup, reinstall the
  old release, and restart. The correct recovery is never to hand-edit
  unknown keys out of a production config.
- **Wire protocol**: `PROTOCOL_VERSION` is a byte in every header; mismatched
  versions are refused explicitly (`VersionMismatch`), not mis-parsed.
  Mixed-version peers cannot tunnel — upgrade both ends.
- **Peers**: keys, identities, and open rotations survive upgrades. An
  unfinalized rotation still waits for `vallum peer finalize`.

## Rollback

```sh
sudo bash -s -- --from-release v1.5.0 --install-only < <(curl -fsSL \
  https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh)
sudo systemctl restart vallum@vallum0
```

If the rollback target predates a schema change, restore `/etc/vallum` from
backup first — see [backup.md](backup.md).
