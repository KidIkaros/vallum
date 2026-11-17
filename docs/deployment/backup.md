# Backup and disaster recovery

All durable Vallum state lives in **two directories**: `/etc/vallum` (identity
and configuration) and `/var/lib/vallum` (records a component has to keep across
a reboot).

| What | Where | Lose it and you… |
|---|---|---|
| Interface config + peers | `/etc/vallum/<name>.toml` | rebuild peers by re-enrolling |
| Private keys | `/etc/vallum/*.key` | lose the machine's identity |
| Identity documents | inside the configs | re-issue identities |
| Enrolment desk: accounts, devices, plans, codes | `/var/lib/vallum/desk.sqlite` | **lose every account number.** It is the desk's only credential and there is no reset flow (ADR-0045) |
| `vallum-quick` undo record | `/var/lib/vallum/<iface>.quick` | a teardown after a reboot cannot tell which routes and resolvers to remove; recoverable by hand |

`/run/vallum` holds only ephemeral state — control sockets and unspent
invites (TTL-bounded). It is recreated by the daemon; never back it up.

**The desk's database is the one that is not recoverable.** Everything else in
this table can be rebuilt from a key or re-enrolled from a ticket; the account
rows cannot, because nothing else in the system knows an account number. A desk
started without its database is not an error — it creates an empty one — so a
restore that misses the file looks healthy and has silently dropped every
account. `scripts/check-state-coverage.sh` exists to keep this table honest: a
durable root that appears in shipped code but not here fails the gate.

## What to back up

### The desk's accounts — automatic

`vallum-desk-backup.timer` is enabled by the installer and runs daily. It
takes a **consistent copy of the live database** through SQLite's own
online-backup API (not `cp`, which can capture a torn page from a database the
desk is writing), writes it `0600` to `/var/backups/vallum`, verifies the copy
by reopening it and comparing `PRAGMA user_version` and the row counts against
the source, and keeps the last 14. On a host with no desk the service is
conditioned on `/var/lib/vallum/desk.sqlite` existing, so the timer is inert
rather than failing every night.

```sh
systemctl list-timers vallum-desk-backup.timer   # when the next copy is due
ls -l /var/backups/vallum                        # what has been taken
sudo /usr/local/lib/vallum/vallum-desk-backup    # one now, before an upgrade
```

Point the copies at storage that is not this machine's disk — a mounted
volume, or whatever collects `/var/backups/vallum` — with one file, no unit
edit:

```sh
# /etc/vallum/desk-backup.env
VALLUM_DESK_BACKUP_ARGS=--dest /mnt/offhost/vallum-desk --keep 30
```

A copy on the same disk as the original is not disaster recovery: it survives
a bad migration or a deleted row, not a lost host.

### Everything else — a manual archive

```sh
# Configs are 0600/root — keep the archive that way too.
sudo tar -czpf vallum-etc-$(date +%F).tar.gz -C / etc/vallum
```

The `vallum-quick` undo record is a few KB of text in the same state
directory — it is what lets a teardown after a reboot know which routes and
resolvers to remove, so it belongs in the archive rather than being left out
as an optimisation:

```sh
sudo tar -czpf vallum-state-$(date +%F).tar.gz -C / var/lib/vallum
```

That archive is the one place the desk's database can also be captured by hand;
the timer above is what makes it happen without anyone remembering.

Back it up to somewhere *off the host*, with the same custody you would give
a CA private key: `/etc/vallum` **is** the server. Anyone with `server.key`
can impersonate your endpoint; anyone with a client key can join as that
client.

## Disaster recovery — the property worth knowing

A Vallum server's public identity is derived from `server.key`. Restoring
`/etc/vallum` onto a freshly installed host restores the *same* server
identity — **clients do not need to re-enrol, re-key, or change configs**.
DR is: install Vallum, restore the directory, start the units.

```sh
# On the replacement host
curl -fsSL -o /tmp/vallum-install.sh https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh \
  && sudo bash /tmp/vallum-install.sh -- --from-release --install-only
sudo tar -xzpf vallum-etc-YYYY-MM-DD.tar.gz -C /
sudo systemctl enable --now vallum@vallum0
sudo vallum doctor --config /etc/vallum/vallum0.toml
```

Contrast with "rebuild and re-enrol everyone": if the key is truly gone (no
backup, or it must be treated as compromised), `vallum server init` mints a
new identity and every client re-enrols — and any pinned `--expect`
fingerprints will correctly refuse the *new* server until the invites are
re-minted. That refusal is the fingerprint mechanism doing its job.

### Restoring the desk

The desk is a client of the daemon, so restoring it is independent of the
tunnel: a host can carry traffic with no desk at all.

```sh
sudo systemctl stop 'vallum-desk@*'
sudo install -o root -g root -m 0600 /root/desk-YYYY-MM-DD.sqlite \
    /var/lib/vallum/desk.sqlite
sudo systemctl start 'vallum-desk@*'
```

Then **prove the copy is the right one before trusting it** — the failure mode
is a desk that starts happily on an empty database. `scripts/accept-desk-restore.sh`
is the same proof run as a gate (it builds a database, copies it, restores it,
and checks every row and the schema version); on a live host do the short
version:

```sh
sudo sqlite3 /var/lib/vallum/desk.sqlite \
    'PRAGMA user_version; SELECT count(*) FROM accounts; SELECT count(*) FROM peers;'
sudo vallum-desk-admin accounts        # the operator's own view, token from its file
```

A copy taken by `vallum-desk-backup` carries the same check in its own output:
every run prints the version and row counts it verified against the source, so
the timer's journal is a record of copies that were opened, not merely written.

A `user_version` lower than the binary's means the backup predates a migration
(the desk migrates forward on open); higher means the backup came from a newer
release and this binary will refuse to open it — restore the matching release
first, as with the config schema below.

## Client machines

Clients are cheaper: `/etc/vallum/<name>.toml` + `<name>.key` is the whole
state, and a destroyed client re-enrols in one command (`setup --remote` or a
fresh invite). Back up client keys only if re-enrolment is expensive for you.

## Uninstall / teardown

Removing Vallum cleanly is part of lifecycle hygiene:

- Server: `sudo vallum server teardown [--config /etc/vallum/vallum0.toml]`
  (`--purge` also removes configs+keys; `--dry-run` prints the plan first).
- Client: `sudo vallum client teardown --name <name>` (same flags).
- The whole install: `sudo vallum uninstall [--dry-run] [--purge]` — every
  unit, the tmpfiles entry, firewall/sysctl state, man pages, completions, and
  the binaries. `/etc/vallum` is kept unless `--purge` (the `apt remove`/`apt
  purge` convention). `/run/vallum` is deliberately left in place: it is shared
  by every daemon on the machine, another daemon's socket may be in it, and it
  disappears with the rest of `/run` at the next boot. `scripts/install.sh
  --uninstall` delegates to it.
