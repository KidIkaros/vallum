# Backup and disaster recovery

All durable Vallum state lives in **one directory**: `/etc/vallum`.

| What | Where | Lose it and you… |
|---|---|---|
| Interface config + peers | `/etc/vallum/<name>.toml` | rebuild peers by re-enrolling |
| Private keys | `/etc/vallum/*.key` | lose the machine's identity |
| Identity documents | inside the configs | re-issue identities |

`/run/vallum` holds only ephemeral state — control sockets and unspent
invites (TTL-bounded). It is recreated by the daemon; never back it up.

## What to back up

```sh
# The whole of it. Configs are 0600/root — keep the backup that way too.
sudo tar -czpf vallum-etc-$(date +%F).tar.gz -C / etc/vallum
```

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
curl -fsSL https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh \
  | sudo bash -s -- --from-release --install-only
sudo tar -xzpf vallum-etc-YYYY-MM-DD.tar.gz -C /
sudo systemctl enable --now vallum@vallum0
sudo vallum doctor --config /etc/vallum/vallum0.toml
```

Contrast with "rebuild and re-enrol everyone": if the key is truly gone (no
backup, or it must be treated as compromised), `vallum server init` mints a
new identity and every client re-enrols — and any pinned `--expect`
fingerprints will correctly refuse the *new* server until the invites are
re-minted. That refusal is the fingerprint mechanism doing its job.

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
  unit, firewall/sysctl state, man pages, completions, `/run/vallum`, and the
  binaries. `/etc/vallum` is kept unless `--purge` (the `apt remove`/`apt
  purge` convention). `scripts/install.sh --uninstall` delegates to it.
