# Automating Vallum

Vallum has no control plane and no API that issues configs. What it has is a
command line with a stable machine interface, so a provisioning service can be
built *around* it without patching it. This page is that contract.

## Exit codes

| Code | Meaning | What an automation should do |
|---|---|---|
| `0` | success | continue |
| `1` | the command failed (bad config, write error, refused request) | surface stderr; do not retry blindly |
| `2` | a precondition was not met and nothing was attempted — not root, no systemd, a missing config | fix the environment, then retry |
| `3` | some steps succeeded and one failed; the message names what is already in place | retry is safe; the command is idempotent |

`2` and `3` are the codes that make a play or a script safe: they distinguish
"nothing happened" from "half happened", which is the difference between a retry
and a repair.

## `vallum server init --json`

```json
{
  "config": "/etc/vallum/vallum0.toml",
  "key": "/etc/vallum/server.key",
  "interface": "vallum0",
  "addresses": ["10.7.0.1/24"],
  "listen": "0.0.0.0:51820",
  "endpoint": "203.0.113.5:51820",
  "public_key": "vallum1:0003:…:-",
  "firewall": "ufw",
  "host_steps": ["persist forwarding in /etc/sysctl.d/90-vallum.conf", "…"],
  "service": "installed and started",
  "control": "/run/vallum/vallum0.sock",
  "next": "vallum peer add laptop --config … --ship-key --bundle-out laptop.vallum-bundle"
}
```

`--dry-run --json` returns the same shape with the plan in `host_steps` and
`control: null`, and changes nothing.

## `vallum peer add --json`

```json
{
  "name": "laptop",
  "address": "10.7.0.2/32",
  "allowed_ips": ["10.7.0.2/32"],
  "fingerprint": "f1e20541fb69",
  "endpoint": "203.0.113.5:51820",
  "keepalive": 25,
  "psk": false,
  "bundle": "/etc/vallum/laptop.vallum-bundle",
  "client_config": null,
  "config": "/etc/vallum/vallum0.toml",
  "backup": "/etc/vallum/vallum0.toml.bak.1792522047",
  "applied": true
}
```

- `public_key` is omitted unless `--full` is passed. It is 4.7 KB; a service
  that supplied it already has it.
- `applied` is `false` when no daemon is listening. The config is still written;
  the daemon reads it when it starts.
- `bundle` and `client_config` are `null` unless you asked for one.
- `--shaping balanced` or `--shaping opening` puts that preset's
  `[[peer.shaping]]` blocks into the config this command writes — the bundle, or
  `--client-config-out` ([presets](../shaping.md#presets)). The JSON does not
  repeat it: the returned config already contains the blocks, and a preset name in
  the report would be a second copy that could disagree with them.
- `peer enroll` takes the same `--shaping` flag, for the path where the device
  generated its own key and the server only wrote its config.

`vallum peer list --json` returns the same objects without `bundle`, `backup`,
or `config`. `vallum peer remove --json` returns `{name, allowed_ips, config,
backup, applied}`.

## `vallum metrics`

One scrape is one `get=1`, printed as Prometheus text:

```
vallum_up 1
vallum_peers_total 3
vallum_peers_handshaked 2
vallum_peer_rx_bytes_total{interface="vallum0",peer="laptop",fingerprint="f1e20541fb69"} 1234
vallum_peer_handshake_age_seconds{...} 42
vallum_peer_epoch{...} 3
vallum_peer_handshaked{...} 1
```

`--prefix` renames every metric. There is no listener: a systemd timer writes the
output into `node_exporter`'s textfile directory, or a scraper runs the command
over SSH. A peer that never handshook reports `-1` for its age, not "now".

## `vallum identity` and rotation

`identity issue` / `self-sign` print the document to stdout (or `--output`), and
`--json` returns `{document, label, not_before, not_after, days, suite,
fingerprint, self_signed}`. `identity verify` exits `1` when the document is not
valid, so a play can gate on it.

`peer rotate --json` returns `{name, fingerprint, bundle, config, backup,
applied}`; `peer finalize --json` returns `{name, retired, config, backup,
applied}`. `retired` is `false` when there was no previous identity, which is how
a script knows a finalize was a no-op.

## Idempotency

Every provisioning command converges:

- `server init` never regenerates a key and never rewrites an existing config
  without `--force`.
- `peer add` refuses a duplicate name instead of creating a second entry.
- `peer remove` fails with exit `1` if the name is absent, so a play that expects
  the peer to exist notices.
- `nft` rules are installed by replacing Vallum's own table, so repeated runs do
  not stack rules.

## The bundle schema

`--bundle-out` writes a versioned JSON document:

```json
{
  "version": 1,
  "name": "laptop",
  "config": "[interface]\n…",
  "key": "[key]\nversion = 1\nsuite = 3\nseed = \"…\"\n"
}
```

- `version` is checked on import; an unknown version is refused rather than
  guessed at.
- `config` must name its key as a bare file name — a path is refused, so a
  bundle cannot write outside its target directory.
- The file is written `0600`. It contains a private key.

A service that wants to issue configs can generate this document itself: the
config is plain TOML, the key is the same format `vallum keygen` writes, and the
client imports it with `vallum import-bundle`.

## Building a provisioning service

The shape that works, in order:

1. On the server, `vallum peer add <name> --public-key <line> --json`. This
   allocates the address, enforces the routing rules, writes the config, and
   applies it. Do not edit the TOML yourself: overlap and suite checks live in
   the command.
2. Take `address` from the JSON and render the client's config (or ask for
   `--client-config-out`).
3. Deliver it however you like — your API, your object store, your QR code.
4. To revoke, `vallum peer remove <name> --json`.

The one thing to keep out of the database is a client private key. Use the
public-key model and you never hold one.

## What is deliberately missing

- No HTTP API, no tokens, no enrolment endpoint. A service that wants one owns
  it; Vallum stays a tunnel.
- No config-format versioning beyond the bundle's `version`. The TOML schema is
  additive and refuses unknown keys, so a config written by a newer release
  fails loudly on an older one rather than being half-read.
