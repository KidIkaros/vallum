# ADR-0013: Server provisioning is a CLI, not a control plane

**Status:** accepted
**Date:** 2026-10-20
**Supersedes:** nothing. Extends ADR-0004 (config) and ADR-0009 (client bundle).

## Context

Vallum's daemon is symmetric: a host with `listen = "0.0.0.0:51820"` and a peer
entry is a server, and a host with a peer that names an endpoint is a client.
The protocol never distinguishes the two.

The *product* did. Until this change, standing up a server meant
`scripts/install.sh` — a bash script that generated a key, wrote a config,
installed a unit, and added a NAT rule — and nothing else. Adding a peer meant
editing TOML by hand and running `syncconf`. Three defects made first install
fail outright: the unit ran `/usr/bin/vallum` while the installer wrote
`/usr/local/bin/vallum` (`203/EXEC`), forwarding was never enabled, and the UDP
port was never opened.

The gap was not cryptographic and not architectural. It was that a VPN needs a
server, and Vallum had no server product.

## Decision

**Provisioning is a first-class CLI surface, and there is no control plane in
core.**

1. `vallum server init` performs the whole host setup: key, config, forwarding,
   firewall, NAT, units, service, verification. Idempotent; `--dry-run` prints
   the plan; every host change has an opt-out.
2. `vallum peer add|list|show|remove` owns peer management. It allocates
   addresses, refuses overlaps, edits the file with `toml_edit` so operator
   comments survive, and applies the change to a running daemon.
3. Client keys default to **client-generated**: `--public-key` enrols a public
   line and the server never holds a private key. `--bundle-out` generates the
   keypair server-side for one-step onboarding, and `--forget-key` deletes the
   server's copy immediately.
4. `vallum import-bundle --install` is the client counterpart: write, install,
   start, verify.
5. `vallum-quick attach|detach` applies routes, DNS, and hooks to an interface a
   supervisor already owns, so a systemd-managed tunnel gets host networking
   without the daemon's sandbox being widened and without `vallum-quick up`
   spawning a second daemon.
6. Every command exposes `--json` and distinguishes exit `2` (precondition, not
   attempted) from exit `3` (partial, retry safe).

## Why not a control plane

A control plane is a different product: an enrolment API, tokens, revocation
semantics, an HTTP surface to secure, and a service to keep running. WireGuard
ships none of it and every commercial deployment builds its own — Tailscale's
coordination server, NetBird's management API, Firezone, Defguard. Adding one to
Vallum's core would make it a managed VPN platform and put an unauthenticated-by-
default network service in the trust path of every tunnel.

The compromise is the machine interface: `--json`, a versioned bundle schema,
and documented exit codes. A third party can build the enrolment service; it
calls the same commands a person does, and Vallum does not have to grow an API to
support it.

## Consequences

- **The server is a product.** Two commands from a clean host to a working VPN,
  with a verification step that names what is wrong.
- **Host networking is automated.** This is a real risk: a tool that edits a
  firewall can lock an operator out. Mitigations are structural — Vallum owns
  only `inet vallum` for NAT, accept rules go into the host's own policy chain
  rather than a shadow table, every step is printed, `--dry-run` exists, and
  each of the three changes can be disabled independently.
- **Two key-custody models ship.** The default is the safer one; the convenient
  one is explicit and prints what it did.
- **`scripts/install.sh` is a bootstrap.** It installs a release, then hands off
  to `vallum server init`. It no longer contains provisioning logic of its own.
- **The QR is not an enrolment channel.** It remains an export format; import is
  from the `.vallum-bundle` file. A mobile client would need an app to scan the
  framed QR, which does not exist.
- **Linux only.** `server init` and `attach` are systemd- and netlink-shaped. A
  non-systemd host gets the config and a printed command instead.

## What this does not claim

1. **No high availability.** One host, one interface, one subnet.
2. **No DNS resolver.** `--dns` pushes a resolver; it does not run one.
3. **No routing protocol.** Site-to-site prefixes are static.
4. **No cloud firewall changes.** Only the host's firewall is touched.
5. **No config-format migration.** The TOML schema refuses unknown keys, so a
   newer config on an older daemon fails loudly.
