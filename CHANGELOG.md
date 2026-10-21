# Changelog

## 1.6.0 — 2026-10-21

Enrolment stops being a side door and takes the shape of the tunnel handshake
(ADR-0015). It is a breaking change to the enrolment wire only; the tunnel
protocol is unchanged.

### Enrolment

- **Two ways to enrol without a bundle.** `vallum setup --remote user@host`
  (the client generates its key, only its public line travels over SSH) and
  `vallum peer invite` → `vallum setup --join host:port` for machines that
  cannot SSH in. Neither ever sends a private key.
- **`peer invite`** mints a single-use token (15 minutes), prints the exact
  client command, the invite id, and the server's fingerprint. `--public-key`
  pins the invite to one device key, so a stolen token enrols nothing.
- **`setup --join --expect <fingerprint>`** refuses a server whose fingerprint
  does not match the invite — the answer is authenticated to the token, so this
  is how a client checks *which* server answered. Nothing is written on a
  mismatch.
- **Enrolment v2 wire** (`VEN2`): cookie gate before any lookup or KEM work,
  opaque invite id instead of the peer name, token-keyed admission tag, and an
  ephemeral KEM leg so the reply key is `KDF(token ‖ ss)` — forward secrecy and
  MEX resistance, as in PQ-WireGuard's Algorithm 2.
- **Enrolment proves the tunnel.** After installing, `setup` waits for a real
  handshake and pings the server's tunnel address, naming the cause when it
  fails instead of reporting success on a dead network.

### Server

- `server init --enroll`, the `setup --server` question, and
  `server enroll --enable|--disable` turn token enrolment on and off together
  with its unit and firewall port.
- `vallum-enroll@.service` hardened: empty capability set, syscall filter,
  `MemoryDenyWriteExecute`, kernel/clock/hostname/cgroup protection.

### Client and keys

- `peer add` no longer generates the device's key by default: it takes a public
  line, or an explicit `--ship-key` that warns and requires a bundle path.
  `import-bundle` says the key it installed was generated on the server.
- `setup --join` reports the tunnel's real endpoint and address, not the
  enrolment port.
- `vallum-quick` installs a full-tunnel default route the way WireGuard does —
  its own table, `not fwmark` rules, `suppress_prefixlength 0` — instead of
  hijacking the main table. Generated client configs carry `fwmark = 51820`.
- The dashboard no longer runs `systemctl` as a normal user (which raised a
  polkit dialog); it hands over the `sudo` command instead, and only treats a
  unit as installed when the config is under `/etc/vallum`.
- `doctor` reports a config the units cannot read (root without
  `CAP_DAC_OVERRIDE` cannot read a `0600` file owned by someone else).

### Security

- `vallum-quick` refuses to run `pre_up`/`post_up` hooks from a config that is
  not root-owned and not group/world-writable, because those hooks are `sh -c`
  as root. `--allow-insecure-config` is the explicit override.
- The enrolment responder logs a legacy-client notice when a `VEN1` client
  tries to enrol, naming the address and the upgrade command — a v1 client
  cannot be answered in a form it understands, so the operator is told instead
  of debugging a silent timeout.

### Fixes

- `install.sh --local` installs and stops, instead of silently preparing the
  host as a server.
- `install.sh --from-release` works with `GH_TOKEN` on a private repository
  (REST asset endpoint, not the web URL).
- A config moved into `/etc/vallum` is chowned to root, so the capability-bound
  units can read it.

## 1.5.0

The release that makes Vallum deployable and explains itself: one command asks
what a machine is, and a server can be brought up and a client enrolled without
editing TOML by hand.

### One entry point

- `vallum setup` asks whether this machine is a server or a client and runs only
  that role's steps — the server path states exactly what it will change on the
  host, then offers to enrol the first client and prints the handoff; the client
  path imports the bundle and says how to run it.
- Bare `vallum` answers "what now?" instead of dumping twenty subcommands.
- The dashboard's first screen is the same question; `1`/`2` copy the command
  for this machine.
- `vallum setup --server` / `--client FILE` are the scriptable forms; without a
  terminal it prints both paths and changes nothing.

### Server provisioning

- `vallum server init` — generates the key, writes the config, enables
  forwarding, opens the UDP port in whichever firewall the host actually uses,
  installs the NAT masquerade for both address families, installs both units and
  starts them. Idempotent, `--dry-run`, and every host change has an opt-out.
- `vallum peer add|list|show|remove` — address allocation, overlap refusal,
  comment-preserving config edits with timestamped backups, live apply to a
  running daemon, and `--json` for automation.
- Client bundles: `peer add --bundle-out`, `vallum import-bundle --install`.
  Device-generated keys stay the default; `--forget-key` deletes the server's
  copy after the bundle is written.
- `vallum-quick attach|detach` manages routes, DNS and hooks for an interface
  another process supervises, with a companion unit that keeps the daemon's
  sandbox intact.

### Identity and rotation

- Identity documents with a signed validity window:
  `vallum identity issue|self-sign|verify|show`, `[interface] identity_issuer`
  (accepts the CA's `vallum1:` line or its signing hex), `[[peer]] identity` and
  `identity_file`. The window is checked at load and at every handshake, so an
  expired credential fails closed while the daemon runs.
- Zero-downtime rotation: `vallum peer rotate` installs a new identity and keeps
  the previous one accepted; `vallum peer finalize` retires it. `doctor` warns
  while a rotation is open.

### Operations

- `vallum metrics` — Prometheus exposition from the control socket, one scrape
  per invocation, no listener. Emits `vallum_up 0` when the daemon is down.
- DNS through systemd-resolved: `resolvectl` with the `~.` routing domain on a
  full tunnel, `resolvconf` otherwise, reverted on detach.
- `doctor --probe-mtu HOST` bisects the real path MTU and compares it with
  `outer_mtu`.
- `pin_endpoint` per peer refuses handshakes from any other address.
- `interface.public_endpoint` remembers the address clients dial, so bundles stop
  falling back to a source-route guess.

### Firewall and host networking fixes

- An installed-but-disabled ufw now gets its rule, so enabling it later does not
  silently break the tunnel.
- iptables `ip filter` chains are inspected: Docker, Tailscale and
  iptables-based ufw all put a `DROP` there, and it was invisible before.
  Accept rules are inserted where the drop lives, and `doctor` reports a
  filtered forwarding path instead of a false pass.

### Terminal interface

- Command palette, configurable keymap, async ping, honest clipboard reporting.
- Half-block QR provisioning with a quiet zone and correct aspect ratio.
- VALLUM brand system, clickable footer and tabs, per-command context in the
  palette.

### Fixed

- The systemd units invoked `/usr/bin/vallum` while the installer wrote
  `/usr/local/bin/vallum`, failing with `203/EXEC` on a first install.
- `vallum peer list | head` panicked on a closed pipe.
- A bare endpoint (`vpn.example.com`) was written without a port and refused by
  the daemon.
- `identity verify --issuer` required the CA's private key; verification now
  needs only its public line.

### Known limitations

- UDP only. No relay, STUN or hole punching, so CGNAT-to-CGNAT needs a public
  endpoint.
- No control plane, SSO or ACL policy in core: the bundle and `--json` contracts
  are the boundary for one.
- Linux only.
- The handshake is fixed-shape and therefore fingerprintable, as WireGuard's is.
