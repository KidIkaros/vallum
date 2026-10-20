# Changelog

## 0.2.0

The release that makes Vallum deployable: a server can be brought up and a
client enrolled without editing TOML by hand.

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
