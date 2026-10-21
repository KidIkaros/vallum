# Changelog

## Unreleased

- **The routes now follow the session.** A new `vallum-quick watch` runs as
  `vallum-quick-watch@.service` and asks the control socket how old the newest
  handshake is. A full tunnel whose peer stops answering has its policy rules
  and default route withdrawn after 90 s, so the host gets its own gateway back
  instead of routing everything into a tunnel with nothing behind it; they are
  restored when a handshake returns (the daemon rekeys at 120 s, so recovery is
  bounded by that). `attach` gated the way in; nothing gated the way out. A
  split tunnel is left alone — a dead `/24` hurts only itself.
- **Host routing teardown removes what was installed.** `vallum-quick` records
  the exact `ip` plan an attach executes under `/var/lib/vallum`, and teardown
  replays it in reverse. Teardown used to re-derive the plan from the config,
  so any edit between attach and detach — a narrowed `allowed_ips`, a cleared
  `fwmark`, a changed `[quick] table` — computed *nothing to remove* and
  stranded the policy rules. One of them, `table main suppress_prefixlength 0`,
  suppresses the main table's default route: the host kept its gateway and lost
  the internet until it was rebooted. Re-attaching now also reverses the
  previous plan first, so `ip rule` duplicates cannot accumulate.
- **`vallum uninstall` tears the routing down too.** It delegates to
  `vallum-quick detach` for every config while the binary is still present,
  instead of removing units, firewall state and binaries while leaving the
  policy rules behind. A recorded plan with no config beside it is named, not
  silently deleted.
- **`--dry-run` no longer writes.** Completing a config's missing `fwmark`
  happened on load, so `vallum-quick attach --dry-run` edited the file it had
  just read — and did so before the ownership check. It is now a separate step
  that runs after the check and only on a real run.
- **`vallum uninstall`**: one manifest-driven removal of everything the
  installer and setup put down — live units, firewall/sysctl state, unit
  files, man pages, completions, `/run/vallum` — keeping `/etc/vallum` (keys)
  unless `--purge`, Debian-style. `install.sh --uninstall` delegates to it;
  the deb ships `prerm`/`postrm` and the rpm `%preun`/`%postun` so
  `apt remove`/`rpm -e` converge on the same teardown.
- **Package-channel parity.** The deb and rpm now ship the full install set
  `install.sh` lays down — metrics units and all three shell completions
  were previously missing — plus `postinst`/`%post` hooks that reload
  systemd and opt the metrics timer in only where node_exporter's textfile
  collector exists. `scripts/check-package-manifest.sh` runs in CI so the
  three manifests cannot drift again.

- **Exit codes follow the documented contract.** `show`, `showconf` and
  `metrics` reported a missing control socket as a failure (1) while `metrics`
  reported the same condition as a precondition (2), and a missing config file
  differed between verb families. `docs/deployment/automation.md` promises 2
  for "nothing was attempted"; every control-plane verb now agrees, and
  `tests/exit_codes.rs` pins the matrix.
- **A shortened interface name says so.** A peer name longer than eight
  characters is truncated to `IFNAMSIZ`, so two peers sharing a prefix became
  one interface with no word to anyone. The derivation now reports the
  shortening, and why the result can collide.
- **DNS is best-effort, and a route already in place is a no-op.** `attach`
  failed outright when no DNS backend worked — `systemd-resolved` installed but
  inactive, `resolvconf` a symlink to `resolvectl` — and threw away a working
  tunnel over a missing convenience. It warns and keeps the tunnel. `ip route
  add` for a route that already points at our own interface no longer fails the
  unit with a raw `RTNETLINK answers: File exists`.
- **A full tunnel is gated on a live handshake, in both directions.** `attach`
  refuses to route one until a peer answers, and `vallum-quick` completes a
  missing `fwmark` on load so a config minted before the mark existed still
  attaches.
- **`install.sh` authenticates without a token first.** It fetches the release
  anonymously and falls back to `gh` only when rate-limited, running `gh` as the
  invoking user rather than as root; `--package` routes deb/rpm through the same
  signature check as the tarball.
- **`verify-remote.sh` documents `--keep`** — the flag that preserves a
  deployment you just proved — and says on exit what it actually kept. In
  scratch mode that is a test daemon still listening on the port, not a
  deployment, which is worth knowing before walking away from a host that does
  something else. Its help also no longer truncates itself with a fixed line
  range.

## 1.6.1 — 2026-10-21

Production readiness: signed and verifiable releases on two architectures, a
complete install→upgrade→monitor→backup→remove lifecycle, a redesigned TUI,
live telemetry, and CI that runs on every push.

### Terminal operations

- **"Boundary & Signal" design system.** A centralized theme with a semantic
  palette and glyph vocabulary, plus TTY-aware CLI styling — `NO_COLOR` and
  `TERM=dumb` degrade to modifiers instead of ANSI noise, and piped/`--json`
  output stays byte-exact plain.
- **Tufte pass.** RX/TX sparklines share one scale so keepalive noise cannot
  fill the bar; the peer detail trades a 40-line hex dump for a
  `vallum1:0003:head…tail` capsule with a proportional transfer bar; the
  footer discloses actions contextually (`f finalize` glows when a rotation
  is open); diffs carry explicit `+`/`-`/`~` glyphs.
- **Full enrolment & rotation parity in the TUI**: `v` mints a one-time v2
  invite with a QR labeled `ONE-TIME ENROLMENT INVITE · ZERO PRIVATE KEYS`;
  `K` rotates a peer's key and `f` finalizes it — without leaving the
  dashboard or dropping the tunnel.

### Telemetry & measurement

- **Live loop counters** (`datagrams`, `packets`, `handshakes
  established/refused`, `reassembled`, `fragments dropped`) ride the run loop
  through `get=1` into `vallum metrics` and the TUI dataplane pane. Daemons
  that predate the fields report absent, never a false zero.
- **`vallum bench` reports a distribution**, not a mean: median, IQR, p95,
  p99, and a 95% confidence interval, sampled in batches.
- **Boundary hardening**: a spent invite is persisted before the responder
  says `ok`; the enrol rate limiter caps its source map at 4096 entries per
  window; config placement writes the private key at 0600 atomically.

### Server lifecycle

- **`vallum server teardown`** reverses `server init` — units, `inet vallum`
  NAT table, firewall/FORWARD rules, sysctl — with `--dry-run` and `--purge`.
- **`vallum peer invites`** lists live unspent invites and TTLs (tokens never
  printed) and prunes expired files; `peer remove` now also revokes an
  unspent invite before enrolment.
- Interactive `vallum setup`, bare `vallum`, and the TUI empty state now lead
  with `--remote` and `--join` — client-owned keys — keeping `.vallum-bundle`
  as the explicit fallback for offline machines.
- **One-ticket enrolment.** `peer invite` prints a single
  `vallum1-join:<host>:<port>/<name>/<id>/<token>/<fp>` ticket (endpoint
  honoring `[enroll].port`, fingerprint baked in) and auto-enables
  `vallum-enroll@` when run as root on a systemd host. The client runs
  `vallum join <ticket>` — one argument instead of four flags — or the same
  ticket via `setup --join`. The flag form still works.
- **Mixed-version enrolment**: a client config whose peer routes `0.0.0.0/0`
  or `::/0` but carries no `[interface] fwmark` (bundles minted before the
  field existed) gains `fwmark = 51820` when the client materializes it —
  `vallum join`, `setup --join/--remote`, and `import-bundle` all normalize.
  The mark is the local machine's routing detail, not a negotiated parameter.
- Dogfood fixes: `setup --join --token -` reads the token from stdin,
  per-peer interface names (`vallum-<peer>`) trim trailing separators at the
  15-byte IFNAMSIZ edge, `systemctl restart` replaces `enable --now` so a
  re-init actually restarts a live daemon, and `peer invite` port opening no
  longer duplicates interface FORWARD rules.
- Fuzz coverage grew an `enroll_parse` target — 35,000 runs found and fixed
  real parser edges.

### Distribution

- **Signed releases.** `scripts/release.sh` signs `SHA256SUMS` with an SSH key
  (`ssh-keygen -Y`); `install.sh --from-release` verifies the signature against
  the key pinned at `packaging/vallum-release.pub` *before* trusting a
  checksum, and refuses a tampered file. Releases before 1.6.1 install with a
  warning; `--require-signature` / `--no-verify-signature` control the policy.
- **aarch64 artifacts.** Cross-built with `cargo zigbuild`; `install.sh` maps
  `aarch64|arm64` to the arm64 tarball.
- **SBOM.** `vallum-<tag>-sbom.spdx.json` (SPDX 2.3) ships with every release.
- **Self-contained source.** `origin-crypto-sdk` is pinned to an exact git tag,
  so a bare `git clone` builds without a sibling checkout; `verify.sh` gates
  it. The sibling-edit workflow survives as a documented `[patch]` override.
- Release binaries are stripped and thin-LTO; zsh and fish completions ship
  alongside bash, and `release.sh` refuses to package stale completions.

### Lifecycle

- **`vallum client teardown (--name NAME | --config FILE)`** — the missing
  outflow for `setup --client/--remote/--join`: stops and disables the
  `vallum@`/`vallum-quick@` units and removes the stale control socket;
  `--purge` also deletes the config and key, `--dry-run` prints the plan.
- **`vallum metrics --output FILE`** writes atomically (temp + rename) so a
  textfile collector never reads a torn scrape, and still writes `up 0` on a
  failed scrape.
- **`vallum@.service` is `Type=notify` with `WatchdogSec=30s`** — the daemon
  sends `READY=1` when the interface serves and `WATCHDOG=1` while the loop
  turns, so a wedged loop is restarted by systemd rather than hanging.
- **`vallum doctor` warns on unsynchronized clocks** — handshake timestamps
  and identity validity windows are wall-clock checks.
- `vallum_interface_info` carries a `version` label for fleet-version
  dashboards.
- **`scripts/verify-remote.sh --upgrade`** installs the previous published
  release, enrols a client, proves traffic, swaps in the new binaries and
  units, and proves the tunnel again — upgrading in place is now a tested,
  gate-stamped path.
- **Shipped monitoring**: `vallum-metrics.service`/`.timer` (enabled only
  when node_exporter's textfile directory exists) and
  `packaging/vallum-alerts.yml` (starting-point Prometheus rules).

### Documentation

- New guides: `docs/deployment/upgrades.md` (in-place upgrade + rollback +
  schema-compat contract), `monitoring.md`, `backup.md` (all state is
  `/etc/vallum`; restoring `server.key` restores the same server identity —
  zero client re-enrolment DR), and `docs/security-model.md` (trust anchors,
  host guarantees, honest non-claims).

### Engineering

- CI runs on `push`/`pull_request` again (the SDK being public and git-pinned
  removed the sibling-checkout machinery); fuzzing smokes on every change and
  runs deep weekly, now including the `enroll_parse` target.
- Pinned privacy invariant: `Resolved`'s `Debug` is tested to never render
  key material — the seed rides `SharedSecret`'s redacting formatter.

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

### Client

- A generated client config names its interface after the peer (`vallum-laptop`,
  at most 15 bytes) instead of `vallum0`, so a machine can be a server and a
  client at once. The control socket follows it.
- `vallum doctor` reports whether the tunnel is *live* — the age of the newest
  handshake, or the three reasons there is none — instead of only checking that
  the parts are configured.

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
