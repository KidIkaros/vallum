# Changelog

## Unreleased

- **`fuzz.yml` no longer cancels the previous run on `main`.** Its concurrency
  group was `fuzz-<ref>` with `cancel-in-progress: true`, so every push to main
  cancelled the fuzz run for the commit before it — pushing `a8ca825` cancelled
  `ad98a17`'s run, leaving that commit with no fuzz evidence even though the
  workflow had started. `ci.yml` was fixed for exactly this; `fuzz.yml` was not.
  Main now gets a group keyed by run id, which nothing else can join.
- **`--clean-remote` copies the deployment it is about to delete, and refuses if it cannot.**
  `scripts/backup-deployment.sh` takes `/etc/vallum`, `/var/lib/vallum` and the units into a
  `0600` archive and **verifies it** — every config present, every member listed, the desk
  database still beginning with the SQLite header — then prints the restore command.
  `verify-remote.sh` runs it on the host before touching anything, refuses the run when it fails,
  and records the archive path in the stamp and in the signed verdict, so the restore is a command
  rather than a paragraph in a document. `scripts/accept-deployment-backup.sh` is the gate:
  12 assertions covering a byte-for-byte round trip and every failure path (no deployment, a desk
  database that is not SQLite, an unusable destination — and no archive left behind by any of them).
- **A gate skip is now an artefact, not a printed line.** `--skip-remote`,
  `--skip-stale`, `--skip-arm`, `--skip-fuzz` and `--skip-desktop` each write a
  **signed, commit-bound verdict** with `status: skipped` and the reason in a
  new `note` field, plus a row in the tracked `docs/qa/gate-skips.md` (verdicts
  are gitignored and regenerated, so history needs a file git keeps). The
  release log now prints `N gate(s) unproven for this commit` and names them,
  and `release.sh` no longer mistakes a recorded skip for a failed gate. This
  closes the mode where a skipped release and a fully gated one left identical
  state on disk.
- **The desk's account database is copied daily, and the copy is proved.**
  `vallum-desk-backup` + `vallum-desk-backup.timer` ship with the desk and the
  installer enables the timer; the service is conditioned on the database
  existing, so it is inert on a host with no desk. Each run copies the live
  database through SQLite's online-backup API, writes it `0600` to
  `/var/backups/vallum`, **reopens the copy and compares `PRAGMA user_version`
  and the row counts against the source**, and keeps the newest 14. A missing
  source exits 2 rather than "succeeding" with nothing.
  `scripts/accept-desk-restore.sh` is the gate: it builds a database, copies
  it, restores it, checks every row and a known token, and asserts the failure
  paths — it runs in `verify.sh`, `ci-local.sh` and the `ci` workflow, and its
  signed verdict joins the release preflight.
- **`vallum uninstall` no longer deletes the desk's accounts.** It removed
  `/var/lib/vallum` wholesale to clear the `<iface>.quick` routing records, so
  an uninstall also destroyed `desk.sqlite` — every account number, which
  cannot be re-issued — under a message promising that secrets were kept. It
  now removes the routing records only, names the database it kept, and leaves
  it to `--purge` beside `/etc/vallum`. The unit list also gained the five
  units it was missing (cleanup, the dead-man pair, the desk, the desk backup
  timer), which a routine uninstall used to leave installed and enabled.
- **The backup document now covers the desk's database, and a gate keeps it
  that way.** `docs/deployment/backup.md` claimed all durable state lived in
  `/etc/vallum`; 1.8.0 put the account database at
  `/var/lib/vallum/desk.sqlite`, outside every backup instruction, holding the
  one credential the service issues and cannot re-issue. The document names
  both roots, how to copy a live SQLite database safely, how to restore it,
  and how to prove the restored copy is the right one.
  `scripts/check-state-coverage.sh` fails when a durable root appears in
  shipped code but not in that document; it runs in `scripts/verify.sh`, the
  `ci` workflow and `ci-local.sh`. Diagnosis in
  `docs/qa/delivery-topology-2026-11-17.md`.
- **The desk's account database is created 0600.** sqlite3 created
  `/var/lib/vallum/desk.sqlite` 0644 under the default umask, so every account
  token — the only credential the service issues, with no reset flow — was
  readable by any local account on the host, including a CI runner user.
  `open_database` now tightens the mode and a test asserts it. Found by the
  pre-commit review; the file's mode, not the process's, was the gap.

## 1.8.0 — 2026-11-16

- **The desk is a service layer: accounts, devices, plans, vouchers.** Per
  ADR-0045 the schema gains a `peers` relation under a versioned
  forward-only migration (`PRAGMA user_version`); one account number now
  carries up to `--device-cap` (default 5) devices on a shared byte pool.
  Invite codes carry plan payloads (`days`/`bytes`/`plan`); `POST
  /api/voucher` applies an unused code's payload to a live account —
  additive, so the cap grows and consumed bytes stay consumed. Revocation
  splits: `/api/admin/revoke` removes one device, `revoke-account` removes
  them all then marks the account.
- **The account page exists — credentials in POST bodies only.** `GET
  /account` asks for the account number; `POST /account` renders plan,
  expiry, the shared pool, and per-device status with add-device, remove,
  and voucher forms. `POST /api/account` is the same view as JSON;
  `/api/devices/revoke` is the owner-scoped remove. Credential-bearing
  pages send `Cache-Control: no-store` + `X-Robots-Tag: noindex`.
- **`GET /api/status?token=` is retired → 410.** The bearer token rode the
  request line into proxy access logs; it travels POST bodies now
  (`POST /api/status`).
- **`vallum-desk-admin` — the operator CLI.** `mint-code [--days --gib
  --plan]`, `accounts`, `devices`, `codes`, `set-plan`, `revoke
  [--account]`, `adopt`, `sweep`; `--json` for scripts. The admin token is
  read from its file, never argv. Ships in every channel beside the desk;
  `/api/admin/devices` and `/api/admin/codes` are the listings it wraps.
- **`--operator-name` brands the pages** and `service/README.md` is now
  the operator's deploy-and-operate guide.
- **The webpage hands the client a join: `vallum://` deep links.** Every
  ticket-bearing response (`signup`, `devices`) carries a `connect` URI —
  `vallum://join?ticket=<t>&account=<token>` — and the ticket page fires it
  from a Connect button via `window.location`, never an `href` where
  prefetch and Referer would carry the credential. The packaged
  `vallum-uri` handler validates the URI byte-strictly (the
  `vallum1-join:` grammar, 32-hex account) and enrols with the ticket on
  stdin and the account in `VALLUM_ACCOUNT` — no secrets in argv, no
  shell-eval — and `vallum join` seals the account into the config's new
  `[account]` table (which `deny_unknown_fields` makes a schema change:
  older binaries refuse configs that carry it).
- **`vallum-gui` takes over the scheme when installed.** Its desktop entry
  owns `x-scheme-handler/vallum`; a launch URI is parsed at startup and
  surfaces as a confirm dialog (server endpoint, account tail) before the
  console enrols — the token crosses the pkexec boundary as a second stdin
  line through `vallum-ops join`, since env dies at privilege elevation.
  The desk's lock is now reentrant with every `self.db` access under it:
  a raced read on the shared connection could surface `InterfaceError`
  under `ThreadingHTTPServer`.
- **Invites can carry the operator's PSK and shaping.** `vallum peer invite
  --psk [--shaping <preset>]` now records the options in the invite, and the
  enrolment responder applies them exactly as `peer add --psk/--shaping` does:
  the PSK is generated and stored server-side (`clients/<name>.psk`) and sealed
  into the client config, and a named shaping preset is written into the
  client's `[[peer.shaping]]` tables. Old invite files still parse.
- **Release evidence is signed and structured.** `scripts/verdict.sh` signs
  each gate verdict with the release key (`ssh-keygen -Y`), recording the
  producer and a hash of the gate script; `release.sh` refuses a this-commit
  `passed` verdict whose signature does not verify. `verify-remote.sh`'s
  `remote-verified` stamp is now a structured record (commit, remote host,
  assertion count, operator, script hash, timestamp) instead of a bare hash.
- **The seccomp gate has an independent oracle.** `scripts/seccomp-expected.txt`
  is a hand-written x86_64 syscall expectation; `seccomp-trace.sh` now fails if
  the binary's allow-list drifts from it in either direction, in addition to
  the trace-vs-allow-list check.
- **Desk hardening.** `vallum-desk` mints tickets via `peer invite --json`
  instead of scraping human output; the revocation sweep removes the peer
  before marking the account (a failed removal stays active and retries); the
  per-IP signup bound honours `X-Forwarded-For` behind the loopback front.
- **Packaging ships the desk.** `vallum-desk` and `vallum-desk@.service` are
  included in tarballs and found by `install.sh` across all layouts.
- **The desk hands a stranger the client, not just a ticket.** The signup and
  ticket pages on `desk.wingman.gold` now carry the release install command
  and the repo link, the JSON signup payload returns an `install` field, and
  the ticket page spells out `vallum join '<ticket>'` (or `join -` on stdin).
  The revocation sweep also treats "no peer named" as already-removed, so a
  ticket that was minted but never redeemed cannot retry `peer remove`
  forever.
- **The repository is public and hosted CI is green.** `ci.yml` and
  `fuzz.yml` run on `ubuntu-latest` since the flip (first green run:
  `f7771e6`). GitHub's hosted image refuses unprivileged user namespaces
  (AppArmor), so `e2e-netns.sh` uses a plain `unshare -n` when it already
  runs as root, and `accept-pair.sh` falls back to its docker backend when
  namespaces and the sudo escalation both fail.

## 1.7.0 — 2026-11-14

- **New obfuscated & encrypted transport carriers (`ss`, `tls`, `quic`).**
  - `carrier = "ss"`: Shadowsocks-style committing AEAD UDP framing (`[24B nonce || AEAD]`) with optional `[interface] ss_psk`, eliminating plaintext headers and fixed magic bytes on the wire.
  - `carrier = "tls"`: Synchronous TLS 1.3 stream carrier over TCP (`rustls` + `rcgen` ephemeral certs + `[interface] tls_sni`), keeping the daemon's non-async architecture and 79-syscall `seccomp` allow-list intact.
  - `carrier = "quic"`: Sans-I/O QUIC v1 `DATAGRAM` (RFC 9221) carrier over UDP (`quinn-proto`), providing encrypted QUIC framing without TCP head-of-line blocking.
- **2-hop multihop (`[quick] via`).**
  - Exit configs can specify `[quick] via = "<entry-config>"` in `vallum-quick` (`up`/`down`/`attach`/`detach`) to bring up an Entry tunnel first, route the Exit endpoint through Entry, and tear down Exit before Entry (with automatic Entry rollback on failure).
- **Relay selector (`vallum peer select`).**
  - Probes candidate relay endpoints (TCP dial or ICMP RTT) and ranks reachable relays by lowest latency.
- **HTTPS/HTTP API fronting for enrolment.**
  - `[enroll] front_port`, `front_tls`, and `front_sni` add an HTTP/HTTPS `POST /_vallum/enroll` responder sharing the cookie gate, rate limiter, and PQ-sealed `VEN2` reply path; `vallum setup --join --front-url <url> [--front-host <host>]` supports CDN domain fronting.
- **Active leak checker & settings migration.**
  - `vallum-quick leak-check` and periodic TTL=1 non-tunnel probes in `vallum-quick watch` (`/run/vallum/<if>.leak-check`, surfaced in `vallum doctor`).
  - `schema_version` + `vallum_config::migrate_toml` (`v0` → `v1` canonicalizing legacy `failure_policy` aliases and injecting `DEFAULT_FWMARK` for full-tunnel configs).
- **Console parity.**
  - Updated `vallum-gui` Interface editor to support `ss`, `tls`, `quic`, `ss_psk`, `tls_sni`, and `[quick] via`.

## 1.6.5 — 2026-11-13

- **The console's composition root stops implementing its own use cases.**
  `main.rs` held the Tauri commands *and* the bodies they call. `preflight()` and
  `ping()` are host facts, so they moved to `hostfacts.rs` beside `measure`,
  `health`, `plan` and `write_gate`; the commands stay thin in the composition
  root, and both transports (webview and `--serve`) still call one
  implementation. Seven stock shadcn components nothing imported (`badge`,
  `card`, `select`, `separator`, `switch`, `table`, `tooltip`) are deleted —
  including two that the design pass had polished before anyone checked whether
  they had a consumer. The hero's verdict colour became a map instead of a
  four-level nested ternary, and `TrafficBars` went with its last consumer.

- **The console and the TUI stop looking generated and start looking designed.**
  Nine passes across both surfaces, with the product's own direction kept (a
  terminal cockpit, not a SaaS dashboard): no emoji, no gradients, no glows were
  ever there, so what changed is craft and hierarchy.
  - **Type.** The 10px step is gone: 13 body, 12 meta, 11 label, on both
    surfaces. `.micro` is sentence case — caps are reserved for panel titles and
    one-word states — because a label that reads as a sentence ("default route",
    "daemon attached") is read, not scanned. `comfortable` survives for anyone
    who needs it, but it is no longer a header control covering for a bad
    default; it moved to the footer.
  - **Hierarchy.** Traffic was drawn three times (two 40-bar sparklines in the
    hero plus the THROUGHPUT chart). It is drawn once, in the chart, which now
    carries the height the sparklines were stealing; the hero keeps the numbers.
    `TrafficBars` is deleted.
  - **TUI: one brand mark.** `◆ Vallum ❯` prefixed four panels — four headers of
    equal weight, and the width the peer table needed. The brand appears once,
    on TUNNEL CONTROL; the rest are plain section titles.
  - **TUI: columns that say something.** `epoch` and `psk` rendered `0` and `—`
    on every row in the ordinary case; they now appear only when some peer
    actually has one. The traffic line's `Σ … pk …` became `… total`, and the
    shared scale ceiling moved into the panel title, where it is one fact
    instead of two per-series numbers.
  - **Stock components tuned to the vocabulary.** Cards 8px radius with no
    shadow on a dark surface, `transition-all` → `transition-colors`, dialogs
    keep the soft shadow (they float), disabled controls at 60% instead of 50%
    so the word is still legible, scrollbars on the ramp instead of the browser
    default, copy affordances with a hairline so they read as controls.
  - **Contrast, measured, and it failed.** `--muted-foreground` (`#6e7681`) is
    the label colour on every row: 4.12:1 on the page, 3.77:1 on a card, 3.19:1
    on a raised row — under WCAG AA on all three, and it was carrying the labels
    the type pass had just made smaller-but-sentence-case. It is `#8b949e` now
    (6.15 / 5.62 / 4.77) and `--subtext` moved up to `#9aa4b0` so the two roles
    stay distinct. Opacity variants survive only where they are decoration
    (a chevron, a placeholder); the two that carried real text are solid again.
  - **Copy.** `filter by name or address   ( / )` → `Filter`; `START`/`STOP`/
    `INTERFACE` → `Start`/`Stop`/`Interface`; the plan panel lost its doubled
    diamond and gained the space its `undo it all:` line was missing.
  - The GUI's brand line wrote `Vallum )` — a literal paren where the TUI writes
    `❯`. It is the chevron now, which is the product's own signature.

- **The gate is green again on a host that runs Vallum.** `scripts/verify.sh` is
  the gate of record, and on a machine with a live daemon it failed before any
  test: `cargo fmt --check` reported 37 diffs (four files, formatting only) and
  `clippy -D warnings` fired seven lints in `vallum-gui` under clippy 1.97 —
  a dead duplicate of `hostfacts::route_device`, a `filter(..).next_back()`, a
  `map(..).flatten()`, a `Cow::to_owned`, an `and_then(|x| Some(y))`, an
  `unwrap()` in a test, and an **unused `group` binding in `preflight()`**.
  That last one was the real bug: the runtime directory's gid was measured and
  thrown away, so the one fact that explains "cannot tell whether it is in use:
  Permission denied" — a dir whose group is not the drop user's group — was the
  one fact preflight never reported. It is now `runtime_group` in
  `/api/preflight`. All ten steps pass (`fmt`, `clippy --all-features`,
  workspace tests, lean daemon, shell syntax, zstd guard, `cargo deny`,
  standalone clone build, TUI snapshot, release-signature round trip).

- **A scratch server no longer dials the machine's live daemon.**
  `crates/vallum/tests/provisioning.rs` ran `server init` with no `--control`,
  which writes the machine-wide `/run/vallum/<name>.sock`. On a host that runs
  Vallum, `peer add`/`peer invite` therefore talked to the *deployed* daemon:
  three provisioning tests failed with "the request was malformed, or two peers
  claim the same prefix" — the live client daemon refusing a server request —
  and on a server host the same request would have mutated the production
  config. The scratch config now names its own socket, so `peer add` reports
  `applied no — no control socket at …` and the twelve tests pass on a
  deployed machine. No product code changed: `--control` already did the right
  thing; the test was the thing that assumed a global path.

- **The machine says what it needs next.** ADR-0040: one facts-driven guidance
  engine (`vallum::guidance::suggest`) rendered by both consoles — the TUI as a
  footer strip with key/palette hints, the GUI as the NextSteps card with
  buttons. Bare machine, stopped service, silent daemon, open enrolment,
  staged rotation, peerless server, stale handshake and stale checkout each
  produce one actionable suggestion; facts are optional, so a console that
  cannot see a unit says nothing rather than guessing. Both palettes learned
  the full lifecycle vocabulary: join, setup, invite, enrolment close,
  start/stop/restart, enable/disable, sync, update-check — no normal
  operation requires a terminal.
- **The alpha install is proven on a machine that is not the author's.**
  `accept-install` runs the colleague story in a clean systemd container:
  `install.sh` from shipped media, zero author paths in installed artifacts,
  a ticket minted on the production server, `vallum join`, both units active,
  0% ICMP loss across the tunnel — then the server forgets the peer.
- **OS knowledge has one home.** ADR-0041: `host/` is where "which OS is
  this" is allowed to live — `host::probes` owns the systemd/SSH/sync
  questions both consoles used to answer separately (with copies that had
  already drifted into different bugs), `host::paths` owns `/etc/vallum` and
  the `VALLUM_RUN_DIR|VALLUM_RUNTIME_DIR` override. The crate type-checks
  for `aarch64-apple-darwin`; `tun::open` stays honestly `Unsupported`
  off-Linux until hardware verifies it.
- **The fingerprint a human sees is the one `peer show` prints.** GUI, TUI
  and uapi dumps all show the 12-char line-hash; the 16-char uapi hint is
  tooling's, not yours.
- **`vallum-ops` hardening.** An explicit interface name with no config no
  longer falls back to the first config — `service restart typo` cannot hit
  the live tunnel, and `disable` can retire orphan units verbatim. `enable`
  restores the full unit set `disable` strips. `sync --check` reports
  staleness without mutating; the verdict parser picks the `sync`-prefixed
  line, not whatever stderr last emitted.

- **The syscall filter enforces by default.** ADR-0028's plan was two stages:
  derive the list from a trace, ship it in `log` mode, empty the log over a real
  exercise, and only then let the kernel kill. All four are done — the last on
  2026-11-09, when an `auditd` window over the full exercise on both carriers,
  including a live rekey, produced zero would-kill records (with a positive
  control proving the collector would have named a violation). So `interface.seccomp`
  now defaults to `enforce`: a syscall off the allow-list kills the daemon instead
  of being logged and allowed, and the property the project documented as missing
  in three places now holds on a default deployment. `seccomp = "log"` remains
  for debugging — it finds a missing entry without costing the daemon its life,
  and `vallum doctor` reports it as the explicit opt-out it is. A config that
  names no `user` or `group` installs no filter, exactly as before: the filter
  is installed with the privilege drop, and the two are one posture.

## 1.6.4 — 2026-11-05

- **The control socket's name is published only once something listens on it.**
  Publishing reserved the path with a placeholder file and renamed the socket
  over it, so for the width of those two calls the name existed with no listener
  behind it — a client that saw the socket and connected lost its request, which
  is how the gate test found it: the daemon had logged "re-binding", the file
  was there, and the connect was refused. `link` now makes the entry appear
  already listening, because the inode is bound and chmodded in the staging
  directory first, and it refuses an occupied path the way the reservation did —
  a daemon that raced in keeps its socket.

- **The TUI's colours come from the theme, and its ages from one clock.** The
  render path carried 201 literal ratatui colours, so restyling meant editing
  the widgets, and a bare `NO_COLOR=1` still emitted colour escapes from a
  quarter of the frames. Every colour now names a token in `theme.rs`; a test
  fails the build if `ui.rs` reaches for a literal again, and another pins all
  nine views to `Color::Reset` when colour is off. Handshake ages were read from
  the wall clock at the point of formatting, in five places, so one frame could
  straddle a second boundary and a published snapshot could never be reproduced —
  the age is now computed against `App::now`, which `refresh` sets and `--at`
  can state outright.

- **Release artifacts stop carrying the builder's paths.** `strip = "symbols"`
  removes debug info, not the `file!()` literals inside panic and assertion
  messages, so 1.6.3 shipped 288 `/home/…` strings in `vallum` and 43 in
  `vallum-quick`: `strings` on a download named the maintainer's home directory
  and cargo layout. Builds now remap both roots to `/build` and `/cargo`, which
  also makes two builders' string tables comparable, and the release refuses to
  package a binary that still names `$HOME` — a stale `target/` puts the paths
  back even with the environment set.

- **The end-to-end harness asserts the peer table the TUI actually draws.** The
  check looked for the lower-case section title the theme pass had upper-cased,
  so it could not fail for the right reason: it would have stopped the next tag
  on a name, not on a fault. It now asserts the title with its peer count and the
  peer's own row.

## 1.6.3 — 2026-10-29

- **`vallum status` stops calling a dead session `up`.** `up` was decided from
  handshake *presence*, so a host whose server died overnight reported `up` for
  as long as it stayed quiet: the delivery rule underneath it needs 100
  datagrams in the window before it will judge anything, and an idle tunnel
  never sends that many. The verdict now decides from handshake *age* first,
  against the protocol's own `REJECT_AFTER_TIME` (180 s), and the state has its
  own word — `stale`: the daemon answers, the session is dead. It is not
  `blocked` (the process is running) and not `LEAKING` (packets still enter the
  tunnel and are dropped there), so `VallumClientStale` pages on it with the
  grace a real restart does not need.

- **`vallum status` reads the control socket its config names.** It resolved
  `/run/vallum/<iface>.sock` regardless of the `control` the config declared, so
  a daemon listening anywhere else — a scratch root, a second instance, a test
  namespace — was reported `not running`, and the verdict said `down` or
  `blocked` about a tunnel that was carrying. `vallum metrics` already resolved
  it from the config; both surfaces now agree. Found by the outage leg below,
  which failed on its first run because of it.

- **A real link proves the outage, and the recovery from it.** Recovery was
  pinned in-process by protocol tests and in the namespace lab, but never across
  two machines: `verify-remote.sh` stopped the *server* and required the client,
  untouched, to stop lying, stop leaking and come back. It does not use a
  single ping for this — a stream keeps the delivery window full for the whole
  outage, so "idle, nothing to judge" cannot be the explanation for a green
  verdict.

  Measured against `wingman-vps`: 731 datagrams into the dead tunnel, none
  answered, with the route still naming the tunnel (`degraded` within the first
  minute, `stale` past 180 s); **carried again 4 s after the server returned**,
  with the client daemon untouched; zero further handshakes in the next 30 s.
  About four minutes of wall clock, once per run, namespaced mode only
  (`--no-outage` skips it).

- **A finalized key rotation no longer strands the peer.** `peer rotate` moved
  the peer's identity and kept the replaced key accepted until `peer finalize`,
  but left the running daemon's handshake hint on the *replaced* key. While the
  window was open both keys resolved, so the rotation looked correct; `finalize`
  then closed the window and the rotated key resolved to no peer at all, and
  every handshake from it was dropped without a log line or a counter. The
  tunnel carried on over the session it already had and only went quiet at the
  next rekey — and a daemon restarted from the same config worked, which is what
  made it read like a crypto fault instead of a stale index.

  The hint is a projection of the accepted identities, so it is now rebuilt from
  the current one when a rotation is applied. The regression test asserts both
  directions: the new key resolves before and after `finalize`, the retired one
  resolves until the window closes and never after.

- **`install.sh` refuses a downgrade.** The SSH signature over `SHA256SUMS`
  proves who built a release, never when — so a replayed older release,
  signature and checksums intact, installed cleanly over a newer one.
  `install.sh` now compares the target tag against the installed
  `vallum --version` and stops if the target is older; `--allow-downgrade` is
  the deliberate rollback switch.

  The installed binary IS the floor: no state file to forget, corrupt, or point
  at the wrong directory, and nothing an attacker could rewrite without already
  owning the host. `dpkg -i` on a kept package still bypasses it by design.

- **`vallum status` answers "am I leaking?" — including when the daemon is
  dead.** Every report Vallum produced needed the daemon alive, so the one case
  that matters had no answer: the process died, the interface is gone, and
  nobody could tell whether the host was now sending traffic in the clear.
  `vallum status` reads the host instead of the process and names the state:
  `up`, `starting`, `blocked`, `down`, `LEAKING` (exit 1), or `unknown`.

  The distinction it exists to draw is `blocked` versus `LEAKING` — both mean
  "the tunnel is down", only one is safe. `unknown` is deliberately not
  `LEAKING`: `nft list` needs `CAP_NET_ADMIN`, so an unprivileged status cannot
  tell "no table" from "not allowed to look", and reporting the second as the
  first would tell a user their traffic is leaking while it is blocked.

- **Operations documentation.** `docs/operations.md` covers install, upgrade,
  rollback, and the incident path, plus `docs/operations/vallum-alerts.yml` —
  five alerts, each with exactly one threshold derived from a daemon timer
  (rekey 120 s, reject 180 s, watchdog 90 s) rather than picked for looking
  round.

  Two rules in it are load-bearing. **Remove the block before removing the
  daemon**: the guard is deliberately not `PartOf=` the tunnel, so removing
  `vallum@` first leaves the host blocked with nothing to carry traffic. And
  **client leak state is not a metric** — it is a property of the client host,
  so a monitoring system polls `vallum status --json` and reads the exit code.

- **The tunnel fails closed.** Vallum had no egress policy at all: `hostnet.rs`
  built masquerade and a port opening and nothing else, so when the tunnel died
  the host silently reverted to the physical default route and traffic that was
  in the tunnel left outside it. `vallum-guard@<if>.service` now installs an
  nftables table that permits loopback, the tunnel interface, the endpoint that
  carries the handshake, and DHCP — and drops the rest, including any family the
  tunnel has no address in. That last rule is the packet-side half of the IPv6
  leak; the config-side half is that `peer add` no longer claims a family the
  peer has no address in.

  The guard is a separate unit, ordered `Before=` the tunnel and deliberately
  not `PartOf=` it: stopping the tunnel must not remove the block, because that
  is the moment it is needed. `Requires=` means a guard that cannot install —
  no resolvable endpoint, no `nft` — stops the tunnel from starting rather than
  letting it run without the protection it promised.

  `[quick] policy` defaults to `auto`: on for a full tunnel, off for a split
  one. `vallum policy on|off|status --config <path>` is the manual path, and
  `off` is the escape hatch that works with no daemon and no network.

  Verified in a throwaway netns: ICMP to the gateway is reachable before the
  guard and dropped after; UDP to the endpoint port is allowed, UDP to any other
  port is dropped.
- **IPv6 works instead of leaking.** `peer add` wrote
  `allowed_ips = ["0.0.0.0/0", "::/0"]` for every peer while giving it a single
  v4 tunnel address. Claiming `::/0` does not create a v6 route — it asserts that
  v6 belongs to the tunnel, and with no v6 address on the interface the traffic
  fell through to the real default route and left outside the tunnel. That is the
  escape `verify-remote.sh` reports.

  The fix is to carry the family rather than drop the claim. `server init` now
  provisions a v6 tunnel subnet by default (`fd00:7::1/64`, unique-local and
  routed, not NATed), `peer add` allocates **one address per family** from the
  tunnel's own subnets, and the client config puts both on the interface and
  claims both default routes. A `::/0` now has an address and a route behind it.

  A v4-only server still yields a v4-only client config: the claim follows the
  addresses the peer was actually given, so the leak cannot come back through a
  hand-written config either.
- **The outer path MTU is discovered instead of assumed.** `interface.outer_mtu`
  defaulted to 1500, so on a narrower link (PPPoE at 1492, DS-Lite at 1280) every
  datagram exceeded the path, the kernel dropped it rather than fragmenting, and
  the tunnel never came up. The daemon now reads the path from the routing table
  in two places: at startup for peers with a configured endpoint, and before the
  first datagram to any destination it has not measured — which is what covers a
  responder, whose endpoint is learned from the handshake rather than configured.
  A path that narrows under a live destination is caught by `EMSGSIZE`, which now
  asks the kernel and narrows the budget instead of repeating the same drop. The
  budget only ever narrows: one reading is not evidence to raise it.
- **The netns gate can degrade the outer link.** `FAULT=mtu1492|mtu1400|mtu1280`
  or `FAULT=loss<N>|delay<N>|reorder<N>` applies the fault before the tunnel is
  built, so every assertion runs under it. `docs/research/fault-lab.md` records
  the results.

- **`/run/vallum` is a machine resource, not a service's state.** It was created
  by `vallum@.service`'s `RuntimeDirectory`, so stopping the server deleted the
  directory — and with it every other daemon's control socket — and a start
  against a missing directory failed with `226/NAMESPACE`. A tmpfiles.d entry
  now owns it, so any unit can start in any order and no unit's exit can break
  another's control plane. See ADR-0017.
- **Installing the package creates the runtime directory at once.** tmpfiles.d
  only runs it at boot, so a host that installed the package and started a unit
  before rebooting still hit `226/NAMESPACE`, because `ReadWritePaths` needs the
  path to exist. `debian/postinst`, the rpm `%post` and `install.sh` now run
  `systemd-tmpfiles --create` as part of installing.
- **`peer add`, `peer remove` and `peer rotate` no longer claim the daemon is
  not running.** They said so whenever the control socket was absent, which is
  also what happens when the daemon is up and its socket was removed. They now
  report what was observed — `no control socket at <path>` — instead of naming a
  cause they cannot know.
- **A daemon with no control socket says so.** It used to start, log `tunnel up`
  and run unreachable and unmanageable in silence.
- **The socket path has one definition.** It was spelled three ways across 34
  sites; `vallum_config::socket_path` and `RUNTIME_DIR` are now the only ones.
- **`vallum-quick attach` reports progress while it waits.** The twenty-second
  wait for a handshake printed nothing, which is indistinguishable from a hang.
- **`verify-host.sh` no longer destroys a deployment it refused to touch.** The
  cleanup trap was armed before the precondition checks, and cleanup removes
  `/etc/vallum`, the units, the nft table and the sysctl drop-in unconditionally
  — so refusing to run against a live deployment tore that deployment down. The
  trap is now armed only once every read-only check has passed.
- **The gate says what it proved.** It printed "the privileged path works end to
  end" while three traffic assertions were informational, and a client on the
  same host as the server cannot exercise egress at all. Those lines now read
  `NOT VERIFIED`, and the verdict names the gates that do verify traffic.
- **A leftover work directory no longer looks like a product failure.**
  `import-bundle` refuses to overwrite client keys, so a previous `--keep` run
  made the next run fail at that step. The work directory is cleared first.
- **The failure dump captures the routing that matters.** A full tunnel keeps its
  default route in its own table behind a policy rule, so the main table showed
  nothing either way and the dump could not distinguish "no routes" from "routes
  elsewhere". It now prints the namespace's rules and `ip route show table all`.

- **CI has its triggers back, and a tag is judged without becoming a
  release.** The workflows had their triggers off wherever hosted Actions was
  unavailable on the private plan, which made every check in this file a claim
  about a local run. `ci.yml` and `fuzz.yml` fire on every push and pull request
  again, and `release.yml` fires on a `v*` tag to run the preflight only: the
  tag names the `Cargo.toml` version and `scripts/release.sh --dry-run` judges
  the rest, so a tag is held to the same gate as a publish instead of a second
  copy of it. It does not upload, deliberately — publishing needs the signing
  key and the two-host stamp, and `install.sh` only *warns* on an unsigned
  release, so a runner-built tag would install with a warning and look official.

  Proving the jobs could pass at all found two defects: the netns gate could
  never have run in CI, because the job built `vallum` alone and the script
  exits 2 without `vallum-quick`; and the 1.95 clippy leg asked for
  `collapsible_match` rewrites that are not equivalent here — a guarded
  `KeyCode::Left` arm falls through to later arms instead of doing nothing — so
  clippy now runs on stable and the MSRV leg keeps fmt, build and tests.

- **The release publisher builds from a clean checkout, which it never did.**
  `release.sh` runs `E2E=1 scripts/verify.sh` before it builds anything, and
  that gate built only `vallum`; the netns gate refuses to start without
  `vallum-quick`, so a release failed at the script's first line on every fresh
  clone — an incrementally built tree hid it, because the binary was already in
  `target/debug`. The publisher also diffed `packaging/vallum.{bash,zsh,fish}`
  against the release binary two steps *before* `gen-completions.sh` wrote them,
  and those files are gitignored, so a clean tree refused with "no such file".

  Both stay checks, and both now run where the files they read exist. The
  completions check asks for content rather than equality: staleness died when
  the files stopped being committed, and an empty file is what can still ship.
  A full `--no-upload` run in a fresh clone now completes through signing, with
  `SHA256SUMS.sig` verified against the committed key.

- **The dual-stack assertion has two witnesses, and a failure says which one
  disagrees.** The kernel's view (`ip addr`) and the daemon's own (`vallum show
  --control --dump`) must now agree that the peer holds both addresses, so the
  gate cannot pass on a daemon that logged "tunnel up" over an interface that
  lost them in between. The one-in-ten failure this was meant to explain has not
  recurred in sixteen full runs since — each address is ACKed over netlink
  before that line is logged, and a failure there is fatal — so the mechanism
  stays unknown, and what changed is that a recurrence names the losing side
  instead of only the kernel's.

## 1.6.2 — 2026-10-21

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
