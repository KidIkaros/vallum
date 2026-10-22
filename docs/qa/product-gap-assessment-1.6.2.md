# Vallum 1.6.2 — product gap assessment

**Context:** first dogfood of Vallum as a *product* rather than as a codebase,
ahead of the alpha/beta. Tree at `aa5bfcc`, clean, tag `v1.6.2`.

**Method:** a real server was initialised in `/tmp` with `--no-host
--no-service`, a real peer enrolled with `--ship-key --bundle-out`, the bundle
imported on the client side, and the daemon run under root against the control
socket. Every step below is a command that was actually executed, with its real
exit code. Host state was restored afterwards (units stopped, daemon stopped,
`/tmp` scratch removed).

**What this is not:** no egress test (the tunnel had one peer and no second
host), no browser walk, no TUI interaction beyond `--snapshot`.

---

## Confirmed findings

### G1 · HIGH — a failed unit loops forever and deletes the shared runtime directory

- **Where:** installed `/usr/lib/systemd/system/vallum@.service` (package
  **1.6.1-1**), `RuntimeDirectory=vallum` + `ReadWritePaths=/run/vallum`;
  `Restart=on-failure`, `RestartSec=2s`, no `StartLimit*`.
- **Evidence:** `vallum@vallum0.service` and `vallum@owtest0.service` were both
  `activating (auto-restart)` with `status=226/NAMESPACE` and `NRestarts=259`,
  still climbing (257 → 259 in six seconds). While they ran, `sudo mkdir -p
  /run/vallum` was deleted again within two seconds — measured twice.
- **Impact:** each restart tears down `/run/vallum`, so **any other Vallum daemon
  on the machine loses its control socket**, silently. `show`, `metrics`,
  `tui`, `setconf`, `syncconf` all stop working with no connection to the unit
  that caused it. This is a cross-service failure from one stale unit.
- **Why it is not simply a stale host:** the fix exists — `packaging/vallum@.service`
  drops `RuntimeDirectory` and `packaging/vallum-tmpfiles.conf` is wired into
  both deb and rpm via `crates/vallum/Cargo.toml` — but it is **unreleased**.
  Any 1.6.1 host carrying a unit whose config no longer exists reproduces this.
- **Residual risk in 1.6.2, not fixed by the above:** `postinst` runs
  `systemd-tmpfiles --create ... 2>/dev/null || true`, so if that ever fails the
  install still reports success and every unit then 226-loops. And the unit
  binds `ReadWritePaths=/run/vallum` without the `-` prefix, so a missing path is
  a hard start failure rather than an ignored one.
- **Fix plan:** `ReadWritePaths=-/run/vallum`; make `postinst` fail loudly if the
  conf is missing; add `StartLimitIntervalSec=60` / `StartLimitBurst=3` so a
  broken unit stops instead of looping.
- **Verify:** stop the units, `mkdir /run/vallum`, confirm it survives 10 s;
  start a daemon and confirm `/run/vallum/<name>.sock` exists.

### G2 · MEDIUM — the daemon never notices when its control socket disappears

- **Where:** `crates/vallum/src/run.rs:308-309` — `control::serve(...)?` binds once
  at startup and nothing re-checks afterwards.
- **Evidence:** with `/run/vallum/server.sock` present and the daemon healthy,
  `sudo rm -f` the socket and wait five seconds: the daemon stays up, the socket
  does not return, and the log still holds only `starting: ...` and `tunnel up on
  interface server`. Every control command afterwards fails with
  `No such file or directory` (exit 1).
- **Correction to a first reading.** This is *not* a failure to create the
  socket. `control::serve` propagates its error, so a bind failure would end the
  process; the process was alive and healthy, and `metrics` answered `vallum_up 1`
  before the socket was removed. The socket was created and then deleted
  underneath it — which is precisely what the G1 loop does every ~3 seconds.
  Recorded because the first draft of this document claimed the opposite, and the
  difference decides the fix: create-and-fail-loudly versus notice-and-recover.
- **Impact:** a running daemon can become permanently uninspectable without a
  single log line. G1 is the trigger observed here, but `rm`, a tmpfiles cleanup,
  or an admin mistake has the same effect.
- **Fix plan:** when the socket is found missing, re-bind and log once — a
  periodic existence check on the existing tick is enough. Not a new watcher.
- **Verify:** start a daemon, delete the socket, assert it returns within a tick
  and that the log records the loss.

### G3 · MEDIUM — `--no-host` does not do what its one-line summary says

- **Where:** `vallum server init --help`.
- **Evidence:** the flag reads `Do not change anything about the host (implies
  the three --no-* above)`. Running `server init --no-host` as a non-root user
  was refused with `run it as root (or pass --no-host --no-service, ...)` — so it
  does **not** imply `--no-service`. Under `--dry-run --no-host` the plan still
  printed `would install /etc/systemd/system/vallum@.service`,
  `vallum-quick@.service`, `vallum-quick-watch@.service` and
  `would enable --now vallum@server vallum-quick@server vallum-quick-watch@server`.
- **Impact:** the flag's promise is false for the service step, and the dry-run —
  the one place a cautious user looks before letting it touch the host — shows
  host changes they did not ask for.
- **Fix plan:** either make `--no-host` imply `--no-service`, or reword to "do
  not change the network configuration" and make the dry-run honest.
- **Verify:** `server init --no-host --dry-run` prints no `would install`.

### G4 · MEDIUM — every install leaves a `.bak.<timestamp>` in `/etc/systemd/system` forever

- **Evidence:** `ls /etc/systemd/system | grep -c 'vallum.*\.bak\.'` → **18**,
  including eleven `vallum-enroll@.service.bak.*`. Nothing prunes them.
- **Impact:** unbounded growth in a system directory; makes it hard to tell which
  unit is real.
- **Fix plan:** keep the most recent backup, prune older ones on install.
- **Verify:** two installs leave one `.bak`.

### G5 · LOW — key-file flags are named three different ways

- **Evidence:** `keygen --output <FILE>`, `pubkey --private-key <FILE>`,
  `peer add --public-key/--public-key-file`. Guessing `--key` gives
  `error: unexpected argument '--key' found` (exit 2).
- **Impact:** every user guesses wrong once. Cosmetic, but it is the first
  command anyone types.
- **Fix plan:** accept `--key` as an alias on `keygen`/`pubkey`, or rename to one
  convention.

### G6 · LOW — `showconf` drops `control`

- **Evidence:** exporting a running daemon produced a config with no `control`
  key; feeding it back to `doctor` gives `WARN control no control socket
  configured`.
- **Impact:** a config restored from `showconf` cannot be inspected. Possibly
  deliberate (the path is host-specific) but undocumented.
- **Fix plan:** either export it or say why it is omitted.

### G7 · LOW — `syncconf` is silent when it changes nothing

- **Evidence:** `syncconf server.toml --control ...` printed nothing, exit 0.
- **Impact:** fine for scripts, unhelpful interactively — the user cannot tell
  "already in sync" from "did nothing".

### G8 · INFO — `doctor` exits 1 when the only failure is "daemon not running"

- **Evidence:** `FAIL control ... No such file or directory`, `doctor found 1
  failure(s)`, exit 1, on a config whose daemon was deliberately not started
  (`--no-service`).
- **Impact:** defensible, but a first-run user will read it as a broken install.

---

## What held up

Recorded because a gap assessment that only lists faults is not an assessment.

- **Version consistency:** `-V`, `--version`, `Cargo.toml` and the git tag all
  agree at 1.6.2.
- **File permissions:** private key `0600`, config `0600`, client bundle `0600`.
- **Exit codes:** every failure path returned a correct non-zero code with an
  actionable message — `peer remove|show|rotate ghost` → 1, `run|setconf` on a
  missing config → 2 (with `create it with vallum server init`), malformed public
  key → 1 naming the field count.
- **Re-init is idempotent:** a second `server init` without `--force` left the
  config byte-identical (`diff` empty) and the peer intact. It does not say it
  changed nothing, but it does not destroy anything either.
- **Restart persistence:** peer `laptop` survived a stop/start cycle, and the
  socket was removed cleanly on stop.
- **Control plane works when the directory is stable:** `show`, `metrics`
  (`vallum_up 1`), `showconf`, `syncconf`, `bench` (seal 85.2 µs median) all
  behaved.
- **`showconf` round-trips:** the exported config parses and resolves under
  `doctor`.
- **TUI degrades honestly:** with a root-only socket, `tui --snapshot` rendered
  `CONTROL UNAVAILABLE` with `Permission denied (os error 13)` instead of
  pretending.

---

## Execution order

1. **G2** — silent control-plane failure. Small, self-contained, and it is the
   reason G1 is so hard to diagnose from the product side.
2. **G1** — `ReadWritePaths=-/run/vallum`, loud `postinst`, `StartLimit*`. Needs
   a packaging rebuild to verify end to end.
3. **G3** — `--no-host` semantics and the dry-run plan.
4. **G4** — prune stale unit backups.
5. **G5–G7** — flag naming, `showconf` control, `syncconf` output.
6. **Full sweep** — `verify.sh` plus a live journey against the fixed binary,
   including the stop/restart step.

**Rule:** tackle all, no cherry-picking. Each fix gets a test or a live
verification, not a compile.
