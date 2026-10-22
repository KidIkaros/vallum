# Control plane — design analysis

**Subject:** the daemon's control socket and everything whose lifetime is bound to
it: `control::serve`, the runtime directory, the supervision units, the metrics
exporter, and the CLI that reaches them.

**Lens:** Meadows' leverage-point ladder. Findings are ranked by leverage, not by
how loud the symptom is. Every finding below was produced by driving the running
system, not by reading for patterns — the two candidate findings that a pattern
match produced were discharged (see "Discharged").

**State:** tree `b94c9c2`, clean. Daemons and scratch removed after the probes.

---

## The system

**Stocks.** The socket inode at `control`; the private key seed in memory; the
device and peer table on the loop thread; the scrape file the exporter writes;
the `/run/vallum` directory that holds every socket on the machine.

**Flows.** CLI request → `uapi::parse` → `Input::Control` → loop thread →
`uapi::render` → reply. Metrics scrape → same path → textfile → node_exporter.

**Loops.**
- *Balancing, present and wired:* systemd `WatchdogSec=30s` ← `pet_watchdog()`
  on every loop iteration (`run.rs:347`); `Type=notify` ← `ready()`
  (`run.rs:332`) and `stopping()` (`run.rs:487`). All three are called. This is
  the one loop in the subsystem that is complete.
- *Balancing, present but blind:* `VallumDown: vallum_up == 0`.
- *Balancing, absent:* nothing bounds the life of a control connection.
- *Reinforcing, present:* `Restart=on-failure` with `RestartSec=2s` — a loop whose
  gain is high enough to become destructive when the failure is permanent.

**Information flows.** The operator learns the daemon is alive via the watchdog
(data plane) and via `vallum_up` (control plane). Neither tells them the control
plane is *wedged*, because a wedge is not a liveness failure of either.

---

## Findings

| # | Leverage point | Gap | Severity | Effort |
|---|---|---|---|---|
| F1 | LP #5 information flow | The metrics exporter shares the control socket, so a wedge yields a **stale `vallum_up 1`** and `VallumDown` cannot fire | **HIGH** | S |
| F2 | LP #7 balancing loop | No read timeout on a control connection; the accept loop is serial, so one silent client wedges the whole plane | **HIGH** | S |
| F3 | LP #10 structure | `/run/vallum` lifetime bound to one arbitrary participant (the unit) | **HIGH** | M |
| F4 | LP #7 balancing loop | The watchdog pets the data plane only; a wedged control plane is invisible to supervision | MEDIUM | S |
| F5 | LP #10 structure | `serve()` unlinks the path before binding with no liveness check — a second daemon silently orphans the first's plane | MEDIUM | S |
| F6 | LP #4 rules | The key file is hardcoded `server.key`, so a second config in the same directory silently shares the first's private key | MEDIUM | S |
| F7 | LP #11 parameters | `RestartSec=2s` with no `StartLimit*` tuning — the destructive loop's gain | LOW (see note) | S |

### F1 · LP #5 — the monitoring shares the failure mode of the monitored path

- **Where:** `packaging/vallum-alerts.yml:12-13`; `crates/vallum/src/control.rs:141`
  (`request`); the `metrics` command.
- **Probe:** with a holder connected and silent, `vallum metrics --output
  /tmp/scrape.prom` ran for the full 10 s cap and returned nothing. The scrape
  file still held `vallum_up 1` from the previous healthy scrape.
- **Why it matters:** `VallumDown` is the *only* alert that covers the control
  plane, and it is fed by the control plane. node_exporter serves the last
  written textfile, so a hung exporter looks like a healthy daemon. The operator
  finds out last, not first — the opposite of what the alert exists for.
- **Leverage:** highest practical rung. A monitoring path that cannot fail
  independently of its subject is not monitoring.
- **Fix shape:** make the exporter unable to hang — a hard timeout shorter than
  the scrape interval, writing `vallum_up 0` on timeout rather than nothing. The
  alert then fires on the wedge, which is the actual failure.

### F2 · LP #7 — no balancing loop bounds a control connection

- **Where:** `crates/vallum/src/control.rs:100-113`.
- **Probe:** a client that connected and sent nothing blocked `vallum show` for
  the whole 6 s cap (no output); `vallum metrics` for 10 s. Killing the holder
  restored service immediately.
- **Why it matters:** `stream.read_to_string(&mut text)` has no timeout, and the
  `for stream in listener.incoming()` loop is serial — one connection at a time.
  Any same-user process wedges the plane: a paused debugger, an aborted client
  that never closes its write half, a `vallum tui` that died mid-request.
- **Scope note:** the reply path *is* bounded (`recv_timeout(5s)`), and the
  serial design is deliberate — all mutation happens on the loop thread. The
  invariant "one request at a time" is sound; the missing bound is on the
  *request read*, which is outside that invariant.
- **Fix shape:** `set_read_timeout` on the accepted stream, and a total
  connection deadline. Not concurrency — the serial design is correct.

### F3 · LP #10 — a shared resource owned by one participant

- **Where:** `packaging/vallum@.service` (1.6.1, installed): `RuntimeDirectory=vallum`
  + `ReadWritePaths=/run/vallum`; `packaging/vallum-tmpfiles.conf` (1.6.2, unshipped).
- **Probe (from the preceding assessment):** two stale units in `activating
  (auto-restart)` at `226/NAMESPACE`, `NRestarts=259` and climbing, deleted
  `/run/vallum` within two seconds of `mkdir` — twice measured. Every other
  daemon on the machine lost its socket with it.
- **Leverage note:** this is the skill's named fault. A Singleton would make it
  owned by nobody — the defect restated. The fix is an owner that outlives every
  dependant: tmpfiles.d, which 1.6.2 does.
- **Residual:** `ReadWritePaths=/run/vallum` has no `-` prefix, so if tmpfiles has
  not run the unit fails hard; and `postinst` runs tmpfiles with
  `2>/dev/null || true`, so the install reports success either way.

### F4 · LP #7 — the watchdog covers the data plane, not the control plane

- **Where:** `crates/vallum/src/run.rs:347`; `packaging/vallum@.service:12`.
- **Observation:** `pet_watchdog()` fires from the loop thread. A wedged control
  thread leaves the loop running, so the watchdog keeps petting and systemd never
  restarts. Correct for what it watches; silent about the half that is broken.
- **Fix shape:** pet the watchdog only while the control plane is also answering —
  a flag the control thread sets. Cheap, and it converts F2's wedge into a
  restart.

### F5 · LP #10 — unlinking before binding steals a live socket

- **Where:** `crates/vallum/src/control.rs:86-93`.
- **Probe:** daemon A on `ctl.sock`; daemon B started with the same `control`
  path. `show` then reported `vallum_interface=second` — B — while A (pid 565804)
  was still running and serving its tunnel. A is permanently uninspectable; no
  `EADDRINUSE`, no log line, no warning.
- **Why it matters:** stale-socket cleanup is right, but it must probe liveness
  first (connect and expect a refusal) or the cleanup deletes a working plane.
  `EADDRINUSE` is already imported in this file for the uapi errno table.

### F6 · LP #4 — the key name does not follow the config name

- **Where:** `crates/vallum/src/commands/server.rs` (key path derivation).
- **Probe:** in a clean directory, `server init --config alpha.toml --name alpha`
  wrote `private_key = "server.key"`. A second
  `server init --config beta.toml --name beta` in the same directory wrote
  `private_key = "server.key"` again and reported `key ... (existing)` — one key,
  two identities, md5 identical.
- **Why it matters:** `--name` implies a separate identity, and the key silently
  does not follow. Two tunnels sharing a static key is a real weakening, and the
  `(existing)` label reads as reassuring rather than as a collision.
- **Note:** the report does show `(existing)`, so this is not silent at the point
  of creation — it is silent in its consequence.

### F7 · LP #11 — the numbers

- `RestartSec=2s`, `WatchdogSec=30s`, `recv_timeout(5s)`, `DEAD_AFTER=90s`.
- **Deliberately ranked last.** These are where most of the attention goes and
  where the least leverage is. The 2 s restart interval only became destructive
  because F3 left the directory missing on every cycle; fixing F3 makes the
  interval unremarkable. Adding `StartLimitIntervalSec=60`/`StartLimitBurst=3`
  is still worth doing, as a backstop rather than a fix.

---

## Discharged (checked, not findings)

Recorded so the tally is honest and the next audit does not re-derive them.

- **"The CLI collapses three states into two."** Checked, not present.
  `Error::IoPath` renders `{action} \`{path}\`: {source}` — the real errno
  survives to the user (`No such file or directory (os error 2)` for a missing
  socket, exit 1). The skill's worked example of a false signifier does not
  reproduce here.
- **"The watchdog is built but unwired."** Checked, all three call sites exist:
  `ready()` at `run.rs:332`, `pet_watchdog()` at `347`, `stopping()` at `487`.
- **"Serial accept is a concurrency bug."** It is a deliberate invariant — all
  mutation on the loop thread, never concurrent with a packet — and it is
  documented in the module header. F2 is about the missing read bound, not the
  serial design.
- **"Same-user-only is a weakness."** It is the stated trust boundary, equivalent
  to the private-key file, and `0600` is enforced at bind
  (`control.rs:96`). Not a gap.

---

## What holds

- `ready` / `pet_watchdog` / `stopping` — a complete, wired supervision loop.
- Socket permissions set to `0600` at bind, with the reasoning in a comment.
- The socket is removed on clean shutdown (`control.rs:132`).
- Reply path bounded by `recv_timeout(5s)`; parse failures answer `EINVAL` rather
  than dropping the connection.
- All mutation serialised onto the loop thread — no locking, no torn state.
- The CLI reports the true errno, so an operator can tell a missing socket from a
  refused one.
