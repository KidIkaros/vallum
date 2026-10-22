# Control plane — improvement plan

Sequenced by leverage, not by severity: the first phase buys the most resilience
per line changed. Each phase is shippable on its own and each has a behavioural
check, because a compile proves nothing about a control plane.

**Alpha-blocking set: Phase 0.** Both items are small, both are missing
balancing loops, and together they turn "wedges silently and nobody finds out"
into "reports itself and recovers".

---

## Phase 0 — bound the connection, unshare the monitor  (F1, F2)

The two highest-leverage changes and the two cheapest.

1. **`control.rs` — read timeout.** `set_read_timeout` on the accepted stream
   before `read_to_string`, plus a total connection deadline. The serial accept
   loop stays exactly as it is; only the unbounded wait goes.
2. **`metrics` — hard timeout, and say so.** The exporter must finish inside the
   scrape interval. On timeout it writes `vallum_up 0` instead of writing
   nothing, so `VallumDown` fires on the wedge.
3. **Alert copy.** `VallumDown` currently reads as "the daemon is down". It now
   also means "the control plane is wedged". Say so in the annotation, so the
   operator's first move is `vallum show`, not `systemctl restart`.

**Verify (behavioural, both):**
- Connect with `python3 -c "socket.connect(path); sleep(30)"`, then
  `vallum show` → must answer within the timeout, not hang.
- Same holder, then `vallum metrics --output f` → must write `vallum_up 0`
  within the deadline and leave the file updated, not stale.

**Why before anything else:** F1 is the difference between the operator finding
out and not. Every other fix is easier to land once the failure is visible.

---

## Phase 1 — let supervision see the control plane  (F4)

4. **`run.rs` — gate the pet on control health.** The control thread sets a flag
   each time it completes a request; the loop pets the watchdog only when the
   flag is fresh. A wedged plane then stops petting, systemd's `WatchdogSec=30s`
   fires, and the restart is the recovery.

**Verify:** wedge the plane, leave it wedged, and confirm systemd restarts the
service inside `WatchdogSec`. This is the one check that needs a real unit, so it
runs after Phase 3 has a package to install.

**Interaction:** with Phase 0 in place this is a backstop rather than the primary
defence. Both are worth having — Phase 0 bounds the damage, Phase 1 recovers from
it.

---

## Phase 2 — stop stealing live sockets, and name the key after the config  (F5, F6)

5. **`control.rs` — liveness before unlink.** Before `remove_file`, connect to the
   path: a successful connect means a live daemon owns it, so refuse with
   `EADDRINUSE` (already in the errno table) instead of unlinking. Only a refused
   connect justifies the cleanup.
6. **`server.rs` — key path follows the config.** `--config beta.toml` should mean
   `beta.key`, not `server.key`. Reusing an existing key must be an explicit
   choice, and the report should say "reusing the key at <path>" rather than
   `(existing)`.

**Verify:**
- Two daemons, same `control` path → the second exits with `EADDRINUSE` and the
  first still answers `show`.
- Two `server init` runs in one directory → two distinct key files, different
  md5s, and the second says which key it created.

---

## Phase 3 — give the directory an owner that outlives its users  (F3)

7. `ReadWritePaths=-/run/vallum` so a missing path is tolerated rather than a hard
   `226/NAMESPACE`.
8. `postinst`: drop `2>/dev/null || true` around `systemd-tmpfiles --create` and
   fail the install if the conf is absent. A silent success here is what turns a
   packaging mistake into a restart loop.
9. `StartLimitIntervalSec=60` / `StartLimitBurst=3` on the unit, as a backstop.

**Verify:** uninstall the tmpfiles conf deliberately, install the package, and
confirm the install *fails loudly* rather than producing a host whose units
crash-loop. Then restore and confirm a fresh boot has `/run/vallum` before any
unit starts.

**Note:** this needs a package rebuild, so it is the only phase that cannot be
proven with the working tree alone.

---

## Phase 4 — the numbers, last  (F7)

10. Revisit `RestartSec` only after Phase 3. With the directory owned properly,
    the 2 s interval stops being destructive and the default is fine.

**Why last:** parameter tuning is the lowest-leverage rung and the one that
attracts the most attention. Changing it before Phase 3 would mask the loop
rather than fix it.

---

## Not proposed

- **Concurrent request handling.** The serial design is a correctness invariant —
  all mutation on the loop thread — and Phase 0 makes it safe. Adding a worker
  pool would trade a solved problem for a new class of race.
- **Socket authentication.** `0600` same-user is the stated trust boundary,
  equivalent to the private-key file. Not a gap, and not worth weakening the
  story by adding a token.
- **A new watcher for socket disappearance.** Phase 1 already routes that signal
  through systemd, which is the component whose job it is.
