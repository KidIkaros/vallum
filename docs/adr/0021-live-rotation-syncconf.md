# 21. A live `set` names the rotation window, not a replacement peer

**Status:** implemented · **Date:** 2026-10-23 · **Found by:** applying `peer rotate` to a running daemon

## Context

`peer rotate` rewrites the config atomically: the new key becomes `public_key`
and the old one is retained as `previous_public_key` until `peer finalize`
retires it (ADR-0014's rotation window). The daemon, however, learned nothing:
the control-plane `set` built a *new* peer with the new key on the anonymous
name and session state it manufactures when the row it addresses does not
exist, leaving the old row orphaned on the running daemon.

Three bad things followed:

1. **The window never opened against the running daemon.** The new key was
   live on the wire but the replaced identity stopped being accepted the
   moment the config said it was no longer `public_key` — plus the daemon
   *still* owned the old row. In-flight traffic on the old identity died at
   once, instead of rolling over (ADR-0019 means a `Rotate` must travel on
   the *accepted*, not the installed, key).
2. **The anonymous row survived syncconf.** The diff in
   `commands/control.rs` saw `public_key` change and sent no `remove=1` for
   the old key. The old row lived on with its old key, its session, and —
   critically — its own name and per-peer metrics. The new key sat beside it
   under a generated name, so traffic was attributed to two peers where
   before there had been one.
3. **Restart-replay diverged.** A daemon restarted while the window was open
   applied the config and came up with one row carrying the window — a state
   no live apply had ever produced on the same config.

## Decision

The rotation window is carried through `set` as a *field on the row it
configures*, in the direction the config always states it:

```
set=1
public_key=<new key>
vallum_previous_public_key=<old key>   # the identity the row rotates from
...
```

`vallum_previous_public_key=(none)` retires the window (`peer finalize`);
a size-mismatched value is refused `EINVAL` before the device is touched.

The diff in `commands/control.rs` computes rotation three ways:

* **No remove/new row** — the set refers to either key of the window, and the
  row answers both until finalize.
* **Previous carried** — the running daemon publishes its window on `get`
  (`peer_lines` includes the retained key), so the full state the apply
  command reads back mirrors what a cold start would see.
* **Previous compared** — the set itself names the replaced key. The rows
  differ only in `public_key` and previous, so the usual structural diff
  detects the rotate, without a special case keyed on the identity types.

The device-side apply (`control.rs::apply_peer`) is a no-op when the daemon
already runs that row, so a re-sent syncconf — and the restart replay both —
arrive at the same end state with no churn on live sessions.

## Limitations

* **KEM-only scope.** The window travels as a bare KEM key, so a rotation of
  a *signed* peer installs its new identity unauthenticated from the control
  plane's point of view. That is bounded by the config itself, which owns the
  decision: the signing side (the identity the config has already validated
  a full, signed public line for) is the one `peer rotate` rewrites to.
  `peer enroll --doc` stays the path for a full signed public line.
* **PSK / endpoint / allowed-ips unchanged.** A rotation never re-opens a
  window set from a peer whose window already closed — the config's field is
  authoritative, as it is for a cold start.

## Alternatives Considered

* **A `remove=1` then `add` pair.** Cheap to express with today's fields, but
  it tears down the old row *first*: the live session, its per-peer metrics
  history, and the name all leave, and every packet the old identity sends
  in the window is refused. The rollover ADR-0019 describes becomes a
  connectivity break. Rejected.
* **A dedicated `rotate=1` verb.** Adds a second wire surface to keep in
  step with both the config parser and the device, at no gain: the row
  addressed by `public_key` is the same row a rotation addresses. Fields on
  the row, not verbs on the set, is how `public_key` already works.
  Rejected.
* **Name the window on *every* peer set (no diff awareness).** Far too chatty
  for the `keepalive`-only updates `syncconf_running` already sends, and it
  would make the window a session-survivable invariant the device has to
  police instead of the config's.

## Verification

* Device side (`control.rs`): `a_rotation_apply_swaps_the_identity_and_opens_a_window`,
  `re_applying_a_rotation_leaves_the_row_unchanged`,
  `a_finalize_apply_closes_the_window`,
  `a_rotation_update_can_arrive_at_a_cold_daemon`.
* Control-plane diff (`commands/control.rs`):
  `a_peer_lines_statement_names_the_window` (get reports the retained key),
  `a_window_the_config_closed_or_opened_is_seen_by_the_diff` (a running rotated
  peer diffs to a rotation set with `vallum_previous_public_key`, not a
  replacement row; finalize diffs to `(none)`).
* `uapi.rs` round-trip: `render_get` emits the window, `render_config`
  carries it, `parse` accepts `(none)`.
* Live gate (`scripts/verify-remote.sh --clean-remote wingman-vps`, 2026-10-23):
  the bundle transport rotates a live peer over the network and the measured
  assertions are egress continuity — `tunnel survives rotation across the
  network` pings through an established session after `peer rotate`, then
  `peer finalize` retires the old identity without further loss. With this
  change the server-side application is no longer a remove+add: the fingerprint
  change is accepted as the same row and `vallum_previous_public_key` travels
  in the diff (debugged on a real daemon after the first gate run turned the
  rotation leg into an egress failure on every attempt, taken live from the
  running pair's logs; a stale `target/release/vallum` was the reason an
  earlier "fixed" gate run still failed, which is why the note lands on a
  recorded commit `8e118c2`).
