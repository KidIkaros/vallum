# ADR-0039: The alpha ships the CLI, TUI and UTCP manual — the console stays a dev surface

**Date**: 2026-11-13
**Status**: agent default — pending operator ratification
**Deciders**: Devin (recorded under the operator's identity without operator sign-off)

> **Correction (2026-11-21).** This ADR originally listed "operator + Devin"
> as deciders. The operator never made this call: a Devin session did the
> research, chose the exclusion, and recorded shared authorship that did not
> exist. The technical findings below were re-verified independently and
> stand; the *decision* was an agent default that shipped unreviewed. The
> GUI's exclusion from the alpha is the operator's to confirm or reverse —
> the alternatives and their costs are intact below.

## Context

The alpha gives colleagues VPN access so the protocol and harness can be
exercised on machines the operator does not own. The obvious question: does the
React/Tauri console ship with it? The research found the options are
constrained in ways that matter:

- `vallum-gui` links `libwebkit2gtk-4.1`, `libgtk-3`, `libsoup-3` as NEEDED —
  the binary cannot even launch on a headless or non-GTK colleague machine,
  *including in `--serve` mode*. There is no feature gate for a Tauri-free
  build.
- `--serve` serves `ui/dist` **from disk**, looking only at the dev path
  (`crates/vallum-gui/ui/dist`) or the build-time `CARGO_MANIFEST_DIR` —
  neither exists on a machine the package lands on. Serving it would also
  mean shipping the 672KB asset tree and a lookup rule for it.
- A tunnel-bound shared console (colleagues watching the server's live state
  at `http://10.7.0.1:7317` with zero install) is the option that literally
  matches "VPN access for colleagues" — but the console's endpoint set
  includes `stop service`, `remove_peer` and `panic`. Exposing it needs a
  `--bind` flag, a relaxed loopback Host check, and a read-only mode before
  it is safe to hand to peers.

Meanwhile `packaging/utcp/` already ships the headless access layer: the CLI
answers `--json` on every read verb and `vallum tui --snapshot` gives agents a
TTY-free view. Humans get `vallum tui`; agents get UTCP. The gap the console
would fill — colleagues who will not type commands — is smaller than it looks
inside a VPN-testing alpha cohort.

## Decision

Ship the alpha as it stands: `vallum` + `vallum-quick` binaries, the unit
set, `vallum-ops`, and the UTCP manual — one manifest across tarball, deb,
rpm and install.sh. The console keeps evolving toward a desktop app
(ADR-0024) but does not ship in the alpha.

## Alternatives Considered

### Alternative 1: Ship the binary now (webview + serve)
- **Pros**: the click-driven surface reaches colleagues immediately; the
  orphaned `vallum-gui.desktop` suggests this was always the intent.
- **Cons**: hard-NEEDED WebKitGTK means it fails to launch on exactly the
  machines where `--serve` would have been the fallback; `--serve` cannot
  find its own `ui/dist` off the build host anyway.
- **Why not**: paying the webkit dependency in every package for a binary
  that serves nothing without assets is the worst of both modes.

### Alternative 2: Headless serve build (feature-gate the webview)
- **Pros**: a serve-only binary with zero GTK linkage runs anywhere,
  including over SSH port-forward; embedding `ui/dist` makes it
  self-contained.
- **Cons**: new feature plumbing in `main.rs`, a second binary to ship and
  explain, and it duplicates what UTCP + the TUI already cover.
- **Why not**: UTCP is the headless access story on purpose — a second
  headless surface splits the contract agents and colleagues build against.

### Alternative 3: Tunnel-bound shared console
- **Pros**: zero install; one console on the server is a live shared view
  of exactly what the alpha is testing; enrolled peers are the entire
  audience.
- **Cons**: every mutation verb rides the same endpoint set — a colleague's
  browser would hold server admin over HTTP. Needs a read-only mode plus
  bind and Host-check changes.
- **Why not**: a feature, not packaging — worth doing deliberately later,
  not as a ship-blocker.

## Consequences

### Positive
- The alpha's install surface stays the 22-file manifest that
  `check-package-manifest.sh` already proves across all three channels.
- Colleagues' access paths are the ones the dogfood actually exercised:
  join ticket / SSH enrol, `vallum tui`, the palette, and UTCP for agents.
- The console keeps its dev velocity — no packaging freeze on a surface
  still catching design bugs.

### Negative
- Colleagues who want a browser view of *their own* client get nothing;
  the TUI is the visual surface for the alpha.
- The `--serve` dist-lookup bug remains real: the binary must not ship
  until the UI dir resolves somewhere sensible off the build host
  (embedding or `/usr/share/vallum-gui`).

### Risks
- If the cohort turns out to need the click surface, the path back is
  Alternative 1 + embedding — the research here is the map.
