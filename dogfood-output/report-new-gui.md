# Dogfood report — Vallum console (new GUI)

**Build under test:** `6a62f6d`, `target/debug/vallum-gui` rebuilt and served fresh on `127.0.0.1:7317` (all stale consoles from earlier sessions killed first). Token-authenticated URL used.
**Scope:** new "Boundary Geometry" console UI — landing, navigation, topology, actions. DX/UX focus.
**Date:** 2026-11-13

## Executive summary

The new console loads cleanly: **zero console errors**, no unhandled rejections, full layout renders. Structure is legible — nav (OVERVIEW / DEVICES / MONITORING / SETTINGS), a three-stage topology (local node → egress lanes → peer mesh), and per-section actions. One UX gap and two carried-over unknowns below.

| # | Severity | Category | Issue |
|---|---|---|---|
| 1 | Low | UX | "Stop service" is an unlabelled destructive action in the header, adjacent to navigation |
| 2 | — | — | Carried over: PING result and CONFIG dialog were swallowed in the *old* build (Tauri/HTTP seam). **Not retested on this build** |

## Issue 1 — "Stop service" is a bare destructive control in the header

**Severity:** Low · **Category:** UX
**URL:** `http://127.0.0.1:7317/`

**Expected:** a destructive action (stops the tunnel, drops the user's connectivity) is visually separated and/or confirmed.
**Actual:** "Stop service" sits in the header beside the interface chip, same weight as navigation controls, no confirmation step observed.

**Why it matters for DX:** a dev exploring the console clicks around; stopping the service from a mis-click is a self-inflicted outage with no undo in the UI.

## Testing notes

- **Tested:** load, auth exchange, nav render, topology render, console-error capture across 3 s of polling.
- **Not tested (deliberately):** Stop service, Remove peer, Apply/Full-tunnel — live tunnel, not worth the outage. PING/CONFIG not retested on this build (the earlier finding was against the old dist).
- **Not tested (budget):** keyboard navigation, every panel, form validation.

## Evidence

- `screenshots/10-new-gui-landing.png`
