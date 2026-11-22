# ADR-0050: The cockpit ships in the alpha tarball

**Date**: 2026-11-21
**Status**: accepted
**Deciders**: operator (Ikaaros)

Supersedes [ADR-0039](0039-alpha-distribution-surface.md).

## Context

ADR-0039 excluded `vallum-gui` from the alpha on real grounds: the binary
hard-links WebKitGTK/GTK/soup so it cannot launch on headless machines even
in `--serve` mode, `--serve` reads `ui/dist` only from the dev build path,
and the mutation-bearing endpoint set made a shared tunnel console unsafe.
That decision was made by an agent session and recorded under the operator's
identity without operator sign-off — corrected in place on this date.

Asked directly, the operator decided the other way: **the GUI is the click
surface.** An alpha for colleagues who should not need a terminal has to
ship it.

## Decision

The cockpit ships in the alpha, packaged by channel:

- **The tarball carries it.** `vallum-gui` (UI embedded at build time by the
  tauri `frontendDist` mechanism — the `--serve` dist-lookup bug does not
  reach the desktop mode), `vallum-gui.desktop`, and its icon go flat into
  the release manifest, and `install.sh` lands all three. A missing
  libwebkit2gtk-4.1 is a named install-time warning, not a failure — the
  CLI halves do not care, and the binary simply never launches headless.
- **Scheme ownership prefers the GUI.** Both `vallum-gui.desktop` and
  `vallum-uri.desktop` claim `x-scheme-handler/vallum`. When the GUI is
  installed it registers as the handler — its in-app confirm is the
  product surface. `vallum-uri` remains the headless fallback on machines
  where the GUI cannot run.
- **The base deb/rpm stay headless.** The cockpit does not ride inside the
  `vallum` package — a server install must not pull WebKitGTK as a
  dependency. Desktop users on deb/rpm get it as a separate Tauri-built
  package; `check-package-manifest` excludes `vallum-gui.desktop` from the
  parity lists for exactly this reason.
- **`--serve` stays dev-host-only** for this release: its dist lookup still
  reads the build tree. A system-path lookup plus a shipped
  `/usr/share/vallum-gui` asset dir is the follow-up if browser-mode
  serving matters for the cohort.

## Consequences

### Positive

- Colleagues get the enrolment *and* the post-join surface without a
  terminal: Connect link → in-app confirm → cockpit view of the tunnel.
- The manifest gate still proves one file set across deb/rpm/install.sh;
  the GUI's two packaging files are excluded with the reason in the gate.

### Negative

- Every tarball carries a ~10 MB WebKitGTK-linked binary headless hosts
  will never run. Accepted: the tarball is the desktop channel; servers
  use the deb/rpm.
- Two registered `vallum://` handlers can exist on one machine; the
  installer's preference rule keeps the answer deterministic (GUI wins).

### Risks

- Colleagues on non-GTK desktops (minimal WMs, WSL, headless) get the CLI
  flow anyway — `vallum-uri` handles their Connect links. No cohort member
  is left without a path.
