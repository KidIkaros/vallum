# Pre-release dogfood — 2026-10-21

The real binary, the real journey, on a real kernel. Two network namespaces
where a privilege was needed (unprivileged user namespaces grant
`CAP_NET_ADMIN` over a netns we own, so TUN, `ip rule` and a genuine handshake
all work without touching the host), and a PTY for the terminal app.

## How it was driven

| Surface | Method |
|---|---|
| CLI, non-privileged | every verb, exit codes captured **unpiped** |
| Daemon, privileged | two namespaces + veth; `server init` → `run` → `peer add` → control plane |
| Terminal app | 7 headless `--snapshot` views **and** a real PTY/tmux session with keystrokes |
| Error paths | unknown flag, unknown subcommand, missing config, missing file, wrong key type |

## Gaps

| # | Severity | Gap | Status |
|---|---|---|---|
| D1 | **MEDIUM** | The automation contract was violated. `docs/deployment/automation.md` promises exit 2 for "a precondition was not met and nothing was attempted — not root, no systemd, a missing config". `show`, `showconf` and `metrics` returned **1** for a missing control socket, and a missing config file returned 1 from the control-plane verbs but 2 from the `peer` verbs. `metrics` disagreed with itself depending on which half failed. | **Fixed** — `control_path` and the `ConfigError` conversion now report `Precondition`; regression test `crates/vallum/tests/exit_codes.rs` pins the whole matrix. |
| D2 | **MEDIUM** | A peer name longer than 8 characters silently truncated the interface name to 15 bytes (`IFNAMSIZ`). `vpsclient-a` and `vpsclient-b` both become `vallum-vpsclien`, so two configs on one machine would fight over one interface — with no warning at the moment it happened. | **Fixed** — the derivation reports that it shortened the name and says why the result may collide. Regression test `a_long_peer_name_is_shortened_and_reported`. |
| D3 | LOW | `showconf` writes `private_key = "private.key"`, a placeholder, so its own output cannot be fed to `setconf`/`addconf`/`syncconf` — they resolve the key and fail with `read key file private.key: No such file`. The export's header comment says to set it, and `vallum save --include-secrets` writes the real path. | **Documented, not changed.** The failure message does not connect itself to the comment; a future pass could name `vallum save --include-secrets`. |
| D4 | LOW | `q` inside the help overlay dismisses the overlay rather than quitting; `q` from the dashboard quits. Conventional for a modal, but the footer offers no hint that the first `q` is consumed. | Observation. |
| D5 | LOW | `showconf` prints to stdout and has no `--output`; `save` is the file-writing variant. Two verbs, similar purpose, and `showconf --help` does not point at `save`. | Observation. |

## Discharged — investigated and *not* defects

- **`identity self-sign` refused every key** with "is a KEM-only key; generate it
  with `vallum keygen --signing`". That flag exists and works. The message is
  actionable; no drift.
- **`doctor --config` exited 1 with all-visible checks passing.** The exit code
  counts *failures*, not warnings (see `doctor.rs`), and the run had a genuine
  failure: no systemd inside the namespace. Correct behaviour.
- **The TUI filter appeared to drop keystrokes** (`FILTER` rendered as `aply`,
  typed text absent). That was a raw PTY byte stream, which is diff-based. In a
  real terminal the screen reads `FILTER  sky█  (Enter: apply · Esc: cancel ·
  Ctrl-U: clear)`. No defect — the probe was wrong, not the product.
- **`setconf --config` was rejected.** The verb takes `--control`; clap was
  right and the test invocation was wrong.

## The journey, as walked

`--version` · `-V` · keygen (both suites, refusing to overwrite, rejecting an
unknown suite) · pubkey · genpsk · doctor (with and without a daemon) · bench ·
show · showconf · metrics · peer add/list/show/remove · syncconf · addconf ·
setconf · identity self-sign/show/verify · completions (bash/zsh/fish) ·
tui (7 views headless, then interactive) · uninstall --dry-run.

## Gate

`scripts/verify.sh` — **PASS**, 50 test suites. Two regression tests added for
the gaps fixed here.
