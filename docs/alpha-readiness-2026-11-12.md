# Alpha readiness, 2026-11-12

The question: is this product alpha-ready end to end? The answer is only worth
as much as the gates behind it, so this file is the gate list and the evidence,
not a narrative.

**What "alpha" means here, in the operator's words (2026-11-12):** this is *not*
a service. It is an alpha that proves the **protocol** and the **harness** work,
and that the proof is **reproducible by anyone** — not only on the operator's own
devices. The VPS is an instrument for validating that, not a product being
operated for users.

So the bar is: **a machine that is not the operator's can install it, join it,
and be served — and someone else can run the same validation and get the same
answer.** Nothing here is about operating a service for strangers: there are no
users, no SLA, and no front door to defend. Invite minting stays a root command
on the server, which is correct for an instrument.

That reframes the security work as well: admission, bundle policy and the hook
refusal are properties of the protocol's boundary — the things a stranger
*reproducing* the validation would otherwise have to trust on faith.

## Gate 1 — `scripts/verify-remote.sh <host>` (the release gate)

**Status: running.**

The skill is explicit: *"Real validation is `scripts/verify-remote.sh <host>`
from the repo… A pass records the commit in `~/.local/state/vallum/remote-verified`,
which `release.sh` requires. Do not substitute a local container pair for this
gate."*

It refuses a host that already runs Vallum, because it will not delete a live
deployment. This project has exactly one host and it is the live one, so the run
required:

1. `tar czf /root/vallum-backup.tgz /etc/vallum <unit files> /usr/local/sbin/vallum-ops`
   — 8 entries, verified by listing before anything was deleted.
2. `scripts/verify-remote.sh wingman-vps --clean-remote`.
3. Restore the tarball, `daemon-reload`, restart `vallum@` and `vallum-quick@`.

The cost is ~2 minutes of tunnel downtime. The alternative — a throwaway second
VPS — is the right long-term answer and needs a human (a `/wizard` job: card,
DNS, provisioning), so it is recorded as the standing improvement rather than
done under time pressure.

## Gate 2 — Fresh-machine install acceptance (the reproducibility gate)

**Status: running** — `~/.hermes/cache/scratch/gate2-install-acceptance.sh`.

The claim under test: a clean systemd container with its own network namespace
installs from the shipped media, gets a ticket minted on the production server,
joins, and carries traffic — with no dependence on the operator's home directory,
shell, or any file that happens to exist on their machine. The script asserts
that last part explicitly: after installing, it greps the installed tree for
`/home/ikaaros` and fails if anything survives.

A systemd container with its own network namespace, `install.sh --local
--install-only`, a join ticket minted on the server and transferred base64, then
`vallum join`. This is the gate that proves a stranger can install the product,
which is the alpha claim.

Known traps already encoded in the skill, to be applied rather than rediscovered:
the installer expects `/opt/vallum` with `target/release/` beneath it, a
minimal container has no `ping`/`curl` (use `/dev/tcp`), and a failed join
leaves the peer registered so it must be removed before re-inviting.

## Gate 3 — Full tunnel, guard and dead-man

**Status: not run.**

The part that can take the internet away: `fwmark` mandatory for `0.0.0.0/0`,
prove the tunnel carries *before* routing into it, arm the dead-man before the
guard, and verify with the public-IP equality check plus a `curl -6` probe. Any
failure runs the panic path, never a `set -e` exit.

This is the gate that separates "the tunnel works" from "production", because
its failure mode is a host with no internet.

## Gate 5 — The harness at scale (a protocol claim, not a service one)

**Status: not run.** The gap between "a client" and "a protocol that carries a
crowd" — the claim `requirements.md` already makes and nobody has demonstrated
end to end.

- Enrol N devices (10 is enough to catch the arithmetic) and confirm each gets
  its own address, its own peer entry, and its own handshake.
- The server must be able to answer "who is on, and is each one carrying?"
  per device — `vallum show` per peer plus the metrics gauges exist for exactly
  this; nobody has read them with ten peers present.
- The measured ceilings (2,000 peers, 8.9 KB/peer, ~109 s to re-establish a
  full herd, 18.4 handshakes/s) become a demonstrated envelope rather than a
  quoted number.
- **Not** in scope, because this is not a service: invite rate limiting, an
  enrolment audit trail, or anything that defends a public front door.

## Gate 4 — CI

**Status: green except one step, fixed.**

`fuzz` and `advisories` passed on every run. `ci` failed three times, each time
for a reason outside the product:

1. `ui/dist` is a gitignored build artifact that `tauri::generate_context!()`
   embeds at compile time, so a fresh checkout could not compile the workspace
   at all — CI never built the frontend. Fixed by building it in the workflow.
2. `utcp_manual.rs` asserted every documented command exists, including `tui`,
   in the `--no-default-features` leg where that subcommand is not compiled.
3. The deb and rpm omitted `vallum-cleanup.service`, `vallum-deadman@.service`
   and `vallum-deadman@.timer` that `install.sh` installs — **a real packaging
   defect**: a host installed from a package got no cleanup floor and no
   dead-man switch.

## What this file will say when the gates finish

Either the product is alpha-ready with four green gates and a recorded commit, or
it is not, with the failing gate named. Nothing above is a judgement about the
code's quality — that was `docs/review-2026-11-11.md`, on a different axis.
