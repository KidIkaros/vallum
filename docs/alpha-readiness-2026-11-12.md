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

**Status: PASS** — `scripts/accept-install.sh`, run from the repo, on a clean
container that is not the operator's machine.

Evidence, verbatim from the run:

```
installed: vallum 1.6.4 (linux-only, experimental-pq)
author path: none
ticket minted for accept1 (127 bytes)
   ok    handshake with the server
   ok    ping 10.7.0.1 (2/2)
units after join: active active
3 packets transmitted, 3 received, 0% packet loss
rtt min/avg/max/mdev = 75.740/77.299/78.545/1.166 ms
peer accept1  endpoint=198.51.100.7:44820  last_handshake_time_sec=…
```

The claim under test was reproducibility, so the script asserts the part that
usually breaks it: after installing, it scans the installed tree for any
`/home/<user>/` path and fails if one survives. Nothing in the install depends on
the author's home directory, shell or files.

The script lives in `scripts/` rather than in the operator's scratch space for
the same reason — a test only its author can run does not prove anything about
reproducibility. Everything machine-specific (host, peer name, config path) is an
environment override.

Three failures on the way were all in the harness, and each is now a pitfall in
the `vallum-operations` skill: the container's cgroup volume spec
(`-v /sys/fs/cgroup:rw` is rejected; source:dest plus `--cgroupns=host`),
a ticket grep whose character class excluded `:` so it matched the *usage
string* and produced a 27-byte "ticket", and a `/dev/tcp` probe aimed at **UDP**
port 51820, which can only fail and looks exactly like a dead tunnel.

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
