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

**Status: PASS** — `scripts/accept-full-tunnel.sh`, inside a container with its
own network namespace, so the default route that moves and the nftables block
that lands belong to the container and never to the host.

```
route: 1.1.1.1 dev vallum-full01 table 51820 src 10.7.0.3
ping 1.1.1.1: yes
resolve example.com: yes
public IP: 203.0.113.10   (server is 203.0.113.10)
IPv6 egress: blocked
vallum@full01 / vallum-guard@full01 / vallum-quick@full01 — all active
dead-man timer: active, armed before the guard
```

The public-IP equality is the assertion that matters: it catches a split route, an
IPv6 escape and a DNS leak in one measurement, and it can only hold if the whole
path is right.

### Four failures on the way, none of them in the routing or tunnel code

1. **`no config at /etc/vallum/vallum-full01.toml`** — the unit instance is the
   config stem (`full01`), the kernel interface is `vallum-full01` because a join
   prefixes `vallum-`. The harness conflated them and asked systemd for an
   instance with no config.
2. **The server had no masquerade table.** `hostnet.rs` plans it and `server init`
   installs it; this deployment had none, so forwarded packets left with a
   private source and no reply could return.
3. **`verify-remote.sh` deleted that table.** The release gate runs
   `nft delete table inet vallum` on cleanup — on a live host that is the
   masquerade rule every full-tunnel client depends on, and a `/etc/vallum`
   tarball cannot restore nftables state. Fixed: the script now saves the table
   before the clean path and restores it on exit.
4. **The server refused to forward.** `Default: deny (routed)`, an empty
   `ufw-user-forward` chain, and no `-i vallum0 -j ACCEPT` rules — so packets
   arrived from the tunnel and went no further, while `ip_forward` read `1` and
   every sysctl-based check would have called it healthy.

### The finding, corrected

My first write-up of this gate said *"the product asks whether forwarding is
enabled, never whether it works"*. **That was wrong**, and it is worth recording
because the correction is the actual lesson.

`doctor` already checks it. With the FORWARD rules removed it says:

```
WARN  forwarding  IP forwarding is on, but iptables filters forwarded traffic
      (Docker, Tailscale, or another manager); run `vallum server init --force`,
      or `iptables -I FORWARD -i vallum0 -j ACCEPT`
```

That is both the diagnosis and the fix — the exact command I eventually ran by
hand, after six container cycles spent finding it. The check reads
`iptables -S FORWARD` for `-i <interface> ... -j ACCEPT` whenever the policy
drops, which is precisely this failure.

So the gap was not in the product. It was in the order I worked: I diagnosed by
hand instead of running the diagnostic that ships with it. `vallum doctor` was
one command, it was already on the server, and it would have ended the hunt at
the second run.

Also resolved here rather than assumed: the traffic demonstrably crosses the
tunnel (the server's per-peer `rx_bytes` moved 710 → 3456 during the probes), so
the guard is not leaking. That was worth proving — a guard that passes traffic is
worse than a DNS failure, and the counters are what told the two apart.

## Gate 5 — The harness at scale

**Status: PASS** — `scripts/accept-many.sh 10`, ten containers with their own
network namespaces, each with its own key, its own allocated address and a real
`vallum join` against the production server.

```
many01 addr=10.7.0.6/24   unit=active ping=yes      many06 addr=10.7.0.5/24  …
many02 addr=10.7.0.13/24  unit=active ping=yes      many07 addr=10.7.0.9/24  …
many03 addr=10.7.0.10/24  unit=active ping=yes      many08 addr=10.7.0.12/24 …
many04 addr=10.7.0.4/24   unit=active ping=yes      many09 addr=10.7.0.11/24 …
many05 addr=10.7.0.3/24   unit=active ping=yes      many10 addr=10.7.0.7/24  …
distinct addresses: 10 of 10
peers the daemon reports: 12   (10 new + the 2 pre-existing config peers)
```

Nothing here is mocked except the hardware: ten distinct source IPs, ten real
keys, ten real enrolments through the allocator, and ten live sessions.

**A criterion worth keeping.** The first run declared PASS on `ping` alone, and
one client showed `ping=yes` beside `unit=inactive` and `addr=?` — three facts
that cannot all hold. It did not reproduce under a stricter rule that requires
the unit active, an address allocated *and* the ping to succeed, and the earlier
containers were already destroyed, so which measurement lied is not knowable.
What is knowable: an acceptance criterion that reads one signal can pass a
contradiction, and the second run is the one to trust.

**What this gate does not prove**, and must not be read as proving: bandwidth at
scale, or handshake timing under a full rekey herd. The memory sample (128 kB
over 10 peers = 12.8 kB/peer) is dominated by page granularity against a 5 MB
baseline; the 8.9 kB/peer claim in `requirements.md` was measured at 0/1000/2000
peers and this sample can neither confirm nor refute it. The capacity harness in
`references/capacity.md` is the instrument for both.

## Gate 4 — CI

**Status: PASS** — run `43230663345` on commit `cbf5ec5`, all four jobs green:

| job | result |
|---|---|
| `test (stable)` | ✓ — fmt, clippy `-D warnings`, workspace suite, lean daemon, TUI snapshot, packaging parity |
| `test (1.95.0)` | ✓ — the declared MSRV compiles every target |
| `end-to-end (two namespaces, real kernel)` | ✓ — netns gate, syscall allow-list, enforce-mode leg |
| `advisories and supply chain` | ✓ — `cargo audit`: no vulnerabilities |

Five failures preceded it, and none was a product defect:

1. **`ui/dist` was never built in CI.** `tauri::generate_context!()` embeds the
   console's frontend at compile time and panics when it is absent; `dist/` is
   gitignored because it is a build artifact, so a fresh checkout could not
   compile the workspace at all. Fixed by building it in the workflow.
2. **A test asserted a command the binary was not built with.**
   `utcp_manual.rs` walks every command in the manual, but CI also runs
   `cargo test --no-default-features`, where `tui` does not exist.
3. **The deb and rpm shipped less than `install.sh`.** Both omitted
   `vallum-cleanup.service`, `vallum-deadman@.service` and
   `vallum-deadman@.timer` — a host installed from a package got no cleanup
   floor and no dead-man switch. This one was a real packaging defect.
4. **The audit job was red for bookkeeping.** `rustsec/audit-check` writes a
   GitHub check run after reporting, and that write 404s on this repository even
   with `checks: write`; its own output said
   `"vulnerabilities":{"found":false,"count":0}`. Replaced with `cargo audit`.
5. **Three runs were cancelled by the next push** (`concurrency:
   cancel-in-progress`), and one cancellation was briefly misread as a failure.

The lesson recorded in `scripts/ci-local.sh`: a push should be an assertion, not
an experiment. Every gate above runs locally with the workflow's own commands.

## What this file will say when the gates finish

Either the product is alpha-ready with four green gates and a recorded commit, or
it is not, with the failing gate named. Nothing above is a judgement about the
code's quality — that was `docs/review-2026-11-11.md`, on a different axis.
