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

> **Correction, 2026-11-17 — the paragraph above is now scoped to the tunnel,
> not to the project.** 1.8.0 shipped the desk, and §"A stranger can join and
> be served" below records `desk.wingman.gold` serving **open signup to
> anonymous visitors** on 2026-11-16, minting accounts with an expiry, a byte
> cap and a device cap. So there *is* a front door, it has served strangers,
> and the thing it hands out is a credential that cannot be re-issued
> (ADR-0045). Read "no users, no SLA" as the tunnel's framing; the desk is a
> service that has not yet been given a reliability target, an error budget, a
> backup timer or an alert — the four things this sentence used to make
> unnecessary. The gap is recorded in `docs/qa/delivery-topology-2026-11-17.md`
> and in the premortem of the same date.

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

> **Correction, 2026-11-17 — step 1 is no longer the operator's job, and it
> never covered the state that matters.** `--clean-remote` now runs
> `scripts/backup-deployment.sh` on the host itself, before it touches
> anything: it copies `/etc/vallum`, `/var/lib/vallum` (the desk's account
> database, which the hand tarball above missed — it did not exist yet) and the
> units, **verifies the archive** (every config present, the database still
> beginning with the SQLite header), and refuses the run if it cannot. The
> archive path is printed at the end and recorded in the verdict, so the
> restore is a command rather than a paragraph. See
> `docs/qa/premortem-alpha-2026-11-17.md`, failure mode 2.

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

**Status: PASS** — the whole pipeline, six jobs, on commit `def8170`
(run `43311779511`):

| job | result |
|---|---|
| `test (stable)` | ✓ — fmt, clippy `-D warnings`, workspace suite, lean daemon, TUI snapshot, packaging parity |
| `test (1.95.0)` | ✓ — the declared MSRV compiles every target |
| `end-to-end (two namespaces, real kernel)` | ✓ — netns gate, syscall allow-list, enforce-mode leg |
| `advisories and supply chain` | ✓ — `cargo audit`: no vulnerabilities |
| `install (staged; no root, no container runtime)` | ✓ — the installer, into a staging tree, with the modes and the completions checked |
| `acceptance (a server and a client, provisioned here)` | ✓ — the path a stranger follows, end to end |

The two newer jobs are the ones that closed the gaps this file recorded. The
**install** job runs the real installer with `--root` into a staging directory
and checks what it produced — every promised file at the path it lands at, the
modes right, the completions matching what the CLI generates now, and nothing
written outside the tree. The **acceptance** job proves the path a person
follows: the server writes the client config, the client installs it with the
receiver, and the tunnel carries.

### The earlier run, with four jobs

Run `43230663345` on commit `cbf5ec5`, all four jobs green:

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

## What a release needs now

`scripts/release.sh --dry-run` refuses today, and its refusal is the whole
remaining story:

```
FAIL  v1.6.4 is at 0505f7b, but HEAD is def8170; move the tag or release the tagged commit
```

Three things are needed, and only the first two are mechanical:

1. **A version.** The tree has moved far past `v1.6.4` (the published release
   is 2026-11-05). This is a decision, not a computation: the version number is
   the project's, not the tool's.
2. **A tag at HEAD**, signed with the release key. The key is present
   (`~/.config/vallum/release-signing-key`, 0600) and the script refuses to
   publish an unsigned release — an unsigned artifact is one `install.sh` cannot
   check, and the whole point of the script is that it can.
3. **A public repository.** Every gate above proves the product works; none of
   them makes it *reachable*. As long as the repository is private, a stranger
   cannot install what has been verified, and the gates are the only ones who
   know it exists.

## What this file will say when the gates finish

Either the product is alpha-ready with four green gates and a recorded commit, or
it is not, with the failing gate named. Nothing above is a judgement about the
code's quality — that was `docs/review-2026-11-11.md`, on a different axis.

## Later the same day: the evidence itself was audited

A premortem was run against the alpha as it stood, and five read-only
investigators were sent after the parts the gates were supposed to cover. Three
came back with defects in the *verification*, not the product. They are recorded
here because they are the state of the record, not because they are tidy.

### The two-host gate could report PASS with the production host broken

`scripts/verify-remote.sh` saved the host's `inet vallum` NAT table and
restored it in the cleanup. Three things were wrong with that, and they
compounded:

1. `restore_nat` had no `else` branch — a failed restore printed nothing.
2. The cleanup runs with `set +e`, and the trap's status does not replace the
   script's exit status, so the run reported **PASS**.
3. The "this commit passed the two-host gate" stamp was written in the main
   body, **before** the cleanup ran — so a run that left the host's NAT table
   deleted still recorded the commit as verified.

A failed restore is now loud (it prints the remedy and the exact `nft`
command), fails the run, and revokes the stamp.
`scripts/selftest-restore-fail.sh` is the proof: a good restore keeps the
stamp, a failed one exits 1 and revokes it.

### `vallum peer invite` undid the responder's demotion

The demotion of the enrolment responder had been done *by hand on one host* —
and the code restored it on the first invite:

- `peer.rs:838` called `server::enroll(enable: true)`, which wrote
  `enroll.enabled = true` into the config, installed the unit and opened the
  port;
- `peer.rs:855` ran `systemctl enable --now`;
- `server.rs:952` enabled the unit whenever the config flag was true — so the
  flag did double duty: "the responder may serve" (the runtime gate at
  `enroll.rs:759`) and "the responder starts at boot".

All three now **start** the responder and never **enable** it, and `peer
invite` prints the teardown where it mints the invite. ADR-0034's decision is
now the code's behaviour rather than a convention on one host.

### The local rehearsal was not the CI gate

`scripts/ci-local.sh` claimed to run the gates CI runs. It ran the same
*commands* on a different *compiler*: CI's `stable` was cargo 1.100.0, the
laptop's was 1.97.1, and the lints born in between (a cargo manifest lint and
`clippy::needless_bool`) failed CI while the rehearsal was green.

The toolchain is now pinned in `rust-toolchain.toml` (1.100.0), CI uses the
pinned version rather than a moving `stable`, and `ci-local.sh` **refuses to
rehearse** on any other toolchain, naming the install command.

### The verdicts count what ran

`scripts/verdict.sh` writes a record per gate — gate, status, commit,
assertion count, target, timestamp — so a verdict from an older tree is
visible ("stale accept-pair ran on 77a0a1d, not this commit") instead of
silently standing in for the current one. A failing gate records too.

The assertion counts were at first hand-written: `accept-full-tunnel.sh`
counted a flat `+3` whether one or three of its conditions held. Each
condition is now counted as it is evaluated. What the count still cannot do is
notice a check that was *neutralised* rather than removed — a sabotage that
prints its "ok" line still counts. It measures what ran, not what was proved.

## Open findings the premortem did not close

These are recorded because they are real and not yet fixed. Nothing here is a
release blocker by itself; each is a place where the product is less than the
documentation implies.

1. **PARTLY FIXED 2026-11-16 — the token path now carries DNS.** The responder
   hands `client_config` the server's own `[quick] dns` (`peer_dns` in
   `commands/peer.rs`), which is exactly what `--dns` sets and what ADR-0013
   calls "pushes a resolver; it does not run one". A ticket-enrolled device is
   now told what to resolve through instead of getting a full tunnel and no
   resolver — which leaked every query to the local network. Two tests pin it.
   PSK and shaping are still not carried: those remain open below.

   **A deviation, recorded:** the first attempt at this built a server-side
   resolver (`vallum-dns@`, a `[enroll] peer_dns` field, a firewall rule for
   53/udp on the tunnel interface) and ran it on the deployment. ADR-0013 says
   plainly "No DNS resolver. `--dns` pushes a resolver; it does not run one",
   and the deployment docs already define `--dns` as one field written to
   `[quick] dns` and pushed to clients. The resolver, the second field, the
   unit and the firewall rule were reverted; what remains is the one-line gap
   fix above. The recorded design was right: a pushed public resolver is
   reached through the tunnel, so it does not leak, and it needs no new
   service, no second statement of an address, and no cache to operate.

   **CLOSED 2026-11-16 — the token path now carries DNS, PSK and shaping.**
   `22459c4` adds optional `psk`/`shaping` fields to the invite (serde defaults
   keep old invites parseable), `peer invite` takes `--psk`/`--shaping`, and the
   responder threads them into the peer record and the sealed client config —
   the same things `--psk`/`--shaping` do in the file path. Two tests pin the
   end-to-end behaviour.

2. **CLOSED 2026-11-16 (verified, not assumed).** The three derivations now
   agree: `peer invite` builds the ticket from `commands/server.rs::enroll_port`
   (the same function the responder binds with), which prefers `[enroll].port`
   and otherwise uses `listen + 1` — with guards that refuse an ephemeral
   `listen` and any port below 1024. The TUI's `join_target` uses the same
   preference. `enroll_port`'s three tests and
   `join_target_uses_listen_port_plus_one_when_public_endpoint_port_differs`
   pin the divergent case. The finding described the tree before `f566b58`.

3. **CLOSED 2026-11-16.** `1e4c56a` adds `scripts/seccomp-expected.txt`, a
   hand-written x86_64 expectation authored from `docs/proof/seccomp.md`'s
   categorization. `seccomp-trace.sh` now diffs the binary's allow-list against
   it in both directions (a missing expected syscall fails; an unexpected
   allowed syscall fails), then keeps the original trace-vs-allow-list
   comparison. Other architectures skip the oracle — the list is
   x86_64-specific — and keep the trace comparison.

4. **CLOSED 2026-11-16.** `0473d8c`: the stamp is now a structured record —
   commit, `remote_host`, `namespaced`, assertion count, the invoking
   operator@host, a hash of `verify-remote.sh`, and a UTC timestamp — so the
   two-host property is encoded in the artefact, not just asserted in prose.
   `release.sh` reads the commit from either format, so a pre-change bare-hash
   stamp is not stranded. The `--skip-remote "reason"` bypass remains
   documented, not silent.

5. **CLOSED 2026-11-16.** `0473d8c`: `verdict.sh` signs each record with the
   release key (`ssh-keygen -Y sign`, the same key and `packaging/allowed_signers`
   trust anchor as release assets), and records the producer and a hash of the
   gate script that ran. `release.sh` refuses a this-commit `passed` verdict
   whose signature does not verify — a hand-written record is no longer
   evidence.


## Verdict, 2026-11-16: the bar is met — with the caveats named

The bar above was: a machine that is not the operator's can install it, join it,
and be served — and someone else can run the same validation and get the same
answer. Every clause now has an artefact:

- **A stranger can get the code and the client.** `git clone` over anonymous
  HTTPS builds the workspace (including the public `origin-crypto-sdk`
  dependency); `install.sh --from-release` fetches the signed v1.7.0 tarball
  with no token and no `gh`; `ssh-keygen -Y verify` against the committed
  `allowed_signers` passes and the tarball checksum matches the signed sums.
- **A stranger can join and be served.** `desk.wingman.gold` (Caddy → the desk,
  open signup) hands a visitor the install command and mints a real join ticket.
  Proven from outside on 2026-11-16: anonymous `/api/signup` →
  `vallum setup --join` → a working full-tunnel config with pushed DNS, the peer
  visible server-side and then revoked. The ticket page now also tells the
  visitor how to get `vallum` — the earlier version handed out a command for a
  binary the stranger did not have.
  <!-- The deployment names, addresses and ports that stood here — the unit
  `vallum-desk@vallumrc`, the peer address `10.99.90.8/32`, the port `51921` —
  were the test harness's, not the live server's. Removed rather than corrected
  in place: a wrong address is worse than no address, and the paragraph's claim
  is about capability, which does not need one. See the correction below. -->

  > **CORRECTION 2026-11-17 — these addresses are the TEST HARNESS's, not the
  > live deployment's.** <!-- harness-address-ok: this block exists to name the
  > harness's values; the exemption is the point of the paragraph. -->
  > `10.99.90.0/24`, the interface name `vallumrc` and UDP port `51921` are
  > `scripts/verify-remote.sh`'s scratch defaults (`SUBNET`, `CIFACE`, `PORT` at
  > lines 116–128), used so the two-host test can run beside a live server
  > without touching it. This paragraph recorded them as if they were the public
  > deployment's addressing.
  >
  > What the host actually runs, inspected 2026-11-17: one config,
  > `/etc/vallum/vallum0.toml`, `10.7.0.1/24`, `listen 0.0.0.0:51820`, unchanged
  > since 2026-11-11; there is no `vallumrc.toml`; the desk, the enrolment
  > responder and the tunnel all run as `@vallum0`; a ticket minted today names
  > `107.175.238.82:51821`. So the stranger signup was real and the *capability*
  > claim holds — re-verified 2026-11-17, the desk answers 200 publicly and
  > `peer invite` mints a real ticket naming the live responder — but the peer
  > that join produced cannot have had address `10.99.90.8/32`, because that
  > subnet belongs to the harness.
  >
  > Kept rather than deleted: a published verdict that described a test rig as
  > production is the thing a future reader most needs to see. `scripts/
  > check-doc-addresses.sh` now fails when a doc's live-deployment claim uses a
  > harness default.
- **The validation is reproducible.** All gates are in the tree and runnable;
  verdicts are signed and commit-bound; the remote stamp names the host, the
  script hash, and the assertion count.
- **Hosted CI is green on the public repo.** `ci.yml` (all six jobs) and
  `fuzz.yml` passed on `ubuntu-latest` at `f7771e6`. The hosted image refuses
  unprivileged user namespaces even for root (Ubuntu 26.04 AppArmor), so
  `accept-pair` now falls back to its docker backend and `e2e-netns.sh` runs a
  plain `unshare -n` when already root.

What is still true, and must stay said: the PQ suite via `origin-crypto-sdk`
is `EXPERIMENTAL — NOT FOR PRODUCTION USE` and has had no external audit; the
remote gate's structured stamp is bound to `a426d82` (later commits are desk,
e2e, and packaging work — a release gate on a newer tag needs a restamp);
`release.yml`'s tag preflight has not yet run on the hosted runner; and the
roadmap's owed items stand — outside deployments, external review, an audit of
the experimental crypto, and a second maintainer.
