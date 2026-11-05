# Published artifact dogfood — 2026-11-05

The tarball a stranger downloads, verified the way `install.sh` verifies it, then
run under the same two-namespace harness the repository uses on itself. The point
is not that HEAD works — `scripts/verify.sh` settles that — but that the **tagged
artifact** still does, and that the trust chain around it verifies without an
account.

## 1. The artifact and its trust chain

`v1.6.3`, `vallum-v1.6.3-x86_64-linux.tar.gz`, 3,465,087 bytes.

| Step | Command | Result |
|---|---|---|
| checksum | `sha256sum vallum-v1.6.3-x86_64-linux.tar.gz` | `60faa8609b34b2acf5761695ce63bb5b5553b8eac8054c59ecbb4aaec67069c6` — the line in `SHA256SUMS` |
| signature | `ssh-keygen -Y verify -f allowed_signers -I vallum-release -n file -s SHA256SUMS.sig < SHA256SUMS` | `Good "file" signature for vallum-release with ED25519 key SHA256:KN2x8GszZ1OGqqUr7zBm76V0kszLBDlxJeuoIstOxMk` |

Verification needs no GitHub account: `SHA256SUMS`, `SHA256SUMS.sig` and
`allowed_signers` are plain files, and `ssh-keygen` is already installed wherever
`vallum` can run. A tampered `SHA256SUMS` is rejected — `scripts/verify.sh`
proves that round trip on every run, and this run was no exception.

The archive holds 17 files: both binaries, five units and a timer, three man
pages, three shell completions, the alerts file, `README.md`, `LICENSE`. No
document in it names a private path; the binaries do, which is §5.

```
vallum 1.6.3 (linux-only, experimental-pq)
vallum-quick 1.6.3
ELF 64-bit LSB pie executable, x86-64
```

## 2. How it was driven

| Surface | Method |
|---|---|
| Harness | `git show v1.6.3:scripts/e2e-netns.sh` — the harness **at the tag**, not at HEAD |
| Binaries | the extracted release `vallum` and `vallum-quick`, not `target/debug` |
| Privilege | unprivileged user namespaces; no root, no host interface touched |
| Network | two namespaces joined by a veth pair, real TUN, real UDP, real kernel routing |

The harness had to be the tag's own copy. HEAD's version asserts on the strings
HEAD renders — section titles went upper-case in `a96009c`, after this tag — so
judging an older artifact with a newer harness reports a mismatch in the *test*,
not the product. Pairing a tag with the harness it shipped with is what makes the
result mean anything.

## 3. Result

**88 checks, 0 failures, exit 0.** The phases, in order:

- outer network up over both families; two distinct tri-hybrid keys from `keygen`;
  a shared PSK written to both configs
- daemons started, interfaces up, `ping 10.7.0.2` crossing the tunnel; A as
  Initiator, B as Responder
- control socket: device, peer, bound port (not the configured `0`), socket mark;
  the default view and `showconf` secret-free; `show --json` secret-free
- headless TUI snapshot with the live device and peer table; `doctor` passing the
  control check
- captured InitHello: one datagram, 4,677 bytes, nothing fragmented
- reverse direction, then `ping -s 1200` (1,228 B on the wire)
- fail-closed: `policy on` blocks egress and port 53, `policy off` restores it
- keepalive cadence on an idle peer
- adversary in the second namespace: junk, oversized datagrams, a replayed
  handshake — no reply, no crash, tunnel still carrying traffic
- runtime listen-port rebind, the scrape while the daemon is dead (`blocked`
  under a guard, `LEAKING` without one)
- restart on a 1000-byte outer path; IPv6 inner addresses; v6 outer with
  dual-stack `/32` inner addresses
- path narrowing to 1,200 bytes while running, then `outer_mtu = 1200` on the
  same path
- provisioning both ends through the CLI, key rotation with no outage, finalize,
  the retired key refused, `peer remove`
- full tunnel: routes installed by the packaged `vallum-quick`, an outside lookup
  routed in, egress that stays physical, detach restoring it
- per-app member namespace: attach, a member lookup resolving inside, `app`
  launching with the pushed resolver, the host's `resolv.conf` untouched, detach
  and re-attach
- a holder that dies with the device inside: refused afterwards, recovered by a
  restart plus re-attach

## 4. What this does not prove

| Gap | Why |
|---|---|
| Two physical machines | Not available here. The two namespaces share one kernel, so this proves the artifact's code paths, not a real WAN path. |
| `setup`, `install.sh`, the systemd units | No passwordless root on this host. The units were shipped and read, never loaded. |
| `.deb` / `.rpm` | Only the tarball was exercised; the packages are built from the same binaries by `scripts/release.sh`. |
| `aarch64` | Only the `x86_64` asset was run; the other is the same source, cross-built. |
| In-place upgrade | Nothing was upgraded over an existing install. |
| A real terminal | The TUI was exercised headless (`--snapshot`) only, no PTY session and no keystrokes. |

## 5. Two defects found

| # | Where | Finding | Status |
|---|---|---|---|
| D1 | `scripts/e2e-netns.sh` at HEAD | The TUI check asserted `grep -q 'Peers'`, which the upper-case section titles made unreachable, so the end-to-end gate would have failed at the next tag for a reason that says nothing about the product. It survived because the renaming commit was never pushed: `ci.yml` runs this script on every push, and the remote has only seen the commits before it. | **Fixed** in `e0d6930`, which now asserts the title with its peer count and the peer's own row. The artifact is unaffected — it renders the older title its own harness expects. |
| D2 | the shipped binaries | Both carry the build machine's filesystem layout: 288 `/home/…` strings in `vallum`, 43 in `vallum-quick`, e.g. `/home/ikaaros/.cargo/git/checkouts/originsdk-cf2b9e8a142936c9/e4f8724/src/drbg/rng.rs`. They are `file!()` literals inside panic and assertion messages, so `strip = "symbols"` does not remove them. Anyone who runs `strings` on a release learns the maintainer's username and home layout. | **Fixed in `scripts/release.sh`** — builds now export `--remap-path-prefix=$HOME=/build --remap-path-prefix=$CARGO_HOME=/cargo`, and the release refuses to package a binary that still names `$HOME`. Measured on a rebuilt `vallum` and `vallum-quick`: 288 and 43 occurrences of `/home/` became 0 and 0, reading `/build/…` and `/cargo/…`. `v1.6.4`, cut the same day, was downloaded back and checked: **0 and 0**, with the strings reading `/cargo/…`, which is why that release exists. |

## 6. Reproducing it

```sh
gh release download v1.6.3 --repo KidIkaros/vallum --dir /tmp/vallum-rel \
    --pattern 'vallum-v1.6.3-x86_64-linux.tar.gz' \
    --pattern 'SHA256SUMS' --pattern 'SHA256SUMS.sig' --pattern 'allowed_signers'

cd /tmp/vallum-rel
sha256sum vallum-v1.6.3-x86_64-linux.tar.gz
ssh-keygen -Y verify -f allowed_signers -I vallum-release -n file \
    -s SHA256SUMS.sig < SHA256SUMS
tar xzf vallum-v1.6.3-x86_64-linux.tar.gz

git -C <checkout> show v1.6.3:scripts/e2e-netns.sh > /tmp/e2e-v163.sh
QUICK=/tmp/vallum-rel/vallum-v1.6.3-x86_64-linux/vallum-quick \
    bash /tmp/e2e-v163.sh /tmp/vallum-rel/vallum-v1.6.3-x86_64-linux/vallum
```

Needs Linux with unprivileged user namespaces, `ip`, `nsenter`, `ping` and
`python3`. `KEEP=1` leaves the scratch directory (keys, configs, both daemons'
logs) behind. Duration on this machine was not measured.
