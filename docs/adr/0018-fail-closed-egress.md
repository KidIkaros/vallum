# ADR-0018: A packet leaves only through the tunnel, or to the endpoint

**Status:** proposed · **Date:** 2026-10-22

---

## Context

Vallum fails **open**. Nothing in the tree drops egress: `hostnet.rs` builds two
kinds of rule — masquerade for a server, and opening the UDP port — and no
others. `grep -rn 'drop\|fail_closed\|kill_switch' crates/` returns handshake
comments and nothing executable.

Three consequences, all observed:

1. **A v4-only server leaked v6.** `peer add` wrote
   `allowed_ips = ["0.0.0.0/0", "::/0"]` for every peer. Claiming `::/0` does not
   create a v6 route; it asserts that v6 belongs to the tunnel. When the route
   cannot be installed the traffic falls through to the real default route.
   `verify-remote.sh` reports it: *IPv6 egress escapes via `wlp0s20f3`, not the
   tunnel.* The config half of this is fixed (`a142840`); the packet half is not.
2. **A dead tunnel is a silent revert.** `vallum-quick detach` removes the
   routes when the tunnel stops, and the host's default route returns to the
   physical interface. Traffic that was in the tunnel leaves outside it, with no
   signal to the user.
3. **The failure is invisible.** Every alert in `packaging/vallum-alerts.yml` is
   server-side. On the client, the first evidence is a website loading from the
   wrong country.

The roadmap's first condition — *a dead tunnel does not leak* — is the only one
with no implementation at all.

## The rule

> A packet may leave this host only through the tunnel, or to the endpoint that
> carries the tunnel.

That is the whole policy. It is deliberately stated as a property of the host,
not of the daemon, because the daemon is the thing that fails.

## Design

### Where the rules live

An nftables table Vallum owns, `inet vallum_policy`, with one `output` hook:

```
table inet vallum_policy {
  chain output {
    type filter hook output priority 0; policy accept;

    oifname "lo" accept                    # loopback
    oifname "vallum*" accept               # the tunnel itself

    ip  daddr <endpoint4> udp dport <port> accept   # the handshake
    ip6 daddr <endpoint6> udp dport <port> accept

    udp sport 68 dport 67 accept           # DHCP, or no address at all
    ip6 nexthdr udp udp sport 546 udp dport 547 accept

    ip daddr <lan> accept                  # only if allow_lan

    meta nfproto ipv6 drop                 # only if the tunnel carries no v6

    drop
  }
}
```

Two properties matter more than the individual rules:

- **The endpoint exception is what makes this survivable.** A kill switch that
  also blocks the handshake is a machine that can never reconnect.
- **The family drop is independent of `allowed_ips`.** Even a config that still
  claims `::/0` cannot leak v6 out of a physical interface. The config fix
  removes the source; this removes the escape.

### Lifecycle — the part that decides fail-open from fail-closed

The block must exist **before** the tunnel comes up and must **outlive** the
tunnel going down. Both are ordering problems, and the obvious placements get
both wrong:

- **Not in `vallum-quick@.service`.** It is `PartOf=vallum@%i.service`, and its
  `ExecStop=vallum-quick detach` runs when the tunnel stops. Putting the block
  there removes it at exactly the moment it is needed.
- **Not in the daemon.** A crash would take the rules with it, or leave state
  nobody owns. The daemon is the failing component; it must not own the policy
  that covers its failure.

A separate unit, `vallum-guard@.service`:

```
Before=vallum@%i.service
Wants=vallum@%i.service
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/vallum-quick guard   /etc/vallum/%i.toml
ExecStop=/usr/bin/vallum-quick unguard  /etc/vallum/%i.toml
```

No `PartOf=`. `unguard` runs when the guard is stopped deliberately — a reboot, or
an operator typing `systemctl stop` — not when the tunnel drops. A tunnel that
fails leaves the host blocked, which is the entire point.

### Configuration

Extend `[quick]`, which is already the host-networking section:

```toml
[quick]
table = "auto"
policy = "off"        # off | on | auto   (see the decision below)
allow_lan = false
allow = []            # extra destinations, e.g. ["192.168.1.0/24"]
```

`auto` means: on when the config is a full tunnel (`allowed_ips` covers a default
route) and the host is not a server; off otherwise. The endpoint and its port are
taken from `[[peer]].endpoint` — never hand-written, so they cannot drift.

### The escape hatch

`vallum policy off` drops the table and says what it did. It works with no
network and no daemon, which is the only condition under which it is needed.
`vallum doctor` reports the policy state, and warns when a full tunnel has it
off.

## Alternatives considered

| Option | Why not |
|---|---|
| A blackhole default route (`ip route add blackhole 0.0.0.0/0 metric 1000`) | Cannot express the endpoint exception, cannot drop one family, and fights the policy-table routing `vallum-quick` already installs |
| Rules through `ufw`/`firewalld` | Depends on the user's firewall manager; `hostnet.rs` already has to detect three backends for NAT, and the policy must not inherit that fragility |
| Rules owned by the daemon | Lifecycle is inverted: the failing component would own the rule that covers its failure |
| Per-app network namespaces | That is split tunnelling (roadmap item 5), a different feature |

## Risks

- **Lockout.** A client reached over SSH becomes unreachable when its tunnel
  fails. This is what a kill switch *is*, and it is why it must be opt-in and
  never applied to a server. `vallum doctor` must say so before the fact.
- **DNS.** With `dns_domain = "~."` queries go through the tunnel and are fine.
  Without it, a fail-closed client loses name resolution. The policy must not
  silently permit a resolver outside the tunnel — that is the leak it exists to
  stop — so the config validation should refuse `policy = "on"` with no tunnel
  DNS and no explicit `allow` entry.
- **Endpoint drift.** A server whose address changes while the block is up is
  unreachable until the operator updates the config. Acceptable; a
  domain-named endpoint re-resolved by the daemon is the mitigation, and it is
  already how `endpoint` works.

## Verification

Extend `e2e-netns.sh` with a `policy` phase, which needs no VPS:

1. Tunnel up, `policy = "on"`: v4 crosses, and a packet to an address outside
   the tunnel leaves through `vallum0`.
2. Tunnel killed, guard still active: v4 to the same address is **dropped**, and
   the endpoint is still reachable (so the tunnel can come back).
3. A v4-only tunnel with a config that claims `::/0`: v6 egress is dropped.
4. `vallum policy off`: v4 crosses again over the physical path.
5. `vallum doctor` reports each of the above states correctly.

## Decision

The mechanism is settled. The default is not:

- **`policy = "off"` in 1.6.x, `"on"` at the alpha cut**, with `doctor` warning
  when a full tunnel has it off. *(recommended)*
- `"on"` for every full tunnel immediately.
- `"auto"` as the default and no announcement.

The first is recommended because a surprise total loss of connectivity on a first
install is the review Vallum cannot afford, while shipping an alpha with a
fail-open VPN is the one it deserves.
