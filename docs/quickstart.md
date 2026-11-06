# Quickstart

One page from nothing to a working tunnel: what to have ready, the three shapes
a deployment takes, and how to tell it worked. Every section links the guide
that owns the detail.

## Before you start

| Requirement | Why | Detail |
|---|---|---|
| Linux with systemd (Debian/Ubuntu, Fedora/RHEL, Arch) | the daemon, units and privileges are Linux-only this release | [`proof/platforms.md`](proof/platforms.md) |
| Root, or `sudo` | the installer, `setup`, and the units need it; the daemon drops privileges itself | [`proof/privileges.md`](proof/privileges.md) |
| One reachable address, for a server | public IPv4, public IPv6, or a DNS name resolving to one | [`deployment/server.md`](deployment/server.md) |
| One UDP port, `51820` by default | open it on the host **and** in the cloud security group — `vallum server init` only manages the host firewall | [`deployment/server.md`](deployment/server.md) |
| A decision: full or split tunnel | full carries everything (`0.0.0.0/0`, `::/0`); split carries the prefixes you name | [`deployment/client.md`](deployment/client.md#full-tunnel-vs-split-tunnel) |
| A DNS answer | systemd-resolved, resolvconf, or deliberately left to the host | [`deployment/client.md`](deployment/client.md#dns) |

Read the crypto posture before trusting this with something that matters: the
post-quantum primitives come from `origin-crypto-sdk`, which labels itself
`EXPERIMENTAL — NOT FOR PRODUCTION USE` and has had no external audit. That
sentence is in the [README](../README.md), and the non-claims are in
[`security-model.md`](security-model.md).

## Install

Both halves use one installer. From a release — the assets are public, so this
needs nothing but `curl` (a private fork is the only case that wants `GH_TOKEN`):

```sh
curl -fsSL https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh \
  | sudo bash -s -- --from-release --install-only
```

From a checkout:

```sh
cargo build --release -p vallum -p vallum-quick
sudo ./scripts/install.sh --local --install-only
```

`--install-only` puts the binaries, units, man pages and completions in place and
stops. Without it the installer goes on to prepare the host as a server. Either
way the release signature is verified before anything is installed; `--package
deb|rpm` routes a package through the same check, because `dpkg -i` and `rpm -i`
verify nothing themselves.

## The three topologies

| You have | You want | Go to |
|---|---|---|
| a server someone else runs | this machine out through their tunnel | [A — a client](#a--a-client-of-an-existing-server) |
| a reachable host, no server yet | your own server, plus its first client | [B — your own server](#b--your-own-server-then-a-client) |
| two networks to join | two LANs over one tunnel, no roaming clients | [C — site-to-site](#c--site-to-site) |

### A — a client of an existing server

Pick the enrolment path by what the client can reach:

```sh
# The client can SSH to the server: its key is generated here, and only the
# public line crosses SSH.
sudo vallum setup --remote you@vpn.example.com

# It cannot: mint a single-use ticket on the server (or press `v` in `vallum tui`),
# then redeem it here. One use, fingerprint pinned, no private key on the wire.
sudo vallum peer invite laptop
sudo vallum join vallum1-join:<host>:<port>/<name>/<id>/<token>/<fp>

# Offline fallback: the server mints a bundle that carries the client's private
# key. Move it over a channel you trust, then delete it.
sudo vallum import-bundle laptop.vallum-bundle --install
```

Every path ends the same way: `/etc/vallum/<name>.toml` and its key at `0600`,
with `vallum@<name>`, `vallum-quick@<name>` and the route watchdog
`vallum-quick-watch@<name>` enabled and started. The server writes a full tunnel
by default; narrow `allowed_ips` in the peer's config for a split tunnel, and
`vallum-quick` will add one route per prefix instead.

### B — your own server, then a client

```sh
sudo vallum setup --server
```

That one command writes the key and config, turns on forwarding, installs the
firewall and NAT rules, and installs the unit. It asks before changing the host;
`--yes` takes the defaults. State the values instead of letting them be detected:

```sh
sudo vallum setup --server \
    --endpoint vpn.example.com \
    --address 10.7.0.1/24 \
    --listen 0.0.0.0:51820
```

Then enrol the first client with any path in [A](#a--a-client-of-an-existing-server).
`vallum server init` is the same preparation without the interview, and
`--no-nat` is for a host that routes real addresses rather than masquerading
([C](#c--site-to-site)). A server never runs the egress guard — its job is to
accept traffic, and [`adr/0018`](adr/0018-fail-closed-egress.md) explains why
the guard is client-side only.

### C — site-to-site

Two hosts, both prepared with `vallum server init --no-nat`, each holding the
other as a peer, neither masquerading the other's traffic:

```sh
# On B, generate a key; only the public line travels.
sudo vallum keygen --output /etc/vallum/server.key --suite 3 > b.pub

# On A, enrol B and route B's LAN into the tunnel.
sudo vallum peer add host-b \
    --public-key-file b.pub \
    --address 10.7.0.2/32 \
    --allowed-ips 10.7.0.2/32,192.168.20.0/24 \
    --endpoint 198.51.100.20:51820
```

Mirror it on B with A's tunnel address and LAN. Then let the LANs through the
forward chain, and tell the LAN routers that the far subnet is behind A. Vallum
does not speak a routing protocol; it moves packets for the prefixes you name.
The full walkthrough, including the NAT and forward rules, is
[`deployment/site-to-site.md`](deployment/site-to-site.md).

## Verify it worked

```sh
sudo vallum doctor --config /etc/vallum/<name>.toml --probe-mtu 1.1.1.1
sudo vallum show   --config /etc/vallum/<name>.toml   # handshake age, rx/tx per peer
sudo vallum status --config /etc/vallum/<name>.toml   # in the tunnel, blocked, or leaking
ping -c 3 10.7.0.1
```

A connected client shows a peer with a recent handshake; `handshake never` means
the two ends have not agreed on a session yet, and
[`deployment/troubleshooting.md`](deployment/troubleshooting.md) walks the
reasons in order. To see the host changes before they are made:

```sh
sudo vallum-quick attach /etc/vallum/<name>.toml --dry-run   # routes, DNS backend, hooks
sudo vallum tui                                              # the operations cockpit
```

For a host whose only path out should be the tunnel — a full-tunnel client that
roams, not a server — one more unit is opt-in:

```sh
sudo systemctl enable --now vallum-guard@<name>         # block egress outside the tunnel, before it starts
vallum policy status --config /etc/vallum/<name>.toml   # what the config asks for, what the host has
```

`vallum-quick-watch@` is already running from `setup`: it takes the routes back
out when the peer stops answering, so a dead server behind a live interface does
not leave the host with no internet. `vallum-guard@` is the fail-closed half of
[`adr/0018`](adr/0018-fail-closed-egress.md): the block goes in before the tunnel
comes up and stays when it dies, because a dead tunnel that restores the physical
default route is a leak nobody sees. `vallum policy off` removes it, works with
no daemon, and is the escape hatch when the block is what locked you out.

Set `[quick] dns` as well: on a full tunnel, systemd-resolved gets the `~.`
routing domain, so a query cannot reach the local resolver behind the tunnel's
back.

## Remove it

```sh
sudo vallum client teardown --name laptop      # one client tunnel, config kept
sudo vallum server teardown --dry-run          # show the plan, then run it
sudo vallum uninstall --purge                  # everything, including /etc/vallum keys
```

Without `--purge`, `uninstall` leaves `/etc/vallum` in place so a reinstall
brings the same tunnels back up.

## Where the detail lives

[server](deployment/server.md) · [client](deployment/client.md) ·
[site-to-site](deployment/site-to-site.md) ·
[automation](deployment/automation.md) · [upgrades](deployment/upgrades.md) ·
[monitoring](deployment/monitoring.md) · [backup](deployment/backup.md) ·
[troubleshooting](deployment/troubleshooting.md) ·
[security model](security-model.md) · [TUI](tui.md) · [roadmap](roadmap.md)
