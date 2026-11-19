# Setting up a Vallum server

This is the server half of a Vallum deployment: one Linux host with a public
address that clients connect to. It is the equivalent of the WireGuard
walkthrough — install, key, config, forwarding, firewall, service — collapsed
into two commands.

If you have not installed Vallum yet, start with [install](#1-install).

## What you need

- A Linux host with systemd (Debian/Ubuntu, Fedora/RHEL, Arch).
- Root, or the ability to run `sudo`.
- A reachable address: a public IPv4, a public IPv6, or a DNS name that resolves
  to one.
- One UDP port, `51820` by default. Open it in any cloud security group as well
  as on the host — `vallum server init` only manages the host firewall.

## 1. Install

From a release:

```sh
curl -fsSL -o /tmp/vallum-install.sh https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh \
  && sudo bash /tmp/vallum-install.sh -- --from-release --install-only
```

The release assets are public, so this needs nothing but `curl`. Installing from
a private fork is the only case that wants a token: set `GH_TOKEN` (or
`GITHUB_TOKEN`) and the installer falls back to `gh`.

Prefer the `.deb`/`.rpm`? Route it through the installer so the package gets the
same signature check as the tarball — `dpkg -i`/`rpm -i` verify nothing on their
own:

```sh
... | sudo bash -s -- --from-release --package deb    # or rpm; bare --package autodetects
```

From a checkout:

```sh
cargo build --release -p vallum -p vallum-quick
sudo ./scripts/install.sh --local --install-only
```

Both install `vallum` and `vallum-quick` into `/usr/bin`, the two systemd units
into `/etc/systemd/system`, and the man pages and completion into `/usr/share`.

## 2. Prepare the server

```sh
sudo vallum server init \
    --endpoint vpn.example.com \
    --address 10.7.0.1/20 \
    --listen 0.0.0.0:51820
```

That single command:

| Step | What it does | Where |
|---|---|---|
| key | generates a tri-hybrid key, or reuses the existing one | `/etc/vallum/server.key` (0600) |
| config | writes the interface, control socket and `[quick]` table | `/etc/vallum/vallum0.toml` (0600) |
| forwarding | enables IPv4/IPv6 forwarding and persists it | `/etc/sysctl.d/90-vallum.conf` |
| firewall | opens the UDP port in ufw, firewalld, or nftables — whichever is active; a manager that is installed but switched off still gets its rule, stored for the day it is enabled | the host's own rules |
| NAT | masquerades the tunnel subnet, v4 and v6 | `inet vallum` table |
| service | installs `vallum@.service` and `vallum-quick@.service`, enables and starts both | systemd |

The key is **never regenerated**: re-running setup on a live server does not
invalidate every client's configuration. The config is not rewritten either
unless you pass `--force`.

### Options

| Flag | Meaning |
|---|---|
| `--endpoint HOST:PORT` | the address clients dial. Detected from the default route if omitted |
| `--address CIDR` | repeatable; one v4 and one v6 address makes a dual-stack tunnel |
| `--listen ADDR:PORT` | default `0.0.0.0:51820` |
| `--dns ADDR` | repeatable; written to `[quick] dns` and pushed to clients |
| `--user USER` | drop to this user after the interface and socket are open |
| `--no-nat` / `--no-firewall` / `--no-forward` | skip that host change |
| `--client-isolation` | service tenancy: drop tunnel-to-tunnel forwarding so peers cannot reach each other (both still reach the internet). Persisted as `[interface] client_isolation`; default is flat (personal tenancy, ADR-0047) |
| `--control PATH` | the control socket; default `/run/vallum/<name>.sock` |
| `--no-host` | skip all three (config and service only) |
| `--no-service` | write the config, do not touch systemd |
| `--dry-run` | print every step and change nothing |
| `--force` | rewrite an existing config, keeping a timestamped `.bak` |

### Expected output

```
ready: server `vallum0`
   config    /etc/vallum/vallum0.toml
   key       /etc/vallum/server.key (new)
   listen    0.0.0.0:51820
   endpoint  vpn.example.com:51820
   address   10.7.0.1/20
   firewall  ufw
   service   installed and started

add a client:
   vallum peer add laptop --config /etc/vallum/vallum0.toml --ship-key --bundle-out laptop.vallum-bundle
```

### Service tenancy: isolating strangers' devices

The default is **personal**: every peer can reach every other peer through the
server — a feature for your own devices. A server offered to strangers wants
the opposite. Set `client_isolation = true` under `[interface]` (or pass
`--client-isolation` at creation) and re-run `vallum server init`: the host
plan converges, adding a drop rule for traffic that enters and leaves the
tunnel interface in Vallum's own `inet vallum` table. Peers then cannot reach
each other, while both still reach the internet and the server itself. Set it
back to `false` (or remove the line) and re-run to return to flat. The config
is the source of truth: on a re-run the flag is refused if it disagrees with
the preserved config. `scripts/accept-isolation.sh` proves both directions
and the preserved egress in namespaces, with no container runtime required.

## 3. Verify

```sh
sudo vallum doctor --config /etc/vallum/vallum0.toml
sudo vallum show   --config /etc/vallum/vallum0.toml
systemctl status vallum@vallum0 vallum-quick@vallum0
```

`doctor` checks the config, the control socket, forwarding, the firewall port,
the unit state, and the config's permissions. A healthy server:

```
PASS  platform   linux (Linux is the supported tier this release)
PASS  config     /etc/vallum/vallum0.toml parsed and resolved
PASS  control    interface `vallum0`, listen 51820, suite 0x0003, 0 peer(s)
PASS  forwarding IP forwarding is enabled for every address family the tunnel uses
PASS  firewall   ufw allows UDP 51820
PASS  service    vallum@vallum0 is active
PASS  config mode 0600 (owner only)
```

## 4. Add a client

Two models, and the difference is who generates the client's private key.

### A. The device generates its own key (recommended)

On the device:

```sh
sudo vallum keygen --output /etc/vallum/laptop.key --suite 3 > laptop.pub
```

Copy `laptop.pub` to the server, then:

```sh
sudo vallum peer add laptop \
    --public-key-file laptop.pub \
    --client-config-out laptop.toml \
    --shaping balanced
```

The server allocated `10.7.0.2/32`, wrote the peer, applied it to the running
daemon, and wrote `laptop.toml` — the device's config, with no private key in it.
`--shaping balanced` adds the [shaping preset](../shaping.md#presets) to that
config instead of leaving the blocks to be copied by hand; `opening` is the other
one, and omitting the flag shapes nothing.
Copy `laptop.toml` to the device as `/etc/vallum/laptop.toml`, next to
`laptop.key`, then see [the client guide](client.md).

### B. The server generates the key and hands over a bundle

```sh
sudo vallum peer add laptop --ship-key --bundle-out laptop.vallum-bundle --forget-key
```

One command, but the server generated the private key. `--forget-key` deletes
its copy immediately; without it the key stays in `/etc/vallum/clients/` so the
bundle can be re-issued. The bundle contains the private key: treat it as one.

## 5. Manage peers

```sh
sudo vallum peer list    --config /etc/vallum/vallum0.toml
sudo vallum peer show    laptop --config /etc/vallum/vallum0.toml
sudo vallum peer remove  laptop --config /etc/vallum/vallum0.toml
```

`list` prints a fingerprint, not the 4.7 KB public line. `show --full` prints the
whole line. Addresses are allocated from the interface's own subnets, skipping
the server's address and anything already routed to a peer; an overlap is
refused, because two peers cannot claim the same addresses.

Edits preserve the file's comments and ordering, and every write leaves a
timestamped backup.

## 6. Rotate a key

A key swap normally means a window where the device cannot connect. Vallum keeps
the old key as a *previous* identity, so the server can install the new one
first:

```sh
# on the device: generate the new key and send its public line
sudo vallum keygen --output /etc/vallum/new.key --suite 3 > new.pub

# on the server: the new key becomes current, the old one stays accepted
sudo vallum peer rotate laptop --public-key-file new.pub
```

Nothing breaks: the device still presents the old key and the server still
accepts it. Move `new.key` to the device, restart the tunnel, then retire the old
key:

```sh
sudo vallum peer finalize laptop
```

`peer list` shows `ROT yes` while a rotation is open, and `doctor` warns until it
is finalized. A rotation is only zero-downtime in the direction that matters: the
**responder** accepts the previous key, so rotate the key of the peer that dials
*you*. For a server-generated key, `peer rotate … --ship-key --bundle-out FILE --forget-key`
writes a bundle instead.

## 7. Identity documents

A public key is a key forever. A document binds the key to a label and a
validity window, so a credential can expire:

```sh
# once: a CA key with a signing half
sudo vallum keygen --output /etc/vallum/ca.key --suite 3 --signing > ca.pub

# trust that CA in the interface — its public line is what keygen printed
#   identity_issuer = "vallum1:0003:..."

# per device: issue a 90-day document over its public line
sudo vallum identity issue --ca-key /etc/vallum/ca.key \
    --peer-public-file laptop.pub --label laptop --days 90 \
    --output laptop.identity

sudo vallum peer add laptop --identity laptop.identity
```

The document is verified at load and at every handshake; an expired one fails
closed, and `peer list` shows `EXPIRED`. With no `identity_issuer`, a document
must be self-signed — a key binding with a window, not an authorisation. `vallum
identity verify` checks one by hand.

## 8. Pin an endpoint

A peer roams by default: a laptop changes networks and the tunnel follows. That
is also the one place an active man in the middle can redirect a tunnel.

```sh
sudo vallum peer add laptop --public-key-file laptop.pub \
    --endpoint 203.0.113.7:51820 --pin-endpoint
```

A pinned peer refuses a handshake from any other address. It also stops NAT
rebinding working, which is why it is opt-in and per peer.

## How the pieces fit

```
client ── UDP 51820 ──▶ [ vallum0 ] ──▶ forwarding ──▶ masquerade ──▶ internet
                          ▲
             vallum@vallum0.service      the tunnel
             vallum-quick@vallum0.service routes, DNS, hooks
```

The daemon owns the interface and the socket and nothing else. The second unit
applies the `[quick]` table — routes, DNS, and your hooks — once the interface
exists, which is why it is a separate unit: the daemon's sandbox is not widened
to let it write `/etc/resolv.conf` or run a shell.

## What this does not do

- **No DNS resolver.** `--dns` pushes a resolver to clients; it does not run one
  (ADR-0013). Point it at a resolver your peers can reach through the tunnel —
  a public one, or an unbound/dnsmasq on this host if you want to run one.
  Clients route their queries through the tunnel, so a pushed resolver is
  reached from inside it, not around it.
- **No high availability.** One host, one interface. Two servers with the same
  subnet is a routing problem, not a supported configuration.
- **No control plane.** There is no API that issues configs. See
  [automation.md](automation.md) for the machine interface a service can wrap.
- **No cloud firewall changes.** Open the UDP port in the provider's security
  group yourself.
- **No mobile clients.** Linux only this release.

## Uninstall

```sh
sudo vallum uninstall --dry-run   # the plan: units, firewall, files, secrets
sudo vallum uninstall             # everything except /etc/vallum
sudo vallum uninstall --purge     # including /etc/vallum — keys are gone for good
```

`install.sh --uninstall` runs the same command. `apt remove vallum` /
`rpm -e vallum` stop the units first (maintainer scripts); `apt purge` also
clears `/etc/vallum`.

## File ownership rule

Every file the daemon reads must be **owned by the user it runs as** — normally
root for the config and key. The unit's capability bounding set has no
`CAP_DAC_OVERRIDE`, so root is only root for files it owns: a config copied in as
another user fails with `Permission denied` even though the operator can read it
in a shell. `install.sh` sets this up; anything hand-placed should be
`chown root:root` and `chmod 600`.

## Enrolment: open the second port only while you are enrolling

The enrolment responder listens on `listen + 1` (51821) and is **not enabled at
boot** — and that is now the code's behaviour, not just a convention:
`vallum peer invite` *starts* the responder for the enrolment but never
*enables* it, and prints the teardown commands below where it mints the
invite. Every peer you already have lives in the server's config and needs only
51820, so the second port is only needed during the seconds a new device joins.
Keeping it open to the world between enrolments is a standing surface with no
reason to be open (ADR-0034).

To enrol a device:

```bash
# on the server
sudo -S -p '' ufw allow 51821/udp
sudo -S -p '' systemctl start vallum-enroll@vallum0
# ... the device joins: vallum join <ticket>
# and afterwards:
sudo -S -p '' systemctl stop vallum-enroll@vallum0
sudo -S -p '' ufw delete allow 51821/udp
```

`sudo ufw status numbered` should show **no** rule for 51821 between enrolments.
If it does, the responder is still running or the rule was left behind — both are
worth checking, because a listener on 51821 is a second service to harden.

The alternative, and the primary path as of ADR-0034, needs no second port at
all: the device generates its keypair, sends its **public line** to the server
operator however you already talk, and the server records it and generates the
client's config:

```bash
# on the server
sudo vallum peer add phone --config /etc/vallum/vallum0.toml \
    --public-key-file phone.pub --client-config-out phone.toml
```

`phone.toml` is the whole client configuration — the same three values
WireGuard's `[Peer]` stanza carries — and the device's private key never leaves
the device.

