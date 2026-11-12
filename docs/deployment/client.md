# Connecting a Linux client

A Vallum client is the same daemon as the server: one config, one key, one
service. What differs is the config — it dials an endpoint and routes traffic
into the tunnel instead of accepting it.

This guide assumes a server is already up. If not, start with
[server.md](server.md).

## What you need

- Linux with systemd.
- Root, or `sudo`.
- The client's config and key, from one of the four enrolment paths below. The
  first is the one the product leads with; all four end in the same place:
  `/etc/vallum/<name>.toml` and `/etc/vallum/<name>.key`, both `0600`, with
  the units installed.
- Outbound UDP to the server's port (default `51820`), or TCP to it if the path
  drops UDP ([below](#if-the-path-blocks-udp)).

## Path A — the server wrote you a config

The path the product leads with, and the one with the best custody: **the
private key never leaves the device.**

On the device, the key is made first:

```sh
sudo vallum keygen --output laptop.key
sudo vallum pubkey --private-key laptop.key     # send this line to the server
```

On the server, that public line becomes a peer, and a config that **names**
`laptop.key`:

```sh
sudo vallum peer add laptop --public-key-file laptop.pub \
    --client-config-out laptop.toml
```

Copy `laptop.toml` to the device, beside `laptop.key`, and install it:

```sh
sudo vallum setup --client-config laptop.toml
```

That writes `/etc/vallum/laptop.toml` and `/etc/vallum/laptop.key` (both
`0600`), installs the units, starts `vallum@laptop` and `vallum-quick@laptop`,
proves the tunnel, and prints the `status` command to check it.

The config names its key as a bare file name (`private_key = "laptop.key"`),
and a relative path resolves against the config's own directory — so the pair
works wherever the two files sit together. The name matters: the server names
the key after the **peer**, so `peer add laptop` expects `laptop.key`, and a
keyfile called anything else is renamed into place when the config is
installed.

If the key is not beside the config, the command says so and tells you the
command that creates it — the key never has to come from anywhere else.

## Path B — over SSH

```sh
sudo vallum setup --remote you@vpn.example.com
```

The key is generated here and only the public line crosses. The server must
have `vallum` installed and passwordless sudo for that user; the error names
which of those is missing.

## Path C — a one-time ticket

For a device that cannot reach the server over SSH. The server mints a ticket
and the device redeems it:

```sh
sudo vallum peer invite laptop          # on the server
sudo vallum join vallum1-join:…          # on the device
```

The responder answers on UDP `51821`, which must be open in the cloud security
group as well as on the host — for the enrolment only. One use, fingerprint
pinned, no private key on the wire.

## Path D — the server handed you a bundle

A `.vallum-bundle` is a JSON file containing the config **and the client's
private key**. The key was generated on the server and travelled in the file,
so anyone holding the file holds the key — which is why this import is
**refused by default**:

```sh
sudo vallum import-bundle laptop.vallum-bundle --install
```

```
vallum: refusing this bundle: it carries this client's PRIVATE KEY.
...
Generate the key on the device instead - it never has to leave:
   vallum keygen --output <name>.key
   vallum pubkey --private-key <name>.key   # send this line to the server
```

If you understand and accept that, `--allow-shipped-key` says so explicitly.
The other three paths never need it, because they never move the key.

## Verify

```sh
sudo vallum doctor --config /etc/vallum/laptop.toml
sudo vallum show   --config /etc/vallum/laptop.toml
ping -c 3 10.7.0.1
```

`doctor` checks the config, the control socket, the unit state, and the config's
permissions. A connected client shows a peer with a recent handshake:

```
peer "server"  10.7.0.1/32  endpoint 203.0.113.5:51820  handshake 12s  rx 1.2K tx 980
```

If the handshake stays at `never`, see [troubleshooting.md](troubleshooting.md).

## Full tunnel vs split tunnel

The server writes `allowed_ips = ["0.0.0.0/0", "::/0"]`, which routes everything
through the tunnel. For a split tunnel, narrow it to the networks the server
should carry:

```toml
[[peer]]
name = "server"
public_key = "vallum1:0003:…"
endpoint = "203.0.113.5:51820"
allowed_ips = ["10.7.0.0/20", "192.168.50.0/24"]
persistent_keepalive = 25
```

`vallum-quick` adds one route per prefix on `up`, and removes them on `down`.

## DNS

```toml
[quick]
dns = ["1.1.1.1"]
table = "auto"
```

`vallum-quick` picks the backend the host actually has:

- **systemd-resolved**, detected by `resolvectl` being present *and*
  `/run/systemd/resolve` existing — installed but disabled is a real state, and
  calling `resolvectl` there fails. It runs `resolvectl dns` and, on a full
  tunnel, claims the `~.` routing domain so no query leaks to the local resolver.
  `detach` runs `resolvectl revert`.
- **resolvconf**, otherwise, through `resolvconf -a`.

If neither exists, DNS is left to the host and `vallum-quick` says so.
`vallum-quick attach <config> --dry-run` prints the commands the chosen backend
would run, which is the fastest way to see which path you are on.

## Expiring a credential without a CA

If you generated your own key, you can still attach a validity window:

```sh
sudo vallum identity self-sign --key /etc/vallum/laptop.key \
    --label laptop --days 90 --output laptop.identity
```

Give the document to the server (`vallum peer add laptop --identity
laptop.identity`) on an interface with no `identity_issuer`. Anyone can mint a
self-signed document, so this is a rotation aid, not an authorisation — for that,
the server needs a CA key.

## MTU

The default inner MTU is 1500. On a path that cannot carry that — PPPoE at 1492,
an IPsec or WireGuard outer tunnel — set the outer MTU so the daemon segments
instead of letting the kernel fragment:

```toml
[interface]
outer_mtu = 1400
```

## If the path blocks UDP

A config the server writes says nothing about the transport, so both ends use the
default: UDP. Where that is dropped — a hotel, a campus, some mobile carriers —
both ends need the stream carrier, because one side speaking TCP to a UDP listener
is silence rather than an error ([ADR-0026](../adr/0026-censorship-resistance.md)):

```toml
[interface]
carrier = "tcp"
```

Open the TCP port instead of the UDP one, and restart both daemons: the config is
read at start. The same packets then travel inside one connection per peer,
framed and about 1 % larger, delivered in one order, and the peer cannot roam.
`vallum doctor` prints the carrier it is using, and `--probe-path` dials each
peer's endpoint — the one check that separates a blocked port from a server that is
not listening. What the carrier costs on a lossy path is measured in
[`proof/transport.md`](../proof/transport.md#28-a-stream-carrier-and-what-it-would-cost).

## If the server shaped the config

`vallum peer add <you> --shaping balanced` (or `opening`) writes `[[peer.shaping]]`
blocks into the config it hands you, so nothing needs copying by hand. Those blocks
are this device's own policy — they shape what *this* end sends — and the server's
config is separate, because shaping is local and never negotiated. A config with no
such blocks shapes nothing, which is the default; what each preset does, and what
it costs, is in [`shaping.md`](../shaping.md#presets).

## Keeping the path open

`persistent_keepalive = 25` sends an empty packet every 25 seconds when idle, so
a NAT binding on the client side does not expire. It is written by default in
server-generated configs; keep it on any client behind NAT.

## Operate it

```sh
sudo systemctl status vallum@laptop
sudo journalctl -u vallum@laptop -f
sudo vallum tui --config /etc/vallum/laptop.toml
```

The terminal cockpit reads the control socket; day-to-day monitoring does not
need root if the socket's owner is your user.

## Remove it

```sh
sudo systemctl disable --now vallum-quick@laptop vallum@laptop
sudo rm -f /etc/vallum/laptop.toml /etc/vallum/laptop.key
```

On the server, `vallum peer remove laptop` stops routing the address to this
device. The client's key files are left in place on the server by design — delete
them by hand if the device is gone for good.

## File ownership rule

Every file the daemon reads must be **owned by the user it runs as** — normally
root for the config and key. The unit's capability bounding set has no
`CAP_DAC_OVERRIDE`, so root is only root for files it owns: a config copied in as
another user fails with `Permission denied` even though the operator can read it
in a shell. `install.sh` sets this up; anything hand-placed should be
`chown root:root` and `chmod 600`.
