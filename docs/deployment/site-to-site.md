# Site-to-site: two networks, one tunnel

Two Vallum hosts, each already set up with `vallum server init`, can route
between their networks. Neither is a "client": both listen, both have peers with
endpoints, and neither masquerades the other's traffic.

## Topology

```
192.168.10.0/24 ── host A (10.7.0.1) ══ tunnel ══ host B (10.7.0.2) ── 192.168.20.0/24
```

A's tunnel address is `10.7.0.1`, B's is `10.7.0.2`. Each routes the *other's*
LAN subnet into the tunnel.

## 1. Point them at each other

On A, enrol B. B generated its own key, so only the public line travels:

```sh
# on B
sudo vallum keygen --output /etc/vallum/server.key --suite 3 > b.pub

# on A
sudo vallum peer add host-b \
    --public-key-file b.pub \
    --address 10.7.0.2/32 \
    --allowed-ips 10.7.0.2/32,192.168.20.0/24 \
    --endpoint 198.51.100.20:51820
```

`--allowed-ips` is the routing rule: packets to `192.168.20.0/24` go to B. The
peer's own tunnel address is included so the tunnel itself is reachable.

Do the mirror on B, with `--allowed-ips 10.7.0.1/32,192.168.10.0/24` and
`--endpoint 198.51.100.10:51820`.

## 2. Turn NAT off

A site-to-site link routes real addresses; masquerading them would hide the
source. Remove the NAT table on both:

```sh
sudo nft delete table inet vallum
```

`vallum server init` installs it because a roaming-client server needs it. A
site-to-site host does not, and can be initialised with `--no-nat` from the
start.

## 3. Let the LANs through

Forwarding is already on (the daemon's host was set up as a server). The LAN
interfaces need to accept traffic to and from the tunnel; on an nftables host
with a drop policy:

```sh
nft add rule inet filter forward iifname "vallum0" accept
nft add rule inet filter forward oifname "vallum0" accept
```

`vallum server init` adds these for `vallum0`; if your LAN interface has its own
policy, mirror the pair for it.

## 4. Advertise the routes

Hosts on `192.168.10.0/24` need to know that `192.168.20.0/24` is behind A. Either
add a static route on the LAN router pointing at A's LAN address, or add the
route on each host. Vallum does not speak a routing protocol; it moves packets
for prefixes you name.

## 5. Verify

```sh
# from a host on A's LAN
ping 192.168.20.10

# on A
sudo vallum show --config /etc/vallum/vallum0.toml
```

The peer's handshake should be recent and its transfer counters should move. If
the tunnel is up but the ping fails, the problem is routing or forwarding, not
the handshake — check `vallum doctor` and the forward chain.

## Notes

- **Both sides need an endpoint** if both dial; a site-to-site link with one
  static address works too — leave the endpoint off on the side that roams.
- **Overlapping LANs cannot be routed.** `192.168.1.0/24` on both sides is
  ambiguous; renumber one.
- **MTU.** A site-to-site link that itself runs over another tunnel needs
  `outer_mtu` set on both sides to the smaller path.
- **Dual stack.** Give each host one v4 and one v6 tunnel address and put both
  remote prefixes in `--allowed-ips`; the data plane carries either family.
