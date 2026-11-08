# Troubleshooting a deployment

Start with `doctor`. It checks the things that are wrong most often, in the order
they fail:

```sh
sudo vallum doctor --config /etc/vallum/vallum0.toml
```

To validate a whole host install — sysctl persistence, the firewall and NAT
rules, the systemd units, a real client through `resolvectl`, and live
rotation — run the privileged half of the test gate:

```sh
sudo ./scripts/verify-host.sh
```

It uses dedicated names (`vallumtest0`/`1`, UDP 51921, `10.99.77.0/24`), asserts
every change it makes, and restores the host on exit. It refuses to run if
`/etc/vallum` or `inet vallum` already exist, so it cannot disturb a real
deployment.

| Check | A failure means | Fix |
|---|---|---|
| `platform` | not Linux | Linux is the supported tier this release |
| `config` | the TOML does not parse, a prefix is wrong, a peer's key is the wrong suite or length, an endpoint does not resolve | the message names the peer and the field |
| `control` | the control socket is not there | `systemctl start vallum@<instance>`; the daemon creates it |
| `forwarding` | `ip_forward` is off | `vallum server init` enables it, or `sysctl -w net.ipv4.ip_forward=1` |
| `firewall` | the port is not open | `ufw allow 51820/udp`, plus `/tcp` if `carrier = "tcp"`; or the nftables chain that drops it |
| *(only with `--probe-path`, and only on tcp)* | the path blocks the port between the hosts | set `carrier = "tcp"` in `[interface]` on **both** ends and open the TCP port: the same packets, framed, about 1 % larger, and 10–12× slower at 2 % loss on a 1 ms path (265× on a 40 ms one) ([ADR-0026](../adr/0026-censorship-resistance.md)) |
| `service` | the unit is inactive or failed | `journalctl -u vallum@<instance>` |
| `config mode` | the config is group/world readable | `chmod 600`, because it can name a PSK file |
| `rotation` | a peer still accepts a previous key | `vallum peer finalize <name>` once the device has the new one |
| `path-mtu` | `doctor --probe-mtu` found a smaller path than `outer_mtu` | set `interface.outer_mtu` to the measured value |
| `carrier` | never fails: it names the transport in use | nothing, unless both ends disagree — `carrier = "tcp"` on one side and the default on the other is silence, not an error |
| `path` | `doctor --probe-path` could not open a TCP connection to a peer's endpoint | the port is closed or filtered, or the far end is not on `carrier = "tcp"`; under UDP the check reports that it cannot probe instead |

## The service will not start

**`status=203/EXEC`** — systemd cannot execute the path in the unit. The unit runs
`/usr/bin/vallum`; a binary in `/usr/local/bin` is not found. Reinstall with
`scripts/install.sh`, which writes both the unit and the binary to the same
place.

**`status=226/NAMESPACE`** — the unit binds `ReadWritePaths=/run/vallum`, and a
missing path is a namespace failure, not a permission problem. The directory is
created by `/usr/lib/tmpfiles.d/vallum-tmpfiles.conf` (installed by the package,
which runs `systemd-tmpfiles --create` from its post-install hook). If it is
absent, run `systemd-tmpfiles --create /usr/lib/tmpfiles.d/vallum-tmpfiles.conf`.
A unit from before 1.6.2 had `RuntimeDirectory=vallum`, which created the
directory inside the service's own mount namespace — where the host, and every
other daemon, could not see it. Reinstall the package to replace that unit.

**`CAP_NET_ADMIN`** — the daemon needs it to create the interface. The unit grants
it; running `vallum run` by hand does not. Use `sudo`, or `setcap` the binary.

## The tunnel is up, but nothing routes

Check in this order:

1. **Is the peer's handshake recent?** `vallum show` — `never` means the
   handshake did not complete, which is a key, endpoint, or port problem, not a
   routing problem.
2. **Is forwarding on?** `sysctl net.ipv4.ip_forward` must be `1` on a server.
3. **Is the port open?** `vallum doctor` checks the host firewall. A cloud
   security group is separate and Vallum cannot see it.
4. **Is the route there?** `ip route get 10.7.0.2` on the client, `ip route` on
   the server. `vallum-quick attach` adds one route per `allowed_ips` prefix.
5. **Did the client's `allowed_ips` narrow the tunnel?** A split tunnel only
   carries the prefixes it names.

## Handshake never completes

- **Endpoint wrong or unreachable.** `nc -u -z <server> 51820`, or watch the
  server's `journalctl -u vallum@vallum0` for a rejected handshake.
- **UDP is blocked somewhere on the path.** A network — a hotel, a campus, a
  corporate egress, some mobile carriers — that drops UDP drops the default
  tunnel, and nothing detects it for you: a silent filter looks from the client
  exactly like a server that is not answering. Test the path from the client, not
  from the server (`nc -u -z <server> 51820` succeeds against a filter that
  silently drops), then compare `vallum show` on both ends — a client whose
  handshake is `never` and a server with no rejected handshake at all is a path
  problem, not a key problem. The one answer is the fallback in
  [ADR-0026](../adr/0026-censorship-resistance.md): put `carrier = "tcp"` in
  `[interface]` on **both** ends and open the TCP port. It carries the same
  packets, framed, about 1 % larger, in one order, and a peer cannot roam under
  it. On TCP the question is answerable rather than guesswork: `vallum doctor
  --config … --probe-path` dials each peer's endpoint, so a refusal or a timeout
  names the side that is not listening.
- **Suite mismatch.** A peer key generated with `--suite 2` on a `0x0003` server
  is refused at load time with the two suites named. Regenerate with the server's
  suite.
- **Clock skew.** Timestamps are TAI64N; a host minutes off will have handshakes
  rejected. Check `timedatectl`.
- **PSK mismatch.** If the peer has a preshared key, the client must have the same
  one. `vallum peer show <name>` says whether one is set.
- **Key permissions.** A key readable by group or world is refused, not warned
  about. `chmod 600`.
- **An expired identity document.** The document's window is checked at load and
  at every handshake; the daemon logs `identity document expired` and `peer list`
  shows `EXPIRED`. Issue a new document and `peer add`/`peer rotate` it.
- **A pinned peer answering from a new address.** `pin_endpoint` refuses it by
  design; remove the pin if the device genuinely roams.

## A client and a server on the same host

A full-tunnel client installs a catch-all policy rule (`ip rule … lookup
<table>`). On the same host as a server, that rule also catches the server's
*forwarded* packets, which come straight back into the tunnel and loop until the
TTL expires. Symptoms: the tunnel itself pings, but nothing reaches the
internet. `wg-quick` behaves the same way.

Put the client on its own machine, or in its own network namespace. The
privileged test gate does exactly that (`scripts/verify-host.sh`).

## It connects, then stops after a while

- **NAT binding expired.** Set `persistent_keepalive = 25` on the client.
- **Rekey failed.** The epoch rekeys with a fresh handshake; a path that drops
  large datagrams will fail it. Set `outer_mtu` to the real path MTU.
- **Address overlap.** Two peers claiming the same prefix is refused at load, but
  a peer added while the daemon runs is applied through the control socket, which
  refuses it too — check `vallum peer list` for a duplicate.

## MTU problems

Symptom: SSH and ping work, large transfers hang. The outer path cannot carry the
inner MTU.

Measure it instead of guessing:

```sh
sudo vallum doctor --config /etc/vallum/vallum0.toml --probe-mtu 203.0.113.5
```

That bisects ICMP payload sizes with `ping -M do` and prints the largest that
crosses, or says it is inconclusive because ICMP is filtered. Then:

```toml
[interface]
outer_mtu = 1400
```

Every datagram is cut to `outer_mtu - 48` so the kernel is never asked to
fragment. Values above 1500 are refused: the protocol's parse cap is built on it.

## DNS does not work on the client

`vallum-quick` chooses between systemd-resolved and `resolvconf`. See which one
it will use:

```sh
sudo vallum-quick attach /etc/vallum/laptop.toml --dry-run
```

It prints `resolvectl dns …` plus `resolvectl domain … ~.` on a full tunnel, or
`resolvconf -a …`, or says neither is installed.

- **On resolved, queries still go to the local resolver.** The `~.` domain is
  what claims all names; check `resolvectl domain vallum0` and that the config
  routes `0.0.0.0/0`.
- **On a split tunnel**, no domain is claimed on purpose: only the names that
  resolve inside the tunnel should go there.
- **Ubuntu 24.04** ships `resolvconf` as a resolved shim that fails for
  `wg-quick`-style interface names. Vallum prefers `resolvectl` when resolved is
  running, which avoids it.

## Reading the logs

```sh
sudo journalctl -u vallum@vallum0 -f
```

`[log] level = "debug"` in the config raises the threshold. The TUI's log view
(`vallum tui`, then `l`) colourises the same stream by severity.

## Starting over

The config and key are the only state:

```sh
sudo cp -a /etc/vallum /etc/vallum.bak
sudo vallum server init --force --endpoint <host:port>
```

`--force` rewrites the config and keeps a timestamped backup; it never
regenerates the key, so existing clients keep working. To start completely
fresh, move `server.key` aside first and re-enrol every client.

## Ping works through the tunnel, DNS and TCP do not

The classic half-broken server, and the most misleading one, because ICMP is the
one protocol that gets through by accident.

On Ubuntu, ufw ships `DEFAULT_FORWARD_POLICY="DROP"` but its
`before-forward` chain accepts ICMP echo. So a server with NAT and no forwarded
accept rules will answer `ping` from a client and silently drop every TCP and
UDP packet. A ping is therefore **not** proof that forwarding works — `dig` or a
TCP connection is.

`vallum server init` adds the accept rules where the drop lives (`iptables
-I FORWARD -i <iface> -j ACCEPT`, and the reverse), and `doctor` reports a
forwarding path that is filtered even when the sysctl is on. If the rules were
added before this existed, `vallum server init --force` re-applies them.

## A client in a namespace on the server's host

Not a supported topology, and not a reliable test one. On a host with
third-party netfilter (Docker, Tailscale) the server's replies are read from its
TUN and never transmitted, so the tunnel pings from the server side and never
from the client side. The same topology forwards correctly on a plain host, so
`scripts/verify-host.sh` reports it as a note rather than a failure.

Test client egress where it really lives: a second machine, or the namespace E2E
(`scripts/e2e-netns.sh`), which is the gate of record for it.
