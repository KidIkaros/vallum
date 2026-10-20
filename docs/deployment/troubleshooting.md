# Troubleshooting a deployment

Start with `doctor`. It checks the things that are wrong most often, in the order
they fail:

```sh
sudo vallum doctor --config /etc/vallum/vallum0.toml
```

| Check | A failure means | Fix |
|---|---|---|
| `platform` | not Linux | Linux is the supported tier this release |
| `config` | the TOML does not parse, a prefix is wrong, a peer's key is the wrong suite or length, an endpoint does not resolve | the message names the peer and the field |
| `control` | the control socket is not there | `systemctl start vallum@<instance>`; the daemon creates it |
| `forwarding` | `ip_forward` is off | `vallum server init` enables it, or `sysctl -w net.ipv4.ip_forward=1` |
| `firewall` | the UDP port is not open | `ufw allow 51820/udp`, or the nftables chain that drops it |
| `service` | the unit is inactive or failed | `journalctl -u vallum@<instance>` |
| `config mode` | the config is group/world readable | `chmod 600`, because it can name a PSK file |

## The service will not start

**`status=203/EXEC`** — systemd cannot execute the path in the unit. The unit runs
`/usr/bin/vallum`; a binary in `/usr/local/bin` is not found. Reinstall with
`scripts/install.sh`, which writes both the unit and the binary to the same
place.

**`status=226/NAMESPACE` or a read-only `/run`** — the unit expects
`RuntimeDirectory=vallum`. An old unit without it, plus `ProtectSystem=strict`,
leaves `/run/vallum` unwritable. Reinstall the unit.

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
- **Suite mismatch.** A peer key generated with `--suite 2` on a `0x0003` server
  is refused at load time with the two suites named. Regenerate with the server's
  suite.
- **Clock skew.** Timestamps are TAI64N; a host minutes off will have handshakes
  rejected. Check `timedatectl`.
- **PSK mismatch.** If the peer has a preshared key, the client must have the same
  one. `vallum peer show <name>` says whether one is set.
- **Key permissions.** A key readable by group or world is refused, not warned
  about. `chmod 600`.

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

```toml
[interface]
outer_mtu = 1400
```

Every datagram is cut to `outer_mtu - 48` so the kernel is never asked to
fragment. Values above 1500 are refused: the protocol's parse cap is built on it.

## DNS does not work on the client

`vallum-quick` installs DNS through `resolvconf` when it exists. Without it:

```sh
resolvectl dns vallum0 1.1.1.1
resolvectl domain vallum0 '~.'
```

Check `vallum-quick attach` output: it prints the `resolvconf` call, or says DNS
was left to the host.

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
