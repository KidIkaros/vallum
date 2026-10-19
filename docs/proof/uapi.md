# G2 — the control plane (WireGuard-style UAPI)

**Status:** a Unix-socket control plane with `get=1`/`set=1`, live peer
mutation, counters, and the `show`/`setconf`/`addconf`/`syncconf` CLI.
**Depends on:** P6.4 (the daemon loop), G1 (the PSK this can update).
**Wire change:** none.

---

## 1. Why

WireGuard's operator surface is `wg show`/`set`/`setconf`/`addconf`/`syncconf`
over a key/value UAPI. Vallum was startup-only: no status, no live peers, and
every change meant a restart and a dropped session. This phase adds the same
surface, with the same key names for the common fields.

---

## 2. The socket

```toml
[interface]
control = "control.sock"   # relative to the config; or an absolute path
```

- A Unix listener, mode **0600**, same-user only. It is the same trust boundary
  as the private-key file; a world-writable socket would be a remote `set`.
- Absent means no control plane.
- One request per connection: the client writes, shuts its write half, and reads
  the reply. All mutation is forwarded to the loop thread as
  `Input::Control` and applied there, so it never races a packet.

---

## 3. The protocol

`get=1` returns:

```
private_key=<hex seed>
listen_port=<port>
fwmark=<decimal>
public_key=<suite-sized KEM key, hex>
vallum_suite=0x0003
# per peer:
public_key=<hex>
preshared_key=<hex>            (only when set)
endpoint=<addr> | (none)
last_handshake_time_sec=<u64>
last_handshake_time_nsec=<u32>
tx_bytes=<u64>
rx_bytes=<u64>
persistent_keepalive_interval=<seconds, 0 = off>
allowed_ip=<prefix>            (repeated)
vallum_epoch=<u64>
errno=0
```

`set=1` accepts device fields before the first `public_key`:

`private_key`, `listen_port`, `fwmark`, `replace_peers`, and then per peer:
`public_key`, `preshared_key`, `endpoint`, `persistent_keepalive_interval`,
`allowed_ip`, `remove`, `update_only`, `replace_allowed_ips`.

- **Keys are suite-sized, not WireGuard's 32 bytes.** The tri-hybrid KEM public
  key is 2 374 bytes; the control layer validates the length against the suite.
  `private_key` (the seed) and `preshared_key` remain 32 bytes.
- `preshared_key` all-zero clears it; `endpoint=(none)` clears the endpoint.
- `remove` marks the peer dead; the table is append-only, so a `PeerId` never
  comes to mean a different peer.
- `update_only` on an absent peer is `ENOENT`.
- Overlapping `allowed_ips` is `EINVAL`; adding a duplicate peer is `EEXIST`.
- Unknown keys are refused, not ignored.

`errno=0` is success; `errno=<positive>` is the failure.

---

## 4. CLI

```
vallum show --control <socket> [--dump] [--field endpoints]
vallum show --config <file> --dump
vallum setconf <config>      # replace every peer
vallum addconf <config>      # add/update the config's peers
vallum syncconf <config>     # diff: remove absent, update present, add new
vallum genpsk
```

`show` prints a small human view; `--dump` prints the raw `get` response;
`--field` accepts `endpoints`, `allowed-ips`, `latest-handshakes`, `transfer`,
`persistent-keepalive`, `preshared-keys`, `public-key`, `private-key`,
`listen-port`, `fwmark`, `peers`.

`syncconf` reads `get`, removes peers the config no longer names, and updates the
rest with `replace_allowed_ips=true`; a peer whose key and endpoint are unchanged
keeps its session.

---

## 5. Measured

- Codec tests: `get`/`set` parsing, clearing a PSK/endpoint, unknown keys, bad
  values, and the rendered `get` shape.
- Control tests: a `set` adds a peer and `get` reports it; `remove` makes it
  disappear; `update_only` on an absent peer is `ENOENT`.
- The e2e creates a socket, asserts `show --dump` ends with `errno=0`, asserts
  `show` reports the interface and peer, and runs `syncconf` against an unchanged
  config.

---

## 6. What this does **not** claim (yet)

1. **`listen_port` and `fwmark` changes are `EOPNOTSUPP`.** They need a socket
   rebind; the plan's next cut is the `SocketHandle` swap. A `set` that repeats
   the current value is accepted, so `syncconf` is idempotent.
2. **`private_key` changes are accepted** and tear down every session and
   handshake, because they were authenticated as the old key.
3. **A PSK change applies to the next handshake.** The live session keeps
   running, as WireGuard does.
4. **No `set` with `wg`'s argv syntax.** The UAPI is complete; the CLI is
   config-based (`setconf`/`addconf`/`syncconf`).
5. **No `showconf`.** `show --dump` is the machine-readable form; `vallum-quick`
   will render a config from it.
6. **No authentication beyond the socket mode.** Same user or root, as with the
   private key.
