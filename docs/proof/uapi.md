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
  The mode is set before the path is published: the socket is bound and
  chmodded inside a `0700` staging directory beside the configured path, then
  hard-linked into place, so a permissive umask never exposes a connectable
  socket even briefly — and the name never exists without a listener behind it,
  so a client that connects the moment it appears is served rather than refused.
  An occupied path is refused with `EEXIST`, never replaced.
- Absent means no control plane.
- One request per connection: the client writes, shuts its write half, and reads
  the reply. All mutation is forwarded to the loop thread as
  `Input::Control` and applied there, so it never races a packet.

---

## 3. The protocol

`get=1` returns:

```
private_key=<hex seed>
vallum_private_key_path=<path>
listen_port=<port>
fwmark=<decimal>
public_key=<suite-sized KEM key, hex>
vallum_interface=<name>
vallum_public_line=<vallum1:…>
vallum_fingerprint=<16 hex>
vallum_listen=<addr:port>
vallum_address=<prefix>       (repeated)
vallum_can_set_private_key=true
vallum_can_set_listen_port=false
vallum_can_set_fwmark=true
vallum_offload=false
vallum_batching=false
vallum_suite=0x0003
# per peer:
public_key=<hex>
vallum_name=<config name>
vallum_fingerprint=<16 hex>
vallum_public_line=<vallum1:…>
preshared_key=<hex>            (only when set)
endpoint=<addr> | (none)
last_handshake_time_sec=<u64>
last_handshake_time_nsec=<u32>
tx_bytes=<u64>
rx_bytes=<u64>
persistent_keepalive_interval=<seconds, 0 = off>
allowed_ip=<prefix>            (repeated)
vallum_epoch=<u64>
vallum_valid_until=<unix seconds>   # only when the peer's identity is a document
vallum_rotating=<0|1>               # 1 while a previous identity is still accepted
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

`stop=1` asks the daemon to shut down, and takes no other line:

```
stop=1

```

It is answered `errno=0` *before* the daemon stops, and the daemon stops after
answering — a stop that replied from a process already gone would be
indistinguishable from a socket that died. It is the same permission as
signalling the pid (the socket is same-user and `0600`) without the part where
the caller has to find one. `vallum stop --control <socket>` sends it.

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

`show` prints a small human view with short fingerprints and peer names; it
**hides `private_key` and `preshared_key`**, as `wg show` does. `--field
private-key` or `--dump` are the explicit ways to see them. `--field` accepts
`endpoints`, `allowed-ips`, `latest-handshakes`, `transfer`,
`persistent-keepalive`, `preshared-keys`, `public-key`, `private-key`,
`listen-port`, `fwmark`, `peers`.

`showconf` exports the running device as a config: the interface name, listen
address, addresses, fwmark, and each peer's name, public line, endpoint,
allowed IPs and keepalive. By default it does **not** export secrets:
`private_key` is a placeholder path and PSKs are omitted with a comment.
`--include-secrets` uses the real key path and writes the PSKs, explicitly.

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

1. **`listen_port` and `fwmark` changes rebind the socket.** The daemon binds
   the new socket first and swaps it in only on success; the reader notices the
   generation change after its 250 ms read timeout. A failure leaves the running
   socket untouched and returns `EPERM`/`EADDRINUSE`/`EADDRNOTAVAIL`, which the
   CLI explains. `get` advertises the capability (`vallum_can_set_*`), and
   `syncconf`/`setconf` send the device fields, so a change is applied rather
   than silently ignored.
2. **`private_key` changes are accepted** and tear down every session and
   handshake, because they were authenticated as the old key.
3. **A PSK change applies to the next handshake.** The live session keeps
   running, as WireGuard does.
4. **No `set` with `wg`'s argv syntax.** The UAPI is complete; the CLI is
   config-based (`setconf`/`addconf`/`syncconf`).
5. **`showconf` hides secrets by default.** `--include-secrets` exports the
   key *path* (never the seed) and the PSKs. `vallum-quick save --in-place
   --include-secrets` replaces the config after writing a `.bak`; without both
   flags it refuses, because a secret-free export would silently drop them.
6. **No authentication beyond the socket mode.** Same user or root, as with the
   private key.
