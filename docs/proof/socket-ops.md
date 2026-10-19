# G3 — socket and endpoint operations

**Status:** `SO_MARK`, hostname endpoints, and real port reporting.
**Depends on:** G2 (`uapi.md`) for the control surface that exposes them.
**Wire change:** none.

---

## 1. `fwmark`

```toml
[interface]
fwmark = 4660
```

- Applied as `SO_MARK` on the UDP socket in `UdpTransport::bind_with_fwmark`,
  **before** the privilege drop, so it works while `CAP_NET_ADMIN` is still
  held. `0` means unset.
- Failure is fatal: a configured mark that cannot be set is a policy-routing
  misconfiguration, not something to log and ignore.
- Reported by the UAPI (`fwmark=<decimal>`) and by `vallum show`.
- A runtime `set fwmark=` rebinds the socket with the new mark. The daemon binds
  the new socket first and swaps it in only on success; the reader picks it up
  after its read timeout. A failure (no `CAP_NET_ADMIN`, port in use) leaves the
  running socket untouched and is reported with the errno.

Why it matters: a mark is how a daemon participates in policy routing — a
kill-switch rule, a separate table, a VRF — without the daemon owning the
routing table.

---

## 2. Hostname endpoints

```toml
[[peer]]
endpoint = "vpn.example.com:51820"
```

- An address literal is used as written. Anything else is resolved at config
  load with `ToSocketAddrs`, retried `VALLUM_ENDPOINT_RESOLUTION_RETRIES` times
  (default 3, one second apart), and the first address is used.
- Not re-resolved periodically. A name that moves is a security-relevant change
  — the endpoint is where authenticated traffic is sent — so a move is an
  operator action (`syncconf`), not a silent refresh. This matches `wg`, which
  resolves at set time.
- A failure names the host and the last resolver error.

---

## 3. Port 0

`listen = "10.99.0.1:0"` binds an ephemeral port. The daemon logs the **bound**
address, not the configured `:0`, and the UAPI's `listen_port` reports the real
port. The configured value stays in `Resolved.listen` so `syncconf` does not
rewrite it.

---

## 4. Measured

- Config tests: `localhost:51820` resolves to a loopback address with the right
  port; `fwmark = 4660` reaches `Resolved.fwmark`.
- The e2e configures A with `listen = "…:0"` and `fwmark = 4660`, then asserts
  `show --dump` reports `fwmark=4660` and a `listen_port` that is not `0`; the
  tunnel still establishes, which is the proof the mark was accepted by the
  kernel.

---

## 5. What this does **not** claim

1. **Runtime `fwmark`/`listen_port` changes need the privilege to bind and to
   set `SO_MARK`.** The daemon attempts the rebind and reports `EPERM` if the
   deployment has dropped `CAP_NET_ADMIN`; the systemd unit keeps it as an
   ambient capability. The socket itself is swappable.
2. **No periodic DNS refresh.** Resolution is at load/set time.
3. **No DNS SRV or multiple-endpoint failover.** The first resolved address is
   used.
4. **No IPv6-specific mark semantics.** `SO_MARK` is family-independent.
