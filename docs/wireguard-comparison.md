# Vallum and WireGuard: how a client connects

A side-by-side of the connection model, so the difference is a decision rather
than an accident. Grounded in the code, not in memory: the client config Vallum
emits is `crates/vallum/src/commands/peer.rs:2098`, and the enrolment protocol
is `crates/vallum/src/enroll.rs`.

## The short version

**They are the same model.** A client needs three values — the server's public
key, the server's endpoint, and the allowed IPs — and both products end there.
Vallum already emits exactly WireGuard's `[Peer]` stanza:

```toml
public_key = "<server_line>"
endpoint = "<endpoint>"
allowed_ips = [...]
```

WireGuard's whole enrolment story is "tell the server the client's public key,
by hand". Vallum's primary path is the same thing with the copy-paste done over
SSH:

```sh
sudo vallum setup --remote you@vpn.example.com
```

The client's key is generated on the client and only the **public line**
crosses the wire. No second port, no token, no daemon, no protocol.

## The comparison

| | WireGuard | Vallum |
|---|---|---|
| **client needs** | server public key, endpoint, allowed IPs | the same three, verbatim |
| **server needs** | client public key, out of band | the same, out of band — or via the ticket path below |
| **who generates the client's key** | the client | the client (`setup --remote`, `keygen`) |
| **who writes the client's config** | the operator, by hand | **the server**, with `peer add --client-config-out` |
| **second listening port** | none | `listen + 1` (51821), only for the ticket path |
| **token** | none | 128-bit, single use, expiry, admission tag |
| **secret files on the server** | none | `/run/vallum/enroll-*.json`, one per invite |
| **responder daemon** | none | `vallum-enroll@` — now **not enabled at boot** |
| **the operator's step** | copy a public line | one SSH command (or a copy-paste, manually) |
| **revocation** | delete the peer | delete the peer |
| **rotation** | new key, tell the peer | new key, tell the peer |

The last two rows are the same on both sides, which is the point: everything
WireGuard does with keys, Vallum does identically.

## Where Vallum has the extra machinery, and why

Vallum ships **three** enrolment paths, and only one of them is WireGuard's:

1. **`setup --remote` — the file path, and the default.** Local keygen, the
   public line crosses SSH, the server writes the peer and generates the
   client's config. This is WireGuard with the copy-paste automated.

2. **`peer invite` + `vallum join <ticket>` — the token path.** A 128-bit
   single-use token, a sealed exchange on `listen + 1`, an expiry, and a
   fingerprint pinned so the client knows which server it joined. It exists for
   the case where the client **cannot** reach the server over SSH — a device
   behind NAT, a phone, a machine someone else administers. That is a real
   case, and WireGuard has nothing for it.

3. **`import-bundle` — the offline path.** The server mints a bundle carrying
   the client's private key, which travels over a channel you trust. This is
   the weakest of the three: it puts a private key in a file, and it is the path
   where the recent hardening matters (a bundle may carry `[quick]` hooks, which
   `sh -c` as root — refused by default; see ADR-0033).

## What the comparison changed

**The responder is no longer enabled at boot.** Every peer already in the
server's config needs only 51820, so 51821 is now opened only for the seconds
an enrolment takes:

```bash
sudo ufw allow 51821/udp
sudo systemctl start vallum-enroll@vallum0
# ... the device joins ...
sudo systemctl stop vallum-enroll@vallum0
sudo ufw delete allow 51821/udp
```

See `docs/deployment/server.md`. This is the concrete step of
[ADR-0034](adr/0034-file-enrolment.md), whose decision is: **the file is the
enrolment; the token protocol is a convenience.**

## What the comparison did *not* change

**Vallum still needs the ticket path.** A device that cannot SSH to the server
has no other way in, and removing it would remove onboarding, not just
ceremony. ADR-0034 demotes the responder; it does not delete it.

**And the file path is not a downgrade.** WireGuard's model has survived a decade
because it is small enough to reason about: one config file, one public key
exchange, no protocol to get wrong. Vallum's file path is the same shape — it
just has a friendlier way to do the copy-paste, and a server that writes the
client's config so the client cannot fat-finger it.

## What is still only claimed

- The file path is proven by `scripts/accept-pair.sh`, which hand-writes the
  client config, runs `peer add` with the client's public line, and handshooks
  and carries — with no enrolment responder involved, on every push.
- What is **not** proven is the *SSH* variant (`setup --remote`), which needs a
  reachable server and a login. It is the same exchange with the transport
  automated, and it is worth its own gate.
