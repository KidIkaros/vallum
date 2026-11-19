# Responding to a key or credential compromise

Three secrets can leak, and they are not the same incident: an **account
token** (a desk credential), a **peer private key** (a device key), or the
**server key** (the host's identity). The desk owns account policy; the daemon
owns the peers ([ADR-0047](../adr/0047-the-account-is-not-the-device.md)).
Private keys are generated on the device and stay there — the server never
holds a client private key unless an operator explicitly opted into
`--ship-key` ([ADR-0013](../adr/0013-server-provisioning.md)). Containment
means making the **daemon** stop accepting the leaked secret, then proving it
stopped. A config edit or a desk row alone is not containment.

> **Verify daemon reality, not config.** The live alpha server runs with two
> peers — `laptop` and `lab8` — whose config fingerprint differs from the
> daemon's session fingerprint; `doctor` warns on both (the `laptop` case is
> #34, recorded in
> [ADR-0047](../adr/0047-the-account-is-not-the-device.md)). The tunnel kept
> answering while the two surfaces disagreed. Every "it is revoked" claim in
> this runbook is checked against `vallum show` / `vallum metrics`, because
> the daemon is the physical truth.

## 1. Detect

How a leak surfaces, in the order you are likely to see it:

| Signal | Where | What it means |
|---|---|---|
| `peer sync` WARN | `vallum doctor` | a peer's config key ≠ the running daemon's session key — the tunnel is not running what the config says; a rotation never applied, an edit never synced, or something changed the daemon behind the config's back |
| `handshakes` WARN/FAIL | `vallum doctor` | refused initiations, named by reason: failed admission (wrong server-key copy, or spoofing), unknown peer (a stale client config — or a removed peer still dialling), pinned-endpoint conflict, stale timestamp (replay or a stepped clock). FAIL names a peer whose authenticated messages were rejected: the far end's key is not the one enrolled |
| Unexpected endpoint or traffic | `vallum show` | a peer answering from an address it never used, or bytes on a device that should be idle. A `pin_endpoint` peer refuses other addresses by design; an unpinned one roams — or is being impersonated |
| Counter anomaly | `vallum metrics` | `vallum_loop_handshakes_refused_total` climbing (`VallumHandshakesRefused`), unknown-index drops (`VallumLoopDroppedUnknownIndex`), a handshake rate far above the ~0.008/s steady-state rekey, `vallum_peers_total` above the expected count |
| Rejected handshakes in the log | `journalctl -u vallum@vallum0` | the daemon names what it refused and why |
| A device the user does not recognise | desk account page, `vallum-desk-admin devices` | the account page lists devices with their last handshake, read from the daemon — an unknown device is an enrolment you did not make |
| User report | help channel | "my account shows a device I don't own", "my laptop was stolen", "I pasted my token somewhere public" — take it as a detection, not a support ticket |

The working set:

```sh
sudo vallum doctor  --config /etc/vallum/vallum0.toml
sudo vallum show    --config /etc/vallum/vallum0.toml --json
sudo vallum metrics --config /etc/vallum/vallum0.toml
sudo vallum peer list    --config /etc/vallum/vallum0.toml
sudo vallum peer invites --config /etc/vallum/vallum0.toml   # unspent invites + TTL
sudo journalctl -u vallum@vallum0 -f
```

`peer list` is the **config's** claim (fingerprints, `ROT yes` for an open
rotation, `EXPIRED` for a lapsed identity document); `show --json` is the
**daemon's** (per peer: `name`, `fingerprint`, `endpoint`, `last_handshake`,
`tx_bytes`/`rx_bytes`). Read both. `peer invites` prints no tokens — an
unspent invite is a live credential until it is spent, expires, or is revoked.

## 2. Triage

Classify by **which secret leaked**. The blast radius decides the containment.

| Class | Leaked secret | What the holder can do | Blast radius |
|---|---|---|---|
| **(a) Account token** | the desk account number (32-hex bearer credential) | enrol devices under the account (`POST /api/devices`; the account-page path is single-use but **unpinned** — the enroling client generates its own key at join), read plan/quota/status, revoke or rotate the account's own devices | one account: its device slots and shared byte cap. In the flat personal topology an enrolled device reaches the other peers. Other accounts are untouched |
| **(b) Peer private key** | a device's `<name>.key` | join **as that device** — the daemon admits the key, not the machine | one peer slot: that device's address, quota and whatever its `allowed_ips` and the tenancy mode permit |
| **(c) Server key** | the interface's `private_key` — `vallum0.key` on a fresh init, `server.key` on older installs | answer **as the server** to every client; impersonate the endpoint | every tunnel on the interface. The same directory holds `desk-admin-token`, `desk.sqlite` and any server-generated client keys — if the leak came from host access, assume all of it is compromised |

Escalation paths between the classes:

- **A compromised device may also leak its account token.** The client config's
  `[account]` table carries the token (written 0600 at join,
  [ADR-0046](../adr/0046-the-client-reads-its-account-from-the-desk.md)). Treat
  a stolen laptop as a possible class (a) as well as (b).
- **A server-key leak from host access is also a desk breach.** The admin token
  and the account database live in `/etc/vallum` and `/var/lib/vallum` on the
  same host. Class (c) containment covers them.
- **A token leak is not a key leak.** The desk holds no private keys
  ([ADR-0045](../adr/0045-the-desk-is-the-account-layer-keys-only.md)); the
  tunnels keep working after an account revoke until their peers are removed.
  Conversely, if the device was enrolled with `--ship-key --bundle-out`, a
  server-side copy of its key may sit in `/etc/vallum/clients/` — a server
  breach then leaks that device key too.

If you cannot tell which secret leaked, contain at the **higher** class: a
peer remove is cheap; an uncontained server key is not.

## 3. Contain

### (a) Account token — revoke the account

The admin token is read from `/etc/vallum/desk-admin-token`, never argv.

```sh
# any device of the account addresses the whole account:
sudo vallum-desk-admin revoke --peer u0007-laptop --account

# a device-less account is addressed by its number, kept out of ps:
sudo vallum-desk-admin revoke --token-file /root/leaked-account.txt --account
```

**Why this order matters:** the desk removes the account's peers from the
daemon **first**, then marks the account `revoked`. A failed removal returns
`502` and leaves the row active so the sweep retries — a row marked revoked
while its peer still answers is a live peer no longer enforced. After the
revoke, the leaked token is refused (`403 account is revoked`) on every
device/status call.

**Lost the number, not the account?** If the account still has a device,
`sudo vallum-desk-admin reset-token --peer u0007-laptop` issues a fresh number
and retires the old immediately; the devices, plan, quota and expiry survive
([ADR-0047](../adr/0047-the-account-is-not-the-device.md) Q3). Reset does not
un-revoke a revoked account — revocation is permanent, and a revoked account
recovers as a new account (§4). A device-less account whose number is lost cannot be
addressed by `reset-token` (no peer, no token), but the operator can still read its number
from `vallum-desk-admin accounts --json` by label — there is no PII to verify the requester
owns it, so recovery is operator-mediated and impersonation-risky; rebuild from a minted
code when ownership cannot be established.

One device's key leaked, not the token? That is class (b): revoke just the
device (`vallum-desk-admin revoke --peer <name>`, no `--account`). The account
and its other devices keep working.

### (b) Peer private key — remove the peer

```sh
sudo vallum peer remove laptop --config /etc/vallum/vallum0.toml
# if the server ever generated this device's key (--ship-key / bundle path):
sudo vallum peer remove laptop --config /etc/vallum/vallum0.toml --forget-key
```

**Why removing the peer stops admission:** `peer remove` edits the config
(timestamped backup), revokes any unspent invite for that name, and pushes the
change through the control socket. `syncconf` sends `remove=true` for the
departed key; the daemon marks the peer removed, **drops its live session and
handshake state**, and forgets its index. The tunnel dies immediately, and
every later handshake from the leaked key is dropped as an unknown peer.
`--forget-key` additionally deletes the server's copies
(`clients/<name>.key`, `clients/<name>.psk`); without it the report names
exactly which files remain — "the device is gone" and "the server has
forgotten the device" are different claims.

The report's `applied` line is the one to read: `no — no control socket at …`
means no daemon holds the peer; `no — the config declares no control socket`
means a running daemon **was not told** and still holds it until it reloads.
`--json` gives the same facts for a play (`{name, allowed_ips, config, backup,
applied, forgotten, remaining}`; exit `1` if the name is absent — see
[automation.md](automation.md)).

Desk-managed devices: `sudo vallum-desk-admin revoke --peer <name>` performs
the same daemon removal and marks the desk row `removed`. The account owner
can self-serve the same act from the account page (`POST /api/devices/revoke`,
bearer token must own the peer).

**Do not contain with `rotate`.** A rotation keeps the old key accepted as a
*previous* identity until `peer finalize`
([ADR-0021](../adr/0021-live-rotation-syncconf.md)) — the leaked key keeps
working for the whole window. Rotation is a recovery tool (§4), not a
containment tool.

### (c) Server key — treat the host as burned

The key cannot be un-leaked, and `server init --force` **never regenerates an
existing key**. Restarting the daemon changes nothing.

1. Preserve what the postmortem needs (logs, `show --json`, `peer list`,
   journal), then isolate the host.
2. Stop the units: `sudo systemctl stop vallum@vallum0` and
   `sudo systemctl stop 'vallum-desk@*'`.
3. Assume everything in `/etc/vallum` is compromised: the server key, the
   admin token, any `clients/*.key`/`*.psk`, and every config. The desk
   database in `/var/lib/vallum/desk.sqlite` is suspect if the leak came from
   host access.
4. Recover on a clean host with a **new identity** (§4c). Every client
   re-enrols; there is no shortcut that keeps the old key.

## 4. Eradicate and recover

### (b) Re-enrol the device clean — a pinned invite

The device generates a **fresh** key; the leaked one is never reused.
`keygen` refuses to overwrite an existing file — use a new path, or move the
leaked key aside first.

```sh
# on the device: new key, public line to stdout
sudo vallum keygen --output /etc/vallum/laptop-new.key --suite 3 > laptop.pub
# (copy laptop.pub to the server; --suite must match the server's)

# on the server: a single-use invite PINNED to that public line
sudo vallum peer invite laptop \
    --config /etc/vallum/vallum0.toml \
    --public-key "$(cat laptop.pub)"
```

The pin turns the token from a bearer credential into a registration for a
key the client already has: a stolen invite enrols nothing without the
matching private key ([ADR-0047](../adr/0047-the-account-is-not-the-device.md)).
Single use, 15 minutes by default (`--ttl MINUTES` to change).
`--public-key-file laptop.pub` takes the line from a file instead. The name
must be free — `invite` refuses an existing peer, which is why containment
removed it first.

```sh
# on the device: paste the vallum1-join:… ticket when prompted (stdin keeps
# it out of ps and shell history); --key is REQUIRED for a pinned invite
sudo vallum join - --key /etc/vallum/laptop-new.key
```

The invite starts its own responder (`vallum-enroll@vallum0`, started not
enabled) on the enrolment port — `listen + 1` by default, UDP 51821 for a
51820 tunnel. When the device has joined, close it again; the invite report
prints the exact commands:

```sh
sudo systemctl stop vallum-enroll@vallum0
sudo ufw delete allow 51821/udp
```

Desk-managed devices re-enrol through the account: `POST /api/devices` with
the account token, a label and the device's **own** new public line mints a
fresh pinned invite under a new reservation — the account, plan and expiry
survive a device revoke. The account page does the same without scripts.

### (b, alternative) Rotate — preserves the slot

When the device itself is trusted and only key material was exposed, rotation
replaces the key **under the stable name**: the address, the plan and the
device count are untouched
([ADR-0047](../adr/0047-the-account-is-not-the-device.md) §4).

```sh
# device: fresh key, send its public line
sudo vallum keygen --output /etc/vallum/new.key --suite 3 > new.pub

# server: new key becomes current; the OLD ONE STAYS ACCEPTED
sudo vallum peer rotate laptop --config /etc/vallum/vallum0.toml \
    --public-key "$(cat new.pub)"

# device adopts new.key, restarts the tunnel, confirms it works — then:
sudo vallum peer finalize laptop --config /etc/vallum/vallum0.toml
```

For a **confirmed leak, finalize immediately** — until then the leaked key
still answers (`peer list` shows `ROT yes`, `doctor`'s `rotation` check warns;
the runtime window is bounded,
[ADR-0038](../adr/0038-rotation-window-expires.md), but containment does not
wait it out). The desk's `POST /api/devices/rotate` runs rotate **and**
finalize as one act and warns if finalize failed ("the old key is still
accepted — retry the rotation"); a retry of the same call is the recovery.
When in doubt, prefer remove + pinned re-enrol: it has no window at all.

### (a) A new account

The revoked account number is dead and there is no recovery flow
([ADR-0045](../adr/0045-the-desk-is-the-account-layer-keys-only.md)):

```sh
sudo vallum-desk-admin mint-code --days 30 --gib 200 --plan plus
```

Hand the code to the user out of band; they sign up again (a fresh account
number) and re-enrol their devices as above. Consumed quota does not migrate —
the new code's payload is the new plan.

### (c) A new server identity

On a clean host (fresh install, or the compromised host rebuilt):

```sh
# The key is the one [interface] private_key names — vallum0.key on a fresh
# init, server.key on older installs. It must NOT be restored: init keeps any
# key it finds. Move it aside (evidence), then init mints a fresh identity:
sudo mv /etc/vallum/vallum0.key /root/evidence/vallum0.key.compromised
sudo vallum server init --force --endpoint <host:port>
```

`--force` rewrites the config but never regenerates an existing key; with the
key absent, `init` generates a new one. The server now has a **new
fingerprint**. Re-enrol every device with fresh pinned invites (§4b) — each
device generates a fresh key too, since server-side copies may have leaked.
Clients pinned to the old `--expect` fingerprint will refuse the new server
until their invites are re-minted: that refusal is the fingerprint mechanism
doing its job ([backup.md](backup.md)).

The desk is independent of the tunnel — accounts are desk credentials, not
tunnel keys, and survive a server re-key:

```sh
# restore the account database from a PRE-compromise backup, then prove it:
sudo systemctl stop 'vallum-desk@*'
sudo install -o root -g root -m 0600 /root/desk-YYYY-MM-DD.sqlite \
    /var/lib/vallum/desk.sqlite
sudo systemctl start 'vallum-desk@*'
sudo sqlite3 /var/lib/vallum/desk.sqlite \
    'PRAGMA user_version; SELECT count(*) FROM accounts; SELECT count(*) FROM peers;'
sudo vallum-desk-admin accounts
```

A desk started without its database creates an empty one and looks healthy —
prove the copy before trusting it ([backup.md](backup.md) has the full
restore proof). **Regenerate the admin token**: stop the desk, delete
`/etc/vallum/desk-admin-token`, start the desk — it generates a fresh 0600
token when the file is absent. If the database itself cannot be trusted,
rebuild accounts from minted codes; there is no reset flow.

## 5. Verify

Containment is not done until the daemon agrees. Run every line:

```sh
sudo vallum doctor --config /etc/vallum/vallum0.toml
sudo vallum show   --config /etc/vallum/vallum0.toml --json
sudo vallum peer list --config /etc/vallum/vallum0.toml
sudo vallum metrics --config /etc/vallum/vallum0.toml
sudo vallum-desk-admin accounts
sudo vallum-desk-admin devices
```

| Check | Done means |
|---|---|
| `doctor` `peer sync` | PASS — "every peer's key in the config matches the running daemon". A WARN here is the alpha failure mode: the config and the daemon disagree, and nothing is contained until they agree (`syncconf` or restart) |
| `doctor` `rotation` | no open window — a leaked key still accepted as *previous* is not contained |
| `doctor` `handshakes` | no authenticated-then-rejected FAIL; refused counters flat after containment |
| `show --json` | **exactly** the expected peers — the removed name absent, no orphan, endpoints and `last_handshake` as expected. This is the daemon's answer, not the config's |
| `peer list` | the config agrees with `show`; no `ROT yes`, no `EXPIRED` |
| `metrics` | `vallum_peers_total` equals the expected count; no traffic on a removed peer |
| desk `accounts` / `devices` | the revoked account is not active; no device rows left `active` under it. `vallum-desk-admin sweep` forces one enforcement pass and clears orphans |
| the leaked credential is dead | the old key's handshakes are dropped as unknown peer (journal / `handshakes` check); the revoked token gets `403`; an old invite is spent or revoked (`peer invites`) |
| the legitimate device works | on the client: `sudo vallum doctor --config /etc/vallum/laptop.toml`, `sudo vallum show --config /etc/vallum/laptop.toml` shows a recent handshake, `ping -c 3 10.7.0.1` crosses |

## 6. Postmortem

Record the incident against [incidents/TEMPLATE.md](incidents/TEMPLATE.md)
and run the response process in [incident-response.md](incident-response.md).
The questions this runbook exists to answer:

- **Which class leaked, and how?** Token in a URL or a screenshot, a key file
  copied off a stolen device, a bundle mailed around, host access.
- **Custody audit.** Was any device enrolled with `--ship-key`/`--bundle-out`?
  Then `/etc/vallum/clients/` held private keys — list what remains
  (`peer remove` without `--forget-key` names them). Backups of `/etc/vallum`
  **are** the server: a leaked backup is a class (c) incident
  ([backup.md](backup.md)). Re-key the backups after a re-key.
- **Detection gap.** Did `doctor`'s `peer sync` or `handshakes` warn before
  anyone noticed? An ignored WARN is the alpha state — wire the alerts in
  [monitoring.md](monitoring.md) so the next one pages.
- **Window discipline.** If rotation was used: when was `finalize` run, and
  did the desk report `finalized: true`? The gap between rotate and finalize
  is time the leaked key still worked.

Related: [troubleshooting.md](troubleshooting.md) (doctor's checks),
[server.md](server.md) (enrolment and rotation),
[client.md](client.md) (the join paths), [automation.md](automation.md)
(`--json` contracts and exit codes),
[ADR-0013](../adr/0013-server-provisioning.md) (key custody),
[ADR-0045](../adr/0045-the-desk-is-the-account-layer-keys-only.md) (the desk
is the account layer),
[ADR-0047](../adr/0047-the-account-is-not-the-device.md) (the account is not
the device).
