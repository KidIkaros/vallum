# vallum-desk — the service layer

**Layout:** `service/vallum-desk` (the service), `service/test_vallum_desk.py`
(its tests), `packaging/vallum-desk@.service` (the unit). The executable
ships in the deb/rpm/install.sh channels like every other shipped program —
`scripts/check-package-manifest.sh` knows about both `packaging/` and
`service/` so the three channels cannot drift.

**Tests:** `python3 -m unittest discover -s service -p 'test_*.py'` (stdlib
only, no dependencies, under a second). They run in `ci-local.sh` and in the
hosted `ci` workflow, because a quota that never matches is a quota that
never fires — the accounting is the whole value of the service, so it is
tested against a fake daemon rather than trusted.

**Shape:** `Desk` holds the account lifecycle and depends on a `Daemon`
port; `DaemonCli` is the one implementation that talks to the `vallum` CLI.
The port is what lets the tests fake the daemon.

Turn a Vallum server into a self-service product: users sign up with an
invite code (or, later, a payment), receive a daemon-minted join ticket, and
run the agent lane (`../agent/`) on their own machine. The operator runs the
desk, not a ticket minting ritual.

```
user's machine                     server
──────────────                     ──────
POST /api/signup {code,name}  ──►  vallum-desk ──► `vallum peer invite` ──► daemon
        ◄── join ticket ─────────┘
vallum join '<ticket>'             (peer is live; counters tracked per peer)
vallum-fox adopt                   (config becomes the agent lane)
                                   sweep thread: expiry + byte caps ──► peer remove
```

## Why this shape

- **The daemon stays the trust boundary.** The desk never edits the config;
  it only calls `vallum peer invite/remove/show` and reads the daemon's own
  counters. A desk bug cannot mint traffic or weaken the tunnel — worst case
  it mints or removes a peer.
- **Blast radius is the peer table.** One account = one peer = one identity.
  Revocation is `peer remove`; expiry is a sweep; quotas are the daemon's own
  byte counters. No billing integration can touch the data plane.
- **Anyone can run it.** The desk is a single stdlib-Python file plus a unit:
  no framework, no external service, no dependency on this repository's
  crates. An operator's income derives from plans they define; the v1 schema
  keeps `plan`/`paid_until`/`bytes_cap` on the account row so a billing
  webhook only ever updates a row.

## Closed-alpha operation

```sh
sudo vallum-desk-admin code        # or: POST /api/admin/code (admin token)
# hand the code to one person — consumed on signup, single-use by default
```

Install:

```sh
scp packaging/vallum-desk packaging/vallum-desk@.service to the server:
  /usr/local/lib/vallum/vallum-desk     (root-owned; the trust boundary)
  /etc/systemd/system/vallum-desk@.service
  /etc/vallum/desk-codes.txt            (invite codes, one per line)
systemctl enable --now vallum-desk@<stem>.service     # binds 127.0.0.1:8400
```

Expose it with a TLS reverse proxy when you are ready for open signups;
until then the operator (or a friend) reaches it over SSH:
`ssh -L 8400:127.0.0.1:8400 <server>`.

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /` | none | signup page |
| `POST /api/signup {code,name}` | invite code | mint + return a join ticket |
| `GET /api/status?token=T` | account token | plan, expiry, bytes used |
| `POST /api/admin/code {admin_token}` | admin | mint an invite code |
| `POST /api/admin/adopt {admin_token,peer}` | admin | adopt an existing peer as an account (migrating a live deployment) |
| `POST /api/admin/plan {admin_token,peer}` | admin | set a cap, an expiry, or a status — a paid tier is a row, not code |
| `POST /api/admin/revoke {admin_token,peer}` | admin | revoke + remove a peer |
| `GET /api/admin/peers {admin_token}` | admin | list accounts |
| `POST /api/admin/sweep {admin_token}` | admin | enforce expiry and quotas now |

Defaults: 14-day trial, 50 GiB byte cap, sweep every 5 min. All overridable
on the command line; plans are rows, so paid tiers are data, not code.
