# vallum-desk — the service layer

**Layout:** `service/vallum-desk` (the service), `service/vallum-desk-admin`
(the operator CLI), `service/vallum-desk-backup` (the verified copy of the
account database), `service/test_vallum_desk.py` + `test_vallum_desk_admin.py`
(the tests), `packaging/vallum-desk@.service` +
`packaging/vallum-desk-backup.{service,timer}` (the units). The executables
ship in the deb, the rpm, the release tarball and `install.sh` like every
other shipped program — `scripts/check-package-manifest.sh` knows about both
`packaging/` and `service/` so the channels cannot drift.

**Tests:** `python3 -m unittest discover -s service -p 'test_*.py'` (stdlib
only, no dependencies, under a second). They run in `ci-local.sh` and in the
hosted `ci` workflow, because a quota that never matches is a quota that
never fires — the accounting is the whole value of the service, so it is
tested against a fake daemon rather than trusted.

**Shape:** `Desk` holds the account lifecycle and depends on a `Daemon`
port; `DaemonCli` is the one implementation that talks to the `vallum` CLI.
The port is what lets the tests fake the daemon.

Turn a Vallum server into a self-service product: a user signs up with an
invite code (or anonymously, in open mode), receives a daemon-minted join
ticket, and joins. Their **account number** — the desk's bearer token — is
the only credential; it carries up to `--device-cap` devices and redeems
codes against the account.

```
user's machine                     server
──────────────                     ──────
POST /api/signup {code,name}  ──►  vallum-desk ──► `vallum peer invite` ──► daemon
        ◄── join ticket + account number ┘
vallum join '<ticket>'             (peer is live; counters tracked per peer)
POST /account {token}              (plan, shared pool, devices, voucher box)
                                   sweep thread: expiry + byte caps ──► peer remove
```

## Why this shape

- **The daemon stays the trust boundary.** The desk never edits the config;
  it only calls `vallum peer invite/remove/show` and reads the daemon's own
  counters. A desk bug cannot mint traffic or weaken the tunnel — worst case
  it mints or removes a peer.
- **Blast radius is the peer table.** One account = up to `device_cap`
  peers; all of an account's devices draw from one shared byte pool.
  Revocation is `peer remove`; expiry is a sweep; quotas are the daemon's
  own byte counters. No billing integration can touch the data plane.
- **Anyone can run it.** The desk is stdlib-Python plus a unit: no
  framework, no external service, no dependency on this repository's
  crates. Plans are rows — a paid tier is data (`plan`, `paid_until`,
  `bytes_cap` on the account row), so a billing webhook only ever updates
  a row.
- **The schema migrates forward.** `PRAGMA user_version` versions the
  SQLite state; a desk refuses to open a database newer than itself rather
  than corrupt a schema it does not know.

## Concepts

An **account number** is the user's only credential: 32 hex chars, issued at
signup, treated like a password. It authenticates `/api/status`,
`/api/account`, `/api/devices`, `/api/voucher` and the `/account` page.
There is no email, no password reset flow — lose the number, lose the
account (an operator can adopt the peers into a fresh account).

A **device** is a daemon peer bound to an account: `POST /api/devices`
with the account number mints a ticket against the account's own plan.
The cap (`--device-cap`, default 5) is enforced under the desk's lock; the
count and the reservation are one step, so a race cannot oversell.

A **plan** is data on the account row: `plan` label, `expires`,
`bytes_cap`, `status`. A **code** may carry a plan payload — minted with
`--days/--bytes/--plan` — which a signup lands instead of the trial, or a
voucher applies to a live account. Voucher semantics are **additive**:
days extend expiry, bytes grow the cap, the label replaces `plan`;
consumed bytes stay consumed.

## Deploy it

```sh
# on the server, as root — from a checkout or release tarball:
install -m755 service/vallum-desk /usr/local/lib/vallum/vallum-desk
install -m755 service/vallum-desk-admin /usr/local/lib/vallum/vallum-desk-admin
install -m644 packaging/vallum-desk@.service /etc/systemd/system/

touch /etc/vallum/desk-codes.txt      # invite codes, one per line (optional)
systemctl daemon-reload
systemctl enable --now vallum-desk@<stem>.service   # binds 127.0.0.1:8400
```

`<stem>` is the vallum config instance the desk enrols against
(`/etc/vallum/<stem>.toml`). The desk mints tickets through
`vallum peer invite --json` on that config's control socket — same daemon,
same trust boundary.

The desk generates its admin token on first run at
`/etc/vallum/desk-admin-token` (mode 0600). `vallum-desk-admin` reads it
from there by default — the token never travels argv.

## The account database is the state that cannot be rebuilt

Everything else in this product is derived from a key or re-enrolled from a
ticket. An account number is not: it is the only credential the desk issues,
there is no email and no reset flow (ADR-0045), so `desk.sqlite` is the one
file whose loss is permanent.

`vallum-desk-backup.timer` therefore ships with the desk and is **enabled by
the installer**; the service is conditioned on the database existing, so it is
inert on a host that does not run a desk. Each run copies the live database
through SQLite's online-backup API, writes the copy `0600` to
`/var/backups/vallum`, reopens it and compares `PRAGMA user_version` and the
row counts against the source, then keeps the newest `--keep` (default 14).

```sh
systemctl list-timers vallum-desk-backup.timer
sudo /usr/local/lib/vallum/vallum-desk-backup --dest /mnt/offhost/desk --keep 30
```

A copy on the same disk survives a bad migration, not a lost host: point
`--dest` off-host via `VALLUM_DESK_BACKUP_ARGS` in `/etc/vallum/desk-backup.env`.
`scripts/accept-desk-restore.sh` is the gate that proves the copy path and the
restore path both work; it runs in `verify.sh`, `ci-local.sh` and CI.

## Config reference (all command-line, repeatable via env file)

| Flag | Default | What it bounds |
|---|---|---|
| `--state` | `/var/lib/vallum/desk.sqlite` | the account database |
| `--codes` | `/etc/vallum/desk-codes.txt` | file invite codes (payload-less) |
| `--admin-token-file` | `/etc/vallum/desk-admin-token` | admin credential file |
| `--bind` / `--port` | `127.0.0.1:8400` | loopback only — front it, don't expose it |
| `--trial-days` / `--trial-bytes` | 14 / 50 GiB | the coded-signup trial |
| `--open-signup` | off | anonymous signup allowed |
| `--open-trial-bytes` | 5 GiB | the anonymous trial cap |
| `--max-active-accounts` | 200 | the peer table is a /24 — a ceiling, not a formality |
| `--signup-ip-day-limit` | 3 | anonymous signups per IP per day (0 = unlimited) |
| `--device-cap` | 5 | devices per account |
| `--sweep-secs` | 300 | enforcement pass cadence |
| `--operator-name` | `vallum desk` | the page header's brand |
| `--cli` | `vallum` | the binary the desk shells to |

Flags ride `VALLUM_DESK_EXTRA_ARGS` in `/etc/vallum/desk.env`, read by the
unit.

## Public front (Caddy, any web server)

```caddyfile
desk.example.com {
    reverse_proxy 127.0.0.1:8400
}
```

Add the host to any exit-notice/fallback catch-all's exclusion list,
validate (`caddy validate`), then reload — a reload, not a restart, so
other sites on the same server never drop. The desk sends its own
`Cache-Control: no-store` and `X-Robots-Tag: noindex` on every
credential-bearing page.

The per-IP bound reads the last `X-Forwarded-For` hop when reached over
loopback, which is how the Caddy front passes the visitor's address.
Without that, every anonymous signup arrives as `127.0.0.1` and the "per
IP" ceiling becomes a global three-a-day ceiling.

## Operate it

```sh
vallum-desk-admin mint-code --days 30 --gib 200 --plan plus
vallum-desk-admin mint-code            # a bare code: the trial, or a signup key
vallum-desk-admin accounts             # the account list
vallum-desk-admin devices              # every peer, its account, its status
vallum-desk-admin codes                # codes, payloads, burn state
vallum-desk-admin set-plan --peer u0007-laptop --plan plus --expires 2026-12-31
vallum-desk-admin revoke --peer u0007-laptop            # one device
vallum-desk-admin revoke --peer u0007-laptop --account  # the whole account
vallum-desk-admin adopt --peer u0003-alice   # a live daemon peer becomes an account
vallum-desk-admin sweep                # enforce expiry + quotas now
vallum-desk-admin --desk http://127.0.0.1:8400 --json accounts   # for scripts
```

Everything the CLI does is `POST /api/admin/*` with the admin token in the
body — the CLI just saves the curl.

`GET /healthz` is the one question a front or a probe can ask without a
credential. It reads the database and asks the daemon (`vallum show --json`),
and answers `200` only when both do:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8400/healthz
```

A `503` names what failed — `{"ok": false, "checks": {"database": "ok",
"daemon": "unreachable"}}` — which is the difference between "the process is
listening" and "the desk can mint a ticket". It needs no credential and names
no account, peer or count, so it is safe to expose through the same front.

## Watch a flow end to end

```sh
# 1. mint a paid-shaped code
vallum-desk-admin mint-code --days 30 --gib 200 --plan plus
#   → prints the code

# 2. a user signs up with it
curl -X POST https://desk.example.com/api/signup \
     -H 'content-type: application/json' -d '{"code":"<code>","name":"laptop"}'
#   → {"ticket": "vallum1-join:…", "token": "<account number>", …}

# 3. their account
curl -X POST https://desk.example.com/api/account \
     -H 'content-type: application/json' -d '{"token":"<account number>"}'
#   → plan plus, 200 GiB cap, one device

# 4. they add a phone
curl -X POST https://desk.example.com/api/devices \
     -H 'content-type: application/json' \
     -d '{"token":"<account number>","name":"phone"}'
#   → a second join ticket bound to the same plan

# 5. they top up
vallum-desk-admin mint-code --gib 100
curl -X POST https://desk.example.com/api/voucher \
     -H 'content-type: application/json' \
     -d '{"token":"<account number>","code":"<code>"}'
#   → cap grows to 300 GiB; the code is burned
```

## The Connect button — vallum:// deep links

Every ticket-bearing response (`signup`, `devices`) carries a `connect` URI,
and the ticket page renders it as a Connect button:

```
vallum://join?ticket=<url-encoded ticket>&account=<account number>
```

The page fires it with `window.location` — never an `href`, where prefetch
and Referer would carry the credential. Two handlers can receive the
scheme, and the desktop picks by which `.desktop` files exist:

- **`vallum-uri` (baseline, ships everywhere).** Validates the URI
  byte-strictly — the `vallum1-join:` grammar for the ticket, 32 hex for
  the account — then runs `vallum join -`: the ticket on stdin, the
  account in `VALLUM_ACCOUNT`. Nothing secret is ever an argv member, and
  nothing is shell-evaluated. `vallum join` seals the account into the
  config's `[account]` table, in the key's 0600 custody.
- **`vallum-gui` (takeover when installed).** Its desktop entry also owns
  `x-scheme-handler/vallum`; the mimeapps default decides between the two.
  The GUI parses the URI at launch, shows a confirm surface (server
  endpoint, account number tail), and enrols through `vallum-ops join` —
  the account rides a second stdin line because pkexec strips env.
  Without the GUI the baseline handler keeps working; installing the GUI
  is the only switch.

`[account]` is desk metadata — the daemon ignores it — and it is gated by
`deny_unknown_fields`: a `vallum` binary older than the field refuses a
config that carries it. Keep a current client on deep-link machines.
Linux is the registered platform today; the macOS/Windows story is the
Tauri bundle's file-association config when those ports ship.

## Security notes — the parts an operator must hear

- **The account number is a bearer credential.** It never travels a URL —
  not a path, not a query. URLs land in proxy access logs; bodies do not.
  The alpha-era `GET /api/status?token=` is retired: it answers `410` and
  points at `POST /api/status`. Keep any external log shipper away from
  request bodies, and do not log the desk's own request bodies either.
- **All credential-bearing pages send `Cache-Control: no-store` and
  `X-Robots-Tag: noindex`.** The desk emits them itself; a front should not
  strip them.
- **`--open-signup` is a posture, not a default.** Closed alpha (invite
  codes only) is the default. Open mode bounds every anonymous axis —
  bytes, capacity, per-IP rate — because the peer table is a /24.
- **Tickets are capabilities.** A minted join ticket redeems once whenever
  presented; revoking the account in the gap between mint and redeem does
  not un-mint it. The window is seconds on the normal path.
- **The admin token lives in a file, mode 0600.** It is read, never passed
  as an argument — argv shows up in `ps`.
- **Concurrency is real.** The server threads requests; every check-then-act
  (redeem, cap, voucher burn) happens inside the desk's lock, and daemon
  subprocess calls happen outside it. If you fork the desk, keep that rule.

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | `200` when the database reads and the daemon answers; `503` naming the dependency that did not |
| `GET /` | none | signup page |
| `GET /account` | none | the account-number shell page |
| `POST /signup {code,name}` | invite code (or none, open mode) | no-script signup → ticket page |
| `POST /account {token}` | account number | no-script account page |
| `POST /account/device {token,name}` | account number | no-script add-device → ticket page |
| `POST /account/revoke {token,peer}` | account number | no-script per-device remove |
| `POST /account/voucher {token,code}` | account number | no-script code redemption |
| `POST /api/signup {code,name}` | invite code (or none, open mode) | mint + return a join ticket |
| `POST /api/status {token}` | account number | plan, expiry, bytes used |
| `POST /api/account {token}` | account number | the full account view: plan, pool, devices |
| `POST /api/devices {token,name}` | account number | mint a device ticket bound to the account |
| `POST /api/devices/revoke {token,peer}` | account number | remove one of the account's devices |
| `POST /api/voucher {token,code}` | account number | apply an unused code's payload to the account |
| `POST /api/admin/code {admin_token,…}` | admin | mint a code (`days`/`bytes`/`plan` optional) |
| `POST /api/admin/adopt {admin_token,peer}` | admin | adopt a live daemon peer as an account |
| `POST /api/admin/plan {admin_token,peer,…}` | admin | set cap, expiry, plan, status |
| `POST /api/admin/revoke {admin_token,peer}` | admin | remove one device |
| `POST /api/admin/revoke-account {admin_token,peer}` | admin | remove every device, then the account |
| `POST /api/admin/peers` / `devices` / `codes` | admin | listings |
| `POST /api/admin/sweep` | admin | enforce expiry and quotas now |

Defaults: 14-day trial, 50 GiB coded cap, 5 GiB anonymous cap, 5 devices
per account, sweep every 5 min. Plans are rows — paid tiers are data, not
code.
