# Running your own Vallum desk (white-label operator guide)

This guide is for an operator who wants to run a **branded, paid VPN service**
on their own Vallum server: your name on the pages, your install link, your
invite codes, your plans. The reference deployment lives at `wingman.gold`;
that host is one deployment, not part of the product — everything below runs
on any Linux host with a Vallum server, under whatever brand you choose.

Read [server.md](server.md) first if you do not have a running Vallum server
yet. The desk is a layer on top of one, not a replacement for it.

## 1. What the desk is

`vallum-desk` is the self-service account layer: one stdlib-Python process
next to the daemon that turns invite codes into accounts, accounts into
device enrolments, and plans into enforced expiry and byte caps — so you
never run an SSH command per user. **The account is not the device**
([ADR-0047](../adr/0047-the-account-is-not-the-device.md)): signup creates an
account alone and returns an account number (a 32-hex bearer token, shown
once, the only credential — no email, no password, no PII,
[ADR-0045](../adr/0045-the-desk-is-the-account-layer-keys-only.md)); devices
enrol later, client-driven, each minting its **own single-use join ticket**
through the daemon, pinned to the device's own public key when the device
presents one. The daemon stays the trust boundary: the desk never edits the
config, it only calls `vallum peer invite/remove/rotate/show` and reads the
daemon's own counters, so a desk bug can mint or remove a peer but cannot
weaken the tunnel. Identity is keys-only and Mullvad-shaped: the account
number is the only credential. Lose it and the operator can re-issue one with
`reset-token` if the account still has a device to address (§5); a device-less
account with a lost number has no handle, which is why the account database is
the one file you must back up ([backup.md](backup.md)).

## 2. Install and run

The executables ship in the deb, the rpm, the release tarball and
`install.sh` like every other shipped program. From a checkout or release
tarball, on the server, as root:

```sh
install -m755 service/vallum-desk       /usr/local/lib/vallum/vallum-desk
install -m755 service/vallum-desk-admin /usr/local/lib/vallum/vallum-desk-admin
install -m644 packaging/vallum-desk@.service /etc/systemd/system/

touch /etc/vallum/desk-codes.txt      # invite codes, one per line (optional)
systemctl daemon-reload
systemctl enable --now vallum-desk@vallum0.service
```

The instance name is the vallum config the desk enrols against:
`vallum-desk@<stem>.service` reads `/etc/vallum/<stem>.toml` and speaks to
that daemon's control socket. The unit is `After=`/`PartOf=` the matching
`vallum@<stem>.service`, runs as root (the control socket is 0600 and peer
operations are privileged), and restarts on failure.

### The real CLI flags

Every knob is a command-line flag; the unit passes them through
`VALLUM_DESK_EXTRA_ARGS` in `/etc/vallum/desk.env`, so you configure by
editing one file, never the unit:

| Flag | Default | What it bounds |
|---|---|---|
| `--config` | *(required)* | the server's vallum config (`/etc/vallum/<stem>.toml` via the unit) |
| `--state` | `/var/lib/vallum/desk.sqlite` | the account database |
| `--codes` | `/etc/vallum/desk-codes.txt` | file invite codes, one per line, payload-less |
| `--admin-token-file` | `/etc/vallum/desk-admin-token` | the admin credential file |
| `--bind` / `--port` | `127.0.0.1` / `8400` | loopback only — front it, don't expose it |
| `--cli` | `vallum` | the binary the desk shells to |
| `--trial-days` / `--trial-bytes` | `14` / 50 GiB | the coded-signup trial |
| `--open-signup` | off | anonymous signup allowed (a posture, not a default) |
| `--open-trial-bytes` | 5 GiB | the anonymous trial cap |
| `--max-active-accounts` | `200` | capacity ceiling — the peer table is a /24 |
| `--signup-ip-day-limit` | `3` | anonymous signups per IP per day (`0` = unlimited) |
| `--device-cap` | `5` | devices per account |
| `--sweep-secs` | `300` | enforcement pass cadence |
| `--operator-name` | `vallum desk` | the service name shown in page headers |
| `--install-source` | upstream `install.sh` URL | the install command the enrolment pages serve |
| `--repo-url` | upstream repo URL | the source/docs link the enrolment pages serve |
| `--metrics` | off | print the funnel as Prometheus text and exit (no listener) |

The admin token is generated on first run at `--admin-token-file` (mode
0600) if the file does not exist. `vallum-desk-admin` reads it from there by
default — the token never travels argv, because argv shows up in `ps`.

### A white-label desk.env

```sh
# /etc/vallum/desk.env
VALLUM_DESK_EXTRA_ARGS=--operator-name "Acme Tunnel" --install-source https://acme.example/install.sh --repo-url https://git.acme.example/tunnel --device-cap 5
```

Then `systemctl restart vallum-desk@vallum0`. The desk binds loopback by
default; put a TLS reverse proxy in front before exposing it:

```caddyfile
desk.acme.example {
    reverse_proxy 127.0.0.1:8400
}
```

The front must forward `Host` (Caddy does): the desk derives the public
origin it hands to clients from that header, and the client records it as
the account's endpoint at join
([ADR-0046](../adr/0046-the-client-reads-its-account-from-the-desk.md)). The
per-IP signup throttle reads the last `X-Forwarded-For` hop when reached over
loopback — without it every anonymous signup arrives as `127.0.0.1` and the
per-IP ceiling becomes a global one. The desk sends its own
`Cache-Control: no-store` and `X-Robots-Tag: noindex` on credential-bearing
pages; do not strip them at the front.

### Service tenancy: isolate strangers

The tunnel default is **personal** — every peer can reach every other peer,
a feature for your own devices. A service offered to strangers wants the
opposite. Create the server with `--client-isolation` (or set
`client_isolation = true` under `[interface]` and re-run `vallum server
init`): peers then cannot reach each other while both still reach the
internet. See [server.md § Service tenancy](server.md#service-tenancy-isolating-strangers-devices).

## 3. Brand it

Three flags rebrand everything the desk serves, no code edit:

- `--operator-name` — the page header and `<title>` on every page.
- `--install-source` — the `install.sh` URL in the install command every
  enrolment page carries. Point it at an installer you host (a mirror of
  `scripts/install.sh`, or your fork's). The script verifies the release
  signature before anything is installed; hosting your own copy is your
  job, the verification behaviour is the script's.
- `--repo-url` — the "Source and docs" link on the enrolment pages.

Unset, all three render the upstream defaults (the `KidIkaros/vallum` repo
and its `install.sh`). Set all three and nothing the desk serves points at
the upstream project.

The visual brand lives in two constants in `service/vallum-desk`, shared by
every page (the same tokens as the landing page's `site/style.css`):

- `DESK_STYLE` — one dark-only stylesheet, no webfont fetch. The tokens an
  operator edits are the `:root` variables: `--bg` (obsidian `#0d1117`),
  `--panel` `#161b22`, `--deep` `#090d12`, `--rule` `#30363d`, `--text`
  `#e6edf3`, `--subtext` `#8b949e`, `--signal` (signal cyan `#39c5cf`),
  `--signal-step` `#4ecbd4`, and the state colours `--live` `#3fb950`,
  `--stale` `#d29922`, `--fault` `#ff7b72`. The diamond glyph `◆` rides
  `h1::before` and `footer::before` in the signal colour.
- `DESK_FOOTER` — the tagline, `every boundary under watch`.

Editing either is a code edit followed by a desk restart; keep the markup
plain (the glyph stays in CSS, not in the HTML the tests read).

**What stays fixed**, whatever you brand:

- The flow: signup creates an account only; devices enrol from the account
  page. No device name at signup, ever.
- The shown-once semantics: the account number and each join ticket are
  displayed once and never stored for re-display.
- Credential hygiene: tokens ride POST bodies, never URLs; credential pages
  are `no-store`/`noindex`; the admin token lives in a 0600 file.
- The join ticket's **15-minute** life — `INVITE_TTL_SECS` in
  `crates/vallum/src/enroll.rs`, a protocol constant, not a desk knob.
- The account number format (32 hex), the device-state vocabulary
  (`live`/`offline`/`never`/`unredeemed`/`unknown`), and the API contract.

## 4. Invite codes, modes, caps

### Minting codes

Two kinds, both single-use:

```sh
vallum-desk-admin mint-code                          # bare: the trial, or a signup key
vallum-desk-admin mint-code --days 30 --gib 200 --plan plus   # a paid-shaped code
vallum-desk-admin codes                              # codes, payloads, burn state
```

A minted code may carry a **plan payload** (`--days`, `--gib`/`--bytes`,
`--plan`): a signup presenting it lands that plan instead of the trial, and
the ticket page renders the label the account actually landed ("plus until
…", never a hardcoded "trial"). A code is burned on signup — or on voucher
redemption against a live account (§5).

The `--codes` file is the other channel: one code per line, `#` comments
allowed, re-read on every request so you can add codes without a restart.
File codes carry no payload — they grant the trial. Use them for a quick
closed alpha; use minted codes when the code itself is the product.

### Closed vs open

**Closed (the default):** signup requires a known, unburned invite code.
This is the right posture for a paid service — the code is what you sell.

**Open (`--open-signup`):** anyone can create an account with no code, on
the anonymous trial (`--open-trial-bytes`, default 5 GiB). Every anonymous
axis is bounded, because the peer table is a /24 and capacity, not
politeness, is what stops a crawl:

- `--signup-ip-day-limit` (default 3) signups per IP per UTC day, persisted
  in the database — a restart does not reset it;
- `--max-active-accounts` (default 200) — at capacity, signup answers 503;
- the anonymous byte cap, enforced by the same sweep as every other plan.

Open mode is a free-trial funnel, not a billing model: an anonymous account
becomes a paying one by redeeming a payload code (§5, voucher).

### Device caps and reservations

`--device-cap` (default 5) is **policy**, a plan attribute you set per tier —
the physical ceiling is server capacity (the address pool, handshake CPU),
which the daemon enforces at allocation. The cap count reconciles against
the daemon's own peers (`vallum show --json`), not the desk's rows alone: a
reservation whose peer the daemon never created **and** whose ticket has
expired is a ghost, and is released so it cannot hold a slot forever.

That release window is `reservation_ttl` — **1200 seconds** by default, a
`DeskConfig` field with no CLI flag today. It is deliberately longer than
the 15-minute ticket so a slow join is not released mid-flight; if you need
a different window, edit the default in `service/vallum-desk`. Within the
TTL a reservation is a live ticket the client may still redeem, not a ghost.

## 5. The lifecycle you support

```
invite code ──► account (token shown once) ──► add_device ──► pinned ticket ──► join
                     │                            ▲                │
                     │  voucher (top-up)          │ expired ticket?│ rotate (new key,
                     ▼                            └── same account ┘  same slot)
              plan row: expires, bytes_cap, status ── sweep enforces ──► revoke
```

**Signup.** The user posts their code to `/signup` (web form) or
`POST /api/signup {"code": "…"}` (agents). The answer is the account number,
shown once, plus the install command and the next step. No daemon call
happens here — a down daemon cannot stop signup.

**Add a device.** From the account page (`/account` with the account number)
or `POST /api/devices {"token": "…", "name": "laptop"}`. The desk mints a
single-use ticket bound to the account's plan — same expiry, same shared
byte pool. A device that presents its own public line gets a **pinned**
ticket: the responder enrols only the holder of the matching private key,
so a stolen account number enrols nothing.

```sh
# on the device — custody stays here
vallum keygen --key agent.key
vallum pubkey --key agent.key            # the public line to present
curl -X POST https://desk.acme.example/api/devices \
     -H 'content-type: application/json' \
     -d '{"token":"<account number>","name":"agent","public_key":"<public line>"}'
# → {"ticket": …, "pinned": true, "connect": "vallum://join?…"}
vallum join '<ticket>' --key agent.key
```

Without a public line (the web page's path) the ticket is single-use but
unpinned — the client generates its key at join time. The ticket page's
**Connect** button fires the `vallum://join` deep link, which carries the
ticket, the account number and your desk's origin; the client seals the
account into its config and reads its account state from your desk
thereafter. The ticket lives 15 minutes; the page says so out loud.

**Expired ticket? Not a lost account.** The account number outlives every
ticket. The user opens their account page and uses **Add a device** again —
a fresh ticket under the same account, no new invite code. This is the
support answer to "my ticket expired": never re-sell a code for it.

**Rotate.** A device replaces its key under its stable peer name —
`POST /api/devices/rotate {"token", "peer", "public_key"}` with the device's
**own new** public line. Rotation is never add-device: no reservation, no
cap check, no ticket; the slot, address and plan are untouched, so it works
even at the device cap. The desk runs `peer rotate --public-key` then
`peer finalize` as one act; if the answer says `finalized: false`, the old
key is still accepted and the recovery is a retry of the same call.

**Revoke.** Three doors, same removal-first order (the daemon removal is
what makes it real; a failed removal leaves the row active for retry):

```sh
# the user, per device: the account page's remove button, or
curl -X POST https://desk.acme.example/api/devices/revoke \
     -H 'content-type: application/json' -d '{"token":"…","peer":"u0007-laptop"}'

# you, per device — the account survives, its other devices keep their tunnel
vallum-desk-admin revoke --peer u0007-laptop
# you, the whole account — every device goes first, then the account
vallum-desk-admin revoke --peer u0007-laptop --account
vallum-desk-admin revoke --token-file <file> --account   # device-less account; number stays out of ps
```

**Enforcement.** A sweep thread runs every `--sweep-secs` (default 300):
accounts past `expires` become `expired`, accounts over `bytes_cap` become
`overquota`, their peers are removed, orphaned and unredeemed reservations
are cleared. Quota needs the daemon's counters; when the daemon cannot be
asked, quota is not judged that pass but expiry still is. Force a pass and
see what it did: `vallum-desk-admin sweep`.

**Top-up (voucher).** An unused payload code applied to a live account:
`POST /api/voucher {"token", "code"}` or the account page's "Have a code?"
box. Additive: days extend expiry (from the later of current expiry and
today), bytes grow the shared cap, the label replaces `plan`; consumed
bytes stay consumed.

Your everyday operator views:

```sh
vallum-desk-admin accounts     # the account list (numbers masked; --json for scripts)
vallum-desk-admin devices      # every peer, its account, its status
vallum-desk-admin codes        # codes, payloads, burn state
vallum-desk-admin set-plan --token-file <file> --plan plus --expires 2026-12-31
vallum-desk-admin adopt --peer u0003-alice   # a live daemon peer becomes an account
vallum-desk-admin reset-token --peer u0003-alice  # re-issue a lost number; the old stops working
```

`adopt` is how you migrate a pre-desk deployment, and the escape hatch for a
user who lost their account number: their peers still exist on the daemon,
and adopting them into a fresh account re-issues a credential out-of-band.

## 6. Operate it

### Health

`GET /healthz` is the one unauthenticated route: it reads the database and
asks the daemon, and answers `200` only when both do — `503` naming the one
that failed (`{"ok": false, "checks": {"database": "ok", "daemon":
"unreachable"}}`). It names no account, peer or count, so it is safe to
expose through the same front and to probe from outside:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8400/healthz
```

"Listening" is not "working"; this is the difference. The reference
deployment probes it with `blackbox_exporter` alongside the desk's TLS
certificate — see [monitoring.md](monitoring.md) and `contrib/monitoring/`.

### Backup — the state that cannot be rebuilt

`desk.sqlite` is the one file whose loss is permanent: the account number is
the only credential, and `reset-token` can only re-issue one for an account it
can still address. A desk started without its
database creates an empty one and looks healthy — so the copy must not
depend on anyone's attention. `vallum-desk-backup.timer` ships with the desk
and is **enabled by the installer**: daily, it copies the live database
through SQLite's online-backup API (not `cp`), writes the copy 0600 to
`/var/backups/vallum`, reopens it and verifies `PRAGMA user_version` and row
counts against the source, and keeps the newest 14.

```sh
systemctl list-timers vallum-desk-backup.timer
sudo /usr/local/lib/vallum/vallum-desk-backup    # one now, before an upgrade
```

Point the copies off-host with one file, no unit edit — a copy on the same
disk survives a bad migration, not a lost host:

```sh
# /etc/vallum/desk-backup.env
VALLUM_DESK_BACKUP_ARGS=--dest /mnt/offhost/vallum-desk --keep 30
```

Restore procedure and the proof that the copy is the right one:
[backup.md](backup.md).

### Monitoring — the funnel

The desk has no metrics listener either. `--metrics` prints the funnel as
Prometheus text and exits — one scrape, no new port, no new credential:

```sh
python3 /usr/local/lib/vallum/vallum-desk --config /etc/vallum/vallum0.toml --metrics
```

The funnel is the number a service lives or dies by: **tickets minted versus
devices that ever handshaked**. Every series is always emitted, including
zeros, so "no devices" is distinguishable from "the desk did not answer":
`vallum_alpha_devices{state="live|offline|never|unredeemed|unknown"}`,
`vallum_alpha_devices_total`, `vallum_alpha_handshaked_devices`,
`vallum_alpha_accounts{status}`, `vallum_alpha_daemon_answered`, and the
signup-attribution series.

The reference wiring pushes it: `contrib/telemetry/vallum-telemetry-push.sh`
runs `vallum metrics`, the desk's `--metrics`, the scheduled gate's result
and `systemctl --failed` into VictoriaMetrics every 15 s
(`vallum-telemetry.timer`). The shipped alert rules
(`packaging/vallum-alerts.yml`) include the two a desk operator must have:

- `VallumNoDeviceEverConnected` — `vallum_alpha_handshaked_devices == 0 and
  vallum_alpha_devices_total > 0` for 24 h. When it fires, read
  `vallum_alpha_devices{state="unredeemed"}`: if it equals the total, tickets
  are being minted and never redeemed — check that the ticket's address and
  port are reachable from outside. This alert exists because 14 tickets with
  0 handshakes once read as a healthy quiet system for a day.
- `VallumDeskCannotSeeDaemon` — `vallum_alpha_daemon_answered == 0` for
  15 m: every device renders `unknown`, so distrust the other funnel series
  until it clears.

For a paid service, tune the `for:` windows to your audience — an idle
overnight is legitimate for an alpha, less so for a service with customers.
The daemon-side and client-side alert groups are in
[monitoring.md](monitoring.md).

### The dead-man's switch

The fail-closed egress guard has a dead-man timer
(`vallum-deadman@<iface>.timer`, every 10 s) that removes the egress block
when the tunnel cannot pass a packet three checks running — it protects the
**client** host, including your own machine when you test a full tunnel
against your service. It is sibling work to this guide; the operator-facing
recovery story (the panic command, what to look at when the internet is
gone) is in [if-it-breaks.md](../if-it-breaks.md).

### When things go wrong

- A user cannot join, tickets expire unredeemed: the funnel alert above,
  then the enrolment-port story in [server.md](server.md#enrolment-open-the-second-port-only-while-you-are-enrolling).
  The desk mints through `vallum peer invite`, which starts the enrolment
  responder and opens its port for the join — the unit's writable paths
  include `/etc/ufw` for exactly that step.
- Suspected credential compromise (a leaked account number, a leaked admin
  token, a stolen key): [compromise.md](compromise.md).
- An outage or a security event on the service itself:
  [incident-response.md](incident-response.md).

## 7. Billing hooks for a paid service

**Be honest about what exists: alpha billing is manual and out-of-band.**
There is no payment integration in the desk — no processor, no checkout, no
billing webhook, no subscription engine. Invite codes are sold or given
externally (your store, your invoice, your handshake), and the desk enforces
what the code grants. Do not advertise automated billing you have not built.

What the desk gives you today is enough to run a paid service by hand:

1. **Sell codes, not accounts.** Mint a payload code per purchase —
   `vallum-desk-admin mint-code --days 30 --gib 200 --plan plus` — and deliver
   it through whatever channel took the money. The code is single-use; the
   signup lands the plan; the sweep enforces the expiry and the cap without
   you watching.
2. **Top-ups are vouchers.** Sell a `--gib 100` code; the user applies it on
   their account page. Days extend, bytes grow, consumed bytes stay
   consumed — prepaid semantics, no refund machinery to build.
3. **Corrections and comps are row edits.** `vallum-desk-admin set-plan`
   changes `bytes_cap`, `expires`, `paid_until`, `plan` or `status` on one
   account — reinstating a mis-quota'd customer is the same call as granting
   a paid tier. Address device-less accounts by `--token-file`.
4. **Renewals are new codes or a `set-plan --expires`.** There is no
   auto-renew; decide per customer whether a renewal is a voucher they apply
   or a row you extend.

The schema is deliberately shaped so automation can attach later without a
rewrite: a plan is **data on the account row** (`plan`, `paid_until`,
`bytes_cap`, `expires`, `status`), so a future billing webhook only ever
updates a row — it never touches the data plane, and no billing bug can mint
traffic. `paid_until` exists today as a field you can set; nothing in the
desk reads it as an enforcement trigger yet (the sweep enforces `expires`
and `bytes_cap`), so treat it as bookkeeping until you wire it.

The constraints a paid service must say out loud to its customers:

- **The account number is the only credential.** No email, no password
  reset. A customer who loses it has two operator recovery paths:
  `vallum-desk-admin reset-token --peer <device>` re-issues a fresh number for
  an account that still has a device (the old number stops working; plan and
  quota survive), or `adopt` re-registers their live peers into a fresh account.
  A device-less account whose number is lost has no handle to address — rebuild
  it from a minted code
  ([ADR-0047](../adr/0047-the-account-is-not-the-device.md) Q3).
- **One host, one interface.** No high availability, no horizontal scaling
  story yet; capacity is the box (the /24 peer table, the address pool,
  handshake CPU). Sell what one server can carry.
- **Revocation is real and immediate** — `peer remove` on the daemon, not a
  flag in a database. A refund that ends in revocation actually ends the
  tunnel.

---

Related: [server.md](server.md) · [client.md](client.md) ·
[monitoring.md](monitoring.md) · [backup.md](backup.md) ·
[automation.md](automation.md) (the machine interface the desk wraps) ·
[incident-response.md](incident-response.md) · [compromise.md](compromise.md) ·
the service layer's own [README](../../service/README.md) (API table,
security notes, deep-link handlers).
