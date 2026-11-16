---
name: vallum-fox
version: 1.0.0
author: Vallum + Hermes Agent
license: Apache-2.0
description: Agent web browsing on a separate IP via Vallum tunnel.
metadata:
  hermes:
    tags: [vallum, agent-browsing, tunnel, rate-limiting]
    related_skills: [vallum-operations, dogfood]
---

# vallum-fox — agent web access on its own identity

## When to Use

Use this lane when a web task carries agent-volume risk: many fetches, file
downloads, scraping-adjacent work, anything where a ban on the operator's
identity would be annoying. Do not use it for ordinary single-page lookups.

`vallum-fox` runs web access through a Vallum per-app tunnel (ADR-0023): the
browser/fetcher executes inside a member namespace whose only route is the
tunnel. What that guarantees, and what the agent must never break:

- **Separate identity.** Sites see the tunnel's IP, not the operator's home IP.
  `vallum-fox egress` shows both and says `separated: yes/no`.
- **Fail-closed.** If the tunnel is down, commands refuse — there is no host
  fallback, and adding one (direct `curl`, proxying around the budget) is
  forbidden: it would spend the operator's identity on agent behavior.
- **The budget is law.** Every request passes a per-domain token budget
  (default 60/hour, 5 s pace). `BUDGET_EXHAUSTED`/`BUDGET_RATE` means STOP that
  domain — never retry in a loop, never raise the cap without the operator.
  Bans are earned by volume; the budget is the volume governor.

## Commands

```sh
vallum-fox status                  # device, units, egress separation, budget
vallum-fox egress                  # agent IP vs host IP
vallum-fox fetch <url> [out-file]  # rate-limited body fetch (curl, IPv4)
vallum-fox dump <url>              # rendered DOM (headless Chrome in the tunnel)
vallum-fox shot <url> <abs.png>    # screenshot; output path must be absolute, never /tmp
vallum-fox dl <url> <abs-file>     # download with budget accounting
vallum-fox budget set <domain> hourly=N interval=S   # tighten per-domain caps
vallum-fox budget list
```

Config: `$VALLUM_FOX_CONFIG` (default `/etc/vallum/vallum-agent.toml`).
The member namespace's `/tmp` is private and dies with the unit — write
artifacts only to shared absolute paths (the operator's home works).

## Setup on a new machine (reproducible)

```sh
# on any machine with SSH access to the Vallum server:
agent/vallum-fox setup <ssh-alias-of-server>
```

That generates the key on the device, enrolls a peer on the server, writes the
`app_class` config, installs it with one polkit/sudo prompt, and adds a
sudoers rule scoped to `vallum-quick app *` only. Requires: Vallum installed
(`scripts/install.sh`), the pinned toolchain build available, systemd.

## Known rough edges (as of the 2025-11-15 dogfood)

- Member `/tmp` is private (unit `PrivateTmp`): downloads to `/tmp` vanish.
  Use shared paths; the product fix is a bound artifacts dir (see
  `dogfood-output/report-app-class-2026-11-15.md`).
- `shot`/`dump` of JS-heavy pages may need a larger `--virtual-time-budget`.
- Chrome dbus/GPU errors in output are noise in a headless container-less run.

## When NOT to use it

Ordinary low-stakes lookups the operator's browser would make anyway. This
lane exists for agent-volume traffic: scraping-ish tasks, many fetches,
downloads, anything where a ban would be annoying. It costs tunnel bandwidth
and a peer slot; don't spend it on one `example.com` lookup.
