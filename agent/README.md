# Vallum agent lane (`vallum-fox`)

Give an AI agent its own web identity: a per-app tunnel (ADR-0023) whose
member namespace carries the agent's browsing — separate IP, private DNS,
fail-closed on tunnel death, and a per-domain request budget so agent volume
cannot earn a ban.

```
operator's host  ── home ISP (untouched; agents never ride it)
agent process    ── member namespace ── tunnel device ── Vallum server
                    (budget-gated: vallum-fox fetch/shot/dl/dump)
```

## Install on a new machine

1. Install Vallum: `scripts/install.sh` (needs the release build or repo tree).
2. `sudo vallum-ops sync` (or install binaries) — must include today's
   `vallum-quick@.service` (app_class needs `CAP_SYS_ADMIN`, added 2025-11-15).
3. Enroll: `agent/vallum-fox setup <ssh-alias-of-server>` — one polkit prompt.
4. Check: `agent/vallum-fox status` → `separated: yes`.

Then point your agent at the CLI. For Hermes: copy `agent/SKILL.md` into
`~/.hermes/skills/vallum-fox/` (or the matching skill dir for your setup).
The CLI is deliberately protocol-agnostic: expose it as a UTCP CLI provider or
an MCP stdio wrapper later without changing it.

## Files

- `vallum-fox` — the CLI (fetch/dump/shot/dl/egress/status/budget/setup).
- `SKILL.md` — the agent-facing skill (copy to the Hermes skills dir).

## Design rules (do not weaken)

1. Member traffic only via `vallum-quick app` — the launch-bound cgroup/namespace
   boundary is the leak-proof statement (ADR-0023).
2. The budget is enforced in the CLI, not in the agent's judgment: caps refuse
   with exit 3 and the message says the agent must stop. Raising a cap is an
   operator decision (`vallum-fox budget set`).
3. No host fallback exists or may be added: a dead tunnel refuses launches.
