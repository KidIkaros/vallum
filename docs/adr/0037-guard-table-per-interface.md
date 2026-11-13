# ADR-0037: The egress guard has one table per interface

**Date:** 2026-11-12
**Status:** proposed
**Deciders:** the maintainer
**Relates to:** ADR-0018 (fail-closed egress)

## Context

The egress guard is one nftables table, `inet vallum_policy`, holding one
`output` hook chain that drops traffic leaving outside the tunnel
(`crates/vallum/src/policy.rs`). The *rules* were per-interface — the chain
accepts `oifname "<interface>"` and the tunnel's endpoint — but the *table*
was not: there was exactly one, named after the product.

That works for a host with one tunnel, which is the common case. It breaks in
two ways as soon as a second tunnel exists:

- **Installing one tunnel's guard replaces the other's.** The ruleset is
  `table inet vallum_policy` / `delete table inet vallum_policy` / `table
  inet vallum_policy { ... }` — declare, delete, create. The delete removes
  the whole table, including the other interface's rules. The first tunnel's
  guard silently stops being there, and nothing reports it: the guard's state
  is read from the table, and the table that is present is the second
  tunnel's.
- **`policy off` removes every interface's guard.** The removal deletes the
  same single table. An operator turning egress back on for one tunnel also
  turned it off for the other, whichever one they were thinking about.

The command text is per-interface ("block egress outside `<interface>`"), so
the behaviour contradicted what it said. A second tunnel is a supported
configuration — the config has an interface name, the units are templated
per interface (`vallum@.service`, `vallum-guard@.service`), and the console
discovers interfaces — so the guard is the one piece of the egress story that
did not scale with it.

## Decision

The guard's table is named per interface: `vallum_policy_<interface>`, with
anything in the interface name that is not a letter or a digit replaced by an
underscore, because nft identifiers are `[A-Za-z_][A-Za-z0-9_]*`.

`policy on` then replaces only that interface's table, `policy off` removes
only that interface's table, and `status` reads only that interface's table.
The legacy host-wide `vallum_policy` table is removed by `policy off`, so an
installation from before this change does not leave a stale guard behind
blocking egress for an interface that no longer exists.

## Alternatives Considered

### Alternative 1: One table, one chain, a per-interface jump

- **Pros**: One table for the host; each interface's rules live in its own
  chain and the output chain jumps to it.
- **Cons**: The chain's rules are still replaced wholesale by the same
  declare-delete-create, so the interference does not go away — it just moves
  one level down. `policy off` would still have to know which chains to
  remove, and a stale chain would remain in the table.
- **Why not**: It keeps the shared object that caused the problem.

### Alternative 2: Keep one table and refuse to install a second guard

- **Pros**: No change to the nft layout; the conflict becomes an explicit
  error instead of a silent overwrite.
- **Cons**: It makes the second tunnel's guard unavailable rather than
  correct. The operator is left with a tunnel whose egress is open, and a
  message. The underlying capability — two tunnels on one host — is real.
- **Why not**: Turning a correctness bug into a refusal is a smaller change
  than fixing it, and it leaves the user with the wrong answer.

### Alternative 3: Name the table after the config path or a UUID

- **Pros**: No sanitisation rules; no possibility of two names colliding.
- **Cons**: The name would no longer be readable. An operator inspecting
  `nft list ruleset` sees which interface a table belongs to, which is the
  point of naming it after the interface.
- **Why not**: Readability at the debugging surface is worth more than
  closing a collision that needs two deliberately punctuation-differing
  interface names.

## Consequences

### Positive
- Two tunnels on one host have independent guards, and installing or
  removing one leaves the other alone.
- `status` and `policy status` read the guard that belongs to the interface
  they are reporting about.
- The table name says which interface it belongs to, at the point where an
  operator looks.

### Negative
- An upgrade leaves the old `vallum_policy` table in place until `policy off`
  runs, or until the guard is reinstalled. It blocks egress (fail-closed), so
  it is safe, but it is stale.
- The sanitisation rule means two interface names differing only in
  punctuation share a table. Interface names are bounded at 15 characters and
  alphanumeric in practice, so this needs two deliberate names.

### Risks
- **A stale legacy table blocks egress after an upgrade.** Mitigated by
  `policy off` removing it, and by the direction of the failure: it blocks,
  it does not leak. The guard unit's `ExecStart` reinstalls the per-interface
  table, so a host that restarts the guard is clean.
- **The sanitisation rule could produce an nft identifier that another
  interface also produces.** Mitigated by the same narrowness as above, and
  by `each_interface_has_its_own_guard_table` and
  `the_ruleset_names_this_interfaces_table` in `crates/vallum/src/policy.rs`,
  which pin the property.
