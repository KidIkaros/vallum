# Vallum UTCP (Universal Tool Calling Protocol) Manual

This directory contains the **Universal Tool Calling Protocol (UTCP)** manual for Vallum: [`vallum.utcp.json`](vallum.utcp.json).

## Why UTCP for Vallum?

AI agents fail when trying to run interactive terminal applications like `vallum tui` because agent execution harnesses do not allocate an interactive pseudo-terminal (TTY).

UTCP provides a standardized, zero-overhead bridge:
- **No wrapper proxy daemon**: The agent calls `vallum` CLI directly.
- **Deterministic JSON**: `--json` wherever the verb offers it — `doctor`, `show`, `status`, `policy`, `keygen`, and the `peer` family — and Prometheus text from `metrics`.
- **Headless visual verification**: Exposes `vallum_tui_snapshot` (`vallum tui --snapshot`) so agents can inspect the dashboard layout without hanging or requiring a TTY.

## Available Tools

| Tool | CLI Command | Purpose |
|---|---|---|
| `vallum_doctor` | `vallum doctor --json` | Platform, tooling (ip, nft, systemctl), and control socket readiness check. |
| `vallum_doctor_config` | `vallum doctor --json --config <file>` | Validate configuration syntax and declared sockets. |
| `vallum_show_config` | `vallum show --json --config <file>` | Inspect offline configuration parameters and peer definitions. |
| `vallum_show_control` | `vallum show --json --control <socket>` | Real-time daemon telemetry: handshakes, bytes transferred, connected peers. |
| `vallum_keygen` | `vallum keygen --suite <id> --output <file> --json` | Generate a KEM-only keypair; reports `action`, `output`, `suite`, `signing`, `public` (default: tri-hybrid Suite 3). |
| `vallum_keygen_signing` | `vallum keygen --suite <id> --output <file> --signing --json` | Generate a keypair with a hybrid signing pair (P3 identity, for a CA). |
| `vallum_pubkey` | `vallum pubkey --private-key <file>` | Extract public identity line from a private key file. |
| `vallum_genpsk` | `vallum genpsk` | Generate a 32-byte (64 hex character) preshared key. |
| `vallum_bench` | `vallum bench --iterations <n> --bytes <n>` | Benchmark PQ data plane seal/open latency and throughput. |
| `vallum_syncconf` | `vallum syncconf <file>` | Apply atomic peer configuration diffs to a running tunnel. |
| `vallum_tui_snapshot` | `vallum tui --snapshot ...` | Capture a headless ASCII render of the cockpit dashboard. |
| `vallum_status` | `vallum status --config <file> --json` | Answer "in the tunnel, blocked, or leaking?" by reading the host, so it works with the daemon dead. |
| `vallum_policy` | `vallum policy on\|off\|status --config <file> --json` | Install, remove, or report the fail-closed egress block, as one object: `declared`, `policy`, `guard`, `egress`, `fix`. |
| `vallum_metrics` | `vallum metrics --config <file>` | Prometheus metrics, including `vallum_peer_delivery_ratio`. |
| `vallum_peer_list` | `vallum peer list --config <file>` | Peers, prefixes, endpoints and fingerprints. |
| `vallum_peer_show` | `vallum peer show <name> --config <file>` | One peer in full — the read to do before a remove. |
| `vallum_peer_add` | `vallum peer add <name> --config <file> --public-key <line>` | Enrol a device that generated its own key. |
| `vallum_peer_invite` | `vallum peer invite <name> --config <file> --ttl <min>` | Mint a single-use `vallum1-join:` ticket, no SSH needed. |
| `vallum_peer_invites` | `vallum peer invites --config <file>` | Live invites, TTL left, spent or not. Tokens are never listed. |
| `vallum_peer_remove` | `vallum peer remove <name> --config <file>` | Remove a peer; returns the backup path, the only undo. |
| `vallum_server_init_plan` | `vallum server init --config <file> --dry-run` | Print every host change provisioning would make. No root needed. |
| `vallum_server_init` | `vallum server init --config <file> --json` | Provision this host as a server: keys, units, port, forwarding, masquerade. |
| `vallum_server_teardown_plan` | `vallum server teardown --config <file> --dry-run` | Print what teardown would remove. No root needed. |
| `vallum_server_teardown` | `vallum server teardown --config <file>` | Reverse `server init`: units, NAT, firewall, sysctl. Keeps the config and key. |

### Activation

A host gets a tunnel three ways. Each has a plan tool, because the apply tool
starts a root daemon and changes the host:

| Tool | CLI Command | Purpose |
|---|---|---|
| `vallum_join_plan` | `vallum join <ticket> --dry-run` | Print what a ticket would write and start. Contacts nothing. |
| `vallum_join` | `vallum join <ticket>` | Enrol this machine with the one-time `vallum1-join:…` ticket. |
| `vallum_import_bundle` | `vallum import-bundle <file> --install` | Install a client from a `.vallum-bundle`: `/etc/vallum`, key, units, started. |
| `vallum_stop` | `vallum stop --config <file>` | Ask the daemon to stop and wait for its acknowledgement. |

## Three rules the manual follows

1. **Every placeholder is a required input, and every input reaches the
   command.** A UTCP CLI template substitutes its placeholders verbatim, so an
   optional one arrives as an empty string and `--suite UTCP_ARG_suite_UTCP_END`
   becomes `--suite --output …`. Where the CLI has a default, the manual asks for
   the default explicitly (`bench`, `tui_snapshot`). The mirror image matters
   too: an input no placeholder reads is decoration, and a caller setting it
   learns nothing — `vallum_status` declared `json` while its command already
   passed `--json`, and `vallum_metrics` declared `control`, `prefix` and
   `output` that no template passed on.
2. **Anything that starts or stops host services has a plan tool beside it.**
   `server init`, `server teardown` and `join` each ship with a `_plan` variant
   running the same command under `--dry-run`, so an agent can show its work
   before it acts.
3. **A verb with no dry run is paired with the read that makes it safe.**
   `peer remove` publishes `backup` and nothing else, so `vallum_peer_show` is
   shipped beside it and the description says to call it first. Flags that a
   template cannot express — a repeated `--address`, `--purge`, `--force`,
   `--allow-hooks`, `--dns`, `--bundle-out`, `--prefix`, `--output` — are named
   in the tool description as shell-only, rather than silently missing.

`crates/vallum/tests/utcp_manual.rs` holds the manual against the binary on four
points: every tool has a call template, every placeholder is a required input,
every declared input is read by a placeholder, and both the subcommand and every
flag in each template exist in `--help`. It runs in `cargo test --workspace`,
which is what CI runs on every push.

## Agent Usage

### With the Python SDK

Two packages, not one: `utcp` carries the client and models, and **`utcp-cli`
registers the `cli` call-template type** every tool here uses. Without the
second, `CallTemplateSerializer` has no `cli` entry and every tool fails to
parse.

```sh
pip install utcp utcp-cli
```

```python
import asyncio
from utcp.plugins.plugin_loader import ensure_plugins_initialized
ensure_plugins_initialized()          # registers `cli` from utcp-cli

from utcp.data.call_template import CallTemplateSerializer
from utcp.data.tool import Tool
from utcp_cli.cli_communication_protocol import CliCommunicationProtocol

import json
tools = {t["name"]: Tool.model_validate(t)
         for t in json.load(open("packaging/utcp/vallum.utcp.json"))["tools"]}

protocol = CliCommunicationProtocol()
result = asyncio.run(protocol.call_tool(
    None, "vallum_doctor", {}, tools["vallum_doctor"].tool_call_template))
print(result)
```

A tool that fails (missing config, no permission, `vallum_status` saying
`LEAKING`) comes back as the command's **stderr text**, not an exception — read
it, it is the product's own sentence about what to fix next.

Python parses JSON stdout for you, so `vallum_doctor` returns a list and
`vallum_peer_add` returns a dict. The TypeScript CLI protocol parses too, but
only when stdout is a JSON object: `vallum_keygen` returns an object, while
`vallum_doctor` (a top-level array) and `vallum_genpsk` (bare text) come back
as strings the caller parses. A caller that accepts both shapes works against
either SDK — and a `--json` success writes nothing to stderr, because transports
that merge the streams would otherwise corrupt the object.

### With the TypeScript SDK

```sh
npm install @utcp/sdk @utcp/cli @utcp/file
```

```typescript
import { UtcpClient } from '@utcp/sdk';
import { FileCallTemplateSerializer } from '@utcp/file';
import { register } from '@utcp/cli';

register();   // the `cli` call-template type

const manual = new FileCallTemplateSerializer().validateDict({
  name: 'vallum',
  call_template_type: 'file',
  file_path: 'packaging/utcp/vallum.utcp.json',
  // The file transport only registers tools whose protocol it allows.
  allowed_communication_protocols: ['cli'],
});

const client = await UtcpClient.create(process.cwd(), {
  manual_call_templates: [manual],
});
const doctor = await client.callTool('vallum.vallum_doctor', {});
```

Two client-side requirements, neither of them visible in the manual: tools are
namespaced under the template's `name` (`vallum.vallum_doctor`), and without
`allowed_communication_protocols: ['cli']` the file transport refuses every tool
with *"uses communication protocol 'cli' which is not in allowed protocols
['file']"*.

**Version note (checked 2026-11-12).** The two SDKs disagree about the manual's
envelope, and this file follows the specification: `utcp_version`,
`manual_version`, `tools` — nothing else.

- `utcp` 1.2.0 (Python) still wants `{version, tools}`, so it rejects this file
  as a whole; validate tools individually as the snippet above does.
- `@utcp/sdk` 1.2.0 (TypeScript) accepts the versions but is **strict** about
  extra keys — the `name` and `description` this file used to carry made it fail
  with `unrecognized_keys` and register zero tools. That is why they are gone,
  and why the description of each tool says what it does.

`$schema` was removed for the same reason it would be useless: the URL the
specification's own manuals point at
(`.../utcp-specification/main/schemas/manual.schema.json`) returns 404.
