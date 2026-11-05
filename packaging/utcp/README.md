# Vallum UTCP (Universal Tool Calling Protocol) Manual

This directory contains the **Universal Tool Calling Protocol (UTCP)** manual for Vallum: [`vallum.utcp.json`](vallum.utcp.json).

## Why UTCP for Vallum?

AI agents fail when trying to run interactive terminal applications like `vallum tui` because agent execution harnesses do not allocate an interactive pseudo-terminal (TTY).

UTCP provides a standardized, zero-overhead bridge:
- **No wrapper proxy daemon**: The agent calls `vallum` CLI directly.
- **Deterministic JSON**: Operates over `--json` and structured subcommands (`doctor`, `show`, `keygen`, `syncconf`, `bench`).
- **Headless visual verification**: Exposes `vallum_tui_snapshot` (`vallum tui --snapshot`) so agents can inspect the dashboard layout without hanging or requiring a TTY.

## Available Tools

| Tool | CLI Command | Purpose |
|---|---|---|
| `vallum_doctor` | `vallum doctor --json` | Platform, tooling (ip, nft, systemctl), and control socket readiness check. |
| `vallum_doctor_config` | `vallum doctor --json --config <file>` | Validate configuration syntax and declared sockets. |
| `vallum_show_config` | `vallum show --json --config <file>` | Inspect offline configuration parameters and peer definitions. |
| `vallum_show_control` | `vallum show --json --control <socket>` | Real-time daemon telemetry: handshakes, bytes transferred, connected peers. |
| `vallum_keygen` | `vallum keygen --suite <id> --output <file>` | Generate post-quantum hybrid keypairs (default: tri-hybrid Suite 3). |
| `vallum_pubkey` | `vallum pubkey --private-key <file>` | Extract public identity line from a private key file. |
| `vallum_genpsk` | `vallum genpsk` | Generate a 32-byte (64 hex character) preshared key. |
| `vallum_bench` | `vallum bench --iterations <n> --bytes <n>` | Benchmark PQ data plane seal/open latency and throughput. |
| `vallum_syncconf` | `vallum syncconf -c <file>` | Apply atomic peer configuration diffs to a running tunnel. |
| `vallum_tui_snapshot` | `vallum tui --snapshot ...` | Capture a headless ASCII render of the cockpit dashboard. |
| `vallum_status` | `vallum status --config <file> [--json]` | Answer "in the tunnel, blocked, or leaking?" by reading the host, so it works with the daemon dead. |
| `vallum_policy` | `vallum policy on\|off\|status --config <file>` | Install, remove, or report the fail-closed egress block. |
| `vallum_metrics` | `vallum metrics --config <file>` | Prometheus metrics, including `vallum_peer_delivery_ratio`. |
| `vallum_peer_list` | `vallum peer list --config <file>` | Peers, prefixes, endpoints and fingerprints. |
| `vallum_server_init` | `vallum server init --config <file> [--dry-run]` | Provision this host as a server: keys, units, port, forwarding, masquerade. |

## Agent Usage

### With UTCP SDK (Python)
```python
from utcp import UTCPClient

client = UTCPClient()
client.load_manual("packaging/utcp/vallum.utcp.json")

# Run readiness diagnostics
diagnostics = client.call_tool("vallum_doctor")

# Generate post-quantum keypair
pubkey = client.call_tool("vallum_keygen", {"output_file": "/tmp/client.key", "suite": 3})
```
