# Architecture Decision Records

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [0001](0001-configured-psk.md) | Mix a configured PSK after the UKS psk, and keep it out of the identity | accepted | 2026-10-19 |
| [0002](0002-wireguard-uapi.md) | WireGuard-style UAPI over a 0600 Unix socket | accepted | 2026-10-19 |
| [0003](0003-runtime-socket-rebind.md) | Runtime socket rebind with a generation-checked SharedSocket | accepted | 2026-10-19 |
| [0004](0004-vallum-config.md) | Extract the TOML schema into vallum-config | accepted | 2026-10-19 |
| [0005](0005-linux-only-platform-scope.md) | Linux-only platform scope for this release | accepted | 2026-10-19 |
| [0006](0006-udp-batching.md) | Batch UDP sends with sendmmsg; defer GSO/GRO | accepted | 2026-10-19 |
| [0007](0007-psk-init-tag.md) | Authenticate InitHello with a configured-PSK admission tag | accepted | 2026-10-19 |
| [0008](0008-tui.md) | A feature-gated `vallum tui` operations console | accepted | 2026-10-19 |
| [0009](0009-client-bundle-qr.md) | A versioned client bundle and animated multi-frame QR | accepted | 2026-10-19 |
| [0010](0010-default-suite.md) | Keep the tri-hybrid default and document a fast profile | accepted | 2026-10-19 |
| [0011](0011-macos-out-of-scope.md) | macOS is out of scope for v0.1 | accepted | 2026-10-19 |
| [0012](0012-code-based-kem-roadmap.md) | Defer a code-based KEM; prefer HQC or provisioned McEliece later | accepted | 2026-10-19 |
| [0013](0013-server-provisioning.md) | Server provisioning is a CLI, not a control plane | accepted | 2026-10-20 |
| [0014](0014-wireguard-gaps.md) | Close the WireGuard gaps Vallum can win | accepted | 2026-10-20 |
| [0015](0015-enrolment-v2.md) | Enrolment v2 — the PQ-WireGuard shape, applied to provisioning | accepted | 2026-10-21 |
| [0016](0016-nat-traversal.md) | NAT traversal and relay — what we will and will not do | proposed | 2026-10-21 |
| [0017](0017-runtime-directory-ownership.md) | The runtime directory is a machine resource, not a service's private state | proposed | 2026-10-21 |
