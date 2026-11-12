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
| [0016](0016-nat-traversal.md) | NAT traversal and relay — what we will and will not do | superseded by [0027](0027-mesh-topology-and-control-plane.md) | 2026-10-21 |
| [0017](0017-runtime-directory-ownership.md) | The runtime directory is a machine resource, not a service's private state | accepted | 2026-10-21 |
| [0018](0018-fail-closed-egress.md) | A packet leaves only through the tunnel, or to the endpoint | accepted | 2026-10-22 |
| [0019](0019-passive-side-reinitiates.md) | The passive side re-initiates, so a restart costs seconds not 120 s | implemented | 2026-10-22 |
| [0020](0020-gateway-forwarding-source-policy.md) | Forwarded replies mix sources; the egress check must not eat them | accepted | 2026-10-22 |
| [0021](0021-live-rotation-syncconf.md) | A live `set` names the rotation window, not a replacement peer | accepted | 2026-10-23 |
| [0022](0022-shaping-policy-in-core.md) | Traffic shaping is a passive policy machine in `vallum-core`; the `Device` is its single driver | accepted | 2026-10-23 |
| [0023](0023-per-app-split-tunnelling.md) | Per-app split tunnelling rides the tunnel's mark tables, with launch-bound membership | implemented (classifier only; exclusive path deferred — 2026-10-28 amendment) | 2026-10-23 |
| [0024](0024-desktop-ui.md) | A Tauri v2 desktop UI that reuses the Rust control client; x86_64 only | accepted | 2026-11-05 |
| [0025](0025-moor-techniques-not-code.md) | Take MOOR's padding and scheduling techniques as bounded shapes, not its code | proposed | 2026-11-06 |
| [0026](0026-censorship-resistance.md) | Censorship resistance is a separate surface from traffic shaping | proposed | 2026-11-06 |
| [0027](0027-mesh-topology-and-control-plane.md) | Mesh topology as an external agent — vallum-core stays a tunnel | proposed | 2026-11-07 |
| [0028](0028-seccomp-filter.md) | A seccomp filter, derived from the daemon's own syscall surface | accepted (log mode) | 2026-11-08 |
| [0029](0029-ops-trust-model.md) | Ops trust model — dev dispatcher vs production pinning | accepted for development | 2026-11-10 |
| [0030](0030-fragment-admission-control.md) | Admission control on the fragment path, before reassembly | proposed | 2026-11-11 |
| [0031](0031-stale-timestamp-scope.md) | A stale initiation is refused only while a session exists | accepted | 2026-11-11 |
| [0032](0032-reader-thread-admission.md) | The admission allowance belongs in the socket reader | accepted | 2026-11-11 |
| [0033](0033-bundle-policy-report.md) | An imported bundle states its policy, and a weak one is refused | proposed | 2026-11-11 |
