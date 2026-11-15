# Delivery Observe & Learn — `v1.7.0` (`2026-11-14`)

**Process:** `/software-delivery-process` Phase 8 (Observe), Phase 9 (Learn), and §11 (Gate-Skip record)  
**Release:** `v1.7.0` (`200da30`) — https://github.com/KidIkaros/vallum/releases/tag/v1.7.0 (private repo)

---

## 1. Observe — Four Delivery Metrics Snapshot

Baseline window: `2026-11-12` to `2026-11-14` (`v1.6.2` through `v1.7.0`).

| Metric | Observed Value (`v1.7.0` window) | Benchmark Tier | Evidence |
|---|---|---|---|
| **Deployment frequency** | 5 tagged releases in window (`v1.6.2`–`v1.7.0`), multiple deploys/day | High | `git tag -l "v1.*"` |
| **Lead time for changes** | Commit → `verify-remote.sh`: ~7m; Commit → `release.sh`: ~21m; `wingman-vps` CI/fuzz: ~30–50m | High (< 1 hr) | `task-3788`, `task-3798`, `gh run list` |
| **Time to restore service (MTTR)** | < 1 hr (manual/scripted rollback & `verify-remote.sh --clean-remote`) | High (< 1 hr) | Observed on `wingman-vps` |
| **Change fail rate** | 1 observed CI fuzz failure on `c10dc7c` prior to `200da30` (under 15% across release commits) | High (0–15%) | `gh run list` (`43655439930`) |

**Re-measure date:** `2026-11-28` (or at `v1.8.0` cut, whichever comes first).

### Context Measures
- **Deployment pain:** Moderate locally, low remotely.
  - Local `ci-local.sh` locks up the developer workstation; heavy CI is offloaded to `wingman-vps`.
  - Local `target/debug` grew to `77 GB`, causing `rustc-LLVM ERROR: No space left on device` (`os error 28`) during `cargo test` until manually cleared.
- **Unplanned vs. new work share:** Majority planned feature/hardening work (TLS/QUIC carriers, 2-hop `via`, API fronting, Clean Code refactor), with unplanned fixes for disk exhaustion, `rustix` `"fs"` feature mismatch in lean builds, and `fuzz/Cargo.lock` sync.

---

## 2. Capabilities to Invest In (Next Cycle)

| Capability (Low/Medium) | Predicted Metric Moved | Concrete Action |
|---|---|---|
| **Test automation & gate freshness** | Change fail rate, Lead time | Run or refresh `accept-install`, `accept-install-layout`, `accept-ops`, `accept-pair` on `wingman-vps`/CI so `release.sh` does not ship with stale stamps. |
| **Build hygiene & CI offload** | Deployment pain, Lead time | Bound `target/debug` / incremental cache growth (`cargo-sweep` or separate `CARGO_TARGET_DIR` cleanup) and keep heavy workspace/feature-matrix builds on `wingman-vps`. |
| **Packaging & clean install/uninstall** | Deployment frequency, Release gate coverage | Close the §7 clean-machine install/uninstall loop for Linux desktop (`vallum-gui`) + CLI/systemd, and frame Android APK packaging. |

---

## 3. Gate-Skip Registry (§11) for `v1.7.0`

`scripts/release.sh` passed `verify.sh` (`E2E=1`), `fuzz.sh` (60s/target), and `verify-remote.sh` on `200da30`, but logged **4 stale acceptance stamps**:

| Skipped / Stale Gate | Last Verified Commit | Risk Left Unchecked | Follow-up Owner & Due Date |
|---|---|---|---|
| `accept-install` (2 assertions) | `ff96038` | Clean-machine installer behavior after `v1.7.0` unit/completion/binary changes | Operator / `2026-11-21` |
| `accept-install-layout` (4 assertions) | `f164617` | Installed file layout vs. `v1.7.0` packaging manifest | Operator / `2026-11-21` |
| `accept-ops` (10 assertions) | `862043d` | `vallum-ops` wrapper flows after `1.7.0` changes | Operator / `2026-11-21` |
| `accept-pair` (88 assertions) | `f164617` | Full pairing matrix after `200da30` `TransportOptions` / `tls_quic` refactor | Operator / `2026-11-21` |

---

## 4. Learn — Surprises & Durable Changes

1. **Surprise:** `target/debug` reached `77 GB` and broke `cargo test` mid-release prep with `os error 28`.
   - **Durable change:** Add a preflight disk-space check (e.g., require ≥ 15 GB free) or periodic `cargo sweep` in developer/release scripts.
2. **Surprise:** `crates/vallum/Cargo.toml` omits `rustix`'s `"fs"` feature, which only surfaced on standalone `-p vallum` builds (`vallum-gui` uses `default-features = false`).
   - **Durable change:** Ensure `wingman-vps` CI checks `-p vallum --no-default-features` and `-p vallum-gui` explicitly so feature-flag drift fails fast.
3. **Surprise:** `release.sh` warns on stale `accept-*` stamps rather than gating or refreshing them, which normalizes shipping with stale acceptance evidence.
   - **Durable change:** Decide via ADR/gate update whether stale `accept-*` stamps block releases or auto-trigger on `wingman-vps` prior to tagging.
