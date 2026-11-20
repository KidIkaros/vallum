# Security policy

## Supported versions

The current release line is `1.x`. Security fixes land on `main` and are
released as a patch tag. The trust model and explicit non-claims are in
[docs/security-model.md](docs/security-model.md).

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository
(Security → Advisories → Report a vulnerability). If that feature is not
available on the repository plan, open a minimal issue asking for a private
channel and do not include exploit details, keys, or packet captures.

Please include:

- the affected version or commit;
- the platform and kernel;
- a minimal reproduction or a description of the protocol state;
- whether the issue is in the protocol, the daemon, the TUI, or packaging.

## Scope

In scope: the handshake and key schedule, the data plane and replay window, the
control UAPI, privilege separation, the TUI's command execution, the installer,
and release artefacts.

Out of scope for a *fix here*: the `origin-crypto-sdk` implementation (the fix
lands in that repository), vulnerabilities that require the private key or root,
and documented non-claims in `docs/proof/` (for example identity hiding/IK and
single-packet handshakes).

**But report SDK findings to us too.** The post-quantum promise is the product's
core claim, so a flaw in the shared crypto implementation matters to Vallum even
though the fix lands upstream: use private reporting here as well, so the operator
can warn users and weigh the alpha's trust posture. Routing a finding only upstream
severs the feedback loop for the exact claim being validated.

## Assurance posture (what is and isn't verified)

The trust path should end in evidence, not only a disclaimer:

- **Verified here:** the handshake and key schedule, the data-plane replay window,
  privilege separation, and the installer are exercised by `scripts/verify.sh` and
  the two-host gate; a self-conducted adversary pass is recorded in
  [docs/proof/pentest.md](docs/proof/pentest.md); the daemon is
  `#![forbid(unsafe_code)]` (one audited `mlockall`).
- **Not verified:** the `origin-crypto-sdk` primitives are experimental and have had
  no external audit. The tri-hybrid design diversifies *algorithm* risk, but X25519,
  the combiner KDF, the AEAD and the RNG all share that one implementation — a single
  implementation bug can defeat all three legs at once. Hybrid composition is not a
  substitute for an audited implementation. See
  [docs/security-model.md](docs/security-model.md).

## What we will not do

We do not put secrets in issues, logs, or the TUI's default view. If a report
requires a key, use a test key only.
