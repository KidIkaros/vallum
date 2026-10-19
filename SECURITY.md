# Security policy

## Supported versions

The current release line is `0.1.x`. Security fixes land on `main` and are
released as a patch tag.

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

Out of scope: the `origin-crypto-sdk` implementation (report it to that
repository), vulnerabilities that require the private key or root, and
documented non-claims in `docs/proof/` (for example identity hiding/IK and
single-packet handshakes).

## What we will not do

We do not put secrets in issues, logs, or the TUI's default view. If a report
requires a key, use a test key only.
