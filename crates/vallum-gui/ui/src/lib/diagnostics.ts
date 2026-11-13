import type { Health } from "@/lib/bridge"

export interface ErrorCodeEntry {
  code: string
  title: string
  category: "CONTROL" | "CONFIG & KEYS" | "DAEMON & OS" | "EGRESS & LEAKS" | "CRYPTO"
  exitCode: 1 | 2
  exitLabel: string
  summary: string
  remediation: string
  command?: string
}

export const EXIT_CODES = [
  {
    code: 0,
    label: "EXIT 0 · OK",
    tone: "text-live" as const,
    meaning: "Operation completed cleanly and runtime/config checks passed.",
  },
  {
    code: 1,
    label: "EXIT 1 · COMMAND / VERDICT FAILED",
    tone: "text-fault" as const,
    meaning:
      "Something was attempted and failed (e.g. `vallum doctor` detected an unprotected client, handshake refusal, or unit crash). Surface diagnostics and do not retry blindly.",
  },
  {
    code: 2,
    label: "EXIT 2 · PRECONDITION / USAGE",
    tone: "text-stale" as const,
    meaning:
      "Nothing was attempted because an environment precondition or CLI usage rule failed (missing config, absent control socket, bad key permissions, unknown flag). Fix the host precondition and retry.",
  },
] as const

export const ERROR_CATALOG: readonly ErrorCodeEntry[] = [
  {
    code: "VAL-E101",
    title: "Control socket permission gate",
    category: "CONTROL",
    exitCode: 2,
    exitLabel: "EXIT 2 · PRECONDITION",
    summary:
      "Write commands are refused because the control socket is not mode 0600 or the runtime directory is world-writable. A wider mode exposes `--dump` (including the private key) to other local users.",
    remediation:
      "Let systemd or `install.sh` recreate the runtime directory with `0770` group permissions and `0600` socket mode.",
    command: "sudo scripts/install.sh --local --install-only",
  },
  {
    code: "VAL-E102",
    title: "Runtime directory unreadable by console user",
    category: "CONTROL",
    exitCode: 2,
    exitLabel: "EXIT 2 · PRECONDITION",
    summary:
      "A daemon control socket exists, but the current desktop/web user lacks group access to open `/run/vallum` (or `$VALLUM_RUNTIME_DIR`).",
    remediation:
      "Run the installer so your user's group owns the `0770` socket directory, then reload or restart your user session.",
    command: "sudo scripts/install.sh --local --install-only",
  },
  {
    code: "VAL-E103",
    title: "Control socket silent or daemon not running",
    category: "CONTROL",
    exitCode: 2,
    exitLabel: "EXIT 2 · PRECONDITION",
    summary:
      "No running `vallum` daemon answered on the Unix control socket (`ENOENT` / `ECONNREFUSED`). If this host expects a full tunnel, traffic is currently unencrypted on the physical interface.",
    remediation:
      "Start the tunnel systemd unit or verify why the process exited using journald logs.",
    command: "sudo systemctl start vallum@vallum0",
  },
  {
    code: "VAL-E201",
    title: "Private key permissions too open",
    category: "CONFIG & KEYS",
    exitCode: 2,
    exitLabel: "EXIT 2 · PRECONDITION",
    summary:
      "The daemon refused to load a private key readable by group or world (`mode != 0600`). Vallum treats group/world-readable private keys as a hard stop rather than a warning.",
    remediation:
      "Restrict key permissions to owner read/write only (`0600`) owned by `root:root`.",
    command: "sudo chmod 600 /etc/vallum/*.key && sudo chown root:root /etc/vallum/*.key",
  },
  {
    code: "VAL-E202",
    title: "Config ownership / CAP_DAC_OVERRIDE denied",
    category: "CONFIG & KEYS",
    exitCode: 2,
    exitLabel: "EXIT 2 · PRECONDITION",
    summary:
      "The systemd unit drops `CAP_DAC_OVERRIDE`, so even root cannot read files owned by another user if mode is `0600`. Copying a config in as a desktop user triggers `Permission denied`.",
    remediation: "Reclaim root ownership and `0600` permissions on `/etc/vallum` files.",
    command: "sudo chown root:root /etc/vallum/*.toml && sudo chmod 600 /etc/vallum/*.toml",
  },
  {
    code: "VAL-E203",
    title: "Configuration TOML / routing table validation failure",
    category: "CONFIG & KEYS",
    exitCode: 2,
    exitLabel: "EXIT 2 · PRECONDITION",
    summary:
      "The configuration failed syntax parsing, overlapped `allowed_ips` across two peers, or referenced mismatched key suites. Vallum refuses invalid tables and keeps your backup.",
    remediation: "Validate and inspect warnings with `vallum doctor` before restarting the unit.",
    command: "sudo vallum doctor --config /etc/vallum/vallum0.toml",
  },
  {
    code: "VAL-E301",
    title: "Seccomp syscall filter violation (status=31/SYS)",
    category: "DAEMON & OS",
    exitCode: 1,
    exitLabel: "EXIT 1 · DAEMON FAULT",
    summary:
      "The hardened seccomp BPF sandbox terminated the daemon (`SIGSYS` / `status=31/SYS`) after an unexpected syscall. Check the journal immediately around the exit.",
    remediation: "Inspect the last unit exit and check sandbox configuration with `vallum doctor`.",
    command: "sudo journalctl -u vallum@vallum0 -n 120 --no-pager",
  },
  {
    code: "VAL-E302",
    title: "TUN device / interface creation refused (EPERM)",
    category: "DAEMON & OS",
    exitCode: 1,
    exitLabel: "EXIT 1 · OS CAPABILITY",
    summary:
      "Opening the layer-3 TUN device failed due to missing `CAP_NET_ADMIN` or absent `/dev/net/tun` kernel module.",
    remediation:
      "Start via systemd (which grants `CAP_NET_ADMIN`) or verify `/dev/net/tun` exists on this host.",
    command: "ls -l /dev/net/tun && sudo systemctl status vallum@vallum0",
  },
  {
    code: "VAL-E303",
    title: "Polkit / systemd unit action authorization denied",
    category: "DAEMON & OS",
    exitCode: 1,
    exitLabel: "EXIT 1 · AUTH DENIED",
    summary:
      "The desktop console's polkit/sudoers rule was not authorized or dismissed, so the systemd unit state did not change.",
    remediation:
      "Run the `systemctl` lifecycle command in an elevated terminal or install the console sudoers rule.",
    command: "sudo systemctl restart vallum@vallum0",
  },
  {
    code: "VAL-E401",
    title: "Full-tunnel DNS leak detected",
    category: "EGRESS & LEAKS",
    exitCode: 1,
    exitLabel: "EXIT 1 · EGRESS FAULT",
    summary:
      "Default IPv4 traffic rides the tunnel, but DNS lookups leave via a physical resolver instead of the tunnel link.",
    remediation:
      "Attach `dns` servers inside the interface config or revert to split mode via the panic switch.",
    command: "resolvectl status",
  },
  {
    code: "VAL-E402",
    title: "Full-tunnel IPv6 egress leak detected",
    category: "EGRESS & LEAKS",
    exitCode: 1,
    exitLabel: "EXIT 1 · EGRESS FAULT",
    summary:
      "IPv6 traffic has a route outside the tunnel interface while `vallum-guard` is inactive.",
    remediation:
      "Engage `vallum-guard` (full-tunnel trial) or add `::/0` into the tunnel peer's `allowed_ips`.",
    command: "sudo systemctl start vallum-guard@vallum0",
  },
  {
    code: "VAL-E403",
    title: "Full-tunnel configured but host is UNPROTECTED",
    category: "EGRESS & LEAKS",
    exitCode: 1,
    exitLabel: "EXIT 1 · UNPROTECTED",
    summary:
      "The configuration expects `0.0.0.0/0` protection, yet traffic is leaving via a physical interface or the guard is stranded without a live tunnel.",
    remediation:
      "If internet connectivity is blocked or unsafe, run `vallum-panic` to restore clean physical routes, then inspect logs.",
    command: "sudo vallum-panic",
  },
  {
    code: "VAL-E501",
    title: "Cryptographic suite or public line mismatch",
    category: "CRYPTO",
    exitCode: 2,
    exitLabel: "EXIT 2 · VALIDATION",
    summary:
      "The peer's `vallum1:<suite>:<kem>:<signing>` line uses a different cryptographic suite ID than the local interface (e.g. non-`0x0003` tri-hybrid) or failed decoding.",
    remediation:
      "Regenerate the device keypair using the same suite ID as the interface before adding or rotating the peer.",
    command: "vallum keygen --suite 3",
  },
  {
    code: "VAL-E502",
    title: "Authenticated datagrams rejected (peer/server key changed)",
    category: "CRYPTO",
    exitCode: 1,
    exitLabel: "EXIT 1 · KEY MISMATCH",
    summary:
      "Datagrams from this peer passed outer framing but failed cryptographic verification (`vallum_dropped_after_auth > 0`). On a client, this means the server's key changed after enrollment rather than a dead network path.",
    remediation:
      "Mint a fresh invite or rotate the peer's public line so both sides agree on the current identity.",
    command: "sudo vallum peer list --config /etc/vallum/vallum0.toml",
  },
] as const

/** Map any raw daemon, socket, systemd, or validation message to a structured VAL-E* entry. */
export function matchDiagnostic(text: string | null | undefined): ErrorCodeEntry | null {
  if (!text) return null
  const msg = text.toLowerCase()
  if (/not 0600|writes refused|--dump/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E101") ?? null
  }
  if (/control socket unreadable|cannot open none|0770/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E102") ?? null
  }
  if (/31\/sys|sigsys|syscall filter/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E301") ?? null
  }
  if (/cap_dac_override|uid .* gid/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E202") ?? null
  }
  if (/insecure-key-permissions|chmod 600|key permissions/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E201") ?? null
  }
  if (/polkit|not authorized|authentication|sudoers/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E303") ?? null
  }
  if (/cap_net_admin|\/dev\/net\/tun|open interface/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E302") ?? null
  }
  if (/toml|peer table refused|overlaps|allowed_ips/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E203") ?? null
  }
  if (/dropped_after_auth|key changed after enrollment/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E502") ?? null
  }
  if (/suite .* does not match|decode_public|vallum1:/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E501") ?? null
  }
  if (/no such file|connection refused|socket.*silent|no daemon|enoent|econnrefused/.test(msg)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E103") ?? null
  }
  return null
}

/** Classify live host egress health into structured leak/exposure error codes. */
export function matchHealthDiagnostic(health: Health | null): ErrorCodeEntry | null {
  if (!health) return null
  const guarded = health.guard.active === "active"
  const tunnelled = health.route4_via_tunnel
  const v6Leaks = health.route6 !== null && !health.route6_via_tunnel && !guarded
  const dnsLeaks = health.expected_full && health.dns.length > 0 && !health.dns_via_tunnel
  if (tunnelled && dnsLeaks) return ERROR_CATALOG.find((e) => e.code === "VAL-E401") ?? null
  if (tunnelled && v6Leaks) return ERROR_CATALOG.find((e) => e.code === "VAL-E402") ?? null
  if ((guarded && !tunnelled) || (health.expected_full && !tunnelled)) {
    return ERROR_CATALOG.find((e) => e.code === "VAL-E403") ?? null
  }
  if (health.last_death) {
    return matchDiagnostic(health.last_death)
  }
  return null
}
