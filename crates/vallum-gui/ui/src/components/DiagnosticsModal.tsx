import { useMemo, useState } from "react"
import { CopyButton } from "@/components/Copy"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { transportKind, type Health, type Preflight, type ServiceStatus } from "@/lib/bridge"
import {
  ERROR_CATALOG,
  EXIT_CODES,
  matchDiagnostic,
  matchHealthDiagnostic,
} from "@/lib/diagnostics"
import { suiteLabel } from "@/lib/validate"
import type { Snapshot } from "@/types"

export type DiagnosticsTab = "doctor" | "metrics" | "codes" | "dx" | "onboarding"

interface DoctorCheck {
  name: string
  status: "PASS" | "WARN" | "FAIL"
  detail: string
  code?: string
}

function buildDoctorChecks({
  facts,
  health,
  service,
  snapshot,
  error,
}: {
  facts: Preflight | null
  health: Health | null
  service: ServiceStatus | null
  snapshot: Snapshot | null
  error: string | null
}): DoctorCheck[] {
  const checks: DoctorCheck[] = []

  checks.push({
    name: "binaries & recovery",
    status: facts && facts.vallum && facts.quick && facts.panic ? "PASS" : facts ? "WARN" : "FAIL",
    detail: facts
      ? `vallum=${facts.vallum ? "ok" : "missing"} · quick=${facts.quick ? "ok" : "missing"} · panic=${facts.panic ? "ok" : "missing"} · deadman=${facts.deadman ? "ok" : "missing"}`
      : "host preflight helper did not answer",
    code: !facts ? "VAL-E103" : undefined,
  })

  const goodDirMode = facts && ["0770", "0775", "0777"].includes(facts.runtime_mode)
  checks.push({
    name: "runtime socket dir",
    status: facts ? (goodDirMode && facts.sockets > 0 ? "PASS" : "WARN") : "WARN",
    detail: facts
      ? `${facts.runtime_dir} (mode ${facts.runtime_mode}, ${facts.sockets} socket${facts.sockets === 1 ? "" : "s"})`
      : "unknown",
    code: facts && !goodDirMode ? "VAL-E102" : undefined,
  })

  const matchedErr = matchDiagnostic(error)
  checks.push({
    name: "control socket",
    status: snapshot && !error ? "PASS" : error ? "FAIL" : "WARN",
    detail: snapshot && !error ? `attached (${snapshot.interface})` : error || "waiting for snapshot",
    code: matchedErr?.code,
  })

  if (service) {
    checks.push({
      name: "systemd unit",
      status:
        service.active === "active"
          ? "PASS"
          : service.enabled === "not-found"
            ? "WARN"
            : "FAIL",
      detail: `${service.unit}: ${service.active} (${service.enabled})`,
      code: service.active === "failed" ? "VAL-E301" : undefined,
    })
  }

  if (health) {
    const healthDiag = matchHealthDiagnostic(health)
    checks.push({
      name: "egress & DNS",
      status: healthDiag ? "FAIL" : health.route4_via_tunnel ? "PASS" : "WARN",
      detail: health.route4_via_tunnel
        ? `tunnelled via ${health.route4} · DNS=${health.dns_via_tunnel ? "tunnel" : health.dns.join(",") || "none"}`
        : health.expected_full
          ? `full tunnel expected, route4 leaves via ${health.route4 ?? "none"}`
          : `split tunnel — egress via ${health.route4 ?? "physical"}`,
      code: healthDiag?.code,
    })

    checks.push({
      name: "process stability",
      status: health.restarts === 0 && !health.last_death ? "PASS" : "WARN",
      detail:
        health.restarts === 0 && !health.last_death
          ? "0 systemd restarts · clean uptime"
          : `${health.restarts} restart(s)${health.last_death ? ` · last exit: ${health.last_death}` : ""}`,
      code: health.last_death ? matchDiagnostic(health.last_death)?.code : undefined,
    })
  }

  if (snapshot) {
    const counters = snapshot.counters
    const authDropPeers = snapshot.peers.filter((p) => p.dropped_after_auth > 0).length
    const allowlistDropPeers = snapshot.peers.filter((p) => p.dropped_allowed_ips > 0).length
    const anomalies =
      counters.datagrams_failed +
      counters.packets_failed +
      counters.refusals +
      counters.fragments_dropped +
      counters.dropped_malformed +
      counters.dropped_unknown_index +
      counters.fragments_rate_limited +
      snapshot.peers.reduce((acc, p) => acc + p.dropped_after_auth + p.dropped_allowed_ips, 0)
    checks.push({
      name: "dataplane counters",
      status: authDropPeers > 0 ? "FAIL" : anomalies === 0 ? "PASS" : "WARN",
      detail: `${counters.datagrams_sent} datagrams sent · ${counters.packets_delivered} packets delivered · ${counters.established} handshakes · ${anomalies} anomaly counter(s)${authDropPeers > 0 ? ` · ${authDropPeers} peer(s) failed post-auth` : ""}${allowlistDropPeers > 0 ? ` · ${allowlistDropPeers} peer allowlist drop(s)` : ""}`,
      code: authDropPeers > 0 ? "VAL-E502" : undefined,
    })
  }

  return checks
}

export function DiagnosticsModal({
  open,
  onOpenChange,
  facts,
  health,
  service,
  snapshot,
  error,
  initialTab = "doctor",
  highlightCode,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  facts: Preflight | null
  health: Health | null
  service: ServiceStatus | null
  snapshot: Snapshot | null
  error: string | null
  initialTab?: DiagnosticsTab
  highlightCode?: string
}) {
  const safeInitial: Exclude<DiagnosticsTab, "onboarding"> =
    initialTab === "onboarding" ? "doctor" : initialTab
  const [tab, setTab] = useState<Exclude<DiagnosticsTab, "onboarding">>(
    highlightCode ? "codes" : safeInitial,
  )
  const [query, setQuery] = useState(highlightCode ?? "")
  const [exportMode, setExportMode] = useState<"prometheus" | "anonymized">("prometheus")

  const activeTab = tab

  const iface = snapshot?.interface || health?.interface || "vallum0"
  const unit = service?.unit || health?.unit || `vallum@${iface}`

  const checks = useMemo(
    () => buildDoctorChecks({ facts, health, service, snapshot, error }),
    [facts, health, service, snapshot, error],
  )

  const filteredCatalog = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return ERROR_CATALOG
    return ERROR_CATALOG.filter(
      (entry) =>
        entry.code.toLowerCase().includes(needle) ||
        entry.title.toLowerCase().includes(needle) ||
        entry.category.toLowerCase().includes(needle) ||
        entry.summary.toLowerCase().includes(needle) ||
        entry.remediation.toLowerCase().includes(needle),
    )
  }, [query])

  // Sanitized diagnostic bundle (explicitly strips public_line / peer keys / tokens).
  const diagnosticBundle = useMemo(
    () =>
      JSON.stringify(
        {
          interface: iface,
          suite: snapshot ? suiteLabel(snapshot.suite) : null,
          build: snapshot?.build ?? null,
          preflight: facts,
          service,
          health,
          counters: snapshot?.counters ?? null,
          peer_count: snapshot?.peers.length ?? 0,
          rotating_peers: snapshot?.peers.filter((p) => p.rotating).length ?? 0,
          last_control_error: error,
          doctor_checks: checks,
        },
        null,
        2,
      ),
    [iface, snapshot, facts, service, health, error, checks],
  )

  const peerRollup = useMemo(() => {
    const peers = snapshot?.peers ?? []
    return {
      total: peers.length,
      handshaked: peers.filter((p) => p.last_handshake_sec > 0).length,
      rotating: peers.filter((p) => p.rotating).length,
      window_received: peers.reduce((acc, p) => acc + p.window_received, 0),
      window_sent: peers.reduce((acc, p) => acc + p.window_sent, 0),
      dropped_after_auth: peers.reduce((acc, p) => acc + p.dropped_after_auth, 0),
      dropped_allowed_ips: peers.reduce((acc, p) => acc + p.dropped_allowed_ips, 0),
      dropped_no_session: peers.reduce((acc, p) => acc + p.dropped_no_session, 0),
      dropped_replay: peers.reduce((acc, p) => acc + p.dropped_replay, 0),
      reinit_offered: peers.reduce((acc, p) => acc + p.reinit_offered, 0),
    }
  }, [snapshot])

  const prometheusText = useMemo(() => {
    const c = snapshot?.counters
    const suite = snapshot?.suite || "unknown"
    const version = snapshot?.build || "unknown"
    const lines = [
      `vallum_up{interface="${iface}"} ${snapshot ? 1 : 0}`,
      `vallum_interface_info{interface="${iface}",suite="${suite}",version="${version}"} 1`,
      `vallum_loop_datagrams_sent_total{interface="${iface}"} ${c?.datagrams_sent ?? 0}`,
      `vallum_loop_datagrams_failed_total{interface="${iface}"} ${c?.datagrams_failed ?? 0}`,
      `vallum_loop_packets_delivered_total{interface="${iface}"} ${c?.packets_delivered ?? 0}`,
      `vallum_loop_packets_failed_total{interface="${iface}"} ${c?.packets_failed ?? 0}`,
      `vallum_loop_handshakes_established_total{interface="${iface}"} ${c?.established ?? 0}`,
      `vallum_loop_handshakes_refused_total{interface="${iface}"} ${c?.refusals ?? 0}`,
      `vallum_loop_reassembled_total{interface="${iface}"} ${c?.reassembled ?? 0}`,
      `vallum_loop_fragments_dropped_total{interface="${iface}"} ${c?.fragments_dropped ?? 0}`,
      `vallum_loop_dropped_malformed_total{interface="${iface}"} ${c?.dropped_malformed ?? 0}`,
      `vallum_loop_dropped_unknown_index_total{interface="${iface}"} ${c?.dropped_unknown_index ?? 0}`,
      `vallum_loop_fragments_rate_limited_total{interface="${iface}"} ${c?.fragments_rate_limited ?? 0}`,
      `vallum_handshake_dropped_no_mac_total{interface="${iface}"} ${c?.handshake_dropped_no_mac ?? 0}`,
      `vallum_handshake_dropped_unidentifiable_total{interface="${iface}"} ${c?.handshake_dropped_unidentifiable ?? 0}`,
      `vallum_handshake_dropped_unknown_peer_total{interface="${iface}"} ${c?.handshake_dropped_unknown_peer ?? 0}`,
      `vallum_handshake_dropped_endpoint_conflict_total{interface="${iface}"} ${c?.handshake_dropped_endpoint_conflict ?? 0}`,
      `vallum_handshake_dropped_stale_total{interface="${iface}"} ${c?.handshake_dropped_stale ?? 0}`,
      `vallum_peers_total{interface="${iface}"} ${peerRollup.total}`,
    ]
    return `${lines.join("\n")}\n`
  }, [iface, snapshot, peerRollup])

  const anonymizedSnapshot = useMemo(() => {
    const c = snapshot?.counters
    const activeCodes = Array.from(
      new Set(checks.map((chk) => chk.code).filter((code): code is string => Boolean(code))),
    )
    const ratio = (ok: number, fail: number) => {
      const total = ok + fail
      return total > 0 ? Math.round((ok / total) * 1000) / 1000 : 1
    }
    const bucket = (n: number) =>
      n === 0 ? "0" : n <= 5 ? "1-5" : n <= 50 ? "6-50" : n <= 500 ? "51-500" : "500+"
    return JSON.stringify(
      {
        schema: "vallum.telemetry.zero-pii.v1",
        opt_in_only: true,
        pii_stripped: ["interface", "peer_names", "ips", "endpoints", "public_lines"],
        transport: transportKind,
        suite: snapshot ? suiteLabel(snapshot.suite) : "unknown",
        egress_mode: snapshot?.expected_egress ?? (health?.expected_full ? "full" : "split"),
        offload: snapshot?.offload ?? null,
        batching: snapshot?.batching ?? null,
        active_error_codes: activeCodes,
        ratios: c
          ? {
              datagram_delivery: ratio(c.datagrams_sent, c.datagrams_failed),
              packet_delivery: ratio(c.packets_delivered, c.packets_failed),
              handshake_admission: ratio(c.established, c.refusals),
              fragment_admission: ratio(c.reassembled, c.fragments_dropped + c.fragments_rate_limited),
            }
          : null,
        drop_buckets: c
          ? {
              malformed: bucket(c.dropped_malformed),
              unknown_index: bucket(c.dropped_unknown_index),
              fragments_rate_limited: bucket(c.fragments_rate_limited),
              handshake_no_mac: bucket(c.handshake_dropped_no_mac),
              handshake_unidentifiable: bucket(c.handshake_dropped_unidentifiable),
              handshake_unknown_peer: bucket(c.handshake_dropped_unknown_peer),
              handshake_endpoint_conflict: bucket(c.handshake_dropped_endpoint_conflict),
              handshake_stale: bucket(c.handshake_dropped_stale),
              peer_after_auth: bucket(peerRollup.dropped_after_auth),
              peer_allowed_ips: bucket(peerRollup.dropped_allowed_ips),
              peer_replay: bucket(peerRollup.dropped_replay),
            }
          : null,
        peer_summary: {
          count_bucket: bucket(peerRollup.total),
          handshaked_count: peerRollup.handshaked,
          rotating_count: peerRollup.rotating,
        },
        host_funnel: {
          binaries_ready: Boolean(facts && facts.vallum && facts.quick && facts.panic),
          runtime_mode: facts?.runtime_mode ?? null,
          guard_active: health ? health.guard.active === "active" : null,
          dns_via_tunnel: health?.dns_via_tunnel ?? null,
          service_restarts: health?.restarts ?? null,
        },
      },
      null,
      2,
    )
  }, [snapshot, checks, health, peerRollup, facts])

  const cliSnippets = [
    {
      label: "Run host readiness doctor (with active path probe)",
      cmd: `sudo vallum doctor --config /etc/vallum/${iface}.toml --probe-path`,
    },
    {
      label: "Inspect live interface + peer state",
      cmd: `sudo vallum show ${iface}`,
    },
    {
      label: "Machine-readable telemetry JSON (Prometheus / scripts)",
      cmd: `sudo vallum metrics --config /etc/vallum/${iface}.toml --json`,
    },
    {
      label: "Hot-sync runtime peers without dropping sessions",
      cmd: `sudo vallum syncconf ${iface} /etc/vallum/${iface}.toml`,
    },
    {
      label: "Follow daemon systemd logs",
      cmd: `sudo journalctl -u ${unit} -n 200 -f`,
    },
    {
      label: "Emergency internet recovery (drops guard + restores routes)",
      cmd: "sudo vallum-panic",
    },
  ]

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setQuery("")
        onOpenChange(next)
      }}
    >
      <DialogContent className="max-h-[88svh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="text-foreground text-base font-semibold">
            System Health &amp; Diagnostics
          </DialogTitle>
          <DialogDescription className="text-xs">
            Sanitized host readiness checks, live counters, error catalog (<code className="font-mono">VAL-E*</code>), and optional headless terminal commands.
          </DialogDescription>
        </DialogHeader>

        <div
          role="tablist"
          aria-label="Diagnostics sections"
          className="border-border/70 bg-background/50 flex flex-wrap gap-1 rounded-lg border p-1"
        >
          {(
            [
              ["doctor", "Health Checks"],
              ["metrics", "Telemetry & Metrics"],
              ["codes", `Error Reference (${ERROR_CATALOG.length})`],
              ["dx", "Headless CLI"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={activeTab === id}
              onClick={() => setTab(id)}
              className={`min-h-0 flex-1 cursor-pointer rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                activeTab === id
                  ? "bg-secondary text-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {activeTab === "doctor" && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="micro">
                Host checks for <span className="text-foreground font-mono">{iface}</span> · zero private keys included
              </span>
              <CopyButton
                value={diagnosticBundle}
                label="Copy Diagnostic JSON"
                title="Copy sanitized host & telemetry JSON (zero private keys)"
              />
            </div>

            <ul className="flex flex-col gap-1.5">
              {checks.map((check) => {
                const badgeClass =
                  check.status === "PASS"
                    ? "bg-[#2ea043] text-[#0d1117]"
                    : check.status === "WARN"
                      ? "bg-stale text-[#0d1117]"
                      : "bg-fault text-[#0d1117]"
                return (
                  <li
                    key={check.name}
                    className="border-border/60 bg-background/40 flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${badgeClass}`}
                        >
                          {check.status}
                        </span>
                        <span className="text-foreground font-medium">{check.name}</span>
                        {check.code && (
                          <Button
                            type="button"
                            size="xs"
                            variant="outline"
                            className="h-5 px-1.5 font-mono text-[10px]"
                            onClick={() => {
                              setQuery(check.code ?? "")
                              setTab("codes")
                            }}
                          >
                            {check.code}
                          </Button>
                        )}
                      </div>
                      <p className="text-muted-foreground mt-1 break-words text-xs">{check.detail}</p>
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>
        )}

        {activeTab === "metrics" && (
          <div className="flex flex-col gap-3 text-xs">
            <div className="border-live/35 bg-live/10 rounded-lg border px-3 py-2">
              <p className="text-live font-medium">
                Local-only by default · Zero network listeners · Zero phone-home
              </p>
              <p className="text-muted-foreground mt-0.5 leading-snug">
                All counters are read over the local Unix control socket (<code className="font-mono">0600</code>). Nothing leaves this host unless you explicitly copy a preview below.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <div className="border-border/60 bg-background/40 rounded-lg border p-3">
                <p className="text-foreground mb-1.5 text-xs font-medium">
                  Dataplane &amp; fragmentation
                </p>
                <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1 font-mono text-[11px]">
                  <dt className="text-muted-foreground">datagrams_sent / failed</dt>
                  <dd>
                    {snapshot?.counters.datagrams_sent.toLocaleString() ?? "—"} /{" "}
                    <span className={snapshot && snapshot.counters.datagrams_failed > 0 ? "text-fault" : ""}>
                      {snapshot?.counters.datagrams_failed ?? "—"}
                    </span>
                  </dd>
                  <dt className="text-muted-foreground">packets_delivered / failed</dt>
                  <dd>
                    {snapshot?.counters.packets_delivered.toLocaleString() ?? "—"} /{" "}
                    <span className={snapshot && snapshot.counters.packets_failed > 0 ? "text-fault" : ""}>
                      {snapshot?.counters.packets_failed ?? "—"}
                    </span>
                  </dd>
                  <dt className="text-muted-foreground">reassembled / dropped</dt>
                  <dd>
                    {snapshot?.counters.reassembled.toLocaleString() ?? "—"} /{" "}
                    {snapshot?.counters.fragments_dropped ?? "—"}
                  </dd>
                  <dt className="text-muted-foreground">fragments_rate_limited</dt>
                  <dd className={snapshot && snapshot.counters.fragments_rate_limited > 0 ? "text-stale" : ""}>
                    {snapshot?.counters.fragments_rate_limited ?? "—"}
                  </dd>
                  <dt className="text-muted-foreground">dropped_malformed / unknown_idx</dt>
                  <dd>
                    {snapshot?.counters.dropped_malformed ?? "—"} /{" "}
                    {snapshot?.counters.dropped_unknown_index ?? "—"}
                  </dd>
                </dl>
              </div>

              <div className="border-border/60 bg-background/40 rounded-lg border p-3">
                <p className="text-foreground mb-1.5 text-xs font-medium">
                  PQ handshake &amp; admission gate
                </p>
                <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1 font-mono text-[11px]">
                  <dt className="text-muted-foreground">established / refused</dt>
                  <dd>
                    {snapshot?.counters.established ?? "—"} /{" "}
                    <span className={snapshot && snapshot.counters.refusals > 0 ? "text-fault" : ""}>
                      {snapshot?.counters.refusals ?? "—"}
                    </span>
                  </dd>
                  <dt className="text-muted-foreground">handshake_dropped_no_mac</dt>
                  <dd>{snapshot?.counters.handshake_dropped_no_mac ?? "—"}</dd>
                  <dt className="text-muted-foreground">handshake_dropped_unidentifiable</dt>
                  <dd>{snapshot?.counters.handshake_dropped_unidentifiable ?? "—"}</dd>
                  <dt className="text-muted-foreground">handshake_dropped_unknown_peer</dt>
                  <dd>{snapshot?.counters.handshake_dropped_unknown_peer ?? "—"}</dd>
                  <dt className="text-muted-foreground">endpoint_conflict / stale</dt>
                  <dd>
                    {snapshot?.counters.handshake_dropped_endpoint_conflict ?? "—"} /{" "}
                    {snapshot?.counters.handshake_dropped_stale ?? "—"}
                  </dd>
                </dl>
              </div>

              <div className="border-border/60 bg-background/40 rounded-lg border p-3">
                <p className="text-foreground mb-1.5 text-xs font-medium">
                  Per-peer security &amp; path rollup
                </p>
                <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1 font-mono text-[11px]">
                  <dt className="text-muted-foreground">handshaked / total peers</dt>
                  <dd>
                    {peerRollup.handshaked} / {peerRollup.total} ({peerRollup.rotating} rotating)
                  </dd>
                  <dt className="text-muted-foreground">window rx / tx pkts</dt>
                  <dd>
                    {peerRollup.window_received.toLocaleString()} /{" "}
                    {peerRollup.window_sent.toLocaleString()}
                  </dd>
                  <dt className="text-muted-foreground">dropped_after_auth (VAL-E502)</dt>
                  <dd className={peerRollup.dropped_after_auth > 0 ? "text-fault font-semibold" : ""}>
                    {peerRollup.dropped_after_auth}
                  </dd>
                  <dt className="text-muted-foreground">dropped_allowed_ips</dt>
                  <dd className={peerRollup.dropped_allowed_ips > 0 ? "text-stale" : ""}>
                    {peerRollup.dropped_allowed_ips}
                  </dd>
                  <dt className="text-muted-foreground">no_session / replay / reinit</dt>
                  <dd>
                    {peerRollup.dropped_no_session} / {peerRollup.dropped_replay} /{" "}
                    {peerRollup.reinit_offered}
                  </dd>
                </dl>
              </div>

              <div className="border-border/60 bg-background/40 rounded-lg border p-3">
                <p className="text-foreground mb-1.5 text-xs font-medium">
                  Host &amp; funnel health
                </p>
                <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1 font-mono text-[11px]">
                  <dt className="text-muted-foreground">egress mode</dt>
                  <dd>{snapshot?.expected_egress ?? (health?.expected_full ? "full" : "split")}</dd>
                  <dt className="text-muted-foreground">guard state</dt>
                  <dd>{health?.guard.active ?? "unknown"}</dd>
                  <dt className="text-muted-foreground">dns via tunnel</dt>
                  <dd>{health ? (health.dns_via_tunnel ? "yes" : "no") : "—"}</dd>
                  <dt className="text-muted-foreground">systemd restarts</dt>
                  <dd>{health?.restarts ?? "—"}</dd>
                  <dt className="text-muted-foreground">runtime dir mode</dt>
                  <dd>{facts?.runtime_mode ?? "unknown"}</dd>
                </dl>
              </div>
            </div>

            <div className="border-border/60 bg-background/40 flex flex-col gap-2 rounded-md border p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1 rounded-md border border-border/60 p-0.5">
                  <button
                    type="button"
                    onClick={() => setExportMode("prometheus")}
                    className={`cursor-pointer rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                      exportMode === "prometheus"
                        ? "bg-secondary text-foreground"
                        : "text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    Prometheus Textfile
                  </button>
                  <button
                    type="button"
                    onClick={() => setExportMode("anonymized")}
                    className={`cursor-pointer rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                      exportMode === "anonymized"
                        ? "bg-secondary text-foreground"
                        : "text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    Zero-PII Snapshot
                  </button>
                </div>
                <CopyButton
                  value={exportMode === "prometheus" ? prometheusText : anonymizedSnapshot}
                  label={exportMode === "prometheus" ? "Copy Prometheus" : "Copy Zero-PII JSON"}
                />
              </div>
              <p className="text-muted-foreground text-[11px]">
                {exportMode === "prometheus"
                  ? "Live `vallum_*` metrics matching `vallum metrics` for local `node_exporter` comparison."
                  : "Opt-in diagnostic preview: quantized ratios, suite ID, error codes, and drop buckets only — zero hostnames, IPs, peer names, or keys."}
              </p>
              <pre className="border-border/60 bg-background/70 max-h-52 overflow-auto rounded border p-2.5 font-mono text-[11px] leading-relaxed">
                {exportMode === "prometheus" ? prometheusText : anonymizedSnapshot}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "codes" && (
          <div className="flex flex-col gap-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              {EXIT_CODES.map((ec) => (
                <div
                  key={ec.code}
                  className="border-border/60 bg-background/45 rounded-md border p-2.5 text-xs"
                >
                  <p className={`font-mono text-[11px] font-semibold ${ec.tone}`}>{ec.label}</p>
                  <p className="text-muted-foreground mt-1 leading-snug text-[11px]">{ec.meaning}</p>
                </div>
              ))}
            </div>

            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search VAL-E* error code, symptom (0600, 31/SYS, DNS, IPv6, suite)…"
              aria-label="Search error catalog"
              className="border-border/70 bg-background/50 text-foreground placeholder:text-muted-foreground w-full rounded-md border px-2.5 py-1.5 font-mono text-xs"
            />

            <ul className="flex max-h-[340px] flex-col gap-2 overflow-y-auto pr-1">
              {filteredCatalog.map((entry) => (
                <li
                  key={entry.code}
                  className="border-border/60 bg-background/40 flex flex-col gap-1 rounded-md border p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="bg-signal text-background rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                      {entry.code}
                    </span>
                    <span className="text-muted-foreground font-mono text-[11px]">
                      {entry.category}
                    </span>
                    <span className="border-border text-muted-foreground ml-auto rounded border px-1.5 py-0.5 font-mono text-[11px]">
                      {entry.exitLabel}
                    </span>
                  </div>
                  <p className="text-foreground font-semibold">{entry.title}</p>
                  <p className="text-muted-foreground leading-snug">{entry.summary}</p>
                  <p className="text-foreground/85 leading-snug">
                    <span className="text-live font-semibold">Remediation:</span> {entry.remediation}
                  </p>
                  {entry.command && (
                    <details className="border-border/60 bg-background/60 mt-1 rounded border px-2 py-1">
                      <summary className="text-muted-foreground hover:text-foreground cursor-pointer text-[11px] select-none">
                        Terminal command
                      </summary>
                      <div className="mt-1 flex items-center justify-between gap-2">
                        <code className="text-signal min-w-0 truncate font-mono text-[11px]">
                          {entry.command}
                        </code>
                        <CopyButton value={entry.command} label="Copy" />
                      </div>
                    </details>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        {activeTab === "dx" && (
          <div className="flex flex-col gap-2.5 text-xs">
            <p className="text-muted-foreground">
              For automation scripts or headless SSH troubleshooting, these CLI commands mirror the desktop console:
            </p>
            <ul className="flex flex-col gap-2">
              {cliSnippets.map((item) => (
                <li
                  key={item.cmd}
                  className="border-border/60 bg-background/40 flex flex-col gap-1 rounded-lg border p-2.5"
                >
                  <span className="text-foreground/90 font-medium">{item.label}</span>
                  <div className="flex items-center justify-between gap-2">
                    <code className="text-signal min-w-0 truncate font-mono text-[11px]">{item.cmd}</code>
                    <CopyButton value={item.cmd} label="Copy" />
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
