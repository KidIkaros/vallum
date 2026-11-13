import { useState } from "react"
import { toast } from "sonner"
import { DiagnosticCallout } from "@/components/DiagnosticCallout"
import { Button } from "@/components/ui/button"
import { Panel } from "@/components/ui/panel"
import { panicNow, type Health } from "@/lib/bridge"
import { matchHealthDiagnostic } from "@/lib/diagnostics"
import { formatError } from "@/lib/validate"

// "Is this actually a VPN right now?" — answered from the host, not the config.
// A config that says 0.0.0.0/0 and a route that says wlp0s20f3 are different
// products; this panel is the difference made visible.

/**
 * The one sentence this console exists to say: is traffic going through the
 * tunnel, or is it going around it? Everything else is detail.
 */
import { egressVerdict } from "@/lib/verdict"

function Verdict({ ok, children }: { ok: boolean | null; children: React.ReactNode }) {
  const tone = ok === null ? "text-muted-foreground" : ok ? "text-live" : "text-fault"
  // A word beside the colour: ~8% of men cannot separate red from green, and a
  // row that only changes hue says nothing to them.
  const word = ok === null ? "?" : ok ? "OK" : "Alert"
  return (
    <span className="text-xs">
      <span className={`${tone} mr-1.5 font-semibold`}>{word}</span>
      <span className={tone}>{children}</span>
    </span>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="border-border/70 bg-background/55 mb-1.5 flex items-baseline justify-between gap-3 rounded-md border px-2.5 py-1.5 last:mb-0">
      <span className="micro">{label}</span>
      <span className="text-right">{children}</span>
    </div>
  )
}

/** The escape hatch, in the place the failure is visible. */
export function PanicButton({
  compact = false,
  onChanged,
}: {
  compact?: boolean
  onChanged?: () => void
}) {
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try {
      const done = await panicNow()
      const msg = /stop/i.test(done.message)
        ? done.message
        : `${done.message} — tunnel service stopped`
      toast.success(msg)
      onChanged?.()
    } catch (error) {
      toast.error(formatError(error))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Button
      size="sm"
      variant="outline"
      className={`border-fault/60 text-fault hover:bg-fault/10 ${compact ? "h-7 px-2.5 text-xs" : ""}`}
      disabled={busy}
      onClick={() => void run()}
      title="Remove the egress block, withdraw the tunnel's routes, stop the tunnel service, and put this host back on the internet"
    >
      {busy ? "Restoring…" : "Restore internet"}
    </Button>
  )
}

export function HealthPanel({
  health,
  stale,
  onChanged,
  onOpenCatalog,
}: {
  health: Health | null
  stale?: boolean
  onChanged?: () => void
  onOpenCatalog?: (code?: string) => void
}) {
  if (!health) {
    return (
      <Panel title="Protection & leak checks">
        {/* Routes and resolvers are read every 5 s. Nothing back for a while is a
            different sentence from "the first read has not landed yet", and only
            one of them is worth waiting on. */}
        <p className="text-muted-foreground py-3 text-xs">
          {stale
            ? "No host reading — the console helper is not answering, so routes and resolvers cannot be checked"
            : "Checking host routes and DNS…"}
        </p>
      </Panel>
    )
  }
  const verdict = egressVerdict(health)
  const v4 = health.route4_via_tunnel
  const guardOn = health.guard.active === "active"
  const armedFull = health.expected_full === true
  const unprotected = armedFull && !health.route4_via_tunnel
  const v6Blocked = health.route6 === null || (guardOn && !health.route6_via_tunnel)
  const v6Tunnel = health.route6_via_tunnel
  const diagnostic = matchHealthDiagnostic(health)
  return (
    <Panel title="Protection & leak checks">
      {unprotected && (
        <div className="border-fault/40 bg-fault/10 mb-2 flex items-center justify-between gap-2 rounded border px-2 py-1.5">
          <span className="text-fault text-xs">
            Full tunnel armed but IPv4 exits via {health.route4 ?? "physical interface"}
            {health.down_since ? ` since ${health.down_since}` : ""}
          </span>
          <PanicButton compact onChanged={onChanged} />
        </div>
      )}
      {health.unit_active === "active" && health.interface_present === false && (
        <div className="border-fault/40 bg-fault/10 mb-2 flex items-center justify-between gap-2 rounded border px-2 py-1.5">
          <span className="text-fault text-xs">
            Interface gone — dead-man switch restored internet; restart service
          </span>
          <PanicButton compact onChanged={onChanged} />
        </div>
      )}
      <Row label="IPv4 route">
        <Verdict ok={armedFull ? v4 : true}>
          {health.route4 ? `via ${health.route4}` : "none"} · {armedFull ? (v4 ? "Tunnel" : "Leak") : "Split"}
        </Verdict>
      </Row>
      <Row label="IPv6 route">
        <Verdict ok={armedFull ? v6Blocked || v6Tunnel : true}>
          {!armedFull
            ? health.route6
              ? `via ${health.route6} · Split`
              : "None"
            : v6Blocked
              ? guardOn && !v6Tunnel
                ? "Blocked by guard"
                : "None"
              : v6Tunnel
                ? `via ${health.route6} · Tunnel`
                : `via ${health.route6} · Leak`}
        </Verdict>
      </Row>
      <Row label="DNS">
        <Verdict ok={armedFull ? health.dns.length > 0 && health.dns_via_tunnel : true}>
          {health.dns_via_tunnel && health.dns_upstream && health.dns_upstream.length > 0
            ? `${health.dns[0]} → ${health.dns_upstream[0]} · Tunnel`
            : `${health.dns[0] ?? "none"} · ${
                armedFull && health.dns.length > 0 && !health.dns_via_tunnel
                  ? "Outside tunnel"
                  : !armedFull && health.dns.length > 0
                    ? "Split"
                    : verdict.label
              }`}
        </Verdict>
      </Row>
      <Row label="Kill-switch">
        <Verdict ok={armedFull ? guardOn : true}>
          {guardOn ? "Active" : armedFull ? "Inactive" : "Off (split)"}
        </Verdict>
      </Row>
      <Row label="Routing table">
        <Verdict ok={armedFull ? health.quick.active === "active" : true}>
          {health.quick.active === "active"
            ? "Applied"
            : armedFull
              ? "Inactive"
              : "Off (split)"}
        </Verdict>
      </Row>
      <Row label="Service restarts">
        <span className={health.restarts > 0 ? "text-stale font-mono text-xs" : "text-foreground/80 font-mono text-xs"}>
          {health.restarts}
        </span>
      </Row>
      {health.last_death && (
        <p className="text-muted-foreground mt-1 truncate text-xs" title={health.last_death}>
          Last exit: {health.last_death}
        </p>
      )}
      {diagnostic && (
        <DiagnosticCallout entry={diagnostic} onOpenCatalog={onOpenCatalog} />
      )}
      <div className="border-border/60 mt-2.5 flex flex-wrap items-center gap-1.5 border-t pt-2.5 text-[10px] font-semibold tracking-wider uppercase">
        <span
          className={`rounded border px-2 py-0.5 ${
            !unprotected && (!armedFull || v6Blocked || v6Tunnel)
              ? "border-[#3fb950]/50 bg-[#3fb950]/12 text-[#3fb950]"
              : "border-border bg-secondary/40 text-muted-foreground"
          }`}
        >
          {armedFull ? "Protected" : "Split mode"}
        </span>
        <span
          className={`rounded border px-2 py-0.5 ${
            guardOn
              ? "border-[#39c5cf]/50 bg-[#39c5cf]/10 text-[#39c5cf]"
              : "border-border bg-secondary/40 text-muted-foreground"
          }`}
        >
          {guardOn ? "Guard armed" : "Guard standby"}
        </span>
        {(unprotected || (armedFull && health.dns.length > 0 && !health.dns_via_tunnel)) && (
          <span className="border-fault/60 bg-fault/12 text-fault rounded border px-2 py-0.5">
            Leak risk
          </span>
        )}
      </div>
    </Panel>
  )
}
