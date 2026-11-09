import { useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Panel } from "@/components/ui/panel"
import { panicNow, type Health } from "@/lib/bridge"

// "Is this actually a VPN right now?" — answered from the host, not the config.
// A config that says 0.0.0.0/0 and a route that says wlp0s20f3 are different
// products; this panel is the difference made visible.

/**
 * The one sentence this console exists to say: is traffic going through the
 * tunnel, or is it going around it? Everything else is detail.
 */
export type Egress = {
  label: string
  detail: string
  tone: "live" | "stale" | "fault" | "muted"
}

export function egressVerdict(health: Health | null): Egress {
  if (!health) return { label: "UNKNOWN", detail: "no host reading yet", tone: "muted" }
  const tunnelled = health.route4_via_tunnel
  const guarded = health.guard.active === "active"
  const v6Leaks = health.route6 !== null && !health.route6_via_tunnel
  if (tunnelled && !v6Leaks) {
    return { label: "PROTECTED", detail: `default route via ${health.route4}`, tone: "live" }
  }
  if (tunnelled && v6Leaks) {
    return { label: "V6 LEAK", detail: `IPv6 leaves via ${health.route6}`, tone: "fault" }
  }
  if (guarded) {
    return { label: "UNPROTECTED", detail: "guard is on but traffic is not tunnelled", tone: "fault" }
  }
  return {
    label: "SPLIT",
    detail: `traffic leaves via ${health.route4 ?? "no route"} — the tunnel carries only its own subnet`,
    tone: "stale",
  }
}

export function EgressBadge({ health }: { health: Health | null }) {
  const verdict = egressVerdict(health)
  const colour = {
    live: "text-live border-live/40",
    stale: "text-stale border-stale/40",
    fault: "text-fault border-fault/40",
    muted: "text-muted-foreground border-border",
  }[verdict.tone]
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] tracking-wider uppercase ${colour}`}
      title={verdict.detail}
    >
      egress <span className="font-semibold">{verdict.label}</span>
    </span>
  )
}

function Verdict({ ok, children }: { ok: boolean | null; children: React.ReactNode }) {
  const tone = ok === null ? "text-muted-foreground" : ok ? "text-live" : "text-fault"
  // A word beside the colour: ~8% of men cannot separate red from green, and a
  // row that only changes hue says nothing to them.
  const word = ok === null ? "?" : ok ? "ok" : "fail"
  return (
    <span className="text-xs">
      <span className={`${tone} mr-1.5 font-semibold uppercase`}>{word}</span>
      <span className={tone}>{children}</span>
    </span>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <span className="micro">{label}</span>
      <span className="text-right">{children}</span>
    </div>
  )
}

/** The escape hatch, in the place the failure is visible. */
export function PanicButton({ compact = false }: { compact?: boolean }) {
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try {
      const done = await panicNow()
      toast.success(done.message)
    } catch (error) {
      toast.error(String(error instanceof Error ? error.message : error))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Button
      size="sm"
      variant="outline"
      className={`border-fault/60 text-fault hover:bg-fault/10 ${compact ? "h-6 px-2 text-[10px]" : ""}`}
      disabled={busy}
      onClick={() => void run()}
      title="Remove the egress block, withdraw the tunnel's routes and put this host back on the internet"
    >
      {busy ? "restoring…" : "restore internet"}
    </Button>
  )
}

export function HealthPanel({ health }: { health: Health | null }) {
  if (!health) {
    return (
      <Panel title="EGRESS HEALTH">
        <p className="text-muted-foreground py-3 text-xs">waiting for the host</p>
      </Panel>
    )
  }
  const v4 = health.route4_via_tunnel
  const v6Blocked = health.route6 === null
  const v6Tunnel = health.route6_via_tunnel
  return (
    <Panel title="EGRESS HEALTH">
      {!v4 && (
        <div className="border-fault/40 bg-fault/10 mb-2 flex items-center justify-between gap-2 rounded border px-2 py-1.5">
          <span className="text-fault text-[11px]">
            {health.guard.active === "active"
              ? "the guard is blocking egress and traffic is not going through the tunnel"
              : "traffic is leaving this host outside the tunnel"}
          </span>
          <PanicButton compact />
        </div>
      )}
      <Row label="default route">
        <Verdict ok={v4}>
          {health.route4 ? `via ${health.route4}` : "no route"}
          {v4 ? "" : " · outside the tunnel"}
        </Verdict>
      </Row>
      <Row label="ipv6">
        <Verdict ok={v6Blocked || v6Tunnel}>
          {v6Blocked ? "blocked" : v6Tunnel ? `tunnelled via ${health.route6}` : `leaks via ${health.route6}`}
        </Verdict>
      </Row>
      <Row label="dns">
        <Verdict ok={health.dns.length > 0 && health.dns_via_tunnel}>
          {health.dns.length > 0 ? health.dns.join(" · ") : "none"}
          {health.dns.length > 0 && !health.dns_via_tunnel ? " · outside the tunnel" : ""}
        </Verdict>
      </Row>
      <Row label="guard">
        <Verdict ok={health.guard.active === "active"}>
          {health.guard.active === "active" ? "blocking egress" : health.guard.active}
        </Verdict>
      </Row>
      <Row label="routes">
        <Verdict ok={health.quick.active === "active"}>
          {health.quick.active === "active" ? "applied" : health.quick.active}
        </Verdict>
      </Row>
      <Row label="restarts">
        <span className={health.restarts > 0 ? "text-stale text-xs" : "text-foreground/80 text-xs"}>
          {health.restarts}
        </span>
      </Row>
      {health.last_death && (
        <p className="text-muted-foreground mt-1 truncate text-[10px]" title={health.last_death}>
          last exit: {health.last_death}
        </p>
      )}
    </Panel>
  )
}
