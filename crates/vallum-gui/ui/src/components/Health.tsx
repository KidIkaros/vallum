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
import { verdictTone, type VerdictTone } from "@/lib/verdict"

export type Egress = {
  label: string
  detail: string
  tone: VerdictTone
}

export function egressVerdict(health: Health | null): Egress {
  if (!health) return { label: "UNKNOWN", detail: "no host reading yet", tone: "muted" }
  const tunnelled = health.route4_via_tunnel
  const guarded = health.guard.active === "active"
  // A route outside the tunnel is only a leak if nothing drops it: with the
  // guard active, v6 packets die in the policy table, so the route is a
  // corpse, not an exit. (The panel rows were fixed for this; the verdict
  // was not — the full-tunnel trial exposed it.)
  const v6Leaks = health.route6 !== null && !health.route6_via_tunnel && !guarded
  // DNS is the leak a routed default hides: with 0.0.0.0/0 through the tunnel
  // and the resolver still pointing at the local stub, every hostname is looked
  // up outside it while the hero says PROTECTED. Only a fault when the config
  // asked for a full tunnel — a split host resolving locally is the design.
  const dnsLeaks =
    health.expected_full && health.dns.length > 0 && !health.dns_via_tunnel
  if (tunnelled && dnsLeaks) {
    return {
      label: "DNS LEAK",
      detail: `lookups leave via ${health.dns.join(", ")} instead of the tunnel`,
      tone: "fault",
    }
  }
  if (tunnelled && !v6Leaks) {
    return { label: "PROTECTED", detail: `default route via ${health.route4}`, tone: "live" }
  }
  if (tunnelled && v6Leaks) {
    return { label: "V6 LEAK", detail: `IPv6 leaves via ${health.route6}`, tone: "fault" }
  }
  if (guarded) {
    return { label: "UNPROTECTED", detail: "guard is on but traffic is not tunnelled", tone: "fault" }
  }
  // A full-tunnel host that is not tunnelled is not "split by design". The
  // daemon publishes what the config asked for (`vallum_egress`); when it asked
  // for full and no traffic enters the tunnel, the same picture a split host
  // shows honestly is here a fault. Without this branch a rebooted full-tunnel
  // machine — guard and quick both disabled, no default route installed — read
  // SPLIT in amber, which is a mode, not a warning.
  if (health.expected_full) {
    const why =
      health.unit_active && health.unit_active !== "active"
        ? `${health.unit} is ${health.unit_active}`
        : `no default route through ${health.interface}`
    return { label: "UNPROTECTED", detail: `full tunnel configured, ${why}`, tone: "fault" }
  }
  return {
    label: "SPLIT",
    detail: `traffic leaves via ${health.route4 ?? "no route"} — the tunnel carries only its own subnet`,
    tone: "stale",
  }
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
      className={`border-fault/60 text-fault hover:bg-fault/10 ${compact ? "h-6 px-2 text-xs" : ""}`}
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
  const verdict = egressVerdict(health)
  const v4 = health.route4_via_tunnel
  const guardOn = health.guard.active === "active"
  // Verdicts compare expectation with measurement: red is reserved for
  // "armed full tunnel and not carrying" — a split host on Wi-Fi is the
  // configuration doing exactly what it says.
  const armedFull = health.expected_full === true
  const unprotected = armedFull && !health.route4_via_tunnel
  // A route outside the tunnel is only a leak if nothing drops it: with the
  // guard active, v6 packets are dropped by policy, so the route is a corpse,
  // not an exit.
  const v6Blocked = health.route6 === null || (guardOn && !health.route6_via_tunnel)
  const v6Tunnel = health.route6_via_tunnel
  return (
    <Panel title="EGRESS HEALTH">
      {/* The state sentence, readable at a glance: the label the header
          shouts, plus the detail it keeps in a tooltip. */}
      <p className={`mb-2 text-sm ${verdictTone[verdict.tone]}`}>
        <span className="font-semibold">{verdict.label}</span>
        <span className="text-muted-foreground"> — {verdict.detail}</span>
      </p>
      {unprotected && (
        <div className="border-fault/40 bg-fault/10 mb-2 flex items-center justify-between gap-2 rounded border px-2 py-1.5">
          <span className="text-fault text-xs">
            the full tunnel is armed but traffic leaves via {health.route4 ?? "the physical interface"} — the tunnel is not carrying
            {health.down_since ? ` — unprotected since ${health.down_since}` : ""}
          </span>
          <PanicButton compact />
        </div>
      )}
      {health.unit_active === "active" && health.interface_present === false && (
        <div className="border-fault/40 bg-fault/10 mb-2 flex items-center justify-between gap-2 rounded border px-2 py-1.5">
          <span className="text-fault text-xs">
            the daemon is running but its interface is gone — the dead-man has restored your internet; restart the tunnel
          </span>
          <PanicButton compact />
        </div>
      )}
      <Row label="default route">
        <Verdict ok={armedFull ? v4 : true}>
          {health.route4 ? `via ${health.route4}` : "no route"}
          {armedFull ? (v4 ? " · tunnel carrying" : " · not carrying") : " · split by design"}
        </Verdict>
      </Row>
      <Row label="ipv6">
        <Verdict ok={armedFull ? v6Blocked || v6Tunnel : true}>
          {!armedFull
            ? `rides ${health.route6 ?? "physical"} · split by design`
            : v6Blocked
              ? guardOn && !v6Tunnel
                ? `blocked by the guard${health.route6 ? ` · route via ${health.route6} dropped` : ""}`
                : "no route"
              : v6Tunnel
                ? `tunnelled via ${health.route6}`
                : `leaks via ${health.route6}`}
        </Verdict>
      </Row>
      <Row label="dns">
        <Verdict ok={armedFull ? health.dns.length > 0 && health.dns_via_tunnel : true}>
          {health.dns_via_tunnel && health.dns_upstream && health.dns_upstream.length > 0
            ? `${health.dns[0]} → ${health.dns_upstream.join(" · ")} (tunnel)`
            : health.dns.length > 0
              ? health.dns.join(" · ")
              : "none"}
          {armedFull && health.dns.length > 0 && !health.dns_via_tunnel
            ? " · outside the tunnel"
            : !armedFull && health.dns.length > 0
              ? " · split by design"
              : ""}
        </Verdict>
      </Row>
      <Row label="guard">
        <Verdict ok={armedFull ? health.guard.active === "active" : true}>
          {health.guard.active === "active"
            ? "blocking egress"
            : armedFull
              ? "inactive — armed full tunnel with no egress block"
              : "not needed in split mode"}
        </Verdict>
      </Row>
      <Row label="routes">
        <Verdict ok={armedFull ? health.quick.active === "active" : true}>
          {health.quick.active === "active"
            ? "applied"
            : armedFull
              ? "inactive — full tunnel without routes"
              : "not needed in split mode"}
        </Verdict>
      </Row>
      <Row label="restarts">
        <span className={health.restarts > 0 ? "text-stale text-xs" : "text-foreground/80 text-xs"}>
          {health.restarts}
        </span>
      </Row>
      {health.last_death && (
        <p className="text-muted-foreground mt-1 truncate text-xs" title={health.last_death}>
          last exit: {health.last_death}
        </p>
      )}
    </Panel>
  )
}
