import { Panel } from "@/components/ui/panel"
import type { Health } from "@/lib/bridge"

// "Is this actually a VPN right now?" — answered from the host, not the config.
// A config that says 0.0.0.0/0 and a route that says wlp0s20f3 are different
// products; this panel is the difference made visible.

function Verdict({ ok, children }: { ok: boolean | null; children: React.ReactNode }) {
  const tone = ok === null ? "text-muted-foreground" : ok ? "text-live" : "text-fault"
  return <span className={`${tone} text-xs`}>{children}</span>
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <span className="micro">{label}</span>
      <span className="text-right">{children}</span>
    </div>
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
