import type { Health } from "@/lib/bridge"

/** The verdict tones both the header and the health panel speak. Lives
 *  outside the component files so fast-refresh sees components only. */
export type VerdictTone = "live" | "stale" | "fault" | "muted"

export type Egress = {
  label: string
  detail: string
  tone: VerdictTone
}

export function egressVerdict(health: Health | null): Egress {
  if (!health) return { label: "Checking…", detail: "Reading host route and DNS state", tone: "muted" }
  const tunnelled = health.route4_via_tunnel
  const guarded = health.guard.active === "active"
  const v6Leaks = health.route6 !== null && !health.route6_via_tunnel && !guarded
  const dnsLeaks =
    health.expected_full && health.dns.length > 0 && !health.dns_via_tunnel
  if (tunnelled && dnsLeaks) {
    return {
      label: "DNS Leak Detected",
      detail: `Lookups leave via ${health.dns.join(", ")} instead of the tunnel`,
      tone: "fault",
    }
  }
  if (tunnelled && !v6Leaks) {
    return { label: "Protected · Full Tunnel", detail: `Default route via ${health.route4}`, tone: "live" }
  }
  if (tunnelled && v6Leaks) {
    return { label: "IPv6 Leak Detected", detail: `IPv6 traffic leaves via ${health.route6}`, tone: "fault" }
  }
  if (guarded) {
    return { label: "Unprotected", detail: "Kill-switch guard is active, but traffic is not tunnelled", tone: "fault" }
  }
  if (health.expected_full) {
    const why =
      health.unit_active && health.unit_active !== "active"
        ? `${health.unit} is ${health.unit_active}`
        : `no default route through ${health.interface}`
    return { label: "Unprotected", detail: `Full tunnel configured, ${why}`, tone: "fault" }
  }
  return {
    label: "Split Tunnel",
    detail: `Internet traffic leaves via ${health.route4 ?? "physical interface"}; only VPN subnets use the tunnel`,
    tone: "stale",
  }
}

/** One place maps a verdict tone to its class. */
export const verdictTone: Record<VerdictTone, string> = {
  live: "text-live",
  fault: "text-fault",
  stale: "text-stale",
  muted: "text-muted-foreground",
}
