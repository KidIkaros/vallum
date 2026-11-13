import { useEffect, useRef, useState } from "react"
import { ArrowRight, Laptop, Server, ShieldAlert, ShieldCheck } from "lucide-react"
import type { PeerRate } from "@/components/TopTalkers"
import { Button } from "@/components/ui/button"
import { Panel } from "@/components/ui/panel"
import { bytes, type Health } from "@/lib/bridge"
import { formatAgeSec, freshness, rateLabel } from "@/lib/traffic"
import { suiteLabel } from "@/lib/validate"
import type { Snapshot } from "@/types"

type LaneState = "tunnel" | "blocked" | "split" | "leak" | "idle"

const LANE_STYLE: Record<LaneState, { bar: string; badge: string }> = {
  tunnel: { bar: "bg-signal", badge: "text-signal border-signal/30 bg-signal/10" },
  blocked: { bar: "bg-live/70", badge: "text-live border-live/30 bg-live/10" },
  split: { bar: "bg-violet/65", badge: "text-muted-foreground border-border bg-secondary/60" },
  leak: { bar: "bg-fault", badge: "text-fault border-fault/30 bg-fault/10" },
  idle: { bar: "bg-muted", badge: "text-muted-foreground border-border bg-secondary/40" },
}

function FlowLane({
  label,
  via,
  dest,
  state,
  live,
  fast,
}: {
  label: string
  via: string
  dest: string
  state: LaneState
  live: boolean
  fast: boolean
}) {
  const tone = LANE_STYLE[state]
  const activeTunnel = live && state === "tunnel"
  const streamClass = activeTunnel ? (fast ? "flow-stream-fast" : "flow-stream-slow") : ""
  return (
    <div className="grid grid-cols-[3.2rem_1fr_auto] items-center gap-2.5 text-xs">
      <span className="text-muted-foreground font-medium">{label}</span>
      <div className="flex min-w-0 items-center gap-2">
        <span className="text-foreground/85 max-w-[9rem] truncate font-mono text-[11px]" title={via}>
          {via}
        </span>
        <div className="bg-muted relative h-1.5 min-w-[2.5rem] flex-1 overflow-hidden rounded-full">
          <div className={`h-full w-full rounded-full transition-colors duration-300 ${tone.bar} ${streamClass}`} />
        </div>
        <ArrowRight
          className={`size-3 shrink-0 transition-colors ${activeTunnel && fast ? "text-signal" : "text-muted-foreground/70"}`}
          aria-hidden
        />
      </div>
      <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${tone.badge}`}>
        {dest}
      </span>
    </div>
  )
}

/**
 * 3-stage live topology & egress flow map: Local Host -> Egress & Tunnel Lanes -> Peers.
 */
export function TunnelFlowMap({
  data,
  health,
  rates,
  rxRate,
  txRate,
  now,
  live,
  onSelectPeer,
}: {
  data: Snapshot | null
  health: Health | null
  rates: PeerRate[]
  rxRate: number
  txRate: number
  now: number
  live: boolean
  onSelectPeer?: (fingerprint: string) => void
}) {
  const iface = data?.interface || health?.interface || "vallum0"
  const full = data?.expected_egress === "full" || health?.expected_full === true
  const guardOn = health?.guard.active === "active"
  const peers = data?.peers ?? []
  const rateByName = new Map(rates.map((r) => [r.name, r]))

  const orderedPeers = [...peers]
    .sort((a, b) => {
      const ra = rateByName.get(a.name)
      const rb = rateByName.get(b.name)
      const rateDiff = (rb ? rb.rx + rb.tx : 0) - (ra ? ra.rx + ra.tx : 0)
      if (rateDiff !== 0) return rateDiff
      return b.rx_bytes + b.tx_bytes - (a.rx_bytes + a.tx_bytes)
    })
    .slice(0, 4)

  const maxPeerTotal = Math.max(1, ...orderedPeers.map((p) => p.rx_bytes + p.tx_bytes))
  const totalRate = rxRate + txRate
  const rxPct = totalRate > 0 ? Math.round((rxRate / totalRate) * 100) : 50

  const lanes: Array<{ label: string; via: string; dest: string; state: LaneState }> = health
    ? [
        {
          label: "IPv4",
          via: health.route4 ? `via ${health.route4}` : "no route",
          dest: health.route4_via_tunnel ? "Tunnel" : full ? "Leak" : "Direct",
          state: health.route4_via_tunnel ? "tunnel" : full ? "leak" : "split",
        },
        {
          label: "IPv6",
          via: health.route6 ? `via ${health.route6}` : "no route",
          dest: health.route6_via_tunnel
            ? "Tunnel"
            : !full
              ? health.route6
                ? "Direct"
                : "None"
              : !health.route6
                ? "None"
                : guardOn
                  ? "Blocked"
                  : "Leak",
          state: health.route6_via_tunnel
            ? "tunnel"
            : !full
              ? "split"
              : !health.route6 || guardOn
                ? "blocked"
                : "leak",
        },
        {
          label: "DNS",
          via: health.dns[0] ?? "none",
          dest: health.dns_via_tunnel ? "Tunnel" : full ? "Leak" : "Direct",
          state: health.dns_via_tunnel ? "tunnel" : full ? "leak" : "split",
        },
      ]
    : [
        { label: "IPv4", via: "checking…", dest: "—", state: "idle" },
        { label: "IPv6", via: "checking…", dest: "—", state: "idle" },
        { label: "DNS", via: "checking…", dest: "—", state: "idle" },
      ]

  return (
    <Panel
      title="Data flow & topology"
      right={
        <span className="text-muted-foreground font-mono text-xs">
          {data ? suiteLabel(data.suite) : "PQ tunnel"}
        </span>
      }
    >
      <div className="grid grid-cols-1 items-stretch gap-3 lg:grid-cols-12">
        {/* Stage 1: Local Host Node */}
        <div className="cyber-grid border-border/80 bg-background/60 flex flex-col justify-between gap-2.5 rounded-lg border p-3 lg:col-span-3">
          <span className="micro text-signal/90 text-[10px]">01 · Local node</span>
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="border-border bg-secondary flex size-7 shrink-0 items-center justify-center rounded-md border">
                <Laptop className="text-signal size-3.5" aria-hidden />
              </div>
              <div className="min-w-0">
                <div className="text-foreground truncate font-mono text-xs font-medium">{iface}</div>
                <div className="text-muted-foreground truncate font-mono text-[11px]">
                  {data?.addresses[0] ?? "—"}
                </div>
              </div>
            </div>
            <span className="relative flex size-2.5 shrink-0 items-center justify-center" aria-hidden>
              {live && totalRate > 0 && (
                <span className="bg-live absolute inline-flex h-full w-full animate-ping rounded-full opacity-65" />
              )}
              <span
                className={`relative inline-flex size-2 rounded-full ${live ? "bg-live" : "bg-muted-foreground/50"}`}
              />
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <span className="border-border bg-secondary/70 text-foreground rounded border px-1.5 py-0.5 font-medium">
              {full ? "Full tunnel" : "Split tunnel"}
            </span>
            <span
              className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-medium ${
                guardOn
                  ? "border-live/30 bg-live/10 text-live"
                  : full
                    ? "border-fault/30 bg-fault/10 text-fault"
                    : "border-border bg-secondary/40 text-muted-foreground"
              }`}
            >
              {guardOn ? (
                <ShieldCheck className="size-3" aria-hidden />
              ) : (
                <ShieldAlert className="size-3" aria-hidden />
              )}
              {guardOn ? "Guard on" : "Guard off"}
            </span>
            {data?.listen_port ? (
              <span className="text-muted-foreground font-mono">:{data.listen_port}</span>
            ) : null}
          </div>
        </div>

        {/* Stage 2: Egress & Tunnel Lanes */}
        <div className="cyber-grid border-border/80 bg-background/60 flex flex-col justify-between gap-2.5 rounded-lg border p-3 lg:col-span-5">
          <span className="micro text-signal/90 text-[10px]">02 · Egress lanes</span>
          <div className="flex flex-col gap-2">
            {lanes.map((lane) => (
              <FlowLane key={lane.label} {...lane} live={live} fast={totalRate >= 4096} />
            ))}
          </div>
          <div className="border-border/50 flex flex-col gap-1 border-t pt-2 text-[11px]">
            <div className="flex items-center justify-between gap-2 font-mono">
              <span className="text-signal">▼ {live ? rateLabel(rxRate) : "—"}</span>
              <span className="text-muted-foreground">Live pipe</span>
              <span className="text-violet">▲ {live ? rateLabel(txRate) : "—"}</span>
            </div>
            <div className="bg-muted flex h-1.5 w-full overflow-hidden rounded-full">
              <span
                className={`bg-signal h-full transition-all duration-300 ${live && rxRate > 0 ? "pipe-shimmer-rx" : ""}`}
                style={{ width: `${totalRate > 0 ? rxPct : 0}%` }}
              />
              <span
                className={`bg-violet h-full transition-all duration-300 ${live && txRate > 0 ? "pipe-shimmer-tx" : ""}`}
                style={{ width: `${totalRate > 0 ? 100 - rxPct : 0}%` }}
              />
            </div>
          </div>
        </div>

        {/* Stage 3: Peer Fan-Out */}
        <div className="cyber-grid border-border/80 bg-background/60 flex flex-col justify-between gap-2 rounded-lg border p-3 lg:col-span-4">
          <div className="flex items-center justify-between text-xs">
            <span className="micro text-signal/90 flex items-center gap-1.5 text-[10px]">
              <Server className="size-3" aria-hidden />
              03 · Peer mesh ({peers.length})
            </span>
            {peers.length > orderedPeers.length && (
              <span className="text-muted-foreground text-[11px]">Top {orderedPeers.length}</span>
            )}
          </div>
          {orderedPeers.length === 0 ? (
            <p className="text-muted-foreground py-3 text-center text-xs">No peers enrolled</p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {orderedPeers.map((peer) => {
                const f = freshness(peer.last_handshake_sec, now)
                const rate = rateByName.get(peer.name)
                const peerRate = rate ? rate.rx + rate.tx : 0
                const peerFlowing = live && peerRate > 0
                const total = peer.rx_bytes + peer.tx_bytes
                const rxShare = total > 0 ? Math.min(100, (peer.rx_bytes / maxPeerTotal) * 100) : 0
                const txShare = total > 0 ? Math.min(100 - rxShare, (peer.tx_bytes / maxPeerTotal) * 100) : 0
                const dot =
                  f === "recent"
                    ? "bg-live"
                    : f === "aging"
                      ? "bg-stale"
                      : "bg-muted-foreground/40"
                return (
                  <button
                    key={peer.fingerprint}
                    type="button"
                    onClick={() => onSelectPeer?.(peer.fingerprint)}
                    className={`bg-card/60 hover:border-border hover:bg-secondary/60 flex cursor-pointer flex-col gap-1 rounded-md border px-2.5 py-1.5 text-left transition-colors ${
                      peerFlowing ? "border-signal/40" : "border-border/40"
                    }`}
                    title={
                      peer.last_handshake_sec > 0
                        ? `Last handshake ${formatAgeSec(Math.max(0, now - peer.last_handshake_sec))} ago`
                        : "No handshake yet"
                    }
                  >
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className="relative flex size-2 shrink-0 items-center justify-center" aria-hidden>
                          {peerFlowing && (
                            <span className="bg-live absolute inline-flex h-full w-full animate-ping rounded-full opacity-70" />
                          )}
                          <span className={`relative inline-flex size-1.5 rounded-full ${dot}`} />
                        </span>
                        <span className="text-foreground truncate font-medium">{peer.name}</span>
                        <span className="text-muted-foreground hidden truncate font-mono text-[11px] sm:inline">
                          {peer.allowed_ips[0] ?? ""}
                        </span>
                      </span>
                      <span className="text-muted-foreground shrink-0 font-mono text-[11px]">
                        {peerRate > 0 ? rateLabel(peerRate) : bytes(total)}
                      </span>
                    </div>
                    <div className="bg-muted flex h-1 w-full overflow-hidden rounded-full">
                      <span
                        className={`bg-signal h-full ${live && (rate?.rx ?? 0) > 0 ? "pipe-shimmer-rx" : ""}`}
                        style={{ width: `${rxShare}%` }}
                      />
                      <span
                        className={`bg-violet h-full ${live && (rate?.tx ?? 0) > 0 ? "pipe-shimmer-tx" : ""}`}
                        style={{ width: `${txShare}%` }}
                      />
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}

const PEER_COLORS = [
  "bg-signal",
  "bg-live",
  "bg-violet",
  "bg-stale",
  "bg-muted-foreground/60",
]

/**
 * 4-stage packet pipeline + directional balance & per-peer volume distribution.
 */
export function PacketPipelineFlow({
  data,
  onOpenMetrics,
}: {
  data: Snapshot | null
  onOpenMetrics?: () => void
}) {
  const peers = data?.peers ?? []
  const c = data?.counters
  const rxBytes = peers.reduce((sum, p) => sum + p.rx_bytes, 0)
  const txBytes = peers.reduce((sum, p) => sum + p.tx_bytes, 0)
  const totalBytes = rxBytes + txBytes
  const rxPct = totalBytes > 0 ? Math.round((rxBytes / totalBytes) * 100) : 0
  const txPct = totalBytes > 0 ? 100 - rxPct : 0

  const peerShares = [...peers]
    .map((p) => ({ name: p.name, total: p.rx_bytes + p.tx_bytes }))
    .filter((p) => p.total > 0)
    .sort((a, b) => b.total - a.total)
  const topShares = peerShares.slice(0, 4)
  const otherTotal = peerShares.slice(4).reduce((sum, p) => sum + p.total, 0)
  if (otherTotal > 0) topShares.push({ name: "Other", total: otherTotal })

  const stages = c
    ? [
        {
          step: "1. Wire ingress",
          ok: c.reassembled,
          okLabel: "reassembled",
          drop: c.fragments_dropped + c.fragments_rate_limited + c.dropped_malformed,
          dropLabel: "dropped",
        },
        {
          step: "2. Handshake gate",
          ok: c.established,
          okLabel: "established",
          drop:
            c.refusals +
            c.handshake_dropped_no_mac +
            c.handshake_dropped_unidentifiable +
            c.handshake_dropped_unknown_peer +
            c.handshake_dropped_endpoint_conflict +
            c.handshake_dropped_stale,
          dropLabel: "rejected",
        },
        {
          step: "3. Tunnel delivery",
          ok: c.packets_delivered,
          okLabel: "delivered",
          drop: c.packets_failed,
          dropLabel: "failed",
        },
        {
          step: "4. Wire egress",
          ok: c.datagrams_sent,
          okLabel: "sent",
          drop: c.datagrams_failed,
          dropLabel: "failed",
        },
      ]
    : []

  const prevStageOkRef = useRef<Record<string, number>>({})
  const [pulsingSteps, setPulsingSteps] = useState<Record<string, boolean>>({})

  useEffect(() => {
    if (!c) return
    const current: Record<string, number> = {
      "1. Wire ingress": c.reassembled,
      "2. Handshake gate": c.established,
      "3. Tunnel delivery": c.packets_delivered,
      "4. Wire egress": c.datagrams_sent,
    }
    const prev = prevStageOkRef.current
    const bumped: Record<string, boolean> = {}
    let any = false
    for (const [step, value] of Object.entries(current)) {
      if (prev[step] !== undefined && value > prev[step]) {
        bumped[step] = true
        any = true
      }
    }
    prevStageOkRef.current = current
    if (!any) return
    const fire = window.setTimeout(() => setPulsingSteps(bumped), 0)
    const clear = window.setTimeout(() => setPulsingSteps({}), 850)
    return () => {
      window.clearTimeout(fire)
      window.clearTimeout(clear)
    }
  }, [c])

  return (
    <Panel
      title="Packet pipeline & volume share"
      right={
        onOpenMetrics ? (
          <Button type="button" size="sm" variant="outline" onClick={onOpenMetrics}>
            Prometheus &amp; metrics…
          </Button>
        ) : undefined
      }
    >
      <div className="flex flex-col gap-4">
        {/* Directional & per-peer distribution bars */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="border-border/60 bg-background/40 flex flex-col gap-2 rounded-lg border p-3 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="text-muted-foreground font-medium">Directional balance</span>
              <span className="text-foreground font-mono">{bytes(totalBytes)} total</span>
            </div>
            <div className="bg-muted flex h-2 w-full overflow-hidden rounded-full">
              <span className="bg-signal h-full transition-all duration-300" style={{ width: `${rxPct}%` }} />
              <span className="bg-violet h-full transition-all duration-300" style={{ width: `${txPct}%` }} />
            </div>
            <div className="flex items-center justify-between font-mono text-[11px]">
              <span className="text-signal">
                ▼ {bytes(rxBytes)} ({rxPct}%)
              </span>
              <span className="text-violet">
                ▲ {bytes(txBytes)} ({txPct}%)
              </span>
            </div>
          </div>

          <div className="border-border/60 bg-background/40 flex flex-col gap-2 rounded-lg border p-3 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="text-muted-foreground font-medium">Volume by peer</span>
              <span className="text-muted-foreground font-mono text-[11px]">
                {peers.length} device{peers.length === 1 ? "" : "s"}
              </span>
            </div>
            {topShares.length === 0 ? (
              <p className="text-muted-foreground py-1 text-xs">No peer traffic recorded yet</p>
            ) : (
              <>
                <div className="bg-muted flex h-2 w-full overflow-hidden rounded-full">
                  {topShares.map((item, idx) => (
                    <span
                      key={item.name}
                      className={`${PEER_COLORS[idx % PEER_COLORS.length]} h-full transition-all duration-300`}
                      style={{ width: `${totalBytes > 0 ? (item.total / totalBytes) * 100 : 0}%` }}
                      title={`${item.name}: ${bytes(item.total)}`}
                    />
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
                  {topShares.map((item, idx) => {
                    const pct = totalBytes > 0 ? Math.round((item.total / totalBytes) * 100) : 0
                    return (
                      <span key={item.name} className="inline-flex items-center gap-1.5">
                        <span
                          className={`size-2 rounded-full ${PEER_COLORS[idx % PEER_COLORS.length]}`}
                          aria-hidden
                        />
                        <span className="text-foreground/90">{item.name}</span>
                        <span className="text-muted-foreground font-mono">{pct}%</span>
                      </span>
                    )
                  })}
                </div>
              </>
            )}
          </div>
        </div>

        {/* 4-stage packet pipeline */}
        {stages.length > 0 && (
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
            {stages.map((stage, idx) => {
              const sum = stage.ok + stage.drop
              const passPct = sum > 0 ? Math.round((stage.ok / sum) * 1000) / 10 : 100
              const hasDrops = stage.drop > 0
              const activePulse = pulsingSteps[stage.step] === true
              return (
                <div
                  key={stage.step}
                  className={`bg-background/40 flex flex-col gap-1.5 rounded-lg border p-3 text-xs transition-colors ${
                    activePulse ? "border-signal/55" : "border-border/60"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted-foreground flex items-center gap-1.5 font-medium">
                      {activePulse && (
                        <span className="relative flex size-2 shrink-0" aria-hidden>
                          <span className="bg-signal absolute inline-flex h-full w-full animate-ping rounded-full opacity-75" />
                          <span className="bg-signal relative inline-flex size-2 rounded-full" />
                        </span>
                      )}
                      <span>{stage.step}</span>
                      {idx < stages.length - 1 && (
                        <ArrowRight
                          className={`hidden size-3 lg:inline ${activePulse ? "text-signal" : "text-muted-foreground/45"}`}
                          aria-hidden
                        />
                      )}
                    </span>
                    <span className={`font-mono text-[11px] font-medium ${hasDrops ? "text-stale" : "text-live"}`}>
                      {sum > 0 ? `${passPct}%` : "—"}
                    </span>
                  </div>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-foreground font-mono text-base font-semibold">
                      {stage.ok.toLocaleString()}
                    </span>
                    <span className="text-muted-foreground text-[11px]">{stage.okLabel}</span>
                  </div>
                  <div className="bg-muted h-1 w-full overflow-hidden rounded-full">
                    <div
                      className={`h-full transition-all duration-300 ${
                        hasDrops && passPct < 99 ? "bg-stale" : "bg-live"
                      } ${activePulse ? "flow-stream-fast" : ""}`}
                      style={{ width: `${sum > 0 ? passPct : 0}%` }}
                    />
                  </div>
                  <div className={`text-[11px] font-mono ${hasDrops ? "text-fault" : "text-muted-foreground"}`}>
                    {stage.drop.toLocaleString()} {stage.dropLabel}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </Panel>
  )
}
