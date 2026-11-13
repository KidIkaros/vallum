// Who is moving bytes right now, per peer. Device totals say how much;
// this says by whom — the question an operator asks when a link saturates.
// Rates come from consecutive snapshots (App holds the baseline), so the
// first visit seeds and shows the quiet state instead of zeros that read
// like measurements. Bars share the chart's scale rule: every row measures
// against the hottest peer, never against itself.

import { bytes } from "@/lib/bridge"
import { rateLabel } from "@/lib/traffic"
import type { Peer } from "@/types"

export interface PeerRate {
  name: string
  rx: number
  tx: number
}

export function TopTalkers({ rates, peers = [] }: { rates: PeerRate[]; peers?: Peer[] }) {
  const liveTop = rates.slice(0, 5)
  if (liveTop.length > 0) {
    const peak = Math.max(1, ...liveTop.map((r) => r.rx + r.tx))
    return (
      <div className="flex flex-col gap-1.5 pt-2">
        <div className="flex items-baseline justify-between">
          <span className="text-muted-foreground text-xs font-medium">Live throughput by peer</span>
          <span className="text-muted-foreground font-mono text-xs">Peak {rateLabel(peak)}</span>
        </div>
        <ul className="flex flex-col gap-1">
          {liveTop.map((peer) => {
            const total = peer.rx + peer.tx
            const rxShare = total > 0 ? (peer.rx / peak) * 100 : 0
            const txShare = total > 0 ? (peer.tx / peak) * 100 : 0
            return (
              <li key={peer.name} className="flex items-center gap-2">
                <span className="w-28 shrink-0 truncate text-xs">{peer.name}</span>
                <span
                  className="bg-muted flex h-[7px] min-w-0 flex-1 overflow-hidden rounded"
                  role="img"
                  aria-label={`${peer.name}: download ${rateLabel(peer.rx)}, upload ${rateLabel(peer.tx)}`}
                >
                  <span className="bg-signal h-full" style={{ width: `${rxShare}%` }} />
                  <span className="bg-violet h-full" style={{ width: `${txShare}%` }} />
                </span>
                <span className="text-muted-foreground w-20 shrink-0 text-right font-mono text-xs">
                  {rateLabel(total)}
                </span>
              </li>
            )
          })}
        </ul>
      </div>
    )
  }

  const volumeTop = [...peers]
    .filter((p) => p.rx_bytes + p.tx_bytes > 0)
    .sort((a, b) => b.rx_bytes + b.tx_bytes - (a.rx_bytes + a.tx_bytes))
    .slice(0, 5)
  const peakVolume = Math.max(1, ...volumeTop.map((p) => p.rx_bytes + p.tx_bytes))

  return (
    <div className="flex flex-col gap-1.5 pt-2">
      <div className="flex items-baseline justify-between">
        <span className="text-muted-foreground text-xs font-medium">Session volume by peer</span>
        {volumeTop.length > 0 && (
          <span className="text-muted-foreground font-mono text-xs">Peak {bytes(peakVolume)}</span>
        )}
      </div>
      {volumeTop.length === 0 ? (
        <p className="text-muted-foreground py-2 text-xs">No peer traffic recorded yet</p>
      ) : (
        <ul className="flex flex-col gap-1">
          {volumeTop.map((peer) => {
            const total = peer.rx_bytes + peer.tx_bytes
            const rxShare = (peer.rx_bytes / peakVolume) * 100
            const txShare = (peer.tx_bytes / peakVolume) * 100
            return (
              <li key={peer.fingerprint} className="flex items-center gap-2">
                <span className="w-28 shrink-0 truncate text-xs">{peer.name}</span>
                <span
                  className="bg-muted flex h-[7px] min-w-0 flex-1 overflow-hidden rounded"
                  role="img"
                  aria-label={`${peer.name}: received ${bytes(peer.rx_bytes)}, sent ${bytes(peer.tx_bytes)}`}
                >
                  <span className="bg-signal h-full" style={{ width: `${rxShare}%` }} />
                  <span className="bg-violet h-full" style={{ width: `${txShare}%` }} />
                </span>
                <span className="text-muted-foreground w-20 shrink-0 text-right font-mono text-xs">
                  {bytes(total)}
                </span>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
