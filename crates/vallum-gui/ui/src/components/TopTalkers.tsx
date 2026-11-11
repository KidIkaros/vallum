// Who is moving bytes right now, per peer. Device totals say how much;
// this says by whom — the question an operator asks when a link saturates.
// Rates come from consecutive snapshots (App holds the baseline), so the
// first visit seeds and shows the quiet state instead of zeros that read
// like measurements. Bars share the chart's scale rule: every row measures
// against the hottest peer, never against itself.

import { rateLabel } from "@/lib/traffic"

export interface PeerRate {
  name: string
  rx: number
  tx: number
}

export function TopTalkers({ rates }: { rates: PeerRate[] }) {
  const top = rates.slice(0, 5)
  const peak = Math.max(1, ...top.map((r) => r.rx + r.tx))
  return (
    <div className="flex flex-col gap-1 pt-2">
      <div className="flex items-baseline justify-between">
        <span className="micro">top talkers · this interval</span>
        {top.length > 0 && (
          <span className="text-muted-foreground text-xs">
            hottest <span className="text-foreground/80">{rateLabel(peak)}</span>
          </span>
        )}
      </div>
      {top.length === 0 ? (
        <p className="text-muted-foreground py-2 text-xs">
          quiet — no peer moved bytes in the last interval
        </p>
      ) : (
        <ul className="flex flex-col gap-1">
          {top.map((peer) => {
            const total = peer.rx + peer.tx
            const rxShare = total > 0 ? (peer.rx / peak) * 100 : 0
            const txShare = total > 0 ? (peer.tx / peak) * 100 : 0
            return (
              <li key={peer.name} className="flex items-center gap-2">
                <span className="w-28 shrink-0 truncate text-xs">{peer.name}</span>
                <span
                  className="flex h-[7px] min-w-0 flex-1 overflow-hidden rounded bg-muted"
                  role="img"
                  aria-label={`${peer.name}: download ${rateLabel(peer.rx)}, upload ${rateLabel(peer.tx)}`}
                >
                  <span className="bg-signal h-full" style={{ width: `${rxShare}%` }} />
                  <span className="bg-violet h-full" style={{ width: `${txShare}%` }} />
                </span>
                <span className="text-muted-foreground w-20 shrink-0 text-right text-xs">
                  {rateLabel(total)}
                </span>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
