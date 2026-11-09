import { useMemo } from "react"
import type { Sample } from "@/lib/traffic"

// The TUI's traffic bars, ported: one bar per poll tick, scaled to the
// window's peak, on a #182a3a baseline — keepalive noise stays near the
// floor (Tufte Lie Factor = 1). RX renders in signal cyan, TX in violet,
// exactly as the cockpit drawing does.

interface BarsProps {
  samples: Sample[]
  kind: "rx" | "tx"
  color: "signal" | "violet"
  bars?: number
  height?: number
}

export function TrafficBars({
  samples,
  kind,
  color,
  bars = 60,
  height = 22,
}: BarsProps) {
  const heights = useMemo(() => {
    const recent = samples.slice(-bars)
    const deltas: number[] = []
    for (let i = 1; i < recent.length; i++) {
      deltas.push(Math.max(0, recent[i][kind] - recent[i - 1][kind]))
    }
    const peak = Math.max(1, ...deltas)
    // Tail-pad so a young window still fills from the right edge.
    while (deltas.length < bars) deltas.unshift(0)
    return deltas.map((d) => {
      if (d <= 0) return 0
      const v = d / peak
      // Floor of 10%: a tick with any traffic stays visible; a truly dead
      // line renders as the baseline itself.
      return Math.max(0.1, v)
    })
  }, [samples, kind, bars])

  return (
    <div
      className="flex items-end gap-px"
      style={{ height }}
      aria-hidden
      data-testid={`bars-${kind}`}
    >
      {heights.map((v, i) => (
        <div
          key={i}
          className={`flex-1 rounded-[1px] transition-[height] duration-300 ease-out ${v === 0 ? "bg-secondary/60" : color === "signal" ? "bg-signal/80" : "bg-violet/80"}`}
          style={{ height: `${v * 100}%`, minHeight: v === 0 ? 1 : 2 }}
        />
      ))}
    </div>
  )
}
