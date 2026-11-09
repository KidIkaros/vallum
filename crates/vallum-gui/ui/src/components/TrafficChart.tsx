import { useMemo } from "react"
import type { Sample } from "@/lib/traffic"
import { rateLabel } from "@/lib/traffic"

// A throughput chart with an honest axis. Two series (rx cyan, tx violet),
// drawn as filled areas over a shared scale, with the peak labelled so the
// reader never has to guess the magnitude. The scale is the window's peak —
// the same rule the bars use: no normalisation, no smoothing that hides a gap.

const W = 720
const H = 96
const PAD = { left: 0, right: 0, top: 6, bottom: 14 }

function series(samples: Sample[], kind: "rx" | "tx"): number[] {
  const deltas: number[] = []
  for (let i = 1; i < samples.length; i++) {
    const seconds = (samples[i].at - samples[i - 1].at) / 1000
    const delta = Math.max(0, samples[i][kind] - samples[i - 1][kind])
    deltas.push(seconds > 0 ? delta / seconds : 0)
  }
  return deltas
}

function area(values: number[], peak: number, width: number): string {
  if (values.length < 2) return ""
  const step = width / (values.length - 1)
  const y = (value: number) => PAD.top + (1 - value / peak) * (H - PAD.top - PAD.bottom)
  const points = values.map((value, index) => `${(index * step).toFixed(1)},${y(value).toFixed(1)}`)
  return `M0,${H - PAD.bottom} L${points.join(" L")} L${width},${H - PAD.bottom} Z`
}

export function TrafficChart({ samples }: { samples: Sample[] }) {
  const { rx, tx, peak, rxPeak, txPeak } = useMemo(() => {
    const rxSeries = series(samples, "rx")
    const txSeries = series(samples, "tx")
    const top = Math.max(1, ...rxSeries, ...txSeries)
    return {
      rx: rxSeries,
      tx: txSeries,
      peak: top,
      rxPeak: Math.max(0, ...rxSeries),
      txPeak: Math.max(0, ...txSeries),
    }
  }, [samples])

  const seconds = samples.length > 1 ? Math.round((samples.at(-1)!.at - samples[0].at) / 1000) : 0

  const peakY = PAD.top + 0.5
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline justify-between">
        <span className="micro">rate · last {seconds || 0}s</span>
        <span className="text-muted-foreground text-[10px]">
          scale 0 – <span className="text-foreground/80">{rateLabel(peak)}</span>
        </span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-[120px] w-full"
        role="img"
        aria-label={`Receive peak ${rateLabel(rxPeak)}, transmit peak ${rateLabel(txPeak)}`}
      >
        <defs>
          <linearGradient id="rx-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-signal)" stopOpacity="0.35" />
            <stop offset="100%" stopColor="var(--color-signal)" stopOpacity="0.02" />
          </linearGradient>
          <linearGradient id="tx-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-violet)" stopOpacity="0.3" />
            <stop offset="100%" stopColor="var(--color-violet)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {/* The top of the scale, drawn: a reader can measure against it. */}
        <line
          x1={0}
          y1={peakY}
          x2={W}
          y2={peakY}
          stroke="var(--color-border)"
          strokeWidth="1"
          strokeDasharray="3 3"
        />
        {/* Baseline: zero is where the chart says it is. */}
        <line
          x1={0}
          y1={H - PAD.bottom}
          x2={W}
          y2={H - PAD.bottom}
          stroke="var(--color-border)"
          strokeWidth="1"
        />
        <path d={area(tx, peak, W)} fill="url(#tx-fill)" stroke="var(--color-violet)" strokeWidth="1.2" />
        <path d={area(rx, peak, W)} fill="url(#rx-fill)" stroke="var(--color-signal)" strokeWidth="1.2" />
      </svg>
      <div className="text-muted-foreground flex justify-between text-[10px]">
        <span>
          <span className="text-signal">▼ rx</span> peak {rateLabel(rxPeak)}
        </span>
        <span>
          <span className="text-violet">▲ tx</span> peak {rateLabel(txPeak)}
        </span>
      </div>
    </div>
  )
}
