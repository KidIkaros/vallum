import { useMemo, useState } from "react"
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
  // Hovered segment, for the crosshair readout. Null is live: the header
  // shows the window, and touching the chart inspects one instant of it.
  const [hover, setHover] = useState<number | null>(null)
  const { rx, tx, peak, rxPeak, txPeak, handshakes } = useMemo(() => {
    const rxSeries = series(samples, "rx")
    const txSeries = series(samples, "tx")
    const top = Math.max(1, ...rxSeries, ...txSeries)
    // Segments where the daemon's handshake counter advanced: the moments
    // new sessions proved themselves. Only where both ends report a count.
    const marks: number[] = []
    for (let i = 1; i < samples.length; i++) {
      const before = samples[i - 1].established
      const after = samples[i].established
      if (before !== undefined && after !== undefined && after > before) marks.push(i)
    }
    return {
      rx: rxSeries,
      tx: txSeries,
      peak: top,
      rxPeak: Math.max(0, ...rxSeries),
      txPeak: Math.max(0, ...txSeries),
      handshakes: marks,
    }
  }, [samples])

  const hovered =
    hover !== null && hover > 0 && hover <= rx.length
      ? {
          ago: Math.max(0, Math.round((samples.at(-1)!.at - samples[hover].at) / 1000)),
          rx: rx[hover - 1],
          tx: tx[hover - 1],
        }
      : null
  const onMove = (event: React.MouseEvent<SVGSVGElement>) => {
    const rect = event.currentTarget.getBoundingClientRect()
    const ratio = (event.clientX - rect.left) / rect.width
    setHover(Math.max(0, Math.min(rx.length, Math.round(ratio * rx.length))))
  }
  // Delta-point i sits at i/(rx.length-1) of the width — the same mapping the
  // area path uses — so ticks and crosshair land on the curve they annotate.
  const xAt = (deltaIndex: number) => (deltaIndex / Math.max(1, rx.length - 1)) * W
  const seconds = samples.length > 1 ? Math.round((samples.at(-1)!.at - samples[0].at) / 1000) : 0
  // Below a few hundred bytes a second the plot is a flat line at a scale that
  // means nothing; saying "idle" is the honest reading.
  const idle = peak < 256

  const peakY = PAD.top + 0.5
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline justify-between">
        <span className="micro">
          {hovered
            ? `${hovered.ago}s ago · ▼ ${rateLabel(hovered.rx)} ▲ ${rateLabel(hovered.tx)}`
            : `rate · last ${seconds || 0}s`}
        </span>
        {!idle && (
          <span className="text-muted-foreground text-xs">
            scale 0 – <span className="text-foreground/80">{rateLabel(peak)}</span>
          </span>
        )}
      </div>
      {samples.length < 2 ? (
        <p className="text-muted-foreground py-6 text-center text-xs">
          waiting for traffic — the chart fills as snapshots arrive
        </p>
      ) : idle ? (
        <p className="text-muted-foreground py-6 text-center text-xs">
          {peak < 1
            ? "idle — no traffic in this window"
            : `low traffic — peak ${rateLabel(peak)}`}
        </p>
      ) : (
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-[160px] w-full cursor-crosshair"
        role="img"
        aria-label={`Receive peak ${rateLabel(rxPeak)}, transmit peak ${rateLabel(txPeak)}${handshakes.length > 0 ? `, ${handshakes.length} handshake${handshakes.length === 1 ? "" : "s"} in window` : ""}`}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
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
        {/* Handshake ticks: short green marks at the top, one per segment
            where the daemon proved a new session. */}
        {handshakes.map((index) => {
          const x = xAt(index - 1)
          return (
            <line
              key={index}
              x1={x}
              y1={peakY}
              x2={x}
              y2={peakY + 7}
              stroke="var(--color-live)"
              strokeWidth="1.5"
            />
          )
        })}
        {/* Crosshair: the inspected instant, drawn so it can be measured. */}
        {hovered !== null && hover !== null && hover > 0 && (
          <line
            x1={xAt(hover - 1)}
            y1={PAD.top}
            x2={xAt(hover - 1)}
            y2={H - PAD.bottom}
            stroke="var(--color-foreground)"
            strokeWidth="1"
            strokeOpacity="0.4"
          />
        )}
      </svg>
      )}
      {!idle && (
        <div className="text-muted-foreground flex justify-between text-xs">
          <span>
            <span className="text-signal">▼ download</span> peak {rateLabel(rxPeak)}
          </span>
          {handshakes.length > 0 && (
            <span>
              <span className="text-live">│</span> {handshakes.length} handshake{handshakes.length === 1 ? "" : "s"}
            </span>
          )}
          <span>
            <span className="text-violet">▲ upload</span> peak {rateLabel(txPeak)}
          </span>
        </div>
      )}
    </div>
  )
}
