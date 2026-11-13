import { useMemo, useState } from "react"
import type { Sample } from "@/lib/traffic"
import { rateLabel } from "@/lib/traffic"

// A throughput chart with an honest axis. Two series (rx cyan, tx violet),
// rendered as clamped Catmull-Rom cubic splines over a shared scale, with peak
// and time reference grid always visible once >= 2 samples exist so layout never jumps.

const W = 720
const H = 104
const PAD = { left: 0, right: 0, top: 8, bottom: 16 }

function series(samples: Sample[], kind: "rx" | "tx"): number[] {
  const deltas: number[] = []
  for (let i = 1; i < samples.length; i++) {
    const seconds = (samples[i].at - samples[i - 1].at) / 1000
    const delta = Math.max(0, samples[i][kind] - samples[i - 1][kind])
    deltas.push(seconds > 0 ? delta / seconds : 0)
  }
  return deltas
}

function clampY(y: number): number {
  return Math.max(PAD.top, Math.min(H - PAD.bottom, y))
}

function toPoints(values: number[], peak: number, width: number): Array<{ x: number; y: number }> {
  const step = width / Math.max(1, values.length - 1)
  return values.map((value, index) => ({
    x: index * step,
    y: PAD.top + (1 - value / peak) * (H - PAD.top - PAD.bottom),
  }))
}

/** Clamped Catmull-Rom -> Cubic Bezier spline (never overshoots baseline or ceiling). */
function smoothLine(values: number[], peak: number, width: number): string {
  if (values.length < 2) return ""
  const pts = toPoints(values, peak, width)
  if (pts.length === 2) {
    return `M${pts[0].x.toFixed(1)},${pts[0].y.toFixed(1)} L${pts[1].x.toFixed(1)},${pts[1].y.toFixed(1)}`
  }
  let d = `M${pts[0].x.toFixed(1)},${pts[0].y.toFixed(1)}`
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[Math.max(0, i - 1)]
    const p1 = pts[i]
    const p2 = pts[i + 1]
    const p3 = pts[Math.min(pts.length - 1, i + 2)]
    const c1x = p1.x + (p2.x - p0.x) / 6
    const c1y = clampY(p1.y + (p2.y - p0.y) / 6)
    const c2x = p2.x - (p3.x - p1.x) / 6
    const c2y = clampY(p2.y - (p3.y - p1.y) / 6)
    d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}`
  }
  return d
}

function smoothArea(values: number[], peak: number, width: number): string {
  const line = smoothLine(values, peak, width)
  if (!line) return ""
  const base = H - PAD.bottom
  return `${line} L${width},${base} L0,${base} Z`
}

export function TrafficChart({ samples }: { samples: Sample[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const { rx, tx, peak, rxPeak, txPeak, rxAvg, txAvg, rxCur, txCur, handshakes } = useMemo(() => {
    const rxSeries = series(samples, "rx")
    const txSeries = series(samples, "tx")
    const top = Math.max(1, ...rxSeries, ...txSeries)
    const avg = (arr: number[]) =>
      arr.length > 0 ? arr.reduce((sum, v) => sum + v, 0) / arr.length : 0

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
      rxAvg: avg(rxSeries),
      txAvg: avg(txSeries),
      rxCur: rxSeries.at(-1) ?? 0,
      txCur: txSeries.at(-1) ?? 0,
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

  const xAt = (deltaIndex: number) => (deltaIndex / Math.max(1, rx.length - 1)) * W
  const seconds = samples.length > 1 ? Math.round((samples.at(-1)!.at - samples[0].at) / 1000) : 0
  const idle = peak < 256

  const peakY = PAD.top + 0.5
  const midY = PAD.top + (H - PAD.top - PAD.bottom) / 2
  const baseY = H - PAD.bottom

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="micro">
          {hovered
            ? `${hovered.ago}s ago · ▼ ${rateLabel(hovered.rx)} ▲ ${rateLabel(hovered.tx)}`
            : `Throughput · last ${seconds || 0}s`}
        </span>
        <div className="flex items-center gap-2 text-xs">
          {idle && samples.length >= 2 && (
            <span className="border-border/70 bg-background/60 text-muted-foreground rounded border px-1.5 py-0.5 font-mono text-[11px]">
              {peak < 1 ? "Idle · 0 B/s" : `Quiet · Peak ${rateLabel(peak)}`}
            </span>
          )}
          <span className="text-muted-foreground text-xs">
            Scale 0 – <span className="text-foreground/80">{idle ? "256 B/s" : rateLabel(peak)}</span>
          </span>
        </div>
      </div>

      {samples.length < 2 ? (
        <p className="text-muted-foreground py-8 text-center text-xs">
          Waiting for traffic — collecting initial telemetry snapshots…
        </p>
      ) : (
        <div className="relative">
          <svg
            viewBox={`0 0 ${W} ${H}`}
            className="h-[164px] w-full cursor-crosshair"
            role="img"
            aria-label={`Receive peak ${rateLabel(rxPeak)}, transmit peak ${rateLabel(txPeak)}${handshakes.length > 0 ? `, ${handshakes.length} handshake${handshakes.length === 1 ? "" : "s"} in window` : ""}`}
            onMouseMove={onMove}
            onMouseLeave={() => setHover(null)}
          >
            <defs>
              <linearGradient id="rx-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-signal)" stopOpacity="0.28" />
                <stop offset="100%" stopColor="var(--color-signal)" stopOpacity="0.02" />
              </linearGradient>
              <linearGradient id="tx-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-violet)" stopOpacity="0.24" />
                <stop offset="100%" stopColor="var(--color-violet)" stopOpacity="0.02" />
              </linearGradient>
              <filter id="cyber-glow" x="-10%" y="-25%" width="120%" height="150%">
                <feGaussianBlur stdDeviation="2" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* 100%, 50%, and 0% honest scale grid lines */}
            <line
              x1={0}
              y1={peakY}
              x2={W}
              y2={peakY}
              stroke="var(--color-border)"
              strokeWidth="1"
              strokeDasharray="3 3"
            />
            <line
              x1={0}
              y1={midY}
              x2={W}
              y2={midY}
              stroke="var(--color-border)"
              strokeOpacity="0.45"
              strokeWidth="1"
              strokeDasharray="2 4"
            />
            <line
              x1={0}
              y1={baseY}
              x2={W}
              y2={baseY}
              stroke="var(--color-border)"
              strokeWidth="1"
            />

            {!idle && (
              <>
                <path
                  d={smoothArea(tx, peak, W)}
                  fill="url(#tx-fill)"
                  stroke="var(--color-violet)"
                  strokeWidth="1.6"
                  filter="url(#cyber-glow)"
                />
                <path
                  d={smoothArea(rx, peak, W)}
                  fill="url(#rx-fill)"
                  stroke="var(--color-signal)"
                  strokeWidth="1.75"
                  filter="url(#cyber-glow)"
                />
              </>
            )}

            {/* Handshake ticks stay visible even during idle traffic windows */}
            {handshakes.map((index) => {
              const x = xAt(index - 1)
              return (
                <line
                  key={index}
                  x1={x}
                  y1={peakY}
                  x2={x}
                  y2={peakY + 8}
                  stroke="var(--color-live)"
                  strokeWidth="1.75"
                />
              )
            })}

            {/* Time-axis ticks */}
            <text x="2" y={H - 2} fill="var(--color-muted-foreground)" fontSize="9" fontFamily="var(--font-mono)">
              -{seconds}s
            </text>
            <text x={W / 2} y={H - 2} textAnchor="middle" fill="var(--color-muted-foreground)" fontSize="9" fontFamily="var(--font-mono)">
              -{Math.round(seconds / 2)}s
            </text>
            <text x={W - 2} y={H - 2} textAnchor="end" fill="var(--color-muted-foreground)" fontSize="9" fontFamily="var(--font-mono)">
              now
            </text>

            {/* Crosshair & intersection markers */}
            {hovered !== null && hover !== null && hover > 0 && (
              <g>
                <line
                  x1={xAt(hover - 1)}
                  y1={PAD.top}
                  x2={xAt(hover - 1)}
                  y2={baseY}
                  stroke="var(--color-foreground)"
                  strokeWidth="1"
                  strokeOpacity="0.45"
                  strokeDasharray="2 2"
                />
                {!idle && (
                  <>
                    <circle
                      cx={xAt(hover - 1)}
                      cy={clampY(PAD.top + (1 - hovered.tx / peak) * (H - PAD.top - PAD.bottom))}
                      r="3.2"
                      fill="var(--color-violet)"
                      stroke="var(--color-background)"
                      strokeWidth="1.5"
                    />
                    <circle
                      cx={xAt(hover - 1)}
                      cy={clampY(PAD.top + (1 - hovered.rx / peak) * (H - PAD.top - PAD.bottom))}
                      r="3.2"
                      fill="var(--color-signal)"
                      stroke="var(--color-background)"
                      strokeWidth="1.5"
                    />
                  </>
                )}
              </g>
            )}
          </svg>
        </div>
      )}

      {/* Compact telemetry stat strip (CUR / AVG / PEAK + handshake count) */}
      <div className="border-border/50 text-muted-foreground grid grid-cols-1 gap-x-4 gap-y-1 border-t pt-2 text-xs sm:grid-cols-3">
        <div>
          <span className="text-signal">▼ Download</span>{" "}
          <span className="text-foreground/85 font-mono">{rateLabel(rxCur)}</span> · avg {rateLabel(rxAvg)} · peak {rateLabel(rxPeak)}
        </div>
        <div className="sm:text-center">
          {handshakes.length > 0 ? (
            <span>
              <span className="text-live">│</span> {handshakes.length} handshake{handshakes.length === 1 ? "" : "s"} in window
            </span>
          ) : (
            <span>0 handshakes in window</span>
          )}
        </div>
        <div className="sm:text-right">
          <span className="text-violet">▲ Upload</span>{" "}
          <span className="text-foreground/85 font-mono">{rateLabel(txCur)}</span> · avg {rateLabel(txAvg)} · peak {rateLabel(txPeak)}
        </div>
      </div>
    </div>
  )
}
