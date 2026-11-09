// Traffic history and rates, ported from the TUI (`tui/ui.rs`, `tui/app.rs`).
//
// The TUI keeps ring buffers of rx/tx per poll tick and draws bars scaled to
// the window's peak — with the explicit rule that keepalive noise never
// renders as a full-height bar (Tufte Lie Factor = 1). The same rule governs
// the sparkline here. Rate labels use the same units and thresholds.

export interface Sample {
  /** Client clock at receipt, ms. */
  at: number
  rx: number
  tx: number
}

/** Samples retained for the sparkline. The TUI keeps 180; so do we. */
const WINDOW = 180

// The ring is memory-only, so a console opened mid-session starts with an empty
// chart and the operator cannot tell "idle" from "not watching yet". Persist the
// window per interface; drop it when it is old enough that it would be a lie.
const STORAGE_PREFIX = "vallum.traffic.v1."
const STALE_MS = 10 * 60 * 1000

export function loadHistory(interfaceName: string): Sample[] {
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + interfaceName)
    if (!raw) return []
    const parsed = JSON.parse(raw) as { at: number; samples: Sample[] }
    if (!Array.isArray(parsed.samples) || parsed.samples.length === 0) return []
    const newest = parsed.samples[parsed.samples.length - 1].at
    if (Date.now() - newest > STALE_MS) return []
    return parsed.samples
  } catch {
    return []
  }
}

export function saveHistory(interfaceName: string, samples: Sample[]): void {
  try {
    localStorage.setItem(
      STORAGE_PREFIX + interfaceName,
      JSON.stringify({ at: Date.now(), samples: samples.slice(-WINDOW) }),
    )
  } catch {
    /* a full or disabled store is not worth failing a poll over */
  }
}

export class TrafficHistory {
  private samples: Sample[] = []

  push(rx: number, tx: number, at: number = Date.now()): void {
    this.samples.push({ at, rx, tx })
    if (this.samples.length > WINDOW) this.samples.shift()
  }

  /** Seed the ring from a previous visit, so the chart opens with history. */
  restore(samples: Sample[]): void {
    if (samples.length === 0 || this.samples.length > 1) return
    this.samples = samples.slice(-WINDOW)
  }

  /** Recent samples; consecutive equal totals are dropped by the caller's rate math, not here. */
  recent(): Sample[] {
    return this.samples
  }

  /** Bytes per second over the last completed interval. */
  rate(kind: "rx" | "tx"): number {
    const n = this.samples.length
    if (n < 2) return 0
    const a = this.samples[n - 2]
    const b = this.samples[n - 1]
    const seconds = (b.at - a.at) / 1000
    if (seconds <= 0) return 0
    const delta = Math.max(0, b[kind] - a[kind])
    return delta / seconds
  }

  peak(kind: "rx" | "tx"): number {
    let peak = 0
    for (let i = 1; i < this.samples.length; i++) {
      const delta = this.samples[i][kind] - this.samples[i - 1][kind]
      if (delta > peak) peak = delta
    }
    // Per-second peak over the sampled cadence.
    const n = this.samples.length
    if (n < 2) return peak
    const seconds = (this.samples[n - 1].at - this.samples[0].at) / (n - 1) / 1000
    return seconds > 0 ? peak / seconds : peak
  }
}

export function rateLabel(rate: number): string {
  if (rate < 1024) return `${rate.toFixed(1)} B/s`
  if (rate < 1024 * 1024) return `${(rate / 1024).toFixed(1)} KB/s`
  if (rate < 1024 ** 3) return `${(rate / (1024 * 1024)).toFixed(1)} MB/s`
  return `${(rate / 1024 ** 3).toFixed(1)} GB/s`
}

/** The TUI's freshness bands, verbatim: <5 min recent, <1 h aging, else old. */
export type Freshness = "never" | "recent" | "aging" | "old"

export function freshness(lastHandshakeSec: number, nowSec: number = Date.now() / 1000): Freshness {
  if (lastHandshakeSec === 0) return "never"
  const age = Math.max(0, nowSec - lastHandshakeSec)
  if (age < 5 * 60) return "recent"
  if (age < 60 * 60) return "aging"
  return "old"
}

export const freshnessLabel: Record<Freshness, string> = {
  never: "NEVER",
  recent: "RECENT",
  aging: "AGING",
  old: "OLD",
}

export function sparklinePoints(
  samples: Sample[],
  kind: "rx" | "tx",
  width: number,
  height: number,
): { line: string; area: string } {
  const n = samples.length
  if (n < 2) return { line: "", area: "" }
  const peak = Math.max(1, peakDelta(samples, kind))
  const step = width / (n - 1)
  const points: string[] = []
  for (let i = 0; i < n; i++) {
    const delta =
      i === 0 ? 0 : Math.max(0, samples[i][kind] - samples[i - 1][kind])
    // Normalised to the window's peak: a quiet tick stays near the floor —
    // keepalives never look like traffic.
    const v = Math.min(1, delta / peak)
    const x = (i * step).toFixed(2)
    const y = (height - 1 - v * (height - 2)).toFixed(2)
    points.push(`${x},${y}`)
  }
  const line = points.join(" ")
  const area = `0,${height} ${line} ${width},${height}`
  return { line, area }
}

function peakDelta(samples: Sample[], kind: "rx" | "tx"): number {
  let peak = 0
  for (let i = 1; i < samples.length; i++) {
    const delta = samples[i][kind] - samples[i - 1][kind]
    if (delta > peak) peak = delta
  }
  return peak
}
