import { suiteLabel } from "@/lib/validate"

// Live renderings of Brandkit §01/§02 (Rampart Seal & Boundary Geometry)
// and §08 (Cryptographic Boundary Architecture) inside the cockpit.

export function RampartSeal({ className = "" }: { className?: string }) {
  return (
    <span
      className={`inline-flex size-8 shrink-0 items-center justify-center rounded-md border border-[#39c5cf]/45 bg-[#39c5cf]/10 shadow-[0_0_16px_rgba(57,197,207,0.22)] ${className}`}
      aria-hidden="true"
    >
      <svg viewBox="0 0 24 24" className="size-5" fill="none" role="img">
        <polygon
          points="12,2.5 21.5,12 12,21.5 2.5,12"
          stroke="var(--color-signal)"
          strokeWidth="1.6"
          fill="color-mix(in oklab, var(--color-signal) 12%, transparent)"
        />
        <polygon points="12,6.8 17.2,12 12,17.2 6.8,12" fill="var(--color-signal)" />
        <circle cx="12" cy="12" r="1.4" fill="#0d1117" />
      </svg>
    </span>
  )
}

type BoundaryTone = "live" | "stale" | "fault" | "muted"

const TONE_STROKE: Record<BoundaryTone, string> = {
  live: "var(--color-live)",
  stale: "var(--color-stale)",
  fault: "var(--color-fault)",
  muted: "var(--color-signal)",
}

export function BoundaryGeometry({
  interfaceName,
  address,
  suite = "0x0003",
  verdictLabel,
  tone,
  peersUp,
  totalPeers,
  live,
}: {
  interfaceName: string
  address: string
  suite?: string
  verdictLabel: string
  tone: BoundaryTone
  peersUp: number
  totalPeers: number
  live: boolean
}) {
  const accent = TONE_STROKE[tone]
  return (
    <div
      className="border-border/90 bg-background/70 flex min-w-[270px] flex-col gap-1.5 rounded-lg border px-3.5 py-2.5 shadow-[inset_0_1px_0_rgba(57,197,207,0.12)]"
      aria-label={`Tunnel boundary for ${interfaceName || "vallum0"}: ${verdictLabel}, ${peersUp} of ${totalPeers} peers up`}
    >
      <div className="flex items-center justify-between gap-4 text-[10px] tracking-[0.1em] uppercase">
        <span className="text-muted-foreground font-semibold">Tunnel boundary</span>
        <span className={peersUp > 0 ? "text-live font-semibold" : "text-muted-foreground font-semibold"}>
          {peersUp}/{totalPeers} peers up
        </span>
      </div>
      <svg
        viewBox="0 0 320 62"
        className="h-[58px] w-full max-w-[320px]"
        role="img"
        aria-hidden="true"
      >
        <defs>
          <pattern id="rampart-grid" width="16" height="16" patternUnits="userSpaceOnUse">
            <path
              d="M 16 0 L 0 0 0 16"
              fill="none"
              stroke="var(--color-border)"
              strokeOpacity="0.4"
              strokeWidth="0.6"
            />
          </pattern>
        </defs>
        <rect x="0" y="0" width="320" height="62" rx="4" fill="url(#rampart-grid)" />
        {/* Horizontal initiator <-> responder vector line */}
        <line
          x1="28"
          y1="31"
          x2="292"
          y2="31"
          stroke={accent}
          strokeWidth="1.6"
          strokeDasharray={live ? undefined : "4 3"}
          strokeOpacity={live ? 0.92 : 0.45}
        />
        {live && (
          <line
            x1="28"
            y1="31"
            x2="292"
            y2="31"
            stroke="var(--color-foreground)"
            strokeWidth="1.8"
            strokeOpacity="0.65"
            strokeLinecap="round"
            className="svg-packet-flow"
          />
        )}
        {/* Vertical rampart axis */}
        <line
          x1="160"
          y1="6"
          x2="160"
          y2="56"
          stroke="var(--color-border)"
          strokeWidth="1"
        />
        {/* Initiator node */}
        <circle
          cx="62"
          cy="31"
          r="6"
          fill="var(--color-background)"
          stroke="var(--color-signal)"
          strokeWidth="1.8"
        />
        {/* Responder node */}
        {live && peersUp > 0 && (
          <circle
            cx="258"
            cy="31"
            r="7"
            fill="none"
            stroke="var(--color-live)"
            strokeWidth="1.4"
            className="beacon-pulse"
          />
        )}
        <circle
          cx="258"
          cy="31"
          r="6"
          fill="var(--color-background)"
          stroke={peersUp > 0 ? "var(--color-live)" : "var(--color-muted-foreground)"}
          strokeWidth="1.8"
        />
        {/* Central Rampart Gate concentric diamonds */}
        {live && peersUp > 0 && (
          <circle
            cx="160"
            cy="31"
            r="10"
            fill="none"
            stroke="var(--color-signal)"
            strokeWidth="1.2"
            className="beacon-pulse"
          />
        )}
        <polygon
          points="160,12 179,31 160,50 141,31"
          fill="var(--color-card)"
          stroke="var(--color-signal)"
          strokeWidth="1.5"
        />
        <polygon points="160,21 170,31 160,41 150,31" fill="var(--color-signal)" />
      </svg>
      <div className="flex items-center justify-between gap-4 font-mono text-[11px]">
        <span className="text-muted-foreground truncate">
          {interfaceName || "vallum0"} · {address || "—"}
        </span>
        <span className="text-signal shrink-0 font-semibold">{suite || "0x0003"} PQ</span>
      </div>
    </div>
  )
}

interface CryptoStage {
  name: string
  role: string
  borderClass: string
  textClass: string
}

function stagesForSuite(suite: string): CryptoStage[] {
  const code = suite.trim().toLowerCase()
  const base: CryptoStage[] = [
    {
      name: "X25519",
      role: "ECDHE",
      borderClass: "border-[#39c5cf]/50 bg-[#39c5cf]/5",
      textClass: "text-[#39c5cf]",
    },
  ]
  if (code !== "0x0002") {
    base.push({
      name: "sntrup761",
      role: "PQ KEM",
      borderClass: "border-[#39c5cf]/50 bg-[#39c5cf]/5",
      textClass: "text-[#39c5cf]",
    })
  }
  if (code !== "0x0001") {
    base.push({
      name: "ML-KEM-768",
      role: "NIST 203",
      borderClass: "border-[#bc8cff]/50 bg-[#bc8cff]/5",
      textClass: "text-[#bc8cff]",
    })
  }
  base.push(
    {
      name: "Blake2s + HKDF",
      role: "32-byte key",
      borderClass: "border-[#d29922]/50 bg-[#d29922]/5",
      textClass: "text-[#d29922]",
    },
    {
      name: "XChaCha20-Poly1305",
      role: "AEAD Tunnel",
      borderClass: "border-[#3fb950]/50 bg-[#3fb950]/5",
      textClass: "text-[#3fb950]",
    },
  )
  return base
}

export function CryptoArchitecture({ suite }: { suite: string }) {
  const stages = stagesForSuite(suite)
  return (
    <div className="flex flex-col gap-2">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {stages.map((stage) => (
          <div
            key={stage.name}
            className={`flex flex-col rounded-md border px-2.5 py-2 ${stage.borderClass}`}
          >
            <span className="text-foreground truncate text-xs font-semibold">{stage.name}</span>
            <span className={`text-[11px] font-medium ${stage.textClass}`}>{stage.role}</span>
          </div>
        ))}
      </div>
      <div className="text-muted-foreground flex flex-wrap items-center justify-between gap-2 text-[11px]">
        <span>MEX-bound static ops · mutual confirmation · eCK-PFS-PSK</span>
        <span className="font-mono">{suiteLabel(suite) || suite}</span>
      </div>
    </div>
  )
}
