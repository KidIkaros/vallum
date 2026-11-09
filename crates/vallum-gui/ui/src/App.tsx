import { useEffect, useMemo, useRef, useState } from "react"
import { Copy, ShieldOff } from "lucide-react"
import { toast } from "sonner"
import { Toaster } from "@/components/ui/sonner"
import { TrafficBars } from "@/components/TrafficBars"
import {
  AddPeerDialog,
  DeviceDialog,
  EditPeerDialog,
  FinalizeButton,
  InviteDialog,
  RemoveDialog,
  RotateDialog,
} from "@/components/PeerDialogs"
import { bytes, hasBridge, listInterfaces, onSnapshot, selectInterface, watchWindowState } from "@/lib/bridge"
import { LogsPanel, ServiceStrip } from "@/components/Service"
import { TrafficHistory, freshness, freshnessLabel, rateLabel, type Sample } from "@/lib/traffic"
import type { InterfaceEntry, Peer, SnapshotPayload } from "@/types"

// The console is the TUI's dashboard rendered in the webview: same vocabulary
// (◆ Vallum ) TUNNEL CONTROL, the semantic palette, traffic bars, the peer
// detail shape) but composed for a window instead of a terminal. The design
// rule: state first, then rate, then detail — each at its own size, so the eye
// lands on "is my tunnel up" before anything else. Where a value is absent the
// surface says so rather than rendering a plausible zero.

const FRESH_SEC = 5 * 60

// The console renders inside the Tauri webview, where `__TAURI_INTERNALS__`
// is the IPC bridge. A plain browser tab has no bridge and no daemon, so the
// app says that instead of throwing "cannot read properties of undefined".

function Diamond({ className = "" }: { className?: string }) {
  return (
    <span aria-hidden className={`inline-block size-1.5 rotate-45 bg-signal ${className}`} />
  )
}

function PanelTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5">
      <Diamond />
      <span className="text-signal text-xs font-semibold tracking-wide">{children}</span>
    </div>
  )
}

function Panel({
  title,
  right,
  children,
  className = "",
}: {
  title: React.ReactNode
  right?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <section className={`bg-card/60 rounded-lg border border-border/70 ${className}`}>
      <div className="flex items-center justify-between px-4 pt-3 pb-1">
        <PanelTitle>{title}</PanelTitle>
        {right}
      </div>
      <div className="px-4 pb-3.5">{children}</div>
    </section>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col py-0.5">
      <span className="micro">{label}</span>
      <span className="text-foreground/90 min-w-0 break-words">{children}</span>
    </div>
  )
}

const freshnessTone: Record<string, string> = {
  never: "text-muted-foreground",
  recent: "text-live",
  aging: "text-stale",
  old: "text-fault",
}

function anyPeerUp(payload: SnapshotPayload | null, now: number): boolean {
  return (
    payload?.data?.peers.some(
      (p) => p.last_handshake_sec > 0 && now - p.last_handshake_sec < FRESH_SEC,
    ) ?? false
  )
}

function useLiveClock(): number {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const timer = window.setInterval(() => setTick((t) => t + 1), 1000)
    return () => window.clearInterval(timer)
  }, [])
  return useMemo(() => Math.floor(Date.now() / 1000), [tick])
}

/** State, rate, and freshness at three sizes — the screen's focal point. */
function Hero({
  payload,
  now,
  history,
  samples,
  lastReply,
}: {
  payload: SnapshotPayload | null
  now: number
  history: TrafficHistory
  samples: Sample[]
  lastReply: string
}) {
  const data = payload?.data
  const up = anyPeerUp(payload, now)
  const unreachable = payload !== null && !payload.ok
  const handshake = data?.peers
    .map((p) => p.last_handshake_sec)
    .filter((s) => s > 0)
    .sort((a, b) => b - a)[0]
  const rx = history.rate("rx")
  const tx = history.rate("tx")
  const last = samples.at(-1) ?? { rx: 0, tx: 0 }

  return (
    <section className="bg-card/60 rounded-lg border border-border/70 px-5 py-4">
      <div className="flex flex-wrap items-end justify-between gap-x-10 gap-y-4">
        <div className="flex flex-col gap-1">
          <span className="micro">tunnel</span>
          <span
            className={`text-3xl leading-none font-semibold tracking-tight ${
              up ? "text-live" : unreachable ? "text-fault" : "text-foreground/80"
            }`}
          >
            {up ? "UP" : unreachable ? "FAULT" : data ? "IDLE" : "…"}
          </span>
          <span className="text-muted-foreground mt-0.5 text-xs">
            {data ? (
              <>
                {data.interface} · {data.addresses.join(" · ")} ·{" "}
                {handshake ? `established ${Math.max(0, now - handshake)}s ago` : "no session yet"}
              </>
            ) : (
              "waiting for the daemon's first snapshot"
            )}
            <span className={payload?.ok ? "text-live" : "text-muted-foreground"}>
              {" "}
              · control {lastReply}
            </span>
          </span>
        </div>

        <div className="flex items-end gap-8">
          {(
            [
              ["▼ rx", rx, last.rx, "signal"] as const,
              ["▲ tx", tx, last.tx, "violet"] as const,
            ]
          ).map(([label, rate, total, tone]) => (
            <div key={label} className="flex flex-col gap-1">
              <span className={`micro ${tone === "signal" ? "text-signal/80" : "text-violet/80"}`}>
                {label}
              </span>
              <span
                className={`text-2xl leading-none font-medium tracking-tight ${
                  tone === "signal" ? "text-signal" : "text-violet"
                }`}
              >
                {rateLabel(rate)}
              </span>
              <span className="text-muted-foreground text-[10px]">Σ {bytes(total)}</span>
              <TrafficBars samples={samples} kind={tone === "signal" ? "rx" : "tx"} color={tone} bars={40} height={20} />
            </div>
          ))}
        </div>
      </div>
      {payload && !payload.ok && payload.error && (
        <p className="text-fault mt-2 text-xs">{payload.error}</p>
      )}
    </section>
  )
}

function peerState(peer: Peer, now: number) {
  const f = freshness(peer.last_handshake_sec, now)
  return { f, tone: freshnessTone[f] }
}

function PeersPanel({
  peers,
  now,
  selected,
  onSelect,
  actions,
}: {
  peers: Peer[]
  now: number
  selected: string | null
  onSelect: (fingerprint: string) => void
  actions?: React.ReactNode
}) {
  return (
    <Panel
      title={
        <>
          PEERS [<span className="text-foreground">{peers.length}</span>]
        </>
      }
      right={actions}
      className="min-w-0"
    >
      {peers.length === 0 ? (
        <p className="text-muted-foreground py-3 text-xs">no peers configured</p>
      ) : (
        <ul className="flex flex-col">
          {peers.map((peer) => {
            const { f, tone } = peerState(peer, now)
            const isSelected = peer.fingerprint === selected
            return (
              <li key={peer.fingerprint}>
                <button
                  onClick={() => onSelect(peer.fingerprint)}
                  aria-pressed={isSelected}
                  className={`flex w-full cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-left transition-colors focus-visible:ring-1 focus-visible:ring-signal focus-visible:outline-none ${
                    isSelected ? "bg-secondary text-foreground" : "hover:bg-secondary/50"
                  }`}
                >
                  <span className={isSelected ? "text-signal" : "text-transparent"}>)</span>
                  <span className="min-w-0 flex-1 truncate">{peer.name}</span>
                  {peer.rotating && (
                    <span className="text-violet text-[10px] uppercase">rotating</span>
                  )}
                  <span className={`text-[10px] uppercase ${tone}`}>{freshnessLabel[f]}</span>
                  <span aria-hidden className="text-muted-foreground/60">
                    ›
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}

function PeerDetail({
  peer,
  now,
  blocked,
}: {
  peer: Peer | null
  now: number
  blocked?: string
}) {
  if (!peer) {
    return (
      <Panel title="PEER DETAIL">
        <p className="text-muted-foreground py-3 text-xs">select a peer</p>
      </Panel>
    )
  }
  const { f, tone } = peerState(peer, now)
  return (
    <Panel
      title={
        <span className="flex items-center gap-1.5">
          <span
            aria-hidden
            className={`inline-block size-1.5 rounded-full ${
              f === "recent" ? "animate-pulse bg-live" : f === "aging" ? "bg-stale" : "bg-muted-foreground/40"
            }`}
          />
          <span className="text-foreground/90">{peer.name}</span>
        </span>
      }
      right={peer.has_preshared_key ? <span className="micro">PSK set</span> : undefined}
    >
      {/* Actions first: they are what the panel is for. */}
      <div className="mb-2 flex flex-wrap items-center gap-1.5">
        {blocked && (
          <span className="micro text-stale" title={blocked}>
            read-only
          </span>
        )}
        <EditPeerDialog peer={peer} blocked={blocked} />
        <RotateDialog peer={peer} blocked={blocked} />
        {peer.rotating && <FinalizeButton peer={peer} blocked={blocked} />}
        <RemoveDialog peer={peer} blocked={blocked} />
      </div>
      <Row label="fingerprint">{peer.fingerprint}</Row>
      <Row label="endpoint">{peer.endpoint || "roaming"}</Row>
      <Row label="allowed">{peer.allowed_ips.join(", ")}</Row>
      <Row label="keepalive">{peer.keepalive !== null ? `${peer.keepalive}s` : "—"}</Row>
      <Row label="transfer">
        {bytes(peer.rx_bytes)} ↓ / {bytes(peer.tx_bytes)} ↑
      </Row>
      <Row label="handshake">
        <span className={tone}>{freshnessLabel[f]}</span>
        <span className="text-muted-foreground">
          {" "}
          {peer.last_handshake_sec === 0
            ? "never"
            : `${Math.max(0, now - peer.last_handshake_sec)}s ago`}
        </span>
      </Row>
      <Row label="epoch">{peer.epoch}</Row>
    </Panel>
  )
}

function InterfaceData({ payload }: { payload: SnapshotPayload | null }) {
  const c = payload?.data?.counters
  const metric = (label: string, primary: string, secondary: React.ReactNode) => (
    <div className="flex flex-col">
      <span className="micro">{label}</span>
      <span>{primary}</span>
      <span className="text-muted-foreground text-xs">{secondary}</span>
    </div>
  )
  return (
    <Panel title="INTERFACE DATA">
      <div className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-3">
        {metric(
          "datagrams",
          `sent ${c ? c.datagrams_sent.toLocaleString() : "—"}`,
          <span className={c && c.datagrams_failed > 0 ? "text-fault" : ""}>
            failed {c?.datagrams_failed ?? "—"}
          </span>,
        )}
        {metric(
          "packets",
          `delivered ${c ? c.packets_delivered.toLocaleString() : "—"}`,
          <span className={c && c.packets_failed > 0 ? "text-fault" : ""}>
            failed {c?.packets_failed ?? "—"}
          </span>,
        )}
        {metric(
          "handshakes",
          `established ${c?.established ?? "—"}`,
          <span className={c && c.refusals > 0 ? "text-fault" : ""}>
            refused {c?.refusals ?? "—"}
          </span>,
        )}
      </div>
    </Panel>
  )
}

function NoBridge() {
  return (
    <section className="bg-card/60 rounded-lg border border-border/70">
      <div className="flex flex-col items-center gap-3 px-6 py-14 text-center">
        <ShieldOff className="text-muted-foreground size-8" aria-hidden />
        <div>
          <p className="font-medium">This is the console's web UI, not the console</p>
          <p className="text-muted-foreground mt-1 max-w-md text-xs">
            This page has no bridge to the daemon. Open the console inside the
            Vallum application, or serve it over localhost:
          </p>
          <code className="text-signal mt-3 inline-block text-xs">
            ./target/release/vallum-gui --serve 7317
          </code>
        </div>
      </div>
    </section>
  )
}

function EmptyState() {
  return (
    <section className="bg-card/60 rounded-lg border border-border/70">
      <div className="flex flex-col items-center gap-3 px-6 py-14 text-center">
        <ShieldOff className="text-muted-foreground size-8" aria-hidden />
        <div>
          <p className="font-medium">No daemon on this machine</p>
          <p className="text-muted-foreground mt-1 max-w-md text-xs">
            The console found no control socket in the runtime directory. Start a daemon
            with <code className="text-signal">vallum run</code> or{" "}
            <code className="text-signal">vallum-quick up</code>.
          </p>
          <button
            className="border-border hover:bg-secondary mt-3 inline-flex cursor-pointer items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] transition-colors focus-visible:ring-1 focus-visible:ring-signal focus-visible:outline-none"
            onClick={() => {
              void navigator.clipboard.writeText("vallum-quick up")
              toast.success("copied: vallum-quick up")
            }}
          >
            <Copy className="size-3" aria-hidden /> copy command
          </button>
        </div>
      </div>
    </section>
  )
}

export default function App() {
  const inApp = useMemo(() => hasBridge, [])
  const [interfaces, setInterfaces] = useState<InterfaceEntry[]>([])
  const [payload, setPayload] = useState<SnapshotPayload | null>(null)
  const [samples, setSamples] = useState<Sample[]>([])
  const [selectedPeer, setSelectedPeer] = useState<string | null>(null)
  const [lastUpdate, setLastUpdate] = useState<number | null>(null)
  const history = useRef(new TrafficHistory())
  const now = useLiveClock()

  useEffect(() => watchWindowState(), [])

  // One ingestion path for live snapshots and demo ones, so the demo renders
  // exactly what a daemon would — and nothing else.
  const ingestRef = useRef((payload: SnapshotPayload) => {
    setPayload(payload)
    setLastUpdate(Date.now() / 1000)
    if (payload.data) {
      const rx = payload.data.peers.reduce((sum, p) => sum + p.rx_bytes, 0)
      const tx = payload.data.peers.reduce((sum, p) => sum + p.tx_bytes, 0)
      history.current.push(rx, tx)
      setSamples([...history.current.recent()])
    }
  })
  const ingest = ingestRef.current

  useEffect(() => {
    if (!inApp) return
    let cancelled = false
    listInterfaces().then((entries) => {
      if (cancelled) return
      setInterfaces(entries)
      // The first socket is the daemon the operator most likely means; picking
      // it saves a click without hiding the others.
      if (entries.length > 0) void selectInterface(entries[0].path)
    })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (!inApp) return
    let unlisten: (() => void) | undefined
    void onSnapshot(ingest).then((fn) => {
      unlisten = fn
    })
    return () => unlisten?.()
  }, [])

  const data = payload?.data
  if (data && data.peers.length > 0 && selectedPeer === null) {
    setSelectedPeer(data.peers[0].fingerprint)
  }
  const detail = data?.peers.find((p) => p.fingerprint === selectedPeer) ?? null
  // Demo data cannot be written to: the daemon is not there to write to.
  const blocked = data ? undefined : "waiting for the daemon's first snapshot"
  const lastReply =
    lastUpdate !== null ? `${Math.max(0, now - Math.floor(lastUpdate))}s` : "—"

  return (
    <div className="mx-auto flex min-h-svh max-w-6xl flex-col gap-3 p-4">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 px-1">
        <PanelTitle>
          <span className="text-foreground">Vallum ) </span>TUNNEL CONTROL
        </PanelTitle>
        {interfaces.length > 0 && (
          <span className="text-subtext text-xs">
            [1/{interfaces.length}] {data?.interface ?? interfaces[0]?.name}
          </span>
        )}
        <div className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
          <ServiceStrip blocked={blocked} />
          <DeviceDialog
            listenPort={data?.listen_port ?? null}
            fwmark={data?.fwmark ?? null}
            blocked={blocked}
          />
          {data && (
            <>
              <span className="text-muted-foreground">
                listen <span className="text-foreground/80">{data.listen_port !== null ? `:${data.listen_port}` : "—"}</span>
              </span>
              <span className="text-muted-foreground">
                suite <span className="text-signal">{data.suite}</span>
              </span>
              {data.fwmark !== null && (
                <span className="text-muted-foreground">
                  fwmark <span className="text-foreground/80">{data.fwmark}</span>
                </span>
              )}
              <span className="text-muted-foreground">
                id <span className="text-foreground/80">{data.fingerprint.slice(0, 16)}</span>
              </span>
            </>
          )}
        </div>
      </header>

      {!inApp ? (
        <NoBridge />
      ) : interfaces.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <Hero
            payload={payload}
            now={now}
            history={history.current}
            samples={samples}
            lastReply={lastReply}
          />
          <div className="flex flex-col gap-3 md:flex-row">
            <div className="flex min-w-0 flex-1 flex-col gap-3">
              <PeersPanel
                peers={data?.peers ?? []}
                now={now}
                selected={selectedPeer}
                onSelect={setSelectedPeer}
                actions={
                  <span className="flex gap-1.5">
                    <InviteDialog blocked={blocked} />
                    <AddPeerDialog blocked={blocked} />
                  </span>
                }
              />
              <InterfaceData payload={payload} />
            </div>
            <div className="flex flex-col gap-3 md:w-[320px] md:shrink-0">
              <PeerDetail peer={detail} now={now} blocked={blocked} />
            </div>
          </div>
          <LogsPanel blocked={blocked} />
          <footer className="text-muted-foreground flex items-center gap-2 px-1 text-[10px]">
            <span>updated {lastReply}</span>
            <span>·</span>
            <span>snapshot stream</span>
          </footer>
        </>
      )}

      <Toaster position="bottom-right" />
    </div>
  )
}
