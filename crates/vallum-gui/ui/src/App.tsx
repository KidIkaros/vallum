import { useEffect, useMemo, useRef, useState } from "react"
import { Copy, ShieldOff } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Toaster } from "@/components/ui/sonner"
import { TrafficBars } from "@/components/TrafficBars"
import {
  AddPeerDialog,
  EditPeerDialog,
  FinalizeButton,
  InviteDialog,
  RemoveDialog,
  RotateDialog,
} from "@/components/PeerDialogs"
import { demoRequested, startDemo } from "@/lib/demo"
import { bytes, listInterfaces, onSnapshot, selectInterface, watchWindowState } from "@/lib/bridge"
import { TrafficHistory, freshness, freshnessLabel, rateLabel, type Sample } from "@/lib/traffic"
import type { Counters, InterfaceEntry, Peer, SnapshotPayload } from "@/types"

// The console is the TUI's dashboard rendered in the webview: same header
// grammar (◆ Vallum ) TUNNEL CONTROL), same semantic palette, same traffic
// bars, same peer-detail shape. Where a value is absent the panel says so
// rather than rendering a plausible zero.

const FRESH_SEC = 5 * 60

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
    <section className={`rounded-md border border-border bg-card ${className}`}>
      <div className="border-border/60 flex items-center justify-between border-b px-3 py-1.5">
        <PanelTitle>{title}</PanelTitle>
        {right}
      </div>
      <div className="p-2.5">{children}</div>
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

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <dt className="micro">{label}</dt>
      <dd className="text-foreground/90">{children}</dd>
    </div>
  )
}

const freshnessTone: Record<string, string> = {
  never: "text-muted-foreground",
  recent: "text-live",
  aging: "text-stale",
  old: "text-fault",
}

function Verdict({
  payload,
  now,
  demo,
}: {
  payload: SnapshotPayload | null
  now: number
  demo: boolean
}) {
  const lastOk = useRef<number | null>(null)
  if (payload?.ok) lastOk.current = now
  const live = lastOk.current !== null && now - lastOk.current < 10
  const anyUp = payload?.data?.peers.some(
    (p) => p.last_handshake_sec > 0 && now - p.last_handshake_sec < FRESH_SEC,
  )
  return (
    <div className="flex items-center gap-2" data-testid="verdict">
      {anyUp ? (
        <Badge className="border-live/40 bg-live/15 text-live" variant="outline">
          ● ACTIVE TUNNEL CONTROL
        </Badge>
      ) : payload && !payload.ok ? (
        <Badge className="border-fault/40 bg-fault/15 text-fault" variant="outline">
          ● CONTROL FAULT
        </Badge>
      ) : (
        <Badge variant="outline" className="text-muted-foreground">
          ● {live ? "CONTROL LIVE" : "CONNECTING"}
        </Badge>
      )}
      {demo && (
        <Badge variant="outline" className="border-violet/40 bg-violet/15 text-violet">
          DEMO DATA
        </Badge>
      )}
    </div>
  )
}

function TrafficPanel({
  history,
  samples,
  counters,
}: {
  history: TrafficHistory
  samples: Sample[]
  counters?: Counters
}) {
  const rx = history.rate("rx")
  const tx = history.rate("tx")
  const last = samples.at(-1) ?? { rx: 0, tx: 0 }
  // Packet counts are the daemon's own: delivered in, datagrams out.
  const pk = (n: number | undefined) =>
    n === undefined ? "—" : n >= 1000 ? `${(n / 1000).toFixed(1)}K` : n.toString()
  return (
    <Panel title="TRAFFIC" className="min-w-[260px] flex-1">
      <div className="flex flex-col gap-3">
        <div>
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-signal">▼ RX {rateLabel(rx)}</span>
            <span className="text-muted-foreground text-xs">
              Σ {bytes(last.rx)} · pk {pk(counters?.packets_delivered)}
            </span>
          </div>
          <div className="mt-1">
            <TrafficBars samples={samples} kind="rx" color="signal" />
          </div>
        </div>
        <div>
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-violet">▲ TX {rateLabel(tx)}</span>
            <span className="text-muted-foreground text-xs">
              Σ {bytes(last.tx)} · pk {pk(counters?.datagrams_sent)}
            </span>
          </div>
          <div className="mt-1">
            <TrafficBars samples={samples} kind="tx" color="violet" />
          </div>
        </div>
      </div>
    </Panel>
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
        <p className="text-muted-foreground py-4 text-xs">no peers configured</p>
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
                  className={`flex w-full cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-left focus-visible:ring-1 focus-visible:ring-signal focus-visible:outline-none ${
                    isSelected ? "bg-secondary text-foreground" : "hover:bg-secondary/50"
                  }`}
                >
                  <span className={isSelected ? "text-signal" : "text-transparent"}>)</span>
                  <span className="min-w-0 flex-1 truncate">{peer.name}</span>
                  {peer.rotating && (
                    <span className="text-violet text-[10px] uppercase">rotating</span>
                  )}
                  <span className={`text-[10px] uppercase ${tone}`}>{freshnessLabel[f]}</span>
                  <span aria-hidden className="text-muted-foreground/60">›</span>
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
        <p className="text-muted-foreground py-4 text-xs">select a peer</p>
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
              f === "recent" ? "bg-live" : f === "aging" ? "bg-stale" : "bg-muted-foreground/40"
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
  return (
    <Panel title="INTERFACE DATA">
      <div className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-3">
        <div className="flex flex-col">
          <span className="micro">datagrams</span>
          <span>sent {c ? c.datagrams_sent.toLocaleString() : "—"}</span>
          <span className={c && c.datagrams_failed > 0 ? "text-fault" : "text-muted-foreground"}>
            failed {c?.datagrams_failed ?? "—"}
          </span>
        </div>
        <div className="flex flex-col">
          <span className="micro">packets</span>
          <span>delivered {c ? c.packets_delivered.toLocaleString() : "—"}</span>
          <span className={c && c.packets_failed > 0 ? "text-fault" : "text-muted-foreground"}>
            failed {c?.packets_failed ?? "—"}
          </span>
        </div>
        <div className="flex flex-col">
          <span className="micro">handshakes</span>
          <span>established {c?.established ?? "—"}</span>
          <span className={c && c.refusals > 0 ? "text-fault" : "text-muted-foreground"}>
            refused {c?.refusals ?? "—"}
          </span>
        </div>
      </div>
    </Panel>
  )
}

function EmptyState() {
  return (
    <section className="rounded-md border border-border bg-card">
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
            className="border-border hover:bg-secondary mt-3 inline-flex cursor-pointer items-center gap-1.5 rounded-sm border px-2 py-1 text-[11px] focus-visible:ring-1 focus-visible:ring-signal focus-visible:outline-none"
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
  const [interfaces, setInterfaces] = useState<InterfaceEntry[]>([])
  const [payload, setPayload] = useState<SnapshotPayload | null>(null)
  const [samples, setSamples] = useState<Sample[]>([])
  const [selectedPeer, setSelectedPeer] = useState<string | null>(null)
  const [, setTick] = useState(0)
  const [lastUpdate, setLastUpdate] = useState<number | null>(null)
  const history = useRef(new TrafficHistory())
  const demo = useMemo(() => demoRequested(), [])

  useEffect(() => watchWindowState(), [])
  useEffect(() => {
    const timer = window.setInterval(() => setTick((t) => t + 1), 1000)
    return () => window.clearInterval(timer)
  }, [])

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
    if (demo) {
      setInterfaces([{ name: "vallum0", path: "demo" }])
      return startDemo(ingest)
    }
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demo])

  useEffect(() => {
    if (demo) return
    let unlisten: (() => void) | undefined
    void onSnapshot(ingest).then((fn) => {
      unlisten = fn
    })
    return () => unlisten?.()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demo])

  const now = Math.floor(Date.now() / 1000) // `tick` re-renders once a second
  const data = payload?.data
  if (data && data.peers.length > 0 && selectedPeer === null) {
    setSelectedPeer(data.peers[0].fingerprint)
  }
  const detail = data?.peers.find((p) => p.fingerprint === selectedPeer) ?? null
  // Demo data cannot be written to: the daemon is not there to write to.
  const blocked = demo
    ? "demo preview: peer changes need a live daemon"
    : !data
      ? "waiting for the first snapshot"
      : undefined
  const lastReply =
    lastUpdate !== null ? `${Math.max(0, now - Math.floor(lastUpdate))}s` : "—"

  return (
    <div className="mx-auto flex min-h-svh max-w-6xl flex-col gap-3 p-4">
      <header className="flex flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <PanelTitle>
            <span className="text-foreground">Vallum ) </span>TUNNEL CONTROL
          </PanelTitle>
          <Verdict payload={payload} now={now} demo={demo} />
          {interfaces.length > 0 && (
            <span className="text-subtext text-xs">
              [1/{interfaces.length}] {data?.interface ?? interfaces[0]?.name}
            </span>
          )}
          {demo && (
            <span className="micro ml-auto">
              browser preview — the built console runs from the binary
            </span>
          )}
        </div>
        {data && (
          <>
            <div className="text-xs">
              <span className={payload?.ok ? "text-live" : "text-fault"}>
                {payload?.ok ? "CONTROL LIVE" : "CONTROL UNREACHABLE"}
              </span>
              <span className="text-muted-foreground"> · last reply {lastReply}</span>
            </div>
            <dl className="flex flex-wrap items-baseline gap-x-4 gap-y-1 text-xs">
              <Meta label="listen">
                {data.listen_port !== null ? `0.0.0.0:${data.listen_port}` : "—"}
              </Meta>
              <Meta label="suite">
                <span className="text-signal">{data.suite}</span>
                <span className="text-muted-foreground"> tri-hybrid</span>
              </Meta>
              {data.fwmark !== null && <Meta label="fwmark">{data.fwmark}</Meta>}
              <Meta label="id">{data.fingerprint}</Meta>
              <Meta label="addr">{data.addresses.join(", ")}</Meta>
            </dl>
          </>
        )}
      </header>

      {interfaces.length === 0 ? (
        <EmptyState />
      ) : (
        <>
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
              <TrafficPanel history={history.current} samples={samples} counters={data?.counters} />
              <PeerDetail peer={detail} now={now} blocked={blocked} />
            </div>
          </div>
          <footer className="text-muted-foreground flex items-center gap-2 text-[10px]">
            <span>updated {lastReply}</span>
            <span>·</span>
            <span>snapshot stream from /run/vallum</span>
            {demo && (
              <>
                <span>·</span>
                <span className="text-violet">synthetic data (?demo=1)</span>
              </>
            )}
          </footer>
        </>
      )}

      <Toaster position="bottom-right" />
    </div>
  )
}
