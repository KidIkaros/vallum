import { useEffect, useMemo, useRef, useState } from "react"
import { ShieldOff } from "lucide-react"
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
import { bytes, hasBridge, health, listInterfaces, onSnapshot, pingPeer, preflight, selectInterface, watchWindowState, type Health, type PingResult, type Preflight } from "@/lib/bridge"
import { LogsPanel, ServiceStrip, StoppedCard, useServiceState } from "@/components/Service"
import { EgressBadge, HealthPanel, PanicButton } from "@/components/Health"
import { CopyButton } from "@/components/Copy"
import { FirstRun } from "@/components/FirstRun"
import { Button } from "@/components/ui/button"
import { TrafficChart } from "@/components/TrafficChart"
import { Panel, PanelTitle } from "@/components/ui/panel"
import { TrafficHistory, freshness, freshnessLabel, loadHistory, rateLabel, saveHistory, type Sample } from "@/lib/traffic"
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

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col py-0.5">
      <span className="micro">{label}</span>
      <span className="text-foreground/90 min-w-0 break-words">{children}</span>
    </div>
  )
}

type SortOrder = "handshake" | "name" | "epoch"
const SORT_CYCLE: SortOrder[] = ["handshake", "name", "epoch"]

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
  health,
}: {
  payload: SnapshotPayload | null
  now: number
  history: TrafficHistory
  samples: Sample[]
  lastReply: string
  health: Health | null
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
          <EgressBadge health={health} />
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
  filter,
  onFilter,
  sort,
  onSort,
}: {
  peers: Peer[]
  now: number
  selected: string | null
  onSelect: (fingerprint: string) => void
  actions?: React.ReactNode
  filter: string
  onFilter: (value: string) => void
  sort: SortOrder
  onSort: () => void
}) {
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    const matching = needle
      ? peers.filter(
          (peer) =>
            peer.name.toLowerCase().includes(needle) ||
            peer.allowed_ips.some((ip) => ip.includes(needle)),
        )
      : peers
    const order = [...matching]
    if (sort === "name") order.sort((a, b) => a.name.localeCompare(b.name))
    else if (sort === "epoch") order.sort((a, b) => b.epoch - a.epoch)
    else order.sort((a, b) => b.last_handshake_sec - a.last_handshake_sec)
    return order
  }, [peers, filter, sort])

  return (
    <Panel
      title={
        <>
          PEERS [<span className="text-foreground">{shown.length}</span>]
          {shown.length !== peers.length && (
            <span className="text-muted-foreground">/{peers.length}</span>
          )}
        </>
      }
      right={
        <span className="flex items-center gap-1.5">
          <button
            onClick={onSort}
            className="micro hover:text-foreground cursor-pointer rounded px-1 py-0.5 uppercase"
            title="cycle sort: handshake → name → epoch (o)"
          >
            sort {sort}
          </button>
          {actions}
        </span>
      }
      className="min-w-0"
    >
      <div className="mb-2 flex items-center gap-2">
        <input
          id="peer-filter"
          value={filter}
          onChange={(event) => onFilter(event.target.value)}
          placeholder="filter by name or address   ( / )"
          className="border-border/70 bg-background/40 text-foreground placeholder:text-muted-foreground/70 focus-visible:ring-signal w-full rounded-md border px-2 py-1 text-[11px] focus-visible:ring-1 focus-visible:outline-none"
          aria-label="filter peers"
        />
      </div>
      {peers.length === 0 ? (
        <p className="text-muted-foreground py-3 text-xs">no peers configured</p>
      ) : shown.length === 0 ? (
        <p className="text-muted-foreground py-3 text-xs">nothing matches “{filter}”</p>
      ) : (
        <ul className="flex flex-col">
          {shown.map((peer) => {
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
                  <span className={`text-[10px] uppercase ${tone}`}>
                    {freshnessLabel[f]}
                    {peer.last_handshake_sec > 0 && (
                      <span className="text-muted-foreground"> {Math.max(0, now - peer.last_handshake_sec)}s</span>
                    )}
                  </span>
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
  const [probe, setProbe] = useState<PingResult | null>(null)
  const [probing, setProbing] = useState(false)
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
        <Button
          size="sm"
          variant="outline"
          className="h-6 px-2 text-[10px] uppercase"
          disabled={probing || peer.allowed_ips.length === 0}
          title={`ping ${peer.allowed_ips[0] ?? "the peer"}`}
          onClick={() => {
            // allowed_ips holds CIDRs; ping wants an address.
            const target = peer.allowed_ips[0]?.split("/")[0]
            if (!target) return
            setProbing(true)
            pingPeer(target)
              .then(setProbe)
              .catch((error: unknown) =>
                setProbe({ address: target, error: String(error) }),
              )
              .finally(() => setProbing(false))
          }}
        >
          {probing ? "…" : "ping"}
        </Button>
        <CopyButton value={peer.public_line} label="copy line" title="copy this peer's public line" />
        <EditPeerDialog peer={peer} blocked={blocked} />
        <RotateDialog peer={peer} blocked={blocked} />
        {peer.rotating && <FinalizeButton peer={peer} blocked={blocked} />}
        <RemoveDialog peer={peer} blocked={blocked} />
      </div>
      {probe && (
        <p className={`text-[11px] ${probe.received ? "text-live" : "text-fault"}`}>
          {probe.error
            ? probe.error
            : `${probe.received ?? 0}/${probe.sent ?? 0} replies from ${probe.address}${
                probe.avg_ms ? ` · ${Number(probe.avg_ms).toFixed(1)} ms avg` : ""
              }`}
        </p>
      )}
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
          "datagrams · outer",
          `sent ${c ? c.datagrams_sent.toLocaleString() : "—"}`,
          <span className={c && c.datagrams_failed > 0 ? "text-fault" : ""}>
            failed {c?.datagrams_failed ?? "—"}
          </span>,
        )}
        {metric(
          "packets · inner",
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


export default function App() {
  const inApp = useMemo(() => hasBridge, [])
  const { service, refresh: refreshService } = useServiceState(inApp)
  const [hostHealth, setHostHealth] = useState<Health | null>(null)
  const [filter, setFilter] = useState("")
  const [sort, setSort] = useState<SortOrder>("handshake")
  const [shortcuts, setShortcuts] = useState(false)
  const [facts, setFacts] = useState<Preflight | null>(null)
  const [interfaces, setInterfaces] = useState<InterfaceEntry[]>([])
  const [payload, setPayload] = useState<SnapshotPayload | null>(null)
  const [samples, setSamples] = useState<Sample[]>([])
  const [selectedPeer, setSelectedPeer] = useState<string | null>(null)
  const [lastUpdate, setLastUpdate] = useState<number | null>(null)
  const history = useRef(new TrafficHistory())
  const now = useLiveClock()

  useEffect(() => watchWindowState(), [])

  // What is installed here, read once: it decides whether the console offers a
  // start button or an install step.
  useEffect(() => {
    preflight()
      .then(setFacts)
      .catch(() => setFacts(null))
  }, [])

  // The TUI's keys, as far as the console has actions for them. Deliberately
  // suppressed while a field has focus or a dialog is open: a shortcut that
  // fires mid-typing is worse than no shortcut.
  useEffect(() => {
    const typing = (target: EventTarget | null) => {
      const element = target as HTMLElement | null
      if (!element) return false
      const tag = element.tagName
      return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || element.isContentEditable
    }
    const dialogOpen = () => document.querySelector("[role=dialog]") !== null
    const click = (id: string) =>
      (document.getElementById(id) as HTMLButtonElement | null)?.click()

    const onKey = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return
      if (event.key === "Escape") {
        setFilter("")
        return
      }
      if (typing(event.target)) return
      if (event.key === "?") {
        event.preventDefault()
        setShortcuts((open) => !open)
        return
      }
      if (dialogOpen()) return
      switch (event.key) {
        case "a":
          event.preventDefault()
          click("add-peer-btn")
          break
        case "e":
          event.preventDefault()
          click("edit-peer-btn")
          break
        case "d":
          event.preventDefault()
          click("remove-peer-btn")
          break
        case "/":
          event.preventDefault()
          document.getElementById("peer-filter")?.focus()
          break
        case "Tab":
          event.preventDefault()
          switchRef.current()
          break
        case "o":
          event.preventDefault()
          setSort((current) => SORT_CYCLE[(SORT_CYCLE.indexOf(current) + 1) % SORT_CYCLE.length])
          break
        default:
          break
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  // Health is measured on the host every 5 s: route, v6, DNS, guard, restarts.
  useEffect(() => {
    if (!inApp) return
    let cancelled = false
    const load = () =>
      health()
        .then((value) => !cancelled && setHostHealth(value))
        .catch(() => !cancelled && setHostHealth(null))
    void load()
    const timer = window.setInterval(load, 5000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [inApp])

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
      if (payload.data?.interface) saveHistory(payload.data.interface, history.current.recent())
    }
  })
  const ingest = ingestRef.current

  useEffect(() => {
    if (!inApp) return
    let cancelled = false
    let bound = false
    const scan = () =>
      listInterfaces().then((entries) => {
        if (cancelled) return
        setInterfaces(entries)
        // The first socket is the daemon the operator most likely means; picking
        // it saves a click without hiding the others.
        if (!bound && entries.length > 0) {
          bound = true
          void selectInterface(entries[0].path)
        }
      })
    void scan()
    const timer = window.setInterval(scan, 5000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
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
  if (data?.interface && samples.length === 0) {
    const restored = loadHistory(data.interface)
    if (restored.length > 1) {
      history.current.restore(restored)
      setSamples([...history.current.recent()])
    }
  }
  const currentName = data?.interface ?? interfaces[0]?.name ?? ""
  const currentIndex = Math.max(
    0,
    interfaces.findIndex((entry) => entry.name === currentName),
  )
  const switchInterface = () => {
    if (interfaces.length < 2) return
    const next = interfaces[(currentIndex + 1) % interfaces.length]
    setSelectedPeer(null)
    setPayload(null)
    void selectInterface(next.path)
  }
  // The key handler is registered once; this keeps it pointed at the latest
  // interface list without re-binding on every snapshot.
  const switchRef = useRef(switchInterface)
  switchRef.current = switchInterface
  if (data && data.peers.length > 0 && selectedPeer === null) {
    setSelectedPeer(data.peers[0].fingerprint)
  }
  const detail = data?.peers.find((p) => p.fingerprint === selectedPeer) ?? null
  // Demo data cannot be written to: the daemon is not there to write to.
  const blocked = data ? undefined : "waiting for the daemon's first snapshot"
  const replyAge = lastUpdate !== null ? Math.max(0, now - Math.floor(lastUpdate)) : null
  const lastReply = replyAge === null ? "—" : replyAge < 1 ? "live" : `${replyAge}s`

  return (
    <div className="mx-auto flex min-h-svh max-w-6xl flex-col gap-3 p-4">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 px-1">
        <PanelTitle>
          <span className="text-foreground">Vallum ) </span>TUNNEL CONTROL
        </PanelTitle>
        {interfaces.length > 0 &&
          (interfaces.length === 1 ? (
            <span className="text-subtext text-xs">[1/1] {currentName}</span>
          ) : (
            <button
              onClick={switchInterface}
              className="text-subtext hover:text-foreground focus-visible:ring-signal cursor-pointer rounded px-1 text-xs focus-visible:ring-1 focus-visible:outline-none"
              title="switch interface (tab)"
            >
              [{currentIndex + 1}/{interfaces.length}] {currentName} ▾
            </button>
          ))}
        <span className="micro" title="the control socket answered">
          daemon{" "}
          <span className={payload?.ok ? "text-live" : "text-muted-foreground"}>
            {payload?.ok ? "attached" : "silent"}
          </span>
        </span>
        <div className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
          {facts?.unit === false ? (
            <span className="micro" title="nothing is installed on this host yet">
              not installed
            </span>
          ) : (
            <>
              <ServiceStrip service={service} onChanged={refreshService} />
              <PanicButton compact />
            </>
          )}
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
                <CopyButton value={data.public_line} label="copy" title="copy this device's public line" />
              </span>
            </>
          )}
        </div>
      </header>

      {!inApp ? (
        <NoBridge />
      ) : facts !== null &&
        !facts.unit &&
        interfaces.length === 0 ? (
        // Nothing installed: show what to run, not a start button for a unit
        // that does not exist.
        <FirstRun facts={facts} />
      ) : service && service.active !== "active" && !payload?.ok ? (
        // The unit being down is only the reason the cockpit is empty when the
        // daemon is also unreachable. A daemon can answer with no unit behind it
        // (a lab, a hand-run process), and hiding a live tunnel because systemd
        // has never heard of it is the console lying in the wrong direction.
        <StoppedCard service={service} onChanged={refreshService} />
      ) : interfaces.length === 0 ? (
        <FirstRun facts={facts} />
      ) : (
        <>
          <Hero
            payload={payload}
            now={now}
            history={history.current}
            samples={samples}
            lastReply={lastReply}
            health={hostHealth}
          />
          <Panel title="THROUGHPUT">
            <TrafficChart samples={samples} />
          </Panel>
          <div className="flex flex-col gap-3 md:flex-row">
            <div className="flex min-w-0 flex-1 flex-col gap-3">
              <PeersPanel
                peers={data?.peers ?? []}
                now={now}
                selected={selectedPeer}
                onSelect={setSelectedPeer}
                filter={filter}
                onFilter={setFilter}
                sort={sort}
                onSort={() =>
                  setSort((current) => SORT_CYCLE[(SORT_CYCLE.indexOf(current) + 1) % SORT_CYCLE.length])
                }
                actions={
                  <span className="flex gap-1.5">
                    <InviteDialog blocked={blocked} />
                    <AddPeerDialog blocked={blocked} peers={data?.peers ?? []} />
                  </span>
                }
              />
              <InterfaceData payload={payload} />
              <HealthPanel health={hostHealth} />
            </div>
            <div className="flex flex-col gap-3 md:w-[320px] md:shrink-0">
              <PeerDetail peer={detail} now={now} blocked={blocked} />
            </div>
          </div>
          <LogsPanel />
          <footer className="text-muted-foreground flex items-center gap-2 px-1 text-[10px]">
            <span>updated {lastReply}</span>
            <span>·</span>
            <span>snapshot stream</span>
          </footer>
        </>
      )}

      {shortcuts && (
        <div
          role="dialog"
          aria-label="keyboard shortcuts"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
          onClick={() => setShortcuts(false)}
        >
          <div
            className="bg-card border-border w-full max-w-sm rounded-lg border p-5"
            onClick={(event) => event.stopPropagation()}
          >
            <p className="text-signal mb-3 text-xs font-semibold tracking-wide uppercase">
              keyboard
            </p>
            <dl className="grid grid-cols-[3rem_1fr] gap-x-3 gap-y-1.5 text-xs">
              {[
                ["a", "add peer"],
                ["e", "edit the selected peer"],
                ["d", "remove the selected peer"],
                ["/", "filter peers"],
                ["o", "cycle sort order"],
                ["esc", "clear the filter"],
                ["?", "this list"],
              ].map(([key, meaning]) => (
                <div key={key} className="contents">
                  <dt className="text-foreground/80 font-mono">{key}</dt>
                  <dd className="text-muted-foreground">{meaning}</dd>
                </div>
              ))}
            </dl>
            <p className="text-muted-foreground mt-3 text-[10px]">
              Shortcuts are off while a field has focus.
            </p>
          </div>
        </div>
      )}
      <Toaster position="bottom-right" />
    </div>
  )
}
