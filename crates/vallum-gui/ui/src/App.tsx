import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { ShieldOff } from "lucide-react"
import { Toaster } from "@/components/ui/sonner"
import {
  AddPeerDialog,
  ConfigDialog,
  DeviceDialog,
  EditPeerDialog,
  ExportBundleDialog,
  FinalizeButton,
  ImportBundleDialog,
  InviteDialog,
  KeygenButton,
  RemoveDialog,
  RotateDialog,
} from "@/components/PeerDialogs"
import { bytes, hasBridge, health, listInterfaces, onSnapshot, pingPeer, preflight, selectInterface, watchWindowState, type Health, type PingResult, type Preflight } from "@/lib/bridge"
import { LogsPanel, ServiceStrip, StoppedCard, useServiceState } from "@/components/Service"
import { egressVerdict, HealthPanel } from "@/components/Health"
import { verdictTone } from "@/lib/verdict"
import { PeerPalette } from "@/components/PeerPalette"
import { PlanPanel } from "@/components/Plan"
import { CopyButton } from "@/components/Copy"
import { FirstRun, SocketUnreadable } from "@/components/FirstRun"
import { Button } from "@/components/ui/button"
import { TopTalkers, type PeerRate } from "@/components/TopTalkers"
import { TrafficChart } from "@/components/TrafficChart"
import { Diamond, Panel, PanelTitle } from "@/components/ui/panel"
import { TrafficHistory, freshness, freshnessLabel, loadHistory, rateLabel, saveHistory, type Sample } from "@/lib/traffic"
import type { InterfaceEntry, Peer, Snapshot, SnapshotPayload } from "@/types"

// The console is the TUI's dashboard rendered in the webview: same vocabulary
// (◆ Vallum ) TUNNEL CONTROL, the semantic palette, traffic bars, the peer
// detail shape) but composed for a window instead of a terminal. The design
// rule: state first, then rate, then detail — each at its own size, so the eye
// lands on "is my tunnel up" before anything else. Where a value is absent the
// surface says so rather than rendering a plausible zero.

const FRESH_SEC = 5 * 60

// The console asks for a snapshot once a second, and the first answer lands in
// milliseconds. Three asks that carried no data is a socket with nothing behind
// it, not a page that is still loading — counted in asks rather than in seconds,
// so the answer does not move with the clock.
const SILENT_ATTEMPTS = 3

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

// The visible peer order, in one place: the list and the j/k handler share
// it, so the keyboard moves through exactly what the eye sees.
function orderPeers(peers: Peer[], filter: string, sort: SortOrder): Peer[] {
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
}
/** Geek-free labels for the sort control: "epoch" is the daemon's key version. */
const SORT_LABELS: Record<SortOrder, string> = {
  handshake: "Last activity",
  name: "Name",
  epoch: "Key version",
}

const freshnessTone: Record<string, string> = {
  never: "text-muted-foreground",
  recent: "text-live",
  aging: "text-stale",
  old: "text-fault",
}

function anyPeerUp(data: Snapshot | null, now: number): boolean {
  return (
    data?.peers.some(
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
  data,
  now,
  history,
  samples,
  health,
  live,
  seen,
  attempts,
  replyAge,
  socket,
  error,
}: {
  data: Snapshot | null
  now: number
  history: TrafficHistory
  samples: Sample[]
  health: Health | null
  /** The daemon answered the most recent poll. */
  live: boolean
  /** A snapshot arrived at some point: an absent one is a disconnect, not a cold start. */
  seen: boolean
  /** How many snapshots the console has asked for since the page opened. */
  attempts: number
  /** Seconds since the daemon last sent data — not since the last frame. */
  replyAge: number | null
  socket: string
  error: string | null
}) {
  const up = anyPeerUp(data, now)
  // A socket in the runtime directory with nothing answering it is a stale file,
  // a daemon that died, or a permission this user does not have. "…" is the one
  // thing the focal point must not say, because all three have the same next
  // step and none of them is "wait longer".
  const silent = !seen && attempts >= SILENT_ATTEMPTS
  // Data still on screen that has stopped arriving is retained, and says so. The
  // TUI has said "showing retained snapshot" since it had a socket to lose; a
  // console that keeps painting a dead tunnel in the live colours is worse than
  // one that shows less.
  const lost = seen && !live
  const handshake = data?.peers
    .map((p) => p.last_handshake_sec)
    .filter((s) => s > 0)
    .sort((a, b) => b - a)[0]
  const rx = history.rate("rx")
  const tx = history.rate("tx")
  const last = samples.at(-1) ?? { rx: 0, tx: 0 }
  // One derivation per render: the headline, its tone and its tooltip all read
  // this value.
  const verdict = health ? egressVerdict(health) : null
  const tone = silent ? "text-fault" : verdictTone[verdict?.tone ?? "muted"]

  return (
    <section className="surface-raised rounded-lg px-5 py-4">
      <div className="flex flex-wrap items-end justify-between gap-x-10 gap-y-4">
        <div className="flex flex-col gap-1">
          {/* One glance must answer "am I protected?" — so the headline IS the
              derived verdict, not a mechanism word the user has to combine
              with a second badge. Usability spec: <=2 s, no scrolling. */}
          <PanelTitle>PROTECTION</PanelTitle>
          <span
            className={`text-3xl leading-none font-semibold tracking-tight ${tone}`}
            title={silent ? `nothing answers ${socket || "the control socket"}` : verdict?.detail}
          >
            {silent ? "NO DAEMON" : verdict ? verdict.label : "…"}
          </span>
          <span className="text-muted-foreground text-xs">
            {silent ? "the control socket has nothing behind it" : `tunnel ${up ? "up" : data ? "idle" : "…"}`}
          </span>
          {!silent && (
          <span className="text-muted-foreground mt-0.5 text-xs">
            {data ? (
              <>
                {data.interface} · {data.addresses.join(" · ")} ·{" "}
                {handshake ? `established ${Math.max(0, now - handshake)}s ago` : "no session yet"}
              </>
            ) : seen ? (
              "no snapshot since the disconnect"
            ) : (
              "waiting for the daemon's first snapshot"
            )}
            <span className={live ? "text-live" : "text-muted-foreground"}>
              {" "}
              · control {live ? "live" : seen ? "silent" : "—"}
            </span>
          </span>
          )}
        </div>

        <div className="flex items-end gap-8">
          {(
            [
              ["DOWNLOAD", rx, last.rx, "signal"] as const,
              ["UPLOAD", tx, last.tx, "violet"] as const,
            ]
          ).map(([label, rate, total, tone]) => (
            <div key={label} className="flex flex-col gap-1">
              <span className={`micro ${tone === "signal" ? "text-signal/80" : "text-violet/80"}`}>
                <span aria-hidden>{tone === "signal" ? "▼ " : "▲ "}</span>
                {label}
              </span>
              <span
                className={`text-2xl leading-none font-medium tracking-tight ${
                  tone === "signal" ? "text-signal" : "text-violet"
                }`}
              >
                {/* A rate is a measurement of now: where there is no now — no
                    snapshot yet, or a retained one — 0.0 B/s would be a number the
                    console does not have. The totals beside it are the last ones
                    the daemon sent, which the note above the panel explains. */}
                {live ? rateLabel(rate) : "—"}
              </span>
              <span className="text-muted-foreground text-xs">
                total {seen ? bytes(total) : "—"}
              </span>
            </div>
          ))}
        </div>
      </div>
      {lost && (
        <p className="text-stale mt-2 text-xs">
          the daemon is not answering — everything below is the last snapshot it sent
          {replyAge !== null ? `, ${replyAge}s ago` : ""}, kept on screen rather than
          blanked. Writes stay disabled until it answers.
        </p>
      )}
      {silent && (
        <p className="text-fault mt-2 text-xs">
          a socket is here but nothing answers it{socket ? `: ${socket}` : ""} — start the tunnel
          with START above, or read its own log for why it is not running.
        </p>
      )}
      {error && (
        <p className={`mt-1 text-xs ${live ? "text-fault" : "text-muted-foreground"}`}>
          {live ? "daemon" : "last control error"}: {error}
        </p>
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
  stale,
  live,
}: {
  peers: Peer[]
  now: number
  selected: string | null
  onSelect: (fingerprint: string) => void
  actions?: React.ReactNode
  filter: string
  onFilter: (value: string) => void
  sort: SortOrder
  onSort: (next: SortOrder) => void
  /** The list is the last one the daemon sent, not a live one. */
  stale: boolean
  /** The daemon is answering now. */
  live: boolean
}) {
  const shown = useMemo(() => orderPeers(peers, filter, sort), [peers, filter, sort])
  const unknown = !live && !stale

  return (
    <Panel
      title={
        <>
          PEERS [<span className="text-foreground">{shown.length}</span>]
          {shown.length !== peers.length && (
            <span className="text-muted-foreground">/{peers.length}</span>
          )}
          {stale && (
            <span
              className="text-stale"
              title="the daemon is not answering — this is the last list it sent"
            >
              {" "}
              · stale
            </span>
          )}
        </>
      }
      right={
        <span className="flex items-center gap-1.5">
          <label className="micro flex items-center gap-1">
            <span>sort</span>
            <select
              value={sort}
              onChange={(event) => onSort(event.target.value as SortOrder)}
              className="bg-background/40 border-border/70 text-foreground cursor-pointer rounded border px-1 py-0.5"
              title="sort peers (o cycles the order)"
              aria-label="sort peers"
            >
              {(Object.keys(SORT_LABELS) as SortOrder[]).map((key) => (
                <option key={key} value={key}>
                  {SORT_LABELS[key]}
                </option>
              ))}
            </select>
          </label>
          {actions}
        </span>
      }
      className="min-w-0"
    >
      <div className="mb-2 flex items-center gap-2">
        <label htmlFor="peer-filter" className="micro sr-only">
          Filter peers
        </label>
        <input
          id="peer-filter"
          value={filter}
          onChange={(event) => onFilter(event.target.value)}
          placeholder="Filter peers by name or IP…"            className="border-border/60 bg-background/40 text-foreground placeholder:text-muted-foreground/70 w-full rounded-md border px-2 py-1 text-xs"
          aria-label="filter peers by name or IP"
        />
      </div>
      {peers.length === 0 ? (
        <p className="text-muted-foreground py-3 text-xs">
          {unknown ? (
            <>no peer list yet — nothing is answering the control socket.</>
          ) : stale ? (
            <>
              no peer list to show — the daemon is not answering, and the last snapshot it sent had
              none.
            </>
          ) : (
            <>
              no peers yet — <span className="text-foreground/80">+ add peer</span> above mints
              the first one, or <span className="text-foreground/80">invite</span> hands a ticket to
              a device.
            </>
          )}
        </p>
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
                  className={`flex w-full cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-left transition-[background-color,color] duration-150 ${
                    isSelected ? "bg-secondary text-foreground" : "hover:bg-secondary/50"
                  }`}
                >
                  <span aria-hidden className={isSelected ? "text-signal text-[8px]" : "text-transparent text-[8px]"}>
                    ●
                  </span>
                  <span className="min-w-0 flex-1 truncate">{peer.name}</span>
                  {peer.rotating && (
                    <span className="text-violet text-xs">rotating</span>
                  )}
                  <span className={`text-xs uppercase ${tone}`}>
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
  unknown,
}: {
  peer: Peer | null
  now: number
  blocked?: string
  /** Nothing has arrived from the daemon yet: there is no list to step through. */
  unknown?: boolean
}) {
  const [probe, setProbe] = useState<PingResult | null>(null)
  const [probing, setProbing] = useState(false)
  if (!peer) {
    return (
      <Panel title="PEER DETAIL">
        <p className="text-muted-foreground py-3 text-xs">
          {unknown ? (
            "no peer data — the control socket has not answered yet."
          ) : (
            <>
              select a peer — <span className="text-foreground/80">j</span>/
              <span className="text-foreground/80">k</span> steps through the list, or{" "}
              <span className="text-foreground/80">:</span> runs any command by name.
            </>
          )}
        </p>
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
          <span className="text-foreground/90">peer · {peer.name}</span>
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
          id="ping-peer-btn"
          size="sm"
          variant="outline"
          className="h-7 px-2.5 text-xs uppercase"
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
        <CopyButton id="copy-line-btn" value={peer.public_line} label="copy line" title="copy this peer's public line" />
        <CopyButton id="copy-address-btn" value={peer.allowed_ips.join(", ") || peer.endpoint} label="copy address" title="copy this peer's address (allowed IPs, else its endpoint)" disabled={peer.allowed_ips.length === 0 && peer.endpoint === ""} />
        <ExportBundleDialog peer={peer} blocked={blocked} />
        <EditPeerDialog peer={peer} blocked={blocked} />
        <RotateDialog peer={peer} blocked={blocked} />
        {peer.rotating && <FinalizeButton peer={peer} blocked={blocked} />}
        <span className="border-border/60 mx-1 h-4 border-l" aria-hidden />
        <RemoveDialog peer={peer} blocked={blocked} />
      </div>
      {probe && (
        <p className={`text-xs ${probe.received ? "text-live" : "text-fault"}`}>
          {probe.error
            ? probe.error
            : `${probe.received ?? 0}/${probe.sent ?? 0} replies from ${probe.address}${
                probe.avg_ms ? ` · ${Number(probe.avg_ms).toFixed(1)} ms avg` : ""
              }`}
        </p>
      )}
      <Row label="fingerprint">{peer.fingerprint}</Row>
      <Row label="endpoint">{peer.endpoint || "roaming"}</Row>
      <Row label="allowed IPs">{peer.allowed_ips.join(", ")}</Row>
      <Row label="keepalive">{peer.keepalive !== null ? `${peer.keepalive}s` : "—"}</Row>
      <Row label="transfer">
        {bytes(peer.rx_bytes)} received / {bytes(peer.tx_bytes)} sent
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
      <Row label="key version">{peer.epoch}</Row>
    </Panel>
  )
}

function InterfaceData({ payload }: { payload: SnapshotPayload | null }) {
  const c = payload?.data?.counters
  const failures =
    (c?.datagrams_failed ?? 0) + (c?.packets_failed ?? 0) + (c?.refusals ?? 0)
  // Healthy counters stay collapsed: the summary line keeps the totals
  // glanceable while the per-kind breakdown waits on demand. Failures flip
  // the key, remounting open so the problem cannot sit hidden; user toggles
  // in between are left alone (uncontrolled details).
  const attention = failures > 0
  const metric = (label: string, primary: string, secondary: React.ReactNode) => (
    <div className="flex flex-col">
      <span className="micro">{label}</span>
      <span>{primary}</span>
      <span className="text-muted-foreground text-xs">{secondary}</span>
    </div>
  )
  return (
    <details
      key={attention ? "attention" : "healthy"}
      open={attention}
      className="surface rounded-lg"
    >
      <summary className="flex cursor-pointer items-center justify-between gap-2 px-4 pt-3 pb-1 select-none">
        <span className="flex items-center gap-1.5">
          <Diamond />
          <span className="text-signal text-xs font-semibold tracking-wide">
            INTERFACE DETAILS
          </span>
        </span>
        <span className="text-muted-foreground text-xs">
          {c ? (
            <>
              {c.datagrams_sent.toLocaleString()} out · {c.packets_delivered.toLocaleString()} in
              {attention && <span className="text-fault"> · {failures} failed</span>}
            </>
          ) : (
            "…"
          )}
        </span>
      </summary>
      <div className="px-4 pb-3.5">
      <div className="grid grid-cols-1 gap-x-6 gap-y-2 pt-1 sm:grid-cols-3">
        {metric(
          "sent",
          `sent ${c ? c.datagrams_sent.toLocaleString() : "—"}`,
          <span className={c && c.datagrams_failed > 0 ? "text-fault" : ""}>
            failed {c?.datagrams_failed ?? "—"}
          </span>,
        )}
        {metric(
          "received",
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
      </div>
    </details>
  )
}

function NoBridge() {
  return (
    <section className="surface rounded-lg">
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
  const [palette, setPalette] = useState(false)
  const [comfortable, setComfortable] = useState(() => {
    try {
      return window.localStorage.getItem("vallum.comfortable") === "1"
    } catch {
      return false
    }
  })
  useEffect(() => {
    try {
      window.localStorage.setItem("vallum.comfortable", comfortable ? "1" : "0")
    } catch {
      /* a disabled store is not worth failing a render over */
    }
  }, [comfortable])
  const [facts, setFacts] = useState<Preflight | null>(null)
  const [interfaces, setInterfaces] = useState<InterfaceEntry[]>([])
  const [payload, setPayload] = useState<SnapshotPayload | null>(null)
  // The last answer the daemon actually gave. A disconnect keeps it on screen,
  // marked, instead of blanking the cockpit into "nothing is configured".
  const [retained, setRetained] = useState<SnapshotPayload | null>(null)
  const [samples, setSamples] = useState<Sample[]>([])
  const [peerRates, setPeerRates] = useState<PeerRate[]>([])
  const prevPeers = useRef(new Map<string, { rx: number; tx: number; at: number }>())
  const [selectedPeer, setSelectedPeer] = useState<string | null>(null)
  // When the daemon last answered with data — not when a frame last arrived.
  // Error frames keep coming every second, and a clock they reset would say
  // "just now" about a snapshot that stopped an hour ago.
  const [lastUpdate, setLastUpdate] = useState<number | null>(null)
  const history = useRef(new TrafficHistory())
  const now = useLiveClock()
  // How many snapshots have been asked for. A socket file with nothing behind it
  // and a daemon one poll behind look identical for a moment, and the count is
  // what tells them apart without waiting on a clock.
  const [attempts, setAttempts] = useState(0)

  useEffect(() => watchWindowState(), [])

  // The palette's own chord: Cmd/Ctrl+K toggles peer search from anywhere.
  // Single-letter shortcuts stay parked behind the typing/dialog guards in
  // the main handler; this chord is reserved and never collides with them.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault()
        setPalette((open) => !open)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  // What is installed here, read once: it decides whether the console offers a
  // start button or an install step. A helper that cannot answer is a state of
  // its own — not a bare machine — so it is worth retrying.
  const loadFacts = useCallback(() => {
    preflight()
      .then(setFacts)
      .catch(() => setFacts(null))
  }, [])
  useEffect(() => {
    void loadFacts()
  }, [loadFacts])

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

    const onKey = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return
      if (event.key === "Escape") {
        // Clearing the peer filter from inside a dialog (or while typing in
        // any other field) destroys input the operator did not mean to lose.
        if (dialogOpen()) return
        const focused = event.target as HTMLElement | null
        if (typing(event.target) && focused?.id !== "peer-filter") return
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
      // Single letters never fire here. A global letter is a loaded key: it
      // can trigger from anywhere the guard misses, and a destructive verb on
      // one is a disaster waiting to happen. Letters live in the palette,
      // which is modal, explicit, and closes on Esc — the only globals are
      // punctuation and navigation, which cannot collide with typing.
      switch (event.key) {
        case "/":
          event.preventDefault()
          document.getElementById("peer-filter")?.focus()
          break
        case ":":
          // The TUI's dispatch key: `:` opens the command palette, like the
          // brandkit's `: commands` pill. Typing and dialogs are guarded
          // above, so this never fires mid-typing.
          event.preventDefault()
          setPalette(true)
          break
        case "Tab":
          event.preventDefault()
          switchRef.current()
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
    setAttempts((count) => count + 1)
    if (payload.data) {
      setRetained(payload)
      setLastUpdate(Date.now() / 1000)
    }
    if (payload.data) {
      const at = Date.now()
      const rx = payload.data.peers.reduce((sum, p) => sum + p.rx_bytes, 0)
      const tx = payload.data.peers.reduce((sum, p) => sum + p.tx_bytes, 0)
      history.current.push(rx, tx, at, payload.data.counters.established)
      setSamples([...history.current.recent()])
      if (payload.data?.interface) saveHistory(payload.data.interface, history.current.recent())
      // Per-peer rates need two snapshots; the first visit only seeds the baseline.
      const rates: PeerRate[] = []
      const next = new Map<string, { rx: number; tx: number; at: number }>()
      for (const peer of payload.data.peers) {
        next.set(peer.fingerprint, { rx: peer.rx_bytes, tx: peer.tx_bytes, at })
        const prev = prevPeers.current.get(peer.fingerprint)
        if (!prev) continue
        const dt = (at - prev.at) / 1000
        if (dt <= 0) continue
        const peerRx = Math.max(0, peer.rx_bytes - prev.rx) / dt
        const peerTx = Math.max(0, peer.tx_bytes - prev.tx) / dt
        if (peerRx > 0 || peerTx > 0) rates.push({ name: peer.name, rx: peerRx, tx: peerTx })
      }
      prevPeers.current = next
      rates.sort((a, b) => b.rx + b.tx - (a.rx + a.tx))
      setPeerRates(rates)
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

  const live = payload?.ok === true
  // Data has arrived at some point: a failure frame with no data behind it is a
  // daemon that never answered, not one that stopped.
  const seen = retained !== null
  // What the daemon last said, when it is no longer saying anything: the panels
  // keep their content and the labels say which it is.
  const data = payload?.data ?? retained?.data ?? null
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
    setRetained(null)
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
  // Retained data cannot be written to: the daemon is not there to write to, and
  // a form that opens over a dead socket fails only after the operator has typed
  // into it.
  const blocked = live
    ? undefined
    : seen
      ? "the daemon is not answering — this is the last snapshot it sent"
      : "waiting for the daemon's first snapshot"
  const replyAge = lastUpdate !== null ? Math.max(0, now - Math.floor(lastUpdate)) : null
  const lastReply = replyAge === null ? "—" : replyAge < 1 ? "live" : `${replyAge}s ago`

  return (
    <div className={`mx-auto flex min-h-svh max-w-6xl flex-col gap-3 p-4 ${comfortable ? "comfortable" : ""}`}>
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 px-1">
        <PanelTitle>
          <span className="text-foreground">Vallum ❯ </span>TUNNEL CONTROL
        </PanelTitle>
        {interfaces.length > 0 &&
          (interfaces.length === 1 ? (
            <span className="text-subtext text-xs">[1/1] {currentName}</span>
          ) : (
            <label className="text-subtext flex items-center gap-1 text-xs">
              <span aria-hidden>
                [{currentIndex + 1}/{interfaces.length}]
              </span>
              <select
                value={currentName}
                onChange={(event) => {
                  const next = interfaces.find((entry) => entry.name === event.target.value)
                  if (!next || next.name === currentName) return
                  setSelectedPeer(null)
                  setPayload(null)
                  setRetained(null)
                  void selectInterface(next.path)
                }}
                className="bg-background/40 border-border/70 text-foreground h-7 cursor-pointer rounded border px-1"
                title="switch interface (tab cycles)"
                aria-label="switch interface"
              >
                {interfaces.map((entry) => (
                  <option key={entry.path} value={entry.name}>
                    {entry.name}
                  </option>
                ))}
              </select>
            </label>
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
            <ServiceStrip service={service} onChanged={refreshService} attached={Boolean(payload?.ok)} />
          )}
          <DeviceDialog
            listenPort={data?.listen_port ?? null}
            fwmark={data?.fwmark ?? null}
            blocked={blocked}
          />
          <ConfigDialog blocked={blocked} />
          {data && (
            <>
              <span className="text-muted-foreground" title={`suite ${data.suite} · fwmark ${data.fwmark ?? 0}`}>
                listen{" "}
                <span className="text-foreground/80">
                  {data.listen_port !== null ? `:${data.listen_port}` : "—"}
                </span>
                <span className="text-muted-foreground"> · {data.suite}</span>
              </span>
              <span className="text-muted-foreground">
                id <span className="text-foreground/80">{data.fingerprint.slice(0, 16)}</span>
                <span className="ml-1.5 inline-block">
                  <CopyButton value={data.public_line} label="copy" title="copy this device's public line" />
                </span>
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
        <FirstRun facts={facts} onRetry={loadFacts} />
      ) : service && service.active !== "active" && !live ? (
        // The unit being down is only the reason the cockpit is empty when the
        // daemon is also unreachable. A daemon can answer with no unit behind it
        // (a lab, a hand-run process), and hiding a live tunnel because systemd
        // has never heard of it is the console lying in the wrong direction.
        <StoppedCard service={service} onChanged={refreshService} />
      ) : interfaces.length === 0 ? (
        // A socket the installer created and this user cannot open is the other
        // reason for an empty list, and it is not the bare machine FirstRun
        // describes: there the steps are the news, here they are a misdiagnosis.
        facts && facts.sockets > 0 ? (
          <SocketUnreadable facts={facts} onRetry={loadFacts} />
        ) : (
          <FirstRun facts={facts} onRetry={loadFacts} />
        )
      ) : (
        <>
          <Hero
            data={data}
            now={now}
            history={history.current}
            samples={samples}
            health={hostHealth}
            live={live}
            seen={seen}
            attempts={attempts}
            replyAge={replyAge}
            socket={interfaces[currentIndex]?.path ?? ""}
            error={payload?.error ?? null}
          />
          {/* Task grouping, not tabs: overview first, then zoom/filter, then
              details on demand. Status answers "am I protected?" at a glance;
              peers are the workbench (list + detail stay together so nothing
              must be held in memory across the screen); system holds the rare,
              dangerous changes. No tab hides another task's state. */}
          <section aria-label="Status">
            <p className="micro px-1 pt-1 pb-1">STATUS — IS TRAFFIC PROTECTED?</p>
            <div className="flex flex-col gap-3 lg:flex-row">
              <div className="min-w-0 flex-[3]">
                <Panel title="THROUGHPUT">
                  <TrafficChart samples={samples} />
                  <TopTalkers rates={peerRates} />
                </Panel>
              </div>
              <div className="min-w-0 flex-[2]">
                <HealthPanel health={hostHealth} stale={!live} />
              </div>
            </div>
          </section>
          <section aria-label="Peers">
            <p className="micro px-1 pt-1 pb-1">PEERS — WHO CAN CONNECT</p>
            <div className="flex flex-col gap-3 md:flex-row">
              <div className="min-w-0 flex-1">
                <PeersPanel
                  peers={data?.peers ?? []}
                  now={now}
                  selected={selectedPeer}
                  onSelect={setSelectedPeer}
                  filter={filter}
                  onFilter={setFilter}
                  sort={sort}
                  onSort={setSort}
                  stale={seen && !live}
                  live={live}
                  actions={
                    <span className="flex gap-1.5">
                      <Button
                        variant="outline"
                        size="sm"
                        className="micro uppercase"
                        onClick={() => setPalette(true)}
                        title="command palette: verbs and peers in one box (: opens it, ⌘K works too)"
                      >
                        : commands
                      </Button>
                      <InviteDialog blocked={blocked} />
                      <ImportBundleDialog blocked={blocked} />
                      <KeygenButton blocked={blocked} />
                      <AddPeerDialog blocked={blocked} peers={data?.peers ?? []} />
                    </span>
                  }
                />
              </div>
              <div className="flex flex-col gap-3 md:w-[320px] md:shrink-0">
                <PeerDetail peer={detail} now={now} blocked={blocked} unknown={!seen} />
              </div>
            </div>
          </section>
          <section aria-label="System">
            <p className="micro px-1 pt-1 pb-1">SYSTEM — RARELY CHANGED</p>
            <div className="flex flex-col gap-3">
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                <InterfaceData payload={payload} />
                <PlanPanel onChanged={() => setHostHealth(null)} />
              </div>
              <LogsPanel />
            </div>
          </section>
          <footer className="text-muted-foreground flex items-center gap-2 px-1 text-xs">
            <span>{lastReply === "live" ? "snapshot live" : lastReply === "—" ? "waiting for snapshot" : `snapshot updated ${lastReply}`}</span>
            <span>·</span>
            <span>snapshot stream</span>
            <span>·</span>
            <button
              onClick={() => setComfortable((c) => !c)}
              className="hover:text-foreground cursor-pointer rounded uppercase"
              title="Text size: comfortable raises controls and text above minimum touch targets"
            >
              text size: {comfortable ? "comfortable" : "compact"}
            </button>
            <span>·</span>
            <button
              onClick={() => setShortcuts(true)}
              className="hover:text-foreground cursor-pointer rounded uppercase"
              title="Keyboard shortcuts (?) — experts keep their speed without forcing novices to memorize"
            >
              shortcuts
            </button>
          </footer>
        </>
      )}

      <PeerPalette
        open={palette}
        onOpenChange={setPalette}
        peers={data?.peers ?? []}
        now={now}
        selected={selectedPeer}
        selectedRotating={detail?.rotating ?? false}
        onSelect={setSelectedPeer}
        onCycleSort={() =>
          setSort((current) => SORT_CYCLE[(SORT_CYCLE.indexOf(current) + 1) % SORT_CYCLE.length])
        }
      />

      {shortcuts && (
        <div
          role="dialog"
          aria-label="keyboard shortcuts"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
          onClick={() => setShortcuts(false)}
        >            <div
              className="surface-raised w-full max-w-sm rounded-xl p-5"
              onClick={(event) => event.stopPropagation()}
            >
            <p className="text-signal mb-3 text-xs font-semibold tracking-wide uppercase">
              keyboard
            </p>
            <dl className="grid grid-cols-[3rem_1fr] gap-x-3 gap-y-1.5 text-xs">
              {[
                ["/", "filter peers"],
                [":", "command palette — every action lives here"],
                ["⌘K", "command palette (alias)"],
                ["Tab", "next interface"],
                ["esc", "clear the peer filter"],
                ["?", "this list"],
              ].map(([key, meaning]) => (
                <div key={key} className="contents">
                  <dt className="text-foreground/80 font-mono">{key}</dt>
                  <dd className="text-muted-foreground">{meaning}</dd>
                </div>
              ))}
            </dl>
            <p className="text-muted-foreground mt-3 text-xs">
              Peer, service, and device actions live in the palette — press : and type.
            </p>
          </div>
        </div>
      )}
      {/* The console is unconditionally dark (see index.css) and mounts no
          ThemeProvider, so sonner's `system` default would follow the OS and
          paint light toasts on a dark cockpit. Pin dark. */}
      <Toaster position="bottom-right" theme="dark" />
    </div>
  )
}
