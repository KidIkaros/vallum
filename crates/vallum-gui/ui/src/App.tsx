import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  Activity,
  BookOpen,
  KeyRound,
  LayoutGrid,
  ShieldCheck,
  ShieldOff,
  SlidersHorizontal,
  User,
  Users,
} from "lucide-react"
import { Toaster } from "@/components/ui/sonner"
import {
  AddPeerDialog,
  ConfigDialog,
  DeviceDialog,
  EditPeerDialog,
  ExportBundleDialog,
  FinalizeButton,
  ImportBundleDialog,
  InterfaceFormDialog,
  InviteDialog,
  KeygenButton,
  RemoveDialog,
  RotateDialog,
  SaveRuntimeButton,
} from "@/components/PeerDialogs"
import { bytes, hasBridge, health, listInterfaces, onSnapshot, pingPeer, preflight, selectInterface, serviceState, watchWindowState, type Health, type PingResult, type Preflight, type ServiceStatus } from "@/lib/bridge"
import { LogsPanel, ServiceStrip, StoppedCard } from "@/components/Service"
import { HealthPanel } from "@/components/Health"
import { NextSteps } from "@/components/NextSteps"
import { egressVerdict, verdictTone } from "@/lib/verdict"
import { formatError, suiteLabel } from "@/lib/validate"
import { BoundaryGeometry, CryptoArchitecture, RampartSeal } from "@/components/BrandVisuals"
import { DiagnosticCallout } from "@/components/DiagnosticCallout"
import { DiagnosticsModal, type DiagnosticsTab } from "@/components/DiagnosticsModal"
import { PeerPalette } from "@/components/PeerPalette"
import { matchDiagnostic } from "@/lib/diagnostics"
import { PlanPanel } from "@/components/Plan"
import { UserKeyCard, UserPreferencesPanel } from "@/components/UserIdentity"
import { ROLE_META, useUserPrefs } from "@/lib/userPrefs"
import { CopyButton } from "@/components/Copy"
import { FirstRun, SocketUnreadable } from "@/components/FirstRun"
import { JoinNetworkDialog, JoinUriBridge, SetupServerDialog } from "@/components/OnboardingDialogs"
import { Button } from "@/components/ui/button"
import { PacketPipelineFlow, TunnelFlowMap } from "@/components/DataFlow"
import { TopTalkers, type PeerRate } from "@/components/TopTalkers"
import { TrafficChart } from "@/components/TrafficChart"
import { Diamond, Panel } from "@/components/ui/panel"
import { TrafficHistory, formatAgeSec, freshness, freshnessLabel, loadHistory, rateLabel, sampleRate, saveHistory, type Sample } from "@/lib/traffic"
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

type SortOrder = "handshake" | "transfer" | "name" | "epoch"
const SORT_CYCLE: SortOrder[] = ["handshake", "transfer", "name", "epoch"]

// The visible peer order, in one place: the list and the j/k handler share
// it, so the keyboard moves through exactly what the eye sees.
function orderPeers(peers: Peer[], filter: string, sort: SortOrder): Peer[] {
  const needle = filter.trim().toLowerCase()
  const matching = needle
    ? peers.filter(
        (peer) =>
          peer.name.toLowerCase().includes(needle) ||
          peer.allowed_ips.some((ip) => ip.toLowerCase().includes(needle)) ||
          (peer.endpoint ?? "").toLowerCase().includes(needle) ||
          peer.fingerprint.toLowerCase().includes(needle),
      )
    : peers
  const order = [...matching]
  if (sort === "name") order.sort((a, b) => a.name.localeCompare(b.name))
  else if (sort === "epoch") order.sort((a, b) => b.epoch - a.epoch)
  else if (sort === "transfer") {
    order.sort((a, b) => b.rx_bytes + b.tx_bytes - (a.rx_bytes + a.tx_bytes))
  } else order.sort((a, b) => b.last_handshake_sec - a.last_handshake_sec)
  return order
}
/** Geek-free labels for the sort control: "epoch" is the daemon's key version. */
const SORT_LABELS: Record<SortOrder, string> = {
  handshake: "Activity",
  transfer: "Transfer",
  name: "Name",
  epoch: "Key",
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
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000))
  useEffect(() => {
    const timer = window.setInterval(
      () => setNow(Math.floor(Date.now() / 1000)),
      1000,
    )
    return () => window.clearInterval(timer)
  }, [])
  return now
}

/** State, rate, and freshness at three sizes — the screen's focal point. */
function Hero({
  data,
  now,
  samples,
  health,
  live,
  seen,
  booting,
  attempts,
  replyAge,
  socket,
  error,
  onOpenCatalog,
  onOpenUserKeys,
}: {
  data: Snapshot | null
  now: number
  samples: Sample[]
  health: Health | null
  /** The daemon answered the most recent poll. */
  live: boolean
  /** A snapshot arrived at some point: an absent one is a disconnect, not a cold start. */
  seen: boolean
  /** True before the first snapshot poll has landed. */
  booting: boolean
  /** How many snapshots the console has asked for since the page opened. */
  attempts: number
  /** Seconds since the daemon last sent data — not since the last frame. */
  replyAge: number | null
  socket: string
  error: string | null
  onOpenCatalog?: (code?: string) => void
  onOpenUserKeys?: () => void
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
  const rx = sampleRate(samples, "rx")
  const tx = sampleRate(samples, "tx")
  const last = samples.at(-1) ?? { rx: 0, tx: 0 }
  // One derivation per render: the headline, its tone and its tooltip all read
  // this value.
  const verdict = health ? egressVerdict(health) : null
  const tone = silent ? "text-fault" : verdictTone[verdict?.tone ?? "muted"]
  const visibleError =
    error && error !== "no interface selected" ? error : null
  // The one thing allowed to move forever: a live tunnel breathes. The dot
  // only renders while the daemon is answering with peers up, so a retained
  // snapshot never pulses in the live colour — and the reduced-motion guard
  // in index.css stills it for anyone who asks for less motion.
  const heartbeat = up && live && !silent
  const peersUp =
    data?.peers.filter((p) => p.last_handshake_sec > 0 && now - p.last_handshake_sec < FRESH_SEC).length ?? 0
  const beam =
    silent || verdict?.tone === "fault"
      ? "hero-beam-fault"
      : lost || verdict?.tone === "stale"
        ? "hero-beam-stale"
        : heartbeat || verdict?.tone === "live"
          ? "hero-beam-live"
          : ""

  return (
    <section className={`surface-raised ${beam} animate-in fade-in slide-in-from-bottom-2 rounded-xl px-5 py-4 duration-500`}>
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-4">
        <div className="flex min-w-[220px] flex-1 flex-col gap-1.5">
          <span className="micro">Protection</span>
          <div className="flex items-center gap-2.5">
            {heartbeat ? (
              <span className="relative flex size-2.5 shrink-0" aria-hidden="true">
                <span className="bg-live absolute inline-flex h-full w-full animate-ping rounded-full opacity-60" />
                <span className="bg-live relative inline-flex size-2.5 rounded-full" />
              </span>
            ) : (
              <Diamond />
            )}
            <span
              key={silent ? "silent" : (verdict?.label ?? (booting ? "connecting" : "…"))}
              className={`animate-in fade-in text-2xl leading-none font-bold tracking-tight uppercase duration-300 ${tone}`}
              title={silent ? `Nothing answers ${socket || "the control socket"}` : verdict?.detail}
            >
              {silent ? "Daemon unreachable" : verdict ? verdict.label : booting ? "Connecting…" : "…"}
            </span>
          </div>
          {!silent && (
            <span className="text-muted-foreground text-xs">
              {data ? (
                <>
                  {data.interface} · {data.addresses[0] ?? "no IP"} ·{" "}
                  {handshake ? `last handshake ${formatAgeSec(now - handshake)} ago` : "no handshake yet"}
                </>
              ) : seen ? (
                "Showing last snapshot — daemon silent"
              ) : (
                "Waiting for daemon snapshot"
              )}
            </span>
          )}
          <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px]">
            <span className="border-border bg-secondary/70 text-foreground rounded border px-2 py-0.5 font-medium uppercase">
              {data?.expected_egress === "full" || health?.expected_full ? "Full tunnel" : "Split tunnel"}
            </span>
            {data?.public_line && (
              <CopyButton value={data.public_line} label="Copy Public Key" title="Copy this device's public key line" />
            )}
            {onOpenUserKeys && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-8 gap-1.5 px-2.5 text-xs"
                onClick={onOpenUserKeys}
                title="View this device's public key QR, operator profile, and preferences"
              >
                <KeyRound className="text-signal size-3.5" aria-hidden />
                <span>User &amp; Keys</span>
              </Button>
            )}
          </div>
        </div>

        <BoundaryGeometry
          interfaceName={data?.interface ?? "vallum0"}
          address={data?.addresses[0] ?? "—"}
          suite={data?.suite ?? "0x0003"}
          verdictLabel={silent ? "UNREACHABLE" : verdict?.label ?? "IDLE"}
          tone={silent ? "fault" : (verdict?.tone ?? "muted")}
          peersUp={peersUp}
          totalPeers={data?.peers.length ?? 0}
          live={live}
        />

        <div className="flex items-end gap-7">
          {(
            [
              ["Download", rx, last.rx, "signal"] as const,
              ["Upload", tx, last.tx, "violet"] as const,
            ]
          ).map(([label, rate, total, seriesTone]) => (
            <div key={label} className="flex flex-col gap-1">
              <span className={`micro ${seriesTone === "signal" ? "text-signal" : "text-violet"}`}>
                <span aria-hidden>{seriesTone === "signal" ? "▼ " : "▲ "}</span>
                {label}
              </span>
              <span
                className={`font-mono text-2xl leading-none font-bold tracking-tight ${
                  seriesTone === "signal" ? "text-signal" : "text-violet"
                }`}
              >
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
      {visibleError && (
        <p className={`mt-1 text-xs ${live ? "text-fault" : "text-muted-foreground"}`}>
          {live ? "daemon" : "last control error"}: {visibleError}
        </p>
      )}
      {(() => {
        const diag = matchDiagnostic(visibleError || (silent ? "socket silent" : null))
        return diag ? (
          <DiagnosticCallout
            entry={diag}
            detail={visibleError || undefined}
            onOpenCatalog={onOpenCatalog}
          />
        ) : null
      })()}
    </section>
  )
}

function peerState(peer: Peer, now: number) {
  const f = freshness(peer.last_handshake_sec, now)
  return { f, tone: freshnessTone[f] }
}

// The one-line diagnosis: every peer gets a verdict, not just the sick ones,
// so a healthy peer reads as healthy instead of as an absence of warnings.
// An idle tunnel goes quiet on its own — only the never and stale cases name
// a next step, and the quiet ones say so.
function peerVerdict(peer: Peer, now: number): string {
  if (peer.rotating) return "Key rotation in progress"
  const age = Math.max(0, now - peer.last_handshake_sec)
  if (peer.last_handshake_sec === 0) return "No handshake yet"
  const ageText = formatAgeSec(age)
  if (age < 5 * 60) return `Active · handshake ${ageText} ago`
  if (age < 60 * 60) return `Idle · handshake ${ageText} ago`
  return `Stale · handshake ${ageText} ago`
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
  const maxTransfer = useMemo(
    () => Math.max(1, ...shown.map((p) => p.rx_bytes + p.tx_bytes)),
    [shown],
  )

  return (
    <Panel
      title={
        <>
          Devices (<span className="text-foreground font-mono">{shown.length}</span>
          {shown.length !== peers.length && (
            <span className="text-muted-foreground font-mono">/{peers.length}</span>
          )}
          )
          {stale && (
            <span
              className="text-stale"
              title="The daemon is not answering — this is the last list it sent"
            >
              {" "}
              · stale
            </span>
          )}
        </>
      }
      right={actions}
      className="min-w-0"
    >
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <label htmlFor="peer-filter" className="micro sr-only">
          Filter peers
        </label>
        <div className="relative min-w-[180px] flex-1">
          <input
            id="peer-filter"
            value={filter}
            onChange={(event) => onFilter(event.target.value)}
            placeholder="Filter peers by name, IP, endpoint, or fingerprint…"
            className="border-border/60 bg-background/40 text-foreground placeholder:text-muted-foreground/70 w-full rounded-md border px-2 py-1 pr-7 text-xs"
            aria-label="filter peers by name, IP, endpoint, or fingerprint"
          />
          {filter !== "" && (
            <button
              type="button"
              onClick={() => {
                onFilter("")
                document.getElementById("peer-filter")?.focus()
              }}
              aria-label="Clear peer filter"
              title="Clear filter (Esc)"
              className="text-muted-foreground hover:text-foreground absolute top-1/2 right-1.5 -translate-y-1/2 cursor-pointer px-1 text-xs leading-none"
            >
              ×
            </button>
          )}
        </div>
        <div
          role="group"
          aria-label="sort peers"
          title="sort peers (o cycles the order)"
          className="border-border/70 bg-background/40 inline-flex items-center rounded-md border p-0.5 text-[11px]"
        >
          {SORT_CYCLE.map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => onSort(key)}
              aria-pressed={sort === key}
              className={`min-h-0 rounded px-2 py-1 transition-colors ${
                sort === key
                  ? "bg-secondary text-foreground font-medium"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {SORT_LABELS[key]}
            </button>
          ))}
        </div>
      </div>
      {peers.length === 0 ? (
        unknown ? (
          <p className="text-muted-foreground py-3 text-xs">
            no peer list yet — nothing is answering the control socket.
          </p>
        ) : stale ? (
          <p className="text-muted-foreground py-3 text-xs">
            no peer list to show — the daemon is not answering, and the last snapshot it sent had none.
          </p>
        ) : (
          <div className="border-border/60 bg-background/35 my-2 flex flex-col gap-3 rounded-lg border p-4 text-xs">
            <div>
              <p className="text-foreground text-sm font-medium">
                Onboard your first device
              </p>
              <p className="text-muted-foreground mt-0.5">
                This interface is ready. Choose how you want to add a device:
              </p>
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <div className="border-border/60 bg-card/70 flex flex-col justify-between gap-2 rounded-lg border p-3">
                <div>
                  <p className="text-foreground font-medium">Invite token &amp; QR</p>
                  <p className="text-muted-foreground mt-0.5 text-xs">
                    Create a short-lived join ticket for a laptop or phone.
                  </p>
                </div>
                <Button
                  type="button"
                  size="sm"
                  onClick={() => document.getElementById("invite-peer-btn")?.click()}
                  className="w-full"
                >
                  Create invite…
                </Button>
              </div>
              <div className="border-border/60 bg-card/70 flex flex-col justify-between gap-2 rounded-lg border p-3">
                <div>
                  <p className="text-foreground font-medium">Client bundle</p>
                  <p className="text-muted-foreground mt-0.5 text-xs">
                    Import an exported <code className="font-mono">.vallum-bundle</code> file.
                  </p>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => document.getElementById("import-bundle-btn")?.click()}
                  className="w-full"
                >
                  Import bundle…
                </Button>
              </div>
              <div className="border-border/60 bg-card/70 flex flex-col justify-between gap-2 rounded-lg border p-3">
                <div>
                  <p className="text-foreground font-medium">Public key</p>
                  <p className="text-muted-foreground mt-0.5 text-xs">
                    Add a peer manually using its <code className="font-mono">vallum1:...</code> public line.
                  </p>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => document.getElementById("add-peer-btn")?.click()}
                  className="w-full"
                >
                  + Add by public key…
                </Button>
              </div>
            </div>
          </div>
        )
      ) : shown.length === 0 ? (
        <div className="flex flex-wrap items-center gap-2 py-3 text-xs">
          <span className="text-muted-foreground">No devices match “{filter}”</span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => {
              onFilter("")
              document.getElementById("peer-filter")?.focus()
            }}
          >
            Clear filter
          </Button>
        </div>
      ) : (
        <ul className="flex flex-col gap-0.5">
          {shown.map((peer) => {
            const { f, tone } = peerState(peer, now)
            const isSelected = peer.fingerprint === selected
            const total = peer.rx_bytes + peer.tx_bytes
            const rxPct = total > 0 ? Math.min(100, (peer.rx_bytes / maxTransfer) * 100) : 0
            const txPct = total > 0 ? Math.min(100 - rxPct, (peer.tx_bytes / maxTransfer) * 100) : 0
            return (
              <li key={peer.fingerprint}>
                <button
                  onClick={() => onSelect(peer.fingerprint)}
                  aria-pressed={isSelected}
                  className={`flex w-full cursor-pointer flex-col gap-1.5 rounded-lg px-2.5 py-2.5 text-left transition-[background-color,color] duration-150 ${
                    isSelected
                      ? "bg-secondary text-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]"
                      : "hover:bg-secondary/50"
                  }`}
                >
                  <div className="flex w-full items-center gap-2">
                    <span aria-hidden className={isSelected ? "text-signal text-[8px]" : "text-transparent text-[8px]"}>
                      ●
                    </span>
                    <span className="min-w-0 flex-1 truncate font-medium">{peer.name}</span>
                    {peer.rotating && (
                      <span className="text-stale text-xs">Rotating</span>
                    )}
                    {total > 0 && (
                      <span className="text-muted-foreground hidden font-mono text-xs sm:inline">
                        <span className="text-signal">▼</span> {bytes(peer.rx_bytes)} ·{" "}
                        <span className="text-subtext">▲</span> {bytes(peer.tx_bytes)}
                      </span>
                    )}
                    <span className={`text-xs font-medium ${tone}`}>
                      {freshnessLabel[f]}
                      {peer.last_handshake_sec > 0 && (
                        <span className="text-muted-foreground font-mono"> {formatAgeSec(now - peer.last_handshake_sec)}</span>
                      )}
                    </span>
                    <span aria-hidden className="text-muted-foreground/60">
                      ›
                    </span>
                  </div>
                  {total > 0 && (
                    <div className="bg-background/70 ml-4 flex h-1 w-[calc(100%-1rem)] overflow-hidden rounded-full">
                      <span className="bg-signal/80 h-full" style={{ width: `${rxPct}%` }} />
                      <span className="bg-subtext/55 h-full" style={{ width: `${txPct}%` }} />
                    </div>
                  )}
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}

function formatAgeMs(ms: number | null): string {
  if (ms === null) return "never"
  if (ms < 1000) return `${ms}ms ago`
  return `${(ms / 1000).toFixed(1)}s ago`
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
      <Panel title="Device details">
        <p className="text-muted-foreground py-3 text-xs">
          {unknown ? (
            "No device data — the control socket has not answered yet."
          ) : (
            <>
              Select a device — <kbd className="kbd-chip">j</kbd>/<kbd className="kbd-chip">k</kbd> steps through the list, or{" "}
              <kbd className="kbd-chip">:</kbd> opens quick commands.
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
        <span className="flex items-center gap-2">
          <span
            aria-hidden
            className={`inline-block size-2 rounded-full ${
              f === "recent" ? "bg-live" : f === "aging" ? "bg-stale" : "bg-muted-foreground/40"
            }`}
          />
          <span className="text-foreground">{peer.name}</span>
        </span>
      }
      right={peer.has_preshared_key ? <span className="micro">PSK set</span> : undefined}
    >
      {/* Actions first: everyday tasks stay on top, key rotation sits in Advanced below. */}
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
          className="h-8 px-3 text-xs font-medium"
          disabled={probing || peer.allowed_ips.length === 0}
          title={`Ping ${peer.allowed_ips[0] ?? "the device"}`}
          onClick={() => {
            // allowed_ips holds CIDRs; ping wants an address.
            const target = peer.allowed_ips[0]?.split("/")[0]
            if (!target) return
            setProbing(true)
            pingPeer(target)
              .then(setProbe)
              .catch((error: unknown) =>
                setProbe({ address: target, error: formatError(error) }),
              )
              .finally(() => setProbing(false))
          }}
        >
          {probing ? "Pinging…" : "Ping Device"}
        </Button>
        <CopyButton id="copy-address-btn" value={peer.allowed_ips.join(", ") || peer.endpoint} label="Copy IP" title="Copy this device's VPN IP (else endpoint)" disabled={peer.allowed_ips.length === 0 && peer.endpoint === ""} />
        <ExportBundleDialog peer={peer} blocked={blocked} />
        <EditPeerDialog peer={peer} blocked={blocked} />
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
      <p className={`mb-2 text-xs ${tone}`}>{peerVerdict(peer, now)}</p>
      {peer.dropped_after_auth > 0 && (
        <div className="border-fault/50 bg-fault/10 text-fault mb-2 rounded border px-2.5 py-1.5 text-xs">
          {peer.dropped_after_auth.toLocaleString()} datagram(s) failed post-auth verification (VAL-E502) — peer or server key changed; re-enrol or rotate rather than chasing a firewall.
        </div>
      )}
      <Row label="VPN IPs">{peer.allowed_ips.join(", ") || "—"}</Row>
      <Row label="Remote Endpoint">{peer.endpoint || "Roaming (updates automatically)"}</Row>
      <Row label="Data Transferred">
        {bytes(peer.rx_bytes)} received / {bytes(peer.tx_bytes)} sent
      </Row>
      <Row label="Last handshake">
        <span className={tone}>{freshnessLabel[f]}</span>
        <span className="text-muted-foreground font-mono">
          {" "}
          {peer.last_handshake_sec === 0
            ? "never"
            : `${formatAgeSec(Math.max(0, now - peer.last_handshake_sec))} ago`}
        </span>
      </Row>
      <Row label="Keepalive">{peer.keepalive !== null ? `${peer.keepalive}s` : "—"}</Row>
      {peer.valid_until !== null && (
        <Row label="Valid Until">
          {(() => {
            const remaining = peer.valid_until - now
            const stamp = new Date(peer.valid_until * 1000)
              .toISOString()
              .replace("T", " ")
              .slice(0, 19)
            return (
              <span className={remaining <= 0 ? "text-fault" : remaining < 86400 ? "text-stale" : ""}>
                {stamp} UTC ·{" "}
                {remaining <= 0
                  ? "EXPIRED"
                  : remaining >= 86400
                    ? `${Math.floor(remaining / 86400)}d left`
                    : `${Math.ceil(remaining / 3600)}h left`}
              </span>
            )
          })()}
        </Row>
      )}
      <details
        className="border-border/50 bg-background/30 mt-3 rounded border px-2.5 py-2"
        open={peer.rotating || peer.dropped_after_auth > 0 || peer.dropped_allowed_ips > 0}
      >
        <summary className="text-muted-foreground hover:text-foreground cursor-pointer text-xs font-medium select-none">
          Advanced Key &amp; Wire Details
        </summary>
        <div className="mt-2.5 flex flex-col gap-1.5">
          <div className="mb-1 flex flex-wrap items-center gap-1.5">
            <CopyButton id="copy-line-btn" value={peer.public_line} label="Copy Public Line" title="Copy this peer's public config line" />
            <RotateDialog peer={peer} blocked={blocked} />
            {peer.rotating && <FinalizeButton peer={peer} blocked={blocked} />}
          </div>
          <Row label="Fingerprint">{peer.fingerprint}</Row>
          <Row label="Key Version">{peer.epoch}</Row>
          <Row label="Delivery Window">
            {peer.window_received.toLocaleString()} rx / {peer.window_sent.toLocaleString()} tx pkts
          </Row>
          <Row label="Wire Age">
            rx {formatAgeMs(peer.last_received_ms)} · tx {formatAgeMs(peer.last_sent_ms)}
          </Row>
          {peer.dropped_allowed_ips > 0 && (
            <Row label="Allowed-IP Drops">
              <span className="text-stale">
                {peer.dropped_allowed_ips.toLocaleString()} · last source: {peer.last_rejected_source ?? "none"}
              </span>
            </Row>
          )}
          {peer.dropped_no_session + peer.dropped_replay + peer.reinit_offered > 0 && (
            <Row label="Session Drops">
              no-session {peer.dropped_no_session.toLocaleString()} · replay {peer.dropped_replay.toLocaleString()} · reinit {peer.reinit_offered.toLocaleString()}
            </Row>
          )}
        </div>
      </details>
    </Panel>
  )
}

function InterfaceData({
  payload,
  onOpenMetrics,
}: {
  payload: SnapshotPayload | null
  onOpenMetrics: () => void
}) {
  const snap = payload?.data
  const c = snap?.counters
  const failures =
    (c?.datagrams_failed ?? 0) +
    (c?.packets_failed ?? 0) +
    (c?.refusals ?? 0) +
    (c?.fragments_dropped ?? 0) +
    (c?.dropped_malformed ?? 0) +
    (c?.dropped_unknown_index ?? 0) +
    (c?.fragments_rate_limited ?? 0) +
    (c?.handshake_dropped_no_mac ?? 0) +
    (c?.handshake_dropped_unidentifiable ?? 0) +
    (c?.handshake_dropped_unknown_peer ?? 0) +
    (c?.handshake_dropped_endpoint_conflict ?? 0) +
    (c?.handshake_dropped_stale ?? 0)
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
      className="surface rounded-xl"
    >
      <summary className="flex cursor-pointer items-center justify-between gap-2 px-5 pt-4 pb-3 select-none">
        <span className="text-foreground text-sm font-medium tracking-tight">
          Interface counters &amp; packet telemetry
        </span>
        <span className="text-muted-foreground font-mono text-xs">
          {/* The counters' canonical nouns (CONTEXT.md): datagrams go out, packets
              come in, and the summary is allowed to shorten them only that far. */}
          {c ? (
            <>
              {c.datagrams_sent.toLocaleString()} datagrams out ·{" "}
              {c.packets_delivered.toLocaleString()} packets in
              {attention && <span className="text-fault"> · {failures} failed</span>}
            </>
          ) : (
            "…"
          )}
        </span>
      </summary>
      <div className="px-5 pb-4">
        {c && (
          <div className="mb-3 grid grid-cols-1 gap-2 pt-1 sm:grid-cols-2 lg:grid-cols-4">
            {(
              [
                ["datagram delivery", c.datagrams_sent, c.datagrams_failed],
                ["packet delivery", c.packets_delivered, c.packets_failed],
                ["handshake admission", c.established, c.refusals],
                ["fragment admission", c.reassembled, c.fragments_dropped + c.fragments_rate_limited],
              ] as const
            ).map(([label, ok, fail]) => {
              const total = ok + fail
              const pct = total > 0 ? Math.round((ok / total) * 1000) / 10 : 100
              const degraded = fail > 0 && pct < 99
              return (
                <div
                  key={label}
                  className="border-border/50 bg-background/40 rounded border px-2.5 py-1.5 text-xs"
                >
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="micro">{label}</span>
                    <span className={degraded ? "text-stale font-semibold" : "text-live font-semibold"}>
                      {total > 0 ? `${pct}%` : "—"}
                    </span>
                  </div>
                  <div className="bg-muted mt-1 h-1 w-full overflow-hidden rounded-full">
                    <div
                      className={degraded ? "bg-stale h-full transition-all duration-300" : "bg-live h-full transition-all duration-300"}
                      style={{ width: `${total > 0 ? pct : 0}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        )}
        <div className="grid grid-cols-1 gap-x-6 gap-y-2 pt-1 sm:grid-cols-2 lg:grid-cols-4">
          {metric(
            "datagrams out",
            `sent ${c ? c.datagrams_sent.toLocaleString() : "—"}`,
            <span className={c && c.datagrams_failed > 0 ? "text-fault" : ""}>
              failed {c?.datagrams_failed ?? "—"}
            </span>,
          )}
          {metric(
            "packets in",
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
          {metric(
            "fragments",
            `reassembled ${c ? c.reassembled.toLocaleString() : "—"}`,
            <span className={c && c.fragments_dropped > 0 ? "text-fault" : ""}>
              dropped {c?.fragments_dropped ?? "—"}
            </span>,
          )}
        </div>
        {c && (
          <div className="border-border/50 mt-3 grid grid-cols-1 gap-2 border-t pt-2.5 text-xs lg:grid-cols-2">
            <div className="border-border/40 bg-background/35 rounded border px-2.5 py-1.5">
              <p className="micro">WIRE &amp; FRAGMENT DROPS</p>
              <p className="text-muted-foreground mt-0.5 font-mono text-[11px]">
                malformed {c.dropped_malformed} · unknown index {c.dropped_unknown_index} · rate-limited{" "}
                <span className={c.fragments_rate_limited > 0 ? "text-stale" : ""}>
                  {c.fragments_rate_limited}
                </span>
              </p>
            </div>
            <div className="border-border/40 bg-background/35 rounded border px-2.5 py-1.5">
              <p className="micro">HANDSHAKE DROP REASONS</p>
              <p className="text-muted-foreground mt-0.5 font-mono text-[11px]">
                no-mac {c.handshake_dropped_no_mac} · unidentifiable {c.handshake_dropped_unidentifiable} · unknown-peer{" "}
                {c.handshake_dropped_unknown_peer} · conflict {c.handshake_dropped_endpoint_conflict} · stale{" "}
                {c.handshake_dropped_stale}
              </p>
            </div>
          </div>
        )}
        {snap && (
          <div className="border-border/50 text-muted-foreground mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t pt-2 text-xs">
            <span>
              offload{" "}
              <span className={snap.offload ? "text-live" : "text-foreground/70"}>
                {snap.offload ? "on" : "off"}
              </span>
            </span>
            <span>
              batching{" "}
              <span className={snap.batching ? "text-live" : "text-foreground/70"}>
                {snap.batching ? "on" : "off"}
              </span>
            </span>
            <span>
              fwmark{" "}
              <span className="text-foreground/80">
                {snap.fwmark !== null && snap.fwmark !== 0 ? snap.fwmark : "off"}
              </span>
            </span>
            {snap.build && (
              <span>
                build <span className="text-foreground/80">{snap.build.slice(0, 12)}</span>
              </span>
            )}
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={onOpenMetrics}
              className="ml-auto"
            >
              Metrics &amp; Telemetry…
            </Button>
          </div>
        )}
        {snap && <CryptoArchitecture suite={snap.suite} />}
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


/** Poll the unit's state. Shared by the header strip and the stopped card. */
function useServiceState(enabled: boolean) {
  const [service, setService] = useState<ServiceStatus | null>(null)
  const refresh = useCallback(() => {
    if (!enabled) return
    serviceState()
      .then(setService)
      .catch(() => setService(null))
  }, [enabled])
  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 5000)
    return () => window.clearInterval(timer)
  }, [refresh])
  return { service, refresh }
}

type CockpitSection = "overview" | "devices" | "settings" | "logs" | "setup" | "all"

const SECTION_TABS: ReadonlyArray<{ id: CockpitSection; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "devices", label: "Devices" },
  { id: "logs", label: "Monitoring" },
  { id: "settings", label: "Settings" },
]

function SectionIcon({ kind }: { kind: CockpitSection }) {
  const cls = "size-4 shrink-0 stroke-[1.5]"
  switch (kind) {
    case "overview":
      return <ShieldCheck className={cls} aria-hidden />
    case "devices":
      return <Users className={cls} aria-hidden />
    case "settings":
      return <SlidersHorizontal className={cls} aria-hidden />
    case "logs":
      return <Activity className={cls} aria-hidden />
    case "setup":
      return <BookOpen className={cls} aria-hidden />
    case "all":
      return <LayoutGrid className={cls} aria-hidden />
  }
}

export default function App() {
  const inApp = useMemo(() => hasBridge, [])
  const { service, refresh: refreshService } = useServiceState(inApp)
  const [section, setSection] = useState<CockpitSection>("overview")
  const [userPrefs, updateUserPrefs, resetUserPrefs] = useUserPrefs()
  const [hostHealth, setHostHealth] = useState<Health | null>(null)
  const [filter, setFilter] = useState("")
  const [sort, setSort] = useState<SortOrder>("handshake")
  const [shortcuts, setShortcuts] = useState(false)
  const [palette, setPalette] = useState(false)
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false)
  const [diagnosticsTab, setDiagnosticsTab] = useState<DiagnosticsTab>("doctor")
  const [diagnosticsCode, setDiagnosticsCode] = useState<string | undefined>(undefined)
  const openDiagnostics = useCallback((tab: DiagnosticsTab | "onboarding" = "doctor", code?: string) => {
    if (tab === "onboarding" && !code) {
      setDiagnosticsOpen(false)
      setSection("setup")
      return
    }
    setDiagnosticsCode(code)
    setDiagnosticsTab(code ? "codes" : tab === "onboarding" ? "doctor" : tab)
    setDiagnosticsOpen(true)
  }, [])
  const [comfortable, setComfortable] = useState(() => {
    try {
      return window.localStorage.getItem("vallum.comfortable") !== "0"
    } catch {
      return true
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

  // Health is measured on the host every 5 s: route, v6, DNS, guard, restarts.
  const refreshHealth = useCallback(() => {
    if (!inApp) return
    health()
      .then((value) => setHostHealth(value))
      .catch(() => setHostHealth(null))
  }, [inApp])

  useEffect(() => {
    if (!inApp) return
    void refreshHealth()
    const timer = window.setInterval(refreshHealth, 5000)
    return () => {
      window.clearInterval(timer)
    }
  }, [inApp, refreshHealth])

  const refreshAfterChange = useCallback(() => {
    setHostHealth(null)
    refreshHealth()
    refreshService()
    loadFacts()
  }, [loadFacts, refreshHealth, refreshService])

  // One ingestion path for live snapshots and demo ones, so the demo renders
  // exactly what a daemon would — and nothing else.
  const ingest = useCallback((payload: SnapshotPayload) => {
    setPayload(payload)
    setAttempts((count) => count + 1)
    if (payload.data) {
      setRetained(payload)
      setLastUpdate(Date.now() / 1000)
      if (history.current.recent().length === 0 && payload.data.interface) {
        const restored = loadHistory(payload.data.interface)
        if (restored.length > 1) history.current.restore(restored)
      }
      const at = Date.now()
      const rx = payload.data.peers.reduce((sum, p) => sum + p.rx_bytes, 0)
      const tx = payload.data.peers.reduce((sum, p) => sum + p.tx_bytes, 0)
      history.current.push(rx, tx, at, payload.data.counters.established)
      setSamples([...history.current.recent()])
      if (payload.data.interface) saveHistory(payload.data.interface, history.current.recent())
      const peers = payload.data.peers
      setSelectedPeer((cur) =>
        cur && peers.some((p) => p.fingerprint === cur)
          ? cur
          : (peers[0]?.fingerprint ?? null),
      )
      // Per-peer rates need two snapshots; the first visit only seeds the baseline.
      const rates: PeerRate[] = []
      const next = new Map<string, { rx: number; tx: number; at: number }>()
      for (const peer of peers) {
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
  }, [])

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
  }, [inApp])

  useEffect(() => {
    if (!inApp) return
    let unlisten: (() => void) | undefined
    void onSnapshot(ingest).then((fn) => {
      unlisten = fn
    })
    return () => unlisten?.()
  }, [inApp, ingest])

  const live = payload?.ok === true
  const booting = attempts === 0 && payload === null && retained === null
  // Data has arrived at some point: a failure frame with no data behind it is a
  // daemon that never answered, not one that stopped.
  const seen = retained !== null
  // What the daemon last said, when it is no longer saying anything: the panels
  // keep their content and the labels say which it is.
  const data = payload?.data ?? retained?.data ?? null
  const currentName = data?.interface ?? interfaces[0]?.name ?? ""
  const currentIndex = Math.max(
    0,
    interfaces.findIndex((entry) => entry.name === currentName),
  )
  const switchInterface = useCallback(
    (delta = 1) => {
      if (interfaces.length < 2) return
      const nextIndex = (currentIndex + delta + interfaces.length) % interfaces.length
      const next = interfaces[nextIndex]
      setSelectedPeer(null)
      setPayload(null)
      setRetained(null)
      void selectInterface(next.path)
    },
    [interfaces, currentIndex],
  )
  const orderedPeers = useMemo(
    () => orderPeers(data?.peers ?? [], filter, sort),
    [data?.peers, filter, sort],
  )
  const stepPeer = useCallback(
    (delta: 1 | -1) => {
      if (orderedPeers.length === 0) return
      const idx = orderedPeers.findIndex((p) => p.fingerprint === selectedPeer)
      const nextIndex =
        idx === -1
          ? delta > 0
            ? 0
            : orderedPeers.length - 1
          : (idx + delta + orderedPeers.length) % orderedPeers.length
      setSelectedPeer(orderedPeers[nextIndex].fingerprint)
    },
    [orderedPeers, selectedPeer],
  )

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
        // The shortcuts overlay holds no input, so it is the one dialog
        // Escape dismisses: a keyboard-only operator has no other way out
        // of it, and an open dialog swallows every other key.
        if (shortcuts) {
          setShortcuts(false)
          return
        }
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
      // Safe navigation and modal-opening keys: never fire while typing or inside
      // another dialog, and destructive mutations stay inside confirmed dialogs.
      switch (event.key) {
        case "1":
          event.preventDefault()
          setSection("overview")
          break
        case "2":
          event.preventDefault()
          setSection("devices")
          break
        case "3":
          event.preventDefault()
          setSection("logs")
          break
        case "4":
          event.preventDefault()
          setSection("settings")
          break
        case "5":
          event.preventDefault()
          setSection("setup")
          break
        case "6":
          event.preventDefault()
          setSection("all")
          break
        case "/":
          event.preventDefault()
          document.getElementById("peer-filter")?.focus()
          break
        case ":":
          event.preventDefault()
          setPalette(true)
          break
        case "Tab":
          event.preventDefault()
          switchInterface(1)
          break
        case "[":
          event.preventDefault()
          switchInterface(-1)
          break
        case "]":
          event.preventDefault()
          switchInterface(1)
          break
        case "j":
        case "ArrowDown":
          event.preventDefault()
          stepPeer(1)
          break
        case "k":
        case "ArrowUp":
          event.preventDefault()
          stepPeer(-1)
          break
        case "o":
          event.preventDefault()
          setSort((current) => SORT_CYCLE[(SORT_CYCLE.indexOf(current) + 1) % SORT_CYCLE.length])
          break
        case "r":
          event.preventDefault()
          refreshAfterChange()
          break
        case "i":
          event.preventDefault()
          document.getElementById("interface-form-btn")?.click()
          break
        case "E":
          event.preventDefault()
          document.getElementById("config-editor-btn")?.click()
          break
        case "W":
          event.preventDefault()
          document.getElementById("save-runtime-btn")?.click()
          break
        case "d":
          event.preventDefault()
          openDiagnostics("doctor")
          break
        default:
          break
      }
    }
    // Re-registered when the overlay opens or closes, so Escape can see it.
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [shortcuts, openDiagnostics, switchInterface, stepPeer, refreshAfterChange])

  const detail = data?.peers.find((p) => p.fingerprint === selectedPeer) ?? data?.peers[0] ?? null
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

  useEffect(() => {
    const iface = currentName || "vallum0"
    if (live && hostHealth) {
      const verdict = egressVerdict(hostHealth)
      document.title = `${verdict.label} · ${iface} — Vallum`
    } else if (!live && service && service.active !== "active") {
      document.title = `${service.active} · ${iface} — Vallum`
    } else if (live) {
      document.title = `Active · ${iface} — Vallum`
    } else {
      document.title = "Vallum — Post-Quantum VPN"
    }
  }, [live, hostHealth, service, currentName])

  return (
    <div className={`mx-auto flex min-h-svh max-w-7xl flex-col gap-4 p-4 sm:p-6 ${comfortable ? "comfortable" : ""}`}>
      <JoinUriBridge />
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 px-1">
        <div className="flex items-center gap-3">
          <RampartSeal />
          <div className="leading-tight">
            <div className="flex items-center gap-2 text-xs font-semibold tracking-[0.08em] uppercase">
              <span className="text-foreground font-bold">Vallum</span>
              <span className="text-signal">{"// Tunnel control"}</span>
            </div>
            <div className="text-muted-foreground hidden text-[10px] tracking-[0.14em] uppercase sm:block">
              Every boundary under watch
            </div>
          </div>
        </div>
        <div className="border-signal/45 bg-signal/10 text-signal inline-flex h-8 items-center gap-2 rounded-md border px-2.5 text-xs font-semibold">
          <Diamond />
          {interfaces.length > 1 ? (
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
              className="text-signal cursor-pointer bg-transparent font-mono font-semibold outline-none"
              title="Switch interface (Tab cycles)"
              aria-label="Switch interface"
            >
              {interfaces.map((entry) => (
                <option key={entry.path} value={entry.name} className="bg-popover text-foreground">
                  {entry.name}
                </option>
              ))}
            </select>
          ) : (
            <span className="font-mono">{currentName || "vallum0"}</span>
          )}
        </div>
        <span
          className={
            payload?.ok
              ? "border-[#3fb950]/50 bg-[#3fb950]/12 text-[#3fb950] inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-[11px] font-semibold tracking-wider uppercase"
              : "border-border bg-secondary/50 text-muted-foreground inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-[11px] font-semibold tracking-wider uppercase"
          }
        >
          <span
            aria-hidden
            className={
              payload?.ok
                ? "size-1.5 rounded-full bg-[#3fb950]"
                : booting
                  ? "size-1.5 rounded-full bg-[#d29922]"
                  : "bg-muted-foreground size-1.5 rounded-full"
            }
          />
          {payload?.ok ? "Running" : booting ? "Connecting" : "Offline"}
        </span>
        <button
          type="button"
          onClick={() => setSection("settings")}
          title={`User identity, keys & preferences (${ROLE_META[userPrefs.role].label}${data?.fingerprint ? ` · ${data.fingerprint}` : ""})`}
          className="border-border/70 bg-secondary/45 hover:border-signal/50 hover:bg-secondary/80 text-foreground inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-md border px-2.5 text-xs transition-colors"
        >
          <User className="text-signal size-3.5" aria-hidden />
          <span className="max-w-[120px] truncate font-medium">
            {userPrefs.alias.trim() || currentName || "vallum0"}
          </span>
          <span className="text-muted-foreground hidden font-mono text-[10px] uppercase sm:inline">
            {ROLE_META[userPrefs.role].badge}
          </span>
        </button>
        <div className="ml-auto flex flex-wrap items-center gap-2 text-xs">
          {facts?.unit === false ? (
            <span className="text-muted-foreground" title="Nothing is installed on this host yet">
              Not installed
            </span>
          ) : (
            <ServiceStrip service={service} onChanged={refreshService} attached={Boolean(payload?.ok)} />
          )}
          {((data?.peers.length ?? 0) === 0 || section === "setup") && (
            <Button
              size="sm"
              variant={section === "setup" ? "default" : "outline"}
              className="h-8 gap-1.5 px-3 text-xs font-medium"
              onClick={() => setSection("setup")}
              title="Guided setup workflow"
            >
              <SectionIcon kind="setup" />
              <span>Setup</span>
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            className="h-8 gap-2 px-3 text-xs font-medium"
            onClick={() => setPalette(true)}
            title="Command palette: search devices and actions (: opens it, ⌘K works too)"
          >
            <span>Search &amp; commands</span>
            <kbd className="kbd-chip">:</kbd>
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="h-8 px-3 text-xs font-medium"
            onClick={() => openDiagnostics("doctor")}
            title="Host readiness doctor, VAL-E* error catalog, and sanitized diagnostic JSON (shortcut: d)"
          >
            Diagnostics
          </Button>
        </div>
      </header>

      {!inApp ? (
        <NoBridge />
      ) : facts !== null &&
        !facts.unit &&
        interfaces.length === 0 ? (
        // Nothing installed: show what to run, not a start button for a unit
        // that does not exist.
        <>
          <FirstRun
            facts={facts}
            onRetry={loadFacts}
            onOpenCatalog={(code) => openDiagnostics(code ? "codes" : "doctor", code)}
          />
          {/* Trigger targets for the guide steps — the dialogs work before any
              socket exists (ticket join, SSH enrol, server init, bundle import). */}
          <div className="hidden" aria-hidden>
            <JoinNetworkDialog />
            <SetupServerDialog />
            <ImportBundleDialog />
          </div>
        </>
      ) : service && service.active !== "active" && !live ? (
        // The unit being down is only the reason the cockpit is empty when the
        // daemon is also unreachable. A daemon can answer with no unit behind it
        // (a lab, a hand-run process), and hiding a live tunnel because systemd
        // has never heard of it is the console lying in the wrong direction.
        <StoppedCard
          service={service}
          health={hostHealth}
          onChanged={refreshService}
          onOpenDiagnostics={(code) => openDiagnostics(code ? "codes" : "doctor", code)}
        />
      ) : interfaces.length === 0 ? (
        // A socket the installer created and this user cannot open is the other
        // reason for an empty list, and it is not the bare machine FirstRun
        // describes: there the steps are the news, here they are a misdiagnosis.
        facts && facts.sockets > 0 ? (
          <SocketUnreadable
            facts={facts}
            onRetry={loadFacts}
            onOpenCatalog={(code) => openDiagnostics(code ? "codes" : "doctor", code)}
          />
        ) : (
          <>
            <FirstRun
              facts={facts}
              onRetry={loadFacts}
              onOpenCatalog={(code) => openDiagnostics(code ? "codes" : "doctor", code)}
            />
            <div className="hidden" aria-hidden>
              <JoinNetworkDialog />
              <SetupServerDialog />
              <ImportBundleDialog />
            </div>
          </>
        )
      ) : (
        <>
          <nav
            aria-label="Primary sections"
            role="tablist"
            className="surface flex flex-wrap items-center gap-1 rounded-xl p-1"
          >
            {SECTION_TABS.map((tab) => {
              const active = section === tab.id
              return (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setSection(tab.id)}
                  className={
                    active
                      ? "border-signal/45 bg-signal/14 text-signal inline-flex min-h-9 cursor-pointer items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-semibold tracking-wider uppercase shadow-[0_0_12px_rgba(57,197,207,0.12)] transition-colors"
                      : "text-muted-foreground hover:text-foreground hover:bg-secondary/50 inline-flex min-h-9 cursor-pointer items-center gap-2 rounded-lg border border-transparent px-3.5 py-1.5 text-xs font-medium tracking-wider uppercase transition-colors"
                  }
                >
                  <SectionIcon kind={tab.id} />
                  <span>{tab.label}</span>
                  {tab.id === "devices" && data && (
                    <span className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 font-mono text-[11px]">
                      {data.peers.length}
                    </span>
                  )}
                </button>
              )
            })}
          </nav>

          {/* All sections stay mounted and use CSS `hidden` when inactive so
              keyboard shortcuts and the command palette (`:`) can trigger any
              dialog or button ID from any tab without losing state. */}
          <div className={section === "overview" || section === "all" ? "flex flex-col gap-4" : "hidden"}>
            <Hero
              data={data}
              now={now}
              samples={samples}
              health={hostHealth}
              live={live}
              seen={seen}
              booting={booting}
              attempts={attempts}
              replyAge={replyAge}
              socket={interfaces[currentIndex]?.path ?? ""}
              error={payload?.error ?? null}
              onOpenCatalog={(code) => openDiagnostics(code ? "codes" : "doctor", code)}
              onOpenUserKeys={() => setSection("settings")}
            />
            <NextSteps
              onChanged={refreshAfterChange}
              onNavigate={setSection}
              onOpenDiagnostics={(tab) => openDiagnostics(tab)}
              publicLine={data?.public_line}
            />
            <TunnelFlowMap
              data={data}
              health={hostHealth}
              rates={peerRates}
              rxRate={sampleRate(samples, "rx")}
              txRate={sampleRate(samples, "tx")}
              now={now}
              live={live}
              onSelectPeer={(fp) => {
                setSelectedPeer(fp)
                setSection("devices")
              }}
            />
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
              <div className="min-w-0 lg:col-span-5">
                <HealthPanel
                  health={hostHealth}
                  stale={!live}
                  onChanged={refreshAfterChange}
                  onOpenCatalog={(code) => openDiagnostics(code ? "codes" : "doctor", code)}
                />
              </div>
              <div className="flex min-w-0 flex-col gap-4 lg:col-span-7">
                <Panel title="Throughput">
                  <TrafficChart samples={samples} />
                  <TopTalkers rates={peerRates} peers={data?.peers ?? []} />
                </Panel>
                <Panel
                  title={`Cryptographic Architecture — Suite ${suiteLabel(data?.suite ?? "0x0003")}`}
                >
                  <CryptoArchitecture suite={data?.suite ?? "0x0003"} />
                </Panel>
              </div>
            </div>
          </div>

          <section
            aria-label="Peers"
            className={
              section === "devices" || section === "all"
                ? "animate-in fade-in slide-in-from-bottom-2 duration-300"
                : "hidden"
            }
          >
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2 px-1 pt-1">
              <h2 className="text-foreground text-sm font-medium">
                Connected devices
                {data ? (
                  <span className="text-muted-foreground ml-2 font-mono text-xs">{data.peers.length}</span>
                ) : null}
              </h2>
              <div className="flex flex-wrap items-center gap-2">
                <JoinNetworkDialog blocked={blocked} />
                <SetupServerDialog blocked={blocked} />
                <InviteDialog blocked={blocked} />
                <ImportBundleDialog blocked={blocked} />
                <AddPeerDialog
                  blocked={blocked}
                  peers={data?.peers ?? []}
                  interfaceAddresses={data?.addresses ?? []}
                />
              </div>
            </div>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
              <div className="min-w-0 lg:col-span-7">
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
                />
              </div>
              <div className="min-w-0 lg:col-span-5">
                <PeerDetail peer={detail} now={now} blocked={blocked} unknown={!seen} />
              </div>
            </div>
          </section>

          <section
            aria-label="Settings and Routing"
            className={
              section === "settings" || section === "all"
                ? "animate-in fade-in slide-in-from-bottom-2 duration-300"
                : "hidden"
            }
          >
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
              <div className="flex min-w-0 flex-col gap-4 lg:col-span-6">
                <UserKeyCard
                  data={data}
                  interfaceName={currentName || "vallum0"}
                  blocked={blocked}
                  prefs={userPrefs}
                  renderKeygen={(onGenerated) => (
                    <KeygenButton blocked={blocked} onGenerated={onGenerated} />
                  )}
                />
                <UserPreferencesPanel
                  prefs={userPrefs}
                  onUpdate={updateUserPrefs}
                  onReset={resetUserPrefs}
                  comfortable={comfortable}
                  onToggleComfortable={() => setComfortable((c) => !c)}
                  interfaceName={currentName || "vallum0"}
                  blocked={blocked}
                />
              </div>
              <div className="flex min-w-0 flex-col gap-4 lg:col-span-6">
                <Panel title="Daemon & Network Configuration">
                  <div className="divide-border/50 flex flex-col divide-y">
                    <div className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-1">
                      <div className="min-w-0">
                        <div className="text-foreground text-xs font-medium">Network &amp; routing</div>
                        <div className="text-muted-foreground font-mono text-[11px]">
                          {data?.addresses.join(", ") || "—"} ·{" "}
                          {data?.expected_egress === "full" ? "Full tunnel" : "Split tunnel"}
                        </div>
                      </div>
                      <InterfaceFormDialog blocked={blocked} data={data} role={userPrefs.role} />
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-3 py-3">
                      <div className="min-w-0">
                        <div className="text-foreground text-xs font-medium">Persist live peers</div>
                        <div className="text-muted-foreground text-[11px]">
                          Write runtime additions and rotations to disk
                        </div>
                      </div>
                      <SaveRuntimeButton blocked={blocked} />
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-3 py-3">
                      <div className="min-w-0">
                        <div className="text-foreground text-xs font-medium">Listen port &amp; cryptography</div>
                        <div className="text-muted-foreground font-mono text-[11px]">
                          {data?.listen_port !== null && data?.listen_port !== undefined
                            ? `UDP :${data.listen_port}`
                            : "Auto port"}{" "}
                          · {suiteLabel(data?.suite)}
                        </div>
                      </div>
                      <DeviceDialog
                        listenPort={data?.listen_port ?? null}
                        fwmark={data?.fwmark ?? null}
                        blocked={blocked}
                      />
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-3 py-3 last:pb-1">
                      <div className="min-w-0">
                        <div className="text-foreground text-xs font-medium">Raw TOML configuration</div>
                        <div className="text-muted-foreground text-[11px]">
                          Config editor with line diff preview and validation
                        </div>
                      </div>
                      <ConfigDialog blocked={blocked} interfaceName={currentName || "vallum0"} />
                    </div>
                  </div>
                </Panel>
                <PlanPanel onChanged={refreshAfterChange} />
              </div>
            </div>
          </section>

          <section
            aria-label="Monitoring and Logs"
            className={
              section === "logs" || section === "all"
                ? "animate-in fade-in slide-in-from-bottom-2 duration-300"
                : "hidden"
            }
          >
            <div className="flex flex-col gap-4">
              <PacketPipelineFlow data={data} onOpenMetrics={() => openDiagnostics("metrics")} />
              <InterfaceData payload={payload} onOpenMetrics={() => openDiagnostics("metrics")} />
              <LogsPanel
                onOpenDiagnostics={(code) => openDiagnostics(code ? "codes" : "doctor", code)}
              />
            </div>
          </section>

          <section
            aria-label="Setup Guide"
            className={
              section === "setup"
                ? "animate-in fade-in slide-in-from-bottom-2 duration-300"
                : "hidden"
            }
          >
            <FirstRun
              facts={facts}
              onRetry={loadFacts}
              embedded
              onOpenCatalog={(code) => openDiagnostics(code ? "codes" : "doctor", code)}
            />
          </section>

          <footer className="text-muted-foreground flex flex-wrap items-center gap-x-2.5 gap-y-1 border-t border-white/8 px-1 pt-3 text-xs">
            <span>
              {lastReply === "live"
                ? "Snapshot live"
                : lastReply === "—"
                  ? "Waiting for snapshot"
                  : `Snapshot updated ${lastReply}`}
            </span>
            <span>·</span>
            <button
              onClick={() => openDiagnostics("doctor")}
              className="hover:text-foreground cursor-pointer rounded transition-colors"
              title="Open host readiness checks, VAL-E* error reference, and sanitized JSON export (d)"
            >
              Diagnostics
            </button>
            <span>·</span>
            <button
              onClick={() => openDiagnostics("metrics")}
              className="hover:text-foreground cursor-pointer rounded transition-colors"
              title="Inspect live telemetry counters and Prometheus exposition"
            >
              Telemetry
            </button>
            <span>·</span>
            <button
              onClick={() => setSection("setup")}
              className="hover:text-foreground cursor-pointer rounded transition-colors"
              title="Open the guided setup workflow"
            >
              Setup guide
            </button>
            <span>·</span>
            <button
              onClick={() => setSection(section === "all" ? "overview" : "all")}
              className="hover:text-foreground cursor-pointer rounded transition-colors"
              title="Toggle single-page view of all panels (shortcut: 6)"
            >
              {section === "all" ? "Tabbed view" : "All panels"}
            </button>
            <span>·</span>
            <button
              onClick={() => setComfortable((c) => !c)}
              className="hover:text-foreground cursor-pointer rounded transition-colors"
              title="Text size: comfortable raises controls and text above minimum touch targets"
            >
              Text size: {comfortable ? "comfortable" : "compact"}
            </button>
            <span>·</span>
            <button
              onClick={() => setShortcuts(true)}
              className="hover:text-foreground cursor-pointer rounded transition-colors"
              title="Keyboard shortcuts (?)"
            >
              Shortcuts
            </button>
            <span className="text-muted-foreground/70 ml-auto font-mono text-[11px]">
              v1.6.4 · Ikaros Digital × AtomGuard
            </span>
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
        sortLabel={SORT_LABELS[sort]}
        hasFilter={filter.trim() !== ""}
        onClearFilter={() => setFilter("")}
        onRefresh={refreshAfterChange}
        onPrevPeer={() => stepPeer(-1)}
        onNextPeer={() => stepPeer(1)}
        onSwitchInterface={() => switchInterface(1)}
        interfaceCount={interfaces.length}
        onToggleDensity={() => setComfortable((c) => !c)}
        comfortable={comfortable}
        onOpenShortcuts={() => setShortcuts(true)}
        onOpenDiagnostics={() => openDiagnostics("doctor")}
        onOpenMetrics={() => openDiagnostics("metrics")}
        onOpenOnboarding={() => openDiagnostics("onboarding")}
      />

      <DiagnosticsModal
        key={`${diagnosticsTab}-${diagnosticsCode ?? ""}`}
        open={diagnosticsOpen}
        onOpenChange={setDiagnosticsOpen}
        facts={facts}
        health={hostHealth}
        service={service}
        snapshot={data}
        error={payload?.error ?? null}
        initialTab={diagnosticsTab}
        highlightCode={diagnosticsCode}
      />

      {shortcuts && (
        <div
          role="dialog"
          aria-label="Keyboard shortcuts"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
          onClick={() => setShortcuts(false)}
        >
          <div
            className="surface-raised w-full max-w-md rounded-xl p-5"
            onClick={(event) => event.stopPropagation()}
          >
            <p className="text-foreground mb-3 text-sm font-medium">
              Keyboard shortcuts
            </p>
            <dl className="grid grid-cols-[5.5rem_1fr] gap-x-3 gap-y-1.5 text-xs">
              {[
                ["1 – 6", "Switch section (Overview / Devices / Monitoring / Settings / Setup / All)"],
                ["j / ↓", "Next peer"],
                ["k / ↑", "Previous peer"],
                ["/", "Filter peers"],
                ["o", "Cycle peer sort (activity / transfer / name / key)"],
                ["r", "Refresh health & service telemetry"],
                ["d", "Open Diagnostics & VAL-E* error reference"],
                ["i", "Open interface settings form"],
                ["E", "Open raw TOML configuration editor"],
                ["W", "Save live runtime peers to configuration"],
                [": / ⌘K", "Command palette — all actions & peers"],
                ["Tab / [ / ]", "Switch interface"],
                ["Esc", "Close dialog · clear peer filter"],
                ["?", "Open / close this list"],
              ].map(([key, meaning]) => (
                <div key={key} className="contents">
                  <dt>
                    <kbd className="kbd-chip">{key}</kbd>
                  </dt>
                  <dd className="text-muted-foreground">{meaning}</dd>
                </div>
              ))}
            </dl>
            <p className="text-muted-foreground mt-3 text-xs">
              All peer, bundle, and service actions also live in the command palette (<kbd className="kbd-chip">:</kbd>).
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
