import { useEffect, useState } from "react"
import { Activity, Moon, ShieldOff, Sun, Unplug } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Toaster } from "@/components/ui/sonner"
import {
  ago,
  bytes,
  listInterfaces,
  onSnapshot,
  peerIsUp,
  selectInterface,
  watchWindowState,
} from "@/lib/bridge"
import type { InterfaceEntry, SnapshotPayload } from "@/types"

function useTheme() {
  const [dark, setDark] = useState(
    () => window.matchMedia("(prefers-color-scheme: dark)").matches,
  )
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark)
  }, [dark])
  return {
    dark,
    toggle: () => setDark((value) => !value),
  }
}

function Verdict({ payload }: { payload: SnapshotPayload | null }) {
  let label = "connecting"
  let tone = "text-muted-foreground border-border"
  if (payload) {
    if (!payload.ok) {
      label = "unreachable"
      tone = "text-destructive border-destructive/40 bg-destructive/10"
    } else if (payload.data && payload.data.peers.some((p) => peerIsUp(p.last_handshake_sec))) {
      label = "up"
      tone = "text-emerald-600 border-emerald-600/40 bg-emerald-600/10 dark:text-emerald-400"
    } else {
      label = "no session"
      tone = "text-amber-600 border-amber-600/40 bg-amber-600/10 dark:text-amber-400"
    }
  }
  return (
    <Badge variant="outline" className={`gap-1.5 ${tone}`} data-testid="verdict">
      <Activity className="size-3" aria-hidden />
      {label}
    </Badge>
  )
}

function Counter({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-muted-foreground text-xs">{label}</span>
      <span className="font-mono text-sm tabular-nums">{value}</span>
    </div>
  )
}

function DeviceCard({ payload }: { payload: SnapshotPayload | null }) {
  const data = payload?.data
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Device</CardTitle>
      </CardHeader>
      <CardContent className="grid grid-cols-2 gap-x-6 gap-y-4">
        <Counter label="interface" value={data?.interface ?? "—"} />
        <Counter label="listen port" value={data?.listen_port?.toString() ?? "—"} />
        <Counter label="addresses" value={data?.addresses.join(", ") || "—"} />
        <Counter
          label="suite"
          value={data ? `0x${Number(data.suite).toString(16).padStart(4, "0")}` : "—"}
        />
        <Counter label="fingerprint" value={data ? `${data.fingerprint.slice(0, 16)}…` : "—"} />
        <div className="flex flex-col gap-1">
          <span className="text-muted-foreground text-xs">offload / batching</span>
          <span className="flex gap-1.5">
            <Badge variant={data?.offload ? "secondary" : "outline"}>
              {data?.offload ? "on" : "off"}
            </Badge>
            <Badge variant={data?.batching ? "secondary" : "outline"}>
              {data?.batching ? "on" : "off"}
            </Badge>
          </span>
        </div>
      </CardContent>
    </Card>
  )
}

function CountersCard({ payload }: { payload: SnapshotPayload | null }) {
  const counters = payload?.data?.counters
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Counters</CardTitle>
      </CardHeader>
      <CardContent className="grid grid-cols-4 gap-x-6 gap-y-4">
        <Counter label="datagrams out" value={counters ? bytes(counters.datagrams_sent) : "—"} />
        <Counter label="out failed" value={counters?.datagrams_failed.toString() ?? "—"} />
        <Counter label="packets in" value={counters ? bytes(counters.packets_delivered) : "—"} />
        <Counter label="in failed" value={counters?.packets_failed.toString() ?? "—"} />
        <Counter label="handshakes" value={counters?.established.toString() ?? "—"} />
        <Counter label="refusals" value={counters?.refusals.toString() ?? "—"} />
        <Counter label="reassembled" value={counters?.reassembled.toString() ?? "—"} />
        <Counter label="frag dropped" value={counters?.fragments_dropped.toString() ?? "—"} />
      </CardContent>
    </Card>
  )
}

function PeersCard({ payload }: { payload: SnapshotPayload | null }) {
  const peers = payload?.data?.peers ?? []
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          Peers
          {peers.length > 0 && (
            <span className="text-muted-foreground ml-2 text-sm font-normal">{peers.length}</span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {peers.length === 0 ? (
          <p className="text-muted-foreground flex items-center gap-2 py-6 text-sm">
            <Unplug className="size-4" aria-hidden />
            No peers configured on this interface.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>peer</TableHead>
                <TableHead>endpoint</TableHead>
                <TableHead>allowed IPs</TableHead>
                <TableHead className="text-right">tx</TableHead>
                <TableHead className="text-right">rx</TableHead>
                <TableHead>handshake</TableHead>
                <TableHead>epoch</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {peers.map((peer) => (
                <TableRow key={peer.fingerprint}>
                  <TableCell className="font-medium">
                    <span className="flex items-center gap-2">
                      <span
                        aria-hidden
                        className={`size-2 rounded-full ${peerIsUp(peer.last_handshake_sec) ? "bg-emerald-500" : "bg-muted-foreground/30"}`}
                      />
                      {peer.name}
                      {peer.rotating && (
                        <Badge variant="outline" className="text-amber-600 dark:text-amber-400">
                          rotating
                        </Badge>
                      )}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{peer.endpoint || "roaming"}</TableCell>
                  <TableCell className="font-mono text-xs">{peer.allowed_ips.join(", ")}</TableCell>
                  <TableCell className="text-right font-mono text-xs tabular-nums">
                    {bytes(peer.tx_bytes)}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs tabular-nums">
                    {bytes(peer.rx_bytes)}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {ago(peer.last_handshake_sec)}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs tabular-nums">
                    {peer.epoch}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}

function EmptyState() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
        <ShieldOff className="text-muted-foreground size-8" aria-hidden />
        <div>
          <p className="font-medium">No daemon on this machine</p>
          <p className="text-muted-foreground mt-1 text-sm">
            The console found no control socket in the runtime directory. Start a
            daemon with <code className="font-mono text-xs">vallum run</code> or{" "}
            <code className="font-mono text-xs">vallum-quick up</code>.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

export default function App() {
  const [interfaces, setInterfaces] = useState<InterfaceEntry[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [payload, setPayload] = useState<SnapshotPayload | null>(null)
  const { dark, toggle } = useTheme()

  useEffect(() => watchWindowState(), [])

  useEffect(() => {
    let cancelled = false
    listInterfaces().then((entries) => {
      if (cancelled) return
      setInterfaces(entries)
      // The first socket is the daemon the operator most likely means; picking
      // it saves a click without hiding the others.
      if (entries.length > 0) {
        setSelected(entries[0].path)
        void selectInterface(entries[0].path)
      }
    })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    let unlisten: (() => void) | undefined
    void onSnapshot(setPayload).then((fn) => {
      unlisten = fn
    })
    return () => unlisten?.()
  }, [])

  const pick = (path: string) => {
    setSelected(path)
    void selectInterface(path)
  }

  return (
    <div className="mx-auto flex min-h-svh max-w-4xl flex-col gap-6 p-6">
      <header className="flex items-center gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Vallum</h1>
        <Verdict payload={payload} />
        <div className="ml-auto flex items-center gap-2">
          {interfaces.length > 0 && (
            <Select value={selected ?? undefined} onValueChange={pick}>
              <SelectTrigger className="w-44" aria-label="Interface">
                <SelectValue placeholder="interface" />
              </SelectTrigger>
              <SelectContent>
                {interfaces.map((entry) => (
                  <SelectItem key={entry.path} value={entry.path}>
                    {entry.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          <button
            onClick={toggle}
            aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
            className="hover:bg-accent inline-flex size-8 items-center justify-center rounded-md"
          >
            {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </button>
        </div>
      </header>

      <Separator />

      {interfaces.length === 0 ? (
        <EmptyState />
      ) : (
        <main className="flex flex-col gap-6">
          <div className="grid gap-6 md:grid-cols-2">
            <DeviceCard payload={payload} />
            <CountersCard payload={payload} />
          </div>
          <PeersCard payload={payload} />
        </main>
      )}

      <Toaster position="bottom-right" />
    </div>
  )
}
