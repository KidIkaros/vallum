import { invoke } from "@tauri-apps/api/core"
import { listen, type UnlistenFn } from "@tauri-apps/api/event"
import type { InterfaceEntry, SnapshotPayload } from "@/types"

// One console, two transports. Inside the Tauri webview the bridge is IPC
// (`window.__TAURI_INTERNALS__`); served by `vallum-gui --serve` it is plain
// localhost HTTP with the same commands and the same payloads. Everything
// above this file is transport-blind.

const IN_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
const OVER_HTTP =
  typeof window !== "undefined" && /^https?:$/.test(window.location.protocol)

/** True when the console can actually reach a daemon, by either transport. */
export const hasBridge = IN_TAURI || OVER_HTTP

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init)
  if (!response.ok) {
    let detail = response.statusText
    try {
      const body = (await response.json()) as { error?: string }
      if (body.error) detail = body.error
    } catch {
      /* a non-JSON error body keeps the status text */
    }
    throw new Error(detail)
  }
  return (await response.json()) as T
}

/** Invoke a console command over whichever transport is available. */
export async function command<T>(name: string, args?: unknown): Promise<T> {
  if (IN_TAURI) return invoke<T>(name, (args ?? {}) as Record<string, unknown>)
  return http<T>(`/api/cmd/${name}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(args ?? {}),
  })
}

export async function listInterfaces(): Promise<InterfaceEntry[]> {
  if (IN_TAURI) return invoke<InterfaceEntry[]>("list_interfaces")
  return http<InterfaceEntry[]>("/api/interfaces")
}

export async function selectInterface(path: string): Promise<void> {
  if (IN_TAURI) {
    await invoke("select", { path })
    return
  }
  await http("/api/select", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ path }),
  })
}

export async function reportWindowState(focused: boolean, visible: boolean): Promise<void> {
  // The HTTP transport has no window; its cadence is fixed server-side.
  if (!IN_TAURI) return
  await invoke("window_state", { focused, visible })
}

export interface ServiceStatus {
  unit: string
  active: string
  enabled: string
}

export interface Health {
  unit: string
  interface: string
  route4: string | null
  route4_via_tunnel: boolean
  route6: string | null
  route6_via_tunnel: boolean
  dns: string[]
  dns_via_tunnel: boolean
  dns_upstream?: string[]
  restarts: number
  last_death: string
  guard: { unit: string; active: string }
  quick: { unit: string; active: string }
}

/** Is this actually a VPN right now? Measured on the host, not read from config. */
export function health(): Promise<Health> {
  if (IN_TAURI) return invoke<Health>("health_state")
  return http<Health>("/api/health")
}

/** Restore this host's internet: policy off, routes back, units stopped. */
export function panicNow(): Promise<{ message: string }> {
  if (IN_TAURI) return invoke("panic_command")
  return http("/api/panic", { method: "POST" })
}

export interface Preflight {
  vallum: boolean
  quick: boolean
  panic: boolean
  deadman: boolean
  unit: boolean
  /** null when the file exists but this user cannot see it. */
  config: boolean | null
  runtime_dir: string
  runtime_mode: string
  sockets: number
}

/** What is on this host, read from disk and systemd. Changes nothing. */
export function preflight(): Promise<Preflight> {
  if (IN_TAURI) return invoke<Preflight>("preflight_state")
  return http<Preflight>("/api/preflight")
}

export interface PingResult {
  address: string
  interface?: string
  sent?: number
  received?: number | null
  avg_ms?: string | null
  output?: string
  error?: string
}

/** Probe a peer over the interface that carries it. */
export function pingPeer(address: string): Promise<PingResult> {
  if (IN_TAURI) return invoke<PingResult>("ping_peer", { address })
  return http<PingResult>("/api/ping", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ address }),
  })
}

export interface LogTail {
  unit: string
  lines?: string
  error?: string
}

/** Whether the tunnel's systemd unit is up — read unprivileged. */
export function serviceState(): Promise<ServiceStatus> {
  if (IN_TAURI) return invoke<ServiceStatus>("service_state")
  return http<ServiceStatus>("/api/service")
}

/** Start/stop through polkit; the desktop asks, the console never sees a password. */
export function serviceAction(action: "start" | "stop" | "restart"): Promise<{ message: string }> {
  if (IN_TAURI) return invoke("service_action", { action })
  return http("/api/service", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action }),
  })
}

/** The unit's last log lines, as journald gives them to this user. */
export function logsTail(lines = 200): Promise<LogTail> {
  if (IN_TAURI) return invoke<LogTail>("logs_tail", { lines })
  return http<LogTail>(`/api/logs?lines=${lines}`)
}

export function onSnapshot(
  handler: (payload: SnapshotPayload) => void,
): Promise<UnlistenFn> {
  if (IN_TAURI) {
    return listen<SnapshotPayload>("snapshot", (event) => handler(event.payload))
  }
  const source = new EventSource("/api/stream")
  source.onmessage = (event) => {
    try {
      handler(JSON.parse(event.data) as SnapshotPayload)
    } catch {
      /* a malformed frame is skipped, not fatal */
    }
  }
  return Promise.resolve(() => source.close())
}

/** The window's own focus/visibility, for the poller's cadence. */
export function watchWindowState(): () => void {
  const report = () => {
    void reportWindowState(document.hasFocus(), document.visibilityState === "visible")
  }
  document.addEventListener("visibilitychange", report)
  window.addEventListener("focus", report)
  window.addEventListener("blur", report)
  report()
  return () => {
    document.removeEventListener("visibilitychange", report)
    window.removeEventListener("focus", report)
    window.removeEventListener("blur", report)
  }
}

export function bytes(size: number): string {
  if (size === 0) return "0 B"
  const units = ["B", "KiB", "MiB", "GiB", "TiB"]
  const power = Math.min(Math.floor(Math.log2(size) / 10), units.length - 1)
  const value = size / 2 ** (10 * power)
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[power]}`
}

export function ago(unixSec: number): string {
  if (unixSec === 0) return "never"
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unixSec)
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

/** A peer with a recent handshake is carrying; anything else is not. */
export function peerIsUp(lastHandshakeSec: number): boolean {
  return lastHandshakeSec > 0 && Date.now() / 1000 - lastHandshakeSec < 180
}
