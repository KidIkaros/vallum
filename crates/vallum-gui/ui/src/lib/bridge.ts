import { invoke } from "@tauri-apps/api/core"
import { listen, type UnlistenFn } from "@tauri-apps/api/event"
import type { InterfaceEntry, SnapshotPayload } from "@/types"

// Every function here is one hop over the Tauri bridge. Nothing invents a
// value the Rust side did not send: an absent field stays absent in the UI.

export async function listInterfaces(): Promise<InterfaceEntry[]> {
  return invoke<InterfaceEntry[]>("list_interfaces")
}

export async function selectInterface(path: string): Promise<void> {
  await invoke("select", { path })
}

export async function reportWindowState(focused: boolean, visible: boolean): Promise<void> {
  await invoke("window_state", { focused, visible })
}

export function onSnapshot(
  handler: (payload: SnapshotPayload) => void,
): Promise<UnlistenFn> {
  return listen<SnapshotPayload>("snapshot", (event) => handler(event.payload))
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
