import { useCallback, useEffect, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Panel } from "@/components/ui/panel"
import { serviceAction } from "@/lib/bridge"
import {
  closeEnrollment,
  disableUnits,
  enableUnits,
  finalizePeer,
  suggestions,
  syncHost,
  type Suggestion,
} from "@/lib/actions"

// The console's answer to "I opened the app — now what". The backend reasons
// over observed state only (units, socket, peers, systemd) and returns an
// ordered list; this card renders it and turns each action into a button for
// an affordance the UI already has. A suggestion whose capability the console
// lacks simply renders as text.

const TONE_CLASS: Record<Suggestion["tone"], string> = {
  Act: "border-signal/45 bg-signal/10 text-signal",
  Warn: "border-stale/50 bg-stale/10 text-stale",
  Info: "border-border bg-secondary/60 text-muted-foreground",
}

const TONE_LABEL: Record<Suggestion["tone"], string> = {
  Act: "next step",
  Warn: "attention",
  Info: "note",
}

/** Button text for each action the card knows how to run. */
function actionLabel(action: NonNullable<Suggestion["action"]>): string {
  if (typeof action !== "string") return "Finalize"
  switch (action) {
    case "JoinNetwork":
      return "Join…"
    case "SetupServer":
      return "Set up…"
    case "StartService":
      return "Start"
    case "EnableService":
      return "Enable at boot"
    case "RestartService":
      return "Restart"
    case "DisableUnits":
      return "Disable…"
    case "InvitePeer":
      return "Invite…"
    case "CloseEnrolment":
      return "Close responder"
    case "PingPeer":
      return "Open devices"
    case "SyncHost":
      return "Sync now"
    case "OpenLogs":
      return "Open logs"
    case "HealthCheck":
      return "Run doctor"
    case "EditConfig":
      return "Edit config"
    case "CopyPublicLine":
      return "Copy key"
    default:
      return "Do it"
  }
}

export function NextSteps({
  onChanged,
  onNavigate,
  onOpenDiagnostics,
  publicLine,
}: {
  /** Refresh app state after an action ran (service, health, preflight). */
  onChanged: () => void
  /** Switch cockpit section, for actions that are a place rather than a call. */
  onNavigate: (section: "devices" | "logs") => void
  onOpenDiagnostics: (tab: "doctor") => void
  publicLine?: string
}) {
  const [items, setItems] = useState<Suggestion[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  // DisableUnits stops the tunnel and keeps it off after reboot — the only
  // suggestion destructive enough to want a second click inside the card.
  const [confirming, setConfirming] = useState<string | null>(null)

  const refresh = useCallback(() => {
    suggestions()
      .then((answer) => setItems(answer.suggestions))
      .catch(() => setItems([]))
  }, [])

  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 5000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const click = (id: string) => document.getElementById(id)?.click()

  const run = async (item: Suggestion) => {
    const action = item.action
    if (!action) return
    const kind = typeof action === "string" ? action : "FinalizePeer"
    if (kind === "DisableUnits" && confirming !== item.id) {
      setConfirming(item.id)
      return
    }
    setConfirming(null)
    setBusy(item.id)
    try {
      switch (kind) {
        case "JoinNetwork":
          click("join-network-btn")
          return
        case "SetupServer":
          click("setup-server-btn")
          return
        case "InvitePeer":
          click("invite-peer-btn")
          return
        case "EditConfig":
          click("config-editor-btn")
          return
        case "OpenLogs":
          onNavigate("logs")
          return
        case "HealthCheck":
          onOpenDiagnostics("doctor")
          return
        case "PingPeer":
          onNavigate("devices")
          return
        case "CopyPublicLine":
          await navigator.clipboard.writeText(publicLine ?? "")
          toast.success("public key line copied")
          return
        case "StartService":
          toast.success((await serviceAction("start")).message)
          break
        case "RestartService":
          toast.success((await serviceAction("restart")).message)
          break
        case "EnableService":
          toast.success((await enableUnits()).message)
          break
        case "DisableUnits":
          toast.success((await disableUnits()).message)
          break
        case "CloseEnrolment":
          toast.success((await closeEnrollment("")).message)
          break
        case "SyncHost":
          toast.success((await syncHost()).message)
          break
        case "FinalizePeer": {
          const name = (action as { FinalizePeer: string }).FinalizePeer
          toast.success((await finalizePeer(name)).message)
          break
        }
      }
      onChanged()
      refresh()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error))
    } finally {
      setBusy(null)
    }
  }

  if (items.length === 0) return null

  return (
    <Panel title="Next steps" className="min-w-0">
      <div className="flex flex-col gap-2">
        {items.map((item) => (
          <div
            key={item.id}
            className={`flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg border px-3 py-2 ${TONE_CLASS[item.tone]}`}
          >
            <span className="micro shrink-0 uppercase">{TONE_LABEL[item.tone]}</span>
            <div className="min-w-0 flex-1">
              <p className="text-foreground text-xs font-medium">{item.title}</p>
              <p className="text-muted-foreground mt-0.5 text-[11px] leading-snug">
                {item.detail}
              </p>
            </div>
            {item.action && (
              <Button
                type="button"
                size="sm"
                variant={confirming === item.id ? "destructive" : "outline"}
                className="h-7 shrink-0 px-2.5 text-[11px]"
                disabled={busy !== null}
                onClick={() => void run(item)}
              >
                {busy === item.id
                  ? "Working…"
                  : confirming === item.id
                    ? "Confirm disable"
                    : actionLabel(item.action)}
              </Button>
            )}
          </div>
        ))}
      </div>
    </Panel>
  )
}
