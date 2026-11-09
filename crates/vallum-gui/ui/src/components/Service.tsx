import { useCallback, useEffect, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { logsTail, serviceAction, serviceState, type ServiceStatus } from "@/lib/bridge"

// The lifecycle the console was missing: whether the tunnel's unit is up, and
// the two buttons that change that. Start/stop go through polkit (or a narrow
// sudoers rule) — the desktop asks, the console never sees a password.

const tone = (active: string) =>
  active === "active" ? "bg-live" : active === "failed" ? "bg-fault" : "bg-stale"

/** Poll the unit's state. Shared by the header strip and the stopped card. */
export function useServiceState(enabled: boolean) {
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

/** Run a lifecycle action and report what systemd says afterwards, not intent. */
function useServiceAction(refresh: () => void) {
  const [pending, setPending] = useState<string | null>(null)
  const act = async (action: "start" | "stop" | "restart") => {
    setPending(action)
    try {
      const done = await serviceAction(action)
      toast.success(done.message)
    } catch (error) {
      toast.error(String(error instanceof Error ? error.message : error))
    } finally {
      setPending(null)
      refresh()
    }
  }
  return { pending, act }
}

export function ServiceStrip({
  service,
  onChanged,
}: {
  service: ServiceStatus | null
  onChanged: () => void
}) {
  const { pending, act } = useServiceAction(onChanged)
  const active = service?.active ?? "unknown"
  return (
    <span className="flex items-center gap-2">
      <span
        className="flex items-center gap-1.5"
        title={`systemd: ${active}, ${service?.enabled ?? "unknown"}`}
      >
        <span aria-hidden className={`inline-block size-1.5 rounded-full ${tone(active)}`} />
        <span className="micro">
          service <span className="text-foreground/80">{active}</span>
        </span>
      </span>
      <Button
        size="sm"
        variant="outline"
        className="h-6 px-2 text-[10px]"
        disabled={pending !== null || active === "active"}
        onClick={() => void act("start")}
      >
        {pending === "start" ? "…" : "START"}
      </Button>
      <Button
        size="sm"
        variant="outline"
        className="h-6 px-2 text-[10px]"
        disabled={pending !== null || active !== "active"}
        onClick={() => void act("stop")}
      >
        {pending === "stop" ? "…" : "STOP"}
      </Button>
    </span>
  )
}

/** Shown in place of the cockpit when the unit is not running: say so, and act. */
export function StoppedCard({
  service,
  onChanged,
}: {
  service: ServiceStatus | null
  onChanged: () => void
}) {
  const { pending, act } = useServiceAction(onChanged)
  const unit = service?.unit ?? "vallum@vallum0"
  const failed = service?.active === "failed"
  return (
    <section className="bg-card/60 rounded-lg border border-border/70 px-5 py-6">
      <div className="flex flex-col gap-1">
        <span className="micro">tunnel</span>
        <span
          className={`text-3xl leading-none font-semibold tracking-tight ${
            failed ? "text-fault" : "text-stale"
          }`}
        >
          {failed ? "FAILED" : "STOPPED"}
        </span>
        <span className="text-muted-foreground mt-1 text-xs">
          {unit} is not running. The console reads a live daemon — start the
          service to bring the tunnel up.
        </span>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button size="sm" disabled={pending !== null} onClick={() => void act("start")}>
          {pending === "start" ? "starting…" : "START TUNNEL"}
        </Button>
        <code className="text-muted-foreground text-[11px]">sudo systemctl start {unit}</code>
      </div>
      <LogsPanel />
    </section>
  )
}

export function LogsPanel() {
  const [text, setText] = useState<string>("")
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [unit, setUnit] = useState<string>("")

  const load = useCallback(() => {
    logsTail(300)
      .then((tail) => {
        setUnit(tail.unit)
        setText(tail.lines ?? "")
        setError(tail.error ?? null)
      })
      .catch((cause) => setError(String(cause instanceof Error ? cause.message : cause)))
  }, [])

  useEffect(() => {
    if (open) load()
  }, [open, load])

  return (
    <details
      className="bg-card/60 rounded-lg border border-border/70"
      onToggle={(event) => setOpen((event.currentTarget as HTMLDetailsElement).open)}
    >
      <summary className="text-muted-foreground flex cursor-pointer items-center gap-2 px-3 py-2 text-[10px] tracking-wider uppercase select-none">
        logs
        <span className="text-muted-foreground/70 normal-case tracking-normal">
          {unit || "journalctl"}
        </span>
        <Button
          size="sm"
          variant="ghost"
          className="ml-auto h-5 px-2 text-[10px]"
          onClick={(event) => {
            event.preventDefault()
            load()
          }}
        >
          refresh
        </Button>
      </summary>
      <pre className="text-foreground/80 max-h-64 overflow-auto border-t border-border/70 px-3 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">
        {error ? `journald: ${error}` : text || "no output"}
      </pre>
    </details>
  )
}
