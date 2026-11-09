import { useCallback, useEffect, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { logsTail, serviceAction, serviceState, type ServiceStatus } from "@/lib/bridge"

// The lifecycle the console was missing: whether the tunnel's unit is up, and
// the two buttons that change that. Start/stop go through polkit — the desktop
// asks for authorisation, the console never sees a password.

const tone = (active: string) =>
  active === "active"
    ? "bg-live"
    : active === "failed"
      ? "bg-fault"
      : "bg-muted-foreground/40"

export function ServiceStrip({ blocked }: { blocked?: string }) {
  const [state, setState] = useState<ServiceStatus | null>(null)
  const [pending, setPending] = useState<string | null>(null)

  const refresh = useCallback(() => {
    serviceState()
      .then(setState)
      .catch(() => setState(null))
  }, [])

  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 5000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const act = async (action: "start" | "stop" | "restart") => {
    setPending(action)
    try {
      const done = await serviceAction(action)
      toast.success(done.message)
      // systemd needs a moment; the poll catches up either way.
      window.setTimeout(refresh, 1500)
    } catch (error) {
      toast.error(String(error instanceof Error ? error.message : error))
    } finally {
      setPending(null)
    }
  }

  const active = state?.active ?? "unknown"
  return (
    <span className="flex items-center gap-2">
      <span className="flex items-center gap-1.5" title={`systemd: ${active}, ${state?.enabled ?? "unknown"}`}>
        <span aria-hidden className={`inline-block size-1.5 rounded-full ${tone(active)}`} />
        <span className="micro">
          service <span className="text-foreground/80">{active}</span>
        </span>
      </span>
      <Button
        size="sm"
        variant="outline"
        className="h-6 px-2 text-[10px]"
        disabled={Boolean(blocked) || pending !== null || active === "active"}
        onClick={() => void act("start")}
      >
        {pending === "start" ? "…" : "START"}
      </Button>
      <Button
        size="sm"
        variant="outline"
        className="h-6 px-2 text-[10px]"
        disabled={Boolean(blocked) || pending !== null || active !== "active"}
        onClick={() => void act("stop")}
      >
        {pending === "stop" ? "…" : "STOP"}
      </Button>
    </span>
  )
}

export function LogsPanel({ blocked }: { blocked?: string }) {
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
          disabled={Boolean(blocked)}
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
