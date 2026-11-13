import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { CopyButton } from "@/components/Copy"
import { DiagnosticCallout } from "@/components/DiagnosticCallout"
import { PanicButton } from "@/components/Health"
import { Button } from "@/components/ui/button"
import {
  logsTail,
  serviceAction,
  type Health,
  type ServiceStatus,
} from "@/lib/bridge"
import { matchDiagnostic } from "@/lib/diagnostics"
import { formatError } from "@/lib/validate"

// The lifecycle the console was missing: whether the tunnel's unit is up, and
// the two buttons that change that. Start/stop go through polkit (or a narrow
// sudoers rule) — the desktop asks, the console never sees a password.

const tone = (active: string) =>
  active === "active" ? "bg-live" : active === "failed" ? "bg-fault" : "bg-stale"

/** A refused start/stop is nearly always a permission, and stderr says so in a
 * form that reads as an error rather than an instruction. The line stays — it is
 * the evidence — and the way past it rides beside it. */
function permissionHint(
  action: "start" | "stop" | "restart",
  message: string,
  unit: string,
): string | undefined {
  if (!/password|polkit|not authorized|access denied|permission|authentication/i.test(message)) {
    return undefined
  }
  return `Nothing changed. Grant this console the installer's sudo rule, or run it yourself: sudo systemctl ${action} ${unit}`
}

/** Run a lifecycle action and report what systemd says afterwards, not intent. */
function useServiceAction(refresh: () => void, unit: string) {
  const [pending, setPending] = useState<string | null>(null)
  const act = async (action: "start" | "stop" | "restart") => {
    setPending(action)
    try {
      const done = await serviceAction(action)
      toast.success(done.message)
    } catch (error) {
      const message = formatError(error)
      const hint = permissionHint(action, message, unit)
      toast.error(message, hint ? { description: hint } : undefined)
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
  attached = false,
}: {
  service: ServiceStatus | null
  onChanged: () => void
  /** The control socket answered: a daemon is running, whatever systemd says. */
  attached?: boolean
}) {
  const unit = service?.unit ?? "vallum@vallum0"
  const { pending, act } = useServiceAction(onChanged, unit)
  // Stopping takes the tunnel away from every user of this machine, so the
  // button asks once, names the effect, and disarms itself after 4 s.
  const [confirmStop, setConfirmStop] = useState(false)
  useEffect(() => {
    if (!confirmStop) return
    const timer = window.setTimeout(() => setConfirmStop(false), 4000)
    return () => window.clearTimeout(timer)
  }, [confirmStop])
  const active = service?.active ?? "unknown"
  // A daemon can run with no unit behind it (a lab, a hand-run process).
  // Offering START for a unit that does not exist is a button that cannot work.
  const noUnit = service?.enabled === "not-found"
  // "unit not running" above a tunnel that is plainly UP reads as a
  // contradiction. When a daemon answers but no unit owns it, say that instead.
  const unmanaged = attached && active !== "active"
  return (
    <span className="flex items-center gap-2">
      <span
        className="flex items-center gap-1.5"
        title={`systemd: ${active}, ${service?.enabled ?? "unknown"}`}
      >
        <span
          aria-hidden
          className={`inline-block size-1.5 rounded-full ${
            unmanaged || noUnit ? "bg-muted-foreground/40" : tone(active)
          }`}
        />
        <span className="micro" title="The systemd unit that owns this tunnel">
          Service:{" "}
          <span className={unmanaged || noUnit ? "text-muted-foreground" : "text-foreground/90"}>
            {noUnit ? "none" : unmanaged ? "unmanaged" : active === "inactive" ? "stopped" : active}
          </span>
        </span>
      </span>
      <Button
        id="service-start-btn"
        size="sm"
        variant="outline"
        className={`h-8 px-3 text-xs font-medium ${active === "active" || noUnit ? "hidden" : ""}`}
        disabled={pending !== null || active === "active" || noUnit}
        title={noUnit ? "No systemd unit owns this interface" : "Start the tunnel service"}
        onClick={() => void act("start")}
      >
        {pending === "start" ? "Starting…" : "Start service"}
      </Button>
      <Button
        id="service-stop-btn"
        size="sm"
        variant="outline"
        className={`relative h-8 overflow-hidden px-3 text-xs font-medium ${
          active !== "active" || noUnit ? "hidden" : ""
        } ${confirmStop ? "border-fault/70 bg-fault/10 text-fault" : ""}`}
        disabled={pending !== null || active !== "active" || noUnit}
        title={
          noUnit
            ? "No systemd unit owns this interface"
            : confirmStop
              ? "Click again within 4s: the tunnel stops and traffic returns to the physical link"
              : "Stops the tunnel; traffic returns to the physical interface"
        }
        onClick={() => {
          if (!confirmStop) {
            setConfirmStop(true)
            return
          }
          setConfirmStop(false)
          void act("stop")
        }}
      >
        {confirmStop && (
          <span
            aria-hidden
            className="animate-countdown bg-fault/60 absolute bottom-0 left-0 h-0.5 w-full"
          />
        )}
        {pending === "stop"
          ? "Stopping…"
          : confirmStop
            ? "Confirm stop · returns to physical link"
            : "Stop service"}
      </Button>
    </span>
  )
}

/** Shown in place of the cockpit when the unit is not running: say so, explain host exit posture, and act. */
export function StoppedCard({
  service,
  health,
  onChanged,
  onOpenDiagnostics,
}: {
  service: ServiceStatus | null
  health?: Health | null
  onChanged: () => void
  onOpenDiagnostics?: (code?: string) => void
}) {
  const unit = service?.unit ?? "vallum@vallum0"
  const { pending, act } = useServiceAction(onChanged, unit)
  const failed = service?.active === "failed"
  const deathDiag = useMemo(() => matchDiagnostic(health?.last_death), [health?.last_death])
  const guardStuck = health?.guard.active === "active"
  const egressStatus = guardStuck
    ? "blocked by vallum-guard"
    : health?.route4
      ? `via ${health.route4} (physical link)`
      : "no default route"

  return (
    <section className="surface animate-in fade-in slide-in-from-bottom-2 flex flex-col gap-3 rounded-xl px-5 py-6 duration-300">
      <div className="flex flex-col gap-1">
        <span className="micro">Tunnel exit state</span>
        <div className="flex flex-wrap items-center gap-3">
          <span
            className={`text-2xl leading-none font-semibold tracking-tight ${
              failed ? "text-fault" : "text-stale"
            }`}
          >
            {failed ? "Tunnel service failed" : "Tunnel service stopped"}
          </span>
          {guardStuck && (
            <span className="bg-fault text-background rounded px-2 py-0.5 font-mono text-xs font-semibold">
              Guard locked · No egress
            </span>
          )}
        </div>
        <span className="text-muted-foreground mt-1 text-xs">
          {unit} is not running. Start the service to bring the tunnel back up, or restore internet if the egress guard is holding traffic.
        </span>
      </div>

      {/* Exit posture & last state matrix */}
      <dl className="border-border/60 bg-background/40 grid grid-cols-1 gap-x-6 gap-y-2 rounded-lg border px-3.5 py-2.5 text-xs sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <dt className="micro">Exit status</dt>
          <dd className={failed ? "text-fault font-medium" : "text-stale font-medium"}>
            {failed ? "Unit failed" : "Clean stop / inactive"}
          </dd>
        </div>
        <div>
          <dt className="micro">Down since</dt>
          <dd className="text-foreground/85">{health?.down_since || "—"}</dd>
        </div>
        <div>
          <dt className="micro">Restarts</dt>
          <dd className={health && health.restarts > 0 ? "text-stale" : "text-foreground/85"}>
            {health ? health.restarts : "—"}
          </dd>
        </div>
        <div>
          <dt className="micro">Current egress</dt>
          <dd className={guardStuck ? "text-fault font-medium" : "text-foreground/85"}>
            {egressStatus}
          </dd>
        </div>
      </dl>

      {health?.last_death && (
        <div className="border-border/60 bg-background/40 rounded-lg border px-3 py-2 text-xs">
          <span className="micro">Last exit signal: </span>
          <span className="text-fault font-mono">{health.last_death}</span>
        </div>
      )}

      {deathDiag && (
        <DiagnosticCallout
          entry={deathDiag}
          detail={health?.last_death || deathDiag.summary}
          onOpenCatalog={onOpenDiagnostics}
        />
      )}

      <div className="mt-1 flex flex-wrap items-center gap-2">
        <Button size="sm" disabled={pending !== null} onClick={() => void act("start")}>
          {pending === "start" ? "Starting…" : "Start tunnel service"}
        </Button>
        {guardStuck && <PanicButton onChanged={onChanged} />}
        {onOpenDiagnostics && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => onOpenDiagnostics(deathDiag?.code)}
          >
            System diagnostics
          </Button>
        )}
      </div>

      <LogsPanel onOpenDiagnostics={onOpenDiagnostics} />
    </section>
  )
}

type LogSeverity = "ALL" | "ERR" | "WARN" | "HANDSHAKE"

const SEVERITY_RE: Record<Exclude<LogSeverity, "ALL">, RegExp> = {
  ERR: /\b(error|err|fatal|panic|failed|sigsys|31\/sys)\b/i,
  WARN: /\b(warn|warning|stale|refused|dropped|timeout)\b/i,
  HANDSHAKE: /\b(handshake|established|listening|ready|rotated|finalized)\b/i,
}

export function LogsPanel({
  onOpenDiagnostics,
}: {
  onOpenDiagnostics?: (code?: string) => void
}) {
  const [text, setText] = useState<string>("")
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [follow, setFollow] = useState(false)
  const [severity, setSeverity] = useState<LogSeverity>("ALL")
  const [lineLimit, setLineLimit] = useState<100 | 300 | 1000>(300)
  const [logFilter, setLogFilter] = useState("")
  const [unit, setUnit] = useState<string>("")

  const load = useCallback(() => {
    logsTail(lineLimit)
      .then((tail) => {
        setUnit(tail.unit)
        setText(tail.lines ?? "")
        setError(tail.error ?? null)
      })
      .catch((cause) => setError(formatError(cause)))
  }, [lineLimit])

  useEffect(() => {
    if (!open) return
    load()
    if (!follow) return
    const timer = window.setInterval(load, 1000)
    return () => window.clearInterval(timer)
  }, [open, follow, load])

  const allLines = useMemo(() => (text ? text.split("\n") : []), [text])
  const counts = useMemo(
    () => ({
      ALL: allLines.length,
      ERR: allLines.filter((line) => SEVERITY_RE.ERR.test(line)).length,
      WARN: allLines.filter((line) => SEVERITY_RE.WARN.test(line)).length,
      HANDSHAKE: allLines.filter((line) => SEVERITY_RE.HANDSHAKE.test(line)).length,
    }),
    [allLines],
  )

  const detectedDiag = useMemo(() => matchDiagnostic(error || text), [error, text])

  const needle = logFilter.trim().toLowerCase()
  const visibleLines = useMemo(() => {
    let list = allLines
    if (severity !== "ALL") {
      list = list.filter((line) => SEVERITY_RE[severity].test(line))
    }
    if (needle) {
      list = list.filter((line) => line.toLowerCase().includes(needle))
    }
    return list
  }, [allLines, severity, needle])

  const lineTone = (line: string) => {
    if (SEVERITY_RE.ERR.test(line)) return "text-fault"
    if (SEVERITY_RE.WARN.test(line)) return "text-stale"
    if (SEVERITY_RE.HANDSHAKE.test(line)) return "text-signal"
    return "text-foreground/80"
  }

  const downloadLog = () => {
    const content = visibleLines.join("\n")
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" })
    const url = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.download = `${(unit || "vallum").replace(/[^a-zA-Z0-9._-]/g, "_")}.log`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  return (
    <details
      id="logs-panel"
      className="surface rounded-xl"
      onToggle={(event) => setOpen((event.currentTarget as HTMLDetailsElement).open)}
    >
      <summary className="text-muted-foreground flex cursor-pointer flex-wrap items-center gap-2 px-4 py-3 text-xs select-none">
        <span className="text-foreground text-sm font-medium">System logs</span>
        <span className="text-muted-foreground font-mono">{unit || "journalctl"}</span>
        {allLines.length > 0 && (
          <span className="text-muted-foreground/75 font-mono text-xs">
            ({visibleLines.length}/{allLines.length} lines)
          </span>
        )}
        <span className="ml-auto flex flex-wrap items-center gap-1.5">
          <Button
            size="sm"
            variant={follow ? "secondary" : "ghost"}
            className="h-7 gap-1.5 px-2.5 text-xs font-medium"
            title="Live-tail unit logs every 1s"
            onClick={(event) => {
              event.preventDefault()
              setFollow((f) => !f)
            }}
          >
            {follow && (
              <span aria-hidden className="bg-live inline-block size-1.5 animate-pulse rounded-full" />
            )}
            {follow ? "Following" : "Follow"}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2.5 text-xs font-medium"
            onClick={(event) => {
              event.preventDefault()
              load()
            }}
          >
            Refresh
          </Button>
        </span>
      </summary>

      {error && /not authorized|permission|access denied|insufficient/i.test(error) && (
        <p className="text-stale px-4 pt-2 text-xs">
          System logs are restricted to members of the <code className="font-mono">systemd-journal</code> group on this host.
        </p>
      )}

      {detectedDiag && (
        <div className="px-4 pb-2">
          <DiagnosticCallout entry={detectedDiag} onOpenCatalog={onOpenDiagnostics} />
        </div>
      )}

      {!error && (
        <div className="border-border/70 flex flex-wrap items-center gap-2 border-t px-4 py-2.5">
          <div
            role="group"
            aria-label="Filter by log severity"
            className="border-border/70 bg-background/40 inline-flex rounded-md border p-0.5 text-xs"
          >
            {(
              [
                ["ALL", "All"],
                ["ERR", "Errors"],
                ["WARN", "Warnings"],
                ["HANDSHAKE", "Handshakes"],
              ] as const
            ).map(([level, label]) => (
              <button
                key={level}
                type="button"
                aria-pressed={severity === level}
                onClick={() => setSeverity(level)}
                className={`min-h-0 cursor-pointer rounded px-2.5 py-0.5 text-xs font-medium transition-colors ${
                  severity === level
                    ? "bg-secondary text-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {label} ({counts[level]})
              </button>
            ))}
          </div>

          <input
            value={logFilter}
            onChange={(event) => setLogFilter(event.target.value)}
            placeholder="Filter logs"
            aria-label="Filter log lines"
            className="border-border/60 bg-background/40 text-foreground placeholder:text-muted-foreground/70 min-w-[160px] flex-1 rounded-md border px-2.5 py-1 text-xs"
          />

          <select
            aria-label="Log line limit"
            value={lineLimit}
            onChange={(event) => setLineLimit(Number(event.target.value) as 100 | 300 | 1000)}
            className="border-border/60 bg-background/40 text-foreground rounded-md border px-2 py-1 font-mono text-xs"
          >
            <option value={100}>100 lines</option>
            <option value={300}>300 lines</option>
            <option value={1000}>1000 lines</option>
          </select>

          <CopyButton
            value={visibleLines.join("\n")}
            label="Copy logs"
            disabled={visibleLines.length === 0}
          />
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={visibleLines.length === 0}
            onClick={downloadLog}
          >
            Download .log
          </Button>
        </div>
      )}

      <div className="border-border/70 max-h-64 overflow-auto border-t px-3 py-2 font-mono text-xs leading-relaxed">
        {error ? (
          <pre className="text-fault whitespace-pre-wrap">journald: {error}</pre>
        ) : visibleLines.length === 0 ? (
          <p className="text-muted-foreground">
            {needle || severity !== "ALL"
              ? `no ${severity === "ALL" ? "" : `${severity} `}lines matching "${logFilter || severity}"`
              : "no output"}
          </p>
        ) : (
          visibleLines.map((line, index) => (
            <div key={index} className={`whitespace-pre-wrap break-words ${lineTone(line)}`}>
              {line || " "}
            </div>
          ))
        )}
      </div>
    </details>
  )
}
