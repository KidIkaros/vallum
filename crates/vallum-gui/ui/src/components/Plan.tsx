import { useCallback, useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { applyPlan, cancelApply, getPlan, revertPlan, type PlanData } from "@/lib/bridge"
import { Button } from "@/components/ui/button"
import { formatError } from "@/lib/validate"

// Plan-before-apply: the panel shows exactly what the full tunnel will change
// on this host and the one command that undoes it, and the apply button stays
// disarmed until the operator types APPLY. The output of the trial script is
// shown verbatim — its verdict is the truth, not ours.
export function PlanPanel({ onChanged }: { onChanged?: () => void }) {
  const [plan, setPlan] = useState<PlanData | null>(null)
  const [confirm, setConfirm] = useState("")
  const [output, setOutput] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // The trial itself cannot be recalled once handed to the root-owned script
  // (it owns its own revert timer), but the console must not trap the
  // operator for 2–3 min: stopping the wait leaves the trial running safely
  // in the background and its output lands here when it finishes.
  const [backgrounded, setBackgrounded] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  // Two-step destructive confirm, mirroring the header's stop button: the
  // first click arms, the second commits, and the arm dies after 4 s.
  const [confirmCancel, setConfirmCancel] = useState(false)
  useEffect(() => {
    if (!confirmCancel) return
    const timer = window.setTimeout(() => setConfirmCancel(false), 4000)
    return () => window.clearTimeout(timer)
  }, [confirmCancel])
  const running = useRef(false)
  const stopWaiting = useRef(false)
  // Guards the apply/cancel race: a late apply verdict after a cancel must
  // not overwrite the revert's output.
  const runId = useRef(0)
  // The trial runs for minutes — past the ~10 s attention limit a bare label
  // reads as a hang. The elapsed seconds are the feedback that it is working.
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (!busy) return
    const timer = window.setInterval(() => setElapsed((s) => s + 1), 1000)
    return () => window.clearInterval(timer)
  }, [busy])
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    getPlan()
      .then(setPlan)
      .catch(() => setPlan(null))
  }, [])

  useEffect(load, [load])

  const armed = confirm.trim().toUpperCase() === "APPLY"

  const run = useCallback(() => {
    if (!armed || running.current) return
    const id = ++runId.current
    running.current = true
    stopWaiting.current = false
    setBusy(true)
    setElapsed(0)
    setBackgrounded(false)
    setConfirmCancel(false)
    setError(null)
    void applyPlan("APPLY")
      .then((result) => {
        if (runId.current !== id) return
        setOutput(result.output)
        setConfirm("")
        onChanged?.()
        if (stopWaiting.current) {
          toast.success("The trial finished — its output is in the panel below.")
        }
      })
      .catch((e) => {
        if (runId.current !== id) return
        const message = formatError(e)
        if (stopWaiting.current) {
          toast.error(message, { duration: 8000 })
        } else {
          setError(message)
        }
      })
      .finally(() => {
        if (runId.current !== id) return
        running.current = false
        stopWaiting.current = false
        setBusy(false)
        setBackgrounded(false)
      })
  }, [armed, onChanged])

  // The real cancel: runs the documented undo (guard off, split config back,
  // unit left running) instead of merely looking away. Late apply verdicts
  // are invalidated by the run id above.
  const cancel = useCallback(() => {
    if (!running.current || cancelling) return
    if (!confirmCancel) {
      setConfirmCancel(true)
      return
    }
    setConfirmCancel(false)
    setCancelling(true)
    runId.current++
    void cancelApply()
      .then((result) => {
        setOutput(result.output || "reverted to the split tunnel")
        setConfirm("")
        setError(null)
        toast.success("Trial stopped — back on the split tunnel.")
        onChanged?.()
      })
      .catch((e) => {
        const message = formatError(e)
        setError(message)
        toast.error(message, { duration: 8000 })
      })
      .finally(() => {
        running.current = false
        stopWaiting.current = false
        setBusy(false)
        setBackgrounded(false)
        setCancelling(false)
      })
  }, [cancelling, confirmCancel, onChanged])

  const stop = useCallback(() => {
    // Stop waiting, not the trial: the script keeps its own revert timer and
    // finishes on the machine; this only frees the console immediately.
    stopWaiting.current = true
    setBusy(false)
    setBackgrounded(true)
  }, [])

  // Applied stays collapsed: a healthy full tunnel should not spend a panel's
  // worth of attention on saying so. But the way back is here, not only in a
  // terminal: reverting restarts the tunnel, so it takes the same typed word
  // the apply took — the confirmation is the deliberation.
  const revertArmed = confirm.trim().toUpperCase() === "REVERT"
  const revert = useCallback(() => {
    if (!revertArmed || running.current) return
    running.current = true
    setBusy(true)
    setError(null)
    void revertPlan("REVERT")
      .then((result) => {
        setOutput(result.output)
        setConfirm("")
        onChanged?.()
        load()
        toast.success("Full tunnel reverted — back on the split tunnel.")
      })
      .catch((e) => {
        setError(formatError(e))
      })
      .finally(() => {
        running.current = false
        setBusy(false)
      })
  }, [revertArmed, load, onChanged])

  if (!plan) return null

  if (plan.already_full) {
    return (
      <details className="surface rounded-xl">
        <summary className="text-muted-foreground flex cursor-pointer items-center gap-2 px-5 py-3 text-xs select-none">
          <span className="text-foreground text-sm font-medium">Full tunnel</span>
          <span>Already active — open to revert to Split Tunnel</span>
        </summary>
        <div className="px-5 pb-4">
          <p className="text-muted-foreground mb-2 text-xs leading-snug">
            Reverting restarts the tunnel back into Split Tunnel mode. Type <code className="font-mono">REVERT</code> to confirm.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Type REVERT"
              disabled={busy}
              className="border-border/60 bg-background/40 h-8 w-40 rounded-md border px-2.5 font-mono text-xs placeholder:text-muted-foreground/70"
              spellCheck={false}
            />
            <Button
              size="sm"
              variant="outline"
              disabled={!revertArmed || busy}
              onClick={() => revert()}
              title="Restore the split config and restart the tunnel"
            >
              {busy ? `Reverting… ${elapsed}s` : "Revert to split tunnel"}
            </Button>
          </div>
          {error && <p className="text-fault mt-2 text-xs">{error}</p>}
          {output && (
            <pre className="border-border bg-canvas text-muted-foreground mt-2 max-h-48 overflow-auto rounded-md border p-2 font-mono text-xs leading-snug whitespace-pre-wrap">
              {output}
            </pre>
          )}
        </div>
      </details>
    )
  }

  return (
    <details className="surface rounded-xl" open={busy || backgrounded || Boolean(output) || Boolean(error)}>
      <summary className="text-muted-foreground flex cursor-pointer items-center justify-between gap-2 px-5 py-3 text-xs select-none">
        <span className="flex items-center gap-2">
          <span className="text-foreground text-sm font-medium">Full-tunnel rollout</span>
          <span>Preview &amp; apply host routing changes</span>
        </span>
        <span className="text-muted-foreground/80 text-[11px]">Expand</span>
      </summary>
      <div className="px-5 pb-4 pt-1">
          <ul className="mb-2 flex flex-col gap-1">
            {plan.steps.map((step) => (
              <li key={step.step} className="text-xs leading-snug">
                <span className="text-foreground font-medium">{step.step}</span>
                <span className="text-muted-foreground"> — {step.change}</span>
              </li>
            ))}
          </ul>
          <details className="text-muted-foreground mb-2 text-xs">
            <summary className="hover:text-foreground cursor-pointer select-none">
              Manual terminal undo command
            </summary>
            <div className="mt-1">{render_undo(plan.undo)}</div>
          </details>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Type APPLY to arm"
              disabled={busy}
              className="border-border/60 bg-background/40 h-8 w-40 rounded-md border px-2.5 font-mono text-xs placeholder:text-muted-foreground/70"
              spellCheck={false}
            />
            <Button
              size="sm"
              disabled={!armed || busy}
              onClick={() => run()}
              title="Arms the trial: revert timer first, then the routes. Any failed check reverts automatically."
            >
              {busy ? `Running trial… ${elapsed}s (2–3 min)` : "Apply full tunnel"}
            </Button>
            {(busy || backgrounded) && (
              <Button
                size="sm"
                variant="outline"
                disabled={cancelling}
                onClick={cancel}
                title={
                  confirmCancel
                    ? "Click again: panic, restore the split config, restart the unit"
                    : "Stop the trial now and converge back on the split tunnel"
                }
                className={confirmCancel ? "border-fault/60 text-fault" : ""}
              >
                {cancelling ? "Reverting…" : confirmCancel ? "Confirm: stop and revert?" : "Stop and revert"}
              </Button>
            )}
            {busy && !backgrounded && (
              <button
                onClick={stop}
                className="text-muted-foreground hover:text-foreground cursor-pointer rounded text-xs underline-offset-2 hover:underline"
                title="Hide this wait — the trial keeps running with its own revert timer; the output lands here when it finishes."
              >
                Hide wait
              </button>
            )}
          </div>
          {backgrounded && (
            <p className="text-muted-foreground mt-2 text-xs">
              Still running on this machine — it reverts itself if a check fails. The output will appear below when it finishes, or stop it now with the revert above.
            </p>
          )}
          {error && <p className="text-fault mt-2 text-xs">{error}</p>}
          {output && (
            <pre className="border-border bg-canvas text-muted-foreground mt-2 max-h-48 overflow-auto rounded border p-2 font-mono text-xs leading-snug whitespace-pre-wrap">
              {output}
            </pre>
          )}
      </div>
    </details>
  )
}

// The undo command is long; wrap it readably instead of letting it push layout.
function render_undo(undo: string) {
  return <span className="text-foreground/80 break-all font-mono">{undo}</span>
}
