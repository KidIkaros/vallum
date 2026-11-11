import { useCallback, useEffect, useState } from "react"
import { applyPlan, getPlan, type PlanData } from "@/lib/bridge"
import { Button } from "@/components/ui/button"
import { Panel } from "@/components/ui/panel"

// Plan-before-apply: the panel shows exactly what the full tunnel will change
// on this host and the one command that undoes it, and the apply button stays
// disarmed until the operator types APPLY. The output of the trial script is
// shown verbatim — its verdict is the truth, not ours.
export function PlanPanel({ onChanged }: { onChanged?: () => void }) {
  const [plan, setPlan] = useState<PlanData | null>(null)
  const [confirm, setConfirm] = useState("")
  const [output, setOutput] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // The trial runs for minutes — past the ~10 s attention limit a bare label
  // reads as a hang. The elapsed seconds are the feedback that it is working.
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (!busy) return
    setElapsed(0)
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

  const run = useCallback(async () => {
    if (!armed || busy) return
    setBusy(true)
    setError(null)
    try {
      const result = await applyPlan("APPLY")
      setOutput(result.output)
      setConfirm("")
      onChanged?.()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }, [armed, busy, onChanged])

  if (!plan) return null

  return (
    <Panel title="◆ FULL TUNNEL — PLAN BEFORE APPLY">
      {plan.already_full ? (
        <p className="text-muted-foreground py-2 text-xs">
          the selected interface is already full-tunnel — nothing to apply
        </p>
      ) : (
        <>
          <ul className="mb-2 flex flex-col gap-1">
            {plan.steps.map((step) => (
              <li key={step.step} className="text-[11px] leading-snug">
                <span className="text-foreground">{step.step}</span>
                <span className="text-muted-foreground"> — {step.change}</span>
              </li>
            ))}
          </ul>
          <p className="text-muted-foreground mb-2 text-[10px] leading-snug">
            undo it all:{render_undo(plan.undo)}
          </p>
          <div className="flex items-center gap-2">
            <input
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="type APPLY to arm"
              className="border-border bg-canvas h-7 w-40 rounded border px-2 font-mono text-[11px] placeholder:text-muted-foreground/60"
              spellCheck={false}
            />
            <Button
              size="sm"
              disabled={!armed || busy}
              onClick={() => void run()}
              title="Arms the trial: revert timer first, then the routes. Any failed check reverts automatically."
            >
              {busy ? `running the trial… ${elapsed}s (usually 2–3 min)` : "apply full tunnel"}
            </Button>
          </div>
          {error && <p className="text-fault mt-2 text-[11px]">{error}</p>}
          {output && (
            <pre className="border-border bg-canvas text-muted-foreground mt-2 max-h-48 overflow-auto rounded border p-2 font-mono text-[10px] leading-snug whitespace-pre-wrap">
              {output}
            </pre>
          )}
        </>
      )}
    </Panel>
  )
}

// The undo command is long; wrap it readably instead of letting it push layout.
function render_undo(undo: string) {
  return <span className="text-foreground/80 break-all font-mono">{undo}</span>
}
