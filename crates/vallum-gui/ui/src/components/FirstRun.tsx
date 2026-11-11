import { useEffect, useState } from "react"
import { preflight, type Preflight } from "@/lib/bridge"
import { CopyButton } from "@/components/Copy"
import { Panel } from "@/components/ui/panel"

// The first thing a new operator sees. It answers three questions with facts
// read off the host: is it installed, is anything running, and what is the next
// single step. Nothing here changes the network; the commands are shown, not run.

type Step = {
  title: string
  detail: string
  command: string
  done: boolean
}

function stepsFor(preflight: Preflight | null): Step[] {
  if (!preflight) return []
  const installed = preflight.vallum && preflight.quick
  return [
    {
      title: "install",
      detail: "binaries, units, the socket directory and the recovery tools — preview it first with --dry-run",
      command: "sudo scripts/install.sh --local --install-only",
      done: installed && preflight.unit && preflight.panic,
    },
    {
      title: "join a server",
      detail: "paste the ticket the server printed with `vallum peer invite <name>`",
      command: "sudo vallum join <ticket>",
      // The join writes the config and its key; a config we cannot see still
      // counts as present (the file may be root-only and that is correct).
      done: preflight.config !== false,
    },
    {
      title: "start the tunnel",
      detail: "systemd owns it; the console's START does the same thing",
      command: "sudo systemctl start vallum@vallum0",
      done: preflight.sockets > 0,
    },
  ]
}

export function FirstRun({ facts: given }: { facts?: Preflight | null }) {
  const [fetched, setFacts] = useState<Preflight | null>(null)
  useEffect(() => {
    if (given !== undefined) return
    preflight()
      .then(setFacts)
      .catch(() => setFacts(null))
  }, [given])
  const facts = given !== undefined ? given : fetched
  const steps = stepsFor(facts)
  const next = steps.find((step) => !step.done)

  return (
    <section className="flex flex-col gap-3">
      <Panel title="NO TUNNEL ON THIS MACHINE">
        <p className="text-muted-foreground max-w-2xl text-xs">
          Nothing here has been changed by opening this page. Below is what is
          installed and the step to take next.
        </p>

        <ul className="mt-3 flex flex-col gap-2">
          {steps.map((step, index) => (
            <li
              key={step.command}
              className={`flex items-start gap-2 rounded-md border px-2.5 py-2 ${
                step.done
                  ? "border-live/30 bg-live/5"
                  : step === next
                    ? "border-signal/40 bg-signal/5"
                    : "border-border/60"
              }`}
            >
              <span
                className={`mt-0.5 text-[10px] ${step.done ? "text-live" : step === next ? "text-signal" : "text-muted-foreground"}`}
              >
                {step.done ? "done" : `${index + 1}`}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-foreground/90 text-xs">{step.title}</p>
                <p className="text-muted-foreground text-[10px]">{step.detail}</p>
                <div className="mt-1 flex items-center gap-2">
                  <code className="text-foreground/80 truncate font-mono text-[11px]">
                    {step.command}
                  </code>
                  <CopyButton value={step.command} label="copy" />
                </div>
              </div>
            </li>
          ))}
        </ul>

        <p className="text-muted-foreground mt-3 text-[10px]">
          A full tunnel is opt-in and reversible: <code>scripts/trial.sh --dry-run</code>{" "}
          shows what it would change, and <code>vallum-panic</code> undoes it.
        </p>
      </Panel>

      <Panel title="WHAT THIS HOST HAS">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-[11px] sm:grid-cols-3">
          {[
            ["vallum binary", facts?.vallum],
            ["vallum-quick", facts?.quick],
            ["systemd unit", facts?.unit],
            ["config file", facts?.config],
            ["restore tool", facts?.panic],
            ["dead-man", facts?.deadman],
          ].map(([label, present]) => (
            <div key={String(label)} className="flex items-baseline justify-between gap-2">
              <dt className="text-muted-foreground">{String(label)}</dt>
              <dd className={present === null ? "text-muted-foreground" : present ? "text-live" : "text-stale"}>
                {facts === null ? "…" : present === null ? "not readable" : present ? "yes" : "no"}
              </dd>
            </div>
          ))}
        </dl>
        <p className="text-muted-foreground mt-2 text-[10px]">
          socket directory {facts?.runtime_dir ?? "—"} · mode{" "}
          {facts?.runtime_mode ?? "—"} · {facts?.sockets ?? 0} socket(s)
        </p>
        {facts && facts.runtime_mode !== "absent" && !["0770", "0775", "0777"].includes(facts.runtime_mode) && (
          <p className="text-stale mt-1 text-[10px]">
            the socket directory is {facts.runtime_mode}: a daemon that drops privileges
            cannot publish its socket there. <code>scripts/install.sh</code> sets 0770
            with the right group.
          </p>
        )}
      </Panel>
    </section>
  )
}
