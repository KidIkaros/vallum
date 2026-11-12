import { useEffect, useState } from "react"
import { preflight, type Preflight } from "@/lib/bridge"
import { CopyButton } from "@/components/Copy"
import { Panel } from "@/components/ui/panel"

// The first thing a new operator sees. It answers three questions with facts
// read off the host: is it installed, is anything running, and what is the next
// single step. Nothing here changes the network; the commands are shown, not run.

/** The console asks the host what is installed. When that fails, say which
 * failure it is: the operator's next step is different. */
function HostUnreadable({ onRetry }: { onRetry?: () => void }) {
  const command = "./target/release/vallum-gui --serve 7317"
  return (
    <Panel title="COULD NOT READ THIS HOST">
      <p className="text-muted-foreground max-w-2xl text-xs">
        The console's helper did not answer, so nothing here can say what this
        machine has installed. That is not the same as a bare machine, and the
        install steps would be a guess.
      </p>
      <p className="text-muted-foreground mt-2 max-w-2xl text-xs">
        Reload the page. If it stays empty, run the console from a terminal and
        read what it prints:
      </p>
      <div className="mt-1 flex items-center gap-2">
        <code className="text-foreground/80 truncate font-mono text-xs">{command}</code>
        <CopyButton value={command} label="copy" />
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="text-signal mt-3 cursor-pointer text-xs uppercase"
        >
          try again
        </button>
      )}
    </Panel>
  )
}

/** A socket exists and this user can open none of them. The tunnel may be running
 * fine — the console is the thing that cannot see it — so the copy names the
 * permissions and the installer that sets them, not the tunnel. */
export function SocketUnreadable({
  facts,
  onRetry,
}: {
  facts: Preflight
  onRetry?: () => void
}) {
  const command = "sudo scripts/install.sh --local --install-only"
  return (
    <Panel title="CONTROL SOCKET UNREADABLE">
      <p className="text-muted-foreground max-w-2xl text-xs">
        {facts.sockets} control socket{facts.sockets === 1 ? "" : "s"} in{" "}
        <code className="text-foreground/80 font-mono">{facts.runtime_dir}</code> — and this
        user can open none of them. The tunnel may be running fine; the console is
        what cannot see it.
      </p>
      <p className="text-muted-foreground mt-2 max-w-2xl text-xs">
        The directory is{" "}
        <code className="text-foreground/80 font-mono">{facts.runtime_mode}</code>. A daemon
        that drops privileges publishes its socket for the installer's group, which
        sets 0770 — so the repair is the installer's own rule:
      </p>
      <div className="mt-1 flex items-center gap-2">
        <code className="text-foreground/80 truncate font-mono text-xs">{command}</code>
        <CopyButton value={command} label="copy" />
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="text-signal mt-3 cursor-pointer text-xs uppercase"
        >
          check again
        </button>
      )}
    </Panel>
  )
}

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
      title: "serve others",
      detail: "turn this machine into a server peers join — the TUI's `1` setup, as a copyable command",
      command: "sudo vallum setup --server",
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

export function FirstRun({
  facts: given,
  onRetry,
}: {
  facts?: Preflight | null
  onRetry?: () => void
}) {
  const [fetched, setFacts] = useState<Preflight | null>(null)
  useEffect(() => {
    if (given !== undefined) return
    preflight()
      .then(setFacts)
      .catch(() => setFacts(null))
  }, [given])
  const facts = given !== undefined ? given : fetched
  // A helper that did not answer is not a machine with nothing installed: the
  // steps below are read off the host, so without them there is nothing to say.
  if (facts === null) return <HostUnreadable onRetry={onRetry} />
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
                className={`mt-0.5 text-xs ${step.done ? "text-live" : step === next ? "text-signal" : "text-muted-foreground"}`}
              >
                {step.done ? "done" : `${index + 1}`}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-foreground/90 text-xs">{step.title}</p>
                <p className="text-muted-foreground text-xs">{step.detail}</p>
                <div className="mt-1 flex items-center gap-2">
                  <code className="text-foreground/80 truncate font-mono text-xs">
                    {step.command}
                  </code>
                  <CopyButton value={step.command} label="copy" />
                </div>
              </div>
            </li>
          ))}
        </ul>

        <p className="text-muted-foreground mt-3 text-xs">
          A full tunnel is opt-in and reversible: <code>scripts/trial.sh --dry-run</code>{" "}
          shows what it would change, and <code>vallum-panic</code> undoes it.
        </p>
      </Panel>

      <Panel title="WHAT THIS HOST HAS">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
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
        <p className="text-muted-foreground mt-2 text-xs">
          socket directory {facts?.runtime_dir ?? "—"} · mode{" "}
          {facts?.runtime_mode ?? "—"} · {facts?.sockets ?? 0} socket(s)
        </p>
        {facts && facts.runtime_mode !== "absent" && !["0770", "0775", "0777"].includes(facts.runtime_mode) && (
          <p className="text-stale mt-1 text-xs">
            the socket directory is {facts.runtime_mode}: a daemon that drops privileges
            cannot publish its socket there. <code>scripts/install.sh</code> sets 0770
            with the right group.
          </p>
        )}
      </Panel>
    </section>
  )
}
