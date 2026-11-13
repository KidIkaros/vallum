import { useEffect, useState } from "react"
import { CryptoArchitecture } from "@/components/BrandVisuals"
import { CopyButton } from "@/components/Copy"
import { DiagnosticCallout } from "@/components/DiagnosticCallout"
import { Button } from "@/components/ui/button"
import { Panel } from "@/components/ui/panel"
import { preflight, type Preflight } from "@/lib/bridge"
import { ERROR_CATALOG } from "@/lib/diagnostics"

// The first thing a new operator sees. It answers three questions with facts
// read off the host: is it installed, is anything running, and what is the next
// single step. Nothing here changes the network; the commands are shown, not run.

type RoleFocus = "client" | "server" | "all"

/** The console asks the host what is installed. When that fails, say which
 * failure it is: the operator's next step is different. */
function HostUnreadable({
  onRetry,
  onOpenCatalog,
}: {
  onRetry?: () => void
  onOpenCatalog?: (code?: string) => void
}) {
  const command = "./target/release/vallum-gui --serve 7317"
  const e103 = ERROR_CATALOG.find((e) => e.code === "VAL-E103")
  return (
    <Panel title="Could not read host state">
      <p className="text-muted-foreground max-w-2xl text-xs">
        The console&apos;s helper did not answer, so nothing here can say what this
        machine has installed. That is not the same as a bare machine, and the
        install steps would be a guess.
      </p>
      <p className="text-muted-foreground mt-2 max-w-2xl text-xs">
        Reload the page, or check that the local console backend is running.
      </p>
      <details className="border-border/60 bg-background/40 mt-3 max-w-xl rounded-lg border px-3 py-2 text-xs">
        <summary className="text-muted-foreground hover:text-foreground cursor-pointer select-none">
          Headless terminal fallback
        </summary>
        <div className="mt-2 flex items-center gap-2">
          <code className="text-foreground/85 truncate font-mono text-xs">{command}</code>
          <CopyButton value={command} label="Copy" />
        </div>
      </details>
      {e103 && (
        <DiagnosticCallout
          entry={e103}
          detail="Host preflight bridge timed out or no daemon runtime answered."
          onOpenCatalog={onOpenCatalog}
        />
      )}
      {onRetry && (
        <Button type="button" size="sm" variant="outline" onClick={onRetry} className="mt-3">
          Try again
        </Button>
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
  onOpenCatalog,
}: {
  facts: Preflight
  onRetry?: () => void
  onOpenCatalog?: (code?: string) => void
}) {
  const command = "sudo scripts/install.sh --local --install-only"
  const e102 = ERROR_CATALOG.find((e) => e.code === "VAL-E102")
  return (
    <Panel title="Control socket permission required">
      <p className="text-muted-foreground max-w-2xl text-xs">
        {facts.sockets} control socket{facts.sockets === 1 ? "" : "s"} in{" "}
        <code className="text-foreground/80 font-mono">{facts.runtime_dir}</code> — and this
        user can open none of them. The tunnel may be running fine; the console is
        what cannot see it.
      </p>
      <p className="text-muted-foreground mt-2 max-w-2xl text-xs">
        The directory is{" "}
        <code className="text-foreground/80 font-mono">{facts.runtime_mode}</code>. A daemon
        that drops privileges publishes its socket for the installer&apos;s group, which
        sets <code className="font-mono">0770</code> permissions.
      </p>
      <details className="border-border/60 bg-background/40 mt-3 max-w-xl rounded-lg border px-3 py-2 text-xs">
        <summary className="text-muted-foreground hover:text-foreground cursor-pointer select-none">
          Headless terminal repair command
        </summary>
        <div className="mt-2 flex items-center gap-2">
          <code className="text-foreground/85 truncate font-mono text-xs">{command}</code>
          <CopyButton value={command} label="Copy" />
        </div>
      </details>
      {e102 && (
        <DiagnosticCallout
          entry={e102}
          detail={`Socket dir ${facts.runtime_dir} is mode ${facts.runtime_mode}; current user cannot open sockets inside it.`}
          onOpenCatalog={onOpenCatalog}
        />
      )}
      {onRetry && (
        <Button type="button" size="sm" variant="outline" onClick={onRetry} className="mt-3">
          Check again
        </Button>
      )}
    </Panel>
  )
}

type Step = {
  id: string
  role: "both" | "client" | "server"
  title: string
  detail: string
  command: string
  actionLabel?: string
  triggerId?: string
  done: boolean
}

function stepsFor(preflight: Preflight | null): Step[] {
  if (!preflight) return []
  const installed = preflight.vallum && preflight.quick
  return [
    {
      id: "install",
      role: "both",
      title: "Install Vallum binaries, systemd units & recovery tools",
      detail: "Installs the VPN daemon, routing helper, emergency panic tool, deadman switch, and runtime permissions.",
      command: "sudo scripts/install.sh --local --install-only",
      done: installed && preflight.unit && preflight.panic,
    },
    {
      id: "join",
      role: "client",
      title: "Join a server by importing a bundle or invite",
      detail: "Import a .vallum-bundle file from your host or enter the server's public key and endpoint in the Devices view.",
      command: "sudo vallum join <ticket>",
      actionLabel: "Import Bundle…",
      triggerId: "import-bundle-btn",
      done: preflight.config !== false,
    },
    {
      id: "server",
      role: "server",
      title: "Configure this machine as a host",
      detail: "Set the local VPN subnet, Full vs Split tunnel egress, DNS, and invite remote devices via QR or ticket.",
      command: "sudo vallum setup --server",
      actionLabel: "Edit Network Settings…",
      triggerId: "interface-form-btn",
      done: preflight.config !== false,
    },
    {
      id: "invite",
      role: "server",
      title: "Invite a client device",
      detail: "Mint a short-lived QR code or join ticket for a laptop, phone, or remote peer.",
      command: "sudo vallum peer invite <name>",
      actionLabel: "Invite Device (QR / Ticket)…",
      triggerId: "invite-peer-btn",
      done: false,
    },
    {
      id: "start",
      role: "both",
      title: "Start the tunnel service",
      detail: "Activates the background service and publishes the local 0600 control socket.",
      command: "sudo systemctl start vallum@vallum0",
      actionLabel: "Start service",
      triggerId: "service-start-btn",
      done: preflight.sockets > 0,
    },
  ]
}

export function FirstRun({
  facts: given,
  onRetry,
  embedded = false,
  onOpenCatalog,
}: {
  facts?: Preflight | null
  onRetry?: () => void
  embedded?: boolean
  onOpenCatalog?: (code?: string) => void
}) {
  const [fetched, setFacts] = useState<Preflight | null>(null)
  const [role, setRole] = useState<RoleFocus>("client")

  useEffect(() => {
    if (given !== undefined) return
    preflight()
      .then(setFacts)
      .catch(() => setFacts(null))
  }, [given])

  const facts = given !== undefined ? given : fetched
  // A helper that did not answer is not a machine with nothing installed: the
  // steps below are read off the host, so without them there is nothing to say.
  if (facts === null) return <HostUnreadable onRetry={onRetry} onOpenCatalog={onOpenCatalog} />

  const steps = stepsFor(facts)
  const visibleSteps = steps.filter(
    (s) => role === "all" || s.role === "both" || s.role === role,
  )
  const next = visibleSteps.find((step) => !step.done)

  const readinessItems = [
    ["vallum binary", facts.vallum],
    ["vallum-quick", facts.quick],
    ["systemd unit", facts.unit],
    ["config file", facts.config],
    ["restore tool", facts.panic],
    ["dead-man", facts.deadman],
  ] as const

  const readyCount = readinessItems.filter(([, present]) => present === true).length
  const readinessPct = Math.round((readyCount / readinessItems.length) * 100)

  return (
    <section className="animate-in fade-in slide-in-from-bottom-2 flex flex-col gap-3 duration-500">
      {!embedded && (
        <Panel title="Vallum setup overview">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            <div className="flex flex-col justify-between gap-2 lg:col-span-6">
              <div>
                <p className="text-foreground text-sm font-medium">
                  Post-quantum Layer-3 VPN
                </p>
                <p className="text-muted-foreground mt-1 text-xs leading-relaxed">
                  Nothing on this screen alters routes or firewall rules automatically. Inspect host readiness below, choose whether this machine joins a server or hosts peers, and complete the highlighted step.
                </p>
              </div>
            </div>
            <div className="lg:col-span-6">
              <CryptoArchitecture suite="0x0003" />
            </div>
          </div>
        </Panel>
      )}

      <Panel title="Setup guide">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div
            role="group"
            aria-label="Choose host role"
            className="border-border/70 bg-background/50 inline-flex flex-wrap rounded-lg border p-0.5 text-xs"
          >
            {(
              [
                ["client", "Join a Server (Client)"],
                ["server", "Host Peers (Server)"],
                ["all", "All Steps"],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                aria-pressed={role === id}
                onClick={() => setRole(id)}
                className={`min-h-0 cursor-pointer rounded-md px-3 py-1 font-medium transition-colors ${
                  role === id
                    ? "bg-secondary text-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="micro">
              Host readiness{" "}
              <span className="text-foreground font-mono font-medium">
                {readyCount}/{readinessItems.length}
              </span>
            </span>
            <div className="bg-muted h-1.5 w-24 overflow-hidden rounded-full">
              <div
                className="bg-live h-full transition-all duration-300"
                style={{ width: `${readinessPct}%` }}
              />
            </div>
          </div>
        </div>

        <ul className="flex flex-col gap-2">
          {visibleSteps.map((step) => {
            const triggerEl =
              embedded && step.triggerId && typeof document !== "undefined"
                ? document.getElementById(step.triggerId)
                : null
            return (
              <li
                key={step.id}
                className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border px-3.5 py-2.5 transition-colors ${
                  step.done
                    ? "border-live/30 bg-live/5"
                    : step === next
                      ? "border-signal/40 bg-signal/5"
                      : "border-border/60 bg-background/30"
                }`}
              >
                <div className="flex min-w-0 flex-1 items-start gap-2.5">
                  <span
                    className={`mt-0.5 shrink-0 rounded px-2 py-0.5 text-xs font-medium ${
                      step.done
                        ? "bg-live/15 text-live"
                        : step === next
                          ? "bg-signal/15 text-signal"
                          : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {step.done ? "Ready" : step === next ? "Next step" : "Pending"}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-foreground text-xs font-medium">{step.title}</p>
                    <p className="text-muted-foreground mt-0.5 text-xs">{step.detail}</p>
                  </div>
                </div>
                {step.actionLabel && step.triggerId && triggerEl && (
                  <Button
                    type="button"
                    size="sm"
                    variant={step === next ? "default" : "outline"}
                    onClick={() => document.getElementById(step.triggerId!)?.click()}
                  >
                    {step.actionLabel}
                  </Button>
                )}
              </li>
            )
          })}
        </ul>

        <details className="border-border/60 bg-background/35 mt-3 rounded-lg border px-3 py-2 text-xs">
          <summary className="text-muted-foreground hover:text-foreground cursor-pointer font-medium select-none">
            Headless terminal commands (optional)
          </summary>
          <p className="text-muted-foreground mt-2 leading-relaxed">
            On a remote SSH host without a desktop session, copy the corresponding terminal commands:
          </p>
          <ul className="mt-2 flex flex-col gap-1.5">
            {visibleSteps.map((step) => (
              <li
                key={step.id}
                className="border-border/50 bg-background/50 flex items-center justify-between gap-2 rounded border px-2.5 py-1.5"
              >
                <div className="min-w-0">
                  <span className="text-muted-foreground block text-[11px]">{step.title}</span>
                  <code className="text-signal truncate font-mono text-xs">{step.command}</code>
                </div>
                <CopyButton value={step.command} label="Copy" />
              </li>
            ))}
          </ul>
          <p className="text-muted-foreground mt-2 text-xs">
            Full tunnel changes are reversible: <code className="font-mono">scripts/trial.sh --dry-run</code> previews host changes, and <code className="font-mono">vallum-panic</code> immediately restores routes.
          </p>
        </details>
      </Panel>

      <Panel title="Installed host components">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
          {readinessItems.map(([label, present]) => (
            <div key={String(label)} className="flex items-baseline justify-between gap-2">
              <dt className="text-muted-foreground">{String(label)}</dt>
              <dd className={present === null ? "text-muted-foreground" : present ? "text-live" : "text-stale"}>
                {present === null ? "Not readable" : present ? "Installed" : "Missing"}
              </dd>
            </div>
          ))}
        </dl>
        <p className="text-muted-foreground mt-2 text-xs">
          Socket directory <code className="font-mono">{facts.runtime_dir ?? "—"}</code> · mode{" "}
          <code className="font-mono">{facts.runtime_mode ?? "—"}</code> · {facts.sockets ?? 0} socket(s)
        </p>
        {facts.runtime_mode !== "absent" && !["0770", "0775", "0777"].includes(facts.runtime_mode) && (
          <p className="text-stale mt-1 text-xs">
            The socket directory is mode {facts.runtime_mode}; run the installer so the privilege-dropped daemon can publish its control socket under mode 0770.
          </p>
        )}
      </Panel>
    </section>
  )
}
