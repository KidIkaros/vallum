import { useEffect, useState, type ReactNode } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import {
  joinNetwork,
  setupServer,
  type JoinFields,
  type ServerSetupFields,
} from "@/lib/actions"
import { preflight, type Preflight } from "@/lib/bridge"
import { formatError, nameProblem } from "@/lib/validate"

// First-contact onboarding: join a network as a client (ticket or SSH
// enrolment) or initialise this machine as a server. These run before any
// tunnel exists, so they do not need a selected interface — the backend runs
// them through the privileged `vallum-ops` dispatcher (sudo -n / pkexec) and
// never passes an invite ticket on a command line.

function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string
  hint?: string
  error?: string | null
  children: ReactNode
}) {
  return (
    <div className="flex flex-col gap-1">
      <Label className="micro">{label}</Label>
      {children}
      {error ? (
        <span className="text-fault text-xs">{error}</span>
      ) : (
        hint && <span className="text-muted-foreground text-xs">{hint}</span>
      )}
    </div>
  )
}

function useSshHosts(open: boolean) {
  const [hosts, setHosts] = useState<NonNullable<Preflight["ssh_hosts"]>>([])
  useEffect(() => {
    if (!open) return
    preflight()
      .then((facts) => setHosts(facts.ssh_hosts ?? []))
      .catch(() => setHosts([]))
  }, [open])
  return hosts
}

function HostChips({
  hosts,
  active,
  onPick,
}: {
  hosts: NonNullable<Preflight["ssh_hosts"]>
  active: string
  onPick: (alias: string) => void
}) {
  if (hosts.length === 0) return null
  return (
    <div className="mt-1 flex flex-wrap gap-1">
      {hosts.map((host) => (
        <button
          key={host.alias}
          type="button"
          title={host.hostname !== host.alias ? `${host.user ? `${host.user}@` : ""}${host.hostname}` : undefined}
          onClick={() => onPick(host.alias)}
          className={`cursor-pointer rounded border px-2 py-0.5 font-mono text-[11px] transition-colors ${
            active === host.alias
              ? "border-signal/60 bg-signal/15 text-signal font-semibold"
              : "border-border/60 bg-background/40 text-muted-foreground hover:border-signal/40 hover:text-foreground"
          }`}
        >
          {host.alias}
        </button>
      ))}
    </div>
  )
}

/** Join an existing network: paste a `vallum1-join:` ticket, or enrol over
 *  SSH against the server. Both paths keep the private key on this device. */
export function JoinNetworkDialog({ blocked }: { blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [fields, setFields] = useState<JoinFields>({
    mode: "ticket",
    ticket: "",
    ssh_target: "",
    name: "",
  })
  const [touched, setTouched] = useState(false)
  const hosts = useSshHosts(open)

  const ticketMode = fields.mode !== "ssh"
  const ticketOk = fields.ticket.includes("vallum1-join:")
  const sshProblem =
    fields.ssh_target.trim() === ""
      ? "enter user@host or pick a saved SSH host"
      : fields.ssh_target.trim().startsWith("-")
        ? "host must not start with -"
        : null
  const nameProblem_ = fields.name.trim() === "" ? null : nameProblem(fields.name)
  const valid = ticketMode ? ticketOk : sshProblem === null && nameProblem_ === null

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          setFields({ mode: "ticket", ticket: "", ssh_target: "", name: "" })
          setTouched(false)
        }
      }}
    >
      <DialogTrigger asChild>
        <Button id="join-network-btn" variant="default" size="sm" disabled={!!blocked} title={blocked}>
          Join network…
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Join a network</DialogTitle>
          <DialogDescription className="text-xs">
            Connect this device to a Vallum server. Your private key is generated on this
            device and never leaves it.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            setTouched(true)
            if (!valid || busy) return
            setBusy(true)
            joinNetwork(fields)
              .then((done) => {
                toast.success(done.message)
                setOpen(false)
                setFields({ mode: "ticket", ticket: "", ssh_target: "", name: "" })
                setTouched(false)
              })
              .catch((error) => toast.error(formatError(error), { duration: 10000 }))
              .finally(() => setBusy(false))
          }}
        >
          <div className="border-border/70 bg-background/50 inline-flex w-fit rounded-lg border p-0.5 text-xs">
            {(
              [
                ["ticket", "Invite ticket"],
                ["ssh", "SSH enrolment"],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                aria-pressed={ticketMode === (id === "ticket")}
                onClick={() => setFields((f) => ({ ...f, mode: id }))}
                className={`min-h-0 cursor-pointer rounded-md px-3 py-1 font-medium transition-colors ${
                  ticketMode === (id === "ticket")
                    ? "bg-secondary text-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {ticketMode ? (
            <Field
              label="invite ticket"
              hint="paste the `vallum1-join:…` ticket — the whole `sudo vallum join …` line works too"
              error={touched && !ticketOk ? "paste a `vallum1-join:` ticket" : null}
            >
              <Textarea
                id="join-ticket"
                value={fields.ticket}
                onChange={(e) => setFields((f) => ({ ...f, ticket: e.target.value }))}
                placeholder="vallum1-join:vpn.example.com:51821/name/id/token/fp"
                rows={3}
                autoFocus
                className="font-mono text-xs"
                aria-invalid={touched && !ticketOk}
              />
            </Field>
          ) : (
            <>
              <Field
                label="server SSH host"
                hint="user@host or an alias from your ~/.ssh/config — enrols this device over SSH"
                error={touched ? sshProblem : null}
              >
                <Input
                  id="join-ssh-target"
                  value={fields.ssh_target}
                  onChange={(e) => setFields((f) => ({ ...f, ssh_target: e.target.value }))}
                  placeholder="user@vpn.example.com"
                  autoFocus
                  aria-invalid={touched && sshProblem !== null}
                />
                <HostChips
                  hosts={hosts}
                  active={fields.ssh_target}
                  onPick={(alias) => setFields((f) => ({ ...f, ssh_target: alias }))}
                />
              </Field>
              <Field
                label="device name (optional)"
                hint="the peer name this device joins as — empty picks the hostname"
                error={touched ? nameProblem_ : null}
              >
                <Input
                  value={fields.name}
                  onChange={(e) => setFields((f) => ({ ...f, name: e.target.value }))}
                  placeholder="laptop"
                  maxLength={15}
                  aria-invalid={touched && nameProblem_ !== null}
                />
              </Field>
            </>
          )}

          <DialogFooter showCloseButton>
            <Button type="submit" size="sm" disabled={!valid || busy}>
              {busy ? "Joining…" : "Join & connect"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Initialise this machine as a Vallum server: writes the server config,
 *  enables forwarding and NAT, and starts the daemon. */
export function SetupServerDialog({ blocked }: { blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [fields, setFields] = useState<ServerSetupFields>({
    address: "10.7.0.1/20",
    listen: "0.0.0.0:51820",
    public_endpoint: "",
  })
  const [touched, setTouched] = useState(false)

  const addrProblem = !fields.address.includes("/")
    ? "tunnel CIDR needs a prefix, e.g. 10.7.0.1/20"
    : null
  const listenProblem =
    fields.listen.trim() !== "" && !/^\S+:\d+$/.test(fields.listen.trim())
      ? "listen must be IP:port, e.g. 0.0.0.0:51820"
      : null
  const valid = addrProblem === null && listenProblem === null

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) setTouched(false)
      }}
    >
      <DialogTrigger asChild>
        <Button id="setup-server-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked}>
          Host a server…
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Host a Vallum server</DialogTitle>
          <DialogDescription className="text-xs">
            Writes /etc/vallum/vallum0.toml, enables IP forwarding and NAT, and starts the
            daemon. You can invite devices right after.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            setTouched(true)
            if (!valid || busy) return
            setBusy(true)
            setupServer(fields)
              .then((done) => {
                toast.success(done.message)
                setOpen(false)
                setTouched(false)
              })
              .catch((error) => toast.error(formatError(error), { duration: 10000 }))
              .finally(() => setBusy(false))
          }}
        >
          <Field
            label="tunnel subnet"
            hint="the server's own tunnel address with its prefix — clients get addresses under it"
            error={touched ? addrProblem : null}
          >
            <Input
              id="setup-server-address"
              value={fields.address}
              onChange={(e) => setFields((f) => ({ ...f, address: e.target.value }))}
              placeholder="10.7.0.1/20"
              autoFocus
              aria-invalid={touched && addrProblem !== null}
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field
              label="listen"
              hint="UDP socket to bind"
              error={touched ? listenProblem : null}
            >
              <Input
                value={fields.listen}
                onChange={(e) => setFields((f) => ({ ...f, listen: e.target.value }))}
                placeholder="0.0.0.0:51820"
                aria-invalid={touched && listenProblem !== null}
              />
            </Field>
            <Field
              label="public endpoint (optional)"
              hint="host:port clients dial — empty auto-detects this host's public IP"
            >
              <Input
                value={fields.public_endpoint}
                onChange={(e) => setFields((f) => ({ ...f, public_endpoint: e.target.value }))}
                placeholder="vpn.example.com:51820"
              />
            </Field>
          </div>
          <DialogFooter showCloseButton>
            <Button type="submit" size="sm" disabled={!valid || busy}>
              {busy ? "Initialising…" : "Initialise & start server"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
