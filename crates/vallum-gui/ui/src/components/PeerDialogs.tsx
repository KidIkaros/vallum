import { useEffect, useRef, useState, type ReactNode } from "react"
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
  addPeer,
  applyDevice,
  applyInterface,
  qrFrame,
  closeEnrollment,
  editPeer,
  emptyPeer,
  exportBundle,
  finalizePeer,
  generateKey,
  importBundle,
  invitePeer,
  readConfig,
  readInterfaceFields,
  removePeer,
  rotatePeer,
  saveRuntime,
  tuneMtu,
  writeConfig,
  type BundleOut,
  type Done,
  type InterfaceFields,
  type InviteFields,
  type KeyOut,
  type MtuTuneOut,
  type PeerFields,
  type QrFrame,
} from "@/lib/actions"
import type { Peer, Snapshot } from "@/types"
import { preflight, type SshHost } from "@/lib/bridge"
import { CopyButton } from "@/components/Copy"
import { ResultPanel } from "@/components/Result"
import { loadUserPrefs, suggestNextPeerIp, type NodeRole } from "@/lib/userPrefs"
import {
  allowedIpsProblem,
  endpointProblem,
  formatError,
  fwmarkProblem,
  keepaliveProblem,
  listenPortProblem,
  nameHint,
  nameProblem,
  presharedKeyProblem,
  publicLineProblem,
  ttlProblem,
} from "@/lib/validate"

// Peer management, mirroring the TUI's action set: add, edit, remove,
// rotate/finalize, invite. Design rules applied here:
//  - every action answers with the daemon's own reply (feedback),
//  - a destructive action names its target and cannot fire without the
//    dialog (constraint, error-proofing),
//  - identity fields are locked when editing (a changed public line is a
//    different peer, not an edit),
//  - submit stays disabled until the required field is present (constraint
//    over instruction).

function Field({
  label,
  labelRight,
  hint,
  error,
  children,
}: {
  label: string
  labelRight?: ReactNode
  hint?: string
  error?: string | null
  children: ReactNode
}) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline justify-between gap-2">
        <Label className="micro">{label}</Label>
        {labelRight}
      </div>
      {children}
      {/* The complaint replaces the hint: two lines of small text under one
          field is noise, and the complaint is the one that matters now. */}
      {error ? (
        <span className="text-fault text-xs">{error}</span>
      ) : (
        hint && <span className="text-muted-foreground text-xs">{hint}</span>
      )}
    </div>
  )
}

function report(promise: Promise<Done>, onDone: () => void) {
  return promise
    .then((done) => {
      toast.success(done.message)
      onDone()
    })
    .catch((error) => {
      toast.error(formatError(error), { duration: 8000 })
    })
}

/** One in-flight write per dialog: the submit disarms while its promise runs
 *  so a double-click cannot double-fire it, and the label says so. The
 *  destructive confirms use it too — a twice-sent remove is not idempotent
 *  in the operator's head even when the daemon forgives it. */
function useGuardedSubmit() {
  const [busy, setBusy] = useState(false)
  const submit = (work: () => Promise<unknown>) => {
    if (busy) return
    setBusy(true)
    void work().finally(() => setBusy(false))
  }
  return { busy, submit }
}

function PresetChip({
  label,
  active,
  disabled,
  onClick,
}: {
  label: string
  active?: boolean
  disabled?: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`cursor-pointer rounded border px-2 py-0.5 font-mono text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${
        active
          ? "border-signal/60 bg-signal/15 text-signal font-semibold"
          : "border-border/60 bg-background/40 text-muted-foreground hover:border-signal/40 hover:text-foreground"
      }`}
    >
      {label}
    </button>
  )
}

function PeerForm({
  peer,
  onSubmit,
  submitLabel,
  suggestedIp,
  defaultKeepalive = "25",
}: {
  peer: Peer | null
  onSubmit: (fields: PeerFields) => unknown
  submitLabel: string
  suggestedIp?: string | null
  defaultKeepalive?: string
}) {
  const { busy, submit } = useGuardedSubmit()
  const editing = peer !== null
  const [fields, setFields] = useState<PeerFields>(() =>
    peer
      ? {
          public_line: peer.public_line,
          name: peer.name,
          endpoint: peer.endpoint,
          allowed_ips: peer.allowed_ips.join(", "),
          keepalive: peer.keepalive !== null ? String(peer.keepalive) : "",
          preshared_key: "",
        }
      : {
          ...emptyPeer(),
          keepalive: defaultKeepalive,
        },
  )
  const set = (key: keyof PeerFields) => (value: string) =>
    setFields((f) => ({ ...f, [key]: value }))
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const mark = (key: string) => () => setTouched((t) => ({ ...t, [key]: true }))

  const problems = {
    name: nameProblem(fields.name),
    public_line: editing ? null : publicLineProblem(fields.public_line),
    endpoint: endpointProblem(fields.endpoint),
    keepalive: keepaliveProblem(fields.keepalive),
    allowed_ips: allowedIpsProblem(fields.allowed_ips),
    preshared_key: presharedKeyProblem(fields.preshared_key),
  }
  const blocking = Object.entries(problems).filter(([, problem]) => problem !== null)
  const ready = blocking.length === 0
  // Only complain about a field the operator has touched, or one that is
  // already wrong after they tried to submit.
  const show = (key: keyof typeof problems) =>
    touched[key] || touched.submit ? problems[key] : null

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault()
        if (!ready) return
        submit(() => Promise.resolve(onSubmit(fields)))
      }}
    >
      <Field
        label="name"
        labelRight={
          <span className="text-muted-foreground font-mono text-[11px]">
            {fields.name.trim().length}/15
          </span>
        }
        hint={nameHint(fields.name) ?? "a name you'll recognise later"}
        error={show("name")}
      >
        <Input
          id="peer-name"
          maxLength={15}
          value={fields.name}
          onChange={(e) => set("name")(e.target.value)}
          onBlur={mark("name")}
          placeholder="laptop"
          autoFocus
          aria-invalid={show("name") !== null}
        />
      </Field>
      <Field
        label="peer key"
        error={show("public_line")}
        hint={
          editing
            ? "locked while editing — a new key is a different peer, not an edit"
            : "paste the key from the other device (it runs `vallum pubkey`; the line starts with vallum1:)"
        }
      >
        <Textarea
          value={fields.public_line}
          onChange={(e) => set("public_line")(e.target.value)}
          readOnly={editing}
          rows={2}
          className={editing ? "opacity-60" : ""}
          placeholder="vallum1:0003:…"
          onBlur={mark("public_line")}
          aria-invalid={show("public_line") !== null}
        />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="address" hint="where to reach them, e.g. 203.0.113.7:51820 — empty means they roam" error={show("endpoint")}>
          <Input
            value={fields.endpoint}
            onChange={(e) => set("endpoint")(e.target.value)}
            placeholder="203.0.113.7:51820"
            onBlur={mark("endpoint")}
          />
        </Field>
        <Field label="keep-alive" hint="seconds between check-ins (25 suits most networks) — empty means off" error={show("keepalive")}>
          <Input
            value={fields.keepalive}
            onChange={(e) => set("keepalive")(e.target.value)}
            placeholder="25"
            inputMode="numeric"
            onBlur={mark("keepalive")}
          />
          <div className="mt-1 flex flex-wrap gap-1">
            <PresetChip label="25s NAT" active={fields.keepalive.trim() === "25"} onClick={() => set("keepalive")("25")} />
            <PresetChip label="60s" active={fields.keepalive.trim() === "60"} onClick={() => set("keepalive")("60")} />
            <PresetChip label="Off" active={fields.keepalive.trim() === ""} onClick={() => set("keepalive")("")} />
          </div>
        </Field>
      </div>
      <Field label="allowed IPs" hint="which addresses go through this peer, e.g. 10.7.0.2/32 — separate several with commas" error={show("allowed_ips")}>
        <Input
          value={fields.allowed_ips}
          onChange={(e) => set("allowed_ips")(e.target.value)}
          placeholder={suggestedIp ?? "10.7.0.2/32"}
          onBlur={mark("allowed_ips")}
        />
        <div className="mt-1 flex flex-wrap gap-1">
          {suggestedIp && (
            <PresetChip
              label={`Next free (${suggestedIp})`}
              active={fields.allowed_ips.trim() === suggestedIp}
              onClick={() => set("allowed_ips")(suggestedIp)}
            />
          )}
          <PresetChip
            label="Full tunnel (0.0.0.0/0, ::/0)"
            active={fields.allowed_ips.trim() === "0.0.0.0/0, ::/0"}
            onClick={() => set("allowed_ips")("0.0.0.0/0, ::/0")}
          />
        </div>
      </Field>
      <Field
        label="extra password"
        hint={editing ? "empty keeps the saved one" : "optional extra secret"}
        error={show("preshared_key")}
      >
        <Input
          value={fields.preshared_key}
          onChange={(e) => set("preshared_key")(e.target.value)}
          placeholder="64 hex characters"
          onBlur={mark("preshared_key")}
        />
      </Field>
      <DialogFooter showCloseButton className="mt-2 items-center gap-3">
        {!ready && (
          <span className="text-muted-foreground mr-auto text-xs">
            {blocking[0][1]}
          </span>
        )}
        <Button
          type="submit"
          size="sm"
          disabled={!ready || busy}
          onClick={() => setTouched((t) => ({ ...t, submit: true }))}
        >
          {busy ? "Saving…" : submitLabel}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function AddPeerDialog({
  blocked,
  peers = [],
  interfaceAddresses = [],
}: {
  blocked?: string
  /** Existing peers, so a duplicate key is caught before the daemon refuses it. */
  peers?: { name: string; public_line: string; allowed_ips?: string[] }[]
  interfaceAddresses?: string[]
}) {
  const [open, setOpen] = useState(false)
  const prefs = open ? loadUserPrefs() : null
  const suggestedIp = open
    ? suggestNextPeerIp(
        interfaceAddresses,
        peers.map((p) => p.allowed_ips ?? []),
      )
    : null
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button id="add-peer-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked}>
          + Add by Public Key
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Add device</DialogTitle>
          <DialogDescription className="text-xs">
            Saved on this computer and sent to the running tunnel.
          </DialogDescription>
        </DialogHeader>
        <PeerForm
          peer={null}
          submitLabel="Add device"
          suggestedIp={suggestedIp}
          defaultKeepalive={prefs?.defaultKeepalive ?? "25"}
          onSubmit={(fields) => {
            const typed = fields.public_line.trim()
            const existing = peers.find((peer) => peer.public_line.trim() === typed)
            if (existing) {
              // The daemon answers EINVAL for this, which reads as "a value was
              // wrong" and sends the operator hunting. Name the peer instead.
              toast.error(`already a peer: ${existing.name || existing.public_line.slice(0, 20)}`)
              return
            }
            report(addPeer(fields), () => setOpen(false))
          }}
        />
      </DialogContent>
    </Dialog>
  )
}

export function EditPeerDialog({ peer, blocked }: { peer: Peer; blocked?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button id="edit-peer-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked}>
          Edit
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Edit device</DialogTitle>
          <DialogDescription className="text-xs">{peer.name}</DialogDescription>
        </DialogHeader>
        <PeerForm
          peer={peer}
          submitLabel="Save changes"
          onSubmit={(fields) => report(editPeer(fields), () => setOpen(false))}
        />
      </DialogContent>
    </Dialog>
  )
}

export function RotateDialog({ peer, blocked }: { peer: Peer; blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [line, setLine] = useState("")
  const [rotatedLine, setRotatedLine] = useState("")
  const [touched, setTouched] = useState(false)
  const [staged, setStaged] = useState<Done | null>(null)
  const [finishing, setFinishing] = useState(false)
  const { busy, submit } = useGuardedSubmit()
  const lineError = publicLineProblem(line)
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          setLine("")
          setTouched(false)
          setStaged(null)
          setRotatedLine("")
        }
      }}
    >
      <DialogTrigger asChild>
        <Button id="rotate-peer-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked}>
          Rotate Key
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Rotate identity key</DialogTitle>
          <DialogDescription className="text-xs">
            The current key stays valid until you finalize — rotate now, switch
            the other device over, then finalize.
          </DialogDescription>
        </DialogHeader>
        {staged ? (
          <div className="flex flex-col gap-3">
            <p className="text-foreground/90 text-xs">{staged.message}</p>
            {rotatedLine && (
              <div className="border-border/70 bg-background/40 flex flex-col gap-1.5 rounded-md border p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="micro">Staged public key</span>
                  <CopyButton value={rotatedLine} label="Copy Public Line" />
                </div>
                <code className="text-foreground/80 break-all font-mono text-[11px]">
                  {rotatedLine}
                </code>
              </div>
            )}
            <p className="text-muted-foreground text-xs">
              Both keys are live. Cut the far end over, then finalize to retire
              the old one — until then the peer shows as rotating.
            </p>
            <div className="flex items-center gap-2 self-end">
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setStaged(null)
                  setRotatedLine("")
                  setOpen(false)
                }}
              >
                later
              </Button>
              <Button
                size="sm"
                disabled={finishing}
                onClick={() => {
                  setFinishing(true)
                  finalizePeer(peer.name)
                    .then((done) => {
                      toast.success(done.message)
                      setStaged(null)
                      setRotatedLine("")
                      setOpen(false)
                    })
                    .catch((error) => toast.error(formatError(error), { duration: 8000 }))
                    .finally(() => setFinishing(false))
                }}
              >
                {finishing ? "finalizing…" : "finalize now"}
              </Button>
            </div>
          </div>
        ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            setTouched(true)
            if (lineError !== null) return
            const trimmed = line.trim()
            submit(() =>
              rotatePeer(peer.name, trimmed)
                .then((done) => {
                  setRotatedLine(trimmed)
                  setStaged(done)
                  setLine("")
                  setTouched(false)
                })
                .catch((error) => toast.error(formatError(error), { duration: 8000 })),
            )
          }}
        >
          <Field
            label="new peer key"
            hint="paste the new key from the other device (starts with vallum1:)"
            error={touched ? lineError : null}
          >
            <Textarea
              value={line}
              onChange={(e) => setLine(e.target.value)}
              onBlur={() => setTouched(true)}
              rows={2}
              autoFocus
              aria-invalid={touched && lineError !== null}
              placeholder="vallum1:0003:…"
            />
          </Field>
          <DialogFooter showCloseButton className="items-center gap-3">
            {touched && lineError && (
              <span className="text-stale mr-auto font-mono text-[11px]">{lineError}</span>
            )}
            <Button type="submit" size="sm" disabled={lineError !== null || busy}>
              {busy ? "Rotating…" : "Rotate key"}
            </Button>
          </DialogFooter>
        </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

export function FinalizeButton({ peer, blocked }: { peer: Peer; blocked?: string }) {
  const [open, setOpen] = useState(false)
  const { busy, submit } = useGuardedSubmit()
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button id="finalize-peer-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked}>
          Finalize key
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Finalize rotation</DialogTitle>
          <DialogDescription className="text-xs">
            The previous identity of {peer.name} stops being accepted. Make sure
            the far end already uses the new key.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter showCloseButton>
          <Button
            size="sm"
            disabled={busy}
            onClick={() => submit(() => report(finalizePeer(peer.name), () => setOpen(false)))}
          >
            {busy ? "Finalizing…" : `Finalize ${peer.name}`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function RemoveDialog({ peer, blocked }: { peer: Peer; blocked?: string }) {
  const [open, setOpen] = useState(false)
  const { busy, submit } = useGuardedSubmit()
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button
          id="remove-peer-btn"
          variant="outline"
          size="sm"
          disabled={!!blocked}
          className="text-fault hover:text-fault"
          title={blocked}
        >
          Remove
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Remove device</DialogTitle>
          <DialogDescription className="text-xs">
            {peer.name} ({peer.fingerprint}) will be removed from the config. This
            cannot be undone from the console.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter showCloseButton>
          <Button
            variant="destructive"
            size="sm"
            disabled={busy}
            onClick={() => submit(() => report(removePeer(peer.public_line), () => setOpen(false)))}
          >
            {busy ? "Removing…" : `Remove ${peer.name}`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function InviteDialog({ blocked }: { blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<Done | null>(null)
  const { busy, submit } = useGuardedSubmit()
  const [sshHosts, setSshHosts] = useState<SshHost[]>([])
  const [closing, setClosing] = useState(false)
  const blank = () => ({
    name: "",
    ttl_minutes: loadUserPrefs().defaultInviteTtl,
    pinned: "",
    ssh_target: "",
  })
  const [fields, setFields] = useState<InviteFields>(() => blank())
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const set = (key: keyof InviteFields) => (value: string) =>
    setFields((f) => ({ ...f, [key]: value }))
  const mark = (key: string) => () => setTouched((t) => ({ ...t, [key]: true }))

  const problems = {
    name: nameProblem(fields.name, true),
    ttl_minutes: ttlProblem(fields.ttl_minutes),
    pinned: fields.pinned.trim() === "" ? null : publicLineProblem(fields.pinned),
    ssh_target:
      fields.ssh_target.trim() !== "" && fields.ssh_target.trim().startsWith("-")
        ? "SSH host must not start with -"
        : null,
  }
  const firstError =
    problems.name ?? problems.ttl_minutes ?? problems.pinned ?? problems.ssh_target
  const show = (key: keyof typeof problems) =>
    touched[key] || touched.submit ? problems[key] : null
  const anyTouched =
    touched.name || touched.ttl_minutes || touched.pinned || touched.submit

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (next) {
          setFields(blank())
          setTouched({})
          preflight()
            .then((facts) => setSshHosts(facts.ssh_hosts ?? []))
            .catch(() => setSshHosts([]))
        } else {
          // The ticket is single-use and the animation carries it: closing clears
          // it rather than leaving it framed behind the dialog.
          setResult(null)
          setFields(blank())
          setTouched({})
        }
      }}
    >
      <DialogTrigger asChild>
        <Button id="invite-peer-btn" variant="default" size="sm" disabled={!!blocked} title={blocked}>
          + Invite Device (QR / Ticket)
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Invite device</DialogTitle>
          <DialogDescription className="text-xs">
            Create a one-time QR code or join ticket for a new device.
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <div className="flex flex-col gap-3">
            {result.command && (
              <AnimatedQr
                key={result.command}
                text={result.command}
                secret="scan this to join from a phone: it is the same command below, as one animation. It carries the one-time token — close this once it is scanned."
              />
            )}
            <ResultPanel
              message={result.message}
              command={result.command}
              onDone={() => {
                setResult(null)
                setOpen(false)
              }}
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={closing}
              onClick={() => {
                if (closing) return
                setClosing(true)
                closeEnrollment(fields.ssh_target)
                  .then((done) => toast.success(done.message))
                  .catch((error) => toast.error(formatError(error), { duration: 8000 }))
                  .finally(() => setClosing(false))
              }}
            >
              {closing ? "Closing enrolment…" : "Close enrolment port (UDP 51821)"}
            </Button>
          </div>
        ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            setTouched((t) => ({ ...t, submit: true }))
            if (firstError !== null) return
            submit(() =>
              invitePeer(fields)
                .then((done) => {
                  setResult(done)
                  if (done.command && loadUserPrefs().autoCopyInvites) {
                    navigator.clipboard
                      ?.writeText(done.command)
                      .then(() => toast.success("Invite ticket copied to clipboard"))
                      .catch(() => {})
                  }
                })
                .catch((error) => toast.error(formatError(error), { duration: 8000 })),
            )
          }}
        >
          <Field
            label="name"
            labelRight={
              <span className="text-muted-foreground font-mono text-[11px]">
                {fields.name.trim().length}/15
              </span>
            }
            hint={nameHint(fields.name) ?? "who is this ticket for?"}
            error={show("name")}
          >
            <Input
              id="invite-name"
              maxLength={15}
              value={fields.name}
              onChange={(e) => set("name")(e.target.value)}
              onBlur={mark("name")}
              placeholder="phone"
              autoFocus
              aria-invalid={show("name") !== null}
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field
              label="expires after"
              hint="minutes until the ticket stops working — empty means 60"
              error={show("ttl_minutes")}
            >
              <Input
                value={fields.ttl_minutes}
                onChange={(e) => set("ttl_minutes")(e.target.value)}
                onBlur={mark("ttl_minutes")}
                placeholder="60"
                inputMode="numeric"
                aria-invalid={show("ttl_minutes") !== null}
              />
              <div className="mt-1 flex flex-wrap gap-1">
                {(
                  [
                    ["15", "15m"],
                    ["60", "1h"],
                    ["1440", "24h"],
                    ["10080", "7d"],
                  ] as const
                ).map(([val, label]) => (
                  <PresetChip
                    key={val}
                    label={label}
                    active={fields.ttl_minutes.trim() === val}
                    onClick={() => set("ttl_minutes")(val)}
                  />
                ))}
              </div>
            </Field>
            <Field
              label="lock to one device"
              hint="optional — only this peer key can use the ticket; empty means anyone with the ticket"
              error={show("pinned")}
            >
              <Input
                value={fields.pinned}
                onChange={(e) => set("pinned")(e.target.value)}
                onBlur={mark("pinned")}
                placeholder="empty means anyone with the ticket"
                aria-invalid={show("pinned") !== null}
              />
            </Field>
          </div>
          <Field
            label="remote server SSH (optional)"
            hint="this machine is a client? mint the invite on your server over SSH — user@host or a saved alias"
            error={show("ssh_target")}
          >
            <Input
              id="invite-ssh-target"
              value={fields.ssh_target}
              onChange={(e) => set("ssh_target")(e.target.value)}
              onBlur={mark("ssh_target")}
              placeholder="empty = this machine is the server"
              aria-invalid={show("ssh_target") !== null}
            />
            {sshHosts.length > 0 && (
              <div className="mt-1 flex flex-wrap gap-1">
                {sshHosts.map((host) => (
                  <PresetChip
                    key={host.alias}
                    label={host.alias}
                    active={fields.ssh_target === host.alias}
                    onClick={() => set("ssh_target")(host.alias)}
                  />
                ))}
              </div>
            )}
          </Field>
          <DialogFooter showCloseButton className="items-center gap-3">
            {anyTouched && firstError && (
              <span className="text-stale mr-auto font-mono text-[11px]">{firstError}</span>
            )}
            <Button
              type="submit"
              size="sm"
              disabled={firstError !== null || busy}
            >
              {busy ? "Creating…" : "Create invite"}
            </Button>
          </DialogFooter>
        </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

// An animated QR for text this console already holds — a bundle's JSON or an
// invite's join command: the same `VALLUM1` frames the TUI animates, at the
// TUI's 700 ms cadence, drawn dark-on-white with a two-module plate the way
// the TUI's quiet zone plates its half-blocks. The dialog clears the text on
// close (ADR-0009: the code carries a secret), so unmount is the wipe — no
// frame outlives the view.
function AnimatedQr({ text, secret }: { text: string; secret: string }) {
  const [frame, setFrame] = useState<QrFrame | null>(null)
  const [failed, setFailed] = useState<string | null>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    let live = true
    let timer = 0
    const load = (index: number) => {
      qrFrame(text, index)
        .then((next) => {
          if (!live) return
          setFrame(next)
          timer = window.setTimeout(() => load((next.index + 1) % next.total), 700)
        })
        .catch((error: unknown) => {
          if (live) setFailed(formatError(error))
        })
    }
    load(0)
    return () => {
      live = false
      window.clearTimeout(timer)
    }
  }, [text])
  useEffect(() => {
    const node = canvas.current
    if (!node || !frame) return
    const quiet = 2
    const pixels = 216
    const scale = pixels / (frame.size + quiet * 2)
    node.width = pixels
    node.height = pixels
    const ctx = node.getContext("2d")
    if (!ctx) return
    ctx.fillStyle = "#ffffff"
    ctx.fillRect(0, 0, pixels, pixels)
    ctx.fillStyle = "#000000"
    const cell = Math.ceil(scale)
    for (let y = 0; y < frame.size; y++) {
      for (let x = 0; x < frame.size; x++) {
        if (frame.modules[y * frame.size + x] === 1) {
          ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, cell, cell)
        }
      }
    }
  }, [frame])
  if (failed) {
    return (
      <p className="text-muted-foreground text-xs">
        no scannable code: {failed} — {secret}.
      </p>
    )
  }
  return (
    <div className="flex items-center gap-3">
      <canvas ref={canvas} className="h-40 w-40 shrink-0 rounded-sm" aria-label="animated QR code" />
      <div className="flex flex-col gap-1">
        <p className="text-foreground/90 font-mono text-xs">
          {frame ? `frame ${frame.index + 1}/${frame.total} · ${frame.hash}` : "framing…"}
        </p>
        <p className="text-muted-foreground text-xs">{secret}</p>
      </div>
    </div>
  )
}

export function ExportBundleDialog({ peer, blocked }: { peer: Peer; blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<BundleOut | null>(null)
  const [endpoint, setEndpoint] = useState("")
  const { busy, submit } = useGuardedSubmit()
  const download = (out: BundleOut) => {
    const url = URL.createObjectURL(
      new Blob([out.json], { type: "application/json" }),
    )
    const link = document.createElement("a")
    link.href = url
    link.download = out.filename
    link.click()
    URL.revokeObjectURL(url)
  }
  return (
    <Dialog open={open} onOpenChange={(next) => {
      setOpen(next)
      // Closing clears the minted bundle: the animation carries the private
      // key, so no frame string outlives the view (ADR-0009).
      if (!next) setResult(null)
    }}>
      <DialogTrigger asChild>
        <Button id="export-bundle-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked ?? "mint a client bundle for this peer: config plus a fresh key, downloaded as one file"}>
          Share Bundle / QR
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Share client bundle</DialogTitle>
          <DialogDescription className="text-xs">
            A full client config for {peer.name}, plus a key minted just for it —
            downloaded as one <span className="font-mono">.vallum-bundle</span> file
            and shown as a scannable animation of the same bytes.
            Whoever holds this file joins as this device.
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <div className="flex flex-col gap-3">
            <AnimatedQr
              key={result.json}
              text={result.json}
              secret="scan this animation to join as this peer. It carries the private key — whoever holds a photo holds the tunnel, so close this when scanned."
            />
            <ResultPanel
              message={result.message}
              onDone={() => {
                setResult(null)
                setOpen(false)
              }}
            />
          </div>
        ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            if (endpoint.trim() === "") return
            submit(() =>
              exportBundle(peer.fingerprint, endpoint)
              .then((out) => {
                download(out)
                setResult(out)
              })
              .catch((error) => toast.error(formatError(error), { duration: 8000 })),
            )
          }}
        >
          <Field label="server address" hint="the address the new client dials to reach this server (host:port)" error={endpoint.trim() === "" ? null : endpointProblem(endpoint)}>
            <Input
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="203.0.113.5:51820"
              autoFocus
            />
          </Field>
          <DialogFooter showCloseButton>
            <Button
              type="submit"
              size="sm"
              disabled={endpoint.trim() === "" || endpointProblem(endpoint) !== null || busy}
            >
              {busy ? "Generating…" : <>Create &amp; download bundle</>}
            </Button>
          </DialogFooter>
        </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

export function ImportBundleDialog({ blocked }: { blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<Done | null>(null)
  const [bundlePath, setBundlePath] = useState("")
  const [outDir, setOutDir] = useState("")
  const { busy, submit } = useGuardedSubmit()
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button id="import-bundle-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked ?? "install a client bundle file onto this machine"}>
          Import Bundle
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Import client bundle</DialogTitle>
          <DialogDescription className="text-xs">
            Install a <span className="font-mono">.vallum-bundle</span> file: writes the
            client config and its key. Leave the destination folder empty to use the
            interface&apos;s config directory.
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <ResultPanel
            message={result.message}
            command={result.command}
            onDone={() => {
              setResult(null)
              setOpen(false)
            }}
          />
        ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            if (bundlePath.trim() === "") return
            submit(() =>
              importBundle(bundlePath, outDir)
                .then((done) => setResult(done))
                .catch((error) => toast.error(formatError(error), { duration: 8000 })),
            )
          }}
        >
          <Field label="bundle file" hint="the .vallum-bundle file to install">
            <Input
              value={bundlePath}
              onChange={(e) => setBundlePath(e.target.value)}
              placeholder="/home/user/phone.vallum-bundle"
              autoFocus
            />
          </Field>
          <Field label="folder" hint="empty means the selected interface's config directory">
            <Input
              value={outDir}
              onChange={(e) => setOutDir(e.target.value)}
              placeholder="empty means the config directory"
            />
          </Field>
          <DialogFooter showCloseButton>
            <Button
              type="submit"
              size="sm"
              disabled={bundlePath.trim() === "" || busy}
            >
              {busy ? "Importing…" : "Import bundle"}
            </Button>
          </DialogFooter>
        </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

export function KeygenButton({
  blocked,
  onGenerated,
}: {
  blocked?: string
  onGenerated?: (out: KeyOut) => void
}) {
  const { busy, submit } = useGuardedSubmit()
  const mint = () => {
    submit(() =>
      generateKey()
      .then((out) => {
        const url = URL.createObjectURL(
          new Blob([out.text], { type: "text/plain" }),
        )
        const link = document.createElement("a")
        link.href = url
        link.download = out.filename
        link.click()
        URL.revokeObjectURL(url)
        onGenerated?.(out)
        toast.success(out.message, { duration: 8000 })
      })
      .catch((error) => toast.error(formatError(error), { duration: 8000 })),
    )
  }
  return (
    <Button id="generate-key-btn" variant="outline" size="sm" disabled={!!blocked || busy} title={blocked ?? "mint a fresh identity key and download it as a .key file"} onClick={mint}>
      {busy ? "…" : "Mint Loose Keypair"}
    </Button>
  )
}

type DiffLine = {
  kind: "equal" | "add" | "del"
  line: string
  oldNum?: number
  newNum?: number
}

function computeLineDiff(before: string, after: string): { rows: DiffLine[]; adds: number; dels: number } {
  const a = before.split("\n")
  const b = after.split("\n")
  // Cap DP size so huge generated configs stay instant.
  if (a.length * b.length > 160_000) {
    const rows: DiffLine[] = [
      ...a.map((line, i) => ({ kind: "del" as const, line, oldNum: i + 1 })),
      ...b.map((line, i) => ({ kind: "add" as const, line, newNum: i + 1 })),
    ]
    return { rows, adds: b.length, dels: a.length }
  }
  const n = a.length
  const m = b.length
  const dp: Uint16Array[] = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1))
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? 1 + dp[i + 1][j + 1] : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }
  const rows: DiffLine[] = []
  let i = 0
  let j = 0
  let adds = 0
  let dels = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      rows.push({ kind: "equal", line: a[i], oldNum: i + 1, newNum: j + 1 })
      i++
      j++
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ kind: "del", line: a[i], oldNum: i + 1 })
      dels++
      i++
    } else {
      rows.push({ kind: "add", line: b[j], newNum: j + 1 })
      adds++
      j++
    }
  }
  while (i < n) {
    rows.push({ kind: "del", line: a[i], oldNum: i + 1 })
    dels++
    i++
  }
  while (j < m) {
    rows.push({ kind: "add", line: b[j], newNum: j + 1 })
    adds++
    j++
  }
  return { rows, adds, dels }
}

export function ConfigDialog({
  blocked,
  interfaceName = "vallum0",
}: {
  blocked?: string
  interfaceName?: string
}) {
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<Done | null>(null)
  const [text, setText] = useState("")
  const [initialText, setInitialText] = useState("")
  const [mode, setMode] = useState<"editor" | "diff">("editor")
  const [loaded, setLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const { busy, submit } = useGuardedSubmit()
  const load = () => {
    setLoaded(false)
    setLoading(true)
    setLoadError(null)
    readConfig()
      .then((body) => {
        setText(body)
        setInitialText(body)
        setLoaded(true)
        setLoadError(null)
      })
      .catch((error) => {
        // Show the permission/unreadable explanation calmly inside the dialog
        // instead of stacking transient toasts on open.
        setLoadError(formatError(error))
      })
      .finally(() => setLoading(false))
  }
  const dirty = loaded && text !== initialText
  const diff = loaded ? computeLineDiff(initialText, text) : { rows: [], adds: 0, dels: 0 }
  const tuiCommand = "sudo vallum tui"
  const editorCommand = `sudo \${EDITOR:-nano} /etc/vallum/${interfaceName}.toml`
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (next) {
          setResult(null)
          setMode("editor")
          load()
        }
      }}
    >
      <DialogTrigger asChild>
        <Button id="config-editor-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked ?? "edit the on-disk interface config: validated before it lands, backed up first"}>
          Edit Raw TOML File…
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <div className="flex flex-wrap items-center justify-between gap-2 pr-6">
            <DialogTitle className="text-base font-semibold">Raw TOML config</DialogTitle>
            {loaded && !result && !loadError && (
              <div className="border-border/70 bg-background/50 inline-flex rounded-md border p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setMode("editor")}
                  className={`cursor-pointer rounded px-2.5 py-0.5 font-medium transition-colors ${
                    mode === "editor"
                      ? "bg-secondary text-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Editor
                </button>
                <button
                  type="button"
                  onClick={() => setMode("diff")}
                  className={`cursor-pointer rounded px-2.5 py-0.5 font-medium transition-colors ${
                    mode === "diff"
                      ? "bg-secondary text-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Diff{" "}
                  {dirty && (
                    <span className="ml-1 font-mono">
                      <span className="text-live">+{diff.adds}</span>{" "}
                      <span className="text-fault">-{diff.dels}</span>
                    </span>
                  )}
                </button>
              </div>
            )}
          </div>
          <DialogDescription className="text-xs">
            The configuration file the daemon starts from. Saving validates syntax first and keeps a timestamped backup.
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <ResultPanel
            message={result.message}
            command={result.command}
            onDone={() => {
              setResult(null)
              setOpen(false)
            }}
          />
        ) : loadError ? (
          <div className="flex flex-col gap-3">
            <div className="border-stale/40 bg-stale/10 flex flex-col gap-2 rounded-lg border p-3">
              <p className="text-stale text-xs font-medium">
                Config is read-only from this session
              </p>
              <p className="text-foreground/90 text-xs">{loadError}</p>
              <p className="text-muted-foreground text-xs">
                Interface configs are stored under mode <code className="font-mono">0600 root</code>.
              </p>
              <details className="pt-1 text-xs">
                <summary className="text-muted-foreground hover:text-foreground cursor-pointer select-none">
                  Show terminal editing commands
                </summary>
                <div className="mt-2 flex flex-col gap-1.5">
                  {[tuiCommand, editorCommand].map((cmd) => (
                    <div
                      key={cmd}
                      className="border-border/70 bg-background/50 flex items-center justify-between gap-2 rounded border px-2 py-1.5"
                    >
                      <code className="text-foreground/90 truncate font-mono text-[11px]">{cmd}</code>
                      <CopyButton value={cmd} label="Copy" />
                    </div>
                  ))}
                </div>
              </details>
            </div>
            <DialogFooter showCloseButton className="items-center gap-3">
              <span className="text-muted-foreground mr-auto font-mono text-[11px]">
                Read-only in unprivileged session
              </span>
              <Button type="button" variant="outline" size="sm" disabled={loading} onClick={load}>
                {loading ? "Reading…" : "Retry"}
              </Button>
              <Button type="button" size="sm" disabled>
                Save config
              </Button>
            </DialogFooter>
          </div>
        ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            submit(() =>
              writeConfig(text)
                .then((done) => setResult(done))
                .catch((error) => toast.error(formatError(error), { duration: 8000 })),
            )
          }}
        >
          {mode === "editor" ? (
            <Textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={loading ? "reading config…" : ""}
              disabled={!loaded}
              rows={18}
              className="font-mono text-xs"
              autoFocus
            />
          ) : (
            <div className="border-border bg-background/60 max-h-[360px] overflow-auto rounded-md border p-2 font-mono text-xs leading-relaxed">
              {!dirty ? (
                <p className="text-muted-foreground py-8 text-center">
                  no changes between disk config and editor buffer
                </p>
              ) : (
                diff.rows.map((row, idx) => (
                  <div
                    key={`${idx}-${row.kind}`}
                    className={`flex gap-2 rounded-xs px-1.5 py-0.5 whitespace-pre-wrap ${
                      row.kind === "add"
                        ? "bg-live/10 text-live"
                        : row.kind === "del"
                          ? "bg-fault/10 text-fault"
                          : "text-muted-foreground"
                    }`}
                  >
                    <span className="w-8 shrink-0 text-right opacity-55 select-none">
                      {row.oldNum ?? ""}
                    </span>
                    <span className="w-8 shrink-0 text-right opacity-55 select-none">
                      {row.newNum ?? ""}
                    </span>
                    <span className="w-3 shrink-0 select-none">
                      {row.kind === "add" ? "+" : row.kind === "del" ? "-" : " "}
                    </span>
                    <span className="min-w-0 flex-1 break-all">{row.line || " "}</span>
                  </div>
                ))
              )}
            </div>
          )}
          <DialogFooter showCloseButton className="items-center gap-3">
            {loaded && !dirty && (
              <span className="text-muted-foreground mr-auto font-mono text-[11px]">
                no unsaved changes
              </span>
            )}
            <Button
              type="submit"
              size="sm"
              disabled={!loaded || !dirty || text.trim() === "" || busy}
            >
              {busy ? "Saving…" : "Save config"}
            </Button>
          </DialogFooter>
        </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

const CONTENT_BLOCKER_OPTIONS = [
  { key: "ads", label: "Ads", bit: 1 << 0 },
  { key: "trackers", label: "Trackers", bit: 1 << 1 },
  { key: "malware", label: "Malware", bit: 1 << 2 },
  { key: "adult", label: "Adult", bit: 1 << 3 },
  { key: "gambling", label: "Gambling", bit: 1 << 4 },
  { key: "social", label: "Social", bit: 1 << 5 },
] as const

const BLOCKER_ALIASES: Record<string, string> = {
  ad: "ads",
  ads: "ads",
  tracker: "trackers",
  trackers: "trackers",
  malware: "malware",
  adult: "adult",
  adult_content: "adult",
  gambling: "gambling",
  social: "social",
  social_media: "social",
}

function parseContentBlockers(raw: string | undefined): Set<string> {
  const active = new Set<string>()
  for (const part of (raw ?? "").split(",")) {
    const canonical = BLOCKER_ALIASES[part.trim().toLowerCase()]
    if (canonical) active.add(canonical)
  }
  return active
}

export function InterfaceFormDialog({
  blocked,
  data,
  role = "client",
}: {
  blocked?: string
  data?: Snapshot | null
  role?: NodeRole
}) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [probingMtu, setProbingMtu] = useState(false)
  const [probedMtu, setProbedMtu] = useState<MtuTuneOut | null>(null)
  const [fields, setFields] = useState<InterfaceFields>({
    listen: "",
    carrier: "",
    tcp_upgrade: "",
    ss_psk: "",
    tls_sni: "",
    mtu: "",
    fwmark: "",
    addresses: "",
    dns: "",
    table: "",
    policy: "",
    content_blockers: "",
    via: "",
  })
  const { busy, submit } = useGuardedSubmit()

  const load = () => {
    setLoading(true)
    setLoadError(null)
    setProbedMtu(null)
    readInterfaceFields()
      .then((loaded) => setFields(loaded))
      .catch((error) => setLoadError(formatError(error)))
      .finally(() => setLoading(false))
  }

  const set = (key: keyof InterfaceFields) => (value: string) =>
    setFields((current) => ({ ...current, [key]: value }))

  const counters = data?.counters
  const fragRatioPct =
    counters && counters.packets_delivered > 0
      ? Math.round((counters.reassembled * 100) / counters.packets_delivered)
      : 0

  let recommendedMtu = "1380"
  let advisorProfile = "PQ-Safe / Gaming (1380)"
  let advisorReason =
    "Balances ML-KEM-768 handshake headroom (1444 B wire) with unfragmented ~1300 B real-time UDP datagrams."
  if (probedMtu) {
    recommendedMtu = String(probedMtu.recommended_inner_mtu)
    advisorProfile = `${probedMtu.profile} (${probedMtu.recommended_inner_mtu} · ceiling ${probedMtu.ceiling_outer_mtu} B)`
    advisorReason = `${probedMtu.host}: ${probedMtu.rationale}`
  } else if (counters && counters.datagrams_failed > 0) {
    recommendedMtu = "1280"
    advisorProfile = "Low-Jitter / USB NIC (1280)"
    advisorReason = `${counters.datagrams_failed} outer datagram failure(s) recorded; 1280 minimizes USB URB straddling and driver drops.`
  } else if (counters && (counters.fragments_dropped > 0 || fragRatioPct >= 2)) {
    recommendedMtu = "1380"
    advisorProfile = "Gaming / Low-Frag UDP (1380)"
    advisorReason =
      counters.fragments_dropped > 0
        ? `${counters.fragments_dropped} fragment drop(s) detected; 1380 prevents inner UDP fragmentation.`
        : `${fragRatioPct}% packet reassembly observed; 1380 avoids splitting real-time datagrams.`
  } else if (role === "server") {
    recommendedMtu = "1420"
    advisorProfile = "Gateway Bulk Throughput (1420)"
    advisorReason =
      "Clean counters on Gateway/Server role; 1420 maximizes bulk TCP/UDP goodput (1484 B outer wire)."
  }

  const parsedMtu = Number.parseInt(fields.mtu.trim(), 10)
  const effectiveMtu =
    Number.isFinite(parsedMtu) && parsedMtu >= 576 && parsedMtu <= 65535
      ? parsedMtu
      : Number.parseInt(recommendedMtu, 10)
  const activeCarrier = (fields.carrier.trim() || "udp").toLowerCase()
  const activePolicy = (fields.policy?.trim() || "auto").toLowerCase()
  const activeBlockers = parseContentBlockers(fields.content_blockers)
  const blockerMask = CONTENT_BLOCKER_OPTIONS.reduce(
    (mask, item) => (activeBlockers.has(item.key) ? mask | item.bit : mask),
    0,
  )
  const toggleBlocker = (key: string) => {
    const next = new Set(activeBlockers)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    const serialized = CONTENT_BLOCKER_OPTIONS.filter((item) => next.has(item.key))
      .map((item) => item.key)
      .join(", ")
    set("content_blockers")(serialized)
  }
  const outerWireMtu = effectiveMtu + (activeCarrier === "tcp" ? 66 : 64)
  const ipv4TcpMss = Math.max(536, effectiveMtu - 40)
  const ipv6TcpMss = Math.max(516, effectiveMtu - 60)

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (next) load()
      }}
    >
      <DialogTrigger asChild>
        <Button
          id="interface-form-btn"
          variant="outline"
          size="sm"
          disabled={!!blocked}
          title={blocked ?? "structured interface config form (i): listen, MTU, fwmark, addresses, DNS, table"}
        >
          Edit Network Settings…
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Tunnel &amp; network settings</DialogTitle>
          <DialogDescription className="text-xs">
            Edits <code className="font-mono">[interface]</code> and <code className="font-mono">[quick]</code> in the TOML config with backup + validation. Blank clears optional fields.
          </DialogDescription>
        </DialogHeader>
        {loadError ? (
          <div className="flex flex-col gap-3">
            <p className="text-stale text-xs">{loadError}</p>
            <DialogFooter showCloseButton>
              <Button type="button" variant="outline" size="sm" onClick={load} disabled={loading}>
                {loading ? "reading…" : "retry"}
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            className="flex flex-col gap-3"
            onSubmit={(event) => {
              event.preventDefault()
              submit(() => report(applyInterface(fields), () => setOpen(false)))
            }}
          >
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="listen address" hint="IP:port, e.g. 0.0.0.0:51820">
                <Input
                  value={fields.listen}
                  onChange={(e) => set("listen")(e.target.value)}
                  disabled={loading}
                  placeholder="0.0.0.0:51820"
                />
              </Field>
              <Field label="MTU" hint="576–65535 or 0 for auto">
                <Input
                  value={fields.mtu}
                  onChange={(e) => set("mtu")(e.target.value)}
                  disabled={loading}
                  inputMode="numeric"
                  placeholder="1420"
                />
                <div className="mt-1 flex flex-wrap gap-1">
                  <PresetChip label="1420 Standard" disabled={loading} active={fields.mtu.trim() === "1420"} onClick={() => set("mtu")("1420")} />
                  <PresetChip label="1380 PQ-Safe" disabled={loading} active={fields.mtu.trim() === "1380"} onClick={() => set("mtu")("1380")} />
                  <PresetChip label="1280 IPv6 Min" disabled={loading} active={fields.mtu.trim() === "1280"} onClick={() => set("mtu")("1280")} />
                </div>
              </Field>
            </div>
            <div className="border-signal/35 bg-signal/5 rounded-md border px-3 py-2 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-signal font-medium">
                  Adaptive MTU &amp; JA4T Advisor · {advisorProfile}
                </span>
                <div className="flex flex-wrap items-center gap-1">
                  <PresetChip
                    label={probingMtu ? "Probing Path…" : "Probe Live Path"}
                    disabled={loading || probingMtu}
                    active={probedMtu !== null}
                    onClick={() => {
                      setProbingMtu(true)
                      tuneMtu()
                        .then((res) => {
                          setProbedMtu(res)
                          set("mtu")(String(res.recommended_inner_mtu))
                          toast.success(
                            `Probed ${res.host}: ${res.profile} recommends MTU ${res.recommended_inner_mtu} (ceiling ${res.ceiling_outer_mtu} B)`,
                          )
                        })
                        .catch((error) => toast.error(formatError(error), { duration: 8000 }))
                        .finally(() => setProbingMtu(false))
                    }}
                  />
                  <PresetChip
                    label={
                      fields.mtu.trim() === recommendedMtu
                        ? `Recommended (${recommendedMtu}) active`
                        : `Apply ${recommendedMtu}`
                    }
                    disabled={loading}
                    active={fields.mtu.trim() === recommendedMtu}
                    onClick={() => set("mtu")(recommendedMtu)}
                  />
                </div>
              </div>
              <p className="text-muted-foreground mt-1 text-[11px]">{advisorReason}</p>
              <p className="text-muted-foreground mt-1 font-mono text-[11px]">
                Wire {outerWireMtu} B ({activeCarrier}) · JA4T MSS IPv4 {ipv4TcpMss} / IPv6 {ipv6TcpMss}
              </p>
            </div>
            <Field
              label="carrier transport"
              hint="udp, lwo, auto, tcp, ss (AEAD UDP), tls (TLS 1.3), or quic (QUIC DATAGRAM)"
            >
              <Input
                value={fields.carrier}
                onChange={(e) => set("carrier")(e.target.value)}
                disabled={loading}
                placeholder="udp"
              />
              <div className="mt-1 flex flex-wrap gap-1">
                <PresetChip
                  label="udp (Default)"
                  disabled={loading}
                  active={activeCarrier === "udp"}
                  onClick={() => set("carrier")("udp")}
                />
                <PresetChip
                  label="lwo (Obfuscated 0B)"
                  disabled={loading}
                  active={activeCarrier === "lwo"}
                  onClick={() => set("carrier")("lwo")}
                />
                <PresetChip
                  label="auto (LWO + TCP Race)"
                  disabled={loading}
                  active={activeCarrier === "auto"}
                  onClick={() => set("carrier")("auto")}
                />
                <PresetChip
                  label="tcp (Framed Stream)"
                  disabled={loading}
                  active={activeCarrier === "tcp"}
                  onClick={() => set("carrier")("tcp")}
                />
                <PresetChip
                  label="ss (AEAD UDP)"
                  disabled={loading}
                  active={activeCarrier === "ss"}
                  onClick={() => set("carrier")("ss")}
                />
                <PresetChip
                  label="tls (TLS 1.3)"
                  disabled={loading}
                  active={activeCarrier === "tls"}
                  onClick={() => set("carrier")("tls")}
                />
                <PresetChip
                  label="quic (DATAGRAM)"
                  disabled={loading}
                  active={activeCarrier === "quic"}
                  onClick={() => set("carrier")("quic")}
                />
              </div>
            </Field>
            {(activeCarrier === "tcp" ||
              activeCarrier === "auto" ||
              Boolean(fields.tcp_upgrade?.trim())) && (
              <Field
                label="tcp upgrade host (optional)"
                hint="HTTP/1.1 Host header sent with GET /_vallum Upgrade: vallum on TCP dials"
              >
                <Input
                  value={fields.tcp_upgrade ?? ""}
                  onChange={(e) => set("tcp_upgrade")(e.target.value)}
                  disabled={loading}
                  placeholder="edge.wingman.gold:443"
                />
              </Field>
            )}
            {(activeCarrier === "ss" || Boolean(fields.ss_psk?.trim())) && (
              <Field
                label="ss pre-shared key (optional)"
                hint="Shared obfuscation secret for carrier = 'ss' (hex/passphrase)"
              >
                <Input
                  value={fields.ss_psk ?? ""}
                  onChange={(e) => set("ss_psk")(e.target.value)}
                  disabled={loading}
                  placeholder="shared-obfuscation-secret"
                />
              </Field>
            )}
            {(activeCarrier === "tls" ||
              activeCarrier === "quic" ||
              Boolean(fields.tls_sni?.trim())) && (
              <Field
                label="tls sni hostname (optional)"
                hint="Server Name Indication sent in TLS/QUIC ClientHello (defaults to localhost)"
              >
                <Input
                  value={fields.tls_sni ?? ""}
                  onChange={(e) => set("tls_sni")(e.target.value)}
                  disabled={loading}
                  placeholder="cdn.example.com"
                />
              </Field>
            )}
            <Field
              label="multihop entry config (optional)"
              hint="Path to entry tunnel TOML for 2-hop Client -> Entry -> Exit ([quick] via)"
            >
              <Input
                value={fields.via ?? ""}
                onChange={(e) => set("via")(e.target.value)}
                disabled={loading}
                placeholder="entry.toml"
              />
            </Field>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="firewall mark" hint="decimal or 0x hex">
                <Input
                  value={fields.fwmark}
                  onChange={(e) => set("fwmark")(e.target.value)}
                  disabled={loading}
                  placeholder="51820"
                />
              </Field>
              <Field label="quick routing table" hint="auto, off, or table ID">
                <Input
                  value={fields.table}
                  onChange={(e) => set("table")(e.target.value)}
                  disabled={loading}
                  placeholder="auto"
                />
                <div className="mt-1 flex flex-wrap gap-1">
                  <PresetChip label="auto" disabled={loading} active={fields.table.trim() === "auto"} onClick={() => set("table")("auto")} />
                  <PresetChip label="off" disabled={loading} active={fields.table.trim() === "off"} onClick={() => set("table")("off")} />
                </div>
              </Field>
            </div>
            <Field label="interface addresses" hint="comma-separated CIDRs, e.g. 10.7.0.1/24, fd00:7::1/64">
              <Input
                value={fields.addresses}
                onChange={(e) => set("addresses")(e.target.value)}
                disabled={loading}
                placeholder="10.7.0.1/24"
              />
            </Field>
            <Field label="quick DNS servers" hint="comma-separated IP addresses">
              <Input
                value={fields.dns}
                onChange={(e) => set("dns")(e.target.value)}
                disabled={loading}
                placeholder="1.1.1.1, 9.9.9.9"
              />
              <div className="mt-1 flex flex-wrap gap-1">
                <PresetChip label="Cloudflare (1.1.1.1)" disabled={loading} active={fields.dns.trim() === "1.1.1.1, 1.0.0.1"} onClick={() => set("dns")("1.1.1.1, 1.0.0.1")} />
                <PresetChip label="Quad9 (9.9.9.9)" disabled={loading} active={fields.dns.trim() === "9.9.9.9"} onClick={() => set("dns")("9.9.9.9")} />
                <PresetChip label="Mullvad (194.242.2.2)" disabled={loading} active={fields.dns.trim() === "194.242.2.2"} onClick={() => set("dns")("194.242.2.2")} />
                <PresetChip label="Clear" disabled={loading} active={fields.dns.trim() === ""} onClick={() => set("dns")("")} />
              </div>
            </Field>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field
                label="egress guard ([quick] policy)"
                hint="auto (full tunnel), on, lockdown (even disconnected), or off"
              >
                <div className="mt-1 flex flex-wrap gap-1">
                  <PresetChip label="auto" disabled={loading} active={activePolicy === "auto"} onClick={() => set("policy")("auto")} />
                  <PresetChip label="on" disabled={loading} active={activePolicy === "on"} onClick={() => set("policy")("on")} />
                  <PresetChip label="lockdown" disabled={loading} active={activePolicy === "lockdown"} onClick={() => set("policy")("lockdown")} />
                  <PresetChip label="off" disabled={loading} active={activePolicy === "off"} onClick={() => set("policy")("off")} />
                </div>
              </Field>
              <Field
                label="content blockers (100.64.0.X)"
                hint="ORs selected categories into the in-tunnel magic resolver IP"
              >
                <div className="mt-1 flex flex-wrap gap-1">
                  {CONTENT_BLOCKER_OPTIONS.map((item) => (
                    <PresetChip
                      key={item.key}
                      label={item.label}
                      disabled={loading}
                      active={activeBlockers.has(item.key)}
                      onClick={() => toggleBlocker(item.key)}
                    />
                  ))}
                </div>
                {blockerMask > 0 && (
                  <p className="text-signal mt-1 font-mono text-[11px]">
                    → resolver 100.64.0.{blockerMask} (blocklist bits ORed into last octet)
                  </p>
                )}
              </Field>
            </div>
            <DialogFooter showCloseButton>
              <Button type="submit" size="sm" disabled={loading || busy}>
                {busy ? "Saving…" : "Save network settings"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

export function SaveRuntimeButton({ blocked }: { blocked?: string }) {
  const { busy, submit } = useGuardedSubmit()
  return (
    <Button
      id="save-runtime-btn"
      variant="outline"
      size="sm"
      disabled={!!blocked || busy}
      title={blocked ?? "save live runtime peer table back to the TOML config (W)"}
      onClick={() =>
        submit(() =>
          saveRuntime()
            .then((done) => toast.success(done.message))
            .catch((error) => toast.error(formatError(error), { duration: 8000 })),
        )
      }
    >
      {busy ? "Saving…" : "Save Live Peers to Disk"}
    </Button>
  )
}

export function DeviceDialog({
  listenPort,
  fwmark,
  blocked,
}: {
  listenPort: number | null
  fwmark: number | null
  blocked?: string
}) {
  const [open, setOpen] = useState(false)
  const [port, setPort] = useState("")
  const [mark, setMark] = useState("")
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const { busy, submit } = useGuardedSubmit()

  const portError = listenPortProblem(port)
  const markError = fwmarkProblem(mark)
  const firstError = portError ?? markError
  const hasChanges = port.trim() !== "" || mark.trim() !== ""
  const markTouched = (key: string) => () =>
    setTouched((t) => ({ ...t, [key]: true }))

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (next) {
          setPort("")
          setMark("")
          setTouched({})
        }
      }}
    >
      <DialogTrigger asChild>
        <Button id="device-form-btn" variant="outline" size="sm" disabled={!!blocked} title={blocked ?? "runtime device form: listen port and firewall mark"}>
          Change Live Port / Mark…
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Runtime listen port &amp; mark</DialogTitle>
          <DialogDescription className="text-xs">
            Applies to the running tunnel only (not persisted to config). Changing the listen port rebinds it without dropping existing sessions.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            setTouched((t) => ({ ...t, submit: true }))
            if (!hasChanges || firstError !== null) return
            submit(() => report(applyDevice(port.trim(), mark.trim()), () => setOpen(false)))
          }}
        >
          <Field
            label="listen port"
            labelRight={
              <span className="text-muted-foreground font-mono text-[11px]">
                current: {listenPort !== null ? `:${listenPort}` : "—"}
              </span>
            }
            hint="blank keeps current · 0 picks an OS-assigned ephemeral port"
            error={touched.port || touched.submit ? portError : null}
          >
            <Input
              value={port}
              onChange={(e) => setPort(e.target.value)}
              onBlur={markTouched("port")}
              inputMode="numeric"
              placeholder={listenPort !== null ? String(listenPort) : "51820"}
              aria-invalid={(touched.port || touched.submit) && portError !== null}
            />
          </Field>
          <Field
            label="firewall mark"
            labelRight={
              <span className="text-muted-foreground font-mono text-[11px]">
                current: {fwmark !== null && fwmark !== 0 ? fwmark : "off"}
              </span>
            }
            hint="blank keeps current · 'off' or 0 clears · decimal or 0x hex"
            error={touched.mark || touched.submit ? markError : null}
          >
            <Input
              value={mark}
              onChange={(e) => setMark(e.target.value)}
              onBlur={markTouched("mark")}
              placeholder={fwmark !== null && fwmark !== 0 ? String(fwmark) : "off"}
              aria-invalid={(touched.mark || touched.submit) && markError !== null}
            />
          </Field>
          <DialogFooter showCloseButton className="items-center gap-3">
            {firstError ? (
              <span className="text-stale mr-auto font-mono text-[11px]">{firstError}</span>
            ) : !hasChanges ? (
              <span className="text-muted-foreground mr-auto font-mono text-[11px]">
                enter a new port or fwmark to apply
              </span>
            ) : null}
            <Button
              type="submit"
              size="sm"
              disabled={busy || !hasChanges || firstError !== null}
            >
              {busy ? "Applying…" : "Apply changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
