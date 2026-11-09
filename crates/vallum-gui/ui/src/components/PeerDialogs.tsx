import { useState, type ReactNode } from "react"
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
  editPeer,
  emptyPeer,
  finalizePeer,
  invitePeer,
  removePeer,
  rotatePeer,
  type Done,
  type InviteFields,
  type PeerFields,
} from "@/lib/actions"
import type { Peer } from "@/types"
import { ResultPanel } from "@/components/Result"
import {
  allowedIpsProblem,
  endpointProblem,
  keepaliveProblem,
  nameProblem,
  presharedKeyProblem,
  publicLineProblem,
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
      {/* The complaint replaces the hint: two lines of small text under one
          field is noise, and the complaint is the one that matters now. */}
      {error ? (
        <span className="text-fault text-[10px]">{error}</span>
      ) : (
        hint && <span className="text-muted-foreground text-[10px]">{hint}</span>
      )}
    </div>
  )
}

function report(promise: Promise<Done>, onDone: () => void) {
  promise
    .then((done) => {
      toast.success(done.message, {
        description: done.command ? `run: ${done.command}` : undefined,
      })
      onDone()
    })
    .catch((error) => {
      toast.error(String(error), { duration: 8000 })
    })
}

function PeerForm({
  peer,
  onSubmit,
  submitLabel,
}: {
  peer: Peer | null
  onSubmit: (fields: PeerFields) => void
  submitLabel: string
}) {
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
      : emptyPeer(),
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
        if (ready) onSubmit(fields)
      }}
    >
      <Field label="name" error={show("name")}>
        <Input
          value={fields.name}
          onChange={(e) => set("name")(e.target.value)}
          onBlur={mark("name")}
          placeholder="laptop"
          autoFocus
          aria-invalid={show("name") !== null}
        />
      </Field>
      <Field
        label="public line"
        error={show("public_line")}
        hint={
          editing
            ? "identity is locked while editing — a new line is a different peer"
            : "vallum1:0003:… from the other end's `vallum pubkey`"
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
        <Field label="endpoint" hint="blank = this peer roams" error={show("endpoint")}>
          <Input
            value={fields.endpoint}
            onChange={(e) => set("endpoint")(e.target.value)}
            placeholder="203.0.113.7:51820"
            onBlur={mark("endpoint")}
          />
        </Field>
        <Field label="keepalive (s)" error={show("keepalive")}>
          <Input
            value={fields.keepalive}
            onChange={(e) => set("keepalive")(e.target.value)}
            placeholder="25"
            inputMode="numeric"
            onBlur={mark("keepalive")}
          />
        </Field>
      </div>
      <Field label="allowed IPs" hint="CIDRs, comma separated" error={show("allowed_ips")}>
        <Input
          value={fields.allowed_ips}
          onChange={(e) => set("allowed_ips")(e.target.value)}
          placeholder="10.7.0.2/32"
          onBlur={mark("allowed_ips")}
        />
      </Field>
      <Field
        label="preshared key"
        hint={editing ? "blank keeps the stored key" : "optional"}
        error={show("preshared_key")}
      >
        <Input
          value={fields.preshared_key}
          onChange={(e) => set("preshared_key")(e.target.value)}
          placeholder="64 hex characters"
          onBlur={mark("preshared_key")}
        />
      </Field>
      <DialogFooter className="mt-2 items-center gap-3">
        {!ready && (
          <span className="text-muted-foreground mr-auto text-[10px]">
            {blocking[0][1]}
          </span>
        )}
        <Button
          type="submit"
          size="sm"
          disabled={!ready}
          className="uppercase"
          onClick={() => setTouched((t) => ({ ...t, submit: true }))}
        >
          {submitLabel}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function AddPeerDialog({
  blocked,
  peers = [],
}: {
  blocked?: string
  /** Existing peers, so a duplicate key is caught before the daemon refuses it. */
  peers?: { name: string; public_line: string }[]
}) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button id="add-peer-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
          + add peer
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">ADD PEER</DialogTitle>
          <DialogDescription className="text-xs">
            Written to the config beside the daemon's control socket and applied
            through it.
          </DialogDescription>
        </DialogHeader>
        <PeerForm
          peer={null}
          submitLabel="add peer"
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
        <Button id="edit-peer-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
          edit
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">EDIT PEER</DialogTitle>
          <DialogDescription className="text-xs">{peer.name}</DialogDescription>
        </DialogHeader>
        <PeerForm
          peer={peer}
          submitLabel="save"
          onSubmit={(fields) => report(editPeer(fields), () => setOpen(false))}
        />
      </DialogContent>
    </Dialog>
  )
}

export function RotateDialog({ peer, blocked }: { peer: Peer; blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [line, setLine] = useState("")
  const [staged, setStaged] = useState<Done | null>(null)
  const [finishing, setFinishing] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
          rotate
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">ROTATE IDENTITY</DialogTitle>
          <DialogDescription className="text-xs">
            The current key stays valid until `finalize` — rotate now, cut over
            the far end, then finalize.
          </DialogDescription>
        </DialogHeader>
        {staged ? (
          <div className="flex flex-col gap-3">
            <p className="text-foreground/90 text-xs">{staged.message}</p>
            <p className="text-muted-foreground text-[11px]">
              Both keys are live. Cut the far end over, then finalize to retire
              the old one — until then the peer shows as rotating.
            </p>
            <div className="flex items-center gap-2 self-end">
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setStaged(null)
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
                      setOpen(false)
                    })
                    .catch((error) => toast.error(String(error), { duration: 8000 }))
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
            if (line.trim() === "") return
            rotatePeer(peer.name, line.trim())
              .then((done) => {
                setStaged(done)
                setLine("")
              })
              .catch((error) => toast.error(String(error), { duration: 8000 }))
          }}
        >
          <Field label="new public line" hint="the peer's new vallum1:0003:… line">
            <Textarea
              value={line}
              onChange={(e) => setLine(e.target.value)}
              rows={2}
              autoFocus
              placeholder="vallum1:0003:…"
            />
          </Field>
          <DialogFooter>
            <Button type="submit" size="sm" disabled={line.trim() === ""} className="uppercase">
              rotate
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
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
          finalize
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">FINALIZE ROTATION</DialogTitle>
          <DialogDescription className="text-xs">
            The previous identity of {peer.name} stops being accepted. Make sure
            the far end already uses the new key.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button
            size="sm"
            className="uppercase"
            onClick={() => report(finalizePeer(peer.name), () => setOpen(false))}
          >
            finalize {peer.name}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function RemoveDialog({ peer, blocked }: { peer: Peer; blocked?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          disabled={!!blocked}
          className="micro text-fault hover:text-fault"
          title={blocked}
        >
          remove
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">REMOVE PEER</DialogTitle>
          <DialogDescription className="text-xs">
            {peer.name} ({peer.fingerprint}) is removed from the config. This
            cannot be undone from the console.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button
            variant="destructive"
            size="sm"
            className="uppercase"
            onClick={() => report(removePeer(peer.public_line), () => setOpen(false))}
          >
            remove {peer.name}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function InviteDialog({ blocked }: { blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<Done | null>(null)
  const [fields, setFields] = useState<InviteFields>({
    name: "",
    ttl_minutes: "",
    pinned: "",
  })
  const set = (key: keyof InviteFields) => (value: string) =>
    setFields((f) => ({ ...f, [key]: value }))
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
          invite
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">INVITE</DialogTitle>
          <DialogDescription className="text-xs">
            Mint a one-time ticket the other end can join with.
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
            if (fields.name.trim() === "") return
            invitePeer(fields)
              .then((done) => setResult(done))
              .catch((error) => toast.error(String(error), { duration: 8000 }))
          }}
        >
          <Field label="name">
            <Input
              value={fields.name}
              onChange={(e) => set("name")(e.target.value)}
              placeholder="phone"
              autoFocus
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="ttl (minutes)" hint="blank = 60">
              <Input
                value={fields.ttl_minutes}
                onChange={(e) => set("ttl_minutes")(e.target.value)}
                placeholder="60"
                inputMode="numeric"
              />
            </Field>
            <Field
              label="pin to a key"
              hint="optional — only this public line can redeem"
              error={
                fields.pinned.trim() === "" ? null : publicLineProblem(fields.pinned)
              }
            >
              <Input
                value={fields.pinned}
                onChange={(e) => set("pinned")(e.target.value)}
                placeholder="blank = anyone with the token"
              />
            </Field>
          </div>
          <DialogFooter>
            <Button
              type="submit"
              size="sm"
              disabled={fields.name.trim() === ""}
              className="uppercase"
            >
              invite
            </Button>
          </DialogFooter>
        </form>
        )}
      </DialogContent>
    </Dialog>
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
  const [port, setPort] = useState(listenPort !== null ? String(listenPort) : "")
  const [mark, setMark] = useState(fwmark !== null ? String(fwmark) : "")
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
          interface
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">INTERFACE</DialogTitle>
          <DialogDescription className="text-xs">
            Applied through the control plane. A listen-port change rebinds the
            socket; existing sessions survive it.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            report(applyDevice(port.trim(), mark.trim()), () => setOpen(false))
          }}
        >
          <Field label="listen port" hint="blank keeps the current port">
            <Input
              value={port}
              onChange={(e) => setPort(e.target.value)}
              inputMode="numeric"
              placeholder={listenPort !== null ? String(listenPort) : "51820"}
            />
          </Field>
          <Field label="fwmark" hint="blank keeps the current mark">
            <Input
              value={mark}
              onChange={(e) => setMark(e.target.value)}
              inputMode="numeric"
              placeholder={fwmark !== null ? String(fwmark) : "0"}
            />
          </Field>
          <DialogFooter>
            <Button type="submit" size="sm" className="uppercase">
              apply
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
