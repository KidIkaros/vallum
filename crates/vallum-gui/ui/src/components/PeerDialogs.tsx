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
  children,
}: {
  label: string
  hint?: string
  children: ReactNode
}) {
  return (
    <div className="flex flex-col gap-1">
      <Label className="micro">{label}</Label>
      {children}
      {hint && <span className="text-muted-foreground text-[10px]">{hint}</span>}
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
  const ready = fields.name.trim() !== "" && fields.public_line.trim() !== ""

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault()
        if (ready) onSubmit(fields)
      }}
    >
      <Field label="name">
        <Input
          value={fields.name}
          onChange={(e) => set("name")(e.target.value)}
          placeholder="laptop"
          autoFocus
        />
      </Field>
      <Field
        label="public line"
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
        />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="endpoint" hint="blank = this peer roams">
          <Input
            value={fields.endpoint}
            onChange={(e) => set("endpoint")(e.target.value)}
            placeholder="203.0.113.7:51820"
          />
        </Field>
        <Field label="keepalive (s)">
          <Input
            value={fields.keepalive}
            onChange={(e) => set("keepalive")(e.target.value)}
            placeholder="25"
            inputMode="numeric"
          />
        </Field>
      </div>
      <Field label="allowed IPs" hint="CIDRs, comma separated">
        <Input
          value={fields.allowed_ips}
          onChange={(e) => set("allowed_ips")(e.target.value)}
          placeholder="10.7.0.2/32"
        />
      </Field>
      <Field label="preshared key" hint={editing ? "blank keeps the stored key" : "optional"}>
        <Input
          value={fields.preshared_key}
          onChange={(e) => set("preshared_key")(e.target.value)}
          placeholder="64 hex characters"
        />
      </Field>
      <DialogFooter className="mt-2">
        <Button type="submit" size="sm" disabled={!ready} className="uppercase">
          {submitLabel}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function AddPeerDialog({ blocked }: { blocked?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
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
          onSubmit={(fields) => report(addPeer(fields), () => setOpen(false))}
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
        <Button variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
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
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            if (line.trim() === "") return
            report(rotatePeer(peer.name, line.trim()), () => {
              setOpen(false)
              setLine("")
            })
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
  const [fields, setFields] = useState<InviteFields>({
    name: "",
    ttl_minutes: "",
    pinned: "false",
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
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            if (fields.name.trim() === "") return
            report(invitePeer(fields), () => setOpen(false))
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
            <Field label="ttl (minutes)" hint="blank = the daemon's default">
              <Input
                value={fields.ttl_minutes}
                onChange={(e) => set("ttl_minutes")(e.target.value)}
                placeholder="60"
                inputMode="numeric"
              />
            </Field>
            <Field label="pin address" hint="true / false">
              <Input
                value={fields.pinned}
                onChange={(e) => set("pinned")(e.target.value)}
                placeholder="false"
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
