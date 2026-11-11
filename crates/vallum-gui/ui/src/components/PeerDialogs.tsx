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
  qrFrame,
  editPeer,
  emptyPeer,
  exportBundle,
  finalizePeer,
  generateKey,
  importBundle,
  invitePeer,
  readConfig,
  removePeer,
  rotatePeer,
  writeConfig,
  type BundleOut,
  type Done,
  type InviteFields,
  type PeerFields,
  type QrFrame,
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
      toast.success(done.message, {
        description: done.command ? `run: ${done.command}` : undefined,
      })
      onDone()
    })
    .catch((error) => {
      toast.error(String(error), { duration: 8000 })
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

function PeerForm({
  peer,
  onSubmit,
  submitLabel,
}: {
  peer: Peer | null
  onSubmit: (fields: PeerFields) => unknown
  submitLabel: string
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
        if (!ready) return
        submit(() => Promise.resolve(onSubmit(fields)))
      }}
    >
      <Field label="name" hint="a name you'll recognise later" error={show("name")}>
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
        </Field>
      </div>
      <Field label="allowed IPs" hint="which addresses go through this peer, e.g. 10.7.0.2/32 — separate several with commas" error={show("allowed_ips")}>
        <Input
          value={fields.allowed_ips}
          onChange={(e) => set("allowed_ips")(e.target.value)}
          placeholder="10.7.0.2/32"
          onBlur={mark("allowed_ips")}
        />
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
          className="uppercase"
          onClick={() => setTouched((t) => ({ ...t, submit: true }))}
        >
          {busy ? "…" : submitLabel}
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
            Saved on this computer and sent to the running tunnel.
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
  const { busy, submit } = useGuardedSubmit()
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button id="rotate-peer-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
          rotate
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">ROTATE IDENTITY</DialogTitle>
          <DialogDescription className="text-xs">
            The current key stays valid until you finalize — rotate now, switch
            the other device over, then finalize.
          </DialogDescription>
        </DialogHeader>
        {staged ? (
          <div className="flex flex-col gap-3">
            <p className="text-foreground/90 text-xs">{staged.message}</p>
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
            submit(() =>
              rotatePeer(peer.name, line.trim())
                .then((done) => {
                  setStaged(done)
                  setLine("")
                })
                .catch((error) => toast.error(String(error), { duration: 8000 })),
            )
          }}
        >
          <Field label="new peer key" hint="paste the new key from the other device (starts with vallum1:)">
            <Textarea
              value={line}
              onChange={(e) => setLine(e.target.value)}
              rows={2}
              autoFocus
              placeholder="vallum1:0003:…"
            />
          </Field>
          <DialogFooter showCloseButton>
            <Button type="submit" size="sm" disabled={line.trim() === "" || busy} className="uppercase">
              {busy ? "…" : "rotate"}
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
        <Button id="finalize-peer-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
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
        <DialogFooter showCloseButton>
          <Button
            size="sm"
            className="uppercase"
            disabled={busy}
            onClick={() => submit(() => report(finalizePeer(peer.name), () => setOpen(false)))}
          >
            {busy ? "…" : `finalize ${peer.name}`}
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
        <DialogFooter showCloseButton>
          <Button
            variant="destructive"
            size="sm"
            className="uppercase"
            disabled={busy}
            onClick={() => submit(() => report(removePeer(peer.public_line), () => setOpen(false)))}
          >
            {busy ? "…" : `remove ${peer.name}`}
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
  const [fields, setFields] = useState<InviteFields>({
    name: "",
    ttl_minutes: "",
    pinned: "",
  })
  const set = (key: keyof InviteFields) => (value: string) =>
    setFields((f) => ({ ...f, [key]: value }))
  return (
    <Dialog open={open} onOpenChange={(next) => {
      setOpen(next)
      // The ticket is single-use and the animation carries it: closing clears
      // it rather than leaving it framed behind the dialog.
      if (!next) setResult(null)
    }}>
      <DialogTrigger asChild>
        <Button id="invite-peer-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked}>
          invite
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">INVITE</DialogTitle>
          <DialogDescription className="text-xs">
            Create a one-time ticket the other device can join with.
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
          </div>
        ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            if (fields.name.trim() === "") return
            submit(() =>
              invitePeer(fields)
                .then((done) => setResult(done))
                .catch((error) => toast.error(String(error), { duration: 8000 })),
            )
          }}
        >
          <Field label="name" hint="who is this ticket for?">
            <Input
              value={fields.name}
              onChange={(e) => set("name")(e.target.value)}
              placeholder="phone"
              autoFocus
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="expires after" hint="minutes until the ticket stops working — empty means 60">
              <Input
                value={fields.ttl_minutes}
                onChange={(e) => set("ttl_minutes")(e.target.value)}
                placeholder="60"
                inputMode="numeric"
              />
            </Field>
            <Field
              label="lock to one device"
              hint="optional — only this peer key can use the ticket; empty means anyone with the ticket"
              error={
                fields.pinned.trim() === "" ? null : publicLineProblem(fields.pinned)
              }
            >
              <Input
                value={fields.pinned}
                onChange={(e) => set("pinned")(e.target.value)}
                placeholder="empty means anyone with the ticket"
              />
            </Field>
          </div>
          <DialogFooter showCloseButton>
            <Button
              type="submit"
              size="sm"
              disabled={fields.name.trim() === "" || busy}
              className="uppercase"
            >
              {busy ? "…" : "invite"}
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
          if (live) setFailed(String(error))
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
        <Button id="export-bundle-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked ?? "mint a client bundle for this peer: config plus a fresh key, downloaded as one file"}>
          bundle
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">CLIENT BUNDLE</DialogTitle>
          <DialogDescription className="text-xs">
            A full client config for {peer.name}, plus a key minted just for it —
            downloaded as one <span className="font-mono">.vallum-bundle</span> file
            and shown as a scannable animation of the same bytes.
            The key exists only in that file: whoever holds it joins as this peer.
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
              .catch((error) => toast.error(String(error), { duration: 8000 })),
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
              className="uppercase"
            >
              {busy ? "…" : <>mint &amp; download</>}
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
        <Button id="import-bundle-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked ?? "install a client bundle file onto this machine"}>
          import
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">IMPORT BUNDLE</DialogTitle>
          <DialogDescription className="text-xs">
            Install a <span className="font-mono">.vallum-bundle</span> file: writes the
            client config and its key. An empty folder means the selected
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
                .catch((error) => toast.error(String(error), { duration: 8000 })),
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
              className="uppercase"
            >
              {busy ? "…" : "import"}
            </Button>
          </DialogFooter>
        </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

export function KeygenButton({ blocked }: { blocked?: string }) {
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
        toast.success(out.message, { duration: 8000 })
      })
      .catch((error) => toast.error(String(error), { duration: 8000 })),
    )
  }
  return (
    <Button id="generate-key-btn" variant="outline" size="sm" disabled={!!blocked || busy} className="micro" title={blocked ?? "mint a fresh identity key and download it as a .key file"} onClick={mint}>
      {busy ? "…" : "key"}
    </Button>
  )
}

export function ConfigDialog({ blocked }: { blocked?: string }) {
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<Done | null>(null)
  const [text, setText] = useState("")
  const [loaded, setLoaded] = useState(false)
  const { busy, submit } = useGuardedSubmit()
  const load = () => {
    setLoaded(false)
    readConfig()
      .then((body) => {
        setText(body)
        setLoaded(true)
      })
      .catch((error) => toast.error(String(error), { duration: 8000 }))
  }
  return (
    <Dialog open={open} onOpenChange={(next) => {
      setOpen(next)
      if (next) {
        setResult(null)
        load()
      }
    }}>
      <DialogTrigger asChild>
        <Button id="config-editor-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked ?? "edit the on-disk interface config: validated before it lands, backed up first"}>
          config
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">INTERFACE CONFIG</DialogTitle>
          <DialogDescription className="text-xs">
            The file the daemon starts from. Saving validates first and keeps a
            timestamped backup; text that does not parse restores the backup
            instead of stranding the tunnel.
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
            submit(() =>
              writeConfig(text)
                .then((done) => setResult(done))
                .catch((error) => toast.error(String(error), { duration: 8000 })),
            )
          }}
        >
          <Textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={loaded ? "" : "reading config…"}
            disabled={!loaded}
            rows={18}
            className="font-mono text-xs"
            autoFocus
          />
          <DialogFooter showCloseButton>
            <Button
              type="submit"
              size="sm"
              disabled={!loaded || text.trim() === "" || busy}
              className="uppercase"
            >
              {busy ? "…" : "save config"}
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
  const { busy, submit } = useGuardedSubmit()
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button id="device-form-btn" variant="outline" size="sm" disabled={!!blocked} className="micro" title={blocked ?? "runtime device form: listen port and firewall mark"}>
          device
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">RUNTIME DEVICE</DialogTitle>
          <DialogDescription className="text-xs">
            Changed on the running tunnel. Changing the listen port rebinds it,
            but existing sessions stay up.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            submit(() => report(applyDevice(port.trim(), mark.trim()), () => setOpen(false)))
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
          <Field label="firewall mark" hint="advanced routing tag — empty keeps the current value">
            <Input
              value={mark}
              onChange={(e) => setMark(e.target.value)}
              inputMode="numeric"
              placeholder={fwmark !== null ? String(fwmark) : "0"}
            />
          </Field>
          <DialogFooter showCloseButton>
            <Button type="submit" size="sm" disabled={busy} className="uppercase">
              {busy ? "…" : "apply"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
