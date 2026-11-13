import { useEffect, useRef, useState, type ReactNode } from "react"
import { Download, KeyRound, QrCode, RotateCcw, Shield, SlidersHorizontal, User } from "lucide-react"
import { toast } from "sonner"
import { CopyButton } from "@/components/Copy"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Panel } from "@/components/ui/panel"
import { qrFrame, readConfig, type KeyOut, type QrFrame } from "@/lib/actions"
import { ROLE_META, type UserPrefs } from "@/lib/userPrefs"
import { formatError, suiteLabel } from "@/lib/validate"
import type { Snapshot } from "@/types"

function downloadTextFile(filename: string, contents: string, mime = "text/plain") {
  const url = URL.createObjectURL(new Blob([contents], { type: mime }))
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function PublicKeyQr({ text }: { text: string }) {
  const [frame, setFrame] = useState<QrFrame | null>(null)
  const [error, setError] = useState<string | null>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    let active = true
    qrFrame(text, 0)
      .then((next) => {
        if (!active) return
        setFrame(next)
        setError(null)
      })
      .catch((err: unknown) => {
        if (!active) return
        setError(formatError(err))
      })
    return () => {
      active = false
    }
  }, [text])

  useEffect(() => {
    const node = canvasRef.current
    if (!node || !frame) return
    const quiet = 2
    const pixels = 168
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

  if (error) {
    return (
      <p className="text-stale font-mono text-[11px]">
        Unable to render QR for public key: {error}
      </p>
    )
  }

  return (
    <div className="border-signal/35 bg-background/70 flex flex-wrap items-center gap-3 rounded-lg border p-3">
      <canvas
        ref={canvasRef}
        className="h-32 w-32 shrink-0 rounded-sm bg-white p-1"
        aria-label="Local device public key QR code"
      />
      <div className="min-w-0 flex-1 space-y-1">
        <div className="text-signal font-mono text-[11px] font-semibold tracking-wider uppercase">
          Public identity QR · share safely
        </div>
        <p className="text-muted-foreground text-xs leading-relaxed">
          Contains only this device&apos;s public key line ({frame ? `frame 1/${frame.total}` : "encoding…"}).
          No private key leaves this host.
        </p>
      </div>
    </div>
  )
}

export function UserKeyCard({
  data,
  interfaceName,
  blocked,
  prefs,
  renderKeygen,
}: {
  data: Snapshot | null
  interfaceName: string
  blocked?: string
  prefs: UserPrefs
  /** Slot that renders <KeygenButton onGenerated={...} /> so `#generate-key-btn` stays unique. */
  renderKeygen: (onGenerated: (out: KeyOut) => void) => ReactNode
}) {
  const [showQr, setShowQr] = useState(false)
  const [mintedKey, setMintedKey] = useState<KeyOut | null>(null)
  const [revealKey, setRevealKey] = useState(false)

  const displayName = prefs.alias.trim() || interfaceName || "vallum0"
  const roleInfo = ROLE_META[prefs.role]

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <User className="text-signal size-3.5" aria-hidden />
          <span>User Identity &amp; Keys</span>
        </span>
      }
      right={
        <span className="border-signal/40 bg-signal/10 text-signal rounded border px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase">
          {roleInfo.badge}
        </span>
      }
    >
      <div className="flex flex-col gap-3.5">
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
          <div className="border-border/50 bg-background/40 rounded-md border px-2.5 py-2">
            <div className="micro">Operator / Host</div>
            <div className="text-foreground truncate font-mono text-xs font-semibold" title={displayName}>
              {displayName}
            </div>
          </div>
          <div className="border-border/50 bg-background/40 rounded-md border px-2.5 py-2">
            <div className="micro">Tunnel IP</div>
            <div className="text-signal truncate font-mono text-xs font-semibold">
              {data?.addresses[0] ?? "—"}
            </div>
          </div>
          <div className="border-border/50 bg-background/40 rounded-md border px-2.5 py-2">
            <div className="micro">Key Fingerprint</div>
            <div className="text-foreground truncate font-mono text-xs" title={data?.fingerprint ?? ""}>
              {data?.fingerprint || "—"}
            </div>
          </div>
          <div className="border-border/50 bg-background/40 rounded-md border px-2.5 py-2">
            <div className="micro">Crypto Suite</div>
            <div className="text-violet truncate font-mono text-xs">
              {suiteLabel(data?.suite)}
            </div>
          </div>
        </div>

        <div className="border-border/60 bg-background/45 flex flex-col gap-2 rounded-lg border p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="micro flex items-center gap-1.5">
              <Shield className="text-signal size-3" aria-hidden />
              <span>This device&apos;s public key line</span>
            </span>
            <span className="text-muted-foreground font-mono text-[10px]">
              safe to share with peers
            </span>
          </div>
          {data?.public_line ? (
            <>
              <code className="border-border/60 bg-background/70 text-foreground/90 block rounded border px-2.5 py-2 font-mono text-[11px] break-all select-all">
                {data.public_line}
              </code>
              <div className="flex flex-wrap items-center gap-2">
                <CopyButton
                  value={data.public_line}
                  label="Copy Public Key"
                  title="Copy this host's vallum1: public key line"
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    downloadTextFile(`${interfaceName || "vallum0"}.pub`, `${data.public_line}\n`)
                    toast.success(`Downloaded ${interfaceName || "vallum0"}.pub`)
                  }}
                >
                  <Download className="size-3.5" aria-hidden />
                  <span>Download .pub</span>
                </Button>
                <Button
                  type="button"
                  variant={showQr ? "default" : "outline"}
                  size="sm"
                  onClick={() => setShowQr((cur) => !cur)}
                >
                  <QrCode className="size-3.5" aria-hidden />
                  <span>{showQr ? "Hide QR" : "Show Key QR"}</span>
                </Button>
              </div>
              {showQr && <PublicKeyQr text={data.public_line} />}
            </>
          ) : (
            <p className="text-muted-foreground text-xs">
              Waiting for the running daemon to report this device&apos;s public key line.
            </p>
          )}
        </div>

        <div className="border-border/60 bg-background/45 flex flex-col gap-2.5 rounded-lg border p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-foreground flex items-center gap-1.5 text-xs font-medium">
                <KeyRound className="text-violet size-3.5" aria-hidden />
                <span>Offline Keypair Generator</span>
              </div>
              <p className="text-muted-foreground mt-0.5 text-[11px]">
                Mint a standalone ML-KEM-1024 + X25519 + ML-DSA-65 identity keypair for a new client or backup.
              </p>
            </div>
            {renderKeygen((out) => {
              setMintedKey(out)
              setRevealKey(false)
            })}
          </div>

          {mintedKey && (
            <div className="border-violet/40 bg-violet/8 flex flex-col gap-2 rounded-md border p-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-violet font-mono text-[11px] font-semibold">
                  Minted: {mintedKey.filename}
                </span>
                <div className="flex flex-wrap items-center gap-1.5">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-7 px-2 text-[11px]"
                    onClick={() => setRevealKey((r) => !r)}
                  >
                    {revealKey ? "Hide Key" : "Inspect"}
                  </Button>
                  <CopyButton
                    value={mintedKey.text}
                    label="Copy Key"
                    className="h-7 px-2 text-[11px]"
                  />
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-7 px-2 text-[11px]"
                    onClick={() => downloadTextFile(mintedKey.filename, mintedKey.text)}
                  >
                    Save .key
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    className="h-7 px-2 text-[11px]"
                    onClick={() => setMintedKey(null)}
                  >
                    Dismiss
                  </Button>
                </div>
              </div>
              <p className="text-foreground/85 text-[11px]">{mintedKey.message}</p>
              {revealKey && (
                <pre className="border-border/60 bg-background/80 text-foreground/90 max-h-36 overflow-auto rounded border p-2 font-mono text-[11px] whitespace-pre-wrap break-all">
                  {mintedKey.text}
                </pre>
              )}
              {blocked && (
                <p className="text-muted-foreground text-[11px]">
                  Note: daemon socket controls are paused while offline.
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}

export function UserPreferencesPanel({
  prefs,
  onUpdate,
  onReset,
  comfortable,
  onToggleComfortable,
  interfaceName,
  blocked,
}: {
  prefs: UserPrefs
  onUpdate: (patch: Partial<UserPrefs>) => void
  onReset: () => void
  comfortable: boolean
  onToggleComfortable: () => void
  interfaceName: string
  blocked?: string
}) {
  const [backingUp, setBackingUp] = useState(false)

  const handleBackup = () => {
    if (backingUp) return
    setBackingUp(true)
    readConfig()
      .then((toml) => {
        const name = `${interfaceName || "vallum0"}-backup.toml`
        downloadTextFile(name, toml)
        toast.success(`Downloaded config backup (${name})`)
      })
      .catch((err: unknown) => {
        toast.error(formatError(err), { duration: 6000 })
      })
      .finally(() => setBackingUp(false))
  }

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <SlidersHorizontal className="text-signal size-3.5" aria-hidden />
          <span>User Settings &amp; Everyday QoL</span>
        </span>
      }
      right={
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-[11px]"
          onClick={() => {
            onReset()
            toast.success("User preferences restored to defaults")
          }}
          title="Restore default user preferences"
        >
          <RotateCcw className="size-3" aria-hidden />
          <span>Reset</span>
        </Button>
      }
    >
      <div className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1">
            <label htmlFor="user-alias-input" className="micro">
              Operator / Device Alias
            </label>
            <Input
              id="user-alias-input"
              value={prefs.alias}
              onChange={(e) => onUpdate({ alias: e.target.value })}
              placeholder={interfaceName || "workstation-01"}
              maxLength={32}
            />
            <span className="text-muted-foreground text-[11px]">
              Shown in the top bar and your local identity card.
            </span>
          </div>

          <div className="flex flex-col gap-1">
            <span className="micro">Device Role</span>
            <div className="grid grid-cols-3 gap-1">
              {(["client", "server", "mesh"] as const).map((role) => {
                const active = prefs.role === role
                return (
                  <button
                    key={role}
                    type="button"
                    aria-pressed={active}
                    onClick={() => onUpdate({ role })}
                    className={`cursor-pointer rounded-md border px-2 py-2 text-[11px] font-medium transition-colors ${
                      active
                        ? "border-signal/60 bg-signal/15 text-signal"
                        : "border-border/60 bg-background/40 text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {role === "client" ? "Client" : role === "server" ? "Gateway" : "Mesh"}
                  </button>
                )
              })}
            </div>
            <span className="text-muted-foreground text-[11px]">
              {ROLE_META[prefs.role].hint}
            </span>
          </div>
        </div>

        <div className="border-border/50 grid grid-cols-1 gap-3 border-t pt-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <span className="micro">Default Invite Expiration</span>
            <div className="flex flex-wrap gap-1">
              {(
                [
                  ["15", "15m"],
                  ["60", "1h"],
                  ["1440", "24h"],
                  ["10080", "7d"],
                ] as const
              ).map(([val, label]) => {
                const active = prefs.defaultInviteTtl === val
                return (
                  <button
                    key={val}
                    type="button"
                    aria-pressed={active}
                    onClick={() => onUpdate({ defaultInviteTtl: val })}
                    className={`cursor-pointer rounded border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                      active
                        ? "border-signal/60 bg-signal/15 text-signal font-semibold"
                        : "border-border/60 bg-background/40 text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {label}
                  </button>
                )
              })}
            </div>
            <span className="text-muted-foreground text-[11px]">
              Pre-filled whenever you open Invite Device.
            </span>
          </div>

          <div className="flex flex-col gap-1.5">
            <span className="micro">Default Peer Keepalive</span>
            <div className="flex flex-wrap gap-1">
              {(
                [
                  ["25", "25s NAT"],
                  ["60", "60s"],
                  ["", "Off"],
                ] as const
              ).map(([val, label]) => {
                const active = prefs.defaultKeepalive === val
                return (
                  <button
                    key={label}
                    type="button"
                    aria-pressed={active}
                    onClick={() => onUpdate({ defaultKeepalive: val })}
                    className={`cursor-pointer rounded border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                      active
                        ? "border-signal/60 bg-signal/15 text-signal font-semibold"
                        : "border-border/60 bg-background/40 text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {label}
                  </button>
                )
              })}
            </div>
            <span className="text-muted-foreground text-[11px]">
              Pre-filled when adding new peers manually.
            </span>
          </div>
        </div>

        <div className="border-border/50 flex flex-wrap items-center justify-between gap-2 border-t pt-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              aria-pressed={prefs.autoCopyInvites}
              onClick={() => onUpdate({ autoCopyInvites: !prefs.autoCopyInvites })}
              className={`cursor-pointer rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                prefs.autoCopyInvites
                  ? "border-live/50 bg-live/10 text-live"
                  : "border-border/60 bg-background/40 text-muted-foreground"
              }`}
            >
              Auto-copy invites: {prefs.autoCopyInvites ? "On" : "Off"}
            </button>
            <button
              type="button"
              aria-pressed={comfortable}
              onClick={onToggleComfortable}
              className="border-border/60 bg-background/40 text-foreground/90 hover:bg-secondary/60 cursor-pointer rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors"
            >
              Density: {comfortable ? "Comfortable" : "Compact"}
            </button>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={!!blocked || backingUp}
            title={blocked ?? "Download a local backup copy of the active TOML config"}
            onClick={handleBackup}
          >
            <Download className="size-3.5" aria-hidden />
            <span>{backingUp ? "Exporting…" : "Backup Config (.toml)"}</span>
          </Button>
        </div>
      </div>
    </Panel>
  )
}
