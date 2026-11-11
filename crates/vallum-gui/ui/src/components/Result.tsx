import { useState } from "react"
import { Button } from "@/components/ui/button"

// An action that produces something to carry away — a join ticket, a rotation
// notice — must show it where it can be read and copied. A toast disappears;
// an invite ticket is useless once it has.
export function ResultPanel({
  message,
  command,
  onDone,
}: {
  message: string
  command?: string
  onDone: () => void
}) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    if (!command) return
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }
  return (
    <div className="flex flex-col gap-3">
      <p className="text-foreground/90 text-xs">{message}</p>
      {command && (
        <>
          <pre className="border-border/70 bg-background/50 text-foreground/85 max-h-40 overflow-auto rounded-md border px-2 py-2 font-mono text-[11px] whitespace-pre-wrap break-all">
            {command}
          </pre>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => void copy()}>
              {copied ? "copied" : "copy command"}
            </Button>
            <span className="text-muted-foreground text-[11px]">
              run it on the other device
            </span>
          </div>
        </>
      )}
      <Button size="sm" className="self-end uppercase" onClick={onDone}>
        done
      </Button>
    </div>
  )
}
