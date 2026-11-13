import { CopyButton } from "@/components/Copy"
import type { ErrorCodeEntry } from "@/lib/diagnostics"

export function DiagnosticCallout({
  entry,
  detail,
  onOpenCatalog,
}: {
  entry: ErrorCodeEntry
  detail?: string
  onOpenCatalog?: (code?: string) => void
}) {
  return (
    <div className="border-fault/45 bg-fault/8 mt-2 flex flex-col gap-1.5 rounded-lg border px-3 py-2.5 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <span className="bg-fault text-background rounded px-1.5 py-0.5 font-mono text-[11px] font-semibold">
          {entry.code}
        </span>
        <span className="border-border/70 bg-background/60 text-muted-foreground rounded border px-1.5 py-0.5 font-mono text-[11px]">
          {entry.exitLabel}
        </span>
        <span className="text-foreground font-semibold">{entry.title}</span>
        {onOpenCatalog && (
          <button
            type="button"
            onClick={() => onOpenCatalog(entry.code)}
            className="text-signal ml-auto cursor-pointer text-xs font-medium hover:underline"
          >
            Explain error →
          </button>
        )}
      </div>
      <p className="text-muted-foreground leading-snug">{detail || entry.summary}</p>
      <p className="text-foreground/85 leading-snug">Fix: {entry.remediation}</p>
      {entry.command && (
        <details className="border-border/60 bg-background/60 mt-0.5 rounded border px-2 py-1">
          <summary className="text-muted-foreground hover:text-foreground cursor-pointer text-[11px] select-none">
            Show terminal command
          </summary>
          <div className="mt-1 flex items-center justify-between gap-2">
            <code className="text-signal min-w-0 truncate font-mono text-[11px]">
              {entry.command}
            </code>
            <CopyButton value={entry.command} label="Copy" />
          </div>
        </details>
      )}
    </div>
  )
}
