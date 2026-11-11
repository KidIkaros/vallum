import { useState } from "react"

// Copy-to-clipboard for values an operator carries elsewhere: a public line, a
// join ticket. Silent on failure would be a lie, so the label reports it.
export function CopyButton({
  value,
  label = "copy",
  title,
  className = "",
  id,
  disabled = false,
}: {
  value: string
  label?: string
  title?: string
  className?: string
  disabled?: boolean
  /** Fired by the palette; the button stays the one mechanism. Global
   *  single-letter shortcuts were removed, so nothing fires this but a
   *  click or the palette row. */
  id?: string
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle")
  const copy = async () => {
    // The async API needs a secure context and permission; a hidden textarea and
    // the legacy command works where it does not. A copy button that silently
    // does nothing is worse than one that says it failed.
    const legacy = () => {
      const area = document.createElement("textarea")
      area.value = value
      area.style.position = "fixed"
      area.style.opacity = "0"
      document.body.appendChild(area)
      area.select()
      const ok = document.execCommand("copy")
      document.body.removeChild(area)
      return ok
    }
    let ok = false
    try {
      await navigator.clipboard.writeText(value)
      ok = true
    } catch {
      ok = legacy()
    }
    setState(ok ? "copied" : "failed")
    window.setTimeout(() => setState("idle"), 1500)
  }
  return (
    <button
      id={id}
      disabled={disabled}
      onClick={() => void copy()}
      title={title ?? "copy to clipboard"}
      className={`micro hover:text-foreground border-border/60 hover:border-border cursor-pointer rounded border px-1.5 py-0.5 uppercase ${className}`}
    >
      {state === "copied" ? "copied" : state === "failed" ? "copy failed" : label}
    </button>
  )
}
