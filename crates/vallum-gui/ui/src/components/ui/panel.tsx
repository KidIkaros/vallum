import type { ReactNode } from "react"

// The cockpit's panel shell: a bordered card with a diamond-marked title.
// Extracted from App.tsx so panels in their own files render identically.

export function Diamond() {
  return (
    <svg viewBox="0 0 8 8" className="size-2 shrink-0" aria-hidden>
      <path d="M4 0 L8 4 L4 8 L0 4 Z" fill="currentColor" className="text-signal" />
    </svg>
  )
}

export function PanelTitle({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-2">
      <Diamond />
      <span className="text-signal text-xs font-semibold tracking-[0.08em] uppercase">{children}</span>
    </div>
  )
}

export function Panel({
  title,
  right,
  children,
  className = "",
}: {
  title: ReactNode
  right?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`surface rounded-xl ${className}`}>
      <div className="flex items-center justify-between gap-3 px-5 pt-4 pb-2">
        <PanelTitle>{title}</PanelTitle>
        {right}
      </div>
      <div className="px-5 pb-4">{children}</div>
    </section>
  )
}
