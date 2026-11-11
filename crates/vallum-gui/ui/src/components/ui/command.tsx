import * as React from "react"
import { Command as CommandPrimitive } from "cmdk"
import { Search } from "lucide-react"
import { cn } from "@/lib/utils"
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog"

// The shadcn command primitives — the same cmdk + Radix base the 21st
// catalogue builds its palettes on — restyled to the console's tokens: mono
// type, card surfaces, signal ring. No light-mode branches and no marketing
// font: this console is dark-only and every label stays in the type ramp.

function Command({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive>) {
  return (
    <CommandPrimitive
      data-slot="command"
      className={cn(
        "bg-card text-foreground flex h-full w-full flex-col overflow-hidden rounded-lg",
        className,
      )}
      {...props}
    />
  )
}

function CommandDialog({
  title = "Command",
  children,
  ...props
}: React.ComponentProps<typeof Dialog> & {
  title?: string
}) {
  return (
    <Dialog {...props}>
      <DialogTitle className="sr-only">{title}</DialogTitle>
      <DialogContent
        showCloseButton={false}
        className="overflow-hidden p-0 sm:max-w-md"
      >
        <Command className="[&_[cmdk-group-heading]]:text-muted-foreground [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group]]:px-1">
          {children}
        </Command>
      </DialogContent>
    </Dialog>
  )
}

function CommandInput({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Input>) {
  return (
    <div
      data-slot="command-input-wrapper"
      className="border-border flex h-10 items-center gap-2 border-b px-3"
    >
      <Search className="text-muted-foreground size-4 shrink-0" aria-hidden />
      <CommandPrimitive.Input
        data-slot="command-input"
        className={cn(
          "placeholder:text-muted-foreground text-foreground flex h-10 w-full rounded-md bg-transparent text-sm outline-none disabled:cursor-not-allowed disabled:opacity-50",
          className,
        )}
        {...props}
      />
    </div>
  )
}

function CommandList({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.List>) {
  // Adopted from uvain's Command Menu (MIT, via 21st): cmdk wraps groups in
  // a sizing div with no role, breaking the listbox → group → option chain
  // for assistive tech. Mark it presentational and silence the dividers.
  const ref = React.useRef<HTMLDivElement>(null)
  React.useEffect(() => {
    ref.current
      ?.querySelector("[cmdk-list-sizer]")
      ?.setAttribute("role", "presentation")
    ref.current
      ?.querySelectorAll("[cmdk-separator]")
      .forEach((el) => el.setAttribute("role", "none"))
  })
  return (
    <CommandPrimitive.List
      ref={ref}
      data-slot="command-list"
      className={cn(
        "max-h-64 scroll-py-1 overflow-x-hidden overflow-y-auto p-1",
        className,
      )}
      {...props}
    />
  )
}

function CommandEmpty({
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Empty>) {
  return (
    <CommandPrimitive.Empty
      data-slot="command-empty"
      className="text-muted-foreground py-6 text-center text-xs"
      {...props}
    />
  )
}

function CommandGroup({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Group>) {
  return (
    <CommandPrimitive.Group
      data-slot="command-group"
      className={cn(
        "text-foreground [&_[cmdk-group-items]]:flex [&_[cmdk-group-items]]:flex-col [&_[cmdk-group-items]]:gap-0.5 overflow-hidden [&_[cmdk-group-heading]]:text-muted-foreground [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pt-1.5 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:uppercase",
        className,
      )}
      {...props}
    />
  )
}

function CommandItem({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Item>) {
  return (
    <CommandPrimitive.Item
      data-slot="command-item"
      className={cn(
        "aria-selected:bg-secondary aria-selected:text-foreground text-foreground/90 relative flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-xs outline-none select-none data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50",
        className,
      )}
      {...props}
    />
  )
}

function CommandShortcut({
  className,
  ...props
}: React.ComponentProps<"span">) {
  return (
    <span
      data-slot="command-shortcut"
      className={cn(
        "border-border text-muted-foreground ml-auto shrink-0 rounded border px-1 font-mono text-xs",
        className,
      )}
      {...props}
    />
  )
}

// The contract line, in the brand's own words (card 09: "type to filter ·
// enter/click runs · esc closes"). Every palette states how it behaves;
// first-time users never have to guess. Adopted from uvain's footer pattern.
function CommandFooter({
  className,
  children,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="command-footer"
      className={cn(
        "border-border text-muted-foreground flex items-center gap-3 border-t px-3 py-2 text-xs",
        className,
      )}
      {...props}
    >
      {children ?? (
        <>
          <span>type to filter</span>
          <span>enter runs</span>
          <span>esc closes</span>
        </>
      )}
    </div>
  )
}

export {
  Command,
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandShortcut,
  CommandFooter,
}
