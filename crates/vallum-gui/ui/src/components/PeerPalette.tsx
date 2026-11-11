import {
  CommandDialog,
  CommandEmpty,
  CommandFooter,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import { freshness, freshnessLabel } from "@/lib/traffic"
import type { Peer } from "@/types"

// The GUI expression of brandkit card 09 and the TUI's `:` dispatch: one box
// that finds anything and does anything. The verbs below are the TUI palette's
// names, categories, keywords, and single letters, verbatim — an operator
// switching between the console and the terminal meets the same words for the
// same verbs. Where the GUI cannot do the thing, the keywords say so: its
// invite is a text ticket, not a QR. Peer-scoped verbs apply to the selected
// peer and disable without one, the way the terminal guards the same way.
// Trigger is `:` like the TUI; ⌘K stays as an unadvertised alias. The TUI's
// single letters are display-only here: global letter shortcuts are a loaded
// key, so the palette is filter-and-Enter (its own footer says so) and every
// verb fires the same button the mouse would. No chip advertises a key that
// does nothing.
export function PeerPalette({
  open,
  onOpenChange,
  peers,
  now,
  selected,
  selectedRotating,
  onSelect,
  onCycleSort,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  peers: Peer[]
  now: number
  selected: string | null
  selectedRotating: boolean
  onSelect: (fingerprint: string) => void
  onCycleSort: () => void
}) {
  const fire = (id: string) => {
    onOpenChange(false)
    // The dialogs own their open state; firing their buttons reuses the one
    // mechanism instead of inventing a second. A disabled button (no daemon)
    // eats the click, which is the correct outcome there too.
    window.setTimeout(() => {
      ;(
        document.getElementById(id) as HTMLButtonElement | null
      )?.click()
    }, 0)
  }
  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Command palette"
    >
      <CommandInput placeholder="Type a command or find a peer…" />
      <CommandList>
        <CommandEmpty>No command or peer matches.</CommandEmpty>
        <CommandGroup heading="Peer">
          <CommandItem
            value="add peer…"
            keywords={["new", "device", "client"]}
            onSelect={() => fire("add-peer-btn")}
          >
            <span className="min-w-0 flex-1 truncate">add peer…</span>
          </CommandItem>
          <CommandItem
            value="invite peer (one-time token)…"
            keywords={["invite", "token", "join", "enroll", "ticket"]}
            onSelect={() => fire("invite-peer-btn")}
          >
            <span className="min-w-0 flex-1 truncate">
              invite peer (one-time token)…
            </span>
          </CommandItem>
          <CommandItem
            value="rotate peer key…"
            keywords={["rotate", "rekey", "replace", "identity"]}
            disabled={!selected}
            onSelect={() => fire("rotate-peer-btn")}
          >
            <span className="min-w-0 flex-1 truncate">rotate peer key…</span>
          </CommandItem>
          <CommandItem
            value="finalize peer key rotation…"
            keywords={["finalize", "retire", "rotation", "old", "key"]}
            disabled={!selected || !selectedRotating}
            onSelect={() => fire("finalize-peer-btn")}
          >
            <span className="min-w-0 flex-1 truncate">
              finalize peer key rotation…
            </span>
          </CommandItem>
          <CommandItem
            value="edit peer…"
            keywords={["change", "endpoint", "keepalive", "psk"]}
            disabled={!selected}
            onSelect={() => fire("edit-peer-btn")}
          >
            <span className="min-w-0 flex-1 truncate">edit peer…</span>
          </CommandItem>
          <CommandItem
            value="remove peer…"
            keywords={["delete", "revoke"]}
            disabled={!selected}
            onSelect={() => fire("remove-peer-btn")}
          >
            <span className="min-w-0 flex-1 truncate">remove peer…</span>
          </CommandItem>
          <CommandItem
            value="ping peer"
            keywords={["test", "reachability"]}
            disabled={!selected}
            onSelect={() => fire("ping-peer-btn")}
          >
            <span className="min-w-0 flex-1 truncate">ping peer</span>
          </CommandItem>
          <CommandItem
            value="copy public line"
            keywords={["clipboard", "yank"]}
            disabled={!selected}
            onSelect={() => fire("copy-line-btn")}
          >
            <span className="min-w-0 flex-1 truncate">copy public line</span>
          </CommandItem>
          <CommandItem
            value="copy peer address"
            keywords={["clipboard", "yank", "endpoint", "ip"]}
            disabled={!selected}
            onSelect={() => fire("copy-address-btn")}
          >
            <span className="min-w-0 flex-1 truncate">copy peer address</span>
          </CommandItem>
          <CommandItem
            value="generate key"
            keywords={["keygen", "identity"]}
            onSelect={() => fire("generate-key-btn")}
          >
            <span className="min-w-0 flex-1 truncate">generate key</span>
          </CommandItem>
          <CommandItem
            value="runtime device form…"
            keywords={["listen", "port", "fwmark", "temporary"]}
            onSelect={() => fire("device-form-btn")}
          >
            <span className="min-w-0 flex-1 truncate">runtime device form…</span>
          </CommandItem>
          <CommandItem
            value="edit interface config…"
            keywords={["config", "toml", "edit", "interface", "file"]}
            onSelect={() => fire("config-editor-btn")}
          >
            <span className="min-w-0 flex-1 truncate">edit interface config…</span>
          </CommandItem>
          <CommandItem
            value="cycle peer sort"
            keywords={["order", "name", "transfer", "handshake"]}
            onSelect={() => {
              onCycleSort()
              onOpenChange(false)
            }}
          >
            <span className="min-w-0 flex-1 truncate">cycle peer sort</span>
          </CommandItem>
        </CommandGroup>
        <CommandGroup heading="Bundle">
          <CommandItem
            value="export client bundle…"
            keywords={["bundle", "share", "mobile", "file", "download", "qr"]}
            disabled={!selected}
            onSelect={() => fire("export-bundle-btn")}
          >
            <span className="min-w-0 flex-1 truncate">export client bundle…</span>
          </CommandItem>
          <CommandItem
            value="import client bundle…"
            keywords={["bundle", "load", "client", "config", "install"]}
            onSelect={() => fire("import-bundle-btn")}
          >
            <span className="min-w-0 flex-1 truncate">import client bundle…</span>
          </CommandItem>
        </CommandGroup>
        <CommandGroup heading="Peers">
          {peers.map((peer) => {
            const age =
              peer.last_handshake_sec === 0
                ? "never"
                : `${Math.max(0, now - peer.last_handshake_sec)}s ago`
            return (
              <CommandItem
                key={peer.fingerprint}
                value={`${peer.name} ${peer.allowed_ips.join(" ")} ${peer.fingerprint}`}
                keywords={[peer.name, ...peer.allowed_ips]}
                onSelect={() => {
                  onSelect(peer.fingerprint)
                  onOpenChange(false)
                }}
              >
                <span
                  aria-hidden
                  className={
                    peer.fingerprint === selected
                      ? "text-signal text-[8px]"
                      : "text-transparent text-[8px]"
                  }
                >
                  ●
                </span>
                <span className="min-w-0 flex-1 truncate">{peer.name}</span>
                <span className="text-muted-foreground shrink-0 text-xs">
                  {freshnessLabel[freshness(peer.last_handshake_sec, now)]} · {age}
                </span>
              </CommandItem>
            )
          })}
        </CommandGroup>
      </CommandList>
      <CommandFooter />
    </CommandDialog>
  )
}
