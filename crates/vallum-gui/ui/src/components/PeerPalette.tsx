import {
  CommandDialog,
  CommandEmpty,
  CommandFooter,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from "@/components/ui/command"
import { freshness, freshnessLabel } from "@/lib/traffic"
import type { Peer } from "@/types"

function Tag({ label }: { label: string }) {
  return (
    <span className="text-signal/85 w-14 shrink-0 font-mono text-[10px] font-semibold tracking-wider uppercase">
      {label}
    </span>
  )
}

// The GUI expression of brandkit card 09 and the TUI's `:` dispatch: one box
// that finds anything and does anything. The verbs below mirror the TUI palette's
// categories, names, keywords, and shortcuts verbatim — an operator switching
// between the console and the terminal meets the same verbs and structure.
export function PeerPalette({
  open,
  onOpenChange,
  peers,
  now,
  selected,
  selectedRotating,
  onSelect,
  onCycleSort,
  sortLabel,
  hasFilter,
  onClearFilter,
  onRefresh,
  onPrevPeer,
  onNextPeer,
  onSwitchInterface,
  interfaceCount,
  onToggleDensity,
  comfortable,
  onOpenShortcuts,
  onOpenDiagnostics,
  onOpenMetrics,
  onOpenOnboarding,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  peers: Peer[]
  now: number
  selected: string | null
  selectedRotating: boolean
  onSelect: (fingerprint: string) => void
  onCycleSort: () => void
  sortLabel: string
  hasFilter: boolean
  onClearFilter: () => void
  onRefresh: () => void
  onPrevPeer: () => void
  onNextPeer: () => void
  onSwitchInterface: () => void
  interfaceCount: number
  onToggleDensity: () => void
  comfortable: boolean
  onOpenShortcuts: () => void
  onOpenDiagnostics: () => void
  onOpenMetrics?: () => void
  onOpenOnboarding: () => void
}) {
  const fire = (id: string) => {
    onOpenChange(false)
    window.setTimeout(() => {
      ;(
        document.getElementById(id) as HTMLButtonElement | null
      )?.click()
    }, 0)
  }

  const run = (fn: () => void) => {
    onOpenChange(false)
    window.setTimeout(fn, 0)
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
            keywords={["new", "device", "client", "a"]}
            onSelect={() => fire("add-peer-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">add peer…</span>
          </CommandItem>
          <CommandItem
            value="invite peer (one-time token)…"
            keywords={["invite", "token", "join", "enroll", "ticket", "t"]}
            onSelect={() => fire("invite-peer-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">
              invite peer (one-time token)…
            </span>
          </CommandItem>
          <CommandItem
            value="rotate peer key…"
            keywords={["rotate", "rekey", "replace", "identity", "r"]}
            disabled={!selected}
            onSelect={() => fire("rotate-peer-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">rotate peer key…</span>
          </CommandItem>
          <CommandItem
            value="finalize peer key rotation…"
            keywords={["finalize", "retire", "rotation", "old", "key", "f"]}
            disabled={!selected || !selectedRotating}
            onSelect={() => fire("finalize-peer-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">
              finalize peer key rotation…
            </span>
          </CommandItem>
          <CommandItem
            value="edit peer…"
            keywords={["change", "endpoint", "keepalive", "psk", "e"]}
            disabled={!selected}
            onSelect={() => fire("edit-peer-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">edit peer…</span>
          </CommandItem>
          <CommandItem
            value="remove peer…"
            keywords={["delete", "revoke", "d"]}
            disabled={!selected}
            onSelect={() => fire("remove-peer-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">remove peer…</span>
          </CommandItem>
          <CommandItem
            value="ping peer"
            keywords={["test", "reachability"]}
            disabled={!selected}
            onSelect={() => fire("ping-peer-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">ping peer</span>
          </CommandItem>
          <CommandItem
            value="copy public line"
            keywords={["clipboard", "yank", "c"]}
            disabled={!selected}
            onSelect={() => fire("copy-line-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">copy public line</span>
          </CommandItem>
          <CommandItem
            value="copy peer address"
            keywords={["clipboard", "yank", "endpoint", "ip"]}
            disabled={!selected}
            onSelect={() => fire("copy-address-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">copy peer address</span>
          </CommandItem>
          <CommandItem
            value="generate key"
            keywords={["keygen", "identity", "g"]}
            onSelect={() => fire("generate-key-btn")}
          >
            <Tag label="PEER" />
            <span className="min-w-0 flex-1 truncate">generate key</span>
          </CommandItem>
        </CommandGroup>

        <CommandGroup heading="Config & Interface">
          <CommandItem
            value="interface config form…"
            keywords={["interface", "listen", "mtu", "addresses", "dns", "table", "i"]}
            onSelect={() => fire("interface-form-btn")}
          >
            <Tag label="CONFIG" />
            <span className="min-w-0 flex-1 truncate">interface config form…</span>
            <CommandShortcut>i</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="edit raw config TOML…"
            keywords={["config", "toml", "edit", "diff", "file", "E"]}
            onSelect={() => fire("config-editor-btn")}
          >
            <Tag label="CONFIG" />
            <span className="min-w-0 flex-1 truncate">edit raw config TOML (with diff)…</span>
            <CommandShortcut>E</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="save runtime config"
            keywords={["save", "persist", "write", "runtime", "toml", "W"]}
            onSelect={() => fire("save-runtime-btn")}
          >
            <Tag label="CONFIG" />
            <span className="min-w-0 flex-1 truncate">save runtime config to disk</span>
            <CommandShortcut>W</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="runtime device form…"
            keywords={["listen", "port", "fwmark", "temporary", "device"]}
            onSelect={() => fire("device-form-btn")}
          >
            <Tag label="CONFIG" />
            <span className="min-w-0 flex-1 truncate">runtime device form (listen / fwmark)…</span>
          </CommandItem>
        </CommandGroup>

        <CommandGroup heading="Bundle">
          <CommandItem
            value="export client bundle…"
            keywords={["bundle", "share", "mobile", "file", "download", "qr", "x"]}
            disabled={!selected}
            onSelect={() => fire("export-bundle-btn")}
          >
            <Tag label="BUNDLE" />
            <span className="min-w-0 flex-1 truncate">export client bundle (with QR)…</span>
          </CommandItem>
          <CommandItem
            value="import client bundle…"
            keywords={["bundle", "load", "client", "config", "install"]}
            onSelect={() => fire("import-bundle-btn")}
          >
            <Tag label="BUNDLE" />
            <span className="min-w-0 flex-1 truncate">import client bundle…</span>
          </CommandItem>
        </CommandGroup>

        <CommandGroup heading="Service & View">
          <CommandItem
            value="start tunnel service"
            keywords={["service", "systemd", "up", "start", "s"]}
            onSelect={() => fire("service-start-btn")}
          >
            <Tag label="SERVICE" />
            <span className="min-w-0 flex-1 truncate">start tunnel service</span>
          </CommandItem>
          <CommandItem
            value="stop tunnel service"
            keywords={["service", "systemd", "down", "stop"]}
            onSelect={() => fire("service-stop-btn")}
          >
            <Tag label="SERVICE" />
            <span className="min-w-0 flex-1 truncate">stop tunnel service</span>
          </CommandItem>
          <CommandItem
            value="view logs"
            keywords={["journald", "logs", "tail", "follow", "l"]}
            onSelect={() =>
              run(() => {
                const details = document.getElementById("logs-panel") as HTMLDetailsElement | null
                if (details) {
                  details.open = true
                  details.scrollIntoView({ behavior: "smooth", block: "nearest" })
                }
              })
            }
          >
            <Tag label="SERVICE" />
            <span className="min-w-0 flex-1 truncate">view daemon logs</span>
          </CommandItem>
          <CommandItem
            value="refresh telemetry"
            keywords={["refresh", "poll", "health", "service", "r"]}
            onSelect={() => run(onRefresh)}
          >
            <Tag label="SERVICE" />
            <span className="min-w-0 flex-1 truncate">refresh telemetry &amp; health</span>
            <CommandShortcut>r</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="filter peers"
            keywords={["search", "filter", "find", "/"]}
            onSelect={() =>
              run(() => {
                document.getElementById("peer-filter")?.focus()
              })
            }
          >
            <Tag label="VIEW" />
            <span className="min-w-0 flex-1 truncate">filter peers…</span>
            <CommandShortcut>/</CommandShortcut>
          </CommandItem>
          {hasFilter && (
            <CommandItem
              value="clear peer filter"
              keywords={["reset", "filter", "esc"]}
              onSelect={() => run(onClearFilter)}
            >
              <Tag label="VIEW" />
              <span className="min-w-0 flex-1 truncate">clear peer filter</span>
              <CommandShortcut>Esc</CommandShortcut>
            </CommandItem>
          )}
          <CommandItem
            value="cycle peer sort"
            keywords={["order", "name", "transfer", "handshake", "epoch", "o"]}
            onSelect={() => run(onCycleSort)}
          >
            <Tag label="VIEW" />
            <span className="min-w-0 flex-1 truncate">cycle peer sort ({sortLabel})</span>
            <CommandShortcut>o</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="next peer"
            keywords={["down", "select", "j"]}
            disabled={peers.length === 0}
            onSelect={() => run(onNextPeer)}
          >
            <Tag label="VIEW" />
            <span className="min-w-0 flex-1 truncate">next peer</span>
            <CommandShortcut>j</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="previous peer"
            keywords={["up", "select", "k"]}
            disabled={peers.length === 0}
            onSelect={() => run(onPrevPeer)}
          >
            <Tag label="VIEW" />
            <span className="min-w-0 flex-1 truncate">previous peer</span>
            <CommandShortcut>k</CommandShortcut>
          </CommandItem>
          {interfaceCount > 1 && (
            <CommandItem
              value="switch next interface"
              keywords={["interface", "cycle", "tab"]}
              onSelect={() => run(onSwitchInterface)}
            >
              <Tag label="VIEW" />
              <span className="min-w-0 flex-1 truncate">next interface</span>
              <CommandShortcut>Tab</CommandShortcut>
            </CommandItem>
          )}
          <CommandItem
            value="toggle text density"
            keywords={["compact", "comfortable", "size", "density"]}
            onSelect={() => run(onToggleDensity)}
          >
            <Tag label="VIEW" />
            <span className="min-w-0 flex-1 truncate">
              density: switch to {comfortable ? "compact" : "comfortable"}
            </span>
          </CommandItem>
          <CommandItem
            value="doctor & error catalog"
            keywords={["doctor", "diagnostics", "error", "code", "val-e", "exit", "bundle", "d"]}
            onSelect={() => run(onOpenDiagnostics)}
          >
            <Tag label="VIEW" />
            <span className="min-w-0 flex-1 truncate">doctor, error codes &amp; DX…</span>
            <CommandShortcut>d</CommandShortcut>
          </CommandItem>
          {onOpenMetrics && (
            <CommandItem
              value="metrics & telemetry inspector"
              keywords={["metrics", "prometheus", "telemetry", "counters", "drops", "privacy"]}
              onSelect={() => run(onOpenMetrics)}
            >
              <Tag label="VIEW" />
              <span className="min-w-0 flex-1 truncate">metrics &amp; telemetry inspector…</span>
            </CommandItem>
          )}
          <CommandItem
            value="start page & onboarding guide"
            keywords={["start", "onboarding", "setup", "server", "client", "wizard"]}
            onSelect={() => run(onOpenOnboarding)}
          >
            <Tag label="VIEW" />
            <span className="min-w-0 flex-1 truncate">start page &amp; onboarding guide…</span>
          </CommandItem>
          <CommandItem
            value="keyboard shortcuts"
            keywords={["help", "keys", "keybindings", "?"]}
            onSelect={() => run(onOpenShortcuts)}
          >
            <Tag label="VIEW" />
            <span className="min-w-0 flex-1 truncate">keyboard shortcuts…</span>
            <CommandShortcut>?</CommandShortcut>
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
                <Tag label="JUMP" />
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
