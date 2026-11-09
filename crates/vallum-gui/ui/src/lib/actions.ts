import { command } from "@/lib/bridge"

// The console's write surface, transport-blind: every function goes through
// the bridge, which is IPC inside Tauri and localhost HTTP under `--serve`.
// The payload shapes match PeerFields and InviteFields in actions.rs, which
// are `#[serde(default)]` — a blank field means "not set".

export interface Done {
  message: string
  /** A command to run when the console could not finish the work itself. */
  command?: string
}

export interface PeerFields {
  public_line: string
  name: string
  endpoint: string
  allowed_ips: string
  keepalive: string
  preshared_key: string
}

export interface InviteFields {
  name: string
  ttl_minutes: string
  pinned: string
}

export const emptyPeer = (): PeerFields => ({
  public_line: "",
  name: "",
  endpoint: "",
  allowed_ips: "",
  keepalive: "",
  preshared_key: "",
})

export const addPeer = (fields: PeerFields) => command<Done>("add_peer", { fields })
export const editPeer = (fields: PeerFields) => command<Done>("edit_peer", { fields })
export const removePeer = (publicLine: string) => command<Done>("remove_peer", { publicLine })
export const rotatePeer = (name: string, newLine: string) =>
  command<Done>("rotate_peer", { name, newLine })
export const finalizePeer = (name: string) => command<Done>("finalize_peer", { name })
export const invitePeer = (fields: InviteFields) => command<Done>("invite_peer", { fields })

/** Change the device's listen port and firewall mark through the daemon. */
export const applyDevice = (listenPort: string, fwmark: string) =>
  command<Done>("apply_device", { listenPort, fwmark })
