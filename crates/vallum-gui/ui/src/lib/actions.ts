import { invoke } from "@tauri-apps/api/core"

// The console's write surface. Every function is one Tauri command from
// crates/vallum-gui/src/main.rs; the payload shapes match PeerFields and
// InviteFields in actions.rs, which are `#[serde(default)]` — a blank field
// means "not set", exactly as the daemon's parsers read it.

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

export const addPeer = (fields: PeerFields) => invoke<Done>("add_peer", { fields })
export const editPeer = (fields: PeerFields) => invoke<Done>("edit_peer", { fields })
export const removePeer = (publicLine: string) => invoke<Done>("remove_peer", { publicLine })
export const rotatePeer = (name: string, newLine: string) =>
  invoke<Done>("rotate_peer", { name, newLine })
export const finalizePeer = (name: string) => invoke<Done>("finalize_peer", { name })
export const invitePeer = (fields: InviteFields) => invoke<Done>("invite_peer", { fields })

/** Change the device's listen port and firewall mark through the daemon. */
export const applyDevice = (listenPort: string, fwmark: string) =>
  invoke<Done>("apply_device", { listenPort, fwmark })
