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
  /** Optional remote server SSH target; mints the invite on that server. */
  ssh_target: string
}

/** What an export answers: the bundle as JSON text plus the file name the
 *  browser saves it under. The key is minted in memory server-side and never
 *  written to disk — the downloaded file is its only copy. */
export interface BundleOut {
  filename: string
  json: string
  message: string
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

/** Fields for the client onboarding flow: paste a join ticket, or SSH enrol. */
export interface JoinFields {
  mode: string
  ticket: string
  ssh_target: string
  name: string
  /** Desk account token from a vallum://join deep link (32 hex, optional). */
  account?: string
}

export const joinNetwork = (fields: JoinFields) =>
  command<Done>("join_network", { fields })

/** Fields for the "Host a Server" wizard. */
export interface ServerSetupFields {
  address: string
  listen: string
  public_endpoint: string
}

export const setupServer = (fields: ServerSetupFields) =>
  command<Done>("setup_server", { fields })

/** Close the temporary UDP 51821 enrolment responder (locally or over SSH). */
export const closeEnrollment = (sshTarget: string) =>
  command<Done>("close_enrollment", { sshTarget })

/** The button a suggestion renders. Unit variants arrive as plain strings;
 *  `FinalizePeer` carries the peer name, matching the Rust enum's serde shape. */
export type SuggestionAction =
  | "JoinNetwork"
  | "SetupServer"
  | "StartService"
  | "EnableService"
  | "RestartService"
  | "DisableUnits"
  | "InvitePeer"
  | "CloseEnrolment"
  | "PingPeer"
  | "SyncHost"
  | "OpenLogs"
  | "HealthCheck"
  | "EditConfig"
  | "CopyPublicLine"
  | { FinalizePeer: string }

/** What the console believes the operator should do next — the machine's
 *  answer to "I opened the app, now what", derived from observed state only. */
export interface Suggestion {
  id: string
  tone: "Act" | "Warn" | "Info"
  title: string
  detail: string
  action: SuggestionAction | null
}

export const suggestions = () => command<{ suggestions: Suggestion[] }>("suggestions", {})

/** Update this host's installed binaries/units from the tracked source tree. */
export const syncHost = () => command<Done>("sync", {})

/** Is the installed build behind the source tree? */
export const syncCheck = () => command<Done>("sync_check", {})

/** Boot persistence for an interface's units; `iface` defaults to the
 *  selected socket's interface when omitted. */
export const enableUnits = (iface?: string) => command<Done>("enable_units", { iface })
export const disableUnits = (iface?: string) => command<Done>("disable_units", { iface })

export const exportBundle = (fingerprint: string, endpoint: string) =>
  command<BundleOut>("export_bundle", { fingerprint, endpoint })

/** One frame of an animated QR: its position in the set, the set's integrity
 *  prefix, and the module grid to draw — dark flags in row-major order, no
 *  quiet zone (the canvas adds the plate). */
export interface QrFrame {
  index: number
  total: number
  hash: string
  size: number
  modules: number[]
}

/** A frame of the animation for text the console already holds: an exported
 *  bundle's JSON, or an invite's join command. */
export const qrFrame = (text: string, index: number) =>
  command<QrFrame>("qr_frame", { text, index })

export const importBundle = (bundlePath: string, outDir: string) =>
  command<Done>("import_bundle", { bundlePath, outDir })

/** A minted key: text plus the file name the browser saves it under. */
export interface KeyOut {
  filename: string
  text: string
  message: string
}

export const generateKey = () => command<KeyOut>("generate_key", {})

export const readConfig = () => command<string>("read_config", {})

export const writeConfig = (text: string) => command<Done>("write_config", { text })

export interface InterfaceFields {
  listen: string
  carrier: string
  tcp_upgrade?: string
  ss_psk?: string
  tls_sni?: string
  mtu: string
  fwmark: string
  addresses: string
  dns: string
  table: string
  policy?: string
  content_blockers?: string
  via?: string
}

export interface MtuTuneOut {
  host: string
  ceiling_outer_mtu: number
  recommended_inner_mtu: number
  recommended_outer_mtu: number
  ipv4_tcp_mss: number
  ipv6_tcp_mss: number
  profile: string
  rationale: string
}

export const readInterfaceFields = () => command<InterfaceFields>("read_interface_fields", {})
export const applyInterface = (fields: InterfaceFields) =>
  command<Done>("apply_interface", { fields })
export const saveRuntime = () => command<Done>("save_runtime", {})
export const tuneMtu = () => command<MtuTuneOut>("tune_mtu", {})

/** Change the device's listen port and firewall mark through the daemon. */
export const applyDevice = (listenPort: string, fwmark: string) =>
  command<Done>("apply_device", { listenPort, fwmark })
