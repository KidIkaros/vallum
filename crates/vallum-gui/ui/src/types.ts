// The shapes the Rust side serialises. Mirrors `crates/vallum-gui/src/snapshot.rs`
// and the command signatures in `src/main.rs`; a field added there lands here.

export interface InterfaceEntry {
  name: string
  path: string
}

export interface Counters {
  datagrams_sent: number
  datagrams_failed: number
  packets_delivered: number
  packets_failed: number
  established: number
  refusals: number
  reassembled: number
  fragments_dropped: number
}

export interface Peer {
  name: string
  fingerprint: string
  public_line: string
  endpoint: string
  allowed_ips: string[]
  keepalive: number | null
  last_handshake_sec: number
  last_handshake_nsec: number
  tx_bytes: number
  rx_bytes: number
  epoch: number
  rotating: boolean
  valid_until: number | null
  has_preshared_key: boolean
}

export interface Snapshot {
  interface: string
  addresses: string[]
  listen_port: number | null
  suite: string
  fwmark: number | null
  fingerprint: string
  public_line: string
  offload: boolean
  batching: boolean
  counters: Counters
  peers: Peer[]
}

export interface SnapshotPayload {
  ok: boolean
  error: string | null
  data: Snapshot | null
}

export interface Done {
  /** What the action did, in the daemon's own words. */
  detail: string
}
