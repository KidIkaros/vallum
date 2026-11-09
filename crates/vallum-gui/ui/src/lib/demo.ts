// Demo mode: a synthesised snapshot stream so the dashboard can be designed
// and previewed in a plain browser, where the Tauri bridge does not exist.
//
// Activation is deliberately narrow: only outside Tauri (`window.__TAURI_INTERNALS__`
// is absent) and only with `?demo=1` in the URL. Inside the real console this
// file is never entered, and the header carries a "demo data" badge whenever
// it is — nothing rendered from here can be mistaken for a live daemon.

import type { SnapshotPayload } from "@/types"

const TAURI_INTERNALS = "__TAURI_INTERNALS__" in window

export function demoRequested(): boolean {
  if (TAURI_INTERNALS) return false
  return new URLSearchParams(window.location.search).has("demo")
}

interface DemoPeer {
  name: string
  fingerprint: string
  endpoint: string
  allowed_ips: string[]
  rx: number
  tx: number
  handshakeAgeSec: number
  epoch: number
  rotating: boolean
  keepalive: number | null
  psk: boolean
}

const PEERS: DemoPeer[] = [
  {
    name: "vps-host",
    fingerprint: "9f2ce41ba88d01c7",
    endpoint: "203.0.113.10:51820",
    allowed_ips: ["10.7.0.0/24"],
    rx: 4_812_345_123,
    tx: 1_204_552_801,
    handshakeAgeSec: 14,
    epoch: 7,
    rotating: false,
    keepalive: null,
    psk: true,
  },
  {
    name: "phone",
    fingerprint: "1c77be04d3a95f22",
    endpoint: "",
    allowed_ips: ["10.7.0.42/32"],
    rx: 214_748_36,
    tx: 88_000_111,
    handshakeAgeSec: 4_820,
    epoch: 2,
    rotating: true,
    keepalive: 25,
    psk: false,
  },
]

interface DemoState {
  datagramsSent: number
  packetsDelivered: number
  established: number
  refusals: number
}

const state: DemoState = {
  datagramsSent: 51_233_904,
  packetsDelivered: 49_887_112,
  established: 128,
  refusals: 3,
}

/** Keepalive-level base traffic with occasional bursts, in bytes per tick. */
function trafficBurst(): number {
  const base = 900 + Math.random() * 400
  const burst = Math.random() < 0.12 ? Math.random() * 90_000 : 0
  return base + burst
}

export function startDemo(onPayload: (payload: SnapshotPayload) => void): () => void {
  const now = () => Math.floor(Date.now() / 1000)
  const tick = () => {
    const up = PEERS[0]
    const phone = PEERS[1]
    const sent = trafficBurst()
    const delivered = trafficBurst()
    state.datagramsSent += Math.ceil(sent / 1200) + 1
    state.packetsDelivered += Math.ceil(delivered / 1400)
    up.tx += sent
    up.rx += delivered
    phone.rx += trafficBurst() * 0.1
    up.handshakeAgeSec = 12 + Math.floor(Math.random() * 3)

    const payload: SnapshotPayload = {
      ok: true,
      error: null,
      data: {
        interface: "vallum0",
        addresses: ["10.7.0.1/24", "fd00:7::1/64"],
        listen_port: 51820,
        suite: "0x0003",
        fwmark: 4660,
        fingerprint: "4b1d9e02c8a7f633",
        public_line: "vallum1:0003:9a4f…(demo, truncated)",
        offload: true,
        batching: true,
        counters: {
          datagrams_sent: state.datagramsSent,
          datagrams_failed: 12,
          packets_delivered: state.packetsDelivered,
          packets_failed: 0,
          established: state.established,
          refusals: state.refusals,
          reassembled: 8_442,
          fragments_dropped: 1,
        },
        peers: PEERS.map((peer) => ({
          name: peer.name,
          fingerprint: peer.fingerprint,
          public_line: `vallum1:0003:${peer.fingerprint}…`,
          endpoint: peer.endpoint,
          allowed_ips: peer.allowed_ips,
          keepalive: peer.keepalive,
          last_handshake_sec: now() - peer.handshakeAgeSec,
          last_handshake_nsec: 0,
          tx_bytes: Math.floor(peer.tx),
          rx_bytes: Math.floor(peer.rx),
          epoch: peer.epoch,
          rotating: peer.rotating,
          valid_until: null,
          has_preshared_key: peer.psk,
        })),
      },
    }
    onPayload(payload)
  }
  tick()
  const handle = window.setInterval(tick, 600)
  return () => window.clearInterval(handle)
}
