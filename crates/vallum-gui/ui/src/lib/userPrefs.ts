import { useCallback, useEffect, useState } from "react"

const PREFS_STORAGE_KEY = "vallum.user.prefs.v1"
const PREFS_EVENT = "vallum-user-prefs"

export type NodeRole = "client" | "server" | "mesh"
export type InviteTtlPreset = "15" | "60" | "1440" | "10080"
export type KeepalivePreset = "25" | "60" | ""

export interface UserPrefs {
  alias: string
  role: NodeRole
  defaultInviteTtl: InviteTtlPreset
  defaultKeepalive: KeepalivePreset
  autoCopyInvites: boolean
}

export const DEFAULT_USER_PREFS: UserPrefs = {
  alias: "",
  role: "client",
  defaultInviteTtl: "60",
  defaultKeepalive: "25",
  autoCopyInvites: true,
}

const VALID_ROLES: readonly NodeRole[] = ["client", "server", "mesh"]
const VALID_TTLS: readonly InviteTtlPreset[] = ["15", "60", "1440", "10080"]
const VALID_KEEPALIVES: readonly KeepalivePreset[] = ["25", "60", ""]

export const ROLE_META: Record<NodeRole, { label: string; badge: string; hint: string }> = {
  client: {
    label: "Client · Endpoint",
    badge: "CLIENT",
    hint: "Dials a gateway or server; uses persistent keepalive behind NAT.",
  },
  server: {
    label: "Server · Gateway",
    badge: "GATEWAY",
    hint: "Accepts inbound handshakes and mints invite tickets for peers.",
  },
  mesh: {
    label: "Mesh Peer",
    badge: "MESH",
    hint: "Direct peer-to-peer routing with symmetric keepalive.",
  },
}

export function loadUserPrefs(): UserPrefs {
  try {
    const raw = window.localStorage.getItem(PREFS_STORAGE_KEY)
    if (!raw) return DEFAULT_USER_PREFS
    const parsed = JSON.parse(raw) as Partial<UserPrefs> | null
    if (!parsed || typeof parsed !== "object") return DEFAULT_USER_PREFS
    return {
      alias: typeof parsed.alias === "string" ? parsed.alias.slice(0, 32) : DEFAULT_USER_PREFS.alias,
      role: VALID_ROLES.includes(parsed.role as NodeRole)
        ? (parsed.role as NodeRole)
        : DEFAULT_USER_PREFS.role,
      defaultInviteTtl: VALID_TTLS.includes(parsed.defaultInviteTtl as InviteTtlPreset)
        ? (parsed.defaultInviteTtl as InviteTtlPreset)
        : DEFAULT_USER_PREFS.defaultInviteTtl,
      defaultKeepalive: VALID_KEEPALIVES.includes(parsed.defaultKeepalive as KeepalivePreset)
        ? (parsed.defaultKeepalive as KeepalivePreset)
        : DEFAULT_USER_PREFS.defaultKeepalive,
      autoCopyInvites:
        typeof parsed.autoCopyInvites === "boolean"
          ? parsed.autoCopyInvites
          : DEFAULT_USER_PREFS.autoCopyInvites,
    }
  } catch {
    return DEFAULT_USER_PREFS
  }
}

export function saveUserPrefs(next: UserPrefs): void {
  try {
    window.localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(next))
    window.dispatchEvent(new CustomEvent(PREFS_EVENT))
  } catch {
    /* ignore disabled storage */
  }
}

export function useUserPrefs(): [UserPrefs, (patch: Partial<UserPrefs>) => void, () => void] {
  const [prefs, setPrefs] = useState<UserPrefs>(() => loadUserPrefs())

  useEffect(() => {
    const sync = () => setPrefs(loadUserPrefs())
    window.addEventListener(PREFS_EVENT, sync)
    window.addEventListener("storage", sync)
    return () => {
      window.removeEventListener(PREFS_EVENT, sync)
      window.removeEventListener("storage", sync)
    }
  }, [])

  const update = useCallback((patch: Partial<UserPrefs>) => {
    const next: UserPrefs = {
      ...loadUserPrefs(),
      ...patch,
    }
    if (typeof next.alias === "string") next.alias = next.alias.slice(0, 32)
    saveUserPrefs(next)
    setPrefs(next)
  }, [])

  const reset = useCallback(() => {
    saveUserPrefs(DEFAULT_USER_PREFS)
    setPrefs(DEFAULT_USER_PREFS)
  }, [])

  return [prefs, update, reset]
}

/** Suggest the lowest free /32 IPv4 peer address inside the interface's /24 subnet. */
export function suggestNextPeerIp(
  interfaceAddresses: string[],
  peerAllowedIps: string[][],
): string | null {
  const ipv4Match = interfaceAddresses
    .map((addr) => addr.trim().match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})(?:\/\d+)?$/))
    .find((m) => m !== null && m !== undefined)

  const prefix = ipv4Match ? `${ipv4Match[1]}.` : "10.7.0."
  const used = new Set<number>()

  for (const raw of [...interfaceAddresses, ...peerAllowedIps.flat()]) {
    const clean = raw.trim().split("/")[0]
    if (!clean.startsWith(prefix)) continue
    const last = Number.parseInt(clean.slice(prefix.length), 10)
    if (Number.isInteger(last) && last >= 1 && last <= 254) {
      used.add(last)
    }
  }

  for (let host = 2; host <= 254; host++) {
    if (!used.has(host)) return `${prefix}${host}/32`
  }
  return null
}
