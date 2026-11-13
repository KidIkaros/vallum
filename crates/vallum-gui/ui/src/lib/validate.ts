// Field-level validation, shared by the peer form and the interface form.
//
// The daemon is still the authority — this is not a second parser, it is the
// same rules stated early enough to point at the field. Every function returns
// `null` for "no complaint" and a sentence for "here is what is wrong", because
// a form that only greys out its submit button makes the operator guess.

/** `vallum1:<suite>:<kem>:<signing|->` — four colon-separated fields, hex body. */
export function publicLineProblem(line: string): string | null {
  const text = line.replace(/\s+/g, "")
  if (text === "") return "paste the other end's public line"
  const fields = text.split(":")
  if (fields.length !== 4) {
    return `expected vallum1:<suite>:<kem>:<signing|-> — found ${fields.length} field${fields.length === 1 ? "" : "s"}`
  }
  if (fields[0] !== "vallum1") return `expected it to start with vallum1, found ${fields[0]}`
  if (!/^[0-9a-fA-F]{4}$/.test(fields[1])) return "the suite field should be four hex digits, e.g. 0003"
  if (!/^[0-9a-fA-F]+$/.test(fields[2]) || fields[2].length % 2 !== 0) {
    return "the KEM field should be an even-length hex string"
  }
  if (fields[3] !== "-" && !/^[0-9a-fA-F]+$/.test(fields[3])) {
    return "the signing field should be hex or `-`"
  }
  return null
}

/** Comma or space separated CIDRs, as the daemon parses them. */
export function allowedIpsProblem(text: string): string | null {
  const items = text
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean)
  if (items.length === 0) return "at least one CIDR, e.g. 10.7.0.2/32"
  for (const item of items) {
    const [address, prefix, ...rest] = item.split("/")
    if (rest.length > 0 || prefix === undefined) return `${item} is not a CIDR`
    const bits = address.includes(":") ? 128 : 32
    if (!/^\d+$/.test(prefix) || Number(prefix) > bits) {
      return `${item}: the prefix should be 0–${bits}`
    }
    if (!/^[0-9a-fA-F:.]+$/.test(address)) return `${item} is not an address`
  }
  return null
}

export function keepaliveProblem(text: string): string | null {
  if (text.trim() === "") return null
  if (!/^\d+$/.test(text.trim())) return "whole seconds, e.g. 25"
  const seconds = Number(text)
  if (seconds < 1 || seconds > 65535) return "between 1 and 65535 seconds"
  return null
}

export function endpointProblem(text: string): string | null {
  const value = text.trim()
  if (value === "") return null // blank means the peer roams
  const lastColon = value.lastIndexOf(":")
  if (lastColon <= 0) return "host:port, e.g. 203.0.113.7:51820"
  const port = Number(value.slice(lastColon + 1))
  if (!Number.isInteger(port) || port < 1 || port > 65535) return "the port should be 1–65535"
  return null
}

export function presharedKeyProblem(text: string): string | null {
  const value = text.trim()
  if (value === "") return null
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length !== 64) {
    return "64 hex characters (32 bytes)"
  }
  return null
}

export function nameProblem(text: string, required = true): string | null {
  const value = text.trim()
  if (value === "") return required ? "peer name is required" : null
  if (value.length > 15) return "15 characters max (Linux interface name limit)"
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) {
    return "use letters, digits, '.', '_', or '-' (start with letter/digit)"
  }
  return null
}

export function nameHint(text: string): string | null {
  const value = text.trim()
  if (value.length > 8 && value.length <= 15) {
    return "client interface vallum-<name> uses the first 8 chars; keep the first 8 unique"
  }
  return null
}

export function ttlProblem(text: string): string | null {
  const value = text.trim()
  if (value === "") return null
  if (!/^\d+$/.test(value)) return "whole minutes required"
  const minutes = Number(value)
  if (minutes < 1 || minutes > 10080) {
    return "TTL must be between 1 and 10080 minutes (7 days)"
  }
  return null
}

export function listenPortProblem(text: string): string | null {
  const value = text.trim()
  if (value === "") return null
  if (!/^\d+$/.test(value)) return "port must be 0–65535"
  const port = Number(value)
  if (port < 0 || port > 65535) return "port must be 0–65535"
  return null
}

export function fwmarkProblem(text: string): string | null {
  const value = text.trim()
  if (value === "" || value.toLowerCase() === "off" || value === "0") return null
  if (!/^(0x[0-9a-fA-F]{1,8}|\d+)$/.test(value)) {
    return "use 'off', decimal, or hex (e.g. 0xca6c)"
  }
  const numeric = value.toLowerCase().startsWith("0x")
    ? Number.parseInt(value.slice(2), 16)
    : Number(value)
  if (!Number.isFinite(numeric) || numeric < 0 || numeric > 0xffffffff) {
    return "fwmark must fit in 32 bits (0–0xffffffff)"
  }
  return null
}

/** Extract a clean, human-readable error message without doubled `Error:` prefixes. */
export function formatError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim().replace(/^Error:\s*/i, "")
  }
  const text = String(error ?? "").trim().replace(/^Error:\s*/i, "")
  return text || "request failed"
}

/** Pair wire suite codes with their human-readable protocol names. */
export function suiteLabel(suite: string | null | undefined): string {
  const value = (suite ?? "").trim()
  if (value === "0x0003") return "0x0003 (tri-hybrid)"
  if (value === "0x0002") return "0x0002 (ml-kem-768)"
  if (value === "0x0001") return "0x0001 (sntrup761)"
  return value
}
