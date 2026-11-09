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

export function nameProblem(text: string): string | null {
  const value = text.trim()
  if (value === "") return "a name, so the peer is recognisable later"
  if (value.length > 64) return "64 characters or fewer"
  return null
}
