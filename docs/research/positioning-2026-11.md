# Positioning research — 2026-11-13

**Status**: survey, not a decision. Feeds a future ADR.
**Question**: after the hub-and-spoke alpha validates the tunnel, where does
Vallum's post-quantum, agent-drivable, mesh-capable design earn a position?

Six candidates were surveyed: the agent economy (x402/A2A), VPN-for-AI-APIs,
VPN-inside-agent-harnesses, VPN-as-a-Service, mesh networking, and secure
browsing. Sources are inline; claims are attributed, inferences are marked.

## Market map

| Candidate | Evidence | Fit |
|---|---|---|
| **Agent economy / x402** | Coinbase + Cloudflare run the x402 Foundation; Google folded x402 into AP2 alongside A2A. ~1M transactions/week but only ~$1.1M in value — early, micropayment-scale ([DL News](https://www.dlnews.com/articles/web3/ai-crypto-payments-using-coinbase-protocol-x402-explode/), [Cloudflare](https://blog.cloudflare.com/x402/)). The **x402 Bazaar** is a machine-readable catalog of paid agent endpoints — semantic search plus an MCP server; literally "search and discover for paid services" ([x402 docs](https://docs.x402.org/extensions/bazaar), [CDP](https://docs.cdp.coinbase.com/x402/bazaar)). | High as narrative, low as revenue today |
| **VPN inside agent harnesses** | Every serious agent-sandbox platform reimplements deny-egress + allowlists + a private inbound path: DigitalOcean Harness Runtime's egress allowlist, Agent Substrate's `atunnel`→PEP CONNECT model, Ryph's token-gated egress proxy, Morph/Freestyle bridging sandbox→VPC **via WireGuard** ([ate.dev](https://ate.dev/docs/guides/network-egress/), [DigitalOcean](https://docs.digitalocean.com/products/managed-agents/agent-harness-runtime/concepts/egress/), [Morph](https://www.morphllm.com/agent-sandbox-private-network)). | **Strongest direct fit** — ADR-0023's member-netns is exactly "the sandbox gets the tunnel, the host stays clean" |
| **VPN-as-a-Service** | The niche exists and is thin: DataCork sells "WireGuard VPNaaS for AI agents" (sessions API returns a peer config); `ai_vpn_mcp` wraps WireGuard provisioning in an MCP server; TPN/PureWL do white-label resale ([DataCork](https://datacork.com/docs/quickstart/), [ai_vpn_mcp](https://github.com/Nolaan/ai_vpn_mcp), [TPN](https://taoprivatenetwork.com/solutions/vpn-resellers)). None do post-quantum. | Strong — validates "on-demand VPN" |
| **Mesh networking** | Tailscale ($6–18/user/mo, proprietary coord, WireGuard/Noise IK); NetBird ($5–12, open, self-hostable); ZeroTier; Netrinos (new indie). **None post-quantum** — every one ships a quantum-vulnerable handshake ([comparison](https://tailscale.com/compare/netbird), [Netrinos HN](https://news.ycombinator.com/item?id=46331364)). | Strong as a wedge; suicidal head-on |
| **VPN for AI APIs** | Real demand (supported-country lists, per-session IP checks) but the segment is consumer listicles — AethoVPN/ProxyTG/FastVPNZone — and ToS-gray: Anthropic/OpenAI gate on *physical* location, which a VPN cannot change ([Gizmodo](https://gizmodo.com/best-vpn/claude), [OpenAI docs](https://developers.openai.com/api/docs/supported-countries)). | A feature, not a story |
| **Secure browsing** | ~$3.6B US market, 42% adult adoption, Nord/Proton own trust and distribution; free-VPN use rebounding ([Security.org](https://www.security.org/resources/vpn-consumer-report-annual/), [IBISWorld](https://www.ibisworld.com/united-states/industry/virtual-private-network-vpn-providers/4020/)). | **Trap.** Commodity + trust game; a one-dev project cannot enter |

## The finding that reframes the question

**CNSA 2.0 makes PQ a deadline, not a nicety.** NSA's suite names "traditional
networking equipment (VPNs, routers)" explicitly: support-and-prefer
quantum-resistant algorithms by **2026**, exclusively by **2030**. NIST IR 8547
disallows quantum-vulnerable public-key algorithms after 2035; NSS acquisitions
must be CNSA-compliant from Jan 2027 ([Quantum Network](https://quantumnetwork.ch/knowledge-base/regulation-and-deadlines/cnsa-2-0-vpn-timeline-when-must-vpns-go-quantum-safe/), [Cisco](https://blogs.cisco.com/networking/safeguard-your-wan-from-quantum-threats-part-2-the-cnsa-2-0-blueprint), [Racktop](https://www.racktopsystems.com/data-defense-center/post-quantum-encryption-reaches-the-data-layer)).

The entire mesh-VPN category is built on handshakes that fail that math.
Mullvad (two-stage PSK upgrade) and Rosenpass (external KEM sidecar) prove
demand for PQ — but both bolt it beside WireGuard rather than making it
native. Vallum's tri-hybrid (X25519 + sntrup761 + ML-KEM-768) is in the
handshake itself, with an audited-NIST-only suite (0x0002) as a documented
option.

## The argued position

**"The post-quantum private network for machines — humans welcome."**

Not a better Tailscale (feature war vs. a staffed company), not a consumer VPN
(commodity), not payments (a rail we don't own). The wedge:

> *Wherever two machines need a private channel that stays private —
> agent-to-agent, sandbox-to-VPC, colleague-to-colleague — and wherever traffic
> recorded today must stay sealed past 2030.*

Each candidate rolls into it:

- **x402/agent economy**: Bazaar endpoints must be public HTTPS today — a
  *private* paid service can't be discovered. Vallum's enrolment ticket is
  already a service-admission credential; a paid mesh is `invite` + a
  settlement step. (Inference, not established demand.)
- **Harness VPN**: per-app member-netns (ADR-0023) + ticket enrolment + the
  ops dispatcher is the exact shape sandbox platforms are rebuilding from
  WireGuard parts.
- **Mesh/discovery**: ADR-0027's coord registry is the Bazaar-shaped layer;
  MagicDNS is the naming (phases 2, 5).
- **On-demand VPN**: `invite`/`join` is the on-demand credential proven by
  accept-install; DataCork charges for exactly this shape.

## Honest caveats

1. x402 volume is a story, not a market — position toward it, never depend.
2. Tailscale's coordination UX is the moat; PQ alone does not win. The wedge
   needs machine-native UX — which ADR-0013's machine interface and ADR-0027's
   external agent already architect for.
3. Agent-economy buyers are infrastructure teams: the API/embeddability story
   (`vallum` is already a library crate) matters more than console polish.
4. DataCork and ai_vpn_mcp are tiny — they validate that *someone* wants this,
   not how many.

## Mapping to the build plan

- Alpha (hub-and-spoke) validates the tunnel — ship it; positioning shapes
  what gets built next, not what ships now.
- ADR-0027 phases sequence the mesh work; phase 1 (static peer set over UAPI)
  is deliberately small and the colleague cohort is a natural test mesh.
- The missing TUI/GUI surface for mesh/join flows is real: today `invite` is
  reachable through the ops palette, but a mesh agent writing peer sets will
  need a visible topology surface eventually (ADR-0024 console direction).

## Sources

Inline above. Search breadth: 11 queries across the six candidates, 40+
results, ~15 primary sources read in full. Confidence: medium — market-size
figures vary wildly by report and are cited as ranges; protocol/adoption
claims are from vendor or standards primary sources.
