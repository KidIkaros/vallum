# Should Vallum ship a Pi-hole-style DNS sinkhole inside the tunnel?

**Status:** research note, not a recommendation. Every factual claim below is
carried by a primary source (Pi-hole's own documentation and repository, the
IETF RFCs, and the operator documentation of a mature privacy VPN). Where a
claim is about Vallum itself, the source is the file and line in this
repository.

The question this note answers: *if Vallum put a Pi-hole-style DNS sinkhole on
the VPN **server**, inside the tunnel, would that help Vallum's users?*

One correction to the framing, before the sources: **RFC 8767 is not
DNS-over-QUIC.** RFC 8767 is *"Serving Stale Data to Improve DNS
Resiliency"* (Lawrence et al., March 2020,
<https://www.rfc-editor.org/rfc/rfc8767.txt>). The DoQ specification is **RFC
9250**, *"DNS over Dedicated QUIC Connections"* (Huitema et al., May 2022,
<https://www.rfc-editor.org/rfc/rfc9250.txt>). This note cites RFC 9250 for
DoQ, and RFC 8767 only for what it actually says.

---

## 1. What Pi-hole actually is, architecturally

**It is a DNS sinkhole, and only that.** Pi-hole's own documentation defines
it in one line: "The Pi-hole® is a **DNS sinkhole** that protects your devices
from unwanted content, without installing any client-side software" — "Network-wide
ad blocking via your own Linux hardware" (<https://docs.pi-hole.net/>; the same
sentence and the same list of properties are in the project README,
<https://github.com/pi-hole/pi-hole>).

**The resolver is FTL, a forked dnsmasq.** Since Pi-hole v4 the resolver is not
a separate `dnsmasq` install but is *inside* FTL: "FTL DNS comes with a
lightweight but powerful inbuilt DNS/ DHCP/ TFTP/... server eliminating the need
to install `dnsmasq` separately (we used to do this before Pi-hole v4.0) ...
we are coupling even closer to it by incorporating it into FTL", and "As we
maintain our own fork of `dnsmasq` we have been able to apply some minimal
changes to the source code" (<https://docs.pi-hole.net/ftldns/dns-resolver/>).
The project's own framing is "Think of FTL DNS as `dnsmasq` with Pi-hole's
special sauce" (same page). FTL additionally provides DHCP, an HTTP API and
web interface, and NTP (<https://docs.pi-hole.net/ftldns/>;
<https://docs.pi-hole.net/main/prerequisites/>).

**Blocklists live in SQLite, not in code.** Two databases: the *domain
database* `gravity.db` holds the allow/deny lists and the subscribed
*adlists*; the *query database* `pihole-FTL.db` holds the long-term query
history (<https://docs.pi-hole.net/database/domain-database/>;
<https://docs.pi-hole.net/database/query-database/>;
<https://docs.pi-hole.net/database/>). Blocking priority is: exact allowlist,
regex allowlist, exact denylist, subscribed allowlists, subscribed denylist,
regex denylist (<https://docs.pi-hole.net/database/domain-database/>).

**Blocking is by answer, not by traffic.** A blocked query is answered with
the unspecified address (`0.0.0.0` / `::`) in the default "NULL" mode;
alternatives are `IP-NODATA-AAAA`, `IP`, `NXDOMAIN`, `NODATA`
(<https://docs.pi-hole.net/ftldns/blockingmode/>). The documented advantage of
NULL mode is precisely that no connection is attempted at all: "Clients should
not even try to establish a connection for the requested website/address ...
requests are never performed" (same page).

**The query log is on by default.** `dns.queryLogging` defaults to `true` ("Log
DNS queries and replies to pihole.log", <https://docs.pi-hole.net/ftldns/configfile/>),
and the long-term query database is flushed to disk about once per minute
(`database.DBinterval`, default 365 days of retention in
`database.maxDBdays`, <https://docs.pi-hole.net/database/query-database/>).
Pi-hole's own answer to "who sees my queries" is a *privacy level* dial, not an
absence of logging: level 0 shows everything; level 1 hides domains; level 2
hides domains and clients; level 3 disables the query log and long-term
database logging entirely (<https://docs.pi-hole.net/ftldns/privacylevels/>).

### What Pi-hole is **not**

- **Not a VPN.** Pi-hole ships no tunnel; it is a LAN appliance that clients
  point their resolvers at, normally via DHCP from the router, or via a router
  that hands out the Pi-hole's IP as the DNS server
  (<https://docs.pi-hole.net/main/post-install/>). Pi-hole's own documentation
  treats a VPN as a separate, optional way to *reach* a Pi-hole — its
  WireGuard guide sets up "a server running Pi-hole and WireGuard" and lists
  "use the full filtering capabilities of your Pi-hole" among the things the
  VPN enables (<https://docs.pi-hole.net/guides/vpn/wireguard/>). The two
  products are complementary, never merged.
- **Not a firewall, and it does not block non-DNS traffic.** Pi-hole's own
  router guide is explicit that stopping clients from bypassing it takes
  *firewall rules somewhere else*: "Optionally, there is also the possibility
  to block DNS traffic to other, non-Pi-hole DNS servers via firewall rules.
  This can be used to prevent clients like Chromecasts of using their hardcoded
  DNS servers", and the guide's own caveat: "this tutorial does not explain on
  how to block DoH or DoT" (<https://docs.pi-hole.net/routers/opnsense/>).
  The Pi-hole host itself has to be firewalled separately, with the project's
  own examples of `iptables`/`ufw` rules for ports 53, 67, 80, 443 and 123
  (<https://docs.pi-hole.net/main/prerequisites/>). A DNS sinkhole sees DNS;
  it cannot see or stop traffic that does not consult it.
- **It is not a complete ad blocker.** DNS blocking removes the *name*, not the
  content: an operator of a comparable DNS-blocking service states the limit
  plainly — "DNS content blocking can not block all ads and trackers. For
  example it can not block YouTube ads"
  (<https://mullvad.net/en/help/dns-over-https-and-dns-over-tls>).

---

## 2. How Pi-hole is installed and updated, and where the blocklist trust anchor is

**Install.** The canonical one-liner is
`curl -sSL https://install.pi-hole.net | bash`; the project explicitly
acknowledges the piping-to-bash objection and offers three reviewable
alternatives: clone the repository and run `automated install/basic-install.sh`,
download the script with `wget` and run it, or use the official Docker images
(<https://docs.pi-hole.net/main/basic-install/>;
<https://github.com/pi-hole/pi-hole>).

**Three components, three repositories, updated separately.** Core, the web
interface and FTL each have their own repository and release notes, and
updating is `pihole -up`, which "Check[s] Pi-hole Core, Web Interface and FTL
repositories to determine what upgrades (if any) are required"
(<https://docs.pi-hole.net/main/pihole-command/>;
<https://docs.pi-hole.net/main/update/>). `update.sh` works by `git fetch` on
the origin remote and comparing tags/commits, and updates the FTL binary
separately (<https://github.com/pi-hole/pi-hole/blob/master/advanced/Scripts/update.sh>).
Release cadence observed on the public repositories: core `v6.6` published
2026-11-11, `v6.5` 2026-10-17, `v6.4.3` 2026-07-06; FTL `v6.9` published
2026-11-11, `v6.8` 2026-10-17, `v6.7.1` 2026-09-19
(<https://github.com/pi-hole/pi-hole/releases>,
<https://github.com/pi-hole/FTL/releases>). Note that the core and FTL
repositories ship *independently* on the same day — a Pi-hole install is
normally three moving parts, not one.

**Blocklist update cadence.** The shipped cron file updates the ad sources
"once a week on Sunday at a random time in the early morning" and separately
runs a version check every 24 hours
(<https://github.com/pi-hole/pi-hole/blob/master/advanced/Templates/pihole.cron>).
The documented process: read the URLs and domains from the `adlists` table in
`gravity.db`, download each URL (`curl` checks the server's `Last-Modified`
header to ensure it is getting a newer version), parse to a domains-only
format, merge, de-duplicate, sort into the `gravity` table, then reload the
DNS server (<https://docs.pi-hole.net/main/pihole-command/>). The `gravity`
and `antigravity` tables are "flushed and completely rebuilt" on every run
(<https://docs.pi-hole.net/database/domain-database/>).

**The trust anchor for the blocklists is: TLS to whoever you subscribed to,
plus a locally-computed SHA-1 that detects change but authenticates nothing.**
In `gravity.sh` the download uses `curl` with ETag/`If-Modified-Since`
conditional requests, and the only integrity check is a `sha1sum` file written
*by Pi-hole itself* from the bytes it just downloaded: "Verify checksum when an
older checksum exists ... if ! sha1sum --check --status --strict "${target}.sha1"
... The list changed upstream, we need to update the checksum". There is no
signature verification in the update path
(<https://github.com/pi-hole/pi-hole/blob/master/gravity.sh>). So the trust
chain for a blocklist is: the URL in the `adlist` table, the TLS session to
the list publisher, and the operator's own judgement about which URLs they
subscribed to. The `adlist` table stores only an `address` (a URL), an
`enabled` flag, and counters — there is no signature or digest column in the
schema (<https://github.com/pi-hole/pi-hole/blob/master/advanced/Templates/gravity.db.sql>).

Compare with a curated, VPN-operator-run equivalent: Mullvad publishes the
exact upstream lists it imports, with URLs, in a public repository, and states
the vetting rule: "We prefer to not block individual custom URLs or add block
lists without them being fully validated and verified first ... it is most
likely down to us not having a way of verifying that the block list is
trustworthy" (<https://github.com/mullvad/dns-blocklists>). That repository is
also the clearest statement of the *operational* cost of running blocklists
inside a VPN: "We aim to update these lists every Monday through Thursday ...
After updating the lists, it will take about an hour for all our servers to
pick up the updated lists" (same page).

---

## 3. A DNS sinkhole on the VPN **server**: the trust model

**If the resolver runs on the VPN server, the VPN operator's host sees every
query name.** This is not a Pi-hole property; it is a property of recursive
resolvers. "Because there is typically no caching in the stub resolver, the
recursive resolver, unlike the authoritative servers, sees all the DNS
traffic" (RFC 9076 §1, <https://www.rfc-editor.org/rfc/rfc9076.txt>; the same
statement is in RFC 7626 §1, which RFC 9076 obsoletes). And: "**Recursive
Resolvers see all the traffic** since there is typically no caching before
them. To summarize: your recursive resolver knows a lot about you" (RFC 9076
§6.1). The risk-analysis framing is explicit: DNS servers are "enablers" who
"may all pose privacy threats ... because they are able to observe, collect,
process, and transfer privacy-relevant data", and "enablers become observers
when they start collecting data" (RFC 7626 §2.5).

**Encryption does not change that; it moves the trust.** RFC 8932 states the
position for resolver operators directly: "Whilst protocols that encrypt DNS
messages on the wire provide protection against certain attacks, **the
resolver operator still has (in principle) full visibility of the query data
and transport identifiers for each user. Therefore, a trust relationship
(whether explicit or implicit) is assumed to exist between each user and the
operator of the resolver(s)**" (<https://www.rfc-editor.org/rfc/rfc8932.txt>).
RFC 9076 §6.1.4.1 repeats it from the user's side: "Use of encrypted transports
does not reduce the data available in the recursive resolver and ironically can
actually expose more information about users to operators." A server-side
sinkhole is the *worst case* for that tradeoff, because the operator gains the
ability to both see and modify the answers.

**The standard privacy-VPN position is: the operator runs the resolver, and
promises not to log it.** Mullvad's published policy: "We log nothing
whatsoever that can be connected to a numbered account's activity: no logging
of traffic, **no logging of DNS requests**, no logging of connections ...
no logging of IP addresses" (<https://mullvad.net/en/help/no-logging-data-policy>).
The same operator ships DNS content blockers *inside the tunnel* — the app
lists "DNS content blockers" among the in-tunnel settings, "This feature uses
blocklists from various providers", and the blocklists repository explicitly
covers "VPN server (also known as VPN relay) based DNS blocking"
(<https://mullvad.net/en/help/using-mullvad-vpn-on-android>;
<https://github.com/mullvad/dns-blocklists>). So the precedent exists: a
privacy VPN that both resolves on the relay and blocks, and that separates the
two promises — *we do the blocking* and *we do not log what you asked for*.

**Vallum's own position in this document's own repo already anticipates the
shape of the problem.** `docs/research/mullvad-reference.md` records that
Mullvad's "DNS goes through the tunnel, not to the host resolver", that
"ad/tracker/malware blocking available as DNS options (all off here)", and
that the privacy VPN's failure mode is to block while Mullvad restores the
gateway. It also already names the gap Vallum would be closing: "DNS that
cannot leak. Today a host with no working resolver manager keeps the tunnel and
resolves through whatever the host has" (same file). And
`docs/security-redteam-round2.md` (R2-2) already treats "its own `[quick] dns`
— every lookup on the client goes where it chooses" as a finding that a bundle
import must report, because "The client's operator believes the import is just
an address and a key."

---

## 4. The censorship-resistance angle: DoH, DoT, DoQ — and their limits

**What each is.** DoH maps each DNS query/response pair into an HTTP exchange
over HTTPS, "using https URIs (and therefore TLS security for integrity and
confidentiality)" (RFC 8484 §1, <https://www.rfc-editor.org/rfc/rfc8484.txt>).
DoT runs DNS over TLS: "Encryption provided by TLS eliminates opportunities for
eavesdropping and on-path tampering with DNS queries in the network" (RFC 7858
abstract, <https://www.rfc-editor.org/rfc/rfc7858.txt>). DoQ runs DNS over
QUIC and "has privacy properties similar to DNS over TLS (DoT) specified in RFC
7858, and latency characteristics similar to classic DNS over UDP" (RFC 9250
abstract).

**What they protect against.** "DoH encrypts DNS traffic and requires
authentication of the server. This mitigates both passive surveillance and
active attacks that attempt to divert DNS traffic to rogue servers ... DNS over
TLS provides similar protections, while direct UDP- and TCP-based transports
are vulnerable to this class of attack" (RFC 8484 §8.1). The same RFC notes
that using the HTTPS default port 443 and mixing DoH with other HTTPS traffic
"can deter unprivileged on-path devices from interfering with DNS operations
and make DNS traffic analysis more difficult" (§8.1), and that filtering
systems relying on unsecured DNS "will not function in a DNS over HTTPS
environment" (§10). RFC 9076 §5.2 is the same point more carefully: "The use
of encrypted transports directly mitigates passive surveillance of the DNS
payload; however, some privacy attacks are still possible."

**What they do NOT protect against — the well-known limitation.**

1. **The resolver still sees the query names.** Encryption protects the
   *path*, not the *endpoint*. RFC 8932: "the resolver operator still has (in
   principle) full visibility of the query data and transport identifiers for
   each user." RFC 9076 §6.1: "Recursive Resolvers see all the traffic."
   A DoH client talking to a DoH resolver on the VPN server gives the server
   operator the query names in cleartext at the endpoint.
2. **A network operator still sees the query names if the *resolver* is not
   encrypted end-to-end from the client.** Unencrypted DNS "can be seen by an
   eavesdropper like any other traffic" (RFC 9076 §5.1). DoH/DoT/DoQ only
   change this for the segment they actually encrypt; if the stub-to-resolver
   leg is plaintext, the names are visible to anyone on that path. This is
   precisely why a *tunnel* is the mechanism that makes a server-side resolver
   safe for the client: the queries travel inside the tunnel, encrypted
   end-to-end between client and server.
3. **Traffic analysis survives encryption.** "Traffic analysis of unpadded
   encrypted traffic is also possible because the sizes and timing of
   encrypted DNS requests and responses can be correlated to unencrypted DNS
   requests upstream of a recursive resolver" (RFC 9076 §5.2). DoQ adds its
   own: 0-RTT data "can be replayed by adversaries ... [they] may be able to
   pick a time at which the recursive resolver outgoing traffic is observable
   and thus find out what name was queried for in the 0-RTT data" (RFC 9250
   §7.1), and session resumption is a linkability problem (§7.2).
4. **Encrypted transports can be blocked, and blocking them is a known
   censorship technique.** "active blocking of port 853 for DoT or blocking of
   specific IP addresses could restrict the resolvers available to the user"
   (RFC 9076 §6.1.3); DoQ's own non-goals say "No attempt is made to evade
   potential blocking of DoQ traffic by middleboxes" (RFC 9250 §1). DoQ
   fallback can also silently downgrade: clients "MAY attempt to fall back to
   DoT and then potentially cleartext" (RFC 9250 §5.2).
5. **Encrypted DNS adds its own identifiers.** DoH "introduces new privacy
   considerations when compared with DNS over UDP, TCP, or TLS", including
   HTTP cookies and "implicit fingerprinting of the unique set and ordering of
   HTTP request header fields", and the `User-Agent`/`Accept-Language` headers
   "often convey specific information about the client version or locale"
   (RFC 9076 §6.1.4.2; RFC 8484 §8.2).

**EDNS Client Subnet (RFC 7871) is the other half of the resolver story.**
ECS exists so authoritative servers can tailor answers to the client's
network, and it is explicitly a privacy trade: the IETF "recommend[s] that the
feature be turned off by default in all nameserver software, and that
operators only enable it explicitly in those circumstances where it provides a
clear benefit for their clients" (<https://www.rfc-editor.org/rfc/rfc7871.txt>
§2). Truncation is the mitigation — "for privacy reasons, and because the
whole IP address is rarely required to determine a tailored response, this
length SHOULD be shorter than the full address" (§7.1) — and a recursive
resolver that forwards ECS "expose[s] the original IP address (or prefix,
depending on the setup)" to the authoritative server (RFC 7626 §2.5.2, via
<https://www.rfc-editor.org/rfc/rfc7626.txt>). A VPN operator's resolver that
enables ECS re-identifies clients it is otherwise hiding behind a shared exit
address. Pi-hole has an `EDNS0ECS` knob for exactly this
(<https://docs.pi-hole.net/ftldns/configfile/>), and ships a `blockESNI`
option that suppresses `_esni.` names for blocked domains — a DNS-layer
privacy control, in the same family (same page).

**What this means for a server-side sinkhole in a VPN.** A Pi-hole-style
resolver *inside* the tunnel is already protected against the local network by
the tunnel itself; adding DoH/DoT/DoQ on the client→server leg changes the
threat model from "your ISP sees the query names" to "the VPN operator sees the
query names". It does not add censorship resistance — the tunnel already
provides that property for the traffic it carries, and ADR-0026 in this
repository draws the line explicitly: "**v0.1 claims no censorship
resistance.** The tunnel is UDP and nothing else", and protocol emulation is
rejected because "the emulation is only as good as the version of the protocol
it copied" (local file `docs/adr/0026-censorship-resistance.md`).

---

## 5. Failure modes and supply-chain cost of a blocklist updater inside a VPN daemon

**The updater is a privileged network client in a security-critical process.**
The daemon's own posture in this repo is the relevant constraint: the daemon
runs with a seccomp filter (ADR-0028) and drops privileges, and the threat
model treats *any* new network egress from the daemon as a new attack surface.
Pi-hole's own updater is, by contrast, deliberately **not** root: `gravity.sh`
re-executes itself as the unprivileged `pihole` user — "Never run gravity as
root, as it writes to paths taken from the pihole-owned config" — and the cron
file notes the same, citing a published advisory
(<https://github.com/pi-hole/pi-hole/blob/master/gravity.sh>;
<https://github.com/pi-hole/pi-hole/blob/master/advanced/Templates/pihole.cron>).
Pi-hole's updater is a **separate script on a separate schedule**, not a
thread in the DNS daemon; FTL's own reload path is a signal
(`SIGHUP`/real-time signal 0 re-reads the gravity database and reloads
filters, <https://docs.pi-hole.net/ftldns/signals/>).

**Concrete failure modes, each with a source.**

- *Stale or empty list → silent loss of blocking, or total DNS failure.* The
  `gravity`/`antigravity` tables are flushed and rebuilt on every run
  (<https://docs.pi-hole.net/database/domain-database/>). A failed or
  interrupted update therefore leaves the resolver with an incomplete
  universe. Pi-hole's own answer to a busy/absent gravity database is a
  per-mode policy with a `BLOCK`/`ALLOW`/`REFUSE` switch
  (<https://docs.pi-hole.net/ftldns/configfile/>), i.e. the failure mode is
  known to be resolver-wide.
- *A malformed or hostile list is a denial-of-service vector.* The list
  format is parsed by the updater; Pi-hole has to handle IDN conversion
  failures raised by list maintainers
  (<https://docs.pi-hole.net/main/faq/>), and lists routinely contain
  duplicates and junk ("The index is intentionally not UNIQUE as poor quality
  adlists may contain domains more than once",
  <https://github.com/pi-hole/pi-hole/blob/master/gravity.sh>).
- *Authenticity is the list publisher's TLS certificate, nothing more.* As in
  §2, the only integrity artefact is a locally computed SHA-1 used for change
  detection. A compromised list host, or a list host the operator chose
  unwisely, feeds the resolver directly; there is no signature to reject.
  Mullvad's own curation note is the industry answer to this: lists are added
  only "without them being fully validated and verified"
  (<https://github.com/mullvad/dns-blocklists>).
- *Regex filters are a filter engine in the request path.* Pi-hole supports
  POSIX ERE filters with priority ordering and per-query-type conditions
  (<https://docs.pi-hole.net/regex/>); a pathological regex is a CPU cost on
  the resolver's hot path.
- *Update cadence has a distribution tail.* Mullvad: lists are rebuilt
  Monday–Thursday and "it will take about an hour for all our servers to pick
  up the updated lists", with caching on top ("it might not be actively used
  immediately") (<https://github.com/mullvad/dns-blocklists>). A fleet of VPN
  servers does not update atomically.
- *The updater needs an outbound network path from the daemon's host.* On a
  VPN *server* that path is normally open; on a *client* it is the one path
  that must not exist. That asymmetry is why the question "inside the tunnel"
  and "inside the daemon" are two different questions: the updater belongs to
  the server process, and the resolver, if any, belongs to the client.

**Cost summary from the sources:** a blocklist updater is a network client
with parse-and-apply logic, a trust decision about third-party URLs, a
distribution-propagation problem across a server fleet, and a failure mode
whose blast radius is "every DNS query on the box". None of that is
cryptographic; all of it is operational. Vallum's stated engineering bar —
"Rejecting emulation keeps the audit surface to Rust we wrote and dependencies
`cargo deny` covers" (`docs/adr/0026-censorship-resistance.md`) — is directly
in tension with embedding an updater that fetches and parses third-party text.

---

## 6. What Vallum already has that overlaps

**The `dns` field in the peer/client config.** `crates/vallum-config/src/lib.rs`
defines `Quick::dns: Vec<String>` — "DNS servers to install on the interface,
through `resolvconf`" — and `Quick::dns_domain: Option<String>`, whose doc
comment says: "`~.` makes the tunnel the default route for every name, which
is what stops a query from leaking to the local resolver on a full tunnel"
(`crates/vallum-config/src/lib.rs`, `Quick` struct). The mechanism is
implemented in `crates/vallum-quick/src/dns.rs` (`set_dns`/`unset_dns`,
`dns_backend_from`, `dns_domain`) and the daemon-side health view already
reports resolver state and DNS-leak risk
(`crates/vallum/src/tui/health.rs`: `dns`, `dns_upstream`, `dns_via_tunnel`,
`dns_leaks`). The CLI already lets a server push a resolver to a client:
`vallum peer add --dns` / `vallum server --dns` ("A DNS server to push to the
client bundle. Repeatable.",
`crates/vallum/src/commands/peer.rs`, `crates/vallum/src/commands/server.rs`),
and `crates/vallum/src/bundle.rs` writes it into the emitted client config's
`[quick]` table (`dns = [...]`). So **the plumbing for "the server tells the
client which resolver to use" already exists, and is already treated as a
security-relevant knob**: `bundle.rs` has a `PolicyFinding::DnsFromBundle`
("`[quick] dns` — every lookup goes where the server says") that the import
report prints when a bundle weakens the client
(`crates/vallum/src/bundle.rs`; `docs/security-redteam-round2.md` R2-2).

Note what the existing `dns` field is *not*: it names resolvers, it does not
run one. There is no resolver, no blocklist, and no filtering anywhere in the
tree; `grep` for `dns` across `crates/` finds only configuration plumbing,
policy rules, health reporting and the TUI.

**MagicDNS in the mesh agent (ADR-0027).** ADR-0027 assigns MagicDNS to
`vallum-mesh`, not to the daemon and not to the tunnel: the ownership table
lists "MagicDNS | `vallum-mesh` | names → `allowed_ips` + resolver config", and
the implementation phase lists "**MagicDNS.** Names from the node registry,
compiled to `allowed_ips` and resolver configuration" as phase 5 of the mesh
agent's work (`docs/adr/0027-mesh-topology-and-control-plane.md`). The
distinction the ADR draws is decisive for this question: MagicDNS is a
**naming** feature — it maps node names to addresses and emits the resolver
configuration — and it lives in the agent that already owns peer-set
distribution, so that the coordination plane can compile names to `allowed_ips`
rather than the data plane resolving anything.

**The surrounding architecture already answers "where does this go".** ADR-0027
is explicit that the mesh is an external agent driving the daemon over the
existing UAPI, and that "`vallum-core` and `vallum-tunnel` are not modified to
become a mesh"; the table of concerns puts "Peer-set distribution" and "STUN /
hole punching" in `vallum-mesh` and leaves sealing, roaming and live peer
apply in core. Any DNS feature that is not part of the sealed data path
therefore has an obvious home: the agent or the operator's tooling, not the
datapath.

**The adjacent gap that *is* in scope.** The functional requirements live in
`docs/roadmap.md`, which states: "**DNS cannot resolve outside the tunnel**
while attached" (condition 2, `docs/roadmap.md`), and lists as a closed item
"### 3. DNS that cannot leak (Closed)" whose "Done means" is "DNS is pushed
into the tunnel or port 53 is blocked outside it while attached; the 'kept the
tunnel, warned about DNS' fallback is gone rather than tolerated, and the
suite in (1) proves resolution does not leave the tunnel". The resolved
mechanisms are named there: "`policy.rs` drops UDP and TCP port 53 egress in
the killswitch filter table before any LAN/custom allow rules", the
`DnsBackend::ResolvFile` fallback in `vallum-quick`, and fail-closed
`attach`/`up` when a resolver cannot be installed (`docs/roadmap.md` §3). The
egress guard drop is in `crates/vallum/src/policy.rs`
("dns_outside_the_tunnel_is_dropped_even_with_lan_exceptions").
`docs/requirements.md` — the non-functional half — contains no DNS
requirement at all; it is capacity, latency, failure-detection and
observability (its own preamble: "Functional requirements live in
`docs/roadmap.md` as seven checkable conditions. This page is the
**non-functional** half"). Nothing in these requirements asks for
*filtering* — they ask for *containment*.

---

## What the sources support

- **Pi-hole is a DNS sinkhole, not a VPN and not a firewall.** It resolves
  names, blocks them by answering with an unspecified address, and logs
  queries by default; it cannot stop traffic that does not consult it, and
  Pi-hole's own docs route the "block the bypass" problem to an external
  firewall. [docs.pi-hole.net overview, ftldns/dns-resolver, ftldns/blockingmode,
  ftldns/privacylevels, routers/opnsense, main/prerequisites]
- **Shipping it means shipping an updater.** Pi-hole's blocklists come from
  third-party URLs, refreshed weekly, authenticated only by TLS plus a
  locally-computed SHA-1, parsed and applied by a script that Pi-hole
  deliberately runs unprivileged and out-of-process. A VPN operator doing the
  same publishes the exact upstream lists it imports and the vetting rule it
  applies. [pi-hole gravity.sh, advanced/Templates/pihole.cron, gravity.db.sql,
  docs/main/pihole-command, docs/database/domain-database;
  github.com/mullvad/dns-blocklists]
- **A server-side resolver is a trust decision, not a technical one.** The
  resolver operator sees the query names; encryption protects the path, not
  the endpoint; the standard privacy-VPN answer is to run the resolver on the
  relay and promise not to log — and to publish the blocklists it uses.
  [RFC 8932 §1, RFC 9076 §1/§6.1/§6.1.4.1, RFC 7626 §2.5;
  mullvad.net no-logging policy, dns-over-https-and-dns-over-tls;
  github.com/mullvad/dns-blocklists]
- **DoH/DoT/DoQ are path protections with documented limits.** They stop
  on-path eavesdropping and tampering; they do not hide names from the
  resolver, do not survive traffic analysis, do not stop an operator who
  blocks the encrypted port or the endpoint IP, and DoH adds HTTP-level
  identifiers; DoQ's own non-goals exclude evading middlebox blocking.
  [RFC 8484 §1/§8.1/§8.2/§10, RFC 7858, RFC 9250 §1/§5.2/§7.1/§7.2,
  RFC 9076 §5.1/§5.2/§6.1.3/§6.1.4.2]
- **ECS is the resolver-side counterweight to that trust**, and the IETF's
  own guidance is to keep it off by default and truncate what is forwarded.
  [RFC 7871 §2/§7.1]
- **Vallum already has the plumbing, the policy, and the precedent.** The
  `dns` field names resolvers, the server already pushes one to the client,
  the bundle import already flags it as a client-weakening finding, the
  egress guard already keeps `:53` inside the tunnel, and ADR-0027 puts
  MagicDNS — a *naming* feature producing "names → `allowed_ips` + resolver
  config" — in the external mesh agent rather than in the datapath.
  [crates/vallum-config/src/lib.rs, crates/vallum-quick/src/dns.rs,
  crates/vallum/src/commands/{peer,server}.rs, crates/vallum/src/bundle.rs,
  crates/vallum/src/policy.rs, crates/vallum/src/tui/health.rs,
  docs/adr/0027, docs/adr/0026, docs/roadmap.md, docs/requirements.md,
  docs/security-redteam-round2.md, docs/research/mullvad-reference.md]

*Sources are primary throughout: pi-hole's documentation site and the
pi-hole/pi-hole, pi-hole/FTL and pi-hole/docs repositories; RFC 8484, 7858,
9250, 9076, 8932, 7871 and 8767 from rfc-editor.org; and the published
documentation and public blocklist repository of one named privacy-VPN
operator (Mullvad). No secondary blog posts or vendor marketing claims are
relied on.*
