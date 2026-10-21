# Mullvad as a reference implementation

What a mature WireGuard client does that Vallum does not, read from a live
Mullvad 2026.5 install (daemon 17 MB, `mullvad-daemon`, ELF x86-64) and from
the strings and configuration it ships. Evidence is marked: **[live]** = read
from the running system, **[settings]** = `/etc/mullvad-vpn/settings.json`,
**[strings]** = extracted from the binary.

The question that started this: *how does having the VPN on affect browsing?*
The answer is the shape of the gap.

## What Mullvad actually does to a machine

**It blocks before the network exists.** `mullvad-early-boot-blocking.service`
runs `mullvad-daemon --initialize-early-boot-firewall` ordered
`Before=network-pre.target` **[live]**. By the time any interface is configured,
a firewall is already dropping traffic. This is why the kill switch survives a
reboot that happens while the tunnel is down.

**It has a state machine, and most states block.** `locked_down`, `connecting`,
`connected`, `disconnecting` **[strings]**. Even with `lockdown_mode: false`
**[settings]** — which permits traffic when fully disconnected — traffic is
blocked while connecting and while disconnecting, so the window where packets
could leave unencrypted does not exist.

**DNS goes through the tunnel, not to the host resolver.** An encrypted DNS
proxy is a first-class access method **[settings]**, with ad/tracker/malware
blocking available as DNS options (all off here).

**MTU is measured, not assumed.** `Failed to detect MTU because all pings timed
out` **[strings]** — it probes with ICMP and picks the largest size that passes.
`mtu: null` **[settings]** means "auto", not "1500".

**It talks to the kernel directly.** `talpid-core` uses netlink rather than
shelling out to `ip` **[strings]**, and its firewall is netfilter: `Removing
table and chain from netfilter` **[live journal]**. On disconnect it removes
the table entirely, so the block and the tunnel share a lifetime.

**Also present, not used here:** split tunnelling by process/app, SOCKS5 local
and remote, obfuscation (Shadowsocks, udp2tcp, QUIC, LWO, MASQUE), multihop, and
a quantum-resistant tunnel — `quantum_resistant: "on"` **[settings]**,
ML-KEM-1024 **[strings]**.

## Side by side

| Concern | Mullvad 2026.5 | Vallum 1.6.2 |
|---|---|---|
| Tunnel failure | **Blocks.** Fail-closed; traffic never escapes | **Restores the gateway.** Fail-open by design — the watchdog's whole job is to give the host its internet back |
| Boot | Firewall before `network-pre.target` | Nothing; no tunnel, no routes, no block |
| DNS | Encrypted proxy inside the tunnel | `resolvectl`/`resolvconf`, best-effort; warns and keeps the tunnel |
| MTU | ICMP probe, auto | Fixed `outer_mtu` 1500, inner derived |
| IPv6 | Off inside the tunnel by default | `::/0` accepted; full tunnel |
| Split tunnel | Per process/app, and by destination | Destination prefixes only (`allowed_ips`) |
| Routing | netlink, own table, netfilter firewall | `ip rule`/`ip route`, table 51820, fwmark 51820 |
| Reconnect | Always-on with backoff; auto-connect | Daemon rekeys at 120 s; manual otherwise |
| Obfuscation | Shadowsocks, udp2tcp, QUIC, LWO, MASQUE | None |
| PQ | ML-KEM-1024 | X25519 + sntrup761 + ML-KEM-768 tri-hybrid |

## The gap that matters

Vallum's failure mode is the **opposite** of a privacy VPN's. When the peer goes
away, Mullvad keeps the machine silent and Vallum hands the machine its own
gateway back. Both are defensible — one protects confidentiality, the other
protects availability — but Vallum currently makes that choice for the operator
and does not say so.

That is a leak, not a bug: a PQ tunnel exists to keep traffic confidential, and
on failure the traffic leaves in the clear with no signal. The watchdog added in
1.6.2 is the right *mechanism* (it already distinguishes `Withdraw` from
`Restore`); what it lacks is a policy.

### Ranked, as the next areas of development

1. **A failure policy, defaulting to closed.** `block-on-failure` installs a
   blackhole rule for the tunnel's prefixes instead of reversing to the gateway;
   `restore` keeps today's behaviour. The verdict is already computed in one
   place, so this is a policy switch, not a second mechanism. Needs the same
   care as the route plan: record what was installed, reverse it exactly.
2. **DNS that cannot leak.** Today a host with no working resolver manager keeps
   the tunnel and resolves through whatever the host has. Either push DNS into
   the tunnel or block port 53 outside it while attached.
3. **Path MTU detection.** A fixed 1500 black-holes on PPPoE and DS-Lite links,
   and the failure looks like "the tunnel is up but some sites hang" — the worst
   kind to diagnose remotely.
4. **Always-on and backoff.** Reconnect without a human, and start at boot.
5. **Per-app split tunnelling.** Destination prefixes cannot express "browser
   through the tunnel, everything else direct".

## On the tooling

REA needed Ghidra 12.1.x (12.0.4 is installed by default) and a full JDK — the
box had a JRE only. With those, Ghidra 12.1.4 imports the daemon but exceeds
REA's 330-second analysis cap on a 17 MB Rust binary, so the deep decompilation
was not available in this pass. Everything above is from the live system, the
settings file, and the binary's own strings; the netlink and netfilter
behaviours are named by the crates that implement them rather than read out of
decompiled code.
