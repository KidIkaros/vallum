# Fault lab — first measurements

The roadmap asks for behaviour under conditions we cannot reproduce from a
laptop. `scripts/e2e-netns.sh` builds a real two-endpoint tunnel over a veth pair
and, since this change, can degrade that link before the tunnel is built:

```sh
sudo FAULT=mtu1492 ./scripts/e2e-netns.sh
sudo FAULT=loss5   ./scripts/e2e-netns.sh
```

`FAULT` accepts `mtu1492`, `mtu1400`, `mtu1280`, `loss<N>`, `delay<N>`,
`reorder<N>`. Unset means no fault, which is the baseline.

## Results

| Fault | Verdict | What it means |
|---|---|---|
| none | PASS | baseline: the tunnel works on a clean link |
| `mtu1492` | PASS | a PPPoE-shaped outer path is carried |
| `mtu1280` | **FAIL** | ping across the tunnel fails — the tunnel is dead |
| `loss5` | **FAIL** | IPv4 crossed; IPv6 did not |

## What the two failures actually are

**`mtu1280` is not an MTU bug, it is a discovery gap.** The mechanism exists:
`interface.outer_mtu` cuts every datagram to `outer_mtu - 48` and derives the
inner MTU, and `crates/vallum/tests/gate.rs` proves a narrow outer MTU carries
both handshake and segmented data. But `outer_mtu` is `Option<u16>` and unset by
default, so the daemon assumes a 1500-byte path. On a 1280-byte link the
datagrams exceed it and the tunnel blackholes — with a warning in the log, not a
recovery.

That is roadmap item 4 stated precisely: the code can handle a narrow path, and
an operator who already knows their MTU can tell it. Nobody discovers it.

**`loss5` needs investigation before it is called a defect.** IPv4 crossed and
IPv6 did not, which is a suspicious asymmetry rather than a simple "loss breaks
things" result. It may be Neighbour Discovery or handshake retry timing under
loss, or the v6 assertion's timeout being tighter than the v4 one.

## What this is not

- **One run per condition is an anecdote, not a dataset.** These are single
  observations. Repetition with a pass rate per condition is what turns them into
  data, and it is not built yet.
- **The link is a veth, not the internet.** No NAT, no middleboxes, no real
  PMTUD, no asymmetric routing. It reproduces MTU and loss; it does not reproduce
  a carrier.
- **No egress.** Same limitation as `verify-host.sh`: nothing here proves a
  browser works.

## The comparison worth making

Not throughput against WireGuard. WireGuard is in-kernel and Vallum is a
userspace daemon with tri-hybrid post-quantum crypto; a throughput number would
measure that architectural choice, which was deliberate, and answer none of the
seven production-readiness conditions.

The comparison worth making is **behaviour under identical faults**: run
`wg-quick` in the same topology under `mtu1280` and `loss5` and record what each
does. That answers "what should production-ready look like here" with evidence,
and it is the control this lab is missing.
