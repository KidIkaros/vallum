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
| `mtu1280` | PASS | carried *after* discovery — the tunnel was dead here before |
| `loss5` | PASS | carried, once the assertions stopped failing on one lost packet |

Both failures below were fixed. The first was a product defect; the second was
the harness accusing the product of something it never observed.

## What the two failures were

**`mtu1280` was a discovery gap, and is now closed.** The mechanism existed —
`interface.outer_mtu` cuts every datagram to `outer_mtu - 48` and
`tests/gate.rs` proves a narrow outer MTU carries handshake and segmented data —
but it was `Option<u16>`, unset by default, so the daemon assumed a 1500-byte
path and blackholed on anything narrower. An operator who already knew their MTU
could tell it; nobody discovered it.

The daemon now reads the path from the routing table (`net::path_mtu`: a
connected UDP socket plus `getsockopt(IP_MTU)`) in two places — at startup for
peers with a configured endpoint, and before the first datagram to any
destination it has not measured. The second is what mattered: **a responder has
no endpoint to probe**, learns the address from the handshake, and was replying
at the default budget. If the path narrows under an already-measured
destination, an `EMSGSIZE` now asks the kernel and narrows, rather than repeating
the same drop. `Segments::narrow_budget` only ever narrows: a budget is a
ceiling, and one reading is not evidence to raise it.

**`loss5` was the harness, not the product.** IPv4 crossed and IPv6 did not, and
the cause was a single `ping -6 -c2` failing when a post-quantum handshake — many
fragments — had not completed inside its window. At 5% loss each attempt has a
real chance of losing a fragment, so several retries are normal. That assertion
retries now, as does the post-rotation check that had the same shape. The product
was never measured failing.

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
