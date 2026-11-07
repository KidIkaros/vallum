# Traffic shaping: the five shapes, and what each costs

Vallum's shaping is off by default. When it is on, it is a list of **named
shapes** under a peer, each with bounded parameters:

```toml
[[peer]]
name = "laptop"
public_key = "..."
allowed_ips = ["10.7.0.2/32"]

[[peer.shaping]]
kind = "pad_to_size"
size = 1400
```

A shape is applied to that peer's tunnel on the machine that runs the config.
It is *local policy*: the two ends need not agree, and padding changes a packet's
size and timing, never its meaning. There is deliberately no syntax for a raw
state machine — a config file that can describe arbitrary machines is a config
file that can describe a flood ([ADR-0022](adr/0022-shaping-policy-in-core.md)).

The one thing every shape assumes: **shaping is not censorship resistance.** It
makes the traffic harder to *analyse*; it does nothing about a network that drops
UDP, and there is no fallback transport
([ADR-0026](adr/0026-censorship-resistance.md)).

## The shapes

| `kind` | parameters (with their rails) | what it hides |
|---|---|---|
| `pad_to_size` | `size` | packet length — the size set becomes a single value |
| `min_interval` | `interval_ms` | timing — a burst becomes a train |
| `respond_with_padding` | `size`, `injections`, `cap` | whether a reply was caused by an inbound packet |
| `constant_rate_floor` | `interval_ms` (min 100), `size`, `jitter_ms` (max half the interval) | silence — an idle tunnel keeps speaking |
| `front_padding` | `count` (max 60), `interval_ms` (max 1 000), `size` | the opening seconds of a peer's life |
| `volume_padding` | `window_ms` (min 1 000), `max_packets` (max 32, rounded down), `size` | how many packets a burst contained |
| `byte_volume_padding` | `window_ms` (min 1 000), `window_bytes`, `size` | the same, in bytes, by fixing the packet size |

Rails are clamped, not rejected: a `constant_rate_floor` at 10 ms runs at 100 ms,
and `front_padding` with `count = 500` sends 60 packets. Clamping a value that is
merely too aggressive is kinder than refusing a config over a number a firewall
already bounds.

## Worked examples

### Close the length channel, and nothing else

```toml
[[peer.shaping]]
kind = "pad_to_size"
size = 1400
```

Every packet leaves at one size, so length carries no information. On the gate's
page-load trace this takes 1 190 bytes of traffic to 10 192 — **+756 %** — because
every small request is inflated to the size of the largest response. That is the
honest price of the strongest single property here.

### Stop an idle tunnel from looking idle

```toml
[[peer.shaping]]
kind = "constant_rate_floor"
interval_ms = 2000
jitter_ms = 500
size = 1400
```

One 1 400-byte packet every two seconds, whether or not anyone is using the
tunnel: 1 800 packets an hour, **2.62 MB/h, 5.82 kbit/s** per tunnel, per
direction. `jitter_ms` spreads the gaps over 1 500–2 500 ms instead of a metronome,
at the same mean rate — the same 7 200 packets an hour at 500 ms
([measured](proof/traffic-shaping.md)). Pick the interval from the bill you are
willing to pay, not from the other end's settings: the floor is not negotiated.

### Filler for the first minute of a session

```toml
[[peer.shaping]]
kind = "front_padding"
count = 30
interval_ms = 200
size = 1400
```

Up to 30 padding packets, each either alongside a real packet or after 200 ms of
silence, then done for good: about **43 kB once**, not a rate. It is the only
shape here whose cost ends, which is why it is the cheapest to leave enabled.

### Make bursts the same shape

```toml
[[peer.shaping]]
kind = "volume_padding"
window_ms = 2000
max_packets = 16
size = 1400
```

A window closes on a two-second pause or on 16 packets, and closing tops the count
up to the next power of two: nine packets become sixteen, eleven become sixteen.
On the page-load trace, three windows close and three packets are added
(**+367 %** on that trace). The cap is rounded down to a power of two, so `20`
means sixteen.

If what matters is bytes rather than packets, use the byte form:

```toml
[[peer.shaping]]
kind = "byte_volume_padding"
window_ms = 2000
window_bytes = 11200
size = 1400
```

This one pads every packet to `size`, so a window's bytes are exactly its count
times `size` and the byte target is a power of two rather than an approximation.
It costs what `pad_to_size` costs (`+1 123 %` on the same trace) because it *is*
`pad_to_size` underneath. A payload larger than `size` cannot be padded down and
counts as more than the window accounts for, so set `size` above your largest
packet.

### Blur causality, expensively

```toml
[[peer.shaping]]
kind = "respond_with_padding"
size = 1400
injections = 1
cap = 8
```

With odds `injections / (injections + 1)`, one inbound packet draws one padding
packet back, up to `cap` times. Use it only where the reply pattern itself is the
signal, and note that `cap` is the whole cost bound.

## Combining shapes

Shapes are independent machines over one tunnel, so their costs add: lengths,
timing and volume are separate channels and each needs its own shape. A
deployment that pads to a fixed size and injects a floor pays both bills, and
`byte_volume_padding` next to `pad_to_size` is the same pad installed twice.

The cheapest useful combination for most deployments is `pad_to_size` plus a
`constant_rate_floor` at an interval you can afford; a `front_padding` burst is
worth adding when a peer's first minute is what an observer sees.

## Measuring it yourself

Every number on this page comes from the gate, printed on every run:

```sh
cargo test -p vallum-protocol-tests --test shaping -- --nocapture
```

The relations the tests assert — same size, more bytes, bounded delay, exact
counts — are in [`proof/traffic-shaping.md`](proof/traffic-shaping.md), which also
records what the framework does *not* claim.
