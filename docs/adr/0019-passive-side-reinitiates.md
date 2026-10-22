# 19. The passive side must re-initiate, or a restart costs every client 120 s

**Status:** proposed · **Date:** 2026-10-22 · **Found by:** restarting a live server under a full-tunnel client

## Context

A full-tunnel client whose server restarts loses all connectivity until it
handshakes again. Measured on a real deployment: the client's handshakes landed
at 11:06:45 and 11:08:45 — exactly 120 s apart, the rekey interval — and during
a 45 s observation window after the restart **every** sample failed to reach the
server. The user's own experience was an internet outage they had to clear by
detaching.

The daemon logs show why:

```
client  peer `server` established at epoch 0 as Initiator
server  peer `laptop` established at epoch 0 as Responder
```

Both sides agree on the roles: the client always initiates, and the server has
never once been the initiator. So when the server restarts and forgets every
session, nothing tells the client. It keeps sending keepalives on a session the
server no longer has, the server drops them silently, and the client only
re-establishes when its own rekey timer expires.

`persistent_keepalive = 25` does not help, which was my first hypothesis and it
was wrong: a keepalive is a data packet on an existing session, not a probe that
can discover the session is gone. The config has had it all along.

WireGuard does not behave this way. A packet arriving for an unknown session
causes the passive side to send a handshake initiation, which is why a WireGuard
server restart costs a client a second or two rather than two minutes.

## Decision

The passive side must initiate a handshake when it receives a data packet for a
session it does not have.

Concretely, in the receive path: an authenticated-enough packet whose session is
unknown — the epoch is not in the session table, or the key has been rejected —
queues the packet and schedules a handshake initiation to that peer's endpoint,
rate-limited so a spoofed flood cannot turn the server into a handshake amplifier.

Rate limiting is the whole difficulty. Without it, an attacker who can spoof a
peer's source address can make the server emit handshakes at line rate. The
limit should be per-peer and coarse — a few attempts per second is far more than
recovery needs and far less than an amplifier is worth.

## Consequences

- A server restart costs a client seconds, not the rekey interval.
- The server gains an initiation path it does not currently have, including the
  state machine transitions that go with it. This is the real cost: the passive
  side currently only responds, and "respond" and "initiate" share less code
  than they look like they should.
- Handshake amplification becomes a thing the server can do, so the rate limit
  is not optional and belongs in the same change.
- Until this lands, the operational answer is in `docs/operations.md`: restarting
  a server disconnects every client for up to 120 s, so do it during a window
  and tell users, or detach clients first.

## Not decided here

Whether the client should also treat "no reply to N keepalives" as a reason to
re-handshake immediately rather than waiting for the rekey timer. That is a
cheaper fix that helps only the client side, and it would not have helped a
server that is trying to reach a client behind NAT. It is worth doing as well,
but it is not a substitute.
