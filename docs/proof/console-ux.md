# Console UX pass — 2026-11-09

Done against a **dry-run lab**: a real daemon in a privileged container on its
own interface (`vallum9`), socket in a scratch directory, console pointed at it
with `VALLUM_RUNTIME_DIR`. Real snapshots, real control socket, real writes —
and no routes, no guard, no DNS, nothing that can touch the host's network.

Reproduce:

```sh
docker run -d --name vallum-dry --privileged --network=host \
  -v ~/.hermes/cache/scratch/vallum-dry:/lab debian:stable-slim sleep 7200
# copy the binary in, chmod 666 the socket and config, then:
VALLUM_RUNTIME_DIR=~/.hermes/cache/scratch/vallum-dry \
  ./target/release/vallum-gui --serve 7317 --ui crates/vallum-gui/ui/dist
```

## Bugs found, all fixed

| Symptom | Cause | Fix |
|---|---|---|
| Every peer write over HTTP failed with *"public key line has the wrong number of fields… found 1 fields"* | `dispatch` deserialised the whole body as `PeerFields`; the UI sends `{fields: {...}}` (correct for Tauri IPC), so every field arrived blank | dispatch unwraps `fields` once; both transports feed the same functions |
| A live daemon with no systemd unit showed the **STOPPED** card and hid the cockpit | the stopped card keyed off the unit, not off "can I reach the daemon" | stopped card only when the daemon is *also* silent |
| Duplicate peer rejected as *"the daemon rejected one of the values (errno 22)"* | EINVAL is what the daemon returns for several different mistakes | console pre-checks the public line against the peer list (*"already a peer: vps"*), and the errno map now says what EINVAL means |
| Header said `SERVICE INACTIVE` while the tunnel read `UP` | two different layers, one label | header now reads `DAEMON ATTACHED` + `UNIT NONE/INACTIVE` |
| The most important fact (is traffic tunnelled?) was buried at the bottom | layout ordered by panel type, not by consequence | an **EGRESS** verdict sits beside the tunnel verdict and leads the health panel |
| Chart had no scale and duplicated its own title | first pass | top-of-scale line, `rate · last Ns`, `scale 0 – peak` |
| `control 0s` | sub-second reads as zero | `live` when under a second |
| Peer freshness said `RECENT` with no age | label without a number | `RECENT 36s` |
| `datagrams` vs `packets` unexplained | two layers, one vocabulary | `datagrams · outer`, `packets · inner` |
| START offered for a unit that does not exist | enabled state ignored | disabled with the reason when the unit is `not-found` |

## Keyboard and validation (second pass)

- **Keys**, suppressed while a field has focus or a dialog is open: `a` add,
  `e` edit, `d` remove, `/` filter, `o` cycle sort (handshake → name → epoch),
  `Esc` clear the filter, `?` the list. Verified in the lab: `?` opens the
  overlay, `a` opens the add dialog, `/` focuses the filter, typing `vp` narrows
  `PEERS [1]/2`, `o` reaches `SORT NAME`.
- **Inline validation** (`lib/validate.ts`): public line, name, endpoint,
  keepalive, allowed IPs and preshared key each get a sentence under the field
  once it is touched — *"expected vallum1:<suite>:<kem>:<signing|-> — found 1
  field"* rather than a greyed-out button with no reason. The submit button
  states the first blocking problem beside it.

## Still open

- Multi-interface: the console shows `[1/1]` but cannot switch.
- Rotate and invite still answer only by toast; neither shows the new key in
  place where an operator would copy it.
- The chart has no history when the console opens mid-session (the ring starts
  empty); a persisted last-N-minutes would read better.
