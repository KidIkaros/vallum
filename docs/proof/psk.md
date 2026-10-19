# G1 — configured preshared key

**Status:** adds the one protocol capability WireGuard has that Vallum did not:
an operator-supplied per-peer PSK.
**Depends on:** P1 (`eck-pfs-psk.md`) for the schedule this extends.
**Wire change:** the default (`None`) path is byte-identical to every frozen
vector. A configured PSK adds a 32-byte admission tag to `InitHello` (+36 B with
the field header); the key schedule itself is unchanged.

---

## 1. Why

WireGuard is `Noise_IKpsk2`: `WGPEER_A_PRESHARED_KEY` is an optional 32-byte
secret mixed into the handshake at a fixed step. It is not a post-quantum
mechanism — it is defence in depth and a deployment requirement in some
environments (a symmetric secret that must also be compromised).

Vallum's schedule already derives a *public* PSK from both static public keys
for UKS mitigation (`PSK_DOMAIN`). That is not a configured secret: anyone who
knows the two public keys can compute it. This phase adds the real one.

---

## 2. Design

- The PSK is an optional `SharedSecret` on `PeerConfig`, **not** on the public
  `PeerIdentity`. The handshake takes it explicitly
  (`initiator_hello_with_psk`, `responder_accept_with_psk`,
  `responder_process_init_with_psk`), and the default functions pass `None`.
  This keeps identity equality and public-key encoding free of the secret, and
  preserves every existing call site's byte-identical default path.
- Mix point, after the existing UKS mix:

  ```
  key = KDF(salt = key_after_uks, ikm = configured_psk,
            info = "vallum/config-psk/v1")
  ```

  A distinct domain, both sides compute the same value, and `None` skips the
  step entirely — which is why the default vectors do not move.
- The responder's confirmation is derived from the mixed key, so a mismatch
  surfaces as `HandshakeError::Confirmation`. There is no "PSK mismatch" oracle:
  the failure is indistinguishable from any other confirmation failure.
- `InitiatorState` retains the PSK from `initiator_hello` so the rebuilt state
  in `initiator_process_resp` uses the same one. A PSK changed between
  `InitHello` and `RespHello` makes that handshake fail and the next one use the
  new value — the same posture WireGuard takes.
- **Admission tag (DoS).** A configured PSK also authenticates the initiation:
  `PSK_TAG` is a 32-byte KDF over `InitHello` minus the tag and the cookie MACs,
  keyed by the PSK (`vallum/init-psk-tag/v1`). The responder checks it after op A
  and **before ops B/C**. Wrong, missing, or unexpected tags return
  `HandshakeError::PskTag` with no reply, so a forged `InitHello` costs the
  responder one op-A decapsulation, not two hybrid encapsulations. This is the
  PQ-WireGuard DoS property; without a PSK, the cookie gate and the sealed hint
  remain the mitigations. The tag is admission-only and not folded into `TR`.

---

## 3. Configuration

```toml
[[peer]]
name = "laptop"
public_key = "vallum1:0003:…"
preshared_key_file = "laptop.psk"   # 64 hex characters, mode 0600
# or, for tests and throwaway deployments:
# preshared_key = "a5a5…"           # 64 hex characters
```

- Both fields set is an error; there is no precedence rule for a secret.
- `preshared_key_file` uses the private-key permission policy: group/world bits
  are refused unless `--allow-insecure-key-permissions`, and the override still
  logs the exposure.
- `vallum genpsk` prints a fresh 32-byte key as 64 hex characters.

---

## 4. Measured

`vallum-protocol-tests/tests/psk.rs`:

- a matching PSK produces identical transcript, key, and both confirmations on
  all shipped suites;
- a different PSK, and a one-sided PSK in either direction, fail with
  `Confirmation`;
- the PSK never appears in any handshake message;
- a configured PSK adds exactly 36 bytes to `InitHello`; the default path is
  unchanged and the frozen interop vectors still pass;
- a wrong, missing, or unexpected tag fails with `PskTag`, and a `CountingSuite`
  proves the responder performs **zero** encapsulations after the rejection.

The e2e generates one PSK with `genpsk`, writes it into both configs, and runs
**every** lifecycle with it — default, narrow MTU, v6 inner, dual-stack, and the
DF path.

---

## 5. What this does **not** claim

1. **Not post-quantum.** The hybrid KEM is the PQ leg; the PSK is an extra
   symmetric secret.
2. **Rotation is live.** The UAPI `set preshared_key` updates the peer; the
   current session keeps running and the next handshake uses the new value.
3. **No per-direction PSK.** One key per peer, as WireGuard has.
4. **No PSK in the identity document.** It is local configuration, never
   published.
5. **No protection against a compromised PSK file.** The permission policy
   covers accidental exposure, as with the private key.
6. **No identity hiding from the tag.** The tag authenticates the initiation to
   the responder; it is not a proof of the initiator's identity and does not
   hide the KEM ciphertexts.
