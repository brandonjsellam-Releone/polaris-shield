# VORLATH Shield — threat model

## Assets
- **Confidentiality** of plaintext sealed in a Shield envelope.
- **Integrity / authenticity** of envelopes and of detached document signatures.
- **Sender authenticity** (in authenticated mode).

## Adversary
A network adversary who can record, modify, drop, replay, and inject envelopes, and who will
later possess a **cryptographically relevant quantum computer (CRQC)** able to break the classical
ECDH leg (X25519/X448). The adversary does **not** have the recipient's private key.

**Explicitly out of scope:** side-channel / timing / power / fault / co-resident observation of the
host running this pure-Python reference (see `SECURITY.md`); compromise of the endpoint or RNG;
coercion / key escrow.

## Properties and how they are achieved

| Property | Mechanism |
|---|---|
| **Confidentiality vs CRQC** (harvest-now, decrypt-later) | AEAD key derived from BOTH an ECDH secret AND an ML-KEM secret; breaking only the classical leg leaves the ML-KEM leg sealing the key. Holds **under the assumption ML-KEM remains secure**. |
| **Hybrid soundness** | HKDF-Extract over length-framed `(ss_classical ‖ ss_pq)`; the combined key's security reduces to the **stronger** of the two KEMs. |
| **Integrity / tamper-evidence** | AES-256-GCM authenticates ciphertext and the entire self-describing header (AAD). |
| **Downgrade resistance** | `suite_id` and `flags` are bound into both the AEAD AAD and the HKDF transcript; the recipient's key dictates the suite, so a sender/attacker cannot negotiate a weaker one. |
| **Transcript binding** | `eph_pub ‖ kem_ct ‖ nonce ‖ recipient_key_id ‖ suite_id ‖ flags` is folded into HKDF `info` and the AAD, preventing re-binding / mix-and-match. |
| **Sender authenticity** (optional) | ML-DSA signature over `pre_auth ‖ sender_key_id` (the signer binds its own identity, SIGMA-style), verified **before** decapsulation; the sender block is also under the AEAD AAD. Optional pinning of the expected sender key-id. |
| **No nonce reuse** | A fresh ephemeral handshake yields a unique per-message key, so a random 12-byte GCM nonce never repeats under a given key. |
| **Robust parsing** | Fully bounds-checked TLV decode with a total-length invariant; malformed input raises `ValueError`, not an out-of-range read. |

## Formal verification

The properties above are **machine-checked**, not just asserted, across **two independent tool
lineages** — [Verifpal](https://verifpal.com) (bounded) and [Tamarin](https://tamarin-prover.com)
(unbounded sessions), both symbolic (Dolev-Yao). The model of the authenticated hybrid handshake in
[`formal/`](formal/) proves that plaintext stays confidential even when an active attacker breaks the
**classical** leg (`formal/shield.vp`, the CRQC / harvest-now-decrypt-later case) **or** the
**ML-KEM** leg (`formal/shield_pq.vp`) — but not both — and that a forged or tampered envelope is
rejected (sender authenticity, transcript binding, downgrade resistance); the Tamarin lineage
(`formal/shield.spthy`) re-proves the same core goals over an unbounded number of concurrent sessions
and adds standalone downgrade- and KCI-resistance lemmas. The documented replay non-property is
reproduced as a verified non-result (`formal/shield_replay.vp`). The CI `formal` job re-runs the
proofs whenever the handshake model or its implementation changes. Scope: symbolic, under idealized
primitives — see [`formal/README.md`](formal/README.md).

## Residual risks (accepted, disclosed)
- **AES-256-GCM is not a key-committing AEAD.** A single ciphertext can in principle be made to
  decrypt under two different keys (the "invisible salamander" / partitioning-oracle class), so GCM
  alone does not commit to the key or context. The Shield supplies key/context commitment **instead at
  the KDF layer**: the AEAD key is bound to the full handshake transcript (`suite_id ‖ flags ‖
  recipient_key_id ‖ eph_pub ‖ kem_ct ‖ nonce`) via the HKDF `info`, so a given ciphertext is tied to
  exactly one derived key and one negotiated context. This is the relevant defence in **anonymous
  mode**, which carries no sender signature; it pre-empts a partitioning-oracle reading of the AEAD.
- Long-term confidentiality depends on ML-KEM remaining unbroken (no scheme is proven).
- Not constant-time; not FIPS-validated (see `SECURITY.md`).
- The envelope is non-standardized; use HPKE / TLS 1.3 hybrid for interop.
- **Replay / freshness is an application-layer responsibility.** A one-shot envelope (including an
  authenticated one) is replayable by design: the sealer is stateless and the sender signature covers
  the transcript, not any recipient-supplied freshness. Callers needing replay resistance must
  deduplicate on the per-envelope nonce / transcript or embed a challenge / timestamp in the plaintext.
