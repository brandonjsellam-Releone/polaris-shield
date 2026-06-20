# Mechanized (CryptoVerif) — VORLATH Shield hybrid combiner

This note records a **machine-checked computational** proof, in
**CryptoVerif 2.12**, of the core security claim of the VORLATH Shield hybrid
combiner: the derived session key is indistinguishable from a fresh random key
under single-leg compromise. It is the artifact named as future work in
[`../SECURITY_ARGUMENT.md`](../SECURITY_ARGUMENT.md) §6.

> **Honesty bar.** Everything below labeled "proved" is a verbatim CryptoVerif
> `RESULT` line that the tool actually emitted. Nothing is rounded up. The
> assumptions that are *abstracted* (ML-KEM IND-CCA, strong-DH, AEAD security)
> are listed explicitly under "What is assumed, not mechanized".

## Files

| File | Front end | What it proves |
|---|---|---|
| [`shield_combiner.cv`](shield_combiner.cv) | oracle | **Core claim.** Combiner key-indistinguishability under single-leg compromise, in **both** directions (classical leg leaked; PQ leg leaked). |
| [`shield_kemdem.cv`](shield_kemdem.cv) | oracle | **Optional corollary.** One-step KEM-DEM: message confidentiality + ciphertext integrity of the AES-256-GCM channel keyed by the combiner output, under classical-leg compromise. |

`.ocv` copies (identical bytes) are kept beside each `.cv` so the oracle front
end is selected by extension without a flag.

### How to reproduce

```bash
# from a checkout, with the vorlath-cryptoverif Docker image:
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "<repo>/tech/formal:/work:ro" vorlath-cryptoverif \
  bash -lc 'opam exec -- cryptoverif -in oracles /work/shield_combiner.cv'

MSYS_NO_PATHCONV=1 docker run --rm \
  -v "<repo>/tech/formal:/work:ro" vorlath-cryptoverif \
  bash -lc 'opam exec -- cryptoverif -in oracles /work/shield_kemdem.cv'
```

(Equivalently, run the `.ocv` copy without `-in oracles`.) Tool:
`Cryptoverif 2.12` (binary `opam exec -- cryptoverif`).

## What the model encodes

The Shield key is (see [`../SECURITY_ARGUMENT.md`](../SECURITY_ARGUMENT.md) §1 and
`vorlath_shield/shield.py:_derive_key`):

```
K = HKDF(salt = "VORLATH-Shield-combiner/v2",
         IKM  = u16(len ss_c) ‖ ss_c ‖ u16(len ss_pq) ‖ ss_pq,
         info = label ‖ suite_id ‖ pre_auth,
         L    = 32)
```

`SECURITY_ARGUMENT.md` §3/§4 abstracts "HKDF as a (dual-)PRF / extractor in the
(Q)ROM". The model takes that abstraction at face value and represents HKDF as a
**random oracle** `H` on its three logical inputs:

```
K = H(ss_c, ss_pq, transcript)
```

- `ss_c` (classical ECDH secret, RFC 7748) and `ss_pq` (ML-KEM secret, FIPS 203)
  are modeled as two **separate `large,fixed` types** — this is the
  computational encoding of the `u16` length-framing that makes the IKM parse
  **injective** (no concatenation ambiguity).
- `transcript` is the HKDF `info` field, public and handed to the adversary.
- The adversary gets an **unrestricted hash oracle** `OH` (it may evaluate the
  KDF/ROM at any point of its choice, up to `qH` queries).

**The game.** One honest handshake completes the combiner; the adversary is
**given one leg** (single-leg compromise) and asked to distinguish `K` from a
fresh independent key (`query secret`). `shield_combiner.cv` runs both directions
in one game: `Kc` (classical leg `ss_c` leaked, `ss_pq` withheld — the
harvest-now-decrypt-later / CRQC case) and `Kq` (PQ leg `ss_pq` leaked, `ss_c`
withheld).

## What CryptoVerif proved — verbatim `RESULT` lines

### `shield_combiner.cv` (the required core)

```
RESULT Proved secrecy of Kq up to probability 2 * qH / |ss_pq_t| + (2 + 2 * qH) / |ss_c_t|
RESULT Proved secrecy of Kc up to probability 2 * qH / |ss_pq_t| + (2 + 2 * qH) / |ss_c_t|
All queries proved.
```

`Kc` = classical leg compromised, `Kq` = PQ leg compromised. The bound is the
honest cryptographic intuition: the only way to distinguish the key is to **guess
the still-secret leg** among the `qH` hash-oracle queries — `qH / |ss_pq_t|` when
the PQ leg is the protected one, `qH / |ss_c_t|` when the classical leg is the
protected one. There is no other distinguishing path; in the abstracted game
`Adv[final game] <= 0`.

### `shield_kemdem.cv` (optional KEM-DEM corollary)

```
RESULT Proved forall c: bitstring; event(accept(c)) ==> event(sent(c)) up to probability Pencctxt(time_1, N, 1, maxlength(game 11: c), maxlength(game 11: hdr_1), maxlength(game 11: hdr_2)) + qH / |ss_pq_t|
RESULT Proved secrecy of b up to probability 2 * Penc(time_2, N) + 2 * Pencctxt(time_1, N, 1, maxlength(game 11: c), maxlength(game 11: hdr_1), maxlength(game 11: hdr_2)) + 2 * qH / |ss_pq_t|
All queries proved.
```

- `secrecy of b` = **message confidentiality**: the secret bit selecting between
  two equal-length adversary plaintexts is hidden (real-or-random of the sealed
  payload).
- `accept ==> sent` = **ciphertext integrity**: the receiver only accepts
  ciphertexts the sender actually produced (INT-CTXT / authentication).

The bound decomposes exactly as the KEM-DEM composition predicts: the
`qH / |ss_pq_t|` term is the **ROM combiner** contribution (guessing the
protected PQ leg) and the `Penc` / `Pencctxt` terms are the **AEAD** layer.

## Exactly what is proven, and under which assumptions

**Proven (mechanized):** In the random-oracle model for HKDF, with one of the two
shared secrets sampled fresh and **withheld** from the adversary (the other leg
being handed over), the combiner output `K = H(ss_c, ss_pq, transcript)` is
indistinguishable from a fresh random key — in **both** single-leg-compromise
directions — and, in the corollary, the AES-256-GCM channel keyed by `K` provides
message confidentiality and ciphertext integrity. This is the **computational
counterpart** of the symbolic `hybrid_secrecy` lemma in
[`shield.spthy`](shield.spthy) and the two single-leg Verifpal models.

| Assumption | How it appears in the model |
|---|---|
| HKDF is a random oracle (the `(Q)ROM` abstraction of §4) | `expand ROM_hash_3(...)` — **modeled** |
| One leg's shared secret is hidden | the withheld `<-R` secret — **modeled** (the adversary lacks it) |
| AES-256-GCM is IND-CPA + INT-CTXT (SP 800-38D) | `expand AEAD(...)` in the corollary — **assumed primitive** |

## What is assumed, not mechanized (cited, not re-proven)

- **ML-KEM IND-CCA** (FIPS 203 / Module-LWE). The model does **not** prove that
  `ss_pq` is hidden from a real ML-KEM adversary; it **abstracts** that by
  sampling `ss_pq` as a fresh secret the adversary is not given. The reduction
  from "ML-KEM IND-CCA" to "`ss_pq` is pseudorandom" lives in
  [GHP18]/[X-Wing], cited in `SECURITY_ARGUMENT.md` §2, not re-proven here.
- **Strong Diffie-Hellman on X25519/X448** (RFC 7748) — abstracted the same way
  for `ss_c`.
- **The HKDF→ROM step itself.** We model HKDF *as* a random oracle; we do not
  derive ROM behavior from HMAC/SHA-2/SHA-3. This is exactly the
  `(dual-)PRF / (Q)ROM` abstraction `SECURITY_ARGUMENT.md` already states.
- **The full channel / protocol logic** (downgrade resistance, sender
  authentication, replay) — those remain covered by the symbolic Tamarin/Verifpal
  models, not by this computational model.

## Honest status

This is a **complete, machine-checked computational proof of the scoped claim**
— combiner key-indistinguishability under single-leg compromise, in the ROM, in
both directions, plus the one-step KEM-DEM corollary — and CryptoVerif reports
`All queries proved` for both files. It is **not** a proof of ML-KEM IND-CCA or
of strong-DH (those are assumed), and it is **not** a full end-to-end protocol
proof. Within its stated scope and assumptions, it closes the specific gap that
`SECURITY_ARGUMENT.md` §6 named as future work for the combiner.
