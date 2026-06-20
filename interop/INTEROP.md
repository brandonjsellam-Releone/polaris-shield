# VORLATH Shield — interoperability corpus (PSTV) and standards-alignment map

This directory is the **cross-implementation interoperability** component for the VORLATH
Shield reference cryptosystem. It exists to answer one question with running code:

> Is the wire-format specification in [`../FORMAT.md`](../FORMAT.md) complete and unambiguous
> enough that a **second, separately-coded** implementation (which shares the same primitive
> libraries), written only from the spec, can verify and decrypt the **same** envelopes the
> reference produces?

It answers "yes" via two artifacts plus a test:

1. **`pstv_vectors.json`** — a frozen "Portable Shield Test Vectors" (PSTV) corpus.
2. **`altcodec.py`** — a *separately-coded* `VRSH`/`VRST` decoder built only from `FORMAT.md`,
   which does **not** import `vorlath_shield`'s envelope/combiner/KDF/key-bundle code (it does,
   by design, share the same primitive libraries — see the scope note below).
3. **`test_pstv.py`** — for every positive vector, both the reference **and** `altcodec`
   reproduce the committed plaintext; for every negative vector, **both** reject.

## Honest framing (mandatory)

- The VORLATH Shield envelope is a **project convention**, **not** a standardized, registered,
  or IANA/IETF-assigned protocol. There is no interoperability claim with any third party.
- **"CNSA 2.0"** here denotes the **algorithm set** (ML-KEM-1024 + ML-DSA-87 + AES-256 +
  SHA-384), **never** a validated module or a certification. For interoperable production
  traffic use TLS 1.3 hybrid key-exchange or HPKE, as `FORMAT.md` and `SECURITY.md` state.
- The corpus proves **byte-level format interoperability** and **combiner/KDF/AEAD agreement**
  between the reference and a second, separately-coded implementation (which shares the same
  primitive libraries). It does **not** prove FIPS 140-3 (CAVP/CMVP)
  validation, and it makes **no** side-channel / timing claim. `kyber-py`, `dilithium-py`, and
  `cryptography` are reference libraries that track the standards; they are not validated modules.
- `altcodec` reuses the same underlying *primitive* libraries as the reference (this is by
  design — the goal is separately-coded **parsing + combiner + KDF + AEAD-open** logic, not a
  from-scratch re-implementation of lattice math).
- **What this independence covers (scope).** The cross-check proves independence at the
  **FORMAT / TLV-parse / combiner / KDF-transcript / AEAD-orchestration** layer, over the
  **shared primitive libraries** (`kyber-py` / `dilithium-py` / `cryptography`) and the **same
  spec author**. It does **not** cross-validate the ML-KEM / ML-DSA / AES-GCM primitives
  themselves, and it cannot catch a spec misreading that both implementations share (they were
  written from the same `FORMAT.md` by the same author).

## Wire-field → spec section → standard basis / modeled on

Each `VRSH` envelope field, mapped to its `FORMAT.md` section and the standard the value or the
operation that consumes it is **based on or modeled on**. (`VRSH` = single-shot envelope;
`VRSK` = key bundle.) Where a row names a NIST publication, read it as *the standard this construction
is built from or shaped after* — not a claim of validated/conformant instantiation of that standard.
In particular, the hybrid combiner is **modeled on** SP 800-56C (its two-step extract-then-expand KDF
with length-framing and a FixedInfo transcript), but it is a **project construction**, not a validated
or conformant SP 800-56C instantiation; see the note below the table.

| Wire field | `FORMAT.md` § | Standard basis / modeled on |
|---|---|---|
| `MAGIC` (`VRSH`), `VERSION` (`0x02`) | §2.2 | project convention (framing) |
| `suite_id` (`0x01` / `0x02`) | §2.2, §6, §2.7 | selects the FIPS 203/204 + RFC 7748 parameter set |
| `flags` (`FLAG_AUTHENTICATED`) | §2.2, §2.7 | project convention; bound into AAD + KDF |
| `recipient_key_id` (32 B SHAKE-256) | §2.3, §5.2 | FIPS 202 (SHAKE-256) |
| `eph_pub` (X25519 32 B / X448 56 B) | §2.3, §6 | RFC 7748 (ECDH) |
| `kem_ct` (ML-KEM ciphertext) | §2.3, §6 | FIPS 203 (ML-KEM encaps/decaps) |
| `nonce` (12 B GCM nonce) | §2.3 | NIST SP 800-38D (AES-GCM) |
| `sender_block` (`sender_kid`/`pub`/`signature`) | §3 | FIPS 204 (ML-DSA), SIGMA-style identity binding |
| `pre_auth` transcript / HKDF `info` | §2.6(b), §8.3 | modeled on NIST SP 800-56C (FixedInfo-shaped transcript) |
| HKDF over length-framed `ss_classical‖ss_pq` | §2.6(b), §8.1 | RFC 5869 (HKDF); combiner shape modeled on SP 800-56C |
| AEAD seal/open with `header` as AAD | §2.4, §2.6(a) | NIST SP 800-38D (AES-256-GCM) |
| exact-length framing (`sealed_len` u32) | §2.4, §8.5 | project convention (anti-truncation) |
| `VRST` per-chunk counter+final nonce/AAD | §4.3, §4.4, §8.4 | SP 800-38D + project counter construction |
| `VRSK` key-bundle TLVs (roles 1–4) | §5, §5.1 | FIPS 203/204 key material, SHAKE-256 key-id |

The TLV primitive itself (2-byte big-endian length + value, bounds-checked) is `FORMAT.md` §1.

> **Combiner standards note (honest framing).** The hybrid combiner is **modeled on** NIST SP 800-56C
> — it borrows the length-framing of the input keying material and the FixedInfo-transcript shape of a
> two-step KDF — but it is a **project construction**, **not** a validated or conformant SP 800-56C
> instantiation, and no SP 800-56C conformance is claimed. Rows above that name SP 800-56C mean
> "structurally analogous to," not "governed by."

## How an independent implementer consumes `pstv_vectors.json`

The committed JSON is the **single authority**. Encryption uses fresh randomness, so re-running
`gen_pstv_vectors.py` mints a *different* corpus — the tests therefore read the committed file and
never call the generator.

Structure:

```jsonc
{
  "meta":   { "frozen": true, "suite_ids": {...}, "field_encoding": "...", ... },
  "vectors": [ { "id": "...", "kind": "...", ... }, ... ]
}
```

- **Encoding.** Every binary field is **UPPERCASE hex**; hex comparison is case-insensitive.
- **Positive vectors** (`kind` = `single_shot_anonymous` | `single_shot_authenticated` | `stream`)
  carry `recipient_public`, `recipient_private`, the full `envelope`, and `expected_plaintext`
  (authenticated vectors also carry `sender_public`). To validate your implementation: parse
  `recipient_private` as a `VRSK` role-2 bundle, decode `envelope`, and assert your plaintext
  equals `expected_plaintext`. For authenticated vectors, verify the embedded ML-DSA signature
  over `pre_auth ‖ sender_kid` (context `VORLATH-Shield/auth/v2`) **before** decapsulation.
- **Negative vectors** (`kind` = `negative`) carry a mutated `envelope`, the `recipient_private`
  needed to attempt decode, a `tamper`/`reason` describing the mutation, and three fields that make
  the rejection *evidentiary* rather than "rejected somehow":
  - `open_as` — which decode path to drive: `anonymous` (decrypt/open_envelope, no pin),
    `authenticated` (pinned to `expected_sender_public`, also carried), or `stream` (open_stream);
  - `expected_error` — the **category** the rejection must fall in (see the taxonomy below);
  - `expected_layer` — `crypto` (the rejection MUST come from the AEAD or signature layer) or
    `structural` (a cheap parse / key-id / suite / pin cross-check). For `crypto` the category must
    be a crypto category (`aead`/`signature`) — a structural parse error does **not** satisfy a
    crypto negative.

  A conformant decoder **must reject** all of them, at the stated layer/category. The mutations per
  suite are:
  - *structural / framing* — `suite_id_mutated` (`suite_mismatch`), `truncated` (`truncation`,
    a header under-run mid-`sealed_len`), `wrong_recipient_key` (`wrong_recipient`),
    `trailing_bytes` (`trailing_data`, the off+clen==len upper bound — extra bytes appended),
    `malformed_inner_tlv` (`inner_tlv`, an inner TLV length over-claiming past the buffer end),
    `auth_flag_set_empty_block` (`truncation`, `FLAG_AUTHENTICATED` SET on an empty `sender_block`
    so the authenticated branch's first `_read_tlv` under-runs before any crypto);
  - *AEAD (crypto)* — `ciphertext_bitflip`, `tag_bitflip` (`aead`);
  - *authenticated-downgrade / fail-closed (crypto)* — `auth_flag_stripped`: clearing
    `FLAG_AUTHENTICATED` and opening anonymously derives a different key (flags is in AAD + KDF) and
    fails the GCM tag (`aead`);
  - *authenticated-path* — `sig_bitflip` (`signature`, crypto), `sig_misbinding` (`signature`,
    crypto — a genuine ML-DSA signature by the same signer over a *different* transcript, grafted
    in by transcript re-use, reaches `verify()` and returns `False`: the SIGMA / unknown-key-share
    property), `sender_kid_mismatch` and `sender_pub_swapped` (`sender_kid`, structural — caught at
    the pre-signature key-id cross-check, **before** `verify()`), `wrong_sender_pin` (`sender_pin`,
    structural);
  - *streaming (VRST), crypto* — `stream_chunk_bitflip`, `stream_final_dropped` (anti-truncation),
    `stream_chunk_reordered` (anti-reorder), `stream_middle_dropped` (anti-drop),
    `stream_chunk_duplicated` (anti-duplication), all `aead`;
  - *streaming (VRST), structural* — `stream_suite_mutated` (`suite_mismatch`),
    `stream_wrong_recipient` (`wrong_recipient`), `stream_header_truncated` (`truncation`) — the
    cheap `open_stream` cross-checks, caught before any decapsulation;
  - *downgrade-bit, crypto* — `flags_downgrade_crypto_binding`: an unused `flags` bit set on an
    anonymous envelope that passes **every** structural cross-check yet is caught **only** by the
    AAD/KDF binding (`aead`). (A *pure suite-byte* downgrade is not constructible as a
    crypto-binding-only bypass — the recipient-key suite/key-id cross-check catches it structurally
    first — so the binding is demonstrated via the `flags` downgrade bit instead; the tamper tag
    names `flags`, not `suite`, accordingly.)

  **Taxonomy** (`meta.taxonomy`): `aead`, `signature` (the two **crypto** categories), plus
  `sender_kid`, `sender_pin`, `wrong_recipient`, `suite_mismatch`, `framing`, `truncation`,
  `inner_tlv`, `trailing_data` (structural).

A minimal consumer in any language: implement the TLV reader (§1), the per-suite size table (§6),
the SP 800-56C-shaped combiner + HKDF `info`/`salt` (§2.6), and AES-256-GCM open with the full
header as AAD (§2.4). `altcodec.py` is a worked reference for exactly this, in ~300 lines.

## Coverage matrix

The **Mechanism** column states the check that actually fires, so no vector is advertised as
exercising a property it does not. In particular the SIGMA / unknown-key-share property is exercised
**only** by `sig_misbinding` (a genuine ML-DSA `verify()` returning `False` on a re-used transcript);
`sender_kid_mismatch` / `sender_pub_swapped` are caught earlier, by the **pre-signature key-id
cross-check** (`sender_kid == claimed_kid`), and never reach `verify()`.

| Case | Layer | Mechanism (what actually fires) | Suite 0x01 | Suite 0x02 |
|---|---|---|---|---|
| Anonymous single-shot | — | hybrid open | ✓ | ✓ |
| Authenticated single-shot (ML-DSA) | — | hybrid open + sig verify | ✓ | ✓ |
| Streaming (`seal_stream`/`open_stream`) | — | counter+final stream open | ✓ | ✓ |
| Negative — ciphertext bit-flip | crypto (`aead`) | AES-256-GCM tag | ✓ | ✓ |
| Negative — AEAD tag bit-flip | crypto (`aead`) | AES-256-GCM tag | ✓ | ✓ |
| Negative — authenticated-flag stripped (fail-closed) | crypto (`aead`) | flags in AAD+KDF → wrong key → tag | ✓ | ✓ |
| Negative — `flags` downgrade-bit crypto binding | crypto (`aead`) | flags in AAD+KDF → wrong key → tag | ✓ | ✓ |
| Negative — sender signature bit-flip | crypto (`signature`) | ML-DSA `verify()` → False | ✓ | ✓ |
| Negative — sender signature misbinding (SIGMA / UKS) | crypto (`signature`) | genuine sig over wrong transcript → `verify()` → False | ✓ | ✓ |
| Negative — sender key-id mismatch | structural (`sender_kid`) | pre-signature key-id cross-check (before `verify()`) | ✓ | ✓ |
| Negative — sender public swapped | structural (`sender_kid`) | pre-signature key-id cross-check (before `verify()`) | ✓ | ✓ |
| Negative — wrong sender pin | structural (`sender_pin`) | `expected_sender_public` pin | ✓ | ✓ |
| Negative — mutated `suite_id` | structural (`suite_mismatch`) | recipient-key suite cross-check | ✓ | ✓ |
| Negative — truncated envelope (mid-`sealed_len`) | structural (`truncation`) | header framing under-run | ✓ | ✓ |
| Negative — trailing bytes appended | structural (`trailing_data`) | exact-length `off+clen==len` bound | ✓ | ✓ |
| Negative — malformed inner TLV (over-claims) | structural (`inner_tlv`) | `_read_tlv` value-past-end bound | ✓ | ✓ |
| Negative — auth flag set on empty sender_block | structural (`truncation`) | authenticated branch `_read_tlv` under-run | ✓ | ✓ |
| Negative — wrong recipient key | structural (`wrong_recipient`) | recipient key-id cross-check | ✓ | ✓ |
| Negative — stream chunk bit-flip | crypto (`aead`) | per-chunk AES-256-GCM tag | ✓ | ✓ |
| Negative — stream final chunk dropped (anti-truncation) | crypto (`aead`) | final-flag in nonce+AAD | ✓ | ✓ |
| Negative — stream chunks reordered (anti-reorder) | crypto (`aead`) | counter in nonce+AAD | ✓ | ✓ |
| Negative — stream middle chunk dropped (anti-drop) | crypto (`aead`) | shifted counters → tag | ✓ | ✓ |
| Negative — stream chunk duplicated (anti-duplication) | crypto (`aead`) | shifted counters → tag | ✓ | ✓ |
| Negative — stream mutated `suite_id` | structural (`suite_mismatch`) | `open_stream` suite cross-check | ✓ | ✓ |
| Negative — stream wrong recipient key | structural (`wrong_recipient`) | `open_stream` key-id cross-check | ✓ | ✓ |
| Negative — stream header truncated (mid-`chunk_size`) | structural (`truncation`) | `open_stream` header under-run | ✓ | ✓ |

## What this corpus does and does **not** prove

**Proves:** that `FORMAT.md` is precise enough for a **second, separately-coded** implementation
(which shares the same primitive libraries) to (a) parse the `VRSH`/`VRST`
byte layout with correct bounds checks, (b) recompute the length-framed combiner (modeled on
SP 800-56C) and the HKDF transcript identically, (c) verify the ML-DSA sender signature with the right context and
identity binding (including the SIGMA / transcript-binding property, exercised by `sig_misbinding`
reaching `verify()` → `False`), and (d) AES-256-GCM-open with the envelope header as AAD — agreeing
byte-for-byte with the reference, and rejecting tampered inputs in lock-step. As noted in *Honest
framing*, this independence is at the **FORMAT / parse / combiner / KDF / AEAD-orchestration** layer
over **shared primitive libraries** and a **single spec author** — it is not a primitive-level
cross-validation and cannot catch a spec misreading shared by both implementations.

**Does not prove:** FIPS 140-3 validation, ACVP conformance of the underlying primitives (that is a
separate effort — see `test_acvp.py`), constant-time / side-channel resistance, or replay/freshness
(authenticated mode proves sender identity + integrity, not freshness; see `FORMAT.md` §8.6).

**Out of scope for this VRSH/VRST corpus (tested elsewhere):**
- **PLHA / PLDU high-assurance** — the SLH-DSA (FIPS 205) high-assurance key bundle and the
  ML-DSA + SLH-DSA **dual signature** (`FORMAT.md` §6) are **not** exercised here; they are covered
  by `test_highassurance.py`. Likewise full **cross-suite key-confusion** (e.g. presenting a suite
  0x01 key against a 0x02 envelope beyond the single `suite_id` byte-mutation negative) is not part
  of this corpus.
- **Whole-envelope replay / freshness** — the streaming counter+final binding defeats reorder, drop,
  truncation, and duplication of chunks *within* a stream, but **whole-envelope replay** (re-sending
  a previously captured, still-valid envelope) is an **application-layer freshness** concern, not a
  format property. Callers needing it must add a nonce/transcript dedup or an in-plaintext
  challenge/timestamp (mirrors `FORMAT.md` §8.6).

## Regenerating the corpus (rarely)

```
cd tech
python interop/gen_pstv_vectors.py     # MINTS A NEW frozen corpus (different bytes!)
python -m pytest interop/test_pstv.py  # cross-validate reference vs altcodec
```

Regenerate only when the wire format intentionally changes; then commit the new
`pstv_vectors.json` as the new authority.
