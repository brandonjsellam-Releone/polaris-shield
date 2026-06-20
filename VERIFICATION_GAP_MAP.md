# POLARIS Shield - verification gap map (the case against our own claims)

Every other document here argues *for* the design. This one argues *against* it. It is the
hostile review a world-class cryptographer would write, published by us, first - because a
verified **design** is not a verified **deployment**, and the fastest way to earn trust is to
name the seams before a reviewer does.

> Read this with [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md) (what each tool proves),
> [`SECURITY.md`](SECURITY.md) (what the Shield is not), and [`REPRODUCE.md`](REPRODUCE.md)
> (how to re-run all of it). Nothing below is hidden elsewhere; this page collects every
> abstraction gap in one place and ranks them.

## The core distinction

- The **proofs** (Verifpal, Tamarin, ProVerif, CryptoVerif - four independent machine-checked
  lineages) reason about **models**.
- The **tests** (497-suite, ACVP, interop, **cross-impl differential**, dudect) exercise the **code**.
- The bridge between a model and the code is **human-authored faithfulness** - the models were
  written to mirror `polaris_shield/shield.py` and `FORMAT.md`. **No prover runs the actual
  Python.** A divergence ("the model says X, the code does Y") is not automatically caught. That
  is the single most important thing to understand before trusting any green checkmark here.

## Gap-by-gap (what each artifact abstracts, and what closes it)

| Artifact | What it idealizes / does NOT cover | What (partially) closes it | Residual risk |
|---|---|---|---|
| **Symbolic proofs** (Verifpal bounded; Tamarin + ProVerif unbounded, **both verified**) | HKDF/AEAD/hash are perfect; ML-KEM is an ideal IND-CCA KEM (`PKE_ENC`), ML-DSA an ideal EUF-CMA signature; the **wire bytes / TLV parser are not executed**; agreement is **non-injective** (replay out of scope by design) | each other (3-4 independent engines agree) + the interop/ACVP tests for the byte layer | a flaw in a primitive *assumption*, or a parser bug, is invisible to these |
| **Tamarin scope** (`shield.spthy`) | authenticated mode only; **anonymous-mode flag-stripping** and **forward-secrecy / ephemeral-state reveal** are **not** lifted into unbounded lemmas (formal/README scopes them out) | carried by the Verifpal models + the implementation/interop tests | "argued, not proved (unbounded)" for FS + anonymous mode |
| **CryptoVerif** (`shield_combiner.cv`) | proves the **combiner** is key-indistinguishable under single-leg compromise; HKDF modelled as a random-oracle / PRF (`ROM_hash_3`), **not concretely as HMAC-SHA384**; `ss_c`/`ss_pq` are abstract secrets; does **not** prove ML-KEM IND-CCA itself, strong-DH, or the full end-to-end protocol | the symbolic proofs (protocol logic) + the assumed primitive standards + the **composition is now mechanized** (`shield_combiner_indcca.cv`) | the step "component ML-KEM IND-CCA => combined hybrid KEM IND-CCA" **is now mechanized** in CryptoVerif (genuine IND-CCA2 KEM macro + decap oracle; bound carries `Adv_PQ_CCA`); ML-KEM IND-CCA itself, its decryption-error, strong-DH, and HKDF-as-ROM remain assumed/abstracted |
| **ACVP conformance** | validates the **primitives** (ML-KEM keyGen/encaps/decaps incl. implicit-rejection + ek/dk checks; ML-DSA keyGen/sigGen/sigVer; SLH-DSA sigVer) against NIST vectors | the gold standard for primitive correctness | does **not** validate the combiner, the protocol, the TLV format, or constant-time; ML-DSA has no NIST key-check vectors; SLH-DSA keyGen/sigGen are KAT/round-trip only; **ACVP conformance is not a FIPS 140-3 validated module** |
| **Interop corpus** (`interop/altcodec.py`) | an **independent re-implementation of the parse / combiner / KDF-transcript / AEAD logic** - but it **shares the same primitive libraries** (`kyber-py`, `dilithium-py`, `cryptography`) | cross-validates the **wire/format/combiner logic** (a spec misread in one impl is caught) | a bug **inside `kyber-py`/`dilithium-py` would be present in BOTH** here - **now cross-validated on random inputs** against an independent PQClean/C lineage (`pqcrypto`) by [`interop/cross_impl.py`](interop/CROSS_IMPL.md); residual: a flaw **shared** by both impls (spec ambiguity) or side channels |
| **Reproducible build + signed bundle** | content-addressed, cosign-signed, SLSA provenance | `REPRODUCE.md` + `release/` let a stranger re-derive the digest | the signed manifest is **rewindable** - a key holder can re-sign a different tree with no external witness; reproducibility is asserted via the hermetic image, not bit-for-bit across two machines |
| **Constant-time** (`dudect`) | **timing only**, honestly measured (ML-DSA signing leaks, \|t\|~575) | the measurement itself is the evidence | **no power / EM / fault / cache** coverage; the pure-Python legs are not side-channel hardened; any local / co-resident / physical adversary is **out of scope** |

## Soundness ledger (what to believe, in order)

1. **Highest confidence - the primitives conform to NIST.** Multiple ML-KEM/ML-DSA operations pass
   the official ACVP vectors, including the IND-CCA implicit-rejection branch and the ek/dk checks.
2. **High - the protocol logic is sound** against an unbounded Dolev-Yao attacker: THREE independent
   symbolic engines (Verifpal bounded; Tamarin and ProVerif unbounded) agree on hybrid secrecy under
   single-leg compromise, sender authentication, and downgrade resistance; CryptoVerif adds a
   *computational* key-indistinguishability result for the combiner.
3. **Medium - the wire format is unambiguous:** a second, independently written codec reproduces
   every positive byte-for-byte and rejects every negative at its expected layer - **but on shared
   primitive libraries.**
4. **The weakest seams (attack us here first):**
   - **(a) Single primitive lineage - largely closed.** `interop/cross_impl.py` now differentially
     cross-validates the primitives against an independent **PQClean/C** implementation (`pqcrypto`)
     on **random** inputs - ML-KEM both-directions shared-secret equality and ML-DSA mutual
     accept/tamper-reject, all four parameter sets, verified live (see
     [`interop/CROSS_IMPL.md`](interop/CROSS_IMPL.md)). Residual: a flaw **shared** by both
     implementations (a spec ambiguity read the same way) or any side channel is still invisible.
   - **(b) Composition - now mechanized (CryptoVerif).** The step "component ML-KEM IND-CCA =>
     the transcript-bound combined hybrid KEM is IND-CCA" is mechanized in
     `formal/shield_combiner_indcca.cv` (CI-gated): a genuine IND-CCA2 ML-KEM macro with an
     encapsulation + decapsulation oracle; CryptoVerif proves the combined-KEM session key is
     real-or-random with bound `2*qH/|ss_c_t| + 2*Adv_PQ_CCA` - the `Adv_PQ_CCA` term confirms the
     ML-KEM IND-CCA assumption is actually invoked, and transcript binding is the load-bearing
     separation. Residual (assumed/abstracted, not re-proven): ML-KEM IND-CCA itself, its small
     decryption error / implicit rejection (X-Wing's delta_correctness term), the classical leg's
     strong-DH, and HKDF-as-ROM.
   - **(c) No model-to-bytes link.** No prover runs the actual TLV parser/combiner; faithfulness is
     human-authored.
   - **(d) Side channels beyond timing** are unmodelled and unhardened.
   - **(e) Not FIPS 140-3 validated** - this is a reference implementation, not a certified module.

## How to falsify us

This page is only credible if you can act on it. Each weak seam has a falsification path:

- **(a)** run a differential harness: same seeds/coins/messages through `kyber-py`/`dilithium-py`
  **and** a second library; any disagreement is a finding. **Implemented:** `interop/cross_impl.py`
  vs `pqcrypto` (PQClean/C); `docker build -f interop/diff.Dockerfile -t polaris-shield-diff interop`
  runs it as the build gate. See [`interop/CROSS_IMPL.md`](interop/CROSS_IMPL.md).
- **(b)** re-run `formal/shield_combiner_indcca.cv` (CryptoVerif, `-in oracles`); it must emit
  "All queries proved" with the `Adv_PQ_CCA` term. Attack the residual: the abstracted classical
  leg, the perfect-correctness assumption (no decryption error), or HKDF-as-ROM. The prior
  hand-written reduction is in `SECURITY_ARGUMENT.md` section 3 / `COMBINER_CRYPTOVERIF.md`.
- **(c)** diff `shield.spthy` / `shield.pv` against `polaris_shield/shield.py` and `FORMAT.md`; any
  field the model omits or reorders is a divergence.
- **(d)** extend `sidechannel/ct_measure.py` to a new leakage class.
- general: `REPRODUCE.md` re-runs every green check on your own machine. If any does not reproduce,
  that is the most valuable finding of all - report it per `SECURITY-DISCLOSURE.md`.

## Council-recommended hardening (2026-06-20; non-breaking; not yet implemented)

A multi-model adversarial review (two rounds; **7 of 8 apex models reached**) found **no new breaking
flaw**: every higher-severity flag collapsed when checked against the code - e.g. a flagged GCM nonce-reuse
does not apply (each message derives a fresh key from a fresh ephemeral DH **and** a fresh ML-KEM
encapsulation, with the AEAD nonce sampled per call). **One confirmed medium finding was FIXED** (not
merely recorded): the verified sender key-id is now **channel-bound into the HKDF FixedInfo** in
authenticated mode (Gemini; see `FORMAT.md` 2.6(b)), so the key-derivation transcript and the signed
transcript can no longer diverge on sender identity - the derived AEAD key, not only the ML-DSA signature,
witnesses the sender. Two further non-breaking hardening ideas remain honest future work (each changes the
combiner and would require re-running the four proof lineages):

- **Explicit key-confirmation.** Add a key-confirmation tag over the derived session key so the recipient
  proves key possession before use - fully closing residual KCI rather than leaning on the transcript /
  AEAD binding. A protocol addition (new wire field + re-proof).
- **Dual-PRF public-key binding.** Fold both KEM public keys directly into the combiner IKM (X-Wing /
  split-PRF style) so the derived key binds the public keys independently of the `recipient_key_id` / AAD
  transcript binding, for defense-in-depth. A combiner-IKM change (re-proof + new vectors).

These are improvements, **not** fixes: the current binding (`recipient_key_id` = H(public keys) carried in
the transcript as HKDF `info`, plus the full header as AEAD AAD) was judged sound. They are listed so a
reviewer sees the strongest available hardening, not because anything is broken.

*This document is maintained as an honest liability. When a gap is closed (e.g. a second primitive
lineage lands), its row moves from "residual risk" to "closed", with the closing artifact named -
never silently deleted.*
