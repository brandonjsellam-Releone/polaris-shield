# VORLATH Shield - verification gap map (the case against our own claims)

Every other document here argues *for* the design. This one argues *against* it. It is the
hostile review a world-class cryptographer would write, published by us, first - because a
verified **design** is not a verified **deployment**, and the fastest way to earn trust is to
name the seams before a reviewer does.

> Read this with [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md) (what each tool proves),
> [`SECURITY.md`](SECURITY.md) (what the Shield is not), and [`REPRODUCE.md`](REPRODUCE.md)
> (how to re-run all of it). Nothing below is hidden elsewhere; this page collects every
> abstraction gap in one place and ranks them.

## Independent adversarial review (2026-06-21)

Two independent passes were run against v2.1.0 and are recorded here in full, **including what they got
wrong** — because a review you can't see the misses of isn't evidence.

- A **6-lens adversarial agent workflow** (combiner injectivity, suite-0x03 downgrade, RFC 8784 PPK,
  sender_kid binding, implementation bugs, formal-model faithfulness); each material finding was
  re-checked against the actual code by independent skeptics.
- A **7-model cryptographer council** (Grok, DeepSeek, Hermes, Gemini, Mistral, watsonx, Perplexity),
  each asked independently where they would attack first.

**Result: no cryptographic break, from either pass.** Findings that did NOT survive verification:

- *"`info` (HKDF FixedInfo) is not self-injective — a byte can cross the unframed `pre_auth‖sender_kid`
  boundary."* **Refuted by the code:** every `pre_auth` field is fixed-length (`suite_id`/`flags` 1 B,
  `recipient_key_id` 32 B, `eph_pub`/`kem_ct` fixed *per suite*, `nonce` 12 B) and `sender_kid` is
  0 B / 32 B pinned by `FLAG_AUTHENTICATED`. With every length pinned by the self-describing
  `suite_id`+`flags`, no byte can move across any boundary — `info` *is* injective on its own; the AEAD
  AAD is a second layer, not the only one.
- *"Downgrade / signature-bypass via decapsulate-first"* (two council members): built on a misreading —
  the protocol **verifies the signature BEFORE decapsulation** (SIGMA), `suite_id` is in the **signed**
  `pre_auth`, and the recipient key **pins** the suite, so those vectors can't be constructed.
- *Precision probes* ("0x01 isn't CNSA 2.0"; "HKDF is the two-step KDF, not one-step") were **already
  correct in the docs** (0x01 is labelled "FIPS-standard"; `SECURITY_ARGUMENT.md` already states "the
  two-step extract-then-expand KDF of NIST SP 800-56C").

**The one finding that DID survive — and is now closed.** The verified `sender_kid` is channel-bound
into the HKDF `info` in code, but the symbolic models had bound it in the *signature only*. That
model-vs-code coverage gap was closed by lifting `sender_kid` into the KDF transcript in **all four**
lineages and re-proving (FORMAL_COVERAGE goal 10; Tamarin 11/11, ProVerif all-queries, both Verifpal
models *All pass*, CryptoVerif *All proved* — verified in Docker).

Confirmed sound by the review: combiner IKM injectivity incl. the zero-length classical leg of 0x03 and
PPK present/absent framing; suite pinned-by-key with `suite_id` bound in three places; classical-leg
strip fails closed; PPK `FLAG_PPK` bound in all transcripts and backward-compatible byte-identical;
verify-before-decapsulate; UKS / KCI resistance; expected-sender pinning; replay honestly scoped out.

**PPK leg — now machine-proved (all four lineages, 2026-06-21).** The RFC 8784 PPK leg was the last "argued, not
proved" combiner leg. `formal/shield_ppk.spthy` (the with-PPK configuration) now carries
`secrecy_under_both_kem_legs_break` — *both KEM legs broken, PPK intact => confidentiality* — verified
verified across ALL FOUR lineages (CI-gated): Tamarin (`shield_ppk.spthy`, 12/12 lemmas) + ProVerif (`shield_ppk.pv`, `attacker(secret_m) ==> RevPPK` true) UNBOUNDED; Verifpal (`shield_ppk.vp`, both KEM legs leaked, *All pass*); CryptoVerif (`shield_ppk_combiner.cv`, *secrecy of Kp up to 2*qH/|ppk|*, computational), alongside the hybrid/auth/downgrade/KCI properties
re-proved in the with-PPK config. The PPK leg is now proved in EVERY lineage — matching `sender_kid` and the two KEM legs.

## The core distinction

- The **proofs** (Verifpal, Tamarin, ProVerif, CryptoVerif - four independent machine-checked
  lineages) reason about **models**.
- The **tests** (497-suite, ACVP, interop, **cross-impl differential**, dudect) exercise the **code**.
- The bridge between a model and the code is **human-authored faithfulness** - the models were
  written to mirror `vorlath_shield/shield.py` and `FORMAT.md`. **No prover runs the actual
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
   - **(b) Composition - now mechanized on BOTH legs (CryptoVerif).** The step "component leg secure
     => the transcript-bound combined hybrid KEM is IND-CCA" is mechanized on EACH side, CI-gated:
     `formal/shield_combiner_indcca.cv` reduces to **ML-KEM IND-CCA** (bound carries `Adv_PQ_CCA`),
     and `formal/shield_combiner_dh.cv` reduces to the classical leg's **Gap-DH** hardness on
     X25519/X448 (bound `4*PDistRerandom + 2*Adv_GDH` - the GDH flavour CryptoVerif's bundled
     HPKE/DHKEM analysis uses). Each gate asserts its advantage term is actually invoked (not collapsed
     to an abstraction). Together they give one-leg-break resistance reduced, on each side, to the
     surviving leg's assumption - so the **classical leg is no longer merely abstracted**. Residual
     (assumed/abstracted, not re-proven): ML-KEM IND-CCA and Gap-DH **themselves**, ML-KEM's small
     decryption error / implicit rejection (X-Wing's delta_correctness term), curve point-validation /
     small-subgroup handling, and HKDF-as-ROM.
   - **(c) No model-to-bytes link.** No prover runs the actual TLV parser/combiner; faithfulness is
     human-authored.
   - **(d) Side channels beyond timing** are unmodelled and unhardened.
   - **(e) Not FIPS 140-3 validated** - this is a reference implementation, not a certified module.

## How to falsify us

This page is only credible if you can act on it. Each weak seam has a falsification path:

- **(a)** run a differential harness: same seeds/coins/messages through `kyber-py`/`dilithium-py`
  **and** a second library; any disagreement is a finding. **Implemented:** `interop/cross_impl.py`
  vs `pqcrypto` (PQClean/C); `docker build -f interop/diff.Dockerfile -t vorlath-shield-diff interop`
  runs it as the build gate. See [`interop/CROSS_IMPL.md`](interop/CROSS_IMPL.md).
- **(b)** re-run both composition models (CryptoVerif, `-in oracles`): `formal/shield_combiner_indcca.cv`
  must emit "All queries proved" with the `Adv_PQ_CCA` term, and `formal/shield_combiner_dh.cv` with the
  `Adv_GDH` term. Attack the residual: the assumptions themselves (ML-KEM IND-CCA / Gap-DH), the
  perfect-correctness assumption (no decryption error), curve point-validation, or HKDF-as-ROM. The
  prior hand-written reduction is in `SECURITY_ARGUMENT.md` section 3 / `COMBINER_CRYPTOVERIF.md`.
- **(c)** diff `shield.spthy` / `shield.pv` against `vorlath_shield/shield.py` and `FORMAT.md`; any
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
