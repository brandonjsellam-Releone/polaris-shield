# VORLATH Shield — audit-readiness package

A self-administered onramp for an external **cryptographic design review** and a **NIST CAVP**
engagement (paid, or grant-funded — see [`../GRANTS.md`](../GRANTS.md)). The point is to make a paid
review *cheap and fast*: an auditor should not have to bill hours discovering the attack surface,
the evidence, or how to reproduce it — it is all here, and we name our own weak seams first.

This package is **honest about maturity**: VORLATH Shield is a real, runnable **reference
implementation** in pure Python. It is **NOT** FIPS 140-3 / CAVP validated and **NOT** side-channel
hardened. Nothing here claims government endorsement.

## 1. Scope for a reviewer

**In scope (the novel, project-authored design — this is what is worth a cryptographer's time):**
- The **SP 800-56C-shaped combiner** (`_derive_key`): length-framed `ss_classical || ss_pq [|| ppk]`,
  HKDF with a domain-separation label, suite byte, and full transcript as FixedInfo.
- The **self-describing TLV envelope / parser** (`FORMAT.md`): bounds-checked decode, header-as-AAD.
- The **authenticated handshake** (SIGMA-style own-identity binding: `sign(pre_auth || sender_kid)`),
  verified before decapsulation, with optional expected-sender pinning.
- The **suites**: `0x01` FIPS, `0x02` CNSA-2.0 hybrid, `0x03` CNSA-2.0 **pure-PQC**, and the optional
  **RFC 8784 PPK** third combiner leg (`FLAG_PPK`).
- **Downgrade resistance** (suite_id/flags bound in AAD and KDF transcript), **key management**
  (self-describing key bundles, SHAKE-256 key-ids, scrypt at-rest wrap), and the **streaming AEAD**
  (per-chunk nonce binding a counter + final-flag).

**Out of scope:** the speculative VORLATH citadel concept (not code); the underlying NIST-primitive
libraries beyond the cross-implementation differential below; anything claiming a deployed system.

## 2. Evidence already in place (start from here, not from zero)

| Evidence | Artifact | What it gives a reviewer |
|---|---|---|
| **4 formal lineages** | `formal/` (Verifpal, Tamarin, ProVerif, CryptoVerif), CI-gated | secrecy under single-leg break, sender-auth, downgrade, KCI — over unbounded sessions |
| **2nd primitive lineage** | `interop/cross_impl.py` vs PQClean/C (`pqcrypto`) | ML-KEM/ML-DSA cross-validated on random inputs, verified live |
| **Conformance** | `test_acvp.py` (NIST ACVP vectors) | ML-KEM/ML-DSA/SLH-DSA primitive correctness vs NIST |
| **502-test suite** | `pytest` (functional + KAT + property/fuzz + interop) | the code path actually exercised |
| **Reproducibility** | `REPRODUCE.md` + cosign-signed `release/RELEASE_MANIFEST.json` | re-derive every green check from a clean checkout |
| **Inventory** | CycloneDX `sbom/` + `cbom/` | dependency + crypto bill of materials |
| **Self-audit** | `VERIFICATION_GAP_MAP.md` | we already ranked our own remaining seams |
| **Crypto frontier** | `BINDING.md` (X-BIND / RFC 9935) | KEM-binding analysis + the transcript-binding repair |
| **Implementation code review** | adversarial multi-agent read of `shield.py` + the CLI / dual-sig / LMS-signing / release-bundle (2026-06-21) | the actual Python read for bugs (not just proved/tested) — found **sound**; 2 defense-in-depth fixes shipped (AEAD reject normalized to `ValueError`; canonical `sender_block` parse) |
| **Standards conformance** | `STANDARDS_ALIGNMENT.md` | crosswalk: the combiner **instantiates** `Concat-then-KDF` (CFRG `draft-irtf-cfrg-hybrid-kems-11`) / SP 800-56C §4.1 (NIST SP 800-227 final), with the draft's recommended pk/ct binding |

## 3. What we want a design review to cover (RFP-style scope)

A reviewer should target these specific questions:
1. **Combiner.** Is the length-framed HKDF input injective and the transcript binding complete? Does
   the pure-PQC suite (`0x03`, empty classical leg) preserve the security argument? Does the PPK leg
   compose cleanly (it only adds a framed secret behind a bound flag)?
2. **Parser / format.** Any TLV length-confusion, canonicalization, or AAD-coverage gap; is every
   security-relevant byte (suite_id, flags, all five TLVs, sender block) under the AEAD AAD?
3. **Handshake.** Is the SIGMA own-identity binding sufficient against UKS / key-compromise
   impersonation? Is the "verify signature before decapsulate" ordering correct and enforced?
4. **Downgrade.** Can any path negotiate a weaker suite than the recipient key pins?
5. **Key management.** Key-id binding, scrypt parameters, any key-reuse / role-confusion across bundles.
6. **Streaming.** Truncation / reorder / drop detection completeness.

## 4. Attack surface — where to push first

Already published, ranked, in [`VERIFICATION_GAP_MAP.md`](VERIFICATION_GAP_MAP.md). The honest order:
(a) primitive lineage — *largely closed* by `cross_impl.py`; (b) the hybrid-KEM IND-CCA composition —
*now mechanized on both legs* in CryptoVerif (`shield_combiner_indcca.cv` carries `Adv_PQ_CCA`,
`shield_combiner_dh.cv` carries `Adv_GDH`; FORMAL_COVERAGE goal 9); (c) the model-to-bytes link (provers
verify the model, not the Python) — *partially closed* by the 2026-06-21 adversarial implementation code
review of `shield.py` (found sound; 2 defense-in-depth fixes), with a code-extracted model the remaining
gold standard; (d) side channels beyond timing; (e) not FIPS 140-3 validated. A reviewer who breaks any of these has a real finding — report per
`SECURITY-DISCLOSURE.md`.

## 5. CAVP / ACVP self-test status (de-risks the lab engagement)

- **Today (free):** `test_acvp.py` runs the Shield's ML-KEM (keyGen/encaps/decaps incl. the
  implicit-rejection branch and ek/dk checks), ML-DSA (keyGen/sigGen/sigVer), and SLH-DSA (sigVer)
  against official **NIST ACVP** vectors. Gaps are disclosed (ML-DSA has no NIST keyCheck vectors;
  SLH-DSA keyGen/sigGen stay KAT/round-trip). The free **NIST ACVTS demo server** can extend this
  self-testing before any lab is engaged.
- **What a paid CAVP lab adds:** an accredited CST lab runs the full ACVP suite under attestation and
  submits for the public CAVP certificate. Our self-test report is the exact input that shortens that
  engagement. (CAVP validates *algorithms*; it is **not** FIPS 140-3 module validation.)

## 6. Side-channel self-assessment (honest, timing-only)

- **Today (free):** `sidechannel/ct_measure.py` (dudect-style) measures **timing** only. It honestly
  reports that pure-Python **ML-DSA signing leaks timing** (large `|t|`), consistent with an
  unhardened reference implementation; constant-time claims and measurements are in `CONSTANT_TIME.md`.
- **Not covered (needs money + a hardware target):** power / EM / fault / cache analysis. These require
  a hardened C/Rust target on real hardware and a specialized lab — **premature on pure Python**, where
  measurements would mostly reflect the interpreter. This is the six-figure tier, correctly deferred.

## 7. Reproduce everything

`REPRODUCE.md` re-derives the 502 tests + the proofs + the constant-time measurement from a clean
checkout. The cosign-signed `release/RELEASE_MANIFEST.json` pins the exact bytes under a single
content-addressed `bundle_digest`, so a reviewer can confirm they are auditing what was proved/tested.

## 8. Honest readiness statement

| Worth funding **now** | Defer until a hardened build exists |
|---|---|
| Cryptographic **design + protocol review** (the in-scope items above) | Physical side-channel (power/EM/fault) |
| **NIST CAVP** algorithm validation (self-test already most of the way) | **FIPS 140-3** module validation (no module boundary in pure Python) |

Spending on physical side-channel or FIPS 140-3 against the current pure-Python reference would mostly
measure Python, not the design. The high-value dollars (or grant) go to the **design review** and
**CAVP** first; the rest is a later phase gated on a productionized, hardened implementation.
