# Security policy & honest assurance posture — POLARIS Shield

POLARIS Shield is a **reference implementation** of a post-quantum hybrid cryptosystem. It is
built to be *correct and standards-faithful*, and it is deliberately honest about what it is
**not**. Read this before using it for anything that matters.

## What it is

- A hybrid (classical + post-quantum) KEM-seal and signature library on the **finalized NIST
  standards** FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), with a self-describing, downgrade-resistant
  wire format and an SP 800-56C-shaped key-derivation combiner.
- The default suite (0x02) uses the **CNSA 2.0 algorithm set**: ML-KEM-1024 + ML-DSA-87 +
  AES-256 + SHA-384, hybridised with X448.
- A construction whose **handshake security goals are machine-checked**: a symbolic (Dolev-Yao)
  model in [`formal/`](formal/) proves, across **two independent tool lineages — Verifpal (bounded)
  and Tamarin (unbounded), both re-run in CI** — confidentiality (surviving a CRQC that breaks
  *either single* leg), sender authenticity, transcript binding and downgrade resistance — and
  reproduces the replay non-property as a verified non-result. Symbolic, under idealized primitives;
  see [`formal/README.md`](formal/README.md).

## What it is NOT — do not deploy without addressing these

1. **Not a FIPS 140-3 (CAVP/CMVP) validated module.** It depends on `kyber-py` and `dilithium-py`,
   clean pure-Python implementations that *track* FIPS 203/204 but are not validated cryptographic
   modules. CNSA 2.0 compliance requires a **validated** module — "CNSA 2.0" here denotes the
   **algorithm set**, never a certification claim.
2. **Not side-channel / constant-time hardened.** The pure-Python PQ legs are not protected against
   timing, cache, power, or fault attacks. Treat any adversary with local/co-resident/physical
   observation as **out of scope**. This is *measured*, not just asserted: a dudect-style leakage
   harness quantifies it — see [`CONSTANT_TIME.md`](CONSTANT_TIME.md) (ML-DSA signing shows a large
   data-dependent timing signal; measuring does not fix it).
3. **Not a standardized interoperable protocol.** The envelope is a project convention. For
   interoperable traffic use TLS 1.3 hybrid key-exchange (e.g. `X25519MLKEM768`), HPKE, or a
   validated library.
4. **ACVP-validated primitives ≠ a validated module.** ML-KEM *keyGen, encapsulation and decapsulation*
   — the latter **including the FO-transform implicit-rejection branch** (a modified ciphertext yields the
   deterministic secret K = J(z‖c), the IND-CCA core) **and the FIPS 203 encapsulation-/decapsulation-key
   checks** (malformed ek/dk are rejected) — and ML-DSA *keyGen, sigGen and sigVer* (deterministic —
   external and internal interfaces), plus SLH-DSA *sigVer* (FIPS 205), are validated against official NIST
   ACVP vectors (`test_acvp.py`, `test_acvp_slhdsa.py`). What is **not** ACVP-covered: **ML-DSA has no
   key-check** — NIST publishes no ML-DSA keyCheck vector set and `dilithium-py` exposes no key validation,
   so it is intentionally absent rather than faked; and **SLH-DSA keyGen and sigGen** remain
   round-trip/KAT-only (`slhdsa==0.2.3` has no seed-based keyGen and signing is too slow to vendor a set).
   Algorithm correctness is necessary but not sufficient — it is still a reference implementation, not a
   FIPS-validated cryptographic module.

## Path to production

- Adopt a FIPS-validated module: a validated build of AWS-LC / BoringSSL, OpenSSL 3.5+, or
  liboqs in a validated configuration.
- Extend ACVP coverage to **SLH-DSA keyGen / sigGen** (the only NIST-published primitive vector sets the
  Shield does not yet exercise). ML-KEM keyGen / encaps / decaps — including implicit-rejection and the
  encapsulation-/decapsulation-key checks — and ML-DSA keyGen / sigGen / sigVer plus SLH-DSA sigVer are
  already validated against the official NIST vectors. (ML-DSA has no key-check vector set to extend to.)
- Commission an independent side-channel + protocol review.
- Use standardized hybrid transports (TLS 1.3 hybrid groups, HPKE) for interoperability.

## Design notes

- **At-rest private-key protection is passphrase-based, by design** — a KEK is derived with
  **scrypt** (n=2¹⁷) from the user passphrase and the bundle is sealed with **AES-256-GCM**. This is
  passphrase wrapping (the standard pattern for protecting a key with a human secret), **not** NIST
  AES-KW (SP 800-38F); AES-KW wraps a key with another *key*, which is a different use case. For
  machine-to-machine key wrapping, use a validated AES-KW / KMS instead.

## Cryptographic design review

The v2 construction was independently reviewed by three model lineages (Gemini, Mistral, Grok).
Findings that were fixed: suite-0x01 mislabeling, key-id width (now 256-bit), and explicit
sender-identity binding in the signed transcript (SIGMA-style). See `THREAT_MODEL.md` for the
properties and assumptions.

## Reporting

This is a component of the **speculative** BOREALIS / POLARIS concept (a strategic exercise, not a
funded venture) and is **not** affiliated with the separate TRELYAN project. If you find a defect
in the construction, open an issue describing the property violated and a reproducing case. Do not
report cryptanalysis intended for operational misuse. The full coordinated-disclosure policy
(scope, contacts, 90-day window, safe harbour) is in [`SECURITY-DISCLOSURE.md`](SECURITY-DISCLOSURE.md)
and published at `/.well-known/security.txt`.

## Reproduce & verify

Don't take this posture on faith — re-derive it: [`REPRODUCE.md`](REPRODUCE.md) re-runs the
480 tests, all three machine-checked proofs, and the constant-time measurement from a clean
checkout, and [`release/`](release/) lets you confirm (via a cosign-signed, content-addressed
manifest) that the bytes you re-run are the exact bytes that were signed. The mechanized-vs-argued
map is [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md).
