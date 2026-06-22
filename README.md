# VORLATH Shield v2 — post-quantum hybrid security (reference)

The **VORLATH Shield** is the real, runnable form of the VORLATH **L9 layer**
(a "post-quantum root of trust" in the **cryptographic** sense — the foundational software PQC
layer; **not** a hardware root of trust, and providing no TPM / secure-element / measured-boot
anchor). It is an **algorithm-agile** hybrid (classical +
post-quantum) cryptosystem on the finalized NIST standards, with a self-describing,
downgrade-resistant wire format — so data captured today cannot be opened by a future
cryptographically-relevant quantum computer ("harvest-now, decrypt-later").

> **Separate project note.** VORLATH Shield is a component of the (speculative) VORLATH /
> VORLATH concept. It is **not** affiliated with, and does not modify, the separate TRELYAN
> project. Any resemblance in subject matter (post-quantum cryptography) is coincidental to
> both working in the same standards space.

## Cryptographic suites

The **recipient's key selects the suite** — a sender (or attacker) cannot negotiate a weaker one.

| Suite | ECDH | KEM (FIPS 203) | Signature (FIPS 204) | KDF | AEAD |
|---|---|---|---|---|---|
| `0x01` FIPS-standard | X25519 | ML-KEM-768 | ML-DSA-65 | HKDF-SHA256 | AES-256-GCM |
| `0x02` **CNSA-2.0** (default) | X448 | **ML-KEM-1024** | **ML-DSA-87** | HKDF-SHA384 | AES-256-GCM |
| `0x03` **CNSA-2.0 pure-PQC** | _none_ | **ML-KEM-1024** | **ML-DSA-87** | HKDF-SHA384 | AES-256-GCM |

Suite `0x02` is the **CNSA 2.0 algorithm set** (Category 5). The AEAD key is derived from **both**
the ECDH secret **and** the ML-KEM secret, length-framed and bound to the full handshake transcript —
an attacker must break **both** legs to recover plaintext. Suite `0x03` is the **pure-PQC** form of
the same Cat-5 set (no classical leg) — the NSA-preferred NSS end-state
([CNSA_MIGRATION.md](CNSA_MIGRATION.md)); it drops hybrid defense-in-depth **by design**, so its
confidentiality rests solely on ML-KEM-1024 (the `secrecy_under_classical_break` case the four proof
lineages already establish). Hybrid `0x02` stays the default; `0x03` is opt-in.

## What's in v2

- **Self-describing, length-prefixed TLV envelope**, bounds-checked on decode, bound as AEAD AAD.
- **SP 800-56C-shaped combiner** (length-framed secrets, domain-separation label, transcript FixedInfo).
- **Authenticated handshake** (optional): ML-DSA over `pre_auth ‖ sender_key_id` (SIGMA-style identity
  binding), verified before decapsulation, with optional expected-sender pinning.
- **Downgrade resistance**: `suite_id`/`flags` bound in both AAD and KDF transcript.
- **Key management**: self-describing keys, 256-bit SHAKE-256 key-ids, scrypt(2¹⁷) at-rest wrap.
- **Streaming AEAD** (`seal_stream`/`open_stream`, CLI `--stream`): chunked large-file encryption whose per-chunk nonce binds a counter and a final-flag, so truncation, reorder, and dropped chunks are all detected — not just bit-flips.
- **High-assurance diversified signatures** (opt-in, `vorlath_shield.highassurance`): adds **SLH-DSA** (FIPS 205, stateless hash-based) alongside the lattice ML-DSA. In `dual_sign`/`dual_verify` mode a forgery requires breaking **both** a lattice and a hash-based scheme — for long-lived roots (evidence, firmware). Large (~29 KB) signatures, deliberately slow signing; not the default.
- **Deterministic KAT/conformance harness** (`test_kats.py` + `kat_vectors.json`).
- **Cross-implementation interoperability corpus** (`interop/`): a frozen set of portable golden vectors (`pstv_vectors.json`, both suites, anonymous/authenticated/streaming + 46 typed-error tamper negatives) plus a **separately-coded decoder** (`altcodec.py`) written only from [FORMAT.md](FORMAT.md) — sharing the primitive libraries but re-implementing the parse/combiner/KDF-transcript/AEAD logic independently. Every positive is reproduced byte-for-byte by **both** implementations; every negative is rejected at its **expected layer** (AEAD / signature / structural) by both. Proves the wire format is complete and unambiguous enough for a second implementation to interoperate. See [interop/INTEROP.md](interop/INTEROP.md).
- **Cross-implementation primitive differential** (`interop/cross_impl.py`): closes the one gap the interop corpus cannot (it shares the primitive libs) by cross-validating ML-KEM / ML-DSA against an **independent PQClean/C implementation** (`pqcrypto`) on **random** inputs — ML-KEM both-directions shared-secret equality and ML-DSA mutual accept/tamper-reject, all four parameter sets (verified live, 500/500). `make interop-diff` (the Docker build *is* the gate). See [interop/CROSS_IMPL.md](interop/CROSS_IMPL.md).

## Install

```bash
pip install -e tech/.[dev]      # or: pip install -r tech/requirements.txt
```

## Use

```bash
cd tech
python -m vorlath_shield demo                                     # live walkthrough (apex suite)
python -m vorlath_shield keygen  --prefix alice [--suite 2] [--passphrase pw]
python -m vorlath_shield encrypt --to alice.kem.pub --in secret.txt --out secret.trsh \
                                 [--sign-key bob.sig.key --sign-pub bob.sig.pub]   # authenticated
python -m vorlath_shield decrypt --key alice.kem.key --in secret.trsh --out out.txt \
                                 [--expect-sender bob.sig.pub] [--passphrase pw]
python -m vorlath_shield sign    --key alice.sig.key --in doc.pdf --out doc.sig
python -m vorlath_shield verify  --pub alice.sig.pub --in doc.pdf --sig doc.sig
python -m vorlath_shield info    --in secret.trsh                 # inspect suite / auth / size
python -m pytest -q                                              # 508 tests (functional + KAT + ACVP + property/fuzz + high-assurance + cross-impl interop)
```

```python
from vorlath_shield import shield
pub, priv = shield.generate_recipient_keys()                      # default = CNSA-2.0 apex suite
env = shield.encrypt(b"classified", pub)
assert shield.decrypt(env, priv) == b"classified"

# authenticated:
spk, ssk = shield.generate_signing_keys()
env = shield.encrypt_authenticated(b"orders", pub, ssk, spk)
assert shield.decrypt_authenticated(env, priv, spk) == b"orders"  # rejects any other sender
```

## Honest limitations — read before any real use

See **[SECURITY.md](SECURITY.md)** and **[THREAT_MODEL.md](THREAT_MODEL.md)**. In short:
`kyber-py` / `dilithium-py` **track** FIPS 203/204 but are **NOT FIPS 140-3 validated** and **not**
side-channel hardened. **ML-KEM (keyGen, encaps, decaps — including the FO-transform
implicit-rejection branch and the encapsulation-/decapsulation-key checks) and ML-DSA (keyGen,
sigGen, sigVer), plus SLH-DSA (sigVer), are conformance-tested against official NIST ACVP vectors**
(`test_acvp.py`, `test_acvp_slhdsa.py`). What remains **not** ACVP-covered: **ML-DSA has no key-check**
(NIST publishes no ML-DSA keyCheck vector set and `dilithium-py` exposes no public-/secret-key
validation, so it is intentionally absent, not faked), and **SLH-DSA keyGen and sigGen** stay
round-trip/KAT-only (the pinned `slhdsa==0.2.3` has no seed-based keyGen and signing is too slow for a
vendored ACVP set). The envelope is a project convention, not a standardized protocol; "CNSA 2.0"
denotes the **algorithm set**, not a validated module. For production: use a FIPS-validated module,
extend ACVP to SLH-DSA keyGen/sigGen, and commission an independent side-channel + protocol review.

The v2 construction was independently reviewed by three model lineages (Gemini, Mistral, Grok);
all actionable findings were fixed.

The handshake's security goals are **machine-checked at two levels**. **Symbolically** (Dolev-Yao),
three independent tool lineages prove confidentiality (surviving a CRQC that breaks *either single*
leg), sender authenticity, transcript binding and downgrade resistance: [Verifpal](https://verifpal.com)
(bounded), [Tamarin](https://tamarin-prover.com) (unbounded sessions, plus standalone downgrade-
and KCI-resistance lemmas) and [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) (unbounded,
Horn-clause resolution; all queries hold, authentication scoped to honest senders via the SetupS witness). **Computationally**, the combiner's hybrid-secrecy core — the derived key
is indistinguishable from random under single-leg compromise, in both directions — is machine-checked
in [CryptoVerif](https://cryptoverif.inria.fr) (`formal/shield_combiner.cv`; HKDF modeled as a (Q)ROM,
ML-KEM IND-CCA / strong-DH abstracted — see [`SECURITY_ARGUMENT.md`](SECURITY_ARGUMENT.md)). All four
lineages are re-run by CI (`make prove-all`). See [`formal/README.md`](formal/README.md).

For the single authoritative map of *what is mechanized vs. argued vs. out of scope* — every
Verifpal query, all 11 Tamarin lemmas and the CryptoVerif theorem against a standard security
goal — see [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md). For the **case against our own claims** —
the hostile self-audit of every proof-vs-code abstraction gap, ranked, with how to falsify each —
see [`VERIFICATION_GAP_MAP.md`](VERIFICATION_GAP_MAP.md).

## Reproduce it yourself & supply chain

"CI-gated" is not "externally reproducible," so both are provided:

- **[`REPRODUCE.md`](REPRODUCE.md)** — re-derive all 508 tests + the three proofs + the
  constant-time measurement from a clean checkout in ~30 min.
- **[`release/`](release/)** — a deterministic, content-addressed **verification bundle**
  (`make_bundle.py` → `RELEASE_MANIFEST.json`, a SHA-256 Merkle-style root over source + proof
  models + vectors), **cosign-signed (keyless OIDC)** with a **SLSA** build-provenance
  attestation in CI (`.github/workflows/provenance.yml`). Confirm the bytes you re-run are the
  bytes that were signed.
- **[`sbom/sbom.cdx.json`](sbom/sbom.cdx.json)** — CycloneDX 1.5 SBOM (pinned direct deps;
  full transitive closure emitted in CI).
- **[`cbom/cbom.cdx.json`](cbom/cbom.cdx.json)** — CycloneDX 1.6 **CBOM** (cryptographic bill of
  materials): the 14 crypto assets with their NIST PQ security levels and governing standards —
  the machine-readable inventory the federal PQC mandates require (NSM-10 / NCCoE SP 1800-38).
  `make cbom`.
- **[`STANDARDS_POSITION.md`](STANDARDS_POSITION.md)** — why this exact combiner/parameter set
  vs. X-Wing / TLS-hybrid / composite-sigs, with the live IETF drafts + CNSA 2.0 timeline.
- **[`BINDING.md`](BINDING.md)** — KEM-binding (X-BIND-K-CT / K-PK): what bare ML-KEM gives
  (LEAK-bind, but *neither* MAL notion per RFC 9935 §9 / Schmieg 2024) and how the Shield's
  transcript binding repairs it at the protocol layer, X-Wing-style.
- **[`GOV_ALIGNMENT.md`](GOV_ALIGNMENT.md)** — a sourced **public/declassified** US-government
  posture map (CNSA 2.0 + CSfC, NIST FIPS/SP, NSM-10/OMB/CISA, DoD ZT) — each requirement to the
  Shield's alignment status. No classified material; posture, not certification.
- **[`CNSA_MIGRATION.md`](CNSA_MIGRATION.md)** — the CNSA 2.0 migration self-assessment matrix +
  the gov-aligned modes (pure-CNSA, LMS signing-first per SP 800-208, CSfC dual-layer / RFC 8784
  PPK) as designs, each with its named ship requirement (honest "verified today vs designed" line).
- **[`AUDIT_READINESS.md`](AUDIT_READINESS.md)** — the onramp for an external cryptographic design
  review + NIST CAVP (paid or grant-funded): scope, the evidence already in place, the review RFP,
  the ranked attack surface, and the CAVP/side-channel self-test status. Honest about reference-impl
  maturity (what to fund now vs what to defer to a hardened build).
- **[`SECURITY-DISCLOSURE.md`](SECURITY-DISCLOSURE.md)** + `/.well-known/security.txt` —
  coordinated vulnerability disclosure policy.

## Standards

FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) — finalized Aug 2024 · CNSA 2.0 (NSA) · SP 800-56C (KDF) ·
SP 800-38D (AES-GCM) · RFC 7748 (X25519/X448) · RFC 5869 (HKDF) · NSM-10 · OMB M-23-02.
