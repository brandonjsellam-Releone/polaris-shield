# POLARIS Shield — reproduce every assurance claim yourself

> The point of this page: turn *"CI-gated"* into *"a stranger can independently confirm it."*
> Everything below runs from a clean checkout. Budget ~30 minutes (most of it is the one-time
> Docker build for the formal provers). No claim here asks you to trust us — each step
> re-derives the result on your machine.

## 0. Confirm you have the exact bytes that were proved

```bash
cd tech
python release/make_bundle.py            # regenerate the manifest from your checkout
# Compare bundle_digest against the published, cosign-signed value:
python - <<'PY'
import json; print(json.load(open("release/RELEASE_MANIFEST.json"))["bundle_digest"])
PY
```

The `bundle_digest` is a SHA-256 Merkle-style root over the source + all three proof models +
the ACVP/KAT vectors + the interop corpus. If your digest matches the signed one (see
`release/README.md` for the cosign verification command), you are re-running the exact
artifacts that were tested and proved — not a lookalike.

## 1. Tests (497) — functional + KAT + ACVP conformance + property/fuzz + interop

```bash
pip install -r requirements.txt
python -m pytest -q                       # expect: 497 passed
```

What this establishes: primitives behave (incl. the **ACVP implicit-rejection branch** and
ek/dk key-checks), the wire format round-trips, and the independent `interop/altcodec.py`
decoder agrees byte-for-byte on every positive and rejects every negative at its expected layer.

## 2. Three machine-checked proofs (hermetic, pinned provers)

The two **symbolic** provers (Verifpal, Tamarin) are pinned by SHA-256 in the hermetic image, so
you do not have to install them by hand. That image runs **both symbolic lineages plus the
497-test suite**, exiting non-zero on any failure:

```bash
docker build -t polaris-shield-verify -f Dockerfile .
docker run --rm polaris-shield-verify        # Verifpal + Tamarin + 497 tests; non-zero on any failure
```

The CryptoVerif **computational** proof is *not* in that image (it needs an OCaml/opam toolchain);
run it with `make prove-cryptoverif` or the native command below. It is independently gated in CI
(`.github/workflows/formal.yml`, the `prove-cryptoverif` job). The **ProVerif fourth lineage is a
DRAFT** pending its own run (`formal/proverif.Dockerfile`); it is **not** counted among the verified
proofs — see [`VERIFICATION_GAP_MAP.md`](VERIFICATION_GAP_MAP.md).

Or natively, if you already have the provers on PATH (versions in `formal/README.md`):

```bash
verifpal verify formal/shield.vp             # All queries pass
verifpal verify formal/shield_pq.vp          # All queries pass
tamarin-prover --prove formal/shield.spthy   # all 11 lemmas verified (~11 s)
cryptoverif -in oracles formal/shield_combiner.cv   # All queries proved
cryptoverif -in oracles formal/shield_kemdem.cv     # All queries proved
```

Map each result to a security goal with [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md).

## 3. Constant-time measurement (honest negative)

```bash
python sidechannel/ct_measure.py             # prints Welch |t| per operation
```

`CONSTANT_TIME.md` documents the expected outcome: the pure-Python ML-DSA signing leg shows a
large data-dependent timing signal (\|t\|≈575). We *measure* this rather than assert constant
time — measuring does not fix it, and `SECURITY.md` scopes side channels out accordingly.

## 4. Supply chain — SBOM + provenance + signature

```bash
python sbom/make_sbom.py                      # regenerate the CycloneDX baseline; diff against sbom/sbom.cdx.json
```

- `sbom/sbom.cdx.json` — CycloneDX 1.5, the pinned direct dependencies.
- At release, CI (`.github/workflows/provenance.yml`) emits a **SLSA** build-provenance
  attestation and a **cosign** (keyless OIDC) signature over the bundle digest and the SBOM.
  `release/README.md` has the one-line `cosign verify-blob` / `gh attestation verify` commands.

## What a clean run proves — and what it does not

A green run here means: the protocol logic is sound against an unbounded Dolev-Yao attacker
(symbolic), the combiner is key-indistinguishable under single-leg compromise (computational),
the primitives conform to NIST ACVP vectors, a second implementation interoperates, and the
artifacts are exactly those that were signed. It does **not** mean FIPS 140-3 validation,
side-channel hardening beyond timing, or that ML-KEM/ML-DSA themselves are unbroken — those are
the standardized assumptions, stated in `SECURITY.md` and `FORMAL_COVERAGE.md`.
