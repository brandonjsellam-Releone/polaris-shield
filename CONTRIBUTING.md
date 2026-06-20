# Contributing to VORLATH Shield

Thanks for your interest. VORLATH Shield is an open-source, algorithm-agile **hybrid** post-quantum
cryptography reference implementation on the finalized NIST standards (ML-KEM / ML-DSA). It is held to
an unusual bar: **every security-relevant claim must be backed by an artifact a reviewer can reproduce**
— a machine-checked proof, a passing test, or a signed reproducible build. Please keep contributions to
that bar.

## Reporting security issues — do NOT open a public issue
If you believe you have found a vulnerability, **do not file a public GitHub issue.** Follow the
coordinated disclosure process in [`SECURITY-DISCLOSURE.md`](SECURITY-DISCLOSURE.md). Cryptographic
findings are exactly what this project wants — the published self-audit
([`VERIFICATION_GAP_MAP.md`](VERIFICATION_GAP_MAP.md)) names the weakest seams and how to attack them.

## Setup

```bash
pip install -e ".[dev]"
```

## Run everything (this is also how you verify a change)

```bash
pytest -q                          # the full test suite (functional + NIST ACVP conformance + KAT + property/fuzz + interop)
ruff check . && mypy vorlath_shield # lint + types
python -m vorlath_shield demo      # live walkthrough

# The four formal-proof lineages (CI runs these on every relevant change):
#   Verifpal (bounded), Tamarin + ProVerif (unbounded), CryptoVerif (computational + the IND-CCA composition).
# See formal/README.md; the proverif/cryptoverif/cross-impl Docker images reproduce them hermetically.

# Independent second-implementation primitive cross-check, and the reproducibility bundle:
docker build -f interop/diff.Dockerfile -t vorlath-shield-diff interop   # ML-KEM/ML-DSA vs PQClean/C
python release/make_bundle.py                                            # content-addressed signed bundle
```

`REPRODUCE.md` re-derives every green check (tests + proofs + the constant-time measurement) from a
clean checkout.

## Standards for a change

- **No overclaiming.** If you add a claim, add the artifact that proves it (a test, a proof query, a
  vector). If a change touches the handshake model or `vorlath_shield/shield.py`, the formal CI
  (`formal.yml`) must stay green; if it changes the wire format, update `FORMAT.md` and the interop
  vectors. Frozen KAT/interop vectors must keep verifying (run `pytest`).
- **Honesty about scope.** This is a reference implementation, **not** FIPS 140-3 validated and not
  side-channel hardened. Don't add language implying otherwise.
- **Keep it reproducible + deterministic.** New vectors and the bundle must re-derive identically.
- **Style.** `ruff` + `mypy` clean; match the surrounding code.

## Licensing of contributions

By submitting a contribution you agree it is licensed under the project's **Apache License 2.0** (see
`LICENSE`), and you certify you have the right to submit it (a Developer Certificate of Origin-style
sign-off, `Signed-off-by:` in your commit, is appreciated).
