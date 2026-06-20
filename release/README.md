# VORLATH Shield — signed, reproducible release bundle

This directory turns the assurance work into something a third party can **fetch, verify, and
re-run** without trusting our CI. Two artifacts, one digest, one signature.

## Artifacts

| File | What it is |
|---|---|
| `make_bundle.py` | Regenerates the manifest from a checkout (deterministic; content only). |
| `RELEASE_MANIFEST.json` | `{path, sha256, bytes}` for every assurance-critical file + a single `bundle_digest`. |
| `RELEASE_MANIFEST.sha256` | `sha256  path` lines — verify with `sha256sum -c RELEASE_MANIFEST.sha256`. |

`bundle_digest` is a SHA-256 Merkle-style root over the sorted `sha256  path` lines. It is a
pure function of file **contents and paths** — no timestamps — so the same source tree always
produces the same digest. That digest is the single value CI signs.

## Verify it yourself

```bash
# 1. Reproduce the digest from your own checkout
cd tech && python release/make_bundle.py
sha256sum -c release/RELEASE_MANIFEST.sha256      # every file: OK

# 2. Confirm the signature over the published bundle (keyless cosign / Sigstore)
cosign verify-blob \
  --certificate-identity-regexp 'github.com/brandonjsellam-Releone/valyonvorlath' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature   vorlath-shield-bundle.sig \
  --certificate vorlath-shield-bundle.pem \
  release/RELEASE_MANIFEST.json

# 3. Confirm SLSA build provenance traces to the exact commit
gh attestation verify vorlath-shield-bundle.tar.gz \
  --repo brandonjsellam-Releone/valyonvorlath
```

If step 1's digest equals the signed digest from step 2, the proofs/tests you re-run from
[`../REPRODUCE.md`](../REPRODUCE.md) are running over **exactly** the bytes that were signed.

## SBOM

`../sbom/sbom.cdx.json` is the checked-in CycloneDX 1.5 baseline (pinned direct deps). The CI
release job additionally runs `cyclonedx-py` against the resolved environment to emit the full
transitive SBOM and signs it alongside the bundle.

## Provenance generation

`.github/workflows/provenance.yml` builds the bundle, generates the SBOM, attaches a SLSA
build-provenance attestation, and cosign-signs the bundle digest + SBOM on every tagged
release. Nothing here is self-asserted: the signer identity is the repository's GitHub OIDC
identity, verifiable by anyone with the commands above.
