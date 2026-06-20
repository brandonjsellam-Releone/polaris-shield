# -*- coding: utf-8 -*-
"""Build the POLARIS Shield content-addressed verification bundle manifest.

"CI-gated" is not the same as "externally reproducible." This script produces a
deterministic, signable manifest over every assurance-critical artifact — the source,
all three formal-proof models, the ACVP/KAT vectors, the interop corpus, the
side-channel harness, and the honest-posture docs — so a third party can fetch the
exact bytes that were proved/tested and confirm they match, then re-run the proofs.

    python tech/release/make_bundle.py        # writes RELEASE_MANIFEST.{json,sha256}

Outputs (in tech/release/):
  RELEASE_MANIFEST.json    - {path, sha256, bytes} per file + a single bundle_digest
  RELEASE_MANIFEST.sha256  - `sha256  path` lines, verifiable with `sha256sum -c`

bundle_digest = SHA-256 over the sorted canonical "sha256  path\\n" lines (a stable
Merkle-style root over the whole assurance set). It depends ONLY on file contents and
paths — no timestamps, no ordering nondeterminism — so the same tree always yields the
same digest. That digest is what CI signs with cosign (keyless OIDC) at release.
"""
import fnmatch
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
TECH = os.path.dirname(HERE)

# Assurance-critical globs, relative to tech/. Anything that a reviewer must be able to
# re-derive the proofs/tests from belongs here. Order does not matter (we sort).
INCLUDE = [
    "polaris_shield/**/*.py",
    "formal/*.vp", "formal/*.spthy", "formal/*.cv", "formal/*.ocv", "formal/*.pv",
    "formal/*.md", "formal/proverif.Dockerfile",
    "acvp/*.json", "acvp/*.py",
    "kat_vectors.json", "gen_kat_vectors.py",
    "interop/*.py", "interop/*.json", "interop/*.md", "interop/diff.Dockerfile",
    "sidechannel/*.py",
    "sbom/sbom.cdx.json", "cbom/cbom.cdx.json",
    "FORMAT.md", "THREAT_MODEL.md", "SECURITY.md", "SECURITY_ARGUMENT.md",
    "SECURITY-DISCLOSURE.md", "CONSTANT_TIME.md", "README.md", "REPRODUCE.md",
    "FORMAL_COVERAGE.md", "STANDARDS_POSITION.md",
    "VERIFICATION_GAP_MAP.md", "BINDING.md", "GOV_ALIGNMENT.md", "CNSA_MIGRATION.md",
    "AUDIT_READINESS.md",
    "requirements.txt", "pyproject.toml", "Dockerfile",
    "test_*.py",
]
# Never hash generated/transient outputs or the manifest itself.
EXCLUDE = ["**/__pycache__/**", "release/RELEASE_MANIFEST.*"]


def _iter_files():
    for base, _dirs, files in os.walk(TECH):
        for fn in files:
            full = os.path.join(base, fn)
            rel = os.path.relpath(full, TECH).replace(os.sep, "/")
            if any(fnmatch.fnmatch(rel, pat) for pat in EXCLUDE):
                continue
            if any(_match(rel, pat) for pat in INCLUDE):
                yield rel, full


def _match(rel, pat):
    # support ** in include globs
    if "**" in pat:
        return fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat.replace("/**", ""))
    return fnmatch.fnmatch(rel, pat)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    entries = []
    for rel, full in _iter_files():
        entries.append({"path": rel, "sha256": _sha256(full), "bytes": os.path.getsize(full)})
    entries.sort(key=lambda e: e["path"])

    # canonical lines -> bundle digest (stable Merkle-style root)
    canon = "".join(f"{e['sha256']}  {e['path']}\n" for e in entries)
    bundle_digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()

    manifest = {
        "artifact": "polaris-shield",
        "version": "2.0.0",
        "manifest_kind": "content-addressed-assurance-bundle",
        "hash_algorithm": "SHA-256",
        "file_count": len(entries),
        "total_bytes": sum(e["bytes"] for e in entries),
        "bundle_digest": bundle_digest,
        "files": entries,
    }

    with open(os.path.join(HERE, "RELEASE_MANIFEST.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    with open(os.path.join(HERE, "RELEASE_MANIFEST.sha256"), "w", encoding="utf-8", newline="\n") as f:
        f.write(canon)

    print(f"bundle: {len(entries)} files, {manifest['total_bytes']:,} bytes")
    print(f"bundle_digest (SHA-256): {bundle_digest}")
    print("wrote release/RELEASE_MANIFEST.json + release/RELEASE_MANIFEST.sha256")


if __name__ == "__main__":
    main()
