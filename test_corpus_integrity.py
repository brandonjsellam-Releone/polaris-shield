"""Pin the vendored corpora by digest, so the "frozen" and "official" claims can fail.

WHY THIS FILE EXISTS
────────────────────────────────────────────────────────────────────────────────────────────────
Two claims about vendored test data were enforced by reading fields out of the data itself:

  test_acvp.py:137        assert "NIST ACVP" in VEC["_meta"]["source"]
  interop/test_pstv.py:158  assert meta["frozen"] is True

The first is a substring match on a PROSE field inside the very file being validated: anyone who
edits `acvp/acvp_vectors.json` and keeps the words "NIST ACVP" in `_meta.source` passes it. The
second compares a boolean to itself — `interop/gen_pstv_vectors.py:629` writes `"frozen": True`,
and the test asserts it is True. Re-minting the corpus with fresh randomness leaves both green.

Neither claim was FALSE, which is what made this worth fixing rather than deleting. An
independent re-check established that all 172 ACVP vectors are bit-exact NIST data from
usnistgov/ACVP-Server at commit 15c0f3deeefb (RELEASE/v1.1.0.42), expected outputs included. The
data is real. The CHECK was not: it carried no information about the bytes on disk.

WHAT THIS DOES INSTEAD
────────────────────────────────────────────────────────────────────────────────────────────────
Recompute the SHA-256 of each corpus and compare it to a digest recorded HERE, in the test — not
in the corpus. The two values then come from independent places, so the comparison can fail:
re-minting, truncating, or hand-editing a vector all change the digest, and no edit to the corpus
can change what it is compared against.

Updating a digest below is a deliberate, reviewable act. That is the point: a frozen corpus that
can be silently re-minted is not frozen, it is merely labelled.
"""

import hashlib
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent

_CRLF = bytes([13, 10])
_LF = bytes([10])


def _content_digest(path: pathlib.Path) -> str:
    """SHA-256 of the file's content with line endings normalised to LF.

    Hashing the RAW bytes was the obvious thing to do and it was wrong: git checks these files
    out CRLF on Windows and LF elsewhere, so the raw digest is a property of the CHECKOUT
    PLATFORM, not of the corpus. The first version of this test pinned the Windows bytes and
    failed all sixteen macOS and Linux CI legs, with a diff of exactly the 1225 CR bytes in
    acvp_vectors.json.

    Normalising to LF pins what git actually tracks, so the same corpus gives the same digest
    everywhere. It does mean a pure CRLF/LF change is invisible here — which is correct: that is
    a checkout artifact, not a change to the vectors.
    """
    return hashlib.sha256(path.read_bytes().replace(_CRLF, _LF)).hexdigest()

# (path, sha256, what changing it means)
#
# ACVP: upstream usnistgov/ACVP-Server @ 15c0f3deeefb (RELEASE/v1.1.0.42). Refreshing from a
# newer upstream is legitimate and SHOULD change this digest — see the note in the ACVP test
# about the nine over-long-ek negatives NIST withdrew on 2026-07-28.
#
# PSTV: minted by interop/gen_pstv_vectors.py. This corpus is meant to be FROZEN, so a changed
# digest here is a re-mint, and a re-mint means the cross-implementation corpus is no longer the
# one the interop results were recorded against.
_PINNED = [
    pytest.param(
        "acvp/acvp_vectors.json",
        "ef45b8d34ece2c9c945ba62f82d44ea5f6217bf5601208b984f2607b46bb127e",
        "the vendored NIST ACVP corpus changed; refresh deliberately and update this digest",
        id="acvp_vectors.json",
    ),
    pytest.param(
        "interop/pstv_vectors.json",
        "0aaa587644d7b92c6ed5e6625881ef7cc4879dada4011044031b062bedfe757d",
        "the PSTV corpus was re-minted; it is supposed to be frozen",
        id="pstv_vectors.json",
    ),
]


@pytest.mark.parametrize(("rel", "expected", "meaning"), _PINNED)
def test_corpus_digest_is_pinned(rel, expected, meaning):
    path = _ROOT / rel
    assert path.exists(), f"{rel} is missing entirely — the suite it feeds would skip or pass vacuously"
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == expected, (
        f"{rel} does not match its pinned digest — {meaning}.\n"
        f"  expected {expected}\n"
        f"  actual   {actual}\n"
        "If the change is intended, update the digest in this file IN THE SAME COMMIT, so the "
        "diff shows a reviewer that vendored test data moved."
    )


def test_the_pin_can_actually_fail():
    """A guard that cannot fail is the defect this closes. Prove this one can.

    Hash a mutated copy in memory rather than trusting that the assertions above would fire —
    they pass today because the corpora are unmodified, which is indistinguishable from a check
    that never looks.
    """
    path = _ROOT / "acvp/acvp_vectors.json"
    raw = path.read_bytes().replace(_CRLF, _LF)   # same normalisation the pin uses
    mutated = raw[:-1] + (b"\x20" if raw[-1:] != b"\x20" else b"\x09")
    assert hashlib.sha256(mutated).hexdigest() != hashlib.sha256(raw).hexdigest(), (
        "a one-byte change did not move the digest; the comparison above is not reading the file"
    )


def test_officialness_is_not_asserted_by_the_file_itself():
    """Guard the ANTI-PATTERN, so it cannot come back in the form it took.

    `assert "NIST ACVP" in VEC["_meta"]["source"]` reads a prose field out of the artifact under
    test. It is not evidence of provenance: it is evidence that someone typed a string. The
    digest pin above is what carries provenance now, and this test exists so that reverting to
    the substring form is a visible failure rather than a silent regression.
    """
    # Skip comments. The commit that removed the old assert quotes it in a comment explaining
    # why, and a guard that fires on its own documentation is a false positive - which is how
    # guards get switched off.
    offenders = [
        f"test_acvp.py:{n}: {line.strip()}"
        for n, line in enumerate((_ROOT / "test_acvp.py").read_text(encoding="utf-8").splitlines(), 1)
        if 'in VEC["_meta"]["source"]' in line and not line.lstrip().startswith("#")
    ]
    assert not offenders, (
        "test_acvp.py is asserting provenance by substring-matching a field inside the corpus it "
        "is validating:\n  " + "\n  ".join(offenders)
        + "\nPin the digest in test_corpus_integrity.py instead."
    )
